// Package authsrv serves the browser login: /auth/login, /auth/callback, /auth/token.
//
// Deliberately not under /api/v1. These are not API calls — they are redirects a browser
// follows, and one of them renders no JSON at all. Mixing them into the API prefix would
// mean the API's bearer-token authentication had to make an exception for the endpoints
// that exist precisely because nobody has a token yet.
//
// # Why the token is handed over rather than kept in a cookie
//
// The obvious design is a long-lived session cookie that the API accepts. It is also how
// an API acquires a CSRF surface: a cookie is attached by the browser to any request to
// this origin, including ones another site caused. Defending that means SameSite plus an
// origin check plus a header nobody can forge, on every state-changing endpoint, forever.
//
// So the cookie here exists for exactly one hop. The callback sets it, the console
// immediately exchanges it at /auth/token for the provider's own `id_token`, and the
// cookie is cleared in the same response. From then on the console sends a bearer header
// like every other API client, and the API has no cookie path at all.
//
// The token then lives in the tab's sessionStorage, readable by any script that gets into
// the console. That is the standard trade for a single-page application, and it is a
// strict improvement on what it replaces: a long-lived static token, pasted by hand, in
// the same place.
package authsrv

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oarlock/oarlock/internal/auth/oidc"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// Prefix is where this server mounts.
const Prefix = "/auth"

const (
	// flowCookie carries the id of an in-flight login. It holds no secret: the state and
	// the PKCE verifier stay on the gateway.
	flowCookie = "oarlock_login"
	// handoffCookie carries the id_token for exactly one request, from the callback
	// redirect to the console's first fetch.
	handoffCookie = "oarlock_handoff"

	// flowTTL bounds how long a started login may sit unfinished. Long enough to type a
	// password and answer an MFA prompt, short enough that an abandoned flow is not a
	// pending authorisation somebody can complete tomorrow.
	flowTTL = 10 * time.Minute
	// handoffTTL is one redirect and one fetch.
	handoffTTL = 60 * time.Second
)

// Options configures the server.
type Options struct {
	// OIDC is the provider client. Required.
	OIDC *oidc.Authenticator
	// RedirectURL is this gateway's callback, exactly as registered with the provider.
	// Required, and not derived from the request: a provider matches it byte for byte,
	// and deriving it from a Host header would let a proxy or an attacker choose where
	// the code is sent.
	RedirectURL string
	// ConsoleURL is where to send the browser once it is signed in. Defaults to /ui/.
	ConsoleURL string
	// Audit receives login outcomes. Nil disables it.
	Audit plugin.AuditSink
	Now   func() time.Time
	Log   *slog.Logger
}

// Server serves the browser login endpoints.
type Server struct {
	o   Options
	mux *http.ServeMux
	log *slog.Logger
	now func() time.Time

	mu       sync.Mutex
	flows    map[string]*flow
	handoffs map[string]*handoff
}

// flow is a login that has started and not finished.
type flow struct {
	state    string
	verifier string
	// returnTo is where the operator was going before they were asked to sign in.
	returnTo string
	expires  time.Time
}

type handoff struct {
	token     string
	principal string
	expires   time.Time
}

// New validates the options and wires the routes.
func New(o Options) (*Server, error) {
	switch {
	case o.OIDC == nil:
		return nil, errors.New("authsrv: OIDC is required")
	case o.RedirectURL == "":
		return nil, errors.New("authsrv: RedirectURL is required, and must be the exact " +
			"URL registered with the provider")
	}
	if !o.OIDC.SupportsBrowserFlow() {
		return nil, errors.New("authsrv: the provider publishes no authorization_endpoint, " +
			"so there is no browser login to serve")
	}
	if o.ConsoleURL == "" {
		o.ConsoleURL = "/ui/"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	s := &Server{o: o, log: o.Log, now: o.Now,
		flows: map[string]*flow{}, handoffs: map[string]*handoff{}}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET "+Prefix+"/login", s.login)
	s.mux.HandleFunc("GET "+Prefix+"/callback", s.callback)
	s.mux.HandleFunc("POST "+Prefix+"/token", s.token)
	s.mux.HandleFunc("POST "+Prefix+"/logout", s.logout)
	s.mux.HandleFunc("GET "+Prefix+"/config", s.config)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Handler exposes the mux for mounting.
func (s *Server) Handler() http.Handler { return s.mux }

// config tells an unauthenticated console how to log in.
//
// Unauthenticated on purpose, and it discloses nothing: "this gateway uses a provider" is
// visible from the login page either way, and a console that has to guess would have to
// try one and fall back to the other.
func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"login": "oidc"})
}

// login starts a flow and redirects to the provider.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state, err := oidc.NewState()
	if err != nil {
		s.fail(w, r, "could not start the login", err)
		return
	}
	pkce, err := oidc.NewPKCE()
	if err != nil {
		s.fail(w, r, "could not start the login", err)
		return
	}
	id, err := oidc.NewState() // an opaque cookie value; the same generator will do
	if err != nil {
		s.fail(w, r, "could not start the login", err)
		return
	}

	// Where to come back to. Only a path on this origin is accepted: an open redirect on
	// a login endpoint is how a phishing link ends up looking like a real one.
	returnTo := s.o.ConsoleURL
	if want := r.URL.Query().Get("return_to"); safeReturnTo(want) {
		returnTo = want
	}

	s.mu.Lock()
	s.sweepLocked()
	s.flows[id] = &flow{state: state, verifier: pkce.Verifier, returnTo: returnTo,
		expires: s.now().Add(flowTTL)}
	s.mu.Unlock()

	target, err := s.o.OIDC.AuthorizeURL(s.o.RedirectURL, state, pkce)
	if err != nil {
		s.fail(w, r, "could not start the login", err)
		return
	}
	s.setCookie(w, flowCookie, id, flowTTL)
	// 303, not 302: the browser must GET the provider regardless of how it got here.
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// callback finishes the flow.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// The provider refused, and it said why. Shown rather than swallowed: "access
		// denied" from an identity provider usually means a policy an operator can act
		// on, not a bug in the gateway.
		s.refuse(w, r, http.StatusForbidden, "The sign-in was refused.",
			strings.TrimSpace(e+" "+q.Get("error_description")))
		return
	}

	cookie, err := r.Cookie(flowCookie)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "That sign-in link has expired.",
			"Start again from the console.")
		return
	}
	s.clearCookie(w, flowCookie)

	// Compare-and-delete: a flow is redeemable once. Without that, a callback URL in
	// somebody's history is a callback URL they can replay.
	s.mu.Lock()
	f, ok := s.flows[cookie.Value]
	if ok {
		delete(s.flows, cookie.Value)
	}
	s.mu.Unlock()
	if !ok || s.now().After(f.expires) {
		s.refuse(w, r, http.StatusBadRequest, "That sign-in has expired.",
			"Start again from the console.")
		return
	}

	// The state check. Constant-time is not required — this is not a secret being
	// compared against a guess, it is a value the gateway generated and the provider
	// echoed — but it must happen, or an attacker can start a flow and have somebody
	// else's browser complete it.
	if q.Get("state") != f.state {
		s.log.Warn("a login callback arrived with the wrong state; a cross-site request " +
			"forgery against the login endpoint looks exactly like this")
		s.refuse(w, r, http.StatusBadRequest, "That sign-in could not be verified.",
			"Start again from the console.")
		return
	}

	p, idToken, err := s.o.OIDC.ExchangeCode(r.Context(), q.Get("code"),
		s.o.RedirectURL, f.verifier)
	if err != nil {
		s.log.Warn("a login could not be completed", "error", err)
		s.audit("", "refused", err.Error())
		s.refuse(w, r, http.StatusForbidden, "Sign-in failed.",
			"Your identity provider would not confirm the sign-in.")
		return
	}

	id, err := oidc.NewState()
	if err != nil {
		s.fail(w, r, "could not finish the login", err)
		return
	}
	s.mu.Lock()
	s.handoffs[id] = &handoff{token: idToken, principal: p.ID,
		expires: s.now().Add(handoffTTL)}
	s.mu.Unlock()

	s.log.Info("signed in", "principal", p.ID, "groups", p.Groups)
	s.audit(p.ID, "signed_in", "")
	s.setCookie(w, handoffCookie, id, handoffTTL)
	http.Redirect(w, r, f.returnTo, http.StatusSeeOther)
}

// token exchanges the handoff cookie for the provider's id_token, once.
//
// POST rather than GET, and not because it changes server state in a way a GET could not:
// a GET would be reachable from an <img> or a link on another site, and while the cookie
// is SameSite=Lax — so it would not be sent — relying on one mechanism for that is thinner
// than relying on two.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(handoffCookie)
	if err != nil {
		// Not an error worth alarming about: the console asks on every load, and most
		// loads are not immediately after a sign-in.
		writeJSON(w, http.StatusNoContent, nil)
		return
	}
	s.clearCookie(w, handoffCookie)

	s.mu.Lock()
	h, ok := s.handoffs[cookie.Value]
	if ok {
		delete(s.handoffs, cookie.Value)
	}
	s.mu.Unlock()
	if !ok || s.now().After(h.expires) {
		writeJSON(w, http.StatusNoContent, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": h.token, "principal": h.principal,
	})
}

// logout clears whatever is left here.
//
// It does not end the session at the provider: this gateway is one relying party, and
// signing somebody out of their identity provider because they closed a terminal would be
// presumptuous. The console forgets its token, which is what "sign out" means here.
func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	s.clearCookie(w, handoffCookie)
	s.clearCookie(w, flowCookie)
	writeJSON(w, http.StatusOK, map[string]any{"signed_out": true})
}

// returnToShape is an allow-list of the characters a same-origin path may contain.
//
// An allow-list, and not a series of checks for the bad cases, because the bad cases keep
// arriving. `url.Parse` is not the arbiter here: it reports an empty Host for
// `/\evil.example.com`, and browsers normalise that backslash to a slash — so what the
// gateway parsed as a path is what the browser follows to another origin. The same trick
// works with a tab or a newline, which browsers strip. Anything not spelled out below is
// refused, whatever a parser makes of it.
var returnToShape = regexp.MustCompile(`^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/?#\[\]]*$`)

// safeReturnTo accepts only a path on this origin.
//
// An open redirect here is worth more to an attacker than most bugs in this repository: a
// link to the gateway's own login endpoint that lands on their page is a phishing link
// carrying a real domain.
func safeReturnTo(want string) bool {
	if want == "" || !returnToShape.MatchString(want) {
		return false
	}
	// A protocol-relative URL starts with a slash and is not on this origin at all.
	if strings.HasPrefix(want, "//") {
		return false
	}
	// Belt and braces: whatever the shape, a parser must also see no scheme and no host.
	u, err := url.Parse(want)
	return err == nil && u.Scheme == "" && u.Host == ""
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
		// Lax rather than Strict: the callback arrives as a top-level navigation from
		// the provider's site, and Strict withholds cookies on exactly that. The flow
		// cookie would not come back and every real sign-in would fail.
		//
		// Not covered by a test, and it cannot easily be: SameSite is computed per
		// *site*, so a provider and a gateway both on 127.0.0.1 are same-site whatever
		// their ports, and Strict passes locally while breaking in production.
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		// Always. The callback is either https or loopback — the config gate requires
		// one of the two — and a browser treats http://127.0.0.1 as a secure context,
		// so a Secure cookie is sent back there too. There is no case left that needed
		// a knob.
		Secure: true,
		MaxAge: int(ttl.Seconds()),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/",
		SameSite: http.SameSiteLaxMode, HttpOnly: true, Secure: true, MaxAge: -1,
	})
}

// sweepLocked drops expired flows. Called on each new login rather than on a timer: the
// only thing that grows this map is somebody starting a login.
func (s *Server) sweepLocked() {
	now := s.now()
	for id, f := range s.flows {
		if now.After(f.expires) {
			delete(s.flows, id)
		}
	}
	for id, h := range s.handoffs {
		if now.After(h.expires) {
			delete(s.handoffs, id)
		}
	}
}

func (s *Server) audit(principal, outcome, detail string) {
	if s.o.Audit == nil {
		return
	}
	s.o.Audit.Emit(context.Background(), plugin.AuditEvent{
		Kind: plugin.AuditAPIError, Principal: principal, Surface: "browser",
		Action: "sign_in", Outcome: outcome, Reason: detail,
	})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("browser login", "what", what, "error", err)
	s.refuse(w, r, http.StatusInternalServerError, "Something here is wrong.",
		"The sign-in could not be started. This is a problem with the gateway.")
}

// refuse renders a plain page. There is no console to render into: an operator who cannot
// sign in cannot be shown the application.
func (s *Server) refuse(w http.ResponseWriter, _ *http.Request, status int,
	headline, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// Static markup with no interpolation of anything a caller controls. A login error
	// page that reflects a query parameter is a cross-site scripting hole on the one
	// endpoint everybody visits.
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">` +
		`<title>Sign-in</title>` +
		`<style>body{font:16px/1.5 system-ui,sans-serif;margin:12vh auto;max-width:34rem;` +
		`padding:0 1.5rem;color:#14201f;background:#f7f8f7}` +
		`h1{font-size:1.35rem;margin:0 0 .5rem}p{color:#52625f;margin:0 0 1rem}` +
		`a{color:#0f545b}@media(prefers-color-scheme:dark){body{color:#e6ece9;` +
		`background:#0d1312}p{color:#9aa8a5}a{color:#64c9d1}}</style>` +
		`<h1>` + escape(headline) + `</h1><p>` + escape(detail) + `</p>` +
		`<p><a href="` + escape(s.o.ConsoleURL) + `">Back to the console</a></p>`))
}

// escape is deliberately minimal and applied to strings this package itself wrote. It is
// here so that a future edit which does interpolate something external is not a hole.
func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	if v == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
