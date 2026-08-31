package sshsrv

// The pre-authentication budget: how long a connection may sit at the front door
// without an operator on the other end of it.
//
// # Why the front door needs its own bound
//
// The WebSocket legs already have one — internal/handshake gives an unauthenticated
// peer a fixed budget and a fixed-size buffer, and the transport refuses an oversized
// message before it is read. The SSH front door had neither, because gliderlabs'
// Server leaves IdleTimeout and MaxTimeout at zero and there is no third field that
// means "bound the handshake". So a peer could open a TCP connection, send the
// version string, and hold a goroutine and a file descriptor open indefinitely — on
// the door that leads to a shell, without proving anything about who it is.
//
// This is slowloris, and the reason it deserves its own file is that neither of the
// two obvious fixes works.
//
// # Why not MaxTimeout, and why not a deadline
//
// **MaxTimeout is an absolute connection timeout, not a handshake one.** Setting it
// to fifteen seconds to bound the handshake would kill every session fifteen seconds
// after it opened. **IdleTimeout is a gap-between-reads timeout**, which during an
// interactive shell is a person thinking. Both are the wrong shape: what needs
// bounding is the interval before authentication and nothing after it.
//
// A read deadline set on the connection does not survive either. gliderlabs wraps
// whatever ConnCallback returns in a serverConn of its own, whose Read and Write both
// call updateDeadline() first — and with IdleTimeout and MaxTimeout unset that
// resolves to SetDeadline(time.Time{}), which *clears* a deadline rather than leaving
// it alone. A deadline set here would therefore last exactly until the first byte
// arrived, which is to say it would bound nothing and look like it did.
//
// So the budget is a timer that closes the socket. A caller that does not know the
// timer exists cannot reset it, which is the property the deadline lacked.
//
// # Why it does not disarm on a successful auth callback
//
// The first version of this disarmed from PublicKeyHandler, which is wrong, and wrong in
// the direction that removes the whole control. x/crypto calls PublicKeyCallback for an
// unsigned *query* — the "would you accept this key?" round trip every OpenSSH client
// makes before it signs anything (`server.go`: the callback runs, and only then is
// `isQuery` consulted). A public key is not a secret, so anyone who has read an
// `authorized_keys` file could offer a query for a key the gateway accepts, disarm the
// budget, never sign, and hold the connection open exactly as before.
//
// What actually means "this peer got through" is gliderlabs setting ContextKeyConn, which
// it does only after gossh.NewServerConn returns successfully. So the timer fires
// regardless and asks that question when it does.

import (
	"net"
	"sync"
	"time"

	gssh "github.com/gliderlabs/ssh"
)

// DefaultHandshakeBudget bounds the interval between a connection arriving and an
// operator authenticating on it.
//
// Generous on purpose. This is not a latency target: keyboard-interactive
// authentication asks a human to approve a login in a browser, and fifteen seconds is
// already tight for that. It is a ceiling that turns "hold a goroutine forever" into
// "hold a goroutine for fifteen seconds", which is the difference that matters.
const DefaultHandshakeBudget = 15 * time.Second

// preauthKey carries the armed connection from ConnCallback to the auth handlers.
// gliderlabs hands both the same Context, which is the only thing joining them.
type preauthKey struct{}

// preauthConn closes itself if nobody authenticates within the budget.
type preauthConn struct {
	net.Conn
	timer *time.Timer
	once  sync.Once
}

func newPreauthConn(ctx gssh.Context, c net.Conn, budget time.Duration) *preauthConn {
	pc := &preauthConn{Conn: c}
	pc.timer = time.AfterFunc(budget, func() {
		// Set once the handshake has completed, and never before — including never for a
		// peer that only ever sent an unsigned public-key query. sshContext guards its
		// values with a mutex, so reading it from the timer's goroutine is sound.
		//
		// There is a window of two statements in gliderlabs between NewServerConn
		// returning and this key being set, in which an authenticated connection would be
		// closed. It is microseconds against a fifteen-second budget, and the failure is a
		// dropped connection at connect time rather than a bypass, so it is left alone
		// rather than papered over with a second timer.
		if ctx.Value(gssh.ContextKeyConn) != nil {
			return
		}
		_ = c.Close()
	})
	return pc
}

// disarm stops the timer. Reached only from Close: nothing during authentication is
// allowed to disarm this, because nothing during authentication proves anything.
func (c *preauthConn) disarm() { c.once.Do(func() { c.timer.Stop() }) }

// Close disarms as well as closing, so a connection that fails authentication and
// hangs up does not leave a timer holding a reference to it for the rest of the
// budget.
func (c *preauthConn) Close() error {
	c.disarm()
	return c.Conn.Close()
}

// armPreauth wraps a new connection with the budget and stashes it on the context.
// A budget of zero or less returns the connection untouched.
func armPreauth(ctx gssh.Context, conn net.Conn, budget time.Duration) net.Conn {
	if budget <= 0 {
		return conn
	}
	pc := newPreauthConn(ctx, conn, budget)
	ctx.SetValue(preauthKey{}, pc)
	return pc
}
