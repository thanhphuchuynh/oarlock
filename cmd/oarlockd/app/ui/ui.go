// Package ui serves the reference console.
//
// The built assets are embedded, so the binary is self-contained: a gateway that needed a
// directory of JavaScript beside it is a gateway somebody deploys wrongly once.
//
// The console is optional. `go build` without the assets present still produces a working
// gateway — the SSH surface, the API and /ws/attach do not depend on it — and the handler
// then says so rather than serving a blank page. That matters because the assets come from
// a separate toolchain: somebody building from a clean checkout without pnpm should get a
// gateway, not a build error.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds the built console. The `all:` prefix keeps files whose names begin with an
// underscore, which a bundler may well produce.
//
//go:embed all:dist
var dist embed.FS

// Handler serves the console under the given prefix, or explains its absence.
func Handler(prefix string) http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil || !built(sub) {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(
				"The console was not built into this binary.\n\n" +
					"Build it with:\n  pnpm install && pnpm build:ui\n" +
					"then rebuild the gateway. Everything else — ssh, /api, /ws/attach —\n" +
					"works without it.\n"))
		})
	}

	files := http.FileServerFS(sub)
	return http.StripPrefix(strings.TrimSuffix(prefix, "/"), http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// A single-page app: any path that is not a file is the app's own route, so
			// it gets index.html rather than a 404. Without this, reloading the page on
			// a deep link would 404 from the gateway instead of reaching the console.
			p := strings.TrimPrefix(r.URL.Path, "/")
			if p != "" && !exists(sub, p) {
				r = r.Clone(r.Context())
				r.URL.Path = "/"
			}
			// The bundle's names are content-hashed, so it can be cached hard; index.html
			// must not be, or a deploy leaves people on the old app forever.
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
		}))
}

// Built reports whether this binary carries a console.
func Built() bool {
	sub, err := fs.Sub(dist, "dist")
	return err == nil && built(sub)
}

func built(sub fs.FS) bool {
	f, err := sub.Open("index.html")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func exists(sub fs.FS, name string) bool {
	f, err := sub.Open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
