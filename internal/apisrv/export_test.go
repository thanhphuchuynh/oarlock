package apisrv

import "net/http"

// StatusFor is exported for the tests: the mapping from condition to HTTP status is
// worth asserting over the whole table rather than over the handful of codes a handler
// test happens to exercise.
func StatusFor(code string) int { return statusFor(code) }

// ClientIP is exported for the tests. The rate-limit key is the whole defence against
// a token-guessing loop, and the address family it is derived from is not something a
// handler test would notice getting wrong.
func ClientIP(r *http.Request) string { return clientIP(r) }
