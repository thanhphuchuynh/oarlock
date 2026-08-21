package apisrv

// StatusFor is exported for the tests: the mapping from condition to HTTP status is
// worth asserting over the whole table rather than over the handful of codes a handler
// test happens to exercise.
func StatusFor(code string) int { return statusFor(code) }
