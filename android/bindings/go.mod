module github.com/oarlock/oarlock/android/bindings

go 1.26.0

	require (
	github.com/oarlock/oarlock v0.0.0
	golang.org/x/crypto v0.55.0
	golang.org/x/mobile v0.0.0-20260821190718-4776eadac327
)

require (
	github.com/coder/websocket v1.8.15 // indirect
	github.com/creack/pty v1.1.18 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/oarlock/oarlock => ../..
