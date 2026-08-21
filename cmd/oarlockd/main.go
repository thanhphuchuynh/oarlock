// Command oarlockd is the Oarlock gateway.
//
// The wiring lives in ./app so that a deployment can link its own plugins in and still
// get the standard arrangement:
//
//	package main
//
//	import (
//	    "github.com/oarlock/oarlock/cmd/oarlockd/app"
//	    _ "example.com/our-stack/ourauthz"
//	)
//
//	func main() { app.Main() }
package main

import "github.com/oarlock/oarlock/cmd/oarlockd/app"

func main() { app.Main() }
