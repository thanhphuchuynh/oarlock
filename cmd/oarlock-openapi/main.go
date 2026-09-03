// Command oarlock-openapi writes docs/openapi.yaml from the gateway's route table.
//
//	go run ./cmd/oarlock-openapi          # write the file
//	go run ./cmd/oarlock-openapi -check   # fail if it is stale
//
// The same shape `tokens/generate.mjs` uses for design tokens, and for the same reason: the
// generated artefact lives in the repository so it shows up in a diff, and a check keeps it
// honest. An endpoint appearing in a pull request is something a person should see.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/oarlock/oarlock/internal/openapi"
)

const path = "docs/openapi.yaml"

func main() {
	check := flag.Bool("check", false, "fail if the committed document is stale")
	out := flag.String("o", path, "where to write")
	flag.Parse()

	doc, err := openapi.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "oarlock-openapi: %v\n", err)
		os.Exit(1)
	}

	if *check {
		have, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oarlock-openapi: %v\nRun `go run ./cmd/oarlock-openapi`.\n", err)
			os.Exit(1)
		}
		if !bytes.Equal(have, doc) {
			fmt.Fprintf(os.Stderr,
				"oarlock-openapi: %s is stale.\n\n"+
					"The route table changed and the document did not. Run:\n"+
					"    go run ./cmd/oarlock-openapi\n\n"+
					"and read the diff — an endpoint appearing or disappearing is "+
					"something a reviewer should see.\n", *out)
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*out, doc, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "oarlock-openapi: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", *out)
}
