package condition_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/oarlock/oarlock/pkg/condition"
)

var update = flag.Bool("update", false, "rewrite the generated condition table")

const generated = "../../packages/terminal/src/conditions.ts"

// TestGeneratedTableIsCurrent keeps the browser's screens and the gateway's vocabulary
// the same set.
//
// The alternative — a table of copy maintained by hand in TypeScript — is how the
// planning documents came to specify eleven screens for a set that had nine entries and
// an acceptance criterion naming a tenth. Generating it means a condition without a
// screen is a build failure.
//
// Regenerate with: go test ./pkg/condition/ -run TestGeneratedTable -update
func TestGeneratedTableIsCurrent(t *testing.T) {
	want := render()
	have, err := os.ReadFile(generated)
	if *update {
		if werr := os.WriteFile(generated, []byte(want), 0o644); werr != nil {
			t.Fatal(werr)
		}
		t.Logf("wrote %s", generated)
		return
	}
	if err != nil {
		t.Fatalf("%v\n\nRegenerate with: go test ./pkg/condition/ -run TestGeneratedTable -update", err)
	}
	if string(have) != want {
		t.Errorf("%s is stale — the gateway's conditions changed and the browser's "+
			"screens did not.\n\nRegenerate with: "+
			"go test ./pkg/condition/ -run TestGeneratedTable -update", generated)
	}
}

func render() string {
	var b strings.Builder
	b.WriteString(`/* GENERATED FROM pkg/condition — do not edit.
 * Regenerate: go test ./pkg/condition/ -run TestGeneratedTable -update
 *
 * The closed set of reasons a session can fail or end, and what each one means to the
 * person looking at the screen. Generated from the gateway's own table so that a
 * condition the server can emit cannot be a screen the browser does not have.
 */

/** Who can act on a condition. */
export type Audience = "operator" | "integrator";

/** Whose problem it is. Encoded rather than implied: a broken doorbell reported as
 *  "device offline" sends an engineer to look at hardware. */
export type Fault = "none" | "device" | "gateway" | "principal" | "client";

export interface Condition {
  /** The wire value: an ERROR code, or a CLOSE reason. */
  readonly id: string;
  /** Where it appears on the wire. An error means the session never started; a close
   *  means it ran and stopped. The same fact at two moments is not one screen. */
  readonly kind: "error" | "close" | "error|close";
  readonly audience: Audience;
  readonly fault: Fault;
  readonly retryable: boolean;
  /** Names the thing. Never "Error", never a code, never an apology. */
  readonly headline: string;
  /** What to do about it. Empty only where there is genuinely nothing to do. */
  readonly nextAction: string;
}

/** The shared screen for a condition an operator cannot act on. */
export const integratorHeadline = `)
	b.WriteString(fmt.Sprintf("%q;\n", condition.IntegratorHeadline))
	b.WriteString("export const integratorNextAction = ")
	b.WriteString(fmt.Sprintf("%q;\n\n", condition.IntegratorNextAction))

	b.WriteString("export const conditions: readonly Condition[] = [\n")
	for _, c := range condition.All() {
		head, next := c.Headline, c.NextAction
		if c.Audience == condition.Integrator && head == "" {
			head, next = condition.IntegratorHeadline, condition.IntegratorNextAction
		}
		row := map[string]any{
			"id": c.ID, "kind": c.Kind.String(), "audience": c.Audience.String(),
			"fault": c.Fault.String(), "retryable": c.Retryable,
			"headline": head, "nextAction": next,
		}
		// Field order fixed by hand: encoding/json would sort the keys and produce a
		// file that reads like data rather than like a table.
		b.WriteString("  {\n")
		for _, k := range []string{"id", "kind", "audience", "fault", "retryable", "headline", "nextAction"} {
			v, err := json.Marshal(row[k])
			if err != nil {
				panic(err)
			}
			b.WriteString(fmt.Sprintf("    %s: %s,\n", k, v))
		}
		b.WriteString("  },\n")
	}
	b.WriteString("];\n\n")

	b.WriteString(`const byID = new Map(conditions.map((c) => [c.id, c]));

/** lookup returns a condition, or undefined if this build has never heard of it. */
export function lookup(id: string): Condition | undefined {
  return byID.get(id);
}

/**
 * get returns a condition, falling back to a well-formed unknown.
 *
 * An unknown code is a gateway newer than this client, which the protocol's versioning
 * rules allow. It has to render as "we don't recognise this" rather than as a blank
 * screen or as whatever the first row of the table happens to be.
 */
export function get(id: string): Condition {
  return (
    byID.get(id) ?? {
      id,
      kind: "error",
      audience: "integrator",
      fault: "client",
      retryable: false,
      headline: integratorHeadline,
      nextAction: integratorNextAction,
    }
  );
}
`)
	return b.String()
}
