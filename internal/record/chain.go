// Package record writes session recordings in asciicast v3, with a hash chain and
// a signed manifest.
//
// # Why integrity is here from the first commit
//
// PCI DSS 4.0.1 expects privileged session recording in a *tamper-proof* log, and
// a plain .cast file in a bucket is not one: anyone with write access can alter it
// afterwards and nothing detects it. The chain has to be designed into the writer,
// because it cannot be added to recordings that already exist — which is why Epic 9
// ships in parallel with Epic 2 rather than after it.
//
// # The chain
//
//	h₀ = SHA-256(domain ‖ 0x00 ‖ header line)
//	hᵢ = SHA-256(hᵢ₋₁ ‖ event line i)
//
// Lines are chained exactly as written, without their newline. Comment lines are
// *not* chained: they carry checkpoints about the chain, and chaining them would be
// self-referential.
//
// # Why checkpoints
//
// Recomputing the chain and comparing it to the signed head detects any change. It
// does not say *what* changed. Periodic checkpoints — written as asciicast comment
// lines, which the format says readers ignore, so asciinema still plays the file —
// let a verifier say "this file is intact up to event 512 and then simply stops",
// which is truncation, distinct from "event 300 does not match", which is
// alteration. Those two findings lead somewhere different.
package record

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ChainAlg and ChainDomain identify the construction. The domain separator means a
// chain hash can never be mistaken for, or replayed as, a hash from some other part
// of the system.
const (
	ChainAlg    = "sha256"
	ChainDomain = "oarlock-recording-v1"

	// CheckpointEvery is how often a checkpoint comment is written. Every 128
	// events is cheap — one 80-byte comment per 128 lines — and bounds how coarsely
	// a truncation point can be reported.
	CheckpointEvery = 128

	chainHeaderComment = "# oarlock-chain v1 alg=" + ChainAlg + " domain=" + ChainDomain
	checkpointPrefix   = "# oarlock-checkpoint "
)

// chain accumulates the running hash.
type chain struct {
	h      [32]byte
	events int
}

// start seeds the chain from the header line.
func newChain(headerLine []byte) *chain {
	sum := sha256.New()
	sum.Write([]byte(ChainDomain))
	sum.Write([]byte{0})
	sum.Write(headerLine)
	c := &chain{}
	copy(c.h[:], sum.Sum(nil))
	return c
}

// add folds one event line in.
func (c *chain) add(eventLine []byte) {
	sum := sha256.New()
	sum.Write(c.h[:])
	sum.Write(eventLine)
	copy(c.h[:], sum.Sum(nil))
	c.events++
}

// head is the current chain value in hex.
func (c *chain) head() string { return hex.EncodeToString(c.h[:]) }

// checkpoint renders the comment line for the current position.
func (c *chain) checkpoint() string {
	return fmt.Sprintf("%s%d %s", checkpointPrefix, c.events, c.head())
}

// Checkpoint is a parsed checkpoint comment.
type Checkpoint struct {
	Events int
	Head   string
}

// parseCheckpoint reads a checkpoint comment, if that is what the line is.
func parseCheckpoint(line string) (Checkpoint, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), checkpointPrefix)
	if !ok {
		return Checkpoint{}, false
	}
	countStr, head, found := strings.Cut(rest, " ")
	if !found {
		return Checkpoint{}, false
	}
	n, err := strconv.Atoi(countStr)
	if err != nil || n < 0 {
		return Checkpoint{}, false
	}
	head = strings.TrimSpace(head)
	if _, err := hex.DecodeString(head); err != nil || len(head) != 64 {
		return Checkpoint{}, false
	}
	return Checkpoint{Events: n, Head: head}, true
}

// isComment reports whether a line is an asciicast comment, which the format says
// readers ignore — and which is therefore where metadata can live without making
// the file unplayable.
func isComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}
