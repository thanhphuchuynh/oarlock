package record

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxLine bounds one line of a .cast while verifying.
//
// A verifier reads files it did not write, so an unbounded line reader is an
// allocation an attacker chooses. Generous enough for a JSON-escaped 1 MiB batch
// (escapes can multiply a byte by six) and far short of anything that hurts.
const MaxLine = 16 << 20

// Status is a verification outcome. These are separate values because they lead
// somewhere different: truncation usually means a process died, alteration means
// somebody edited the file, and a bad signature means the manifest itself is not
// ours.
type Status string

const (
	// StatusValid: the chain reaches the signed head, with the expected count.
	StatusValid Status = "valid"
	// StatusTruncated: everything present is intact, and the file stops early.
	StatusTruncated Status = "truncated"
	// StatusAltered: the content does not match what was signed.
	StatusAltered Status = "altered"
	// StatusBadSignature: the manifest is unsigned or not signed by this key.
	StatusBadSignature Status = "bad_signature"
	// StatusMalformed: the file is not a readable asciicast.
	StatusMalformed Status = "malformed"
)

// Verdict is the result of verifying a recording.
type Verdict struct {
	OK     bool
	Status Status
	Detail string

	EventsFound    int
	EventsExpected int

	// LastGoodCheckpoint is the highest event count that verified against a
	// checkpoint comment. It is what turns "this file is wrong" into "this file is
	// intact up to event 512 and then stops".
	LastGoodCheckpoint int

	ComputedHead string
	ExpectedHead string
}

func (v Verdict) String() string {
	if v.OK {
		return fmt.Sprintf("valid: %d events", v.EventsFound)
	}
	return fmt.Sprintf("%s: %s", v.Status, v.Detail)
}

// Verify checks a recording against its manifest.
//
// The signature is checked first, and deliberately so: if the manifest is not ours
// then the head, the counts and the checkpoints are all attacker-chosen, and
// comparing the file against them proves nothing. A forged manifest that "verifies"
// against a forged recording is the failure this ordering prevents.
func Verify(cast io.Reader, m Manifest, pub ed25519.PublicKey) (Verdict, error) {
	if err := m.VerifySignature(pub); err != nil {
		return Verdict{
			Status: StatusBadSignature,
			Detail: err.Error(),
		}, nil
	}
	if m.Chain.Alg != ChainAlg || m.Chain.Domain != ChainDomain {
		return Verdict{
			Status: StatusMalformed,
			Detail: fmt.Sprintf("manifest describes chain %s/%s, this build computes %s/%s",
				m.Chain.Alg, m.Chain.Domain, ChainAlg, ChainDomain),
		}, nil
	}

	r := bufio.NewReaderSize(cast, 64<<10)
	headerLine, err := readLine(r)
	if err != nil {
		return Verdict{Status: StatusMalformed, Detail: "no header line"}, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(string(headerLine)), "{") {
		return Verdict{Status: StatusMalformed, Detail: "header is not a JSON object"}, nil
	}

	c := newChain(headerLine)
	v := Verdict{EventsExpected: m.Chain.Events, ExpectedHead: m.Chain.Head}
	altered := false

	for {
		line, err := readLine(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Verdict{Status: StatusMalformed, Detail: err.Error()}, nil
		}
		s := string(line)

		if isComment(s) {
			cp, ok := parseCheckpoint(s)
			if !ok {
				continue // some other comment; the format says ignore it
			}
			// A checkpoint is a claim about the chain at a point. If it disagrees
			// with what we computed, the content before it was changed.
			if cp.Events == c.events && cp.Head == c.head() {
				v.LastGoodCheckpoint = cp.Events
			} else {
				altered = true
			}
			continue
		}

		if !strings.HasPrefix(strings.TrimSpace(s), "[") {
			return Verdict{Status: StatusMalformed,
				Detail: fmt.Sprintf("line %d is neither a comment nor an event", c.events+1)}, nil
		}
		c.add(line)
	}

	v.EventsFound = c.events
	v.ComputedHead = c.head()

	switch {
	case altered:
		v.Status = StatusAltered
		v.Detail = fmt.Sprintf("content changed after event %d", v.LastGoodCheckpoint)
	case v.ComputedHead == v.ExpectedHead && v.EventsFound == v.EventsExpected:
		v.OK = true
		v.Status = StatusValid
	case v.EventsFound < v.EventsExpected:
		// Everything present chained cleanly and there is simply less of it. That is
		// a file that stopped, not a file that was edited.
		v.Status = StatusTruncated
		v.Detail = fmt.Sprintf("%d of %d events present; intact up to event %d",
			v.EventsFound, v.EventsExpected, v.LastGoodCheckpoint)
	default:
		v.Status = StatusAltered
		v.Detail = fmt.Sprintf("chain head %s does not match the signed %s (%d events, expected %d)",
			short(v.ComputedHead), short(v.ExpectedHead), v.EventsFound, v.EventsExpected)
	}
	return v, nil
}

// readLine reads one bounded line without its newline.
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(out)+len(chunk) > MaxLine {
			return nil, fmt.Errorf("record: line exceeds %d bytes", MaxLine)
		}
		out = append(out, chunk...)
		if err == nil {
			return trimNewline(out), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(out) == 0 {
				return nil, io.EOF
			}
			// A final line with no newline: a file that was cut mid-write. Treat it
			// as a line, so the chain sees exactly what is on disk.
			return trimNewline(out), nil
		}
		return nil, err
	}
}

func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	return b
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
