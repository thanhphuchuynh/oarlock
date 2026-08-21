// Package pump moves bytes between a device connection and an operator connection.
//
// Two rules shape everything here, and they pull in opposite directions:
//
//   - Output is coalesced. A chatty PTY writes thousands of times a second, and one
//     frame per write is a syscall storm on both ends plus a WebSocket header per
//     byte. Batching is order-preserving and lossless, so it is always on.
//   - **A shell must never lose a byte.** A dropped chunk lands in the middle of an
//     escape sequence and leaves the terminal corrupt until something forces a full
//     redraw: vi, tmux and anything ncurses render as garbage, and a "42 bytes
//     dropped" marker cannot repair it.
//
// So throttling is per profile: line-oriented output may be dropped and announced,
// and a screen may only be slowed down.
package pump

import "time"

// Policy is what happens when the operator cannot keep up.
type Policy uint8

const (
	// Backpressure slows the device instead of losing data. The gateway stops
	// reading the device connection at a high-water mark and resumes at a low one;
	// WebSocket flow control carries the stall down to the agent, which blocks on
	// its own PTY write. A device producing faster than the operator consumes then
	// behaves exactly as it would on a local terminal. That is correct, not a stall
	// to fix.
	//
	// Because Oarlock does not multiplex (ADR-024), stopping the read on a session
	// connection slows exactly that session. Under multiplexing this would have
	// head-of-line blocked every other session sharing the connection, which is the
	// problem per-stream credit windows exist to solve — and the reason not
	// multiplexing made this simple rather than merely different.
	Backpressure Policy = iota

	// Drop discards bytes and says how many. Correct for line-oriented output: a
	// log firehose loses a line, a THROTTLE frame names the byte count, and the
	// reader is no worse off.
	Drop
)

func (p Policy) String() string {
	if p == Drop {
		return "drop"
	}
	return "backpressure"
}

// PolicyFor returns the throttle policy for a profile.
//
// Unknown profiles get Backpressure. Failing safe here means an unrecognised
// profile is slow rather than corrupt, and a new profile added without touching
// this table cannot silently start losing bytes.
func PolicyFor(profile string) Policy {
	switch profile {
	case "log", "exec":
		return Drop
	default:
		// shell and sshpass must never drop. file and tcp must not either: dropping
		// bytes from a byte-exact transfer is corruption, and dropping bytes out of
		// an SSH stream breaks the MAC and kills the connection outright — so for
		// sshpass backpressure is not even a policy choice, it is the only option.
		return Backpressure
	}
}

// Limits are the throughput numbers, chosen as one set rather than independently.
// Choosing them separately is how a spec ends up with a 1 MiB frame ceiling on a
// 256 KiB/s stream and no way to tell which number is wrong.
type Limits struct {
	// Batch caps one coalesced DATA frame.
	Batch int
	// Window is how long output may be held to batch it.
	Window time.Duration
	// Rate is sustained bytes per second, device to operator. Zero disables.
	Rate int
	// Burst is the token-bucket depth. Zero means one second of Rate.
	Burst int
	// HighWater is the buffered-byte mark at which the policy engages.
	HighWater int
	// LowWater is where backpressure releases. Hysteresis matters: releasing at the
	// same mark that engaged it makes the reader oscillate one byte at a time.
	LowWater int
}

// DefaultLimits matches ARCHITECTURE § 9.3.
//
// A 25 ms window at the sustained rate holds roughly 6.5 KiB, and Batch sits an
// order of magnitude above that so a burst — a full-screen redraw, a dmesg dump —
// travels in one frame instead of ten.
func DefaultLimits() Limits {
	return Limits{
		Batch:     64 << 10,
		Window:    25 * time.Millisecond,
		Rate:      256 << 10,
		Burst:     1 << 20,
		HighWater: 256 << 10,
		LowWater:  64 << 10,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.Batch <= 0 {
		l.Batch = d.Batch
	}
	if l.Window <= 0 {
		l.Window = d.Window
	}
	if l.Burst <= 0 {
		if l.Rate > 0 {
			l.Burst = l.Rate
		} else {
			l.Burst = d.Burst
		}
	}
	if l.HighWater <= 0 {
		l.HighWater = d.HighWater
	}
	if l.LowWater <= 0 || l.LowWater >= l.HighWater {
		l.LowWater = l.HighWater / 4
		if l.LowWater <= 0 {
			l.LowWater = 1
		}
	}
	return l
}
