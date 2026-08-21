package sshsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	gssh "github.com/gliderlabs/ssh"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
)

// sshConn adapts an SSH session to transport.Conn.
//
// The pump moves frames between two transport.Conns and knows nothing about SSH or
// WebSocket. Translating here rather than teaching the pump a second shape means the
// browser leg (E3) reuses the identical pump, and the SSH-specific mess — stdin as a
// byte stream, window changes on their own channel, signals on another — stays in
// one file.
//
// The cost is encoding a frame to cross an in-process boundary. That is one small
// allocation per batch against a working pump for both operator surfaces, which is
// a trade worth making.
type sshConn struct {
	sess gssh.Session

	frames  chan []byte
	closeCh chan struct{}
	once    sync.Once

	wmu sync.Mutex
	buf []byte

	exit atomic.Pointer[int]
	// throttled records whether a THROTTLE ever reached an SSH operator, so a bug
	// in the shell policy is visible rather than silent.
	throttled atomic.Bool
}

var _ transport.Conn = (*sshConn)(nil)

func newSSHConn(sess gssh.Session, win <-chan gssh.Window) *sshConn {
	c := &sshConn{
		sess:    sess,
		frames:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	go c.readStdin()
	if win != nil {
		go c.readWindows(win)
	}
	go c.readSignals()
	return c
}

// readStdin turns keystrokes into DATA frames. Never batched: a human is waiting on
// the echo, and 25 ms added to every keystroke is felt.
func (c *sshConn) readStdin() {
	buf := make([]byte, 4096)
	for {
		n, err := c.sess.Read(buf)
		if n > 0 {
			if !c.offer(frame.Data(buf[:n])) {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.offerClose("transport_error")
				return
			}
			// EOF on stdin means "no more input", not "the session is over" — and
			// treating them as the same thing broke the most ordinary non-interactive
			// use there is. `ssh host < script` and `echo cmd | ssh host` send their
			// bytes and immediately close the channel's write side, so closing here
			// ended the session before the device's output had come back: the operator
			// got a disclosure banner, a close reason, and none of the output they
			// asked for.
			//
			// So stop reading and leave the session running. What ends it is the thing
			// that should: the device's shell exiting (which is what the `exit` at the
			// end of a piped script does), an idle timer, or the SSH connection
			// actually going away — which cancels sess.Context() and takes the pump
			// with it. An interactive operator pressing Ctrl-D is unaffected, because
			// that arrives as a byte through the PTY's line discipline rather than as a
			// channel EOF.
			return
		}
	}
}

func (c *sshConn) readWindows(win <-chan gssh.Window) {
	for w := range win {
		// A client that does not know its own terminal size reports zero, and
		// `ssh -tt` with piped stdin does exactly that — it asks for a PTY while stdin
		// is not a terminal, so there is no size to report. That is not a resize
		// request, and forwarding it as one used to kill the session: the recorder
		// refuses a zero-sized resize, and a recording failure cancels the session.
		//
		// Dropped here rather than tolerated further down, because the meaningless
		// value should not enter the protocol at all.
		if w.Width <= 0 || w.Height <= 0 {
			continue
		}
		f, err := frame.Marshal(frame.TypeResize, frame.Resize{Cols: w.Width, Rows: w.Height})
		if err != nil {
			return
		}
		if !c.offer(f) {
			return
		}
	}
}

func (c *sshConn) readSignals() {
	sigs := make(chan gssh.Signal, 4)
	c.sess.Signals(sigs)
	for s := range sigs {
		f, err := frame.Marshal(frame.TypeSignal, frame.Signal{Signal: string(s)})
		if err != nil {
			return
		}
		if !c.offer(f) {
			return
		}
	}
}

func (c *sshConn) offer(f frame.Frame) bool {
	wire, err := frame.Codec{}.Encode(nil, f)
	if err != nil {
		return false
	}
	select {
	case c.frames <- wire:
		return true
	case <-c.closeCh:
		return false
	}
}

func (c *sshConn) offerClose(reason string) {
	f, err := frame.Marshal(frame.TypeClose, frame.Close{Reason: reason})
	if err == nil {
		c.offer(f)
	}
}

// Recv hands the next operator-side frame to the pump.
func (c *sshConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeCh:
		return nil, transport.ErrClosed
	case b := <-c.frames:
		return b, nil
	}
}

// Send writes the gateway's output to the SSH client.
func (c *sshConn) Send(_ context.Context, b []byte) error {
	f, err := frame.Codec{}.Decode(b)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	switch f.Type {
	case frame.TypeData:
		_, err := c.sess.Write(f.Payload)
		return err
	case frame.TypeDataErr:
		_, err := c.sess.Stderr().Write(f.Payload)
		return err
	case frame.TypeThrottle:
		var t frame.Throttle
		_ = frame.Unmarshal(f, &t)
		c.throttled.Store(true)
		// Out of band on stderr, so it cannot be mistaken for program output and
		// cannot corrupt a screen the way injecting it into stdout would.
		_, err := fmt.Fprintf(c.sess.Stderr(),
			"\r\n[oarlock] %d bytes dropped\r\n", t.DroppedBytes)
		return err
	case frame.TypeError:
		var e frame.Error
		_ = frame.Unmarshal(f, &e)
		_, err := fmt.Fprintf(c.sess.Stderr(), "\r\n[oarlock] %s: %s\r\n", e.Code, e.Message)
		return err
	case frame.TypeExit:
		var x frame.Exit
		if err := frame.Unmarshal(f, &x); err == nil {
			code := x.Code
			c.exit.Store(&code)
		}
		return nil
	case frame.TypeReady, frame.TypePing, frame.TypePong:
		// An SSH client is already "ready", and liveness on this leg is TCP's job.
		return nil
	default:
		return fmt.Errorf("sshsrv: cannot render %s to an SSH client", f.Type)
	}
}

func (c *sshConn) Close(transport.CloseCode, string) error {
	c.once.Do(func() { close(c.closeCh) })
	return nil
}

func (c *sshConn) RemoteAddr() string { return c.sess.RemoteAddr().String() }

// exitCode returns the code the device reported, if any.
func (c *sshConn) exitCode() *int { return c.exit.Load() }

// sawThrottle reports whether a THROTTLE ever arrived. On a shell profile that is a
// gateway bug, not a condition to render.
func (c *sshConn) sawThrottle() bool { return c.throttled.Load() }
