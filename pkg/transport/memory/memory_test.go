package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/transport"
	"github.com/oarlock/oarlock/pkg/transport/memory"
)

func TestPairCarriesFrames(t *testing.T) {
	ctx := context.Background()
	a, b := memory.Pair(0)
	c := frame.Codec{}

	wire, err := c.Encode(nil, frame.Data([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, wire); err != nil {
		t.Fatal(err)
	}
	got, err := b.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "hello" {
		t.Errorf("payload %q", f.Payload)
	}
}

func TestTextIsAProtocolError(t *testing.T) {
	ctx := context.Background()
	a, b := memory.Pair(0)
	if err := memory.SendText(ctx, a, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Recv(ctx); !errors.Is(err, transport.ErrTextMessage) {
		t.Fatalf("got %v, want ErrTextMessage", err)
	}
}

func TestOverLimit(t *testing.T) {
	ctx := context.Background()
	a, b := memory.Pair(8)
	if err := a.Send(ctx, make([]byte, 9)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Recv(ctx); !errors.Is(err, transport.ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestSendCopies(t *testing.T) {
	// The receiver must not observe a mutation the sender makes afterwards.
	ctx := context.Background()
	a, b := memory.Pair(0)
	buf := []byte("abc")
	if err := a.Send(ctx, buf); err != nil {
		t.Fatal(err)
	}
	buf[0] = 'z'
	got, err := b.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("receiver saw %q; Send must copy", got)
	}
}

func TestCloseUnblocksRecv(t *testing.T) {
	ctx := context.Background()
	a, b := memory.Pair(0)
	if err := a.Close(transport.CloseNormal, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Recv(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
	if err := a.Close(transport.CloseNormal, "again"); err != nil {
		t.Errorf("Close must be idempotent: %v", err)
	}
}

func TestRecvHonoursContext(t *testing.T) {
	a, _ := memory.Pair(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Recv(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// TestCloseUnblocksTheLocalReader models what a real WebSocket does: closing a
// connection makes your *own* pending Read return, not only the peer's. A double
// that only unblocked the peer hid a class of bug — code that closes a connection
// to stop its own read loop looked correct in tests and hung in production.
func TestCloseUnblocksTheLocalReader(t *testing.T) {
	a, _ := memory.Pair(0)
	ctx := context.Background()

	errs := make(chan error, 1)
	go func() {
		_, err := a.Recv(ctx)
		errs <- err
	}()
	time.Sleep(10 * time.Millisecond) // let the reader block
	if err := a.Close(transport.CloseNormal, "stopping"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, transport.ErrClosed) {
			t.Fatalf("local Recv returned %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the connection did not unblock the local reader")
	}
}

func TestSendAfterLocalCloseFails(t *testing.T) {
	a, _ := memory.Pair(0)
	_ = a.Close(transport.CloseNormal, "done")
	if err := a.Send(context.Background(), []byte("x")); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}
