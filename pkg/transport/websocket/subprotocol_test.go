package websocket_test

import (
	"os"
	"regexp"
	"testing"

	"github.com/oarlock/oarlock/pkg/transport/websocket"
)

// TestTheBrowserOffersTheSameSubprotocol.
//
// The gateway refuses an upgrade that does not offer it, so a mismatch between the Go
// constant and the browser's is not a degraded connection — it is no connection at all,
// and it is invisible to every test on either side: the component's tests inject a stub
// socket and the gateway's tests use the Go client.
//
// That is exactly how the browser came to not offer it for the whole of Epic 3.
func TestTheBrowserOffersTheSameSubprotocol(t *testing.T) {
	src, err := os.ReadFile("../../../packages/terminal/src/session.ts")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`export const Subprotocol = "([^"]+)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal("packages/terminal/src/session.ts does not export a Subprotocol constant")
	}
	if got := string(m[1]); got != websocket.Subprotocol {
		t.Errorf("the browser offers %q and the gateway requires %q — every upgrade from "+
			"a browser would be refused, and no test on either side would notice",
			got, websocket.Subprotocol)
	}
}
