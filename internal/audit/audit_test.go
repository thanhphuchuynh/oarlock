package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/audit"
	"github.com/oarlock/oarlock/pkg/plugin"
)

type blockingSink struct {
	release chan struct{}
}

func (s blockingSink) Emit(context.Context, plugin.AuditEvent) { <-s.release }

func TestAsyncCountsDroppedEvents(t *testing.T) {
	release := make(chan struct{})
	a := audit.NewAsync(blockingSink{release: release}, 1, nil)
	defer func() {
		close(release)
		_ = a.Close()
	}()

	for range 1000 {
		a.Emit(context.Background(), plugin.AuditEvent{Kind: plugin.AuditAPIError})
	}
	if a.Dropped() == 0 {
		t.Fatal("audit queue overflow dropped nothing")
	}
}

func TestJSONLSinkWritesEvents(t *testing.T) {
	mem := &audit.Memory{}
	mem.Emit(context.Background(), plugin.AuditEvent{
		Time: time.Unix(1, 0).UTC(), Kind: plugin.AuditSessionClosed,
		SessionID: "sess_1", Reason: "revoked",
	})
	got := mem.Snapshot()
	if len(got) != 1 || got[0].Kind != plugin.AuditSessionClosed || got[0].Reason != "revoked" {
		t.Fatalf("events = %+v", got)
	}
}
