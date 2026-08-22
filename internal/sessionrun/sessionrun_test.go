package sessionrun_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/audit"
	"github.com/oarlock/oarlock/internal/sessionrun"
	"github.com/oarlock/oarlock/internal/sessions"
	"github.com/oarlock/oarlock/pkg/frame"
	"github.com/oarlock/oarlock/pkg/plugin"
)

type captureRecorder struct {
	meta *plugin.SessionMeta
}

func (r *captureRecorder) Open(_ context.Context, m *plugin.SessionMeta) (plugin.RecordingWriter, error) {
	cp := *m
	r.meta = &cp
	return noopRecording{}, nil
}

func (captureRecorder) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, plugin.ErrUnsupported
}

func (captureRecorder) URL(context.Context, string, time.Duration) (string, error) {
	return "", plugin.ErrUnsupported
}

type noopRecording struct{}

func (noopRecording) Output(time.Duration, []byte) error { return nil }
func (noopRecording) Input(time.Duration, []byte) error  { return nil }
func (noopRecording) Resize(time.Duration, int, int) error {
	return nil
}
func (noopRecording) Exit(time.Duration, int) error { return nil }
func (noopRecording) Close(context.Context, plugin.RecordingResult) error {
	return nil
}

func TestPreparePassesResolvedRecordInputToRecorder(t *testing.T) {
	store := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 1}, nil)
	row := &sessions.Session{
		ID: "sess_1", DeviceID: "dev-1", Principal: "ana@example.com",
		Profile: "shell", State: sessions.StateWaking,
	}
	if err := store.Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	rec := &captureRecorder{}
	auditLog := &audit.Memory{}
	runner := &sessionrun.Runner{Sessions: store, Recorder: rec, Audit: auditLog}
	_, _, _, err := runner.Prepare(context.Background(), sessionrun.Params{
		SessionID: "sess_1", DeviceID: "dev-1", Profile: "shell",
		Principal: "ana@example.com", RecordInput: true,
		PTY: &frame.PTY{Cols: 80, Rows: 24, Term: "xterm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.meta == nil || !rec.meta.RecordInput {
		t.Fatalf("record input meta = %+v", rec.meta)
	}
	events := auditLog.Snapshot()
	if len(events) != 1 || events[0].Kind != plugin.AuditSessionOpened ||
		events[0].SessionID != "sess_1" {
		t.Fatalf("audit events = %+v", events)
	}
}

func TestRejectEmitsAuditEvent(t *testing.T) {
	store := sessions.NewMemory(sessions.Limits{PerDevice: 1, PerPrincipal: 1}, nil)
	row := &sessions.Session{
		ID: "sess_1", DeviceID: "dev-1", Principal: "ana@example.com",
		Profile: "shell", State: sessions.StateWaking,
	}
	if err := store.Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	auditLog := &audit.Memory{}
	runner := &sessionrun.Runner{Sessions: store, Audit: auditLog}
	runner.Reject(context.Background(), "sess_1", "policy_conflict")

	events := auditLog.Snapshot()
	if len(events) != 1 || events[0].Kind != plugin.AuditSessionRejected ||
		events[0].Reason != "policy_conflict" || events[0].DeviceID != "dev-1" {
		t.Fatalf("audit events = %+v", events)
	}
}
