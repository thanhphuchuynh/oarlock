package plugin

import (
	"context"
	"time"
)

// AuditKind names an auditable gateway event.
type AuditKind string

const (
	AuditSessionOpened   AuditKind = "session.opened"
	AuditSessionClosed   AuditKind = "session.closed"
	AuditSessionRejected AuditKind = "session.rejected"
	AuditAPIError        AuditKind = "api.error"
	AuditObserveIssued   AuditKind = "observe.issued"
	AuditSQLQuery        AuditKind = "sql.query"
	// AuditAdminChange is an administrative request: a device record written, a
	// permission written, a session or control channel ended by an administrator.
	// Emitted whether it was allowed or refused, because a refused attempt to rewrite
	// the policy is the more interesting of the two.
	AuditAdminChange AuditKind = "admin.change"
)

// AuditEvent is one line of the audit trail.
//
// The struct is deliberately flat. Backends can store it as JSON, syslog fields or a
// table row without learning a per-event schema first; Kind says which fields matter.
type AuditEvent struct {
	Time      time.Time         `json:"time"`
	Kind      AuditKind         `json:"kind"`
	SessionID string            `json:"session_id,omitempty"`
	DeviceID  string            `json:"device_id,omitempty"`
	Principal string            `json:"principal,omitempty"`
	OpenedBy  string            `json:"opened_by,omitempty"`
	Observer  string            `json:"observer,omitempty"`
	Surface   string            `json:"surface,omitempty"`
	Action    string            `json:"action,omitempty"`
	Code      string            `json:"code,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Retryable bool              `json:"retryable,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// AuditSink receives auditable events.
//
// Emit is best effort and cannot fail by contract: audit must never become the thing
// that breaks a shell. Implementations that buffer must expose their own drop counters.
type AuditSink interface {
	Emit(ctx context.Context, e AuditEvent)
}
