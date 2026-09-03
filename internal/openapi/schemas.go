package openapi

// The response shapes, written against the structs that produce them.
//
// Hand-written and therefore capable of drifting, which is why the test in this package
// renders a *real* response from apisrv and compares its field names against what is
// declared here. A schema that claims a field the gateway does not send is a generated SDK
// with a field nobody can populate; one that omits a field the gateway does send is an SDK
// that silently discards it.

func str(desc string) schema  { return schema{Type: "string", Description: desc} }
func num(desc string) schema  { return schema{Type: "integer", Description: desc} }
func flag(desc string) schema { return schema{Type: "boolean", Description: desc} }

func schemas() map[string]schema {
	return map[string]schema{
		"Problem": {
			Type: "object",
			Description: "RFC 9457. Every failure is one of these, and `type` is the " +
				"machine-readable half — the closed set in pkg/condition, which the " +
				"console renders a screen per.",
			Required: []string{"type", "title", "status"},
			Properties: map[string]schema{
				"type":   str("A URI naming the condition. The stable part."),
				"title":  str("One line, for a person."),
				"detail": str("What went wrong this time, when there is more to say."),
				"status": num("The HTTP status, repeated here."),
				"request": str("The correlation id. Quote it when asking for help; it is " +
					"in the gateway's logs against everything this request did."),
				"instance": str("The resource this is about, when there is one."),
			},
		},

		"Session": {
			Type:     "object",
			Required: []string{"id", "device_id", "profile", "mode", "principal", "state"},
			Properties: map[string]schema{
				"id":        str("The session id. Recordings and audit events are keyed by it."),
				"device_id": str("The device."),
				"profile":   str("shell, exec, log, file, tcp or sshpass."),
				"mode":      str("gateway or passthrough. A passthrough session is not recorded and cannot be."),
				"principal": str("Who opened it."),
				"opened_by": str("The service account, when a service acted for a human."),
				"unattended": flag("A service session with no human subject, so robot and " +
					"human activity can be counted apart."),
				"reason":          str("Why the session is in this state, where the state alone does not say."),
				"state":           str("waking, attached, closed…"),
				"recording_state": str("recorded or not_recorded. An unrecorded session is a queryable fact rather than a missing file."),
				"close_reason":    str("The closed set from ARCHITECTURE § 6."),
				"exit_code":       {Type: "integer", Nullable: true, Description: "The process's exit status, where the profile has one."},
				"bytes_in":        num("Operator to device."),
				"bytes_out":       num("Device to operator."),
				"bytes_dropped":   num("Discarded by backpressure. Non-zero means the transcript has a hole in it."),
				"created_at":      {Type: "string", Format: "date-time"},
				"attached_at":     {Type: "string", Format: "date-time", Nullable: true},
				"closed_at":       {Type: "string", Format: "date-time", Nullable: true},
				"live":            flag("Still running, somewhere."),
				"live_here":       flag("Still running on the node that answered. A session can be live in the ledger and not here."),
			},
		},
		"SessionList": {
			Type:     "object",
			Required: []string{"sessions"},
			Properties: map[string]schema{
				"sessions":    {Type: "array", Items: &schema{Ref: "#/components/schemas/Session"}},
				"next_cursor": str("Pass as `cursor` for the next page. Absent on the last."),
			},
		},

		"Device": {
			Type:     "object",
			Required: []string{"id", "platform", "resolved_mode", "connected"},
			Properties: map[string]schema{
				"id":                str("The device id, which is also the SSH username."),
				"platform":          str("android, linux, container or other. It picks the reachability default."),
				"enabled":           {Type: "boolean", Nullable: true, Description: "False means the device is revoked without being deleted."},
				"mode":              str("An explicit reachability override, when set."),
				"resolved_mode":     str("persistent or dispatch, after the platform default is applied."),
				"keys":              {Type: "array", Items: &schema{Type: "string"}, Description: "The device's control-channel identity keys. A list, which is the whole rotation story."},
				"retired_keys":      {Type: "array", Items: &schema{Type: "string"}, Description: "Keys that must no longer authenticate. Explicit, so revocation is auditable."},
				"allow_passthrough": flag("Mode A is permitted for this device. Half of a two-key switch; policy.allow_unrecorded is the other."),
				"tags":              {Type: "object", AdditionalProperties: &schema{Type: "string"}, Description: "What authorizer selectors and record_input policy match on."},
				"profiles":          {Type: "array", Items: &schema{Type: "string"}, Description: "What this device may be asked to do. Empty means the gateway's default set."},
				"connected":         flag("Holding a control channel right now."),
			},
		},
		"DeviceList": {
			Type:     "object",
			Required: []string{"devices"},
			Properties: map[string]schema{
				"devices":     {Type: "array", Items: &schema{Ref: "#/components/schemas/Device"}},
				"next_cursor": str("Pass as `cursor` for the next page. Absent on the last."),
			},
		},

		"Agent": {
			Type:     "object",
			Required: []string{"device_id", "connected"},
			Properties: map[string]schema{
				"device_id": str("The device holding the channel."),
				"connected": flag("Whether it is up."),
			},
		},
		"AgentList": {
			Type:     "object",
			Required: []string{"agents"},
			Properties: map[string]schema{
				"agents": {Type: "array", Items: &schema{Ref: "#/components/schemas/Agent"}},
			},
		},

		"Recording": {
			Type: "object",
			Description: "An asciicast with the manifest it was signed with. The manifest " +
				"is here so a reader can verify the recording themselves rather than " +
				"trusting this gateway's verdict on its own file.",
			Required: []string{"cast", "verdict"},
			Properties: map[string]schema{
				"cast":     str("The asciicast, as text."),
				"manifest": {Type: "string", Format: "byte", Description: "The signed manifest, base64. Verify against the recorder's public key."},
				"verdict":  {Ref: "#/components/schemas/Verdict"},
			},
		},
		"Verdict": {
			Type: "object",
			Description: "This gateway's own check of the recording. Worth printing and " +
				"not evidence: the party that might have altered a recording is the " +
				"party being asked.",
			Required: []string{"status", "ok"},
			Properties: map[string]schema{
				"status":               str("ok, bad_signature, malformed, truncated…"),
				"ok":                   flag("Whether it verified."),
				"events_found":         num(""),
				"events_expected":      num(""),
				"last_good_checkpoint": num("Where the hash chain last agreed."),
				"detail":               str(""),
			},
		},
	}
}
