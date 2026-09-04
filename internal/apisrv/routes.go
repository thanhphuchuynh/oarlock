package apisrv

// The API's routes, as data.
//
// # Why a table and not twenty-five HandleFunc calls
//
// E7.S1 asks for an OpenAPI document generated from the handlers, with drift failing the
// build — and the failure it exists to prevent is a document that describes an API the
// gateway no longer has. An SDK generated from a stale spec compiles and then 404s in
// production, which is the worst place to find out.
//
// A hand-maintained spec beside hand-registered routes has two sources of truth and no
// mechanism. This has one: the mux is built from this table and the document is generated
// from it, so a route that exists and is undocumented cannot happen. There is a test for
// each direction, because "cannot happen" is a claim about code somebody will edit.
//
// # What the table cannot capture
//
// Request and response *shapes* are not here — they live in the schema components, written
// by hand. A generator that inferred them from the handlers would need annotations on every
// struct, and the annotations would be the thing that drifted instead. The check that
// matters is that every path, method and authorisation requirement agrees; a wrong field
// type in a schema is a bug somebody hits in an SDK, and a missing endpoint is a bug they
// hit in production.

import (
	"net/http"

	"github.com/oarlock/oarlock/pkg/plugin"
)

// route is one endpoint.
type route struct {
	// ID is the operation id an SDK turns into a method name. See the note below.
	ID     string
	Method string
	// Path is relative to Prefix, with Go 1.22 wildcards: /devices/{id}.
	Path string
	// Summary is one line, in the imperative. It becomes the operation's summary and is
	// what an SDK puts in a doc comment.
	Summary string
	// Action is the authorisation action this endpoint checks, if any. Empty means the
	// endpoint is scoped by the caller's own identity rather than by a grant — listing
	// your sessions, for instance.
	Action plugin.Action
	// Requires names the Options field this route needs, for the document's prose: an
	// endpoint that is absent because the deployment has no SQL explorer is not an
	// endpoint that is missing.
	Requires string
	// available reports whether this deployment serves the route.
	available func(Options) bool
	// handler resolves the method on a built Server.
	handler func(*Server) func(http.ResponseWriter, *http.Request, *plugin.Principal)
}

// ID is the stable name an SDK generator turns into a method.
//
// Chosen rather than derived. The first version of this derived one from the method and
// path, which produced `getSessions` for both `GET /sessions` and `GET /sessions/{id}` —
// two operations of one name, which is a generated client that does not compile. A
// singulariser would have fixed that case and turned `/ssh` into `getSh`.
//
// These are names somebody will type in four languages. They are worth choosing, and the
// uniqueness that derivation was supposed to guarantee is a test instead.

// routes is the whole API surface, in the order the document should read.
//
// Sessions first because they are what the product is for; administration last because it
// is what you reach for when something is wrong.
func routes() []route {
	always := func(Options) bool { return true }
	has := func(f func(Options) bool) func(Options) bool { return f }

	return []route{
		// ── sessions ──
		{
			ID:     "listSessions",
			Method: "GET", Path: "/sessions",
			Summary:   "List sessions.",
			available: always,
			handler:   func(s *Server) handlerFunc { return s.listSessions },
		},
		{
			ID:     "getSession",
			Method: "GET", Path: "/sessions/{id}",
			Summary:   "Get one session.",
			available: always,
			handler:   func(s *Server) handlerFunc { return s.getSession },
		},
		{
			ID:     "killSession",
			Method: "DELETE", Path: "/sessions/{id}",
			Summary:   "End a live session.",
			Action:    plugin.ActionAdminKill,
			available: always,
			handler:   func(s *Server) handlerFunc { return s.killSession },
		},
		{
			ID:     "openSession",
			Method: "POST", Path: "/sessions",
			Summary:  "Open a session on a device and return an attach ticket.",
			Requires: "Registry and Inviter",
			available: has(func(o Options) bool {
				return o.Registry != nil && o.Inviter != nil
			}),
			handler: func(s *Server) handlerFunc { return s.openSession },
		},
		{
			ID:     "renewAttachTicket",
			Method: "POST", Path: "/sessions/{id}/attach",
			Summary:   "Mint a fresh attach ticket for a session, revoking its predecessor.",
			Requires:  "Inviter",
			available: has(func(o Options) bool { return o.Inviter != nil }),
			handler:   func(s *Server) handlerFunc { return s.renewAttach },
		},
		{
			ID:     "createObserveTicket",
			Method: "POST", Path: "/sessions/{id}/observe",
			Summary:   "Mint a read-only ticket to watch a live session.",
			Action:    plugin.ActionObserve,
			Requires:  "Inviter",
			available: has(func(o Options) bool { return o.Inviter != nil }),
			handler:   func(s *Server) handlerFunc { return s.observeSession },
		},

		// ── devices ──
		{
			ID:     "listDevices",
			Method: "GET", Path: "/devices",
			Summary:   "List devices.",
			Requires:  "Registry",
			available: has(func(o Options) bool { return o.Registry != nil }),
			handler:   func(s *Server) handlerFunc { return s.listDevices },
		},
		{
			ID:     "getDevice",
			Method: "GET", Path: "/devices/{id}",
			Summary:   "Get one device.",
			Requires:  "Registry",
			available: has(func(o Options) bool { return o.Registry != nil }),
			handler:   func(s *Server) handlerFunc { return s.getDevice },
		},
		{
			ID:     "createDevice",
			Method: "POST", Path: "/devices",
			Summary:   "Create a device.",
			Action:    plugin.ActionAdminDevices,
			Requires:  "RegistryAdmin",
			available: has(func(o Options) bool { return o.RegistryAdmin != nil }),
			handler:   func(s *Server) handlerFunc { return s.createDevice },
		},
		{
			ID:     "replaceDevice",
			Method: "PUT", Path: "/devices/{id}",
			Summary:   "Replace a device's record.",
			Action:    plugin.ActionAdminDevices,
			Requires:  "RegistryAdmin",
			available: has(func(o Options) bool { return o.RegistryAdmin != nil }),
			handler:   func(s *Server) handlerFunc { return s.updateDevice },
		},
		{
			ID:     "deleteDevice",
			Method: "DELETE", Path: "/devices/{id}",
			Summary:   "Delete a device.",
			Action:    plugin.ActionAdminDevices,
			Requires:  "RegistryAdmin",
			available: has(func(o Options) bool { return o.RegistryAdmin != nil }),
			handler:   func(s *Server) handlerFunc { return s.deleteDevice },
		},
		{
			ID:     "getDeviceAccess",
			Method: "GET", Path: "/devices/{id}/access",
			Summary:  "List who may reach and who may administer a device.",
			Action:   plugin.ActionAdminPermissions,
			Requires: "Permissions and Registry",
			available: has(func(o Options) bool {
				return o.Permissions != nil && o.Registry != nil
			}),
			handler: func(s *Server) handlerFunc { return s.deviceAccess },
		},
		{
			ID:     "getPrincipalAccess",
			Method: "GET", Path: "/principals/{id}/access",
			Summary:   "List the rules that apply to one principal.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.principalAccess },
		},

		// ── running things on a device ──
		{
			ID:     "execOnDevice",
			Method: "POST", Path: "/devices/{id}/exec",
			Summary:  "Run one allow-listed command on a device and return its output.",
			Action:   plugin.ActionExec,
			Requires: "Registry and Inviter",
			available: has(func(o Options) bool {
				return o.Registry != nil && o.Inviter != nil
			}),
			handler: func(s *Server) handlerFunc { return s.execOnDevice },
		},
		{
			ID:     "readDeviceFile",
			Method: "GET", Path: "/devices/{id}/file",
			Summary:  "Read one file from under the device's configured root.",
			Action:   plugin.ActionFileRead,
			Requires: "Registry and Inviter",
			available: has(func(o Options) bool {
				return o.Registry != nil && o.Inviter != nil
			}),
			handler: func(s *Server) handlerFunc { return s.readFileOnDevice },
		},
		{
			ID:     "writeDeviceFile",
			Method: "PUT", Path: "/devices/{id}/file",
			Summary:  "Write one file under the device's configured root.",
			Action:   plugin.ActionFileWrite,
			Requires: "Registry and Inviter",
			available: has(func(o Options) bool {
				return o.Registry != nil && o.Inviter != nil
			}),
			handler: func(s *Server) handlerFunc { return s.writeFileOnDevice },
		},

		// ── permissions ──
		{
			ID:     "listPermissions",
			Method: "GET", Path: "/permissions",
			Summary:   "List authorisation grants.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.listPermissions },
		},
		{
			ID:     "getPermission",
			Method: "GET", Path: "/permissions/{id}",
			Summary:   "Get one grant.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.getPermission },
		},
		{
			ID:     "createPermission",
			Method: "POST", Path: "/permissions",
			Summary:   "Create a grant.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.createPermission },
		},
		{
			ID:     "replacePermission",
			Method: "PUT", Path: "/permissions/{id}",
			Summary:   "Replace a grant.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.updatePermission },
		},
		{
			ID:     "deletePermission",
			Method: "DELETE", Path: "/permissions/{id}",
			Summary:   "Delete a grant.",
			Action:    plugin.ActionAdminPermissions,
			Requires:  "Permissions",
			available: has(func(o Options) bool { return o.Permissions != nil }),
			handler:   func(s *Server) handlerFunc { return s.deletePermission },
		},

		// ── agents ──
		{
			ID:     "listAgents",
			Method: "GET", Path: "/agents",
			Summary:   "List devices holding a control channel on this node.",
			Requires:  "Agents",
			available: has(func(o Options) bool { return o.Agents != nil }),
			handler:   func(s *Server) handlerFunc { return s.listAgents },
		},
		{
			ID:     "disconnectAgent",
			Method: "DELETE", Path: "/agents/{id}",
			Summary:   "Drop a device's control channel.",
			Action:    plugin.ActionAdminKill,
			Requires:  "Agents",
			available: has(func(o Options) bool { return o.Agents != nil }),
			handler:   func(s *Server) handlerFunc { return s.disconnectAgent },
		},

		// ── recordings ──
		{
			ID:     "getRecording",
			Method: "GET", Path: "/recordings/{id}",
			Summary:   "Fetch a session recording with its manifest and a verdict.",
			Action:    plugin.ActionReplay,
			Requires:  "Replays",
			available: has(func(o Options) bool { return o.Replays != nil }),
			handler:   func(s *Server) handlerFunc { return s.getRecording },
		},

		// ── the operational database ──
		{
			ID:     "getSSHConnection",
			Method: "GET", Path: "/ssh",
			Summary:   "Get this gateway's SSH host details, for a client to pin.",
			Requires:  "SSH",
			available: has(func(o Options) bool { return o.SSH != nil }),
			handler:   func(s *Server) handlerFunc { return s.sshConnection },
		},
		{
			ID:     "getSQLSchema",
			Method: "GET", Path: "/sql/schema",
			Summary:   "Describe the curated read-only operational schema.",
			Action:    plugin.ActionSQLRead,
			Requires:  "SQL",
			available: has(func(o Options) bool { return o.SQL != nil }),
			handler:   func(s *Server) handlerFunc { return s.sqlSchema },
		},
		{
			ID:     "runSQLQuery",
			Method: "POST", Path: "/sql/query",
			Summary:   "Run a read-only query against the operational database.",
			Action:    plugin.ActionSQLRead,
			Requires:  "SQL",
			available: has(func(o Options) bool { return o.SQL != nil }),
			handler:   func(s *Server) handlerFunc { return s.sqlQuery },
		},
	}
}

// handlerFunc is the shape every API handler has: the principal is resolved by wrap before
// the handler runs, so no handler authenticates for itself.
type handlerFunc = func(http.ResponseWriter, *http.Request, *plugin.Principal)

// Routes returns the API surface as data, for the OpenAPI generator and its drift test.
//
// Exported because the generator lives outside this package — it is a build-time tool, and
// putting it here would mean the server binary carried a YAML writer it never uses.
func Routes() []RouteInfo {
	all := routes()
	out := make([]RouteInfo, 0, len(all))
	for _, r := range all {
		out = append(out, RouteInfo{
			Method: r.Method, Path: Prefix + r.Path, Summary: r.Summary,
			Action: string(r.Action), Requires: r.Requires,
			OperationID: r.ID,
			Optional:    r.Requires != "",
		})
	}
	return out
}

// RouteInfo is one endpoint, described.
type RouteInfo struct {
	Method      string
	Path        string
	Summary     string
	Action      string
	Requires    string
	OperationID string
	// Optional says the route exists only in a deployment that configured what it needs.
	Optional bool
}
