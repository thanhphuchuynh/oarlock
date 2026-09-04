// The console's client for the control API.
//
// Thin on purpose: the API is the contract, and a client that reshapes its answers is a
// second place for the vocabulary to drift. Problem documents come back as they are, so a
// failure screen can render the condition the server named rather than one this file
// invented.

import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";

export interface Session {
  id: string;
  device_id: string;
  profile: string;
  mode: string;
  principal: string;
  state: string;
  recording_state: string;
  close_reason: string;
  exit_code: number | null;
  reason?: string;
  bytes_in: number;
  bytes_out: number;
  created_at: string;
  attached_at?: string;
  closed_at?: string;
  live: boolean;
  live_here: boolean;
}

export interface Attach {
  ticket: string;
  url: string;
  expires_at: string;
}

export interface Agent {
  device_id: string;
  connected: boolean;
}

export interface Device {
  id: string;
  platform: "android" | "linux" | "container" | "other";
  enabled: boolean;
  mode?: "persistent" | "dispatch" | "";
  resolved_mode: "persistent" | "dispatch";
  keys?: string[];
  retired_keys?: string[];
  allow_passthrough?: boolean;
  tags?: Record<string, string>;
  profiles?: string[];
  connected: boolean;
}

export interface Permission {
  id: string;
  name: string;
  principals: string[];
  devices: string[];
  tags: Record<string, string>;
  actions: string[];
  effect: "allow" | "deny";
  reason: string;
  priority: number;
  enabled: boolean;
  max_duration?: string;
  idle?: string;
  ttl?: string;
  created_at?: string;
  updated_at?: string;
}

/** Who can reach one device, and the vocabulary needed to read the answer. */
export interface DeviceAccess {
  device_id: string;
  rules: Permission[];
  /** Which actions are administrative, named by the gateway rather than guessed here. */
  admin_actions: string[];
}

/** What one principal was allowed to do — the Person page's second question. */
export interface PrincipalAccess {
  principal: string;
  rules: Permission[];
  /** Which actions are administrative, named by the gateway rather than guessed here. */
  admin_actions: string[];
}

/** A `/api/v1/sessions` query. Every field is optional, and an absent one is an absent
 *  URL parameter rather than an empty one — see `sessions()` below. */
export interface SessionQuery {
  principal?: string;
  since?: string;
  until?: string;
  device?: string;
  state?: string;
  limit?: number;
}

export interface SSHInfo {
  host: string;
  port: string;
  principal: string;
  host_key: string;
  known_hosts: string;
  fingerprint: string;
}

export interface SQLColumn {
  name: string;
  type: string;
}

export interface SQLTable {
  name: string;
  columns: SQLColumn[];
}

export interface SQLResult {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
  duration_ms: number;
}

/** ApiError carries the server's own condition, not a rephrasing of it. */
export class ApiError extends Error {
  readonly code: string;
  readonly condition: Condition;
  readonly reference: string;
  readonly status: number;
  readonly detail: string;

  constructor(status: number, body: Record<string, unknown>) {
    const code = String(body["code"] ?? body["type"] ?? "internal").replace(
      /^https?:\/\/\S+\/errors\//,
      "",
    );
    const condition = getCondition(code);
    super(String(body["title"] ?? condition.headline));
    this.status = status;
    this.code = code;
    this.condition = condition;
    this.reference = String(body["instance"] ?? "");
    this.detail = String(body["detail"] ?? "");
  }
}

/** How this gateway wants an operator to sign in. */
export type LoginMode = "oidc" | "token";

/**
 * loginMode asks the gateway which sign-in to render.
 *
 * Asked rather than guessed: a console that assumed one and fell back to the other would
 * flash the wrong screen on every load. Unauthenticated on purpose — "this gateway uses a
 * provider" is visible from the login page either way.
 */
export async function loginMode(base = ""): Promise<LoginMode> {
  try {
    const res = await fetch(base + "/auth/config", { headers: { Accept: "application/json" } });
    if (!res.ok) return "token";
    const body: unknown = await res.json();
    const login = (body as { login?: string }).login;
    return login === "oidc" ? "oidc" : "token";
  } catch {
    // A gateway with no browser login does not serve this at all.
    return "token";
  }
}

/**
 * collectHandoff picks up the token left by a completed sign-in, once.
 *
 * The callback set a one-hop cookie and redirected here; this exchanges it for the
 * provider's own id_token and the gateway clears the cookie in the same response. Returns
 * null on any load that did not just come back from a sign-in, which is most of them.
 */
export async function collectHandoff(base = ""): Promise<{ token: string; principal: string } | null> {
  try {
    const res = await fetch(base + "/auth/token", { method: "POST" });
    if (res.status !== 200) return null;
    const body = (await res.json()) as { token?: string; principal?: string };
    if (!body.token) return null;
    return { token: body.token, principal: body.principal ?? "" };
  } catch {
    return null;
  }
}

/** endSession clears whatever the gateway is holding for this browser. */
export async function endSession(base = ""): Promise<void> {
  try {
    await fetch(base + "/auth/logout", { method: "POST" });
  } catch {
    // Signing out locally is the part that matters; the gateway holds nothing durable.
  }
}

export class Client {
  constructor(
    private readonly base: string,
    private token: string,
  ) {}

  setToken(t: string) {
    this.token = t;
  }

  hasToken(): boolean {
    return this.token !== "";
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.base + path, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    const parsed: unknown = text ? JSON.parse(text) : {};
    if (!res.ok) {
      throw new ApiError(res.status, parsed as Record<string, unknown>);
    }
    return parsed as T;
  }

  /**
   * sessions lists sessions, optionally narrowed by principal, time range, device or
   * state.
   *
   * `query` is optional and every field within it is too, on purpose: `App.tsx`'s
   * `refresh()` calls this with no arguments at all, and that call has to keep producing
   * exactly `?limit=50` — the string increment 1's tests were written against — so a
   * caller that passes nothing gets nothing added to the query beyond the same default
   * limit. An absent facet is an absent parameter rather than `&since=`, so a hand-edited
   * link that omits one narrows on nothing rather than filtering on the empty string.
   */
  sessions(query?: SessionQuery): Promise<{ sessions: Session[] }> {
    const params = new URLSearchParams();
    params.set("limit", String(query?.limit ?? 50));
    if (query?.principal) params.set("principal", query.principal);
    if (query?.since) params.set("since", query.since);
    if (query?.until) params.set("until", query.until);
    // The wire parameter is `device_id` (apisrv.go's listSessions reads
    // r.URL.Query().Get("device_id")) — kept as `device` on this side only because
    // that is the vocabulary `route.facets` already uses.
    if (query?.device) params.set("device_id", query.device);
    if (query?.state) params.set("state", query.state);
    return this.call("GET", `/api/v1/sessions?${params.toString()}`);
  }

  agents(): Promise<{ agents: Agent[] }> {
    return this.call("GET", "/api/v1/agents");
  }

  devices(): Promise<{ devices: Device[] }> {
    return this.call("GET", "/api/v1/devices?limit=100");
  }

  createDevice(device: Partial<Device>): Promise<Device> {
    return this.call("POST", "/api/v1/devices", device);
  }

  updateDevice(id: string, device: Partial<Device>): Promise<Device> {
    return this.call("PUT", `/api/v1/devices/${encodeURIComponent(id)}`, device);
  }

  deleteDevice(id: string): Promise<unknown> {
    return this.call("DELETE", `/api/v1/devices/${encodeURIComponent(id)}`);
  }

  /** Who can reach one device, evaluated by the gateway's own matcher. */
  deviceAccess(id: string): Promise<DeviceAccess> {
    return this.call("GET", `/api/v1/devices/${encodeURIComponent(id)}/access`);
  }

  /** What one principal was allowed to do, evaluated by the gateway's own matcher.
   *  Encoded: a principal id routinely contains `@` and `.`. */
  principalAccess(id: string): Promise<PrincipalAccess> {
    return this.call("GET", `/api/v1/principals/${encodeURIComponent(id)}/access`);
  }

  permissions(): Promise<{ permissions: Permission[] }> {
    return this.call("GET", "/api/v1/permissions");
  }

  createPermission(permission: Partial<Permission>): Promise<Permission> {
    return this.call("POST", "/api/v1/permissions", permission);
  }

  updatePermission(id: string, permission: Partial<Permission>): Promise<Permission> {
    return this.call("PUT", `/api/v1/permissions/${encodeURIComponent(id)}`, permission);
  }

  deletePermission(id: string): Promise<unknown> {
    return this.call("DELETE", `/api/v1/permissions/${encodeURIComponent(id)}`);
  }

  sshInfo(): Promise<SSHInfo> {
    return this.call("GET", "/api/v1/ssh");
  }

  disconnectAgent(deviceID: string): Promise<unknown> {
    return this.call("DELETE", `/api/v1/agents/${encodeURIComponent(deviceID)}`);
  }

  sqlSchema(): Promise<{ tables: SQLTable[] }> {
    return this.call("GET", "/api/v1/sql/schema");
  }

  sqlQuery(query: string, limit = 200): Promise<SQLResult> {
    return this.call("POST", "/api/v1/sql/query", { query, limit });
  }

  session(id: string): Promise<Session> {
    return this.call("GET", `/api/v1/sessions/${encodeURIComponent(id)}`);
  }

  open(deviceID: string, reason: string, pty: { cols: number; rows: number }): Promise<{
    session: Session;
    attach: Attach;
  }> {
    return this.call("POST", "/api/v1/sessions", {
      device_id: deviceID,
      profile: "shell",
      reason,
      pty: { cols: pty.cols, rows: pty.rows, term: "xterm-256color" },
    });
  }

  /** renewAttach is what the terminal component's renewTicket callback calls. */
  renewAttach(id: string): Promise<Attach> {
    return this.call("POST", `/api/v1/sessions/${encodeURIComponent(id)}/attach`);
  }

  observe(id: string): Promise<Attach> {
    return this.call("POST", `/api/v1/sessions/${encodeURIComponent(id)}/observe`);
  }

  kill(id: string, reason: string): Promise<unknown> {
    return this.call("DELETE", `/api/v1/sessions/${encodeURIComponent(id)}?reason=${encodeURIComponent(reason)}`);
  }
}
