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

  sessions(): Promise<{ sessions: Session[] }> {
    return this.call("GET", "/api/v1/sessions?limit=50");
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
