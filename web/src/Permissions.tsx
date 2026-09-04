import { useEffect, useState, type ReactNode } from "react";
import { ApiError, Client, type Permission } from "./api";

type PermissionForm = {
  id: string;
  name: string;
  principals: string;
  devices: string;
  tags: string;
  actions: string;
  effect: Permission["effect"];
  reason: string;
  priority: number;
  enabled: boolean;
  maxDuration: string;
  idle: string;
  ttl: string;
};

const emptyForm: PermissionForm = {
  id: "",
  name: "",
  principals: "",
  devices: "*",
  tags: "",
  actions: "shell",
  effect: "allow",
  reason: "",
  priority: 0,
  enabled: true,
  maxDuration: "",
  idle: "",
  ttl: "",
};

function split(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function tags(value: string): Record<string, string> {
  return Object.fromEntries(split(value).map((item) => {
    const [key, ...rest] = item.split("=");
    return [key!.trim(), rest.join("=").trim()];
  }).filter(([key]) => key));
}

function editableTags(value: Record<string, string>): string {
  return Object.entries(value ?? {}).map(([key, item]) => `${key}=${item}`).join(", ");
}

function formFrom(permission: Permission): PermissionForm {
  return {
    id: permission.id,
    name: permission.name,
    principals: permission.principals.join(", "),
    devices: permission.devices.join(", "),
    tags: editableTags(permission.tags),
    actions: permission.actions.join(", "),
    effect: permission.effect,
    reason: permission.reason,
    priority: permission.priority,
    enabled: permission.enabled,
    maxDuration: permission.max_duration ?? "",
    idle: permission.idle ?? "",
    ttl: permission.ttl ?? "",
  };
}

function payload(form: PermissionForm): Partial<Permission> {
  return {
    id: form.id.trim(),
    name: form.name.trim(),
    principals: split(form.principals),
    devices: split(form.devices),
    tags: tags(form.tags),
    actions: split(form.actions),
    effect: form.effect,
    reason: form.reason.trim(),
    priority: form.priority,
    enabled: form.enabled,
    max_duration: form.maxDuration.trim(),
    idle: form.idle.trim(),
    ttl: form.ttl.trim(),
  };
}

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}

export function Permissions({ client }: { client: Client }) {
  const [items, setItems] = useState<Permission[]>([]);
  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState<Permission | "new" | null>(null);
  const [error, setError] = useState("");
  // A refusal is not an empty policy, and the two must not render the same. An empty
  // table under an "Add permission" button says there are no rules; what actually
  // happened is that reading them is somebody else's job.
  const [refused, setRefused] = useState<ApiError | null>(null);

  async function refresh() {
    try {
      const response = await client.permissions();
      setItems(response.permissions);
      setError("");
      setRefused(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "not_authorized") {
        setItems([]);
        setError("");
        setRefused(caught);
        return;
      }
      setError(errorText(caught));
    }
  }

  useEffect(() => {
    void refresh();
  }, [client]);

  const matching = items.filter((permission) => {
    const needle = query.trim().toLowerCase();
    return !needle || [permission.id, permission.name, permission.effect,
      ...permission.principals, ...permission.devices, ...permission.actions]
      .some((value) => value.toLowerCase().includes(needle));
  });

  // Denials first. A matching deny beats every allow wherever it sits in the store, so a
  // table ordered by creation date is actively misleading: it reads top-to-bottom like a
  // precedence list and is not one. `deny-pci` — every principal, every device, every
  // action — used to be the last row on the page.
  const visible = [
    ...matching.filter((p) => p.effect === "deny"),
    ...matching.filter((p) => p.effect !== "deny"),
  ];
  const denials = matching.filter((p) => p.effect === "deny").length;

  async function save(form: PermissionForm): Promise<string | null> {
    try {
      if (editing === "new") {
        await client.createPermission(payload(form));
      } else {
        await client.updatePermission(form.id, payload(form));
      }
      await refresh();
      return null;
    } catch (caught) {
      return errorText(caught);
    }
  }

  async function toggle(permission: Permission) {
    try {
      await client.updatePermission(permission.id, { ...permission, enabled: !permission.enabled });
      await refresh();
    } catch (caught) {
      setError(errorText(caught));
    }
  }

  async function remove(permission: Permission) {
    if (!confirm(`Delete ${permission.name || permission.id}?\n\nNew authorization checks will no longer use it.`)) return;
    try {
      await client.deletePermission(permission.id);
      await refresh();
    } catch (caught) {
      setError(errorText(caught));
    }
  }

  return (
    <section className="panel" data-testid="permissions">
      <div className="panel-header flex-wrap">
        {/* The page already has a heading. This said the same thing again in a smaller
            type size, on every page, which is how a header stops being read. */}
        <p className="text-sm text-fg-muted">
          <span className="font-semibold text-fg">{items.length}</span>
          {items.length === 1 ? " rule" : " rules"}
          {denials > 0 && ` · ${denials} ${denials === 1 ? "denial" : "denials"}, which outrank every allow`}
        </p>
        {!refused && (
          <div className="flex w-full gap-2 sm:w-auto">
            <input className="field min-w-0 sm:w-60" placeholder="Search permissions"
              aria-label="Search permissions" value={query} onChange={(event) => setQuery(event.target.value)} />
            <button className="btn btn-primary whitespace-nowrap" onClick={() => setEditing("new")}>Add permission</button>
          </div>
        )}
      </div>
      {error && <p className="border-t border-border p-4 text-sm text-state-refused" role="alert">{error}</p>}
      {refused ? (
        <div className="border-t border-border p-4" role="alert" data-testid="permissions-refused">
          <p className="text-sm font-medium">{refused.condition.headline}</p>
          <p className="mt-1 text-sm text-fg-muted">
            {refused.detail || refused.condition.nextAction}
          </p>
          <p className="mt-2 text-sm text-fg-faint">
            Reading the policy needs the <span className="mono">admin:permissions</span> action
            on <span className="mono">gateway</span>.
          </p>
        </div>
      ) : (
      <div className="overflow-x-auto border-t border-border">
        <table className="w-full border-collapse text-left">
          <thead className="bg-bg-raised text-sm uppercase tracking-wider text-fg-faint">
            <tr>
              <th className="px-3 py-2 font-medium">Effect</th>
              <th className="px-3 py-2 font-medium">Permission</th>
              <th className="px-3 py-2 font-medium">Principals</th>
              <th className="hidden px-3 py-2 font-medium md:table-cell">Devices</th>
              <th className="hidden px-3 py-2 font-medium lg:table-cell">Actions</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {visible.map((permission) => {
              const deny = permission.effect === "deny";
              return (
              <tr
                className={`border-t border-border align-middle hover:bg-bg-raised/60 ${
                  permission.enabled ? "" : "opacity-55"
                }`}
                key={permission.id}
                data-permission={permission.id}
              >
                {/* Effect leads the row. It is the first thing that decides what the rest
                    of the line means, and a deny that reads as an aside in column two is
                    a deny somebody skims past. */}
                <td className="px-3 py-3">
                  <span
                    className={`text-[11px] font-semibold uppercase tracking-wider ${
                      deny ? "text-state-refused" : "text-state-recorded"
                    }`}
                  >
                    {deny ? "Deny" : "Allow"}
                  </span>
                </td>
                <td className="px-3 py-3">
                  <div className="font-medium">{permission.name || permission.id}</div>
                  <div className="mono mt-0.5 text-sm text-fg-faint">{permission.id}</div>
                  {/* One word for the state, next to the thing it is the state of. It
                      used to be a column reading "Enabled" beside a button reading
                      "Disable" — two words a foot apart meaning the same thing. */}
                  {!permission.enabled && (
                    <div className="mt-1 text-sm text-fg-faint">Disabled — not consulted</div>
                  )}
                  {deny && permission.reason && (
                    <div className="mt-1 max-w-[40ch] text-sm text-state-refused">{permission.reason}</div>
                  )}
                </td>
                <td className="mono max-w-64 px-3 py-3 text-sm text-fg-muted">{permission.principals.join(", ")}</td>
                <td className="mono hidden max-w-64 px-3 py-3 text-sm text-fg-muted md:table-cell">
                  {permission.devices.length ? permission.devices.join(", ") : "*"}
                </td>
                <td className="mono hidden px-3 py-3 text-sm text-fg-muted lg:table-cell">{permission.actions.join(", ")}</td>
                <td className="px-3 py-3 text-right">
                  {/* Routine actions read as text; the destructive one is separated from
                      them and is the only coloured control in the row. */}
                  <div className="flex justify-end gap-1">
                    <button className="btn btn-quiet" onClick={() => void toggle(permission)}>{permission.enabled ? "Disable" : "Enable"}</button>
                    <button className="btn btn-quiet" onClick={() => setEditing(permission)}>Edit</button>
                    <button className="btn btn-danger ml-1" onClick={() => void remove(permission)}>Delete</button>
                  </div>
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
        {visible.length === 0 && (
          <p className="p-10 text-center text-sm text-fg-muted">
            {items.length ? "No permissions match this search." : "No permissions are configured."}
          </p>
        )}
      </div>
      )}
      {editing && (
        <PermissionDrawer {...(editing === "new" ? {} : { permission: editing })}
          onClose={() => setEditing(null)} onSave={save} />
      )}
    </section>
  );
}

function PermissionDrawer({ permission, onClose, onSave }: {
  permission?: Permission;
  onClose: () => void;
  onSave: (form: PermissionForm) => Promise<string | null>;
}) {
  const [form, setForm] = useState(permission ? formFrom(permission) : emptyForm);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/35" role="presentation" onMouseDown={onClose}>
      <section className="h-full w-full max-w-lg overflow-y-auto border-l border-border bg-bg-raised p-6 shadow-2xl"
        role="dialog" aria-modal="true" aria-labelledby="permission-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}>
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <h2 id="permission-dialog-title" className="text-lg font-semibold">{permission ? "Edit permission" : "Add permission"}</h2>
            <p className="mt-1 text-sm text-fg-muted">Changes apply to new checks immediately.</p>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close permission dialog" title="Close">x</button>
        </div>
        <form className="grid gap-4" onSubmit={async (event) => {
          event.preventDefault();
          setSaving(true);
          setError("");
          const failure = await onSave(form);
          setSaving(false);
          if (failure) setError(failure); else onClose();
        }}>
          <div className="grid grid-cols-2 gap-3">
            <Label label="Permission ID"><input className="field mono" placeholder="support-shell" required disabled={Boolean(permission)}
              value={form.id} onChange={(event) => setForm({ ...form, id: event.target.value })} /></Label>
            <Label label="Name"><input className="field" placeholder="Support shell" value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })} /></Label>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Label label="Effect"><select className="field" value={form.effect}
              onChange={(event) => setForm({ ...form, effect: event.target.value as Permission["effect"] })}>
              <option value="allow">Allow</option><option value="deny">Deny</option>
            </select></Label>
            <Label label="Priority"><input className="field mono" type="number" value={form.priority}
              onChange={(event) => setForm({ ...form, priority: Number(event.target.value) })} /></Label>
          </div>
          <Label label="Principals"><input className="field mono" required placeholder="admin@mail.com, *@oncall.example.com"
            value={form.principals} onChange={(event) => setForm({ ...form, principals: event.target.value })} /></Label>
          <Label label="Devices"><input className="field mono" placeholder="samsung-*, treadmill-*"
            value={form.devices} onChange={(event) => setForm({ ...form, devices: event.target.value })} /></Label>
          <Label label="Device tags"><input className="field mono" placeholder="fleet=qa, region=us"
            value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} /></Label>
          <Label label="Actions"><input className="field mono" required placeholder="shell, exec"
            value={form.actions} onChange={(event) => setForm({ ...form, actions: event.target.value })} /></Label>
          <div className="grid grid-cols-3 gap-3">
            <Label label="Max duration"><input className="field mono" placeholder="15m" value={form.maxDuration}
              onChange={(event) => setForm({ ...form, maxDuration: event.target.value })} /></Label>
            <Label label="Idle"><input className="field mono" placeholder="2m" value={form.idle}
              onChange={(event) => setForm({ ...form, idle: event.target.value })} /></Label>
            <Label label="Recheck TTL"><input className="field mono" placeholder="10s" value={form.ttl}
              onChange={(event) => setForm({ ...form, ttl: event.target.value })} /></Label>
          </div>
          <Label label="Denial reason"><textarea className="field" rows={2} placeholder="Change ticket required"
            value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} /></Label>
          <label className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
            <span><span className="block text-sm font-medium">Enabled</span>
              <span className="block text-sm text-fg-muted">Include this permission in authorization decisions.</span></span>
            <input type="checkbox" className="mt-1 size-4 accent-current" checked={form.enabled}
              onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />
          </label>
          {error && <p className="rounded-md border border-state-refused/50 p-3 text-sm text-state-refused" role="alert">{error}</p>}
          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <button className="btn" type="button" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" type="submit" disabled={saving}>{saving ? "Saving..." : "Save permission"}</button>
          </div>
        </form>
      </section>
    </div>
  );
}

function Label({ label, children }: { label: string; children: ReactNode }) {
  return <label className="flex flex-col gap-1"><span className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">{label}</span>{children}</label>;
}
