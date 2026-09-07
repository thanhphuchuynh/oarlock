// The permission editor — add and edit a policy rule, moved from `Permissions.tsx`
// verbatim. `PermissionsPage` is its only caller.

import { useEffect, useState } from "react";
import type { Permission } from "../../api";
import { FieldLabel } from "./Field";

export type PermissionForm = {
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

export const emptyPermissionForm: PermissionForm = {
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

/** Seeds the form from an existing permission — the "Edit" path's starting point. */
export function formFromPermission(permission: Permission): PermissionForm {
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

/** Converts what the form collected into the payload `createPermission`/`updatePermission`
 *  send. */
export function permissionPayload(form: PermissionForm): Partial<Permission> {
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

export function PermissionDialog({ permission, onClose, onSave }: {
  permission?: Permission;
  onClose: () => void;
  onSave: (form: PermissionForm) => Promise<string | null>;
}) {
  const [form, setForm] = useState(permission ? formFromPermission(permission) : emptyPermissionForm);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" role="presentation" onMouseDown={onClose}>
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
            <FieldLabel label="Permission ID"><input className="field mono" placeholder="support-shell" required disabled={Boolean(permission)}
              value={form.id} onChange={(event) => setForm({ ...form, id: event.target.value })} /></FieldLabel>
            <FieldLabel label="Name"><input className="field" placeholder="Support shell" value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })} /></FieldLabel>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <FieldLabel label="Effect"><select className="field" value={form.effect}
              onChange={(event) => setForm({ ...form, effect: event.target.value as Permission["effect"] })}>
              <option value="allow">Allow</option><option value="deny">Deny</option>
            </select></FieldLabel>
            <FieldLabel label="Priority"><input className="field mono" type="number" value={form.priority}
              onChange={(event) => setForm({ ...form, priority: Number(event.target.value) })} /></FieldLabel>
          </div>
          <FieldLabel label="Principals"><input className="field mono" required placeholder="admin@mail.com, *@oncall.example.com"
            value={form.principals} onChange={(event) => setForm({ ...form, principals: event.target.value })} /></FieldLabel>
          <FieldLabel label="Devices"><input className="field mono" placeholder="samsung-*, treadmill-*"
            value={form.devices} onChange={(event) => setForm({ ...form, devices: event.target.value })} /></FieldLabel>
          <FieldLabel label="Device tags"><input className="field mono" placeholder="fleet=qa, region=us"
            value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} /></FieldLabel>
          <FieldLabel label="Actions"><input className="field mono" required placeholder="shell, exec"
            value={form.actions} onChange={(event) => setForm({ ...form, actions: event.target.value })} /></FieldLabel>
          <div className="grid grid-cols-3 gap-3">
            <FieldLabel label="Max duration"><input className="field mono" placeholder="15m" value={form.maxDuration}
              onChange={(event) => setForm({ ...form, maxDuration: event.target.value })} /></FieldLabel>
            <FieldLabel label="Idle"><input className="field mono" placeholder="2m" value={form.idle}
              onChange={(event) => setForm({ ...form, idle: event.target.value })} /></FieldLabel>
            <FieldLabel label="Recheck TTL"><input className="field mono" placeholder="10s" value={form.ttl}
              onChange={(event) => setForm({ ...form, ttl: event.target.value })} /></FieldLabel>
          </div>
          <FieldLabel label="Denial reason"><textarea className="field" rows={2} placeholder="Change ticket required"
            value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} /></FieldLabel>
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
