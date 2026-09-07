// The device form — add and edit, moved from `App.tsx` verbatim. Whether it is adding or
// editing is a fact about the `device` prop, not two components: the same fields, the same
// validation, the same drawer chrome either way.
//
// Two callers own this dialog now instead of one: `SearchPage` opens it with no `device`
// for "Add device", and `DevicePage` opens it with the device already on screen for "Edit".
// Each owns its own open/closed state and its own save handler — this file only renders the
// form and converts what it collected into the shape the API wants.

import { useEffect, useState } from "react";
import { ApiError, type Device } from "../../api";
import { FieldLabel } from "./Field";

export type DeviceForm = {
  id: string;
  platform: Device["platform"];
  mode: NonNullable<Device["mode"]>;
  keys: string;
  retiredKeys: string;
  tags: string;
  profiles: string;
  enabled: boolean;
  allowPassthrough: boolean;
};

const emptyDeviceForm: DeviceForm = {
  id: "",
  platform: "android",
  mode: "dispatch",
  keys: "",
  retiredKeys: "",
  tags: "",
  profiles: "shell",
  enabled: true,
  allowPassthrough: false,
};

function splitList(value: string): string[] {
  return value.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseTags(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of splitList(value)) {
    const [key, ...rest] = part.split("=");
    const name = key?.trim();
    if (!name) continue;
    out[name] = rest.join("=").trim();
  }
  return out;
}

function formatEditableTags(tags: Record<string, string> | undefined): string {
  return Object.entries(tags ?? {}).map(([key, value]) => `${key}=${value}`).join(", ");
}

/** Seeds the form from an existing device — the "Edit" path's starting point. */
export function formFromDevice(device: Device): DeviceForm {
  return {
    id: device.id,
    platform: device.platform,
    mode: device.mode ?? "",
    keys: (device.keys ?? []).join(", "),
    retiredKeys: (device.retired_keys ?? []).join(", "),
    tags: formatEditableTags(device.tags),
    profiles: (device.profiles ?? []).join(", "),
    enabled: device.enabled !== false,
    allowPassthrough: device.allow_passthrough === true,
  };
}

/** Converts what the form collected into the payload `createDevice`/`updateDevice` send. */
export function devicePayload(input: DeviceForm): Partial<Device> {
  return {
    id: input.id.trim(),
    platform: input.platform,
    mode: input.mode,
    keys: splitList(input.keys),
    retired_keys: splitList(input.retiredKeys),
    tags: parseTags(input.tags),
    profiles: splitList(input.profiles),
    enabled: input.enabled,
    allow_passthrough: input.allowPassthrough,
  };
}

export function deviceOperationError(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}

function DeviceFormEditor({
  initial,
  editing,
  onSave,
  onDone,
}: {
  initial: DeviceForm;
  editing: boolean;
  onSave: (input: DeviceForm) => Promise<string | null>;
  onDone: () => void;
}) {
  const [form, setForm] = useState<DeviceForm>(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  return (
    <form
      className="grid grid-cols-[minmax(0,1fr)] gap-4"
      onSubmit={async (e) => {
        e.preventDefault();
        setSaving(true);
        setError("");
        const saveError = await onSave(form);
        setSaving(false);
        if (!saveError) {
          onDone();
        } else {
          setError(saveError);
        }
      }}
    >
      <FieldLabel label="Device ID">
        <input
          className="field mono"
          placeholder="treadmill-4821"
          value={form.id}
          onChange={(e) => setForm({ ...form, id: e.target.value })}
          disabled={editing}
          required
        />
      </FieldLabel>
      <div className="grid grid-cols-2 gap-3">
        <FieldLabel label="Platform">
          <select
            className="field"
            value={form.platform}
            onChange={(e) => setForm({ ...form, platform: e.target.value as Device["platform"] })}
          >
            <option value="android">Android</option>
            <option value="linux">Linux</option>
            <option value="container">Container</option>
            <option value="other">Other</option>
          </select>
        </FieldLabel>
        <FieldLabel label="Mode">
          <select
            className="field"
            value={form.mode}
            onChange={(e) => setForm({ ...form, mode: e.target.value as DeviceForm["mode"] })}
          >
            <option value="dispatch">Dispatch</option>
            <option value="persistent">Persistent</option>
            <option value="">Platform default</option>
          </select>
        </FieldLabel>
      </div>
      <FieldLabel label="Public keys">
        <textarea
          className="field mono"
          placeholder="ssh-ed25519..."
          rows={3}
          value={form.keys}
          onChange={(e) => setForm({ ...form, keys: e.target.value })}
        />
        <span className="text-sm text-fg-faint">Comma-separated authorized public keys.</span>
      </FieldLabel>
      <FieldLabel label="Retired keys">
        <textarea
          className="field mono"
          placeholder="Keys that must no longer authenticate"
          rows={2}
          value={form.retiredKeys}
          onChange={(e) => setForm({ ...form, retiredKeys: e.target.value })}
        />
      </FieldLabel>
      <FieldLabel label="Profiles">
        <input
          className="field"
          placeholder="shell"
          value={form.profiles}
          onChange={(e) => setForm({ ...form, profiles: e.target.value })}
        />
      </FieldLabel>
      <FieldLabel label="Tags">
        <input
          className="field"
          placeholder="fleet=qa"
          value={form.tags}
          onChange={(e) => setForm({ ...form, tags: e.target.value })}
        />
      </FieldLabel>
      <label className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
        <span>
          <span className="block text-sm font-medium">Enabled</span>
          <span className="block text-sm text-fg-muted">Allow agent authentication and new sessions.</span>
        </span>
        <input
          type="checkbox"
          className="mt-1 size-4 accent-current"
          checked={form.enabled}
          onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
        />
      </label>
      <label className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
        <span>
          <span className="block text-sm font-medium">Allow passthrough</span>
          <span className="block text-sm text-fg-muted">Permit explicitly unrecorded sessions for this device.</span>
        </span>
        <input
          type="checkbox"
          className="mt-1 size-4 accent-current"
          checked={form.allowPassthrough}
          onChange={(event) => setForm({ ...form, allowPassthrough: event.target.checked })}
        />
      </label>
      {error && (
        <p className="rounded-md border border-state-refused/50 p-3 text-sm text-state-refused" role="alert">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2 border-t border-border pt-4">
        <button className="btn" type="button" onClick={onDone}>Cancel</button>
        <button className="btn btn-primary" type="submit" disabled={saving}>
          {saving ? "Saving..." : editing ? "Save changes" : "Add device"}
        </button>
      </div>
    </form>
  );
}

export function DeviceDialog({
  device,
  onClose,
  onSave,
}: {
  device?: Device;
  onClose: () => void;
  onSave: (input: DeviceForm) => Promise<string | null>;
}) {
  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" role="presentation" onMouseDown={onClose}>
      <section
        className="h-full w-full max-w-md overflow-y-auto border-l border-border bg-bg-raised p-6 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <h2 id="device-dialog-title" className="text-lg font-semibold">
              {device ? "Edit device" : "Add device"}
            </h2>
            <p className="mt-1 text-sm text-fg-muted">
              {device ? `Update ${device.id} without losing its session history.` : "Register a target before its agent connects."}
            </p>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close add device dialog" title="Close">
            <span aria-hidden="true">x</span>
          </button>
        </div>
        <DeviceFormEditor
          initial={device ? formFromDevice(device) : emptyDeviceForm}
          editing={Boolean(device)}
          onSave={onSave}
          onDone={onClose}
        />
      </section>
    </div>
  );
}
