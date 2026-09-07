// The policy editor — list, add, edit, delete — moved from `Permissions.tsx`. The dialog
// that used to live at the bottom of that file is `components/dialogs/PermissionDialog`
// now; everything else here is unchanged, including the `permissions` and
// `permissions-refused` hooks the tests key off.

import { useEffect, useState } from "react";
import { ApiError, type Client, type Permission } from "../api";
import { PermissionDialog, permissionPayload, type PermissionForm } from "../components/dialogs/PermissionDialog";

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}

export function PermissionsPage({ client }: { client: Client }) {
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
        await client.createPermission(permissionPayload(form));
      } else {
        await client.updatePermission(form.id, permissionPayload(form));
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
        <PermissionDialog {...(editing === "new" ? {} : { permission: editing })}
          onClose={() => setEditing(null)} onSave={save} />
      )}
    </section>
  );
}
