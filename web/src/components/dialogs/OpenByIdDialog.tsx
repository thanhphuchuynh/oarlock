// Opening a shell on a device id you typed, moved from `App.tsx` verbatim.
//
// The secondary path, on purpose: from the fleet list you pick a row and never retype an
// id. This is for the id you already know and the row you cannot see — a fleet longer than
// a page, or an id that is not registered at all, which is a journey worth keeping
// reachable because the gateway has a screen for it. `SearchPage` is its only caller now:
// the fleet list it sits beside is the thing this dialog is an alternative to.

import { useEffect } from "react";
import { FieldLabel } from "./Field";

export function OpenByIdDialog({
  value,
  onChange,
  onClose,
  onOpen,
}: {
  value: { device: string; reason: string };
  onChange: (next: { device: string; reason: string }) => void;
  onClose: () => void;
  onOpen: () => void;
}) {
  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 sm:items-center"
      role="presentation"
      onMouseDown={onClose}
    >
      <form
        className="w-full max-w-md rounded-lg border border-border bg-bg-raised p-6 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="open-by-id-title"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault();
          onOpen();
        }}
      >
        <h2 id="open-by-id-title" className="text-lg font-semibold">
          Open by device id
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          For a device that is not in front of you. The session is recorded and attributed
          the same way either way.
        </p>
        <div className="mt-4 grid gap-3">
          <FieldLabel label="Device id">
            <input
              className="field mono"
              placeholder="treadmill-4821"
              value={value.device}
              onChange={(event) => onChange({ ...value, device: event.target.value })}
              data-testid="open-by-id-device"
              autoFocus
            />
          </FieldLabel>
          <FieldLabel label="Reason">
            <input
              className="field"
              placeholder="ticket or reason"
              value={value.reason}
              onChange={(event) => onChange({ ...value, reason: event.target.value })}
              data-testid="open-by-id-reason"
            />
          </FieldLabel>
        </div>
        <div className="mt-5 flex justify-end gap-2 border-t border-border pt-4">
          <button className="btn" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!value.device.trim()}
            data-testid="open-by-id-submit"
          >
            Open
          </button>
        </div>
      </form>
    </div>
  );
}
