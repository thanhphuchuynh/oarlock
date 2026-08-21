// The two named waits — the moment between clicking Shell and getting a prompt.
//
// The UX spec calls this the defining experience, and it is: the gateway has to wake a
// device that may be asleep on a cellular radio, pair two connections, start a recording
// and hand over a terminal, and any of those can be slow or fail for a different reason
// with a different remedy.
//
// **Two named steps, never one spinner.** A step that is waiting says what it is waiting
// for and roughly how long is reasonable — a doorbell that takes twenty seconds is normal
// on a sleeping radio, a spinner cannot say that, and an operator who thinks the UI has
// hung will reload and open a second session. A progress bar would be worse still: a bar
// implies a knowable fraction and nothing here has one.
//
// **A failure replaces its own step, in place.** The step that failed *is* the diagnosis,
// so there is no generic error banner underneath.
//
// **On success the steps disappear.** They are scaffolding for a wait, not a log.

import type { Condition } from "@oarlock/terminal/conditions";

export type StepState = "pending" | "waiting" | "done" | "failed";

export interface Step {
  readonly key: string;
  readonly label: string;
  readonly state: StepState;
  /** Shown while waiting: what a reasonable wait looks like. */
  readonly budget?: string;
  /** Replaces the label when this step is the one that failed. */
  readonly failure?: Condition;
  readonly detail?: string;
}

const glyph: Record<StepState, string> = {
  pending: "○",
  waiting: "⟳",
  done: "✓",
  failed: "⊘",
};

const tone: Record<StepState, string> = {
  pending: "text-fg-faint",
  waiting: "text-state-reconnecting",
  done: "text-state-recorded",
  failed: "text-state-refused",
};

export function Waits({ steps, reference }: { steps: readonly Step[]; reference?: string }) {
  return (
    <div
      className="rounded-md border border-border bg-bg-raised p-4"
      role="status"
      aria-live="polite"
    >
      <ol className="flex flex-col gap-2">
        {steps.map((s) => (
          <li key={s.key} className="flex items-start gap-3">
            <span
              className={`${tone[s.state]} w-4 shrink-0 text-center`}
              aria-hidden="true"
            >
              {glyph[s.state]}
            </span>
            <span className="min-w-0 flex-1">
              {s.failure ? (
                <>
                  {/* The step that failed is the diagnosis: its own line becomes the
                      sentence, rather than a banner appearing somewhere else. */}
                  <span className="font-semibold text-fg">{s.failure.headline}</span>
                  {s.failure.nextAction && (
                    <span className="block text-fg-muted">{s.failure.nextAction}</span>
                  )}
                  {s.detail && (
                    <span className="mono block pt-1 text-xs text-fg-faint">{s.detail}</span>
                  )}
                </>
              ) : (
                <span className={s.state === "pending" ? "text-fg-faint" : "text-fg"}>
                  {s.label}
                </span>
              )}
            </span>
            {s.state === "waiting" && s.budget && (
              <span className="shrink-0 text-xs text-fg-faint">{s.budget}</span>
            )}
          </li>
        ))}
      </ol>
      {reference && (
        <p className="mono pt-3 text-xs text-fg-faint">
          {/* Present for the report, not shouted at the operator. */}
          <span className="not-mono">Reference (for support): </span>
          {reference}
        </p>
      )}
    </div>
  );
}
