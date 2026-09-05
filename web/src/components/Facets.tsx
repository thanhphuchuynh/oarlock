// The facet chips — what is currently narrowing a timeline, each one removable. Shared
// between the Person and Device pages: every filter round-trips through the URL, because a
// page whose `since` lived only in component state would show a colleague something
// different from what the link they were sent promised.

import type { Facets as FacetValues } from "../router/routes";

export interface FacetSpec {
  readonly key: keyof FacetValues;
  readonly label: string;
}

/** Clearing a facet is not the same as it never having been set — a caller whose default
 *  re-lands the moment its facet is gone (the 30-day window, on both pages) has to decide
 *  that for itself in `onClear`; this component only ever renders what the URL already
 *  says. */
export function FacetBar({
  facets,
  specs,
  onClear,
  testId,
}: {
  facets: FacetValues;
  specs: readonly FacetSpec[];
  onClear: (key: FacetSpec["key"]) => void;
  testId: string;
}) {
  const active = specs.filter((f) => facets[f.key]);
  if (active.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid={testId}>
      {active.map((f) => (
        <span
          key={f.key}
          className="inline-flex items-center gap-1.5 border border-border px-2 py-1 text-sm"
        >
          <span className="text-fg-muted">{f.label}</span>
          <span className="mono">{facets[f.key]}</span>
          <button
            type="button"
            className="text-fg-faint hover:text-fg"
            aria-label={`Clear the ${f.label} filter`}
            onClick={() => onClear(f.key)}
          >
            ×
          </button>
        </span>
      ))}
    </div>
  );
}
