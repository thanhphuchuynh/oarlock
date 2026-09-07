// One labelled field, shared by every dialog below: a small caps label over whatever
// control it wraps. Used to be three near-identical copies — App.tsx's `FieldLabel` and
// Permissions.tsx's `Label` differed only in whether a caller could pass a className — now
// one definition, so a change to how a label reads applies to every dialog at once.

import type { ReactNode } from "react";

export function FieldLabel({
  label,
  className = "",
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <label className={"flex flex-col gap-1 " + className}>
      <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">
        {label}
      </span>
      {children}
    </label>
  );
}
