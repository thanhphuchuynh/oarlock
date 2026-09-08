// The nav rail — a sticky sidebar at desktop widths, a horizontal strip below `lg:`. Moved
// out of `App.tsx` because the two variants are markup, not logic: `App` still owns which
// page is current and what a click does about it, this file only draws the two shapes that
// selection can take.
//
// Renders unconditionally, on purpose: it is meant to stay reachable even while a wait or a
// full-page failure owns the body, which is why `App` clears those on the rail's own click
// rather than leaving it for an effect to notice.

export interface NavPageSpec {
  id: string;
  label: string;
}

export function NavRail({
  pages,
  section,
  me,
  onSelect,
  onSignOut,
}: {
  pages: readonly NavPageSpec[];
  section: string;
  me: string;
  onSelect: (id: string) => void;
  onSignOut: () => void;
}) {
  return (
    <>
      <aside className="hidden border-r border-border bg-bg-raised lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col lg:p-4">
        <div className="border-b border-border-strong px-2 pb-3">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 shrink-0 place-items-center border border-border-strong text-[11px] font-semibold leading-none tracking-[0.08em]">
              O<br />L
            </span>
            <span className="text-[13px] font-semibold uppercase leading-tight tracking-[0.1em]">
              Oarlock
            </span>
          </div>
          <p className="label mt-2">gateway-terminated ssh</p>
        </div>
        <nav className="mt-5 grid gap-1 text-sm" aria-label="Admin navigation">
          {pages.map((page) => (
            <button
              key={page.id}
              className={`nav-item text-left ${section === page.id ? "nav-item-active" : ""}`}
              onClick={() => onSelect(page.id)}
            >
              {page.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto border-t border-border px-2 pt-4">
          <p className="mono truncate text-sm text-fg-muted">{me || "operator"}</p>
          <button className="mt-2 text-sm font-medium text-fg-muted hover:text-fg" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="border-b border-border bg-bg-raised lg:hidden">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 shrink-0 place-items-center border border-border-strong text-[11px] font-semibold leading-none tracking-[0.08em]">
              O<br />L
            </span>
            <span className="text-[13px] font-semibold uppercase tracking-[0.14em]">
              Oarlock
            </span>
          </div>
          <button className="btn" onClick={onSignOut}>Sign out</button>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-4 pb-3 text-sm" aria-label="Admin navigation">
          {pages.map((page) => (
            <button
              key={page.id}
              className={`nav-item whitespace-nowrap ${section === page.id ? "nav-item-active" : ""}`}
              onClick={() => onSelect(page.id)}
            >
              {page.label}
            </button>
          ))}
        </nav>
      </div>
    </>
  );
}
