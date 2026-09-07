// One header per page, moved out of `App.tsx` — the wait, the session page and the
// full-page failure each carry their own heading (or none), so this renders nothing but
// the product name once `App` says none of the three list-like pages is current.

export function PageHeader({
  show,
  title,
  blurb,
  sheet,
  total,
}: {
  /** False while a wait, a session or a full-page failure owns the body. */
  show: boolean;
  title: string;
  blurb: string;
  sheet: number;
  total: number;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4 border-b border-border-strong pb-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold">{show ? title : "Oarlock"}</h1>
        {show && <p className="mt-1 text-sm text-fg-muted">{blurb}</p>}
      </div>
      {/* The title block. A sheet says which one it is out of how many, and the nav
          rail is that index. */}
      {show && (
        <p className="label shrink-0 text-right leading-relaxed">
          <span className="block text-fg">Sheet {sheet} of {total}</span>
          File no. OARLOCK-v0
        </p>
      )}
    </header>
  );
}
