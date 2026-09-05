// Route parsing: a pure function of a path and a query string, nothing else.
//
// No `window`, no React — so it can run under Node the way `tests/unit/router.spec.ts`
// does, the same reason `@oarlock/terminal/disclosure` sits behind its own subpath rather
// than inside the component that uses it. Everything that actually reads the browser's
// address bar belongs in `useRouter.ts`; this file only says what a given address means.

// The closed set of query keys a route may carry. Closed on purpose: a URL is something
// an operator pastes to a colleague or bookmarks, and a parameter this list does not name
// is dropped rather than smuggled through to a page that never validated it.
const FACET_NAMES = ["since", "until", "device", "state", "cursor"] as const;
type FacetName = (typeof FACET_NAMES)[number];

export type Facets = Partial<Record<FacetName, string>>;

export type Route =
  | { kind: "search" }
  | { kind: "person"; principal: string; facets: Facets }
  | { kind: "device"; device: string; facets: Facets }
  | { kind: "session"; session: string }
  | { kind: "permissions" }
  | { kind: "sql" };

const SEARCH_ROUTE: Route = { kind: "search" };

/**
 * parsePath turns a pathname and a query string into a `Route`.
 *
 * Never throws: the gateway serves the same index page for every path, so a mistyped or
 * corrupted link arrives here rather than at a 404, and the one acceptable answer to
 * "I don't recognise this" is the search screen, not a crash.
 */
export function parsePath(pathname: string, search = ""): Route {
  const segments = pathname.split("/").filter((segment) => segment !== "");

  if (segments.length === 0) return SEARCH_ROUTE;

  if (segments.length === 1) {
    if (segments[0] === "permissions") return { kind: "permissions" };
    if (segments[0] === "sql") return { kind: "sql" };
    return SEARCH_ROUTE;
  }

  if (segments.length === 2) {
    const prefix = segments[0]!;
    const id = decodeSegment(segments[1]!);
    if (id === null) return SEARCH_ROUTE;

    if (prefix === "p") return { kind: "person", principal: id, facets: facetsFromSearch(search) };
    if (prefix === "d") return { kind: "device", device: id, facets: facetsFromSearch(search) };
    if (prefix === "s") return { kind: "session", session: id };
  }

  return SEARCH_ROUTE;
}

/** formatPath is parsePath's inverse: what to push onto the address bar for a `Route`. */
export function formatPath(route: Route): string {
  switch (route.kind) {
    case "search":
      return "/";
    case "permissions":
      return "/permissions";
    case "sql":
      return "/sql";
    case "session":
      return `/s/${encodeURIComponent(route.session)}`;
    case "person":
      return `/p/${encodeURIComponent(route.principal)}${facetsToSearch(route.facets)}`;
    case "device":
      return `/d/${encodeURIComponent(route.device)}${facetsToSearch(route.facets)}`;
  }
}

// A percent-escape a person typed by hand, or one a proxy mangled, can be malformed —
// decodeURIComponent throws rather than returning a best guess. Returning null instead of
// letting that exception reach the caller is what keeps a bad link a redirect to search
// instead of a blank page.
function decodeSegment(segment: string): string | null {
  try {
    const decoded = decodeURIComponent(segment);
    return decoded === "" ? null : decoded;
  } catch {
    return null;
  }
}

function facetsFromSearch(search: string): Facets {
  const params = new URLSearchParams(search);
  const facets: Facets = {};
  for (const name of FACET_NAMES) {
    const value = params.get(name);
    if (value) facets[name] = value;
  }
  return facets;
}

// The order is fixed by FACET_NAMES rather than by insertion order into `facets`: the URL
// is compared and pasted between people, so the same set of facets must always render as
// the same string no matter which order the caller built the object in.
function facetsToSearch(facets: Facets): string {
  const params = new URLSearchParams();
  for (const name of FACET_NAMES) {
    const value = facets[name];
    if (value) params.set(name, value);
  }
  const rendered = params.toString();
  return rendered ? `?${rendered}` : "";
}
