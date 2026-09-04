// Route parsing, with no DOM and no React.
//
// Split out so it can be tested in Node: the same reason the terminal package puts its
// disclosure policy behind its own subpath. Everything that touches `window` lives in
// useRouter.ts, and this file is the part with the decisions in it.

export type Facets = Partial<Record<"since" | "until" | "device" | "state" | "cursor", string>>;

export type Route =
  | { kind: "search" }
  | { kind: "person"; principal: string; facets: Facets }
  | { kind: "device"; device: string; facets: Facets }
  | { kind: "session"; session: string }
  | { kind: "permissions" }
  | { kind: "sql" };

// The closed set. An unrecognised parameter is dropped rather than carried, so a link
// cannot smuggle state the UI never validated.
const FACET_KEYS = ["since", "until", "device", "state", "cursor"] as const;

function readFacets(search: string): Facets {
  const out: Facets = {};
  const params = new URLSearchParams(search);
  for (const key of FACET_KEYS) {
    const value = params.get(key);
    if (value) out[key] = value;
  }
  return out;
}

export function parsePath(pathname: string, search = ""): Route {
  const parts = pathname.split("/").filter(Boolean);

  if (parts.length === 0) return { kind: "search" };
  if (parts.length === 1 && parts[0] === "permissions") return { kind: "permissions" };
  if (parts.length === 1 && parts[0] === "sql") return { kind: "sql" };

  if (parts.length === 2) {
    // decodeURIComponent throws on a malformed sequence — a hand-edited URL should land
    // on search, not crash the app.
    let id: string;
    try {
      id = decodeURIComponent(parts[1]!);
    } catch {
      return { kind: "search" };
    }
    if (!id) return { kind: "search" };
    if (parts[0] === "p") return { kind: "person", principal: id, facets: readFacets(search) };
    if (parts[0] === "d") return { kind: "device", device: id, facets: readFacets(search) };
    if (parts[0] === "s") return { kind: "session", session: id };
  }

  return { kind: "search" };
}

export function formatPath(route: Route): string {
  switch (route.kind) {
    case "search":
      return "/";
    case "permissions":
      return "/permissions";
    case "sql":
      return "/sql";
    case "session":
      return "/s/" + encodeURIComponent(route.session);
    case "person":
      return "/p/" + encodeURIComponent(route.principal) + query(route.facets);
    case "device":
      return "/d/" + encodeURIComponent(route.device) + query(route.facets);
  }
}

// Stable order, because the URL is something people paste to each other and compare.
// Two views of the same thing must produce byte-identical links.
function query(facets: Facets): string {
  const params = new URLSearchParams();
  for (const key of FACET_KEYS) {
    const value = facets[key];
    if (value) params.set(key, value);
  }
  const s = params.toString();
  return s ? "?" + s : "";
}
