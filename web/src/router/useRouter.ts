import { useCallback, useSyncExternalStore } from "react";
import { formatPath, parsePath, type Route } from "./routes";

// One store for the whole app, because the URL is one thing.
//
// The obvious version of this hook keeps the route in useState and calls setRoute inside
// navigate(). That is a bug the moment two components call useRouter(): pushState does
// not fire popstate, so only the component that navigated learns about it and every
// other one renders the previous route forever. useSyncExternalStore is the primitive
// for exactly this shape — one external source, every subscriber on one snapshot.

const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

// getSnapshot must return a referentially stable value or React re-renders forever, and
// parsePath builds a fresh object every call. So the parse is memoised on the URL
// string, which is the route's actual identity.
let cachedURL: string | null = null;
let cachedRoute: Route = { kind: "search" };

function snapshot(): Route {
  const url = window.location.pathname + window.location.search;
  if (url !== cachedURL) {
    cachedURL = url;
    cachedRoute = parsePath(window.location.pathname, window.location.search);
  }
  return cachedRoute;
}

// One popstate listener for N components rather than one each: the listener is attached
// when the first subscriber arrives and removed when the last leaves.
function subscribe(onChange: () => void): () => void {
  if (listeners.size === 0) window.addEventListener("popstate", emit);
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
    if (listeners.size === 0) window.removeEventListener("popstate", emit);
  };
}

// useSyncExternalStore requires a server snapshot. The console is client-rendered, but
// returning the client one would touch `window` where it may not exist.
const serverSnapshot = (): Route => ({ kind: "search" });

export function useRouter() {
  const route = useSyncExternalStore(subscribe, snapshot, serverSnapshot);

  const navigate = useCallback((to: Route | string, opts?: { replace?: boolean }) => {
    const path = typeof to === "string" ? to : formatPath(to);
    if (path === window.location.pathname + window.location.search) return;
    if (opts?.replace) window.history.replaceState(null, "", path);
    else window.history.pushState(null, "", path);
    // pushState does not fire popstate. This line is what tells every subscriber.
    emit();
    // A new page starts at the top. Without this, following a link from halfway down a
    // session list lands you halfway down the next page.
    window.scrollTo(0, 0);
  }, []);

  return { route, navigate };
}
