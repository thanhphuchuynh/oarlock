import { useCallback, useSyncExternalStore } from "react";
import { formatPath, parsePath, type Route } from "./routes";

// The route lives in exactly one place: a module-level store, read through
// useSyncExternalStore rather than through this hook's own useState.
//
// The version that looks obviously fine — keep `route` in useState here and call
// setRoute inside navigate() — breaks the instant a second component calls useRouter().
// window.history.pushState() does not raise a `popstate` event, so the only component
// that would ever learn about the change is whichever one happened to call navigate();
// the app's nav rail, a page body, anything else subscribed would keep rendering
// whatever route was current the last time *it* rendered. A store outside React, with
// every subscriber reading the same snapshot, is what useSyncExternalStore is for.

// --- where this app is mounted -------------------------------------------------------
//
// cmd/oarlockd/app/app.go serves the built console under a path prefix —
// `mux.Handle("/ui/", ui.Handler("/ui"))` — but `pnpm dev:ui` serves the identical app at
// the site root. Vite's own `base` setting does not help here: it governs asset URLs
// ("./"), not the routes this hook parses. So the prefix is not a constant; it is
// answered once, when this module first loads, by looking at the address the browser is
// already sitting on.
const MOUNT_PREFIX = ((): string => {
  const { pathname } = window.location;
  return pathname === "/ui" || pathname.startsWith("/ui/") ? "/ui" : "";
})();

// Reverses MOUNT_PREFIX so `routes.ts` only ever sees an unprefixed path. A device or
// principal id that happens to start with "ui" is unaffected: the comparison is against
// the whole leading segment, so `/ui/d/ui` becomes `/d/ui`, not `/d/`.
function unmount(pathname: string): string {
  if (pathname === MOUNT_PREFIX) return "/";
  if (MOUNT_PREFIX !== "" && pathname.startsWith(MOUNT_PREFIX + "/")) {
    return pathname.slice(MOUNT_PREFIX.length);
  }
  return pathname;
}

function here(): string {
  return window.location.pathname + window.location.search;
}

// --- the store itself ------------------------------------------------------------------

type Listener = () => void;
const subscribers = new Set<Listener>();

function announce(): void {
  for (const notify of subscribers) notify();
}

// A single `popstate` listener does for every subscriber what N of them would do
// separately: it is attached once the first component asks for the route and removed
// once the last one stops caring.
function subscribe(onStoreChange: Listener): () => void {
  if (subscribers.size === 0) window.addEventListener("popstate", announce);
  subscribers.add(onStoreChange);
  return () => {
    subscribers.delete(onStoreChange);
    if (subscribers.size === 0) window.removeEventListener("popstate", announce);
  };
}

// React requires getSnapshot to return the identical value it returned last time unless
// something really changed, or it will treat every render as a change and loop forever.
// parsePath has no memory of its own — it builds a fresh object on every call — so the
// memoisation happens here, keyed on the URL string, which is the only thing that
// actually identifies "the same route" between one call and the next.
let memoisedURL: string | undefined;
let memoisedRoute: Route = { kind: "search" };

function getSnapshot(): Route {
  const url = here();
  if (url !== memoisedURL) {
    memoisedURL = url;
    memoisedRoute = parsePath(unmount(window.location.pathname), window.location.search);
  }
  return memoisedRoute;
}

// This app never runs outside a browser, so there is no real server render to answer
// for — but useSyncExternalStore's contract still asks for one, and reaching into
// `window` here would defeat the point of a *server* snapshot.
function getServerSnapshot(): Route {
  return { kind: "search" };
}

export function useRouter(): { route: Route; navigate: (to: Route | string, options?: { replace?: boolean }) => void } {
  const route = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const navigate = useCallback((to: Route | string, options?: { replace?: boolean }) => {
    // A string argument is a path some caller already formatted (or built to look like
    // one) — never a raw, already-mounted href. Either way the mount prefix is applied
    // exactly once, after this branch, so neither a caller building a Route nor one
    // building a string has to know whether the console is living under /ui today.
    const unmountedPath = typeof to === "string" ? to : formatPath(to);
    const target = MOUNT_PREFIX + unmountedPath;
    if (target === here()) return;

    if (options?.replace) {
      window.history.replaceState(null, "", target);
    } else {
      window.history.pushState(null, "", target);
    }
    // The line pushState itself will never trigger: every subscriber's only way to hear
    // about this navigation is this explicit call.
    announce();
    // A freshly opened page reads from the top. Without this, following a link from
    // partway down a long session list would open the next page partway down too.
    window.scrollTo(0, 0);
  }, []);

  return { route, navigate };
}
