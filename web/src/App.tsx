// The admin console — the auth shell and the route switch, and nothing else. Everything
// else moved out: dialogs to `SearchPage`/`DevicePage`, fleet polling to `hooks/useFleet`,
// session-opening and `/s/{id}`'s own data loading to `pages/SessionRoute`. What stays is
// what must be reachable no matter which page is on screen: sign-in/out, the nav rail, and
// the three states — `opening`, `bypass`, `failure` — gating the whole body, not one page.

import { useEffect, useRef, useState } from "react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import { ApiError, Client, endSession, type Session } from "./api";
import { Waits } from "./components/Waits";
import { SignIn } from "./components/SignIn";
import { NavRail } from "./components/NavRail";
import { PageHeader } from "./components/PageHeader";
import { SessionPage } from "./pages/SessionPage";
import { PersonPage } from "./pages/PersonPage";
import { DevicePage } from "./pages/DevicePage";
import { SearchPage } from "./pages/SearchPage";
import { PermissionsPage } from "./pages/PermissionsPage";
import { SqlPage } from "./pages/SqlPage";
import { SessionRoute, openSession, openSessionRow, type Opening, type SessionBypass } from "./pages/SessionRoute";
import { useRouter } from "./router/useRouter";
import { useFleet } from "./hooks/useFleet";

const tokenKey = "oarlock.token";

// The three destinations on the nav rail. "Sessions" has no route of its own — a session
// is reached from a row, or the link in `route.session` — so it is not a page here either.
type NavPage = "search" | "permissions" | "sql";

const pages: { id: NavPage; label: string; blurb: string }[] = [
  { id: "search", label: "Search", blurb: "Look up a person, a device, or a session — or browse the fleet." },
  { id: "permissions", label: "Permissions", blurb: "Who may perform which actions on which devices." },
  { id: "sql", label: "SQL Explorer", blurb: "Read-only access to operational SQLite data." },
];

export function App() {
  // sessionStorage, not localStorage: a shared secret should not outlive the tab it was
  // typed into, and static tokens refuse to start outside dev anyway.
  const [token, setToken] = useState(() => sessionStorage.getItem(tokenKey) ?? "");
  const client = useRef(new Client("", token));
  client.current.setToken(token);

  const { route, navigate } = useRouter();
  const rendersFleet = route.kind === "search" || route.kind === "device";
  const { sessions, devices, me, setMe, listError, refresh } = useFleet(client.current, token, rendersFleet);

  // See `pages/SessionRoute.tsx`. `pushState` never fires `popstate`, so Back/Forward needs
  // its own listener below rather than an effect keyed on `route`, which would also fire
  // for `openSessionRow`'s own navigation and clear a wait still genuinely in flight.
  const [opening, setOpening] = useState<Opening | null>(null);
  const [failure, setFailure] = useState<{ condition: Condition; detail: string; reference: string } | null>(null);
  const [bypass, setBypass] = useState<SessionBypass | null>(null);

  useEffect(() => {
    const onPopState = () => {
      setOpening(null);
      setFailure(null);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  // A token exists now: from OIDC (which also names the principal) or a pasted static one
  // (principal unknown until `useFleet`'s own session list supplies it).
  function signedIn(t: string, principal: string) {
    if (principal) setMe(principal);
    sessionStorage.setItem(tokenKey, t);
    setToken(t);
  }

  // Shared by `DevicePage`'s "Open" button and `SearchPage`'s open-by-id dialog.
  const onOpen = (device: string, reason: string) =>
    void openSession({ client: client.current, device, reason, me, setMe, setOpening, setBypass, navigate, refresh: () => void refresh() });

  // Shared by `DevicePage` and `PersonPage`'s timelines; rejects rather than reporting to
  // `failure`, since the row that called it renders its own refusal in place.
  const onOpenSession = (session: Session): Promise<void> =>
    openSessionRow({ client: client.current, token, session, setBypass, navigate });

  function fail(err: unknown) {
    const e = err instanceof ApiError ? err : null;
    setFailure({ condition: e?.condition ?? getCondition("internal"), detail: e?.detail ?? String(err), reference: e?.reference ?? "" });
  }

  // SignIn owns everything about getting a token: which flavour to show, OIDC, the form.
  if (!token) return <SignIn onSignedIn={signedIn} />;

  const signOut = () => {
    void endSession(); // the gateway's one-hop cookie, then this tab's own token
    sessionStorage.removeItem(tokenKey);
    setToken("");
  };

  function goToPage(id: NavPage) {
    setOpening(null);
    setFailure(null);
    navigate({ kind: id });
  }

  const section: NavPage = route.kind === "person" || route.kind === "device" ? "search" : (route.kind as NavPage);
  // `section` is "session" for the one route with no nav entry of its own — `current` is
  // undefined exactly then, which is also exactly when `showChrome` (and so `PageHeader`'s
  // own `show`) is false, so the fallbacks below are never actually rendered.
  const current = pages.find((p) => p.id === section);
  const showChrome = !opening && !failure && route.kind !== "session";

  return (
    <div className="min-h-screen bg-bg lg:grid lg:grid-cols-[13.5rem_minmax(0,1fr)]">
      <NavRail pages={pages} section={section} me={me} onSelect={(id) => goToPage(id as NavPage)} onSignOut={signOut} />

      <main className="min-w-0">
        <div className="mx-auto flex max-w-[90rem] flex-col gap-6 p-4 sm:p-6 lg:p-8">
          <PageHeader
            show={showChrome}
            title={current?.label ?? "Oarlock"}
            blurb={current?.blurb ?? ""}
            sheet={pages.findIndex((p) => p.id === section) + 1}
            total={pages.length}
          />

          {showChrome && (
            <>
              {listError && (
                <p className="rounded-md border border-state-refused/50 bg-bg-raised p-4" role="alert">
                  <span className="font-semibold">{listError.headline}</span>{" "}
                  <span className="text-fg-muted">{listError.nextAction}</span>
                </p>
              )}
              {route.kind === "search" && (
                <SearchPage
                  client={client.current}
                  devices={devices}
                  sessions={sessions}
                  navigate={navigate}
                  onOpen={onOpen}
                  refresh={refresh}
                />
              )}
              {route.kind === "device" && (
                <DevicePage
                  client={client.current}
                  device={route.device}
                  devices={devices}
                  facets={route.facets}
                  navigate={navigate}
                  onOpen={onOpen}
                  onOpenSession={onOpenSession}
                  refresh={refresh}
                  onFail={fail}
                />
              )}
              {route.kind === "person" && (
                <PersonPage
                  client={client.current}
                  principal={route.principal}
                  facets={route.facets}
                  navigate={navigate}
                  onOpenSession={onOpenSession}
                />
              )}
              {route.kind === "permissions" && <PermissionsPage client={client.current} />}
              {route.kind === "sql" && <SqlPage client={client.current} />}
            </>
          )}
          {opening && (
            <section className="flex flex-col gap-4" data-testid="waits">
              <Waits steps={opening.steps} {...(opening.reference ? { reference: opening.reference } : {})} />
              <div><button className="btn" onClick={() => setOpening(null)}>Back</button></div>
            </section>
          )}
          {route.kind === "session" && !opening && !failure && (
            <SessionRoute
              client={client.current}
              token={token}
              id={route.session}
              bypass={bypass}
              onConsumeBypass={() => setBypass(null)}
              onBack={() => navigate({ kind: "search" })}
              refresh={() => void refresh()}
            />
          )}
          {failure && (
            <SessionPage
              readOnly={false}
              failure={failure}
              onClose={() => setFailure(null)}
              onLeave={() => setFailure(null)}
              onSessionEnded={() => {}}
              renewTicket={() => Promise.reject(new Error("renewTicket has no session to renew a ticket for"))}
            />
          )}
        </div>
      </main>
    </div>
  );
}
