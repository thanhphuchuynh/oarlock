// The screen shown before the console has a token.
//
// Which of the two flavours — a link to an identity provider, or a field to paste a
// static token into — depends on what the gateway answers, never on what this file
// assumes: a console that guessed would show the wrong screen for a moment on every
// single load, and the wrong screen to guess is "paste a secret", which is the one habit
// this flow exists to remove. So nothing is rendered until `loginMode()` has answered,
// and the tri-state (`undefined` while asking, then `"oidc"` or `"token"`) is exactly
// that: not a boolean, because "not yet known" is a real, renderable third state here.

import { useEffect, useState } from "react";
import { collectHandoff, loginMode, type LoginMode } from "../api";

export function SignIn({
  onSignedIn,
}: {
  /** Called once a token exists to sign in with — from a completed OIDC handoff (with the
   *  principal the provider vouched for) or a pasted static token (principal unknown, so
   *  ""; the fleet's own session list fills that in once one exists). */
  onSignedIn: (token: string, principal: string) => void;
}) {
  // undefined until the gateway has answered.
  const [login, setLogin] = useState<LoginMode | undefined>();

  // Two things happen before anything is rendered.
  //
  // The handoff first: this load may be the redirect back from a completed sign-in, and
  // the cookie waiting for us is redeemable exactly once. Only when there was none does
  // the mode matter, so the right screen appears.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const handed = await collectHandoff();
      if (cancelled) return;
      if (handed) {
        onSignedIn(handed.token, handed.principal);
        return;
      }
      const mode = await loginMode();
      if (!cancelled) setLogin(mode);
    })();
    return () => {
      cancelled = true;
    };
    // Deliberately run once: a handoff cookie is redeemable exactly once, so re-running
    // this on every render of a component that stays mounted until a token exists would
    // be trying to redeem it again rather than reflecting any real change of state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (login === undefined) {
    return (
      <main className="mx-auto max-w-lg p-8">
        <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
        <p className="text-fg-muted">Checking how this gateway signs you in…</p>
      </main>
    );
  }

  if (login === "oidc") {
    return (
      <main className="mx-auto max-w-lg p-8">
        <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
        <p className="pb-4 text-fg-muted">
          Sign in with your identity provider. This gateway never sees your password or
          your second factor.
        </p>
        {/* A link, not a fetch: the whole point is a top-level navigation the browser
            can follow to the provider and back. `return_to` brings you to the page you
            were heading for — the gateway accepts only a path on its own origin. */}
        <a
          className="btn btn-primary inline-flex"
          href={`/auth/login?return_to=${encodeURIComponent(location.pathname + location.hash)}`}
          data-testid="sign-in"
        >
          Sign in
        </a>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-lg p-8">
      <h1 className="pb-2 text-xl font-semibold">Oarlock</h1>
      <p className="pb-4 text-fg-muted">
        Paste an API token to continue. This is a development mechanism — static tokens
        are long-lived shared secrets and the gateway refuses them outside{" "}
        <code className="mono">dev</code>. Configure{" "}
        <code className="mono">auth.kind: oidc</code> and a sign-in button replaces this.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const t = new FormData(e.currentTarget).get("token");
          if (typeof t === "string" && t) onSignedIn(t, "");
        }}
        className="flex flex-col gap-3"
      >
        <input name="token" className="field mono" placeholder="token" autoFocus />
        <button className="btn btn-primary" type="submit">
          Continue
        </button>
      </form>
    </main>
  );
}
