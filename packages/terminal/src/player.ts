// Replay: an asciinema player with an integrity verdict above it.
//
// The verdict is not a prop and not a slot. `mountPlayer` renders it, from the verdict the
// caller supplies, and there is no option that removes it — because a player that shows a
// tampered recording exactly like an intact one is a player that launders it. The whole
// point of the hash chain and the signed manifest is that somebody reading a session
// afterwards can tell what they are reading, and that guarantee survives only if the
// answer is on the screen next to the thing it is about.
//
// The caller supplies the verdict rather than the component computing one, and that is
// deliberate too: verification needs the manifest and a public key the *deployment*
// trusts, which is a decision a browser cannot make for itself. What the component
// enforces is that the answer is shown — including when the answer is "the caller did not
// give me one", which renders as unverified rather than as fine.

import { create, type Options as PlayerOptions, type Player } from "asciinema-player";
import { createVerdictBanner, type Verdict, type VerdictHandle } from "./verdict.js";

export interface PlayerMountOptions {
  /** The recording, as asciicast text. */
  readonly cast: string;
  /**
   * What the gateway's verifier said. Required.
   *
   * Typed as possibly-absent so that a caller who omits it in JavaScript gets the
   * unverified banner rather than a crash — the failure mode of a missing verdict has to
   * be "we cannot vouch for this", not a blank page or an exception somebody catches and
   * ignores.
   */
  readonly verdict: Verdict | undefined;
  readonly sessionID?: string;
  readonly theme?: "dark" | "light" | "inherit";
  /** Playback options passed through: speed, idle time limit, autoplay. */
  readonly speed?: number;
  readonly idleTimeLimit?: number;
  readonly autoPlay?: boolean;
  readonly poster?: string;
}

export interface PlayerHandle {
  readonly el: HTMLElement;
  readonly player: Player | null;
  readonly verdict: VerdictHandle;
  dispose(): void;
}

const unverified: Verdict = {
  status: "unverified",
  ok: false,
  detail: "No verification result was supplied for this recording.",
};


export function mountPlayer(container: HTMLElement, opts: PlayerMountOptions): PlayerHandle {
  const root = document.createElement("div");
  root.className = "oarlock-term oarlock-replay";
  root.dataset["oarlockTheme"] = opts.theme ?? "inherit";

  // Above, in the DOM as well as visually: a verdict that a stylesheet could move below
  // the fold, or that arrives after the player in reading order, is one somebody scrolls
  // past. Assistive technology reads the order in the document.
  const verdict = createVerdictBanner({
    verdict: opts.verdict ?? unverified,
    ...(opts.sessionID ? { sessionID: opts.sessionID } : {}),
  });
  root.append(verdict.el);

  const stage = document.createElement("div");
  stage.className = "oarlock-replay__stage";
  root.append(stage);
  container.append(root);

  let player: Player | null = null;
  try {
    const playerOpts: PlayerOptions = {
      // The palette arrives through CSS (player.css maps the player's own
      // --term-color-* variables onto the generated --oarlock-terminal-* tokens), so
      // replay and live sessions cannot drift into two different terminals. Passing
      // colours here as well would be a second source for the same values.
      theme: "oarlock",
      terminalFontFamily:
        '"JetBrains Mono", "SF Mono", ui-monospace, "Cascadia Mono", "Menlo", monospace',
      ...(opts.speed !== undefined ? { speed: opts.speed } : {}),
      ...(opts.idleTimeLimit !== undefined ? { idleTimeLimit: opts.idleTimeLimit } : {}),
      ...(opts.autoPlay !== undefined ? { autoPlay: opts.autoPlay } : {}),
      ...(opts.poster ? { poster: opts.poster } : {}),
    };
    // A data URL rather than a fetch: the recording is already in hand, and asking the
    // player to fetch it would put a second retrieval — with its own auth and its own
    // failure modes — between the bytes that were verified and the bytes that are played.
    player = create(
      { data: opts.cast, parser: "asciicast" },
      stage,
      playerOpts as PlayerOptions,
    );
  } catch (err) {
    // A recording that cannot be parsed still gets its verdict, which is likely to say
    // `malformed` and explain why. Silence here would leave the banner alone above an
    // empty box with nothing connecting the two.
    const failed = document.createElement("p");
    failed.className = "oarlock-replay__failed";
    failed.textContent =
      err instanceof Error
        ? `This recording could not be played: ${err.message}`
        : "This recording could not be played.";
    stage.append(failed);
  }

  return {
    el: root,
    player,
    verdict,
    dispose: () => {
      player?.dispose();
      verdict.dispose();
      root.remove();
    },
  };
}
