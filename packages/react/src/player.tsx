// The replay player, on its own subpath.
//
// Separate from the root export because it carries its own terminal emulator: bundling it
// with `<Terminal>` charged every integrator who embeds a live session for a player they
// may never use.
//
//     import { Player } from "@oarlock/react/player";
//     import "@oarlock/terminal/player.css";

import { useEffect, useRef } from "react";
import { mountPlayer } from "@oarlock/terminal/player";
import type { Verdict } from "@oarlock/terminal";

export interface PlayerProps {
  /** The recording, as asciicast text. */
  readonly cast: string;
  /** What the gateway's verifier said. Omitting it renders "unverified", not silence. */
  readonly verdict: Verdict | undefined;
  readonly sessionID?: string;
  readonly theme?: "dark" | "light" | "inherit";
  readonly speed?: number;
  readonly idleTimeLimit?: number;
  readonly autoPlay?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

/**
 * `<Player>` — replay with the integrity verdict above it.
 *
 * The verdict is not a prop and not a slot: it is rendered from the verdict you pass, and
 * there is no way to have the player without it. A player that shows a tampered recording
 * exactly like an intact one is a player that launders it, and the hash chain exists so
 * that somebody reading a session afterwards can tell the difference.
 *
 * Requires `import "@oarlock/terminal/player.css"` — kept separate from the main
 * stylesheet so that embedding a live terminal does not drag the player's styles in.
 */
export function Player(props: PlayerProps): React.ReactElement {
  const host = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const h = mountPlayer(el, {
      cast: props.cast,
      verdict: props.verdict,
      ...(props.sessionID ? { sessionID: props.sessionID } : {}),
      ...(props.theme ? { theme: props.theme } : {}),
      ...(props.speed !== undefined ? { speed: props.speed } : {}),
      ...(props.idleTimeLimit !== undefined ? { idleTimeLimit: props.idleTimeLimit } : {}),
      ...(props.autoPlay !== undefined ? { autoPlay: props.autoPlay } : {}),
    });
    return () => h.dispose();
  }, [props.cast, props.verdict, props.sessionID, props.theme]);

  return <div ref={host} className={props.className} style={props.style} />;
}

