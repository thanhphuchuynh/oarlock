// @oarlock/terminal — a browser terminal for an Oarlock gateway.
//
// The package exports its parts separately so an integrator can build their own chrome,
// and enforces the disclosure rules in the core so that doing so cannot drop them.
//
// The replay player is deliberately *not* here: it carries its own terminal emulator
// (asciinema-player), and exporting it from the root put that in the bundle of every
// integrator who embedded a live terminal and never replayed anything. Import it from
// `@oarlock/terminal/player` instead. The verdict stays — it is small, dependency-free,
// and a host may want to render one without a player.

export { mount, readyOf, type MountOptions, type MountHandle } from "./mount.js";
export { createTerminal, type TerminalHandle, type XtermOptions } from "./xterm.js";
export { createStatusBar, type StatusBarHandle } from "./statusbar.js";
export { createFailureScreen, type FailureHandle, type FailureOptions } from "./failure.js";
export {
  createVerdictBanner,
  describe as describeVerdict,
  type Verdict,
  type VerdictCopy,
  type VerdictHandle,
  type VerdictStatus,
} from "./verdict.js";
export {
  conditions,
  get as getCondition,
  lookup as lookupCondition,
  integratorHeadline,
  integratorNextAction,
  type Audience,
  type Condition,
  type Fault,
} from "./conditions.js";
export { createPreflightGate, type PreflightHandle, type PreflightOptions } from "./preflight.js";
export {
  decide,
  concernsOf,
  facts,
  sessionOf,
  type Concern,
  type ConnectionState,
  type DisclosureInput,
  type Facts,
  type FactsInput,
  type GateCopy,
  type Session,
  type DisclosureVerdict,
} from "./disclosure.js";
export {
  OarlockSession,
  Subprotocol,
  type SessionOptions,
  type SessionFailure,
  type WebSocketLike,
} from "./session.js";
export {
  FrameType,
  MaxFrame,
  ProtocolError,
  decode,
  decodeJSON,
  encode,
  encodeData,
  encodeJSON,
  frameName,
  type CloseMsg,
  type ErrorMsg,
  type ExitMsg,
  type Frame,
  type Open,
  type PTY,
  type Ready,
  type ThrottleMsg,
} from "./frame.js";
export { palette, type XtermPalette } from "./palette.js";
