/* GENERATED FROM pkg/condition — do not edit.
 * Regenerate: go test ./pkg/condition/ -run TestGeneratedTable -update
 *
 * The closed set of reasons a session can fail or end, and what each one means to the
 * person looking at the screen. Generated from the gateway's own table so that a
 * condition the server can emit cannot be a screen the browser does not have.
 */

/** Who can act on a condition. */
export type Audience = "operator" | "integrator";

/** Whose problem it is. Encoded rather than implied: a broken doorbell reported as
 *  "device offline" sends an engineer to look at hardware. */
export type Fault = "none" | "device" | "gateway" | "principal" | "client";

export interface Condition {
  /** The wire value: an ERROR code, or a CLOSE reason. */
  readonly id: string;
  /** Where it appears on the wire. An error means the session never started; a close
   *  means it ran and stopped. The same fact at two moments is not one screen. */
  readonly kind: "error" | "close" | "error|close";
  readonly audience: Audience;
  readonly fault: Fault;
  readonly retryable: boolean;
  /** Names the thing. Never "Error", never a code, never an apology. */
  readonly headline: string;
  /** What to do about it. Empty only where there is genuinely nothing to do. */
  readonly nextAction: string;
}

/** The shared screen for a condition an operator cannot act on. */
export const integratorHeadline = "Something in this application is wrong.";
export const integratorNextAction = "This isn’t something you can fix from here. Quote the reference below if you report it.";

export const conditions: readonly Condition[] = [
  {
    id: "admin_kill",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: false,
    headline: "An administrator ended this session.",
    nextAction: "It was closed from the session list, not by a failure.",
  },
  {
    id: "already_attached",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "Somebody is already attached to this session.",
    nextAction: "Two operators can’t share one shell. Open your own session, or ask them to leave.",
  },
  {
    id: "auth_failed",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "Your credentials were rejected.",
    nextAction: "Sign in again, or check the key you offered.",
  },
  {
    id: "authz_unavailable",
    kind: "error|close",
    audience: "operator",
    fault: "gateway",
    retryable: true,
    headline: "We couldn’t confirm your access.",
    nextAction: "The service that checks permissions isn’t responding. Your access hasn’t changed — try again shortly.",
  },
  {
    id: "connection_lost",
    kind: "error",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "Connection lost.",
    nextAction: "Reconnecting — the session is still open and nothing has been lost.",
  },
  {
    id: "device_close",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: false,
    headline: "The device ended the session.",
    nextAction: "The shell exited, or the agent shut down.",
  },
  {
    id: "device_not_connected",
    kind: "error",
    audience: "operator",
    fault: "device",
    retryable: true,
    headline: "This device isn’t connected.",
    nextAction: "It may be powered off or off the network. Check it, then try again.",
  },
  {
    id: "device_offline",
    kind: "error|close",
    audience: "operator",
    fault: "device",
    retryable: true,
    headline: "The agent didn’t answer.",
    nextAction: "The device may be asleep — try again in a moment.",
  },
  {
    id: "device_on_another_node",
    kind: "error",
    audience: "operator",
    fault: "gateway",
    retryable: true,
    headline: "This device is connected to a different gateway node.",
    nextAction: "Try again — a retry usually reaches the node holding it.",
  },
  {
    id: "device_unknown",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "No such device, or you don't have access to it.",
    nextAction: "Check the device id, and check with whoever manages access for this fleet.",
  },
  {
    id: "device_unreachable",
    kind: "error",
    audience: "operator",
    fault: "device",
    retryable: true,
    headline: "This device isn’t reachable right now.",
    nextAction: "The wake-up service says it can’t be reached. Try again shortly.",
  },
  {
    id: "doorbell_failed",
    kind: "error",
    audience: "operator",
    fault: "gateway",
    retryable: true,
    headline: "Can’t reach the device right now.",
    nextAction: "The wake-up service isn’t responding. This is a problem on our side; try again shortly.",
  },
  {
    id: "frame_too_large",
    kind: "error",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "gateway_shutdown",
    kind: "error|close",
    audience: "operator",
    fault: "gateway",
    retryable: true,
    headline: "The gateway is restarting.",
    nextAction: "Sessions are being closed for a deploy. Try again in a moment.",
  },
  {
    id: "idle_timeout",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "The session closed after being idle.",
    nextAction: "Nothing was typed for a while, so the device’s slot was released. Open a new session when you need it.",
  },
  {
    id: "internal",
    kind: "error|close",
    audience: "integrator",
    fault: "gateway",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "invalid_argument",
    kind: "error",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "max_duration",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "The session reached its time limit.",
    nextAction: "Sessions have a ceiling on how long they can run. Open a new one if you still need it.",
  },
  {
    id: "no_wake_method",
    kind: "error",
    audience: "operator",
    fault: "gateway",
    retryable: false,
    headline: "This device can’t be reached.",
    nextAction: "No wake-up method is configured for it. This is a deployment problem on our side.",
  },
  {
    id: "not_authorized",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "You don’t have access to do that here.",
    nextAction: "Ask whoever manages access for this fleet.",
  },
  {
    id: "not_found",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "That isn't there, or you don't have access to it.",
    nextAction: "Check the id you asked for, and check with whoever manages access.",
  },
  {
    id: "operator_close",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: false,
    headline: "Session ended.",
    nextAction: "",
  },
  {
    id: "operator_declined",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "You chose not to continue.",
    nextAction: "The session was closed because it couldn’t be recorded.",
  },
  {
    id: "operator_gave_up",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "You stopped waiting before the device answered.",
    nextAction: "Nothing was opened. Try again when the device is awake.",
  },
  {
    id: "policy_conflict",
    kind: "error",
    audience: "integrator",
    fault: "gateway",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "policy_denied",
    kind: "error|close",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "Unrecorded sessions aren’t allowed here.",
    nextAction: "This device can only be reached in a mode the gateway can record.",
  },
  {
    id: "profile_unsupported",
    kind: "error",
    audience: "operator",
    fault: "device",
    retryable: false,
    headline: "This device can’t do that.",
    nextAction: "The agent didn’t advertise the capability you asked for.",
  },
  {
    id: "protocol_error",
    kind: "error|close",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "recorder_failed",
    kind: "error|close",
    audience: "operator",
    fault: "gateway",
    retryable: false,
    headline: "The session stopped because it could no longer be recorded.",
    nextAction: "Rather than continue unrecorded, the gateway ended it. This is a problem on our side.",
  },
  {
    id: "revoked",
    kind: "error|close",
    audience: "operator",
    fault: "principal",
    retryable: false,
    headline: "Your access was revoked.",
    nextAction: "The session was ended because your access was withdrawn. Ask whoever manages access for this fleet.",
  },
  {
    id: "session_closed",
    kind: "error",
    audience: "operator",
    fault: "none",
    retryable: false,
    headline: "That session has ended.",
    nextAction: "Open a new one.",
  },
  {
    id: "session_limit",
    kind: "error",
    audience: "operator",
    fault: "principal",
    retryable: true,
    headline: "That device already has a session open.",
    nextAction: "Wait for it to finish, or end it from the session list.",
  },
  {
    id: "ticket_invalid",
    kind: "error",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "ticket_scope",
    kind: "error",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "transport_error",
    kind: "close",
    audience: "operator",
    fault: "none",
    retryable: true,
    headline: "The connection failed.",
    nextAction: "Something between here and the gateway dropped the session. Try again.",
  },
  {
    id: "version_unsupported",
    kind: "error",
    audience: "integrator",
    fault: "client",
    retryable: false,
    headline: "Something in this application is wrong.",
    nextAction: "This isn’t something you can fix from here. Quote the reference below if you report it.",
  },
  {
    id: "wrong_node",
    kind: "error",
    audience: "operator",
    fault: "gateway",
    retryable: true,
    headline: "That session is running somewhere else.",
    nextAction: "Ask for a fresh connection and you’ll be sent to the right gateway.",
  },
];

const byID = new Map(conditions.map((c) => [c.id, c]));

/** lookup returns a condition, or undefined if this build has never heard of it. */
export function lookup(id: string): Condition | undefined {
  return byID.get(id);
}

/**
 * get returns a condition, falling back to a well-formed unknown.
 *
 * An unknown code is a gateway newer than this client, which the protocol's versioning
 * rules allow. It has to render as "we don't recognise this" rather than as a blank
 * screen or as whatever the first row of the table happens to be.
 */
export function get(id: string): Condition {
  return (
    byID.get(id) ?? {
      id,
      kind: "error",
      audience: "integrator",
      fault: "client",
      retryable: false,
      headline: integratorHeadline,
      nextAction: integratorNextAction,
    }
  );
}
