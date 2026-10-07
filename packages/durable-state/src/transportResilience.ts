/**
 * PHASE 26F — Transport Resilience & Backpressure (QUALIFICATION LAYER).
 *
 * This module qualifies what happens when the local transport is under
 * stress or when a peer disappears: bounded queues, backpressure, deadlines,
 * connection counts, deterministic cleanup, and reconnect semantics. It is a
 * pure decision layer plus ONE bounded state object. It owns no I/O, no
 * socket, no listener, no timer, no clock, and no store — callers supply
 * `nowMs` and the observations, exactly as in the frozen Phase-26 gates above.
 *
 * THE LAWS IT ENFORCES
 *   · NO UNBOUNDED MEMORY GROWTH — queue depth, queued bytes, connection
 *     slots, reconnect attempts, and tracked resources are all bounded by
 *     CONSTANTS. A caller may send MORE than a bound; it can never redefine
 *     one. Refuse, never clamp, never grow, never drop-and-continue.
 *   · DETERMINISTIC CLOSE — a window closes in one pinned order with one
 *     terminal code, and every close path is idempotent.
 *   · ZERO ORPHAN HANDLES/TIMERS — every resource a caller registers must be
 *     released; the ledger refuses cleanup while anything is still held.
 *   · RECONNECT INHERITS NO AUTHORITY — a reconnect is a NEW session. It
 *     carries no trust, no admission, no transcript, no authority. Key use
 *     and local admission are revalidated from current facts before the new
 *     session can carry anything.
 *   · RETRIES CANNOT BYPASS REPLAY — re-sending a message id this node has
 *     already seen refuses, across reconnects, behind backpressure, and
 *     after any number of attempts.
 *   · NETWORK FAILURE NEVER TRIGGERS EXECUTABLE REPLAY — the disposition
 *     vocabulary is closed and contains no resume/replay/execute entry, so a
 *     failure has no code path back into work.
 *
 * WHAT IS DELIBERATELY NOT CLAIMED
 *   No DDoS resistance, no WAN behaviour, no production capacity, no
 *   power-loss safety. Process-crash evidence from Phase 25 remains
 *   process-crash evidence. See RESILIENCE_UNCLAIMED_SCOPES.
 */

import { decideSessionTransition, type SessionState } from "./federationTransportTrust.js";
import { FRAMED_TRANSPORT_BOUNDS } from "./framedSocketTransport.js";
import {
  INGRESS_STAGE_CODES,
  INGRESS_STAGES,
  type IngressRefusalCode,
  type IngressStage,
} from "./transportIngressJunction.js";

/** Closed schema version of this qualification layer's records. */
export const TRANSPORT_RESILIENCE_SCHEMA_VERSION = "menog-transport-resilience/v0" as const;

/**
 * Scopes this gate explicitly does NOT claim. Recorded as a closed
 * vocabulary so every resilience decision can carry it verbatim and no
 * reader can mistake a local-loopback qualification for a capacity claim.
 */
export const RESILIENCE_UNCLAIMED_SCOPES = Object.freeze([
  "no_ddos_resistance_claim",
  "no_wan_or_internet_behaviour_claim",
  "no_production_capacity_claim",
  "no_power_loss_or_hardware_safety_claim",
] as const);
export type ResilienceUnclaimedScope = (typeof RESILIENCE_UNCLAIMED_SCOPES)[number];

/**
 * Frozen bounds. These are CONSTANTS, not caller inputs: a caller can only
 * exceed them (and be refused), never redefine them. The framed-transport
 * values are read from the frozen 26C object so the two layers cannot drift.
 */
export const RESILIENCE_BOUNDS = Object.freeze({
  /** Max queued application frames awaiting a writable receiver. */
  maxQueueDepth: 256,
  /** Max queued bytes awaiting a writable receiver. */
  maxQueuedBytes: FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes,
  /** Max simultaneously open connections. */
  maxConnections: FRAMED_TRANSPORT_BOUNDS.maxConnections,
  /** Max reconnect attempts per window (bounded reconnect storm). */
  maxReconnectsPerWindow: 8,
  /** The reconnect window these attempts are counted over. */
  reconnectWindowMs: 60000,
  /** Max retry attempts for one outbound message. */
  maxRetryAttempts: 4,
  /** Max resources a window may track at once (orphan-ledger bound). */
  maxTrackedResources: 64,
  /** Deadlines (frozen 26C values, never widened). */
  readDeadlineMs: FRAMED_TRANSPORT_BOUNDS.readDeadlineMs,
  writeDeadlineMs: FRAMED_TRANSPORT_BOUNDS.writeDeadlineMs,
  idleDeadlineMs: FRAMED_TRANSPORT_BOUNDS.idleDeadlineMs,
});
export type ResilienceBoundName = keyof typeof RESILIENCE_BOUNDS;

/**
 * Closed failure catalog. Every failure the pack names appears exactly once,
 * with exactly one disposition. There is deliberately NO member meaning
 * "resume", "replay the work", or "execute": a network failure has no code
 * path back into work.
 */
export const RESILIENCE_FAILURE_CLASSES = Object.freeze([
  "peer_exit",
  "peer_half_close",
  "connection_reset",
  "read_timeout",
  "write_timeout",
  "idle_timeout",
  "queue_saturation",
  "slow_receiver",
  "reconnect_storm",
  "trust_changed",
  "key_changed",
  "malformed_frame",
  "malformed_mixed_with_valid",
  "local_shutdown",
] as const);
export type ResilienceFailureClass = (typeof RESILIENCE_FAILURE_CLASSES)[number];

/**
 * Closed disposition vocabulary. Every value is a TRANSPORT action; none of
 * them resumes, replays, or executes anything.
 */
export const RESILIENCE_DISPOSITIONS = Object.freeze([
  "close_session",
  "fault_session",
  "refuse_frame",
  "refuse_message",
  "new_session_rehandshake",
  "quarantine_peer",
  "refuse_reconnect",
  "close_all",
] as const);
export type ResilienceDisposition = (typeof RESILIENCE_DISPOSITIONS)[number];

/** The single frozen disposition for each failure class (closed, pinned). */
export const RESILIENCE_DISPOSITION_BY_CLASS: Readonly<
  Record<ResilienceFailureClass, ResilienceDisposition>
> = Object.freeze({
  peer_exit: "close_session",
  peer_half_close: "close_session",
  connection_reset: "fault_session",
  read_timeout: "fault_session",
  write_timeout: "fault_session",
  idle_timeout: "close_session",
  queue_saturation: "refuse_frame",
  slow_receiver: "refuse_frame",
  reconnect_storm: "refuse_reconnect",
  trust_changed: "quarantine_peer",
  key_changed: "new_session_rehandshake",
  malformed_frame: "refuse_frame",
  malformed_mixed_with_valid: "refuse_frame",
  local_shutdown: "close_all",
});

/** Deterministic explanation for every failure class (closed, suite-pinned). */
export const RESILIENCE_FAILURE_EXPLANATIONS: Readonly<
  Record<ResilienceFailureClass, string>
> = Object.freeze({
  peer_exit: "the peer process or connection ended — close the session deterministically; nothing is resumed",
  peer_half_close: "the peer half-closed the stream — finish the closed direction and close; a half-close is never a continuation",
  connection_reset: "the connection was reset — fault the session and release every resource it held",
  read_timeout: "the read deadline expired — fault the session; a slow peer never extends a deadline",
  write_timeout: "the write deadline expired — fault the session; backpressure never becomes a longer buffer",
  idle_timeout: "the idle deadline expired — close the session; an idle connection holds no work",
  queue_saturation: "the outbound queue is full — refuse the frame; memory stays bounded and nothing is dropped and retried silently",
  slow_receiver: "the receiver is not draining — apply backpressure and refuse further enqueues; the queue never grows past its bound",
  reconnect_storm: "the reconnect window is exhausted — refuse further reconnect attempts; a storm cannot be answered with more attempts",
  trust_changed: "peer trust changed during traffic — quarantine for LOCAL judgment; trust is re-evaluated, never assumed",
  key_changed: "the peer's key changed during traffic — a new session with a full rehandshake is required; a changed key inherits nothing",
  malformed_frame: "the frame is malformed — refuse that frame only; one bad frame never tears down healthy state",
  malformed_mixed_with_valid: "a malformed frame arrived beside valid ones — refuse the malformed frame and keep the valid sequence in order",
  local_shutdown: "the local node is shutting down — close every session deterministically and release every tracked resource",
});

/** The frozen result of classifying one observed failure. */
export interface ResilienceFailureDecision {
  readonly failureClass: ResilienceFailureClass;
  readonly disposition: ResilienceDisposition;
  /** Structural law: a failure NEVER resumes, replays, or executes. */
  readonly resumesWork: false;
  readonly executableReplay: false;
  readonly authority: "none";
  readonly unclaimedScopes: readonly ResilienceUnclaimedScope[];
  readonly explanation: string;
}

/**
 * Classify one observed transport failure into its single frozen
 * disposition. Pure, deterministic, and total over the closed catalog; an
 * unknown class refuses rather than defaulting.
 */
export function classifyTransportFailure(input: {
  readonly failureClass: string;
}): ResilienceFailureDecision | { readonly ok: false; readonly explanation: string } {
  const failureClass = input.failureClass;
  if (
    typeof failureClass !== "string" ||
    !(RESILIENCE_FAILURE_CLASSES as readonly string[]).includes(failureClass)
  ) {
    return {
      ok: false,
      explanation:
        "failure class '" +
        String(failureClass) +
        "' is not in the frozen catalog — refusing to classify an unknown failure (fail closed; an unnamed failure gets no disposition and therefore no recovery path)",
    };
  }
  const known = failureClass as ResilienceFailureClass;
  return {
    failureClass: known,
    disposition: RESILIENCE_DISPOSITION_BY_CLASS[known],
    resumesWork: false,
    executableReplay: false,
    authority: "none",
    unclaimedScopes: RESILIENCE_UNCLAIMED_SCOPES,
    explanation: RESILIENCE_FAILURE_EXPLANATIONS[known],
  };
}

// ── reconnect ────────────────────────────────────────────────────────────────

/** Closed reconnect decision codes. */
export const RESILIENCE_RECONNECT_CODES = Object.freeze([
  "new_session_required",
  "reconnect_refused_storm_bound",
  "reconnect_refused_continuation",
] as const);
export type ResilienceReconnectCode = (typeof RESILIENCE_RECONNECT_CODES)[number];

export const RESILIENCE_RECONNECT_EXPLANATIONS: Readonly<
  Record<ResilienceReconnectCode, string>
> = Object.freeze({
  new_session_required:
    "a reconnect is a NEW session: it carries no trust, no admission, no transcript, no authority — key use and local admission are revalidated from current facts before it can carry anything",
  reconnect_refused_storm_bound:
    "the reconnect window is exhausted — further reconnect attempts are refused; a storm is never answered with more attempts",
  reconnect_refused_continuation:
    "a caller asked to CONTINUE a prior session across a reconnect — refused; a reconnect is a new session, never a resumption",
});

/** What a permitted reconnect must revalidate before carrying anything. */
export const RESILIENCE_RECONNECT_REVALIDATION = Object.freeze([
  "key_use",
  "local_admission",
  "runtime_epoch",
  "transcript",
] as const);
export type ResilienceRevalidation = (typeof RESILIENCE_RECONNECT_REVALIDATION)[number];

export type ResilienceReconnectDecision =
  | {
      readonly ok: true;
      readonly code: "new_session_required";
      /** Structural literal: a reconnect inherits NOTHING. */
      readonly inheritsAuthority: false;
      readonly carriedAuthority: "none";
      readonly carriedAdmission: "none";
      readonly carriedTranscript: "none";
      readonly revalidate: readonly ResilienceRevalidation[];
      /** The 26A session state a reconnect always starts from. */
      readonly priorState: SessionState;
      readonly unclaimedScopes: readonly ResilienceUnclaimedScope[];
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: Exclude<ResilienceReconnectCode, "new_session_required">;
      readonly explanation: string;
    };

/**
 * Decide a reconnect. A reconnect is ALWAYS a new session and always
 * inherits nothing: the result carries `inheritsAuthority: false` and
 * `carriedAuthority: "none"` as literal types. A caller that asks to continue
 * the prior session is refused outright. Reconnect attempts are counted in a
 * bounded window, so a storm exhausts the bound instead of multiplying
 * sessions.
 */
export function decideReconnect(input: {
  readonly priorState: SessionState;
  readonly priorTranscriptHash: string | null;
  readonly reconnectAttemptsInWindow: number;
  /** A caller may only LOWER the storm bound, never raise it. */
  readonly maxReconnectsPerWindow?: number;
  /** True when the caller is asking to carry the prior session forward. */
  readonly continuesPriorSession?: boolean;
}): ResilienceReconnectDecision {
  const requestedBound = input.maxReconnectsPerWindow ?? RESILIENCE_BOUNDS.maxReconnectsPerWindow;
  if (!Number.isInteger(requestedBound) || requestedBound < 1 || requestedBound > RESILIENCE_BOUNDS.maxReconnectsPerWindow) {
    return {
      ok: false,
      code: "reconnect_refused_storm_bound",
      explanation:
        RESILIENCE_RECONNECT_EXPLANATIONS.reconnect_refused_storm_bound +
        " (maxReconnectsPerWindow " +
        String(requestedBound) +
        " is outside [1, " +
        String(RESILIENCE_BOUNDS.maxReconnectsPerWindow) +
        "]; a bound may be lowered, never raised)",
    };
  }
  const stormBound = requestedBound;
  if (
    !Number.isInteger(input.reconnectAttemptsInWindow) ||
    input.reconnectAttemptsInWindow < 0
  ) {
    return {
      ok: false,
      code: "reconnect_refused_continuation",
      explanation:
        "the reconnect attempt count is malformed — refusing rather than guessing at a storm bound (fail closed)",
    };
  }
  if (input.reconnectAttemptsInWindow > stormBound) {
    return {
      ok: false,
      code: "reconnect_refused_storm_bound",
      explanation:
        RESILIENCE_RECONNECT_EXPLANATIONS.reconnect_refused_storm_bound +
        " (attempts " +
        String(input.reconnectAttemptsInWindow) +
        " > bound " +
        String(stormBound) +
        ")",
    };
  }
  if (input.continuesPriorSession === true) {
    return {
      ok: false,
      code: "reconnect_refused_continuation",
      explanation:
        RESILIENCE_RECONNECT_EXPLANATIONS.reconnect_refused_continuation +
        " (prior transcript " +
        (input.priorTranscriptHash === null ? "none" : "bound") +
        ")",
    };
  }
  // The frozen 26A machine decides whether a reconnect event is even legal
  // from this state — the resilience layer never re-implements it.
  const transition = decideSessionTransition({ state: input.priorState, event: "reconnect" });
  return {
    ok: true,
    code: "new_session_required",
    inheritsAuthority: false,
    carriedAuthority: "none",
    carriedAdmission: "none",
    carriedTranscript: "none",
    revalidate: RESILIENCE_RECONNECT_REVALIDATION,
    priorState: input.priorState,
    unclaimedScopes: RESILIENCE_UNCLAIMED_SCOPES,
    explanation:
      RESILIENCE_RECONNECT_EXPLANATIONS.new_session_required +
      " (frozen 26A transition from '" +
      input.priorState +
      "' was '" +
      transition.code +
      "')",
  };
}

// ── retry vs replay ──────────────────────────────────────────────────────────

/** Closed retry decision codes. */
export const RESILIENCE_RETRY_CODES = Object.freeze([
  "retry_permitted_new_message",
  "retry_refused_replay",
  "retry_refused_attempt_bound",
] as const);
export type ResilienceRetryCode = (typeof RESILIENCE_RETRY_CODES)[number];

export const RESILIENCE_RETRY_EXPLANATIONS: Readonly<Record<ResilienceRetryCode, string>> =
  Object.freeze({
    retry_permitted_new_message:
      "the message id has not been seen by this node — a retry with a FRESH message id is permitted; the failure disposition still applies",
    retry_refused_replay:
      "this node has already seen this message id — retrying it refuses as replay. Reconnect, backpressure, and failure never reset the replay record; re-sending is never a way past replay",
    retry_refused_attempt_bound:
      "the retry attempt bound is exhausted — further attempts refuse; a bound is a bound and is never widened",
  });

export type ResilienceRetryDecision =
  | { readonly ok: true; readonly code: "retry_permitted_new_message"; readonly attempt: number; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code: Exclude<ResilienceRetryCode, "retry_permitted_new_message">;
      readonly attempt: number;
      readonly executableReplay: false;
      readonly explanation: string;
    };

/**
 * Decide a retry. A retry is permitted only for a message id this node has
 * NOT seen, and only within the frozen attempt bound. Re-sending a seen id
 * refuses as replay — no reconnect, backpressure, or failure state can clear
 * the record, so retries can never become a replay bypass.
 */
export function decideRetry(input: {
  readonly messageId: string;
  readonly attempt: number;
  readonly seenMessageIds: ReadonlySet<string>;
}): ResilienceRetryDecision {
  const bound = RESILIENCE_BOUNDS.maxRetryAttempts;
  if (typeof input.messageId !== "string" || input.messageId.length === 0) {
    return {
      ok: false,
      code: "retry_refused_attempt_bound",
      attempt: input.attempt,
      executableReplay: false,
      explanation: "the retry message id is malformed — refusing rather than guessing (fail closed)",
    };
  }
  if (!Number.isInteger(input.attempt) || input.attempt < 1) {
    return {
      ok: false,
      code: "retry_refused_attempt_bound",
      attempt: input.attempt,
      executableReplay: false,
      explanation: "the retry attempt number is malformed — refusing rather than guessing (fail closed)",
    };
  }
  if (input.attempt > bound) {
    return {
      ok: false,
      code: "retry_refused_attempt_bound",
      attempt: input.attempt,
      executableReplay: false,
      explanation:
        RESILIENCE_RETRY_EXPLANATIONS.retry_refused_attempt_bound +
        " (attempt " +
        String(input.attempt) +
        " > bound " +
        String(bound) +
        ")",
    };
  }
  if (input.seenMessageIds.has(input.messageId)) {
    return {
      ok: false,
      code: "retry_refused_replay",
      attempt: input.attempt,
      executableReplay: false,
      explanation:
        RESILIENCE_RETRY_EXPLANATIONS.retry_refused_replay +
        " (message id '" +
        input.messageId +
        "', attempt " +
        String(input.attempt) +
        ")",
    };
  }
  return {
    ok: true,
    code: "retry_permitted_new_message",
    attempt: input.attempt,
    explanation:
      RESILIENCE_RETRY_EXPLANATIONS.retry_permitted_new_message +
      " (attempt " +
      String(input.attempt) +
      " of bound " +
      String(bound) +
      ")",
  };
}

// ── deadlines ────────────────────────────────────────────────────────────────

/** Closed deadline kinds, checked in this pinned order. */
export const RESILIENCE_DEADLINES = Object.freeze(["read", "write", "idle"] as const);
export type ResilienceDeadline = (typeof RESILIENCE_DEADLINES)[number];

export type ResilienceDeadlineDecision =
  | { readonly ok: true; readonly deadline: ResilienceDeadline | null; readonly explanation: string }
  | {
      readonly ok: false;
      readonly deadline: ResilienceDeadline;
      readonly elapsedMs: number;
      readonly boundMs: number;
      readonly disposition: "fault_session" | "close_session";
      readonly explanation: string;
    };

/**
 * Decide deadlines in the frozen order read → write → idle (first expired
 * wins; the suite pins multi-violation precedence). The read deadline is
 * measured from the FIRST BYTE of an incomplete frame, so a sender that
 * dribbles cannot extend it, and no caller input can widen a bound.
 */
export function decideDeadlines(input: {
  readonly openedAtMs: number;
  readonly lastActivityAtMs: number;
  readonly firstPartialByteAtMs: number | null;
  readonly pendingRead: boolean;
  readonly pendingWrite: boolean;
  readonly nowMs: number;
  readonly peerTimeoutMs?: number;
}): ResilienceDeadlineDecision {
  const bounds = RESILIENCE_BOUNDS;
  if (
    !Number.isFinite(input.nowMs) ||
    !Number.isFinite(input.openedAtMs) ||
    !Number.isFinite(input.lastActivityAtMs) ||
    (input.firstPartialByteAtMs !== null && !Number.isFinite(input.firstPartialByteAtMs)) ||
    typeof input.pendingRead !== "boolean" ||
    typeof input.pendingWrite !== "boolean"
  ) {
    return {
      ok: false,
      deadline: "read",
      elapsedMs: 0,
      boundMs: bounds.readDeadlineMs,
      disposition: "fault_session",
      explanation: "deadline inputs are malformed — refusing rather than guessing an elapsed time (fail closed)",
    };
  }
  const peerTimeout =
    input.peerTimeoutMs === undefined
      ? bounds.readDeadlineMs
      : input.peerTimeoutMs;
  if (!Number.isInteger(peerTimeout) || peerTimeout < 1 || peerTimeout > bounds.readDeadlineMs) {
    return {
      ok: false,
      deadline: "read",
      elapsedMs: 0,
      boundMs: bounds.readDeadlineMs,
      disposition: "fault_session",
      explanation:
        "peerTimeoutMs " +
        String(peerTimeout) +
        " is outside [1, " +
        String(bounds.readDeadlineMs) +
        "] — refused, never clamped (a caller may only shorten a deadline)",
    };
  }
  const expired = (kind: ResilienceDeadline, sinceMs: number, boundMs: number) => ({
    ok: false as const,
    deadline: kind,
    elapsedMs: input.nowMs - sinceMs,
    boundMs,
    disposition: kind === "idle" ? ("close_session" as const) : ("fault_session" as const),
    explanation:
      kind +
      " deadline expired: " +
      String(input.nowMs - sinceMs) +
      " ms since " +
      String(sinceMs) +
      " exceeds the pinned bound of " +
      String(boundMs) +
      " ms — a slow peer never extends a deadline",
  });
  if (input.pendingRead) {
    const since =
      input.firstPartialByteAtMs === null ? input.openedAtMs : input.firstPartialByteAtMs;
    if (input.nowMs - since > peerTimeout) return expired("read", since, peerTimeout);
  }
  if (input.pendingWrite && input.nowMs - input.openedAtMs > bounds.writeDeadlineMs) {
    return expired("write", input.openedAtMs, bounds.writeDeadlineMs);
  }
  if (input.nowMs - input.lastActivityAtMs > bounds.idleDeadlineMs) {
    return expired("idle", input.lastActivityAtMs, bounds.idleDeadlineMs);
  }
  return {
    ok: true,
    deadline: null,
    explanation:
      "no deadline expired (read " +
      String(bounds.readDeadlineMs) +
      " ms · write " +
      String(bounds.writeDeadlineMs) +
      " ms · idle " +
      String(bounds.idleDeadlineMs) +
      " ms, all frozen)",
  };
}

// ── bounded queue + backpressure ─────────────────────────────────────────────

/** Closed queue/backpressure refusal codes. */
export const RESILIENCE_QUEUE_CODES = Object.freeze([
  "queue_accepted",
  "queue_refused_depth",
  "queue_refused_bytes",
  "queue_refused_backpressure",
  "queue_refused_byte_size",
  "connection_refused_bound",
  "connection_released",
] as const);
export type ResilienceQueueCode = (typeof RESILIENCE_QUEUE_CODES)[number];

export const RESILIENCE_QUEUE_EXPLANATIONS: Readonly<Record<ResilienceQueueCode, string>> =
  Object.freeze({
    queue_accepted: "the frame fits the frozen queue bounds and the receiver is draining",
    queue_refused_depth:
      "the queue is at its frozen depth bound — refusing; memory stays bounded and nothing is silently dropped",
    queue_refused_bytes:
      "the queue is at its frozen byte bound — refusing; a slow receiver never grows the buffer",
    queue_refused_backpressure:
      "the receiver is not draining — backpressure: the frame is refused rather than buffered",
    queue_refused_byte_size:
      "the frame exceeds the frozen per-frame byte bound — refused before any allocation",
    connection_refused_bound:
      "the connection count is at its frozen bound — refusing; a reconnect storm never multiplies sessions",
    connection_released: "the connection slot was released deterministically",
  });

/** The refusal codes the queue decision can emit (the accepted code aside). */
export type ResilienceQueueRefusal = Exclude<
  ResilienceQueueCode,
  "queue_accepted" | "connection_released" | "connection_refused_bound"
>;

export type ResilienceQueueDecision =
  | { readonly ok: true; readonly code: "queue_accepted"; readonly depth: number; readonly bytes: number; readonly explanation: string }
  | { readonly ok: false; readonly code: ResilienceQueueRefusal; readonly depth: number; readonly bytes: number; readonly explanation: string };

/**
 * The pure bounded-queue decision. Checks run in a PINNED order
 * (byte size → depth → bytes → backpressure) and the first match refuses.
 * Nothing here allocates: the byte size is compared against the constant
 * before any buffer could grow.
 */
export function decideQueueAdmission(input: {
  readonly frameBytes: number;
  readonly depth: number;
  readonly queuedBytes: number;
  readonly receiverDraining: boolean;
}): ResilienceQueueDecision {
  const bounds = RESILIENCE_BOUNDS;
  const refuse = (code: ResilienceQueueRefusal): ResilienceQueueDecision => ({
    ok: false,
    code,
    depth: input.depth,
    bytes: input.queuedBytes,
    explanation: RESILIENCE_QUEUE_EXPLANATIONS[code],
  });
  if (
    !Number.isInteger(input.frameBytes) ||
    input.frameBytes < 0 ||
    !Number.isInteger(input.depth) ||
    input.depth < 0 ||
    !Number.isInteger(input.queuedBytes) ||
    input.queuedBytes < 0 ||
    typeof input.receiverDraining !== "boolean"
  ) {
    return refuse("queue_refused_byte_size");
  }
  if (input.frameBytes > FRAMED_TRANSPORT_BOUNDS.maxFrameBytes) {
    return refuse("queue_refused_byte_size");
  }
  if (input.depth >= bounds.maxQueueDepth) return refuse("queue_refused_depth");
  if (input.queuedBytes + input.frameBytes > bounds.maxQueuedBytes) {
    return refuse("queue_refused_bytes");
  }
  if (!input.receiverDraining) return refuse("queue_refused_backpressure");
  return {
    ok: true,
    code: "queue_accepted",
    depth: input.depth + 1,
    bytes: input.queuedBytes + input.frameBytes,
    explanation: RESILIENCE_QUEUE_EXPLANATIONS.queue_accepted,
  };
}

// ── the resource ledger (orphan handles/timers) ──────────────────────────────

/** Closed resource kinds the ledger tracks. */
export const RESILIENCE_RESOURCE_KINDS = Object.freeze([
  "socket",
  "timer",
  "frame",
  "session",
] as const);
export type ResilienceResourceKind = (typeof RESILIENCE_RESOURCE_KINDS)[number];

export type ResilienceLedgerDecision =
  | { readonly ok: true; readonly code: "resource_registered"; readonly tracked: number; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code: "resource_refused_ledger_bound" | "resource_refused_duplicate" | "resource_unknown" | "resource_refused_released";
      readonly tracked: number;
      readonly explanation: string;
    };

/**
 * The ledger of resources a window holds (sockets, timers, frames,
 * sessions). Every registration must be matched by exactly one release; a
 * cleanup qualification refuses while any resource is still held, which is
 * what makes "zero orphan handles/timers" a checkable property rather than a
 * claim. The ledger allocates nothing beyond its own bounded Map.
 */
export class ResourceLedger {
  readonly #kinds: ReadonlySet<string>;
  readonly #held = new Map<string, ResilienceResourceKind>();
  readonly #bound: number;
  #releasedCount = 0;

  private constructor(kinds: ReadonlySet<string>, bound: number) {
    this.#kinds = kinds;
    this.#bound = bound;
  }

  /** The ONLY construction path, so the bound is structural. */
  static open(bound: number = RESILIENCE_BOUNDS.maxTrackedResources): ResourceLedger {
    return new ResourceLedger(new Set(RESILIENCE_RESOURCE_KINDS), bound);
  }

  /** Resources still held (the orphan set). */
  orphans(): readonly { readonly id: string; readonly kind: ResilienceResourceKind }[] {
    return Object.freeze([...this.#held.entries()].map(([id, kind]) => ({ id, kind })));
  }

  held(): number {
    return this.#held.size;
  }

  released(): number {
    return this.#releasedCount;
  }

  register(id: string, kind: string): ResilienceLedgerDecision {
    if (typeof id !== "string" || id.length === 0 || !this.#kinds.has(kind)) {
      return {
        ok: false,
        code: "resource_unknown",
        tracked: this.#held.size,
        explanation:
          "resource '" +
          String(id) +
          "' of kind '" +
          String(kind) +
          "' is not in the closed ledger vocabulary — refusing (fail closed)",
      };
    }
    if (this.#held.has(id)) {
      return {
        ok: false,
        code: "resource_refused_duplicate",
        tracked: this.#held.size,
        explanation: "resource '" + id + "' is already held — a double registration would make the orphan count a lie",
      };
    }
    if (this.#held.size >= this.#bound) {
      return {
        ok: false,
        code: "resource_refused_ledger_bound",
        tracked: this.#held.size,
        explanation:
          "the ledger already holds its frozen bound of " +
          String(this.#bound) +
          " resources — refusing; the ledger itself never grows past its bound",
      };
    }
    this.#held.set(id, kind as ResilienceResourceKind);
    return {
      ok: true,
      code: "resource_registered",
      tracked: this.#held.size,
      explanation: "resource '" + id + "' (" + kind + ") is held and must be released before cleanup qualifies",
    };
  }

  /** Release a held resource. Releasing an unknown or twice-released id refuses. */
  release(id: string): ResilienceLedgerDecision {
    if (typeof id !== "string" || !this.#held.has(id)) {
      return {
        ok: false,
        code: "resource_refused_released",
        tracked: this.#held.size,
        explanation:
          "resource '" +
          String(id) +
          "' is not held — releasing an unheld resource would mask a real orphan (fail closed)",
      };
    }
    this.#held.delete(id);
    this.#releasedCount += 1;
    return {
      ok: true,
      code: "resource_registered",
      tracked: this.#held.size,
      explanation: "resource '" + id + "' released deterministically",
    };
  }
}

/** The cleanup qualification: zero orphans is a checkable result. */
export function qualifyCleanup(input: {
  readonly ledger: ResourceLedger;
}): {
  readonly ok: boolean;
  readonly orphans: readonly { readonly id: string; readonly kind: ResilienceResourceKind }[];
  readonly explanation: string;
} {
  const orphans = input.ledger.orphans();
  if (orphans.length === 0) {
    return {
      ok: true,
      orphans,
      explanation:
        "cleanup qualifies: zero orphaned handles/timers after " +
        String(input.ledger.released()) +
        " deterministic release(s)",
    };
  }
  return {
    ok: false,
    orphans,
    explanation:
      "cleanup REFUSES: " +
      String(orphans.length) +
      " resource(s) still held (" +
      orphans.map((entry) => entry.kind + ":" + entry.id).join(", ") +
      ") — zero orphan handles/timers is a checkable property, not a claim",
  };
}

// ── the bounded window ───────────────────────────────────────────────────────

/** Closed window states. */
export const RESILIENCE_WINDOW_STATES = Object.freeze(["open", "closed"] as const);
export type ResilienceWindowState = (typeof RESILIENCE_WINDOW_STATES)[number];

/** Closed terminal codes for a window. */
export const RESILIENCE_WINDOW_CLOSE_CODES = Object.freeze([
  "local_shutdown",
  "fault",
  "idle_timeout",
  "deadline_expired",
  "connection_bound",
] as const);
export type ResilienceWindowCloseCode = (typeof RESILIENCE_WINDOW_CLOSE_CODES)[number];

/** Closed per-operation refusal codes for the window. */
export const RESILIENCE_WINDOW_REFUSALS = Object.freeze([
  "window_closed",
  "clock_invalid",
  "config_invalid",
  "connections_refused",
  "queue_refused_depth",
  "queue_refused_bytes",
  "queue_refused_backpressure",
  "queue_refused_byte_size",
  "reconnect_refused_storm_bound",
  "reconnect_refused_continuation",
  "retry_refused_replay",
  "retry_refused_attempt_bound",
  "peer_not_admitted",
  "key_use_refused",
] as const);
export type ResilienceWindowRefusal = (typeof RESILIENCE_WINDOW_REFUSALS)[number];

export const RESILIENCE_WINDOW_REFUSAL_EXPLANATIONS: Readonly<
  Record<ResilienceWindowRefusal, string>
> = Object.freeze({
  window_closed: "the window is closed; a closed window accepts no further operations",
  clock_invalid: "caller-supplied nowMs must be a finite number; refused, session unchanged",
  config_invalid: "window configuration is outside the frozen bounds; refused, never clamped",
  connections_refused: "the connection count is at its frozen bound — refusing a new connection",
  queue_refused_depth: "the queue is at its frozen depth bound — refusing; memory stays bounded",
  queue_refused_bytes: "the queue is at its frozen byte bound — refusing; a slow receiver never grows the buffer",
  queue_refused_backpressure: "the receiver is not draining — backpressure refuses the frame rather than buffering it",
  queue_refused_byte_size: "the frame exceeds the frozen per-frame byte bound — refused before any allocation",
  reconnect_refused_storm_bound: "the reconnect window is exhausted — a storm is never answered with more attempts",
  reconnect_refused_continuation: "a reconnect cannot continue the prior session — it is a NEW session that inherits nothing",
  retry_refused_replay: "this node has already seen this message id — retrying refuses as replay; no reconnect clears the record",
  retry_refused_attempt_bound: "the retry attempt bound is exhausted — further attempts refuse",
  peer_not_admitted: "the peer's CURRENT local admission is not admitted — the frozen 26E stage-4 code, carried verbatim",
  key_use_refused: "the frozen 25B key-use gate refused a key on current facts — carried verbatim",
});

export type ResilienceWindowResult<T> =
  | ({ readonly ok: true } & T)
  | {
      readonly ok: false;
      readonly code: ResilienceWindowRefusal;
      readonly state: ResilienceWindowState;
      readonly explanation: string;
    };

/** The live bounds observed by a window (for memory-growth qualification). */
export interface ResilienceWindowStats {
  readonly depth: number;
  readonly queuedBytes: number;
  readonly connections: number;
  readonly reconnectsInWindow: number;
  readonly highWaterDepth: number;
  readonly highWaterBytes: number;
  readonly highWaterConnections: number;
  readonly trackedResources: number;
}

/**
 * The bounded transport window: connections, queue, backpressure, deadlines,
 * reconnect accounting, retry-vs-replay state, and the resource ledger.
 *
 * Constructed ONLY through `openResilienceWindow`, so every bound is
 * structural. It performs no I/O, opens no socket, sets no timer, and never
 * reads a clock — the caller supplies `nowMs` on every operation. All state
 * is bounded by RESILIENCE_BOUNDS constants, so a hostile or broken peer can
 * make the window refuse but can never make it grow.
 */
export class ResilienceWindow {
  readonly ledger: ResourceLedger;
  readonly #openedAtMs: number;
  readonly #maxReconnects: number;
  readonly #reconnectWindowMs: number;
  /** The ONLY construction path, so every bound is structural. */
  static open(openedAtMs: number, maxReconnects: number, reconnectWindowMs: number): ResilienceWindow {
    return new ResilienceWindow(openedAtMs, maxReconnects, reconnectWindowMs);
  }

  #state: ResilienceWindowState = "open";
  #closeCode: ResilienceWindowCloseCode | null = null;
  #lastActivityAtMs: number;
  #firstPartialByteAtMs: number | null = null;
  #pendingRead = false;
  #pendingWrite = false;
  #connections = 0;
  #depth = 0;
  #queuedBytes = 0;
  /**
   * The bounded outbound FIFO: one entry per queued frame holding its byte
   * count, so a dequeue releases exactly what was enqueued. The array can
   * never exceed RESILIENCE_BOUNDS.maxQueueDepth entries — `enqueue` refuses
   * before pushing — so this is a bound, not a growth point.
   */
  readonly #queue: number[] = [];
  #receiverDraining = true;
  #reconnects: { atMs: number; count: number }[] = [];
  readonly #seenMessageIds = new Set<string>();
  #highWaterDepth = 0;
  #highWaterBytes = 0;
  #highWaterConnections = 0;

  private constructor(openedAtMs: number, maxReconnects: number, reconnectWindowMs: number) {
    this.#openedAtMs = openedAtMs;
    this.#lastActivityAtMs = openedAtMs;
    this.#maxReconnects = maxReconnects;
    this.#reconnectWindowMs = reconnectWindowMs;
    this.ledger = ResourceLedger.open();
  }

  state(): ResilienceWindowState {
    return this.#state;
  }

  closeCode(): ResilienceWindowCloseCode | null {
    return this.#closeCode;
  }

  /** Fail closed: a closed window accepts nothing further. */
  #refuse(code: ResilienceWindowRefusal, detail: string): ResilienceWindowResult<never> {
    return {
      ok: false,
      code,
      state: this.#state,
      explanation: RESILIENCE_WINDOW_REFUSAL_EXPLANATIONS[code] + (detail === "" ? "" : "; " + detail),
    };
  }

  #clock(nowMs: number): boolean {
    return Number.isFinite(nowMs);
  }

  #openOnly(): ResilienceWindowResult<never> | null {
    if (this.#state === "closed") return this.#refuse("window_closed", "");
    return null;
  }

  stats(): ResilienceWindowStats {
    return Object.freeze({
      depth: this.#depth,
      queuedBytes: this.#queuedBytes,
      connections: this.#connections,
      reconnectsInWindow: this.reconnectsInWindow(this.#lastActivityAtMs),
      highWaterDepth: this.#highWaterDepth,
      highWaterBytes: this.#highWaterBytes,
      highWaterConnections: this.#highWaterConnections,
      trackedResources: this.ledger.held(),
    });
  }

  /** Connections are a bounded resource: the bound refuses, never queues. */
  openConnection(nowMs: number): ResilienceWindowResult<{ connections: number; id: string }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    if (this.#connections >= RESILIENCE_BOUNDS.maxConnections) {
      return this.#refuse(
        "connections_refused",
        "bound " + String(RESILIENCE_BOUNDS.maxConnections) + " reached",
      );
    }
    this.#connections += 1;
    this.#lastActivityAtMs = nowMs;
    if (this.#connections > this.#highWaterConnections) this.#highWaterConnections = this.#connections;
    const id = "conn-" + String(this.#connections);
    this.ledger.register(id, "session");
    return { ok: true, connections: this.#connections, id };
  }

  closeConnection(id: string): ResilienceWindowResult<{ connections: number }> {
    if (typeof id !== "string" || this.#connections <= 0) {
      return this.#refuse("config_invalid", "no connection slot to release");
    }
    this.ledger.release(id);
    this.#connections -= 1;
    return { ok: true, connections: this.#connections };
  }

  /** The receiver's drain state drives backpressure; nothing else may. */
  setReceiverDraining(draining: boolean, nowMs: number): ResilienceWindowResult<{ depth: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    if (typeof draining !== "boolean") return this.#refuse("config_invalid", "draining must be a boolean");
    this.#receiverDraining = draining;
    this.#lastActivityAtMs = nowMs;
    if (draining) this.#drain();
    return { ok: true, depth: this.#depth };
  }

  /** Accept a partial inbound frame (starts the drip-proof read deadline). */
  notePartialByte(nowMs: number): ResilienceWindowResult<{ sinceMs: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    if (this.#firstPartialByteAtMs === null) this.#firstPartialByteAtMs = nowMs;
    this.#pendingRead = true;
    return { ok: true, sinceMs: this.#firstPartialByteAtMs };
  }

  noteActivity(nowMs: number): ResilienceWindowResult<{ lastActivityAtMs: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    this.#pendingRead = false;
    this.#firstPartialByteAtMs = null;
    this.#lastActivityAtMs = nowMs;
    return { ok: true, lastActivityAtMs: this.#lastActivityAtMs };
  }

  /** Check deadlines and apply the frozen disposition. */
  checkDeadlines(nowMs: number): ResilienceWindowResult<{ deadline: ResilienceDeadline | null }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    const decision = decideDeadlines({
      openedAtMs: this.#openedAtMs,
      lastActivityAtMs: this.#lastActivityAtMs,
      firstPartialByteAtMs: this.#firstPartialByteAtMs,
      pendingRead: this.#pendingRead,
      pendingWrite: this.#pendingWrite,
      nowMs,
    });
    if (!decision.ok) {
      this.#close(decision.disposition === "fault_session" ? "fault" : "idle_timeout");
      return this.#refuse(
        "config_invalid",
        "deadline '" + decision.deadline + "' expired — " + decision.explanation,
      );
    }
    return { ok: true, deadline: decision.deadline };
  }

  /** Enqueue one outbound frame through the bounded queue decision. */
  enqueue(frameBytes: number, nowMs: number): ResilienceWindowResult<{ depth: number; queuedBytes: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    this.#pendingWrite = true;
    const decision = decideQueueAdmission({
      frameBytes,
      depth: this.#depth,
      queuedBytes: this.#queuedBytes,
      receiverDraining: this.#receiverDraining,
    });
    if (!decision.ok) return this.#refuse(decision.code, decision.explanation);
    this.#depth += 1;
    this.#queuedBytes += frameBytes;
    this.#queue.push(frameBytes);
    this.#lastActivityAtMs = nowMs;
    if (this.#depth > this.#highWaterDepth) this.#highWaterDepth = this.#depth;
    if (this.#queuedBytes > this.#highWaterBytes) this.#highWaterBytes = this.#queuedBytes;
    return { ok: true, depth: this.#depth, queuedBytes: this.#queuedBytes };
  }

  #drain(): void {
    this.#queue.length = 0;
    this.#depth = 0;
    this.#queuedBytes = 0;
    this.#pendingWrite = false;
  }

  /** The receiver drained one frame; exactly its bytes are released. */
  dequeue(nowMs: number): ResilienceWindowResult<{ depth: number; queuedBytes: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    const head = this.#queue.shift();
    if (head !== undefined) {
      this.#depth -= 1;
      this.#queuedBytes -= head;
      this.#lastActivityAtMs = nowMs;
    }
    return { ok: true, depth: this.#depth, queuedBytes: this.#queuedBytes };
  }

  reconnectsInWindow(nowMs: number): number {
    const kept = this.#reconnects.filter((entry) => nowMs - entry.atMs <= this.#reconnectWindowMs);
    this.#reconnects = kept;
    return kept.length;
  }

  /**
   * A reconnect is a NEW session that inherits nothing. The window counts it
   * against the frozen storm bound; over the bound, it refuses.
   */
  reconnect(nowMs: number, priorState: SessionState): ResilienceWindowResult<{ inheritsAuthority: false }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    const attempts = this.reconnectsInWindow(nowMs);
    // The PROSPECTIVE attempt number is what the bound is checked against, so
    // a bound of N permits exactly N reconnects per window and refuses the
    // N+1th — never N+1.
    const decision = decideReconnect({
      priorState,
      priorTranscriptHash: null,
      reconnectAttemptsInWindow: attempts + 1,
      maxReconnectsPerWindow: this.#maxReconnects,
    });
    if (!decision.ok) {
      return this.#refuse(
        decision.code === "reconnect_refused_storm_bound"
          ? "reconnect_refused_storm_bound"
          : "reconnect_refused_continuation",
        decision.explanation,
      );
    }
    this.#reconnects.push({ atMs: nowMs, count: attempts + 1 });
    this.#lastActivityAtMs = nowMs;
    return { ok: true, inheritsAuthority: false };
  }

  /** A retry may never bypass the replay record. */
  retry(messageId: string, attempt: number, nowMs: number): ResilienceWindowResult<{ attempt: number }> {
    if (!this.#clock(nowMs)) return this.#refuse("clock_invalid", "nowMs must be finite");
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    const decision = decideRetry({ messageId, attempt, seenMessageIds: this.#seenMessageIds });
    if (!decision.ok) {
      return this.#refuse(
        decision.code === "retry_refused_replay" ? "retry_refused_replay" : "retry_refused_attempt_bound",
        decision.explanation,
      );
    }
    this.#lastActivityAtMs = nowMs;
    return { ok: true, attempt: decision.attempt };
  }

  /** Record a message id this node has SEEN — the replay record. */
  noteMessageSeen(messageId: string): ResilienceWindowResult<{ seen: number }> {
    const closed = this.#openOnly();
    if (closed !== null) return closed;
    if (typeof messageId !== "string" || messageId.length === 0) {
      return this.#refuse("config_invalid", "message id must be a non-empty string");
    }
    this.#seenMessageIds.add(messageId);
    return { ok: true, seen: this.#seenMessageIds.size };
  }

  seenMessageCount(): number {
    return this.#seenMessageIds.size;
  }

  /** Deterministic, idempotent close. The second call changes nothing. */
  #close(code: ResilienceWindowCloseCode): void {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#closeCode = code;
    this.#depth = 0;
    this.#queuedBytes = 0;
    this.#queue.length = 0;
    this.#pendingRead = false;
    this.#pendingWrite = false;
    this.#firstPartialByteAtMs = null;
    this.#connections = 0;
    this.#reconnects = [];
  }

  close(code: ResilienceWindowCloseCode): ResilienceWindowResult<{ closeCode: ResilienceWindowCloseCode }> {
    const already = this.#state === "closed";
    this.#close(code);
    return {
      ok: true,
      closeCode: this.#closeCode ?? code,
      ...(already ? { alreadyClosed: true } : {}),
    };
  }
}

/**
 * The ONLY construction path for a window, so every bound is structural
 * rather than caller-configurable. Config values may only go LOWER than the
 * frozen constants; anything fractional, non-finite, non-numeric, or above
 * the ceiling refuses `config_invalid` — never clamped.
 */
export function openResilienceWindow(
  config: { readonly nowMs: number; readonly maxReconnectsPerWindow?: number },
): ResilienceWindowResult<{ window: ResilienceWindow }> {
  const bounds = RESILIENCE_BOUNDS;
  const requested = config.maxReconnectsPerWindow ?? bounds.maxReconnectsPerWindow;
  if (
    !Number.isFinite(config.nowMs) ||
    !Number.isInteger(requested) ||
    requested < 1 ||
    requested > bounds.maxReconnectsPerWindow
  ) {
    return {
      ok: false,
      code: "config_invalid",
      state: "open",
      explanation:
        RESILIENCE_WINDOW_REFUSAL_EXPLANATIONS.config_invalid +
        " (maxReconnectsPerWindow " +
        String(requested) +
        " must be an integer in [1, " +
        String(bounds.maxReconnectsPerWindow) +
        "]; nowMs must be finite)",
    };
  }
  return { ok: true, window: ResilienceWindow.open(config.nowMs, requested, bounds.reconnectWindowMs) };
}

/**
 * The 26E ingress refusal each failure class maps onto during live traffic,
 * or null when the failure is purely transport-level and owns no ingress
 * code. A trust change lands on the 26E admission stage; a key change lands
 * on the 26E key-use stage. Both are the frozen codes, carried verbatim.
 */
export const RESILIENCE_INGRESS_REMAP: Readonly<
  Record<ResilienceFailureClass, IngressRefusalCode | null>
> = Object.freeze({
  peer_exit: null,
  peer_half_close: null,
  connection_reset: null,
  read_timeout: null,
  write_timeout: null,
  idle_timeout: null,
  queue_saturation: null,
  slow_receiver: null,
  reconnect_storm: null,
  trust_changed: "peer_not_admitted",
  key_changed: "key_use_refused",
  malformed_frame: null,
  malformed_mixed_with_valid: null,
  local_shutdown: null,
});

/**
 * The frozen 26E stage a refusal code belongs to, or null when no stage in
 * the pinned order owns it (only the universal `config_invalid`, which every
 * stage may emit).
 */
export function ingressStageOf(code: IngressRefusalCode): IngressStage | null {
  if (code === "config_invalid") return null;
  for (const stage of INGRESS_STAGES) {
    if (INGRESS_STAGE_CODES[stage].includes(code)) return stage;
  }
  return null;
}

/**
 * The closed, no-DDoS/no-WAN/no-capacity/no-power-loss scope statement that
 * every resilience record carries, plus the honest statement of what this
 * gate DID qualify.
 */
export const RESILIENCE_QUALIFIED_SCOPES = Object.freeze([
  "bounded_queue_depth",
  "bounded_queued_bytes",
  "bounded_connection_count",
  "backpressure_refusal",
  "frozen_deadlines",
  "deterministic_close",
  "orphan_resource_ledger",
  "reconnect_inherits_no_authority",
  "retry_cannot_bypass_replay",
] as const);
export type ResilienceQualifiedScope = (typeof RESILIENCE_QUALIFIED_SCOPES)[number];
