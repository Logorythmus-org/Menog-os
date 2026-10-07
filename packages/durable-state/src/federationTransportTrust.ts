/**
 * PHASE 26A — Governed Local Network Transport: Transport Trust Model
 * (CONTRACT-FIRST / NO SOCKET IMPLEMENTATION / NO NEW AUTHORITY).
 *
 * This module defines the CLOSED vocabularies and deterministic,
 * fail-closed decisions for the Phase-26 transport trust model before any
 * socket, listener, or frame-carrying code exists (26B+). It implements no
 * transport, no sockets, no discovery, no crypto, no store access, and no
 * execution surface: every decision here is a pure function of caller-
 * supplied facts, and every decision embeds a deterministic explanation.
 *
 * The pack pins, each enforced structurally below and by the suite:
 *
 *  T1  REACHABILITY ≠ IDENTITY              — a reachable endpoint proves
 *                                              only that bytes could be
 *                                              sent; it names no node.
 *  T2  IDENTITY ≠ ADMISSION                 — a verified identity is not
 *                                              peer admission (24C owns
 *                                              admission, unchanged).
 *  T3  ADMISSION ≠ AUTHORITY                — admission grants no
 *                                              authority of any kind.
 *  T4  AUTHENTICATED SESSION ≠ EXECUTION    — an authenticated transport
 *                                              session never executes;
 *                                              execution stays behind
 *                                              fresh LOCAL Allocation →
 *                                              Policy → Phase-20 → 21.
 *  T5  REMOTE MESSAGE ≠ LOCAL POLICY        — a remote-delivered message
 *                                              is untrusted DATA and can
 *                                              never be (or choose) a
 *                                              local Policy decision.
 *  T6  TRANSPORT SUCCESS ≠ APPLICATION
 *      ACCEPTANCE                           — bytes went out on a
 *                                              connection says nothing
 *                                              about whether the
 *                                              application accepted.
 *  T7  CONNECTION STATE ≠ TRUST STATE       — connection/session states
 *                                              are transport facts only;
 *                                              trust state lives in the
 *                                              frozen 24C registry.
 *  T8  RECONNECT ≠ RE-ADMISSION             — a new connection starts
 *                                              with zero carried trust;
 *                                              admission is re-checked
 *                                              fresh, never inherited.
 *  T9  NETWORK EVIDENCE ≠ AUTHORITY         — transport evidence records
 *                                              what happened on the
 *                                              wire; consuming it grants
 *                                              nothing.
 *
 * The transport-threat surface (closed vocabulary TT-01..TT-18): unknown,
 * wrong-key, stale, replay, duplicate, truncation, oversize, slow sender,
 * flood, half-close, reorder, tamper, downgrade, stale disclosure, peer
 * terminal mid-session, public bind, remote admin, direct tool — each a
 * first-class classification with a deterministic, fail-closed disposition.
 *
 * SCOPE LAW: LOCAL NETWORK ONLY. Endpoint classes outside
 * {loopback, local_lan} are refused here at the contract layer; no
 * Internet/public endpoint, automatic discovery, cloud relay, NAT
 * traversal, consensus, or remote authority is representable in this
 * module's vocabularies (unknown values refuse rather than guess).
 */

import { canonicalHash } from "./canonical.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Transport trust-model contract schema version (26A). */
export const TRANSPORT_TRUST_SCHEMA_VERSION = "menog-transport-trust/v0" as const;
export type TransportTrustSchemaVersion = typeof TRANSPORT_TRUST_SCHEMA_VERSION;

// ── the nine transport pins (machine-checkable) ──────────────────────────────

/** The nine pins, as a closed, ordered vocabulary (T1..T9). */
export const TRANSPORT_TRUST_PINS = Object.freeze([
  "REACHABILITY_NOT_IDENTITY",
  "IDENTITY_NOT_ADMISSION",
  "ADMISSION_NOT_AUTHORITY",
  "AUTHENTICATED_SESSION_NOT_EXECUTION",
  "REMOTE_MESSAGE_NOT_LOCAL_POLICY",
  "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
  "CONNECTION_STATE_NOT_TRUST_STATE",
  "RECONNECT_NOT_RE_ADMISSION",
  "NETWORK_EVIDENCE_NOT_AUTHORITY",
] as const);
export type TransportTrustPin = (typeof TRANSPORT_TRUST_PINS)[number];

/**
 * Deterministic, closed explanations for each pin. The SAME strings are
 * embedded in every decision this module emits, so explanations are
 * stable, greppable, and test-pinned (no free-form authority prose).
 */
export const TRANSPORT_TRUST_PIN_EXPLANATIONS: Readonly<
  Record<TransportTrustPin, string>
> = Object.freeze({
  REACHABILITY_NOT_IDENTITY:
    "T1 REACHABILITY != IDENTITY: a reachable endpoint proves only that bytes could be sent; reachability names no node and never substitutes for 24B identity verification.",
  IDENTITY_NOT_ADMISSION:
    "T2 IDENTITY != ADMISSION: a verified identity is not peer admission; admission remains the frozen 24C registry's evidenced local decision.",
  ADMISSION_NOT_AUTHORITY:
    "T3 ADMISSION != AUTHORITY: admitting a peer grants communication trust only; execution authority still requires fresh LOCAL Allocation, LOCAL Policy, Phase-20 isolation, and the Phase-21 governed tool runtime.",
  AUTHENTICATED_SESSION_NOT_EXECUTION:
    "T4 AUTHENTICATED SESSION != EXECUTION: an authenticated transport session never executes anything; it only carries bounded frames as untrusted DATA toward the frozen local pipeline.",
  REMOTE_MESSAGE_NOT_LOCAL_POLICY:
    "T5 REMOTE MESSAGE != LOCAL POLICY: a remote-delivered message is untrusted DATA and can never be, choose, or override a local Policy decision.",
  TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE:
    "T6 TRANSPORT SUCCESS != APPLICATION ACCEPTANCE: bytes written to a connection record only that the transport carried them; application acceptance is a separate local judgment.",
  CONNECTION_STATE_NOT_TRUST_STATE:
    "T7 CONNECTION STATE != TRUST STATE: connection and session states are transport facts; peer trust state lives only in the frozen 24C registry and is never mutated by transport events.",
  RECONNECT_NOT_RE_ADMISSION:
    "T8 RECONNECT != RE-ADMISSION: a new connection starts with zero carried trust; admission is re-checked fresh against the 24C registry and is never inherited from a prior session.",
  NETWORK_EVIDENCE_NOT_AUTHORITY:
    "T9 NETWORK EVIDENCE != AUTHORITY: transport evidence records what happened on the wire; consuming it grants, widens, and resumes nothing.",
});

// ── endpoint vocabulary (closed) ─────────────────────────────────────────────

/**
 * Endpoint classes. Only LOCAL classes can ever be accepted; `public` and
 * `discovery` exist solely so they can be NAMED and REFUSED deterministically
 * (an unnamed class cannot ride through — fail closed on unknown values).
 */
export const TRANSPORT_ENDPOINT_CLASSES = Object.freeze([
  "loopback",
  "local_lan",
  "public",
  "discovery",
  "unknown",
] as const);
export type TransportEndpointClass = (typeof TRANSPORT_ENDPOINT_CLASSES)[number];

/** Bind addresses that are implicitly out of the LOCAL NETWORK ONLY scope. */
export const TRANSPORT_FORBIDDEN_BIND_ADDRESSES = Object.freeze([
  "0.0.0.0",
  "::",
  "*",
  "[::]",
] as const);

export type EndpointDeclarationDecision =
  | { readonly ok: true; readonly code: "endpoint_in_local_scope"; readonly endpointClass: TransportEndpointClass; readonly explanation: string; readonly provenanceHash: string }
  | { readonly ok: false; readonly code: "endpoint_refused"; readonly refusal: TransportRefusalCode; readonly endpointClass: TransportEndpointClass; readonly explanation: string; readonly provenanceHash: string };

/**
 * Decide an endpoint declaration (contract layer — no binding happens here).
 * loopback/local_lan are in scope; public and discovery are refused by the
 * LOCAL NETWORK ONLY law; a wildcard/public bind address refuses REGARDLESS
 * of the declared class (the address outranks the label); unknown classes
 * refuse rather than guess.
 */
export function decideEndpointDeclaration(input: {
  readonly endpointClass: TransportEndpointClass;
  readonly bindAddress: string;
  readonly decidedAtEpochMs: number;
}): EndpointDeclarationDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: TRANSPORT_TRUST_SCHEMA_VERSION,
    endpointClass: input.endpointClass,
    bindAddress: input.bindAddress,
    decidedAtEpochMs: input.decidedAtEpochMs,
  });
  if (TRANSPORT_FORBIDDEN_BIND_ADDRESSES.includes(input.bindAddress as (typeof TRANSPORT_FORBIDDEN_BIND_ADDRESSES)[number])) {
    return {
      ok: false,
      code: "endpoint_refused",
      refusal: "refused_public_bind",
      endpointClass: input.endpointClass,
      explanation:
        "a wildcard/public bind address is outside the LOCAL NETWORK ONLY scope — refused regardless of the declared endpoint class (pack law: no public endpoints)",
      provenanceHash,
    };
  }
  switch (input.endpointClass) {
    case "loopback":
    case "local_lan":
      return {
        ok: true,
        code: "endpoint_in_local_scope",
        endpointClass: input.endpointClass,
        explanation:
          "endpoint class '" + input.endpointClass + "' is within the LOCAL NETWORK ONLY scope — declared only; this contract binds nothing and opens nothing (26B owns any listener boundary)",
        provenanceHash,
      };
    case "public":
      return {
        ok: false,
        code: "endpoint_refused",
        refusal: "refused_public_bind",
        endpointClass: input.endpointClass,
        explanation:
          "endpoint class 'public' is refused by the LOCAL NETWORK ONLY law — public/internet endpoints are not representable as accepted transport scope",
        provenanceHash,
      };
    case "discovery":
      return {
        ok: false,
        code: "endpoint_refused",
        refusal: "refused_discovery_endpoint",
        endpointClass: input.endpointClass,
        explanation:
          "endpoint class 'discovery' is refused — automatic discovery is forbidden by pack law; peers are only ever the locally configured or 24C-admitted set",
        provenanceHash,
      };
    case "unknown":
      return {
        ok: false,
        code: "endpoint_refused",
        refusal: "refused_unknown_endpoint_class",
        endpointClass: "unknown",
        explanation: "unknown endpoint class — refusing (fail closed); an unnamed class cannot ride through",
        provenanceHash,
      };
    default: {
      const unknown: never = input.endpointClass;
      void unknown;
      return {
        ok: false,
        code: "endpoint_refused",
        refusal: "refused_unknown_endpoint_class",
        endpointClass: "unknown",
        explanation: "unmapped endpoint class — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── transport (connection outcome) vocabulary (closed) ───────────────────────

/** Raw connection-level outcomes. Each is a TRANSPORT FACT, never an acceptance. */
export const TRANSPORT_OUTCOMES = Object.freeze([
  "transport_connected",
  "transport_refused",
  "transport_timeout",
  "transport_reset",
] as const);
export type TransportOutcome = (typeof TRANSPORT_OUTCOMES)[number];

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Every refusal this contract can emit. Unknown codes are unrepresentable. */
export const TRANSPORT_REFUSAL_CODES = Object.freeze([
  "refused_public_bind",
  "refused_discovery_endpoint",
  "refused_unknown_endpoint_class",
  "refused_oversize",
  "refused_truncated",
  "refused_tampered",
  "refused_downgrade",
  "refused_replay",
  "refused_duplicate",
  "refused_reordered",
  "refused_half_closed_direction",
  "refused_stale_disclosure",
  "refused_slow_sender",
  "refused_flood",
  "refused_claim_crosses_boundary",
  "refused_out_of_transport_scope",
  "refused_unknown_scope",
  "refused_invalid_session_transition",
  "refused_anonymous_claim",
  "refused_unknown",
] as const);
export type TransportRefusalCode = (typeof TRANSPORT_REFUSAL_CODES)[number];

// ── close vocabulary (closed) ────────────────────────────────────────────────

/** Why a session closes. A close is a transport fact, never a trust event. */
export const TRANSPORT_CLOSE_REASONS = Object.freeze([
  "local_close",
  "remote_close",
  "authentication_failed",
  "protocol_violation",
  "timeout",
  "fault",
  "shutdown",
  "half_close_completed",
  "refused_by_gate",
] as const);
export type TransportCloseReason = (typeof TRANSPORT_CLOSE_REASONS)[number];

// ── frame vocabulary + bounded frame decision ────────────────────────────────

/** Frame dispositions (closed). Acceptance means ONLY "in-order, bounded, intact". */
export const FRAME_DISPOSITIONS = Object.freeze([
  "frame_accepted",
  "refused_oversize",
  "refused_truncated",
  "refused_tampered",
  "refused_downgrade",
  "refused_replay",
  "refused_duplicate",
  "refused_reordered",
  "refused_half_closed_direction",
  "refused_stale_disclosure",
] as const);
export type FrameDisposition = (typeof FRAME_DISPOSITIONS)[number];

/**
 * Pinned transport bounds. These refuse to widen: they are constants, not
 * caller inputs (a caller can only send MORE than the bound, never redefine it).
 */
export const TRANSPORT_BOUNDS = Object.freeze({
  maxFrameBytes: 8192,
  maxFramesPerWindow: 256,
  frameWindowMs: 1000,
  slowSenderMaxGapMs: 30000,
});

export interface FrameDecision {
  readonly disposition: FrameDisposition;
  /** null exactly when disposition === "frame_accepted". */
  readonly refusal: TransportRefusalCode | null;
  readonly pins: readonly TransportTrustPin[];
  /** Deterministic; identical facts always yield identical explanations. */
  readonly explanation: string;
}

/**
 * The deterministic frame decision. Checks run in a PINNED order (first
 * match wins — the suite pins the precedence with multi-violation inputs):
 *   oversize → truncation → tamper → downgrade → replay → duplicate →
 *   reorder → half-close direction → stale disclosure → accept.
 * `frameAccepted` therefore means ONLY: bounded, byte-identical, integrity-
 * verified, protocol-matched, first-seen, in-order, sent on an open
 * direction, with a fresh disclosure. It never means admission, authority,
 * Policy, execution, or application acceptance (T1–T9).
 */
export function decideFrame(input: {
  readonly declaredBytes: number;
  readonly actualBytes: number;
  readonly sequence: number;
  readonly expectedSequence: number;
  readonly previouslyDelivered: boolean;
  readonly integrityOk: boolean;
  readonly protocolVersion: string;
  readonly expectedProtocolVersion: string;
  readonly disclosureFresh: boolean;
  readonly halfClosedDirection: "none" | "local" | "remote";
  readonly frameDirection: "inbound" | "outbound";
}): FrameDecision {
  if (
    input.declaredBytes > TRANSPORT_BOUNDS.maxFrameBytes ||
    input.actualBytes > TRANSPORT_BOUNDS.maxFrameBytes ||
    input.declaredBytes < 0 ||
    !Number.isInteger(input.declaredBytes) ||
    !Number.isInteger(input.actualBytes)
  ) {
    return {
      disposition: "refused_oversize",
      refusal: "refused_oversize",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame declares " + String(input.declaredBytes) + "/" + String(input.actualBytes) +
        " bytes against the pinned bound " + String(TRANSPORT_BOUNDS.maxFrameBytes) +
        " — oversize or malformed frames refuse; the bound is a constant and cannot be widened by the caller (T6)",
    };
  }
  if (input.actualBytes !== input.declaredBytes) {
    return {
      disposition: "refused_truncated",
      refusal: "refused_truncated",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame declared " + String(input.declaredBytes) + " bytes but " + String(input.actualBytes) +
        " arrived — truncation refuses; partial bytes are never padded, guessed, or accepted (T6)",
    };
  }
  if (!input.integrityOk) {
    return {
      disposition: "refused_tampered",
      refusal: "refused_tampered",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame failed its integrity check — tampering refuses the frame and closes the exchange basis; transport success never implies acceptance (T6)",
    };
  }
  if (input.protocolVersion !== input.expectedProtocolVersion) {
    return {
      disposition: "refused_downgrade",
      refusal: "refused_downgrade",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame protocol version '" + input.protocolVersion + "' does not equal the pinned expected '" +
        input.expectedProtocolVersion + "' — downgrade/mismatch refuses; versions are exact-equality pins, never negotiated down (T6)",
    };
  }
  if (input.previouslyDelivered) {
    return {
      disposition: "refused_replay",
      refusal: "refused_replay",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame was already delivered (durable replay guard, 24D discipline) — replay refuses with zero downstream evaluation (T6)",
    };
  }
  if (input.sequence < input.expectedSequence) {
    return {
      disposition: "refused_duplicate",
      refusal: "refused_duplicate",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame sequence " + String(input.sequence) + " is behind expected " + String(input.expectedSequence) +
        " — duplicate frames refuse; already-covered sequence numbers never re-enter (T6)",
    };
  }
  if (input.sequence > input.expectedSequence) {
    return {
      disposition: "refused_reordered",
      refusal: "refused_reordered",
      pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      explanation:
        "frame sequence " + String(input.sequence) + " jumps ahead of expected " + String(input.expectedSequence) +
        " — reordered frames refuse; this transport accepts strict in-order delivery only, never gap-fill (T6)",
    };
  }
  if (
    (input.halfClosedDirection === "local" && input.frameDirection === "outbound") ||
    (input.halfClosedDirection === "remote" && input.frameDirection === "inbound")
  ) {
    return {
      disposition: "refused_half_closed_direction",
      refusal: "refused_half_closed_direction",
      pins: ["CONNECTION_STATE_NOT_TRUST_STATE"],
      explanation:
        "the '" + input.halfClosedDirection + "' side has half-closed its send direction; frames in the " +
        input.frameDirection + " direction refuse — half-close is a transport fact only and never a trust event (T7)",
    };
  }
  if (!input.disclosureFresh) {
    return {
      disposition: "refused_stale_disclosure",
      refusal: "refused_stale_disclosure",
      pins: ["NETWORK_EVIDENCE_NOT_AUTHORITY"],
      explanation:
        "the frame's disclosure binding is stale against the outgoing payload (25D stale-discipline) — stale disclosure refuses; a prior disclosure never authorizes a later send (T9)",
    };
  }
  return {
    disposition: "frame_accepted",
    refusal: null,
    pins: [
      "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
      "CONNECTION_STATE_NOT_TRUST_STATE",
    ],
    explanation:
      "frame accepted as bounded, intact, in-order transport DATA only — acceptance is NOT application acceptance, admission, authority, Policy, or execution (T6/T7); the frozen local pipeline still evaluates everything fresh",
  };
}

/**
 * Deterministic sender-pace decision (slow sender / flood). Bounds are the
 * pinned TRANSPORT_BOUNDS constants; the caller supplies only observations.
 */
export function decideSenderPace(input: {
  readonly framesInWindow: number;
  readonly msSinceLastFrame: number;
}): { readonly ok: boolean; readonly refusal: TransportRefusalCode | null; readonly explanation: string } {
  if (input.framesInWindow >= TRANSPORT_BOUNDS.maxFramesPerWindow) {
    return {
      ok: false,
      refusal: "refused_flood",
      explanation:
        "sender sent " + String(input.framesInWindow) + " frames within the pinned window (" +
        String(TRANSPORT_BOUNDS.maxFramesPerWindow) + " per " + String(TRANSPORT_BOUNDS.frameWindowMs) +
        " ms) — flood refuses and closes the exchange basis; the bound cannot be widened",
    };
  }
  if (input.msSinceLastFrame > TRANSPORT_BOUNDS.slowSenderMaxGapMs) {
    return {
      ok: false,
      refusal: "refused_slow_sender",
      explanation:
        "sender idle " + String(input.msSinceLastFrame) + " ms exceeds the pinned slow-sender gap (" +
        String(TRANSPORT_BOUNDS.slowSenderMaxGapMs) + " ms) — slow sender refuses; stalls are closed, never waited on unboundedly",
    };
  }
  return {
    ok: true,
    refusal: null,
    explanation:
      "sender pace within the pinned bounds — pace OK says nothing about identity, admission, or acceptance (T1/T6)",
  };
}

// ── session vocabulary + deterministic state machine ─────────────────────────

/** Session states (closed). No state here is a trust state (T7). */
export const SESSION_STATES = Object.freeze([
  "no_session",
  "connected",
  "authenticated",
  "half_closed_local",
  "half_closed_remote",
  "closed",
  "faulted",
] as const);
export type SessionState = (typeof SESSION_STATES)[number];

/** Session events (closed). */
export const SESSION_EVENTS = Object.freeze([
  "connect",
  "authenticate_ok",
  "authenticate_fail",
  "local_half_close",
  "remote_half_close",
  "close",
  "fault",
  "reconnect",
] as const);
export type SessionEvent = (typeof SESSION_EVENTS)[number];

export interface SessionTransition {
  readonly ok: boolean;
  readonly code: "session_state_advanced" | "session_transition_refused";
  /** The resulting state; UNCHANGED from the prior state when refused. */
  readonly state: SessionState;
  readonly closeReason: TransportCloseReason | null;
  readonly refusal: TransportRefusalCode | null;
  /**
   * TRUE for every non-terminal state: usable sessions ALWAYS require a
   * fresh 24C admission check before anything downstream (T2/T8).
   */
  readonly freshAdmissionRequired: boolean;
  /** Structural constant: transport transitions never carry trust (T7/T8). */
  readonly trustCarried: false;
  readonly explanation: string;
}

function advanced(
  state: SessionState,
  closeReason: TransportCloseReason | null,
  explanation: string
): SessionTransition {
  const terminal = state === "closed" || state === "faulted" || state === "no_session";
  return {
    ok: true,
    code: "session_state_advanced",
    state,
    closeReason,
    refusal: null,
    freshAdmissionRequired: terminal ? false : true,
    trustCarried: false,
    explanation,
  };
}

function refusedTransition(
  state: SessionState,
  explanation: string
): SessionTransition {
  return {
    ok: false,
    code: "session_transition_refused",
    state,
    closeReason: null,
    refusal: "refused_invalid_session_transition",
    freshAdmissionRequired: state === "closed" || state === "faulted" || state === "no_session" ? false : true,
    trustCarried: false,
    explanation,
  };
}

/**
 * Deterministic session state machine (transport facts ONLY). Rules the
 * suite pins:
 *  - connect/reconnect from closed/faulted starts a NEW session carrying
 *    ZERO trust (trustCarried is the literal false; fresh admission is
 *    required again) — T8.
 *  - authentication is a transport fact; authenticate_fail closes with
 *    `authentication_failed`; authenticating twice or without a connection
 *    refuses (fail closed, no silent transitions).
 *  - half-close from `connected`/`authenticated` moves to the matching
 *    half-closed state; the SECOND half-close completes the close
 *    (`half_close_completed`).
 *  - every non-terminal transition sets freshAdmissionRequired: true —
 *    no session state ever waives the fresh 24C admission re-check (T2/T7).
 *  - unknown state/event combinations refuse; the state NEVER changes on a
 *    refusal.
 */
export function decideSessionTransition(input: {
  readonly state: SessionState;
  readonly event: SessionEvent;
}): SessionTransition {
  const { state, event } = input;
  switch (state) {
    case "no_session":
      if (event === "connect") {
        return advanced(
          "connected",
          null,
          "no_session + connect → connected: a connection is opened as a transport fact; it names no peer, carries no trust, and requires a fresh 24C admission check before anything downstream (T1/T2/T7)"
        );
      }
      return refusedTransition(
        state,
        "no_session refuses event '" + event + "' — there is no session to authenticate, half-close, close, fault, or reconnect; fail closed with no state change (reconnect without a prior session is not a connect)"
      );
    case "connected":
      switch (event) {
        case "authenticate_ok":
          return advanced(
            "authenticated",
            null,
            "connected + authenticate_ok → authenticated: authentication is a transport fact; the session still executes nothing and still requires fresh admission (T4/T2/T7)"
          );
        case "authenticate_fail":
          return advanced(
            "closed",
            "authentication_failed",
            "connected + authenticate_fail → closed(authentication_failed): failed authentication closes the session; no retry loop, no state widening (T7)"
          );
        case "local_half_close":
          return advanced(
            "half_closed_local",
            null,
            "connected + local_half_close → half_closed_local: half-close is a transport fact only; trust state is untouched (T7)"
          );
        case "remote_half_close":
          return advanced(
            "half_closed_remote",
            null,
            "connected + remote_half_close → half_closed_remote: half-close is a transport fact only; trust state is untouched (T7)"
          );
        case "close":
          return advanced("closed", "local_close", "connected + close → closed(local_close): local close is a transport fact; nothing resumes from it (T7)");
        case "fault":
          return advanced("faulted", "fault", "connected + fault → faulted(fault): a faulted session is terminal for this session object; reconnect starts fresh with zero trust (T8)");
        default:
          return refusedTransition(
            state,
            "connected refuses event '" + event + "' — connect while connected, reconnect while connected, and re-authentication refuse (no silent double-connect, no state change)"
          );
      }
    case "authenticated":
      switch (event) {
        case "local_half_close":
          return advanced(
            "half_closed_local",
            null,
            "authenticated + local_half_close → half_closed_local: half-close never mutates trust state (T7)"
          );
        case "remote_half_close":
          return advanced(
            "half_closed_remote",
            null,
            "authenticated + remote_half_close → half_closed_remote: half-close never mutates trust state (T7)"
          );
        case "close":
          return advanced("closed", "local_close", "authenticated + close → closed(local_close): closing carries no trust anywhere; a later reconnect must re-earn admission (T8)");
        case "fault":
          return advanced("faulted", "fault", "authenticated + fault → faulted(fault): faulted is terminal for this session; zero trust carries forward (T8)");
        default:
          return refusedTransition(
            state,
            "authenticated refuses event '" + event + "' — duplicate authentication, connect, reconnect, and authenticate_fail all refuse on an already-authenticated session (fail closed)"
          );
      }
    case "half_closed_local":
    case "half_closed_remote": {
      const opposite: SessionEvent = state === "half_closed_local" ? "remote_half_close" : "local_half_close";
      if (event === opposite) {
        return advanced(
          "closed",
          "half_close_completed",
          state + " + " + event + " → closed(half_close_completed): both send directions closed; the close is a transport fact and carries no trust (T7/T8)"
        );
      }
      if (event === "close") {
        return advanced("closed", "local_close", state + " + close → closed(local_close): explicit close ends the session as a transport fact (T7)");
      }
      if (event === "fault") {
        return advanced("faulted", "fault", state + " + fault → faulted(fault): a fault mid-half-close is terminal for this session (T7)");
      }
      return refusedTransition(
        state,
        state + " refuses event '" + event + "' — only the opposite half-close (completing the close), close, or fault are legal here; fail closed with no state change"
      );
    }
    case "closed":
    case "faulted": {
      if (event === "reconnect" || event === "connect") {
        return advanced(
          "connected",
          null,
          state + " + " + event + " → connected: a NEW session object with ZERO carried trust — trustCarried is structurally false and fresh 24C admission is required again; reconnect is never re-admission (T8/T7)"
        );
      }
      return refusedTransition(
        state,
        state + " refuses event '" + event + "' — terminal sessions accept only connect/reconnect (which start fresh with zero trust); all other events fail closed with no state change"
      );
    }
    default: {
      const unknownState: never = state;
      void unknownState;
      return refusedTransition("no_session", "unknown session state — refusing (fail closed)");
    }
  }
}

// ── scope vocabulary (closed) ────────────────────────────────────────────────

/** What the transport layer is ALLOWED to do (closed MAY set). */
export const TRANSPORT_SCOPES = Object.freeze([
  "declare_local_endpoint",
  "open_local_connection",
  "send_bounded_frame",
  "receive_bounded_frame",
  "close_session",
  "record_network_evidence",
] as const);
export type TransportScope = (typeof TRANSPORT_SCOPES)[number];

/**
 * Capabilities the transport layer MUST NEVER hold (closed MAY-NOT set).
 * Each maps to the pin that refuses it; unknown capabilities refuse too.
 */
export const TRANSPORT_NON_SCOPES = Object.freeze([
  "execute_tool",
  "choose_policy",
  "admit_peer",
  "grant_authority",
  "persist_record",
  "administer_peer",
  "discover_peers",
  "bind_public",
  "traverse_nat",
  "relay_cloud",
  "reach_internet",
] as const);
export type TransportNonScope = (typeof TRANSPORT_NON_SCOPES)[number];

const NON_SCOPE_PINS: Readonly<Record<TransportNonScope, TransportTrustPin>> = Object.freeze({
  execute_tool: "AUTHENTICATED_SESSION_NOT_EXECUTION",
  choose_policy: "REMOTE_MESSAGE_NOT_LOCAL_POLICY",
  admit_peer: "IDENTITY_NOT_ADMISSION",
  grant_authority: "ADMISSION_NOT_AUTHORITY",
  persist_record: "NETWORK_EVIDENCE_NOT_AUTHORITY",
  administer_peer: "ADMISSION_NOT_AUTHORITY",
  discover_peers: "REACHABILITY_NOT_IDENTITY",
  bind_public: "REACHABILITY_NOT_IDENTITY",
  traverse_nat: "REACHABILITY_NOT_IDENTITY",
  relay_cloud: "REACHABILITY_NOT_IDENTITY",
  reach_internet: "REACHABILITY_NOT_IDENTITY",
});

export type ScopeDecision =
  | { readonly ok: true; readonly code: "within_transport_scope"; readonly scope: TransportScope; readonly explanation: string }
  | { readonly ok: false; readonly code: "outside_transport_scope"; readonly refusal: TransportRefusalCode; readonly violatedPin: TransportTrustPin | null; readonly explanation: string };

/**
 * Decide a requested transport capability. Closed MAY set passes; the closed
 * MAY-NOT set refuses naming its pin; anything unknown refuses with null pin
 * (fail closed — an unnamed capability cannot ride through).
 */
export function decideTransportScope(request: { readonly capability: string }): ScopeDecision {
  if ((TRANSPORT_SCOPES as readonly string[]).includes(request.capability)) {
    const scope = request.capability as TransportScope;
    return {
      ok: true,
      code: "within_transport_scope",
      scope,
      explanation:
        "capability '" + scope + "' is within the closed transport MAY set — bounded transport behavior only; it executes nothing and grants nothing (T3/T4)",
    };
  }
  if ((TRANSPORT_NON_SCOPES as readonly string[]).includes(request.capability)) {
    const nonScope = request.capability as TransportNonScope;
    return {
      ok: false,
      code: "outside_transport_scope",
      refusal: "refused_out_of_transport_scope",
      violatedPin: NON_SCOPE_PINS[nonScope],
      explanation:
        "capability '" + nonScope + "' is in the closed transport MAY-NOT set — refused by " +
        NON_SCOPE_PINS[nonScope] + "; the transport layer never holds this capability at all",
    };
  }
  return {
    ok: false,
    code: "outside_transport_scope",
    refusal: "refused_unknown_scope",
    violatedPin: null,
    explanation:
      "capability '" + request.capability + "' is not in the closed transport vocabulary — refusing (fail closed); only the pinned MAY set is representable",
  };
}

// ── transport claim decisions (the nine pins over one claim) ─────────────────

/** Claims presented AT the transport boundary (by a peer or process). */
export type TransportClaimKind =
  | "reachability_fact"
  | "identity_fact"
  | "admission_fact"
  | "frame_data_fact"
  | "authenticated_session_execution_claim"
  | "remote_message_policy_claim"
  | "transport_success_acceptance_claim"
  | "connection_state_trust_claim"
  | "reconnect_readmission_claim"
  | "network_evidence_authority_claim";

export type TransportClaimDecision =
  | { readonly ok: true; readonly code: "claim_received_as_data"; readonly explanation: string; readonly provenanceHash: string }
  | { readonly ok: false; readonly code: "claim_crosses_boundary"; readonly violatedPin: TransportTrustPin; readonly explanation: string; readonly provenanceHash: string };

/**
 * Decide a claim presented at the transport boundary. Fact claims
 * (reachability/identity/admission/frame bytes) are receivable precisely
 * because they grant nothing (T1/T2/T3). Claims that ASSERT a conflation —
 * execution from an authenticated session, Policy from a remote message,
 * acceptance from transport success, trust from connection state,
 * re-admission from reconnect, authority from network evidence — cross the
 * boundary and are refused, naming the violated pin (T4–T9).
 * Deterministic: the provenance hash binds (kind, subject, decidedAt).
 */
export function decideTransportClaim(input: {
  readonly claimKind: TransportClaimKind;
  readonly subject: string;
  readonly decidedAtEpochMs: number;
}): TransportClaimDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: TRANSPORT_TRUST_SCHEMA_VERSION,
    claimKind: input.claimKind,
    subject: input.subject,
    decidedAtEpochMs: input.decidedAtEpochMs,
  });
  if (typeof input.subject !== "string" || input.subject.length === 0) {
    return {
      ok: false,
      code: "claim_crosses_boundary",
      violatedPin: "REACHABILITY_NOT_IDENTITY",
      explanation:
        "transport claim carries no subject — an anonymous claim cannot even be evaluated as DATA (fail closed)",
      provenanceHash,
    };
  }
  switch (input.claimKind) {
    case "reachability_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.REACHABILITY_NOT_IDENTITY + " The fact is receivable as DATA and identifies nothing.",
        provenanceHash,
      };
    case "identity_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.IDENTITY_NOT_ADMISSION + " The fact is receivable as DATA and admits nothing by itself.",
        provenanceHash,
      };
    case "admission_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.ADMISSION_NOT_AUTHORITY + " The fact is receivable as DATA and authorizes nothing.",
        provenanceHash,
      };
    case "frame_data_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.REMOTE_MESSAGE_NOT_LOCAL_POLICY + " Frame bytes are untrusted DATA on the way to the frozen local pipeline.",
        provenanceHash,
      };
    case "authenticated_session_execution_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "AUTHENTICATED_SESSION_NOT_EXECUTION",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.AUTHENTICATED_SESSION_NOT_EXECUTION + " A claim that an authenticated session may execute crosses the boundary and is refused.",
        provenanceHash,
      };
    case "remote_message_policy_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "REMOTE_MESSAGE_NOT_LOCAL_POLICY",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.REMOTE_MESSAGE_NOT_LOCAL_POLICY + " A claim that a remote message is (or decides) Policy crosses the boundary and is refused.",
        provenanceHash,
      };
    case "transport_success_acceptance_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE + " A claim that transport success is application acceptance crosses the boundary and is refused.",
        provenanceHash,
      };
    case "connection_state_trust_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "CONNECTION_STATE_NOT_TRUST_STATE",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.CONNECTION_STATE_NOT_TRUST_STATE + " A claim that connection state is trust state crosses the boundary and is refused.",
        provenanceHash,
      };
    case "reconnect_readmission_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "RECONNECT_NOT_RE_ADMISSION",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.RECONNECT_NOT_RE_ADMISSION + " A claim that reconnecting re-admits the peer crosses the boundary and is refused.",
        provenanceHash,
      };
    case "network_evidence_authority_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "NETWORK_EVIDENCE_NOT_AUTHORITY",
        explanation: TRANSPORT_TRUST_PIN_EXPLANATIONS.NETWORK_EVIDENCE_NOT_AUTHORITY + " A claim that transport evidence grants authority crosses the boundary and is refused.",
        provenanceHash,
      };
    default: {
      const unknown: never = input.claimKind;
      void unknown;
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "REACHABILITY_NOT_IDENTITY",
        explanation: "unknown transport claim kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── transport threat vocabulary (closed TT-01..TT-18) ────────────────────────

/** The closed transport-threat catalog. Every pack-named threat appears exactly once. */
export const TRANSPORT_THREAT_IDS = Object.freeze([
  "TT-01_unknown_source",
  "TT-02_wrong_key",
  "TT-03_stale_session",
  "TT-04_replay",
  "TT-05_duplicate",
  "TT-06_truncation",
  "TT-07_oversize",
  "TT-08_slow_sender",
  "TT-09_flood",
  "TT-10_half_close_misuse",
  "TT-11_reorder",
  "TT-12_tamper",
  "TT-13_downgrade",
  "TT-14_stale_disclosure",
  "TT-15_peer_terminal_mid_session",
  "TT-16_public_bind",
  "TT-17_remote_admin",
  "TT-18_direct_tool",
] as const);
export type TransportThreatId = (typeof TRANSPORT_THREAT_IDS)[number];

/** Closed threat dispositions (fail-closed; no silent handling exists). */
export const TRANSPORT_THREAT_DISPOSITIONS = Object.freeze([
  "refuse",
  "close_session",
  "monitor",
] as const);
export type TransportThreatDisposition = (typeof TRANSPORT_THREAT_DISPOSITIONS)[number];

export interface TransportThreatClassification {
  readonly threatId: TransportThreatId;
  readonly disposition: TransportThreatDisposition;
  readonly refusal: TransportRefusalCode;
  readonly pins: readonly TransportTrustPin[];
  /** Deterministic; identical threats always yield identical explanations. */
  readonly explanation: string;
}

/**
 * Deterministic threat classification (pure). Each of the pack's eighteen
 * threats maps to exactly one disposition, one refusal code, and its pins.
 * Unknown ids refuse (fail closed) rather than fall through unnamed.
 */
export function classifyTransportThreat(threatId: TransportThreatId): TransportThreatClassification {
  switch (threatId) {
    case "TT-01_unknown_source":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_claim_crosses_boundary",
        pins: ["REACHABILITY_NOT_IDENTITY", "IDENTITY_NOT_ADMISSION"],
        explanation: "TT-01 unknown source: an unreachable-to-name source is refused before evaluation — reachability is not identity and an unknown source is never admitted by the transport (T1/T2)",
      };
    case "TT-02_wrong_key":
      return {
        threatId,
        disposition: "close_session",
        refusal: "refused_tampered",
        pins: ["IDENTITY_NOT_ADMISSION"],
        explanation: "TT-02 wrong key: a signature/key mismatch closes the session; identity verification stays the 24B layer's job and a wrong key never merely 'fails forward' (T2)",
      };
    case "TT-03_stale_session":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_replay",
        pins: ["CONNECTION_STATE_NOT_TRUST_STATE"],
        explanation: "TT-03 stale session: stale session material is refused — session state never became trust state and cannot be revived by age or replay (T7)",
      };
    case "TT-04_replay":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_replay",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-04 replay: previously delivered frames refuse at the durable guard before downstream evaluation (24D discipline; T6)",
      };
    case "TT-05_duplicate":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_duplicate",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-05 duplicate: already-covered sequence numbers refuse; duplicates never re-enter the pipeline (T6)",
      };
    case "TT-06_truncation":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_truncated",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-06 truncation: byte-count mismatch refuses the frame; partial data is never padded or guessed (T6)",
      };
    case "TT-07_oversize":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_oversize",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-07 oversize: frames beyond the pinned bound refuse; bounds are constants and cannot widen (T6)",
      };
    case "TT-08_slow_sender":
      return {
        threatId,
        disposition: "close_session",
        refusal: "refused_slow_sender",
        pins: ["CONNECTION_STATE_NOT_TRUST_STATE"],
        explanation: "TT-08 slow sender: an idle gap beyond the pinned bound closes the session; stalls are never waited on unboundedly and no trust attaches to the stall (T7)",
      };
    case "TT-09_flood":
      return {
        threatId,
        disposition: "close_session",
        refusal: "refused_flood",
        pins: ["CONNECTION_STATE_NOT_TRUST_STATE"],
        explanation: "TT-09 flood: a frame rate beyond the pinned window closes the session; the bound cannot widen and no trust attaches to the flood (T7)",
      };
    case "TT-10_half_close_misuse":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_half_closed_direction",
        pins: ["CONNECTION_STATE_NOT_TRUST_STATE"],
        explanation: "TT-10 half-close misuse: frames in a half-closed direction refuse — half-close is a transport fact, never a trust or delivery override (T7)",
      };
    case "TT-11_reorder":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_reordered",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-11 reorder: out-of-order frames refuse; strict in-order delivery only, never gap-fill (T6)",
      };
    case "TT-12_tamper":
      return {
        threatId,
        disposition: "close_session",
        refusal: "refused_tampered",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-12 tamper: an integrity failure closes the session; transport success never implies acceptance of tampered bytes (T6)",
      };
    case "TT-13_downgrade":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_downgrade",
        pins: ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
        explanation: "TT-13 downgrade: protocol version mismatch refuses; versions are exact-equality pins and are never negotiated down (T6)",
      };
    case "TT-14_stale_disclosure":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_stale_disclosure",
        pins: ["NETWORK_EVIDENCE_NOT_AUTHORITY"],
        explanation: "TT-14 stale disclosure: a stale 25D disclosure binding refuses — a prior disclosure never authorizes a later send (T9)",
      };
    case "TT-15_peer_terminal_mid_session":
      return {
        threatId,
        disposition: "close_session",
        refusal: "refused_claim_crosses_boundary",
        pins: ["IDENTITY_NOT_ADMISSION", "CONNECTION_STATE_NOT_TRUST_STATE"],
        explanation: "TT-15 peer terminal mid-session: if the 24C registry says the peer is quarantined/retired (terminal), the session closes — transport never overrides terminal trust state and never resurrects it (T2/T7)",
      };
    case "TT-16_public_bind":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_public_bind",
        pins: ["REACHABILITY_NOT_IDENTITY"],
        explanation: "TT-16 public bind: any public/wildcard bind attempt refuses at the contract layer — LOCAL NETWORK ONLY; reachability outside local scope is never identity or access (T1)",
      };
    case "TT-17_remote_admin":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_out_of_transport_scope",
        pins: ["ADMISSION_NOT_AUTHORITY"],
        explanation: "TT-17 remote admin: an admin command arriving over the transport refuses — no remote control plane exists; a peer message can never be an admin command (25C law; T3)",
      };
    case "TT-18_direct_tool":
      return {
        threatId,
        disposition: "refuse",
        refusal: "refused_out_of_transport_scope",
        pins: ["AUTHENTICATED_SESSION_NOT_EXECUTION"],
        explanation: "TT-18 direct tool: any network→tool path refuses structurally — the transport has no tool capability at all; execution stays behind fresh LOCAL Allocation → Policy → Phase-20 → Phase-21 (T4)",
      };
    default: {
      const unknown: never = threatId;
      void unknown;
      return {
        threatId: "TT-01_unknown_source",
        disposition: "refuse",
        refusal: "refused_unknown",
        pins: ["REACHABILITY_NOT_IDENTITY"],
        explanation: "unknown transport threat id — refusing (fail closed)",
      };
    }
  }
}

// ── transport self-description (pure) ────────────────────────────────────────

/**
 * Deterministic, canonical description of the transport trust model for
 * provenance bindings (no I/O; pure function of the supplied facts).
 */
export function transportTrustFingerprint(input: {
  readonly localNodeId: string | null;
  readonly decidedAtEpochMs: number;
}): string {
  return canonicalHash({
    schemaVersion: TRANSPORT_TRUST_SCHEMA_VERSION,
    localNodeId: input.localNodeId,
    decidedAtEpochMs: input.decidedAtEpochMs,
    pins: TRANSPORT_TRUST_PINS,
    bounds: TRANSPORT_BOUNDS,
    scopes: TRANSPORT_SCOPES,
    threats: TRANSPORT_THREAT_IDS,
  });
}
