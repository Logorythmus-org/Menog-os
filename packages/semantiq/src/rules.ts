import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type {
  SemantiqClaim,
  SemantiqClaimKind,
  SemantiqDenyReason,
  SemantiqEvaluationRequest,
  SemantiqEventView,
} from "./types.js";
import {
  KNOWN_SEMANTIQ_CLAIM_KINDS,
  KNOWN_SEMANTIQ_DENY_REASONS,
  KNOWN_SEMANTIQ_EVENT_TYPES,
  KNOWN_SEMANTIQ_TRIGGERS,
} from "./types.js";

/**
 * Phase 18A — validation, bounding, and deterministic normalization for the
 * SemantIQ adapter. Mirrors the Phase-17 selector discipline:
 *  - requests are bounded and validated BEFORE any engine runs;
 *  - engine output is normalized into frozen, authority-pinned claims;
 *  - unknown/untrusted shapes are DROPPED (fail closed), never surfaced.
 */

/** Caps (18A): bounded evaluation surface, mirroring the Phase-17 style. */
export const SEMANTIQ_MAX_SUBJECT_CHARS = 256;
export const SEMANTIQ_MAX_NOTE_CHARS = 256;
export const SEMANTIQ_MAX_SUMMARY_CHARS = 512;
export const SEMANTIQ_MAX_CLAIMS = 16;
export const SEMANTIQ_MAX_CLAIM_VALUE_CHARS = 256;
export const SEMANTIQ_MAX_DERIVED_FROM = 64;
export const SEMANTIQ_MAX_EVENTS_PER_EVALUATION = 256;
export const SEMANTIQ_MAX_EVENT_ID_CHARS = 256;
export const SEMANTIQ_MAX_EVENT_TYPE_CHARS = 64;

export function isSemantiqDenyReason(value: unknown): value is SemantiqDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_SEMANTIQ_DENY_REASONS as readonly string[]).includes(value)
  );
}

/** Validate the bounded evaluation request; returns an error string or null. */
export function validateEvaluationRequest(
  request: SemantiqEvaluationRequest
): string | null {
  if (request === null || typeof request !== "object") {
    return "evaluation request must be an object";
  }
  if (typeof request.subject !== "string" || request.subject.length === 0) {
    return "subject must be a non-empty string";
  }
  if (request.subject.length > SEMANTIQ_MAX_SUBJECT_CHARS) {
    return (
      "subject is " +
      String(request.subject.length) +
      " chars which exceeds SEMANTIQ_MAX_SUBJECT_CHARS (" +
      String(SEMANTIQ_MAX_SUBJECT_CHARS) +
      ")"
    );
  }
  if (
    typeof request.trigger !== "string" ||
    !(KNOWN_SEMANTIQ_TRIGGERS as readonly string[]).includes(request.trigger)
  ) {
    return "trigger must be one of manual | scheduled | cli | event_hook | unknown";
  }
  if (request.eventTypes !== undefined) {
    if (!Array.isArray(request.eventTypes)) {
      return "eventTypes must be an array";
    }
    for (const t of request.eventTypes) {
      if (
        typeof t !== "string" ||
        !(KNOWN_SEMANTIQ_EVENT_TYPES as readonly string[]).includes(t)
      ) {
        return "eventTypes entries must be known SemantIQ event types";
      }
    }
  }
  if (request.note !== undefined) {
    if (typeof request.note !== "string") {
      return "note, when present, must be a string";
    }
    if (request.note.length > SEMANTIQ_MAX_NOTE_CHARS) {
      return (
        "note is " +
        String(request.note.length) +
        " chars which exceeds SEMANTIQ_MAX_NOTE_CHARS (" +
        String(SEMANTIQ_MAX_NOTE_CHARS) +
        ")"
      );
    }
  }
  return null;
}

/** A claim-shaped object attempting to carry an authority field. */
function carriesAuthorityField(raw: Record<string, unknown>): boolean {
  return (
    "executionAuthorized" in raw ||
    "policyDecision" in raw ||
    "grants" in raw ||
    "capabilities" in raw ||
    "authority" in raw
  );
}

/**
 * Normalize one engine-produced claim. Unknown kinds, non-string values,
 * non-finite confidence, or any attempt to carry an authority field result
 * in null (the claim is dropped, never surfaced).
 */
export function normalizeClaim(raw: unknown): SemantiqClaim | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (carriesAuthorityField(r)) return null;
  if (
    typeof r.kind !== "string" ||
    !(KNOWN_SEMANTIQ_CLAIM_KINDS as readonly string[]).includes(r.kind)
  ) {
    return null;
  }
  if (typeof r.value !== "string" || r.value.length === 0) return null;
  if (typeof r.confidence !== "number" || !Number.isFinite(r.confidence)) {
    return null;
  }
  const kind = r.kind as SemantiqClaimKind;
  const confidence = Math.max(0, Math.min(1, r.confidence));
  const value =
    r.value.length > SEMANTIQ_MAX_CLAIM_VALUE_CHARS
      ? r.value.slice(0, SEMANTIQ_MAX_CLAIM_VALUE_CHARS)
      : r.value;
  return Object.freeze({ kind, value, confidence });
}

/**
 * Normalize the raw ledger event into the bounded view the adapter consumes.
 * Unshapeable events are dropped (null) — a malformed ledger entry can never
 * poison an evaluation with unbounded or non-normalizable content.
 */
export function normalizeEventView(raw: unknown): SemantiqEventView | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (
    typeof r.eventId !== "string" ||
    r.eventId.length === 0 ||
    r.eventId.length > SEMANTIQ_MAX_EVENT_ID_CHARS ||
    typeof r.eventType !== "string" ||
    r.eventType.length === 0 ||
    r.eventType.length > SEMANTIQ_MAX_EVENT_TYPE_CHARS ||
    typeof r.timestamp !== "string"
  ) {
    return null;
  }
  const actor = r.actor as Record<string, unknown> | undefined;
  if (
    actor === null ||
    typeof actor !== "object" ||
    typeof actor.type !== "string" ||
    typeof actor.id !== "string"
  ) {
    return null;
  }
  return Object.freeze({
    eventId: r.eventId,
    eventType: r.eventType,
    actor: Object.freeze({ type: actor.type, id: actor.id }),
    timestamp: r.timestamp,
    ...(typeof r.verb === "string" ? { verb: r.verb.slice(0, 64) } : {}),
    ...(typeof r.policyDecision === "string"
      ? { policyDecision: r.policyDecision.slice(0, 32) }
      : {}),
  });
}

/** Machine-readable denial constructor (frozen). */
export function semantiqDeny(
  denyReason: SemantiqDenyReason,
  reason: string,
  stage: "requested" | "computed" = "requested"
): {
  readonly ok: false;
  readonly schemaVersion: "menog-semantiq/v0";
  readonly stage: typeof stage;
  readonly denyReason: SemantiqDenyReason;
  readonly reason: string;
} {
  return Object.freeze({
    ok: false,
    schemaVersion: SEMANTIQ_SCHEMA_VERSION,
    stage,
    denyReason,
    reason,
  });
}
