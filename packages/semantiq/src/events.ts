import { createHash } from "node:crypto";
import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type {
  SemantiqDimensionScore,
  SemantiqEvaluationDeniedEvent,
  SemantiqEvaluationDimension,
  SemantiqEvaluationEvent,
  SemantiqEvaluationProvenance,
  SemantiqEvaluationRequestEvent,
  SemantiqEvaluationResultEvent,
  SemantiqEvaluationVerdict,
  SemantiqProvenanceSource,
  SemantiqTrigger,
} from "./types.js";
import {
  SEMANTIQ_EVALUATION_VERDICTS,
  SEMANTIQ_PROVENANCE_SOURCES,
  isSemantiqEvaluationDimension,
} from "./types.js";
import {
  SEMANTIQ_MAX_EVENT_ID_CHARS,
  SEMANTIQ_MAX_SUBJECT_CHARS,
  SEMANTIQ_MAX_SUMMARY_CHARS,
  isSemantiqDenyReason,
  validateEvaluationRequest,
} from "./rules.js";

/**
 * Phase 18B — Evaluation Event Model.
 *
 * Typed, bounded, provenance-carrying evaluation REQUEST / RESULT / DENIED
 * events. Discipline carried over from 18A:
 *  - events are ABOUT the HOW WELL layer and are NEVER runtime authority:
 *    `authority: "advisory_data"` and `executionAuthorized: false` are
 *    re-stamped by the builders regardless of caller input;
 *  - every payload is deterministic and canonically serializable, so equal
 *    inputs produce byte-identical events (hash-anchored provenance);
 *  - conflict detection is EXACT (pinned discrete score grid) and its
 *    resolution is HUMAN-ONLY — the machine refuses to pick a winner.
 */

// ---------------------------------------------------------------------------
// Caps & pinned constants (18B).
// ---------------------------------------------------------------------------

export const SEMANTIQ_MAX_EVENT_DIMENSIONS = 4;
/** Bounded record store: beyond this, persistence fails closed (store_full). */
export const SEMANTIQ_MAX_RECORDS = 1024;
export const SEMANTIQ_MAX_DERIVED_FROM = 64;
export const SEMANTIQ_MAX_ID_CHARS = 128;
export const SEMANTIQ_MAX_RATIONALE_CHARS = 256;
export const SEMANTIQ_MAX_PROVENANCE_NOTE_CHARS = 256;
/** Discrete score grid: 0, 0.1, …, 1.0 (exact one-decimal arithmetic). */
export const SEMANTIQ_SCORE_STEP = 0.1;

/**
 * Deterministic verdict mapping (conclusion-only, human-reviewable):
 * mean score ≥ 0.8 ⇒ pass; ≥ 0.5 ⇒ borderline; ≥ 0 ⇒ fail; no dimensions
 * ⇒ indeterminate. Derivation thresholds are fixed constants (17D-style
 * known debt); they are recommendation heuristics, never policy.
 */
export const SEMANTIQ_VERDICT_PASS_THRESHOLD = 0.8;
export const SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD = 0.5;

export function isSemantiqProvenanceSource(value: unknown): value is SemantiqProvenanceSource {
  return (
    typeof value === "string" &&
    (SEMANTIQ_PROVENANCE_SOURCES as readonly string[]).includes(value)
  );
}

export function isSemantiqVerdict(value: unknown): value is SemantiqEvaluationVerdict {
  return (
    typeof value === "string" &&
    (SEMANTIQ_EVALUATION_VERDICTS as readonly string[]).includes(value)
  );
}

export function isSemantiqTrigger(value: unknown): value is SemantiqTrigger {
  return (
    value === "manual" ||
    value === "scheduled" ||
    value === "cli" ||
    value === "event_hook" ||
    value === "unknown"
  );
}

/**
 * Snap a finite number onto the pinned score grid; non-conforming ⇒ null.
 * Off-grid values are REJECTED (fail closed), not silently snapped — only
 * floating-point dust (0.30000000000000004 vs 0.3) is cleaned.
 */
export function snapScore(raw: number): number | null {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return null;
  if (raw < 0 || raw > 1) return null;
  const snapped = Math.round(raw / SEMANTIQ_SCORE_STEP) * SEMANTIQ_SCORE_STEP;
  const cleaned = Math.round(snapped * 10) / 10;
  if (Math.abs(raw - cleaned) > 1e-9) return null;
  return cleaned;
}

// ---------------------------------------------------------------------------
// Strict validation (fail closed on unknown shapes).
// ---------------------------------------------------------------------------

function boundedString(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= max;
}

/** Validate a provenance block; returns an error string or null. */
export function validateProvenance(p: unknown): string | null {
  if (p === null || typeof p !== "object") {
    return "provenance must be an object";
  }
  const r = p as Record<string, unknown>;
  if (!isSemantiqProvenanceSource(r.source)) {
    return "provenance.source must be one of human | engine | derived_from_ledger | mixed";
  }
  if (!boundedString(r.actorId, SEMANTIQ_MAX_ID_CHARS)) {
    return "provenance.actorId must be a non-empty bounded string";
  }
  if (!boundedString(r.actorType, SEMANTIQ_MAX_ID_CHARS)) {
    return "provenance.actorType must be a non-empty bounded string";
  }
  if (!Array.isArray(r.derivedFrom)) {
    return "provenance.derivedFrom must be an array";
  }
  if (r.derivedFrom.length > SEMANTIQ_MAX_DERIVED_FROM) {
    return (
      "provenance.derivedFrom has " + String(r.derivedFrom.length) +
      " entries which exceeds the bound (" + String(SEMANTIQ_MAX_DERIVED_FROM) + ")"
    );
  }
  for (const id of r.derivedFrom) {
    if (typeof id !== "string" || id.length === 0 || id.length > SEMANTIQ_MAX_EVENT_ID_CHARS) {
      return "provenance.derivedFrom entries must be bounded non-empty strings";
    }
  }
  if (r.engineId !== undefined && !boundedString(r.engineId, SEMANTIQ_MAX_ID_CHARS)) {
    return "provenance.engineId, when present, must be a bounded non-empty string";
  }
  if (r.engineVersion !== undefined && !boundedString(r.engineVersion, SEMANTIQ_MAX_ID_CHARS)) {
    return "provenance.engineVersion, when present, must be a bounded non-empty string";
  }
  if (r.reviewerId !== undefined && !boundedString(r.reviewerId, SEMANTIQ_MAX_ID_CHARS)) {
    return "provenance.reviewerId, when present, must be a bounded non-empty string";
  }
  if (r.note !== undefined && (typeof r.note !== "string" || r.note.length > SEMANTIQ_MAX_PROVENANCE_NOTE_CHARS)) {
    return "provenance.note, when present, must be a bounded string";
  }
  // Cross-field coherence: engine-provenance fields only make sense with a
  // machine source; reviewerId only with a human/mixed source. These are
  // validation errors (fail closed), not silent drops.
  if (
    (r.source === "engine" || r.source === "mixed") &&
    r.engineId === undefined
  ) {
    return "provenance.engineId is required when source is engine or mixed";
  }
  if (r.source === "human" && r.engineId !== undefined) {
    return "provenance.engineId must be absent when source is human";
  }
  if (r.source === "human" && r.reviewerId === undefined) {
    return "provenance.reviewerId is required when source is human";
  }
  return null;
}

/** Validate one dimension score; returns an error string or null. */
export function validateDimensionScore(s: unknown): string | null {
  if (s === null || typeof s !== "object") {
    return "dimension score must be an object";
  }
  const r = s as Record<string, unknown>;
  if (!isSemantiqEvaluationDimension(r.dimension)) {
    return "dimension must be one of plan_quality | task_completion | policy_compliance | reproducibility";
  }
  if (typeof r.score !== "number" || snapScore(r.score) === null) {
    return "score must be a finite number in [0,1] on the pinned 0.1 step grid";
  }
  if (typeof r.confidence !== "number" || !Number.isFinite(r.confidence) || r.confidence < 0 || r.confidence > 1) {
    return "confidence must be a finite number in [0,1]";
  }
  if (r.rationale !== undefined && (typeof r.rationale !== "string" || r.rationale.length > SEMANTIQ_MAX_RATIONALE_CHARS)) {
    return "rationale, when present, must be a bounded string";
  }
  return null;
}

/**
 * Validate a full evaluation event. This is the event-schema gate: any
 * unknown kind, wrong authority pin, bad dimension set, or malformed
 * provenance fails closed with a machine-readable error string.
 */
export function validateEvaluationEvent(event: unknown): string | null {
  if (event === null || typeof event !== "object") {
    return "evaluation event must be an object";
  }
  const e = event as Record<string, unknown>;
  if (e.kind !== "request" && e.kind !== "result" && e.kind !== "denied") {
    return "event kind must be one of request | result | denied";
  }
  if (e.schemaVersion !== SEMANTIQ_SCHEMA_VERSION) {
    return "event schemaVersion must be " + SEMANTIQ_SCHEMA_VERSION;
  }
  if (!boundedString(e.subject, SEMANTIQ_MAX_SUBJECT_CHARS)) {
    return "subject must be a non-empty bounded string";
  }
  if (!isSemantiqTrigger(e.trigger)) {
    return "trigger must be one of manual | scheduled | cli | event_hook | unknown";
  }
  if (typeof e.authority !== "string" || e.authority !== "advisory_data") {
    return "authority must be advisory_data (evaluation events are never authority)";
  }
  if (e.executionAuthorized !== false) {
    return "executionAuthorized must be false (evaluation events never authorize)";
  }
  const provErr = validateProvenance(e.provenance);
  if (provErr !== null) return provErr;
  if (!Array.isArray(e.dimensions)) {
    return "dimensions must be an array";
  }
  if (e.dimensions.length > SEMANTIQ_MAX_EVENT_DIMENSIONS) {
    return "dimensions exceeds the four-dimension bound";
  }
  if (e.kind === "result") {
    if (e.dimensions.length === 0) {
      return "result events require at least one dimension score";
    }
    for (const d of e.dimensions) {
      const err = validateDimensionScore(d);
      if (err !== null) return err;
    }
    // Closed-set duplicate check: at most one score per dimension.
    const seen: string[] = [];
    for (const d of e.dimensions as readonly SemantiqDimensionScore[]) {
      if (seen.includes(d.dimension)) {
        return "duplicate dimension score: " + d.dimension;
      }
      seen.push(d.dimension);
    }
    if (!isSemantiqVerdict(e.verdict)) {
      return "result verdict must be one of pass | borderline | fail | indeterminate";
    }
    if (e.verdict !== deriveVerdict(e.dimensions as readonly SemantiqDimensionScore[])) {
      return "verdict does not match the deterministic derivation from dimension scores";
    }
    if (typeof e.evaluatedAtEpochMs !== "number" || !Number.isFinite(e.evaluatedAtEpochMs)) {
      return "evaluatedAtEpochMs must be a finite number";
    }
  } else {
    if (e.dimensions.length !== 0) {
      return "request/denied events carry no dimension scores";
    }
    if (e.verdict !== "indeterminate") {
      return "request/denied verdict must be indeterminate";
    }
    if (e.kind === "denied") {
      if (!isSemantiqDenyReason(e.denyReason)) {
        return "denied events require a known machine-readable denyReason";
      }
      if (typeof e.reason !== "string" || e.reason.length === 0 || e.reason.length > SEMANTIQ_MAX_SUMMARY_CHARS) {
        return "denied events require a bounded non-empty reason";
      }
      if (typeof e.deniedAtEpochMs !== "number" || !Number.isFinite(e.deniedAtEpochMs)) {
        return "deniedAtEpochMs must be a finite number";
      }
    } else if (typeof e.requestedAtEpochMs !== "number" || !Number.isFinite(e.requestedAtEpochMs)) {
      return "requestedAtEpochMs must be a finite number";
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Deterministic verdict derivation + conflict detection.
// ---------------------------------------------------------------------------

/** Derive the verdict from dimension scores (deterministic; see thresholds). */
export function deriveVerdict(dimensions: readonly SemantiqDimensionScore[]): SemantiqEvaluationVerdict {
  if (dimensions.length === 0) return "indeterminate";
  const mean = dimensions.reduce((acc, d) => acc + d.score, 0) / dimensions.length;
  if (mean >= SEMANTIQ_VERDICT_PASS_THRESHOLD) return "pass";
  if (mean >= SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD) return "borderline";
  return "fail";
}

export interface ScoreConflict {
  readonly dimension: SemantiqEvaluationDimension;
  readonly scoreA: number;
  readonly scoreB: number;
  readonly engineIdA: string;
  readonly engineIdB: string;
}

/**
 * Exact conflict detection across two score sets: a conflict exists when
 * BOTH sets score the same dimension and the pinned scores differ.
 * Resolution is human-only: callers surface `conflict_unresolved`, never
 * average, never let one side win by authority.
 */
export function detectScoreConflicts(
  a: readonly SemantiqDimensionScore[],
  b: readonly SemantiqDimensionScore[],
  engineIdA: string,
  engineIdB: string
): readonly ScoreConflict[] {
  const conflicts: ScoreConflict[] = [];
  for (const da of a) {
    for (const db of b) {
      if (da.dimension === db.dimension && snapScore(da.score) !== snapScore(db.score)) {
        conflicts.push(
          Object.freeze({
            dimension: da.dimension,
            scoreA: snapScore(da.score)!,
            scoreB: snapScore(db.score)!,
            engineIdA,
            engineIdB,
          })
        );
      }
    }
  }
  return Object.freeze(conflicts);
}

// ---------------------------------------------------------------------------
// Canonical serialization + hash (deterministic; sorted keys, fixed order).
// ---------------------------------------------------------------------------

const EVENT_KEY_ORDER: readonly string[] = Object.freeze([
  "authority",
  "denyReason",
  "dimensions",
  "evaluatedAtEpochMs",
  "deniedAtEpochMs",
  "executionAuthorized",
  "kind",
  "provenance",
  "reason",
  "requestedAtEpochMs",
  "schemaVersion",
  "subject",
  "trigger",
  "verdict",
]);

/** Deterministic JSON with recursively sorted object keys (exported for hashing consumers). */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) => {
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      const rec = v as Record<string, unknown>;
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(rec).sort()) sorted[k] = rec[k];
      return sorted;
    }
    return v;
  });
}

/** Canonical serialization of an evaluation event (deterministic). */
export function serializeEvaluationEvent(event: SemantiqEvaluationEvent): string {
  const rec = event as unknown as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of EVENT_KEY_ORDER) {
    if (rec[k] === undefined) continue;
    parts.push(JSON.stringify(k) + ":" + stableStringify(rec[k]));
  }
  return "{" + parts.join(",") + "}";
}

/** SHA-256 hex of the canonical event serialization (provenance anchor). */
export function evaluationEventHash(event: SemantiqEvaluationEvent): string {
  return createHash("sha256").update(serializeEvaluationEvent(event), "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Pinned builders (authority re-stamped; inputs normalized).
// ---------------------------------------------------------------------------

function normalizeProvenanceInput(
  p: SemantiqEvaluationProvenance
): SemantiqEvaluationProvenance | string {
  const err = validateProvenance(p);
  if (err !== null) return err;
  return Object.freeze({
    source: p.source,
    actorId: p.actorId,
    actorType: p.actorType,
    derivedFrom: Object.freeze([...p.derivedFrom].slice(0, SEMANTIQ_MAX_DERIVED_FROM)),
    ...(p.engineId !== undefined ? { engineId: p.engineId } : {}),
    ...(p.engineVersion !== undefined ? { engineVersion: p.engineVersion } : {}),
    ...(p.reviewerId !== undefined ? { reviewerId: p.reviewerId } : {}),
    ...(p.note !== undefined ? { note: p.note.slice(0, SEMANTIQ_MAX_PROVENANCE_NOTE_CHARS) } : {}),
  });
}

function normalizeSubject(subject: string): string | null {
  if (typeof subject !== "string" || subject.length === 0) return null;
  return subject.length > SEMANTIQ_MAX_SUBJECT_CHARS
    ? subject.slice(0, SEMANTIQ_MAX_SUBJECT_CHARS)
    : subject;
}

export interface EvaluationEventBuildInput {
  readonly subject: string;
  readonly trigger: SemantiqTrigger;
  readonly atEpochMs: number;
  readonly provenance: SemantiqEvaluationProvenance;
}

/** Build a typed evaluation REQUEST event (no scores; verdict indeterminate). */
export function buildEvaluationRequestEvent(
  input: EvaluationEventBuildInput
): { readonly ok: true; readonly event: SemantiqEvaluationRequestEvent } | { readonly ok: false; readonly denyReason: "invalid_request" | "oversized_request"; readonly reason: string } {
  const subject = normalizeSubject(input.subject);
  if (subject === null) {
    return { ok: false, denyReason: "invalid_request", reason: "subject must be a non-empty string" };
  }
  if (!isSemantiqTrigger(input.trigger)) {
    return { ok: false, denyReason: "invalid_request", reason: "trigger must be a known trigger" };
  }
  if (typeof input.atEpochMs !== "number" || !Number.isFinite(input.atEpochMs)) {
    return { ok: false, denyReason: "invalid_request", reason: "atEpochMs must be a finite number" };
  }
  const prov = normalizeProvenanceInput(input.provenance);
  if (typeof prov === "string") {
    return { ok: false, denyReason: "invalid_request", reason: prov };
  }
  const reqErr = validateEvaluationRequest({ subject, trigger: input.trigger });
  if (reqErr !== null) {
    return { ok: false, denyReason: "invalid_request", reason: reqErr };
  }
  return {
    ok: true,
    event: Object.freeze({
      kind: "request",
      schemaVersion: SEMANTIQ_SCHEMA_VERSION,
      subject,
      trigger: input.trigger,
      requestedAtEpochMs: input.atEpochMs,
      dimensions: Object.freeze([]),
      verdict: "indeterminate",
      provenance: prov,
      // Authority pins are RE-STAMPED here; caller values are ignored.
      authority: "advisory_data",
      executionAuthorized: false,
    }),
  };
}

export interface EvaluationResultBuildInput extends EvaluationEventBuildInput {
  readonly dimensions: readonly SemantiqDimensionScore[];
}

/** Build a typed evaluation RESULT event (scores normalized + verdict derived). */
export function buildEvaluationResultEvent(
  input: EvaluationResultBuildInput
): { readonly ok: true; readonly event: SemantiqEvaluationResultEvent } | { readonly ok: false; readonly denyReason: "invalid_request" | "oversized_request"; readonly reason: string } {
  const subject = normalizeSubject(input.subject);
  if (subject === null) {
    return { ok: false, denyReason: "invalid_request", reason: "subject must be a non-empty string" };
  }
  if (!isSemantiqTrigger(input.trigger)) {
    return { ok: false, denyReason: "invalid_request", reason: "trigger must be a known trigger" };
  }
  if (typeof input.atEpochMs !== "number" || !Number.isFinite(input.atEpochMs)) {
    return { ok: false, denyReason: "invalid_request", reason: "atEpochMs must be a finite number" };
  }
  const prov = normalizeProvenanceInput(input.provenance);
  if (typeof prov === "string") {
    return { ok: false, denyReason: "invalid_request", reason: prov };
  }
  if (!Array.isArray(input.dimensions) || input.dimensions.length === 0) {
    return { ok: false, denyReason: "invalid_request", reason: "result events require at least one dimension score" };
  }
  if (input.dimensions.length > SEMANTIQ_MAX_EVENT_DIMENSIONS) {
    return { ok: false, denyReason: "oversized_request", reason: "dimensions exceeds the four-dimension bound" };
  }
  const dimensions: SemantiqDimensionScore[] = [];
  const seen: SemantiqEvaluationDimension[] = [];
  for (const raw of input.dimensions) {
    const err = validateDimensionScore(raw);
    if (err !== null) {
      return { ok: false, denyReason: "invalid_request", reason: err };
    }
    if (seen.includes(raw.dimension)) {
      return { ok: false, denyReason: "invalid_request", reason: "duplicate dimension score: " + raw.dimension };
    }
    seen.push(raw.dimension);
    dimensions.push(
      Object.freeze({
        dimension: raw.dimension,
        score: snapScore(raw.score)!,
        confidence: Math.max(0, Math.min(1, raw.confidence)),
        ...(raw.rationale !== undefined
          ? { rationale: raw.rationale.slice(0, SEMANTIQ_MAX_RATIONALE_CHARS) }
          : {}),
      })
    );
  }
  return {
    ok: true,
    event: Object.freeze({
      kind: "result",
      schemaVersion: SEMANTIQ_SCHEMA_VERSION,
      subject,
      trigger: input.trigger,
      evaluatedAtEpochMs: input.atEpochMs,
      dimensions: Object.freeze(dimensions),
      verdict: deriveVerdict(dimensions),
      provenance: prov,
      authority: "advisory_data",
      executionAuthorized: false,
    }),
  };
}

export interface EvaluationDeniedBuildInput extends EvaluationEventBuildInput {
  readonly denyReason: SemantiqEvaluationDeniedEvent["denyReason"];
  readonly reason: string;
}

/** Build a typed evaluation DENIED event (machine-readable denial). */
export function buildEvaluationDeniedEvent(
  input: EvaluationDeniedBuildInput
): { readonly ok: true; readonly event: SemantiqEvaluationDeniedEvent } | { readonly ok: false; readonly denyReason: "invalid_request" | "oversized_request"; readonly reason: string } {
  const subject = normalizeSubject(input.subject);
  if (subject === null) {
    return { ok: false, denyReason: "invalid_request", reason: "subject must be a non-empty string" };
  }
  if (!isSemantiqTrigger(input.trigger)) {
    return { ok: false, denyReason: "invalid_request", reason: "trigger must be a known trigger" };
  }
  if (typeof input.atEpochMs !== "number" || !Number.isFinite(input.atEpochMs)) {
    return { ok: false, denyReason: "invalid_request", reason: "atEpochMs must be a finite number" };
  }
  if (!isSemantiqDenyReason(input.denyReason)) {
    return { ok: false, denyReason: "invalid_request", reason: "denyReason must be a known machine-readable reason" };
  }
  if (typeof input.reason !== "string" || input.reason.length === 0) {
    return { ok: false, denyReason: "invalid_request", reason: "reason must be a non-empty string" };
  }
  const prov = normalizeProvenanceInput(input.provenance);
  if (typeof prov === "string") {
    return { ok: false, denyReason: "invalid_request", reason: prov };
  }
  return {
    ok: true,
    event: Object.freeze({
      kind: "denied",
      schemaVersion: SEMANTIQ_SCHEMA_VERSION,
      subject,
      trigger: input.trigger,
      deniedAtEpochMs: input.atEpochMs,
      dimensions: Object.freeze([]),
      verdict: "indeterminate",
      denyReason: input.denyReason,
      reason: input.reason.slice(0, SEMANTIQ_MAX_SUMMARY_CHARS),
      provenance: prov,
      authority: "advisory_data",
      executionAuthorized: false,
    }),
  };
}

/** Stable record id for a persisted event: sha256(kind|subject|contentHash). */
export function evaluationRecordId(event: SemantiqEvaluationEvent, contentHash: string): string {
  return createHash("sha256")
    .update(event.kind + "|" + event.subject + "|" + contentHash, "utf8")
    .digest("hex");
}
