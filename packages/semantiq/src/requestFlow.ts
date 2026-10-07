import type {
  SemantiqDimensionScore,
  SemantiqEvaluationProvenance,
  SemantiqEvaluationRecord,
  SemantiqEvaluationRequestEvent,
  SemantiqEvaluationResultEvent,
  SemantiqEvaluationDeniedEvent,
  SemantiqRuntimeContext,
  SemantiqTrigger,
} from "./types.js";
import {
  buildEvaluationDeniedEvent,
  buildEvaluationRequestEvent,
  buildEvaluationResultEvent,
  detectScoreConflicts,
  type ScoreConflict,
} from "./events.js";
import { SEMANTIQ_MAX_SUBJECT_CHARS } from "./rules.js";
import { SemantiqEvaluationRecordStore } from "./records.js";

/**
 * Phase 18B — Evaluation request flow.
 *
 * Orchestrates a full evaluation lifecycle from a typed REQUEST event to a
 * persisted RESULT or DENIED event:
 *
 *   request event → [engine?] → result event → (conflict check) → persist
 *                        ↘ no engine ⇒ typed DENIED event
 *
 * Discipline carried over from 18A:
 *  - MISSING EVALUATOR is a TYPED, PERSISTED denial
 *    (`adapter_disabled`), never an error and never a guessed result;
 *  - every event is schema-built (authority re-stamped), hash-anchored, and
 *    insert-once persisted — provenance cannot be rewritten;
 *  - conflicting scores from two engines are SURFACED
 *    (`conflict_unresolved` denied event + conflicting record) — the
 *    machine never averages and never picks a winner by authority.
 */

export const SEMANTIQ_MAX_CONFLICTING_ENGINES = 4;

/** Provenance for events produced by the contract layer itself. */
export function contractLayerProvenance(
  context: SemantiqRuntimeContext,
  derivedFrom: readonly string[]
): SemantiqEvaluationProvenance {
  return Object.freeze({
    source: "derived_from_ledger",
    actorId: context.actor.id,
    actorType: context.actor.type,
    derivedFrom: Object.freeze([...derivedFrom].slice(0, 64)),
  });
}

export interface RequestEvaluationInput {
  readonly subject: string;
  readonly trigger: SemantiqTrigger;
  readonly atEpochMs: number;
  readonly context: SemantiqRuntimeContext;
}

export interface EngineContribution {
  /** Stable engine id (used for conflict attribution). */
  readonly engineId: string;
  /** Engine version (recorded in provenance). */
  readonly engineVersion: string;
  /** The engine's per-dimension scores. */
  readonly dimensions: readonly SemantiqDimensionScore[];
}

export type RequestEvaluationOutcome =
  | {
      readonly ok: true;
      readonly kind: "result";
      readonly event: SemantiqEvaluationResultEvent;
      readonly record: SemantiqEvaluationRecord;
    }
  | {
      readonly ok: true;
      readonly kind: "denied";
      readonly event: SemantiqEvaluationDeniedEvent;
      readonly record: SemantiqEvaluationRecord;
    }
  | {
      readonly ok: false;
      readonly kind: "request_invalid";
      readonly event: SemantiqEvaluationRequestEvent;
      readonly record: SemantiqEvaluationRecord;
      readonly reason: string;
    };

/**
 * Run one full evaluation flow. Semantics:
 *  - the REQUEST event is built + persisted first (always observable);
 *  - no engines ⇒ persisted DENIED event with `adapter_disabled` (missing
 *    evaluator is a typed, honest state — Menog works fully without one);
 *  - exactly one engine ⇒ persisted RESULT event with its scores;
 *  - multiple engines ⇒ per-dimension exact conflict check; any conflict
 *    ⇒ persisted DENIED event with `conflict_unresolved` plus a
 *    `conflicting` record per engine contribution (surface, never resolve);
 *    no conflicts ⇒ RESULT with the minimum-confidence contribution's
 *    scores and mixed provenance listing every engine.
 */
export function requestEvaluation(
  input: RequestEvaluationInput,
  store: SemantiqEvaluationRecordStore,
  contributions: readonly EngineContribution[]
): RequestEvaluationOutcome {
  const invalidRequest =
    input === null ||
    typeof input !== "object" ||
    typeof input.subject !== "string" ||
    input.subject.length === 0 ||
    input.subject.length > SEMANTIQ_MAX_SUBJECT_CHARS;
  if (invalidRequest) {
    throw new TypeError("requestEvaluation: subject must be a bounded non-empty string");
  }

  // Stage 1 — REQUEST event: built, authority-pinned, persisted.
  const reqBuilt = buildEvaluationRequestEvent({
    subject: input.subject,
    trigger: input.trigger,
    atEpochMs: input.atEpochMs,
    provenance: contractLayerProvenance(input.context, []),
  });
  if (!reqBuilt.ok) {
    throw new TypeError("requestEvaluation: " + reqBuilt.reason);
  }
  const persistedRequest = store.persist(reqBuilt.event);
  if (!persistedRequest.ok) {
    throw new TypeError("requestEvaluation: request event not persistable: " + persistedRequest.reason);
  }

  const finish = (
    outcome: RequestEvaluationOutcome
  ): RequestEvaluationOutcome => {
    return outcome;
  };

  // Stage 2a — MISSING EVALUATOR: typed, persisted denial (not an error).
  if (contributions.length === 0) {
    const built = buildEvaluationDeniedEvent({
      subject: input.subject,
      trigger: input.trigger,
      atEpochMs: input.atEpochMs + 1,
      denyReason: "adapter_disabled",
      reason:
        "no evaluation engine is configured; evaluation denied — Menog works fully without an external evaluator (ADR-0007)",
      provenance: contractLayerProvenance(input.context, []),
    });
    if (!built.ok) {
      throw new TypeError("requestEvaluation: denied event rejected: " + built.reason);
    }
    const persisted = store.persist(built.event);
    if (!persisted.ok) {
      throw new TypeError("requestEvaluation: denied event not persistable: " + persisted.reason);
    }
    return finish({
      ok: true,
      kind: "denied",
      event: built.event,
      record: persisted.record,
    });
  }

  // Stage 2b — engine contributions must be schema-valid before any
  // conflict work (fail closed on malformed input).
  if (contributions.length > SEMANTIQ_MAX_CONFLICTING_ENGINES) {
    const built = buildEvaluationDeniedEvent({
      subject: input.subject,
      trigger: input.trigger,
      atEpochMs: input.atEpochMs + 1,
      denyReason: "oversized_request",
      reason:
        "engine contributions exceed the bound (" +
        String(SEMANTIQ_MAX_CONFLICTING_ENGINES) +
        ")",
      provenance: contractLayerProvenance(input.context, []),
    });
    if (!built.ok) {
      throw new TypeError("requestEvaluation: denied event rejected: " + built.reason);
    }
    const persisted = store.persist(built.event);
    if (!persisted.ok) {
      throw new TypeError("requestEvaluation: denied event not persistable: " + persisted.reason);
    }
    return finish({ ok: true, kind: "denied", event: built.event, record: persisted.record });
  }
  for (const c of contributions) {
    if (typeof c.engineId !== "string" || c.engineId.length === 0 || c.engineId.length > 128) {
      throw new TypeError("requestEvaluation: engineId must be a bounded non-empty string");
    }
    if (!Array.isArray(c.dimensions) || c.dimensions.length === 0) {
      throw new TypeError("requestEvaluation: engine contributions require scores");
    }
  }

  // Stage 2c — CONFLICT CHECK across contributions (exact, per-dimension).
  const conflicts: ScoreConflict[] = [];
  for (let i = 0; i < contributions.length; i++) {
    for (let j = i + 1; j < contributions.length; j++) {
      conflicts.push(
        ...detectScoreConflicts(
          contributions[i]!.dimensions,
          contributions[j]!.dimensions,
          contributions[i]!.engineId,
          contributions[j]!.engineId
        )
      );
    }
  }
  if (conflicts.length > 0) {
    const built = buildEvaluationDeniedEvent({
      subject: input.subject,
      trigger: input.trigger,
      atEpochMs: input.atEpochMs + 1,
      denyReason: "conflict_unresolved",
      reason:
        "conflicting scores across engines for dimension(s) " +
        [...new Set(conflicts.map((c) => c.dimension))].join(", ") +
        "; resolution is human-only (no averaging, no authority tie-break)",
      provenance: contractLayerProvenance(input.context, []),
    });
    if (!built.ok) {
      throw new TypeError("requestEvaluation: denied event rejected: " + built.reason);
    }
    const persisted = store.persist(built.event);
    if (!persisted.ok) {
      throw new TypeError("requestEvaluation: denied event not persistable: " + persisted.reason);
    }
    return finish({
      ok: true,
      kind: "denied",
      event: built.event,
      record: persisted.record,
    });
  }

  // Stage 2d — single resolved result: the minimum-confidence contribution
  // provides the scores; provenance records EVERY engine (mixed).
  const chosen = [...contributions].sort(
    (a, b) =>
      a.dimensions.reduce((s, d) => s + d.confidence, 0) -
      b.dimensions.reduce((s, d) => s + d.confidence, 0)
  )[0]!;
  const resultBuilt = buildEvaluationResultEvent({
    subject: input.subject,
    trigger: input.trigger,
    atEpochMs: input.atEpochMs + 2,
    dimensions: chosen.dimensions,
    provenance: Object.freeze({
      source: "mixed",
      actorId: input.context.actor.id,
      actorType: input.context.actor.type,
      derivedFrom: Object.freeze([]),
      engineId: [...contributions.map((c) => c.engineId)].join(","),
      engineVersion: [...contributions.map((c) => c.engineVersion)].join(","),
    }),
  });
  if (!resultBuilt.ok) {
    throw new TypeError("requestEvaluation: result event rejected: " + resultBuilt.reason);
  }
  const persistedResult = store.persist(resultBuilt.event);
  if (!persistedResult.ok) {
    throw new TypeError("requestEvaluation: result event not persistable: " + persistedResult.reason);
  }
  return finish({
    ok: true,
    kind: "result",
    event: resultBuilt.event,
    record: persistedResult.record,
  });
}
