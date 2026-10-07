import { createHash } from "node:crypto";
import type { AlgorithmRecommendation, RuntimeContext } from "./types.js";
import { ALGORITHM_SCHEMA_VERSION } from "./types.js";
import type { AlgorithmEvaluationResult } from "./types.js";

/**
 * Phase 17A — canonical serialization for algorithm stage results.
 *
 * Deterministic sorted-key JSON, mirroring the memory/commit-engine
 * serialization discipline: identical logical results serialize identically,
 * so evaluation evidence is stable across processes and runs and can be
 * anchored into the event ledger or memory without ambiguity.
 */

const RECOMMENDATION_KEY_ORDER: readonly string[] = Object.freeze([
  "confidence",
  "executionAuthorized",
  "family",
  "isRecommendation",
  "nextOidaState",
  "rankedCandidates",
  "rationale",
  "reasoningSummary",
  "riskVerdict",
  "strategyId",
]);

/**
 * Canonical serialization of an algorithm recommendation: fixed key order,
 * bounded output. Equal recommendations ⇒ equal strings. 17B optional keys
 * (`reasoningSummary`, `nextOidaState`) are included only when present, so
 * 17A-shaped recommendations serialize exactly as before.
 */
export function serializeRecommendation(
  rec: AlgorithmRecommendation
): string {
  const rankedJson = JSON.stringify([...rec.rankedCandidates]);
  const all: Record<string, string> = {
    confidence: JSON.stringify(rec.confidence),
    executionAuthorized: JSON.stringify(rec.executionAuthorized),
    family: JSON.stringify(rec.family),
    isRecommendation: JSON.stringify(rec.isRecommendation),
    rankedCandidates: rankedJson,
    rationale: JSON.stringify(rec.rationale),
    strategyId: JSON.stringify(rec.strategyId),
  };
  if (rec.reasoningSummary !== undefined) {
    all["reasoningSummary"] = JSON.stringify(rec.reasoningSummary);
  }
  if (rec.nextOidaState !== undefined) {
    const st = rec.nextOidaState;
    all["nextOidaState"] =
      '{"currentPhase":' +
      JSON.stringify(st.currentPhase) +
      ',"done":' +
      JSON.stringify(st.done) +
      ',"iteration":' +
      JSON.stringify(st.iteration) +
      "}";
  }
  if (rec.riskVerdict !== undefined) {
    const rv = rec.riskVerdict;
    all["riskVerdict"] =
      '{"reason":' +
      JSON.stringify(rv.reason) +
      ',"tier":' +
      JSON.stringify(rv.tier) +
      (rv.withholdCapabilities !== undefined
        ? ',"withholdCapabilities":' + JSON.stringify([...rv.withholdCapabilities])
        : "") +
      "}";
  }
  const parts: string[] = [];
  for (const k of RECOMMENDATION_KEY_ORDER) {
    const v = all[k];
    if (v === undefined) continue;
    parts.push(JSON.stringify(k) + ":" + v);
  }
  return "{" + parts.join(",") + "}";
}

/** SHA-256 hex of the canonical recommendation serialization. */
export function recommendationHash(rec: AlgorithmRecommendation): string {
  return createHash("sha256")
    .update(serializeRecommendation(rec), "utf8")
    .digest("hex");
}

/**
 * Canonical serialization of a full evaluation result (success or denial):
 * fixed outer shape, sorted inner content, deterministic across runs.
 */
export function serializeAlgorithmResult(
  result: AlgorithmEvaluationResult,
  context: RuntimeContext
): string {
  const ctxRec = context as unknown as Record<string, unknown>;
  const ctxKeys = Object.keys(ctxRec).sort();
  const ctxParts: string[] = [];
  for (const k of ctxKeys) {
    const v = ctxRec[k];
    if (v === undefined) continue;
    ctxParts.push(JSON.stringify(k) + ":" + JSON.stringify(v));
  }

  if (result.ok) {
    return (
      '{"context":{' +
      ctxParts.join(",") +
      '},"ok":true,"recommendation":' +
      serializeRecommendation(result.recommendation) +
      ',"schemaVersion":' +
      JSON.stringify(ALGORITHM_SCHEMA_VERSION) +
      "}"
    );
  }
  return (
    '{"context":{' +
    ctxParts.join(",") +
    '},"denyReason":' +
    JSON.stringify(result.denyReason) +
    ',"ok":false,"reason":' +
    JSON.stringify(result.reason) +
    "}"
  );
}
