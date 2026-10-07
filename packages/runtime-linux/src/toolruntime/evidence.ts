/**
 * PRE-21E — tool evidence, explainability, and NON-EXECUTING replay.
 *
 * Objective: explain and reconstruct a governed tool run WITHOUT claiming
 * executable replay or rollback. The Phase-14 rollback/replay question is
 * explicitly NOT resolved here: nothing in this module can re-run anything.
 *
 * The structural guarantee (test-locked): a replay PLAN is derived from a
 * TAMPER-EVIDENT RECORD that contains only hashes and metadata — the
 * request hash, NOT the request; the output hash, NOT the output; the
 * manifest hash, NOT the manifest. The plan carries no argv, no cwd, no
 * executable path, no launcher flags, no env, no transport, no input
 * payload — there is nothing in it that any executor could consume.
 *
 * Tamper detection: recordHash binds every field of a run record; any
 * mutation (output hash swap, manifest drift, decision rewrite, id
 * reference change) is rejected by verifyToolRunRecord. Ledger-backed
 * records are re-verified against the AppendOnlyLedger chain and the event
 * must exist with a matching evidence hash.
 *
 * Redaction: workspace paths never enter a record — only the non-reversible
 * redacted label (redactWorkspace) is carried. Explanations reproduce the
 * redacted form only.
 */

import { isolationEvidenceHash } from "../isolation/canonical.js";
import { redactWorkspace } from "../isolation/binding.js";
import type { AppendOnlyLedger } from "@menog/event-ledger";

// ── schema ───────────────────────────────────────────────────────────────────

export const TOOL_EVIDENCE_SCHEMA_VERSION = "menog-tool-evidence/v0" as const;
export type ToolEvidenceSchemaVersion = typeof TOOL_EVIDENCE_SCHEMA_VERSION;

/**
 * Replay semantics marker. "non_executing" is the ONLY value this module
 * ever produces: an explicit guard that a replay plan here is an evidence
 * reconstruction, never an executable replay. Phase-14 executable
 * rollback/replay remains unresolved and out of scope.
 */
export const TOOL_REPLAY_SEMANTICS = "non_executing" as const;

// ── the complete run record (hashes and metadata ONLY) ───────────────────────

export interface ToolRunRecord {
  readonly schemaVersion: ToolEvidenceSchemaVersion;
  /** Parent identifiers (skill/task/step/assignment provenance). */
  readonly parents: {
    readonly skillId: string | null;
    readonly skillStepId: string | null;
    readonly taskId: string | null;
    readonly assignmentId: string | null;
    readonly agentId: string;
  };
  /** SHA-256 of the canonical REQUEST — the request itself is not stored. */
  readonly requestHash: string;
  readonly toolId: string;
  readonly version: string;
  /** Pinned manifest hash at execution time (drift-detectable). */
  readonly manifestHash: string;
  /** Policy decision metadata (outcome + matched rule; not the full result). */
  readonly policy: { readonly outcome: string; readonly matchedRule: string | null };
  /** Isolation enforcement reference (profile id + isolation evidence hash). */
  readonly isolation: { readonly profileId: string; readonly evidenceHash: string | null };
  /** Result metadata: output hash + size + truncation — never the output. */
  readonly result: {
    readonly status: string;
    readonly exitCode: number | null;
    readonly timedOut: boolean;
    readonly outputHash: string | null;
    readonly outputBytes: number | null;
    readonly truncated: boolean;
  };
  /** Redacted workspace label (non-reversible); never a path. */
  readonly workspaceId: string;
  readonly recordedAt: string;
  /** SHA-256 canonical hash binding every field above. */
  readonly recordHash: string;
}

/** Build a run record from the junction's outputs. Hashes only — no payloads. */
export function buildToolRunRecord(input: {
  parents: ToolRunRecord["parents"];
  requestHash: string;
  toolId: string;
  version: string;
  manifestHash: string;
  policy: ToolRunRecord["policy"];
  isolation: ToolRunRecord["isolation"];
  result: ToolRunRecord["result"];
  workspaceRoot: string;
  recordedAt: string;
}): ToolRunRecord {
  const body = {
    schemaVersion: TOOL_EVIDENCE_SCHEMA_VERSION,
    parents: input.parents,
    requestHash: input.requestHash,
    toolId: input.toolId,
    version: input.version,
    manifestHash: input.manifestHash,
    policy: input.policy,
    isolation: input.isolation,
    result: input.result,
    workspaceId: redactWorkspace(input.workspaceRoot),
    recordedAt: input.recordedAt,
  };
  return Object.freeze({ ...body, recordHash: isolationEvidenceHash(body) });
}

// ── tamper detection ─────────────────────────────────────────────────────────

export type ToolEvidenceFailureCode =
  | "RECORD_TAMPERED"
  | "MANIFEST_DRIFT"
  | "OUTPUT_TAMPERED"
  | "LEDGER_EVENT_MISSING"
  | "LEDGER_CHAIN_BROKEN";

export type ToolEvidenceResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: ToolEvidenceFailureCode; message: string };

/**
 * Verify a record's internal integrity: the recordHash must re-derive from
 * the record body. Any field mutation — including swapping the output hash,
 * the manifest hash, a decision, or a parent id — breaks the binding.
 */
export function verifyToolRunRecord(record: ToolRunRecord): ToolEvidenceResult<true> {
  const { recordHash, ...body } = record;
  const expected = isolationEvidenceHash(body);
  if (expected !== recordHash) {
    return {
      ok: false,
      code: "RECORD_TAMPERED",
      message: "recordHash mismatch — the record was modified after sealing",
    };
  }
  return { ok: true, value: true };
}

/**
 * Cross-check the pinned manifest hash against the CURRENT registry entry:
 * any drift (tool re-registered with changed content under the same
 * id+version) is a typed failure — never a silent accept.
 */
export function checkManifestIntegrity(
  record: ToolRunRecord,
  currentManifestHash: string
): ToolEvidenceResult<true> {
  const inner = verifyToolRunRecord(record);
  if (!inner.ok) return inner;
  if (record.manifestHash !== currentManifestHash) {
    return {
      ok: false,
      code: "MANIFEST_DRIFT",
      message:
        "manifest hash drift for " + record.toolId + "@" + record.version +
        " — the executed manifest no longer matches the registered one",
    };
  }
  return { ok: true, value: true };
}

/**
 * Verify the recorded output hash against the ACTUAL output bytes (when the
 * caller holds them). Detects output tamper/substitution after the fact.
 */
export function verifyOutputIntegrity(
  record: ToolRunRecord,
  actualOutputHash: string | null
): ToolEvidenceResult<true> {
  const inner = verifyToolRunRecord(record);
  if (!inner.ok) return inner;
  if (record.result.outputHash === null) {
    return { ok: true, value: true }; // nothing was recorded to compare
  }
  if (actualOutputHash === null || actualOutputHash !== record.result.outputHash) {
    return {
      ok: false,
      code: "OUTPUT_TAMPERED",
      message: "output hash does not match the sealed record — output was modified or lost",
    };
  }
  return { ok: true, value: true };
}

/**
 * Ledger verification: the record must exist as a ledger event whose
 * evidence hash matches, and the whole chain must verify. A missing event or
 * a broken chain is a typed failure — the record alone is never trusted as
 * proof of observation.
 */
export function verifyLedgerObservation(
  record: ToolRunRecord,
  ledger: AppendOnlyLedger
): ToolEvidenceResult<{ eventId: string }> {
  const inner = verifyToolRunRecord(record);
  if (!inner.ok) return inner;

  const chain = ledger.verify();
  if (!chain.ok) {
    return { ok: false, code: "LEDGER_CHAIN_BROKEN", message: "ledger hash chain failed verification" };
  }
  const needle = record.recordHash;
  const hit = ledger
    .events()
    .find((e) => JSON.stringify(e.resultSummary ?? {}).includes(needle));
  if (hit === undefined) {
    return {
      ok: false,
      code: "LEDGER_EVENT_MISSING",
      message: "no ledger event carries this record's hash — the run was never observed",
    };
  }
  return { ok: true, value: { eventId: hit.eventId } };
}

// ── deterministic explanation ────────────────────────────────────────────────

export interface ToolRunExplanation {
  readonly schemaVersion: ToolEvidenceSchemaVersion;
  readonly summary: string;
  readonly tool: string;
  readonly executedBy: string;
  readonly policyVerdict: string;
  readonly isolation: string;
  readonly outcome: string;
  readonly output: string;
  readonly workspace: string;
  readonly integrity: "verified" | "tampered";
  readonly warnings: readonly string[];
}

/**
 * Deterministic, human-readable explanation derived ONLY from the record
 * (plus optional 21A evidence). Same record ⇒ byte-identical explanation.
 * Every sentence is backed by a sealed field; nothing is inferred.
 */
export function explainToolRun(
  record: ToolRunRecord
): ToolRunExplanation {
  const warnings: string[] = [];
  let integrity: ToolRunExplanation["integrity"] = "verified";
  if (!verifyToolRunRecord(record).ok) {
    integrity = "tampered";
    warnings.push("record hash mismatch — treat every field below as untrusted");
  }
  const p = record.parents;
  const via = p.skillId !== null
    ? "skill '" + p.skillId + "'" + (p.skillStepId !== null ? " step '" + p.skillStepId + "'" : "")
    : p.taskId !== null
      ? "task '" + p.taskId + "'"
      : "direct request";
  const summary =
    "Run of " + record.toolId + "@" + record.version + " via " + via +
    " (executed by " + p.agentId + ") was " + record.result.status +
    (record.result.exitCode !== null ? " (exit " + String(record.result.exitCode) + ")" : "") +
    ".";
  return {
    schemaVersion: TOOL_EVIDENCE_SCHEMA_VERSION,
    summary,
    tool:
      record.toolId + "@" + record.version +
      " (manifest " + record.manifestHash.slice(0, 12) + "…)",
    executedBy: p.agentId + (p.assignmentId !== null ? " (assignment " + p.assignmentId + ")" : ""),
    policyVerdict:
      record.policy.outcome + (record.policy.matchedRule ? " via " + record.policy.matchedRule : ""),
    isolation:
      "profile '" + record.isolation.profileId + "'" +
      (record.isolation.evidenceHash !== null
        ? " with evidence " + record.isolation.evidenceHash.slice(0, 12) + "…"
        : " (no per-primitive evidence recorded)"),
    outcome:
      record.result.status +
      (record.result.timedOut ? " after hitting the deadline" : "") +
      (record.result.exitCode !== null ? ", exit code " + String(record.result.exitCode) : ""),
    output: record.result.outputHash === null
      ? "no output recorded"
      : "output sealed as " + record.result.outputHash.slice(0, 12) + "… (" +
        String(record.result.outputBytes) + " bytes" +
        (record.result.truncated ? ", TRUNCATED" : "") + ")",
    workspace: record.workspaceId,
    integrity,
    warnings,
  };
}

// ── non-executing replay plan ────────────────────────────────────────────────

export interface ReplayStep {
  readonly sequence: number;
  readonly toolId: string;
  readonly version: string;
  readonly manifestHash: string;
  readonly requestHash: string;
  readonly outcomeStatus: string;
  readonly recordHash: string;
}

export interface EvidenceReplayPlan {
  readonly schemaVersion: ToolEvidenceSchemaVersion;
  readonly replaySemantics: typeof TOOL_REPLAY_SEMANTICS;
  readonly disclaimer: string;
  readonly skillId: string | null;
  readonly steps: readonly ReplayStep[];
  readonly pathHash: string;
  readonly builtAt: string;
}

/**
 * Derive a NON-EXECUTING replay plan from one or more sealed records (in
 * execution order). The plan contains hashes and identity fields only —
 * deliberately NO argv, cwd, executable path, launcher flags, env, or input
 * payload — so no executor can ever consume it. It answers "what happened,
 * in what order, under what authority", nothing more.
 */
export function planEvidenceReplay(records: readonly ToolRunRecord[]): ToolEvidenceResult<EvidenceReplayPlan> {
  if (records.length === 0) {
    return { ok: false, code: "RECORD_TAMPERED", message: "no records supplied" };
  }
  for (const r of records) {
    const v = verifyToolRunRecord(r);
    if (!v.ok) return v;
  }
  const steps: ReplayStep[] = records.map((r, i) => ({
    sequence: i + 1,
    toolId: r.toolId,
    version: r.version,
    manifestHash: r.manifestHash,
    requestHash: r.requestHash,
    outcomeStatus: r.result.status,
    recordHash: r.recordHash,
  }));
  const skillIds = new Set(records.map((r) => r.parents.skillId));
  const plan: EvidenceReplayPlan = {
    schemaVersion: TOOL_EVIDENCE_SCHEMA_VERSION,
    replaySemantics: TOOL_REPLAY_SEMANTICS,
    disclaimer:
      "EVIDENCE RECONSTRUCTION ONLY — this plan is not executable and resolves nothing in Phase 14. " +
      "It carries hashes and identities, never argv/paths/env/input; no executor can consume it.",
    skillId: skillIds.size === 1 ? (records[0] as ToolRunRecord).parents.skillId : null,
    steps,
    pathHash: isolationEvidenceHash({ steps }),
    builtAt: new Date().toISOString(),
  };
  return { ok: true, value: Object.freeze(plan) };
}
