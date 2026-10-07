/**
 * PRE-20D — Policy→Isolation binding (INTEGRATION / AUTHORITY-SEPARATION).
 *
 * Formalizes Policy first → isolation preflight/enforcement → spawn on the
 * existing evidence spine:
 *
 * - Trusted projection: an ALLOWED PolicyResult is projected into an
 *   IsolationProfile by a PURE, human-reviewed mapping (frozen baseline
 *   requirements; no agent data, no policy echo fields). The projection is
 *   MONOTONE: it only ADDS restrictions over the 20C floor (network denial
 *   ⇒ required netns; write-class confinement; rlimits). A policy DENY never
 *   projects — it is refused at the projection boundary.
 * - Strict sequencing: record_policy → record_plan → record_spawn; any other
 *   order is a sequence violation and must not spawn.
 * - Evidence binding: execution evidence binds to the existing task / agent /
 *   execution identifiers with a REDACTED workspace label, and is appended to
 *   the caller's ledger (the caller retains append authority).
 * - Isolation failure AFTER an allow emits `execution_not_started` evidence.
 */

import { createHash } from "node:crypto";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import type { PolicyResult } from "@menog/policy";
import { ISOLATION_CONTRACT_SCHEMA_VERSION, type IsolationProfile } from "./types.js";
import { validateIsolationProfile } from "./evaluate.js";
import type { ExecutionPlan } from "./enforce/preflight.js";
import type { IsolatedRunResult } from "./enforce/launcher.js";

// ── trusted projection ───────────────────────────────────────────────────────

export interface ProjectionContext {
  readonly executionClass: "readonly_inspect" | "bounded_write";
}

export const EXECUTION_BASELINE_PROFILE_ID = "exec-isolated-fs-v0";

/** Human-reviewed frozen floor (20C baseline); no agent or policy-echo data. */
const BASELINE_REQUIREMENTS = Object.freeze([
  Object.freeze({ primitive: "ns_user", criticality: "required", onMissing: "fail_closed" }),
  Object.freeze({ primitive: "ns_mount", criticality: "required", onMissing: "fail_closed" }),
  Object.freeze({ primitive: "landlock_fs", criticality: "required", onMissing: "fail_closed", minLandlockAbi: 1 }),
  Object.freeze({ primitive: "no_new_privs", criticality: "required", onMissing: "fail_closed" }),
  Object.freeze({ primitive: "seccomp_filter", criticality: "required", onMissing: "fail_closed" }),
  Object.freeze({
    primitive: "cgroup_v2_controllers",
    criticality: "optional",
    onMissing: "degrade_explicit",
    degradationNote: "no memory.max/pids.max on this target; rlimits bound resources only",
  }),
]) as readonly Record<string, unknown>[];

/**
 * Trusted, monotone projection: policy ALLOW ⇒ IsolationProfile.
 * - `network:external` NOT in allowedCapabilities ⇒ ns_net REQUIRED
 *   (fail-closed). Day-1 denies network:external always, so the projection
 *   always adds the netns requirement for a real Day-1 engine.
 * - The result is always `human_reviewed` and re-validated by the 20B
 *   contract before it can be used.
 */
export function projectPolicyToProfile(
  policy: PolicyResult
): { ok: true; profile: IsolationProfile } | { ok: false; reason: string } {
  if (policy.decision.outcome !== "allow") {
    return { ok: false, reason: "policy_did_not_allow: deny never projects to a profile" };
  }
  const allowed = new Set<string>(policy.allowedCapabilities);
  const networkAllowed = allowed.has("network:external");

  const requirements: Array<Record<string, unknown>> = BASELINE_REQUIREMENTS.map((r) => ({ ...r }));
  if (!networkAllowed) {
    requirements.push({ primitive: "ns_net", criticality: "required", onMissing: "fail_closed" });
  }

  const v = validateIsolationProfile({
    profileId:
      EXECUTION_BASELINE_PROFILE_ID + "+20d:net" + (networkAllowed ? "allow" : "deny"),
    origin: "human_reviewed",
    note: "20D trusted projection from a policy ALLOW; monotone over the 20C floor",
    requirements,
  });
  if (!v.ok) {
    return { ok: false, reason: "projection produced an invalid profile: " + v.failure.message };
  }
  return { ok: true, profile: v.profile };
}

// ── strict sequencing ────────────────────────────────────────────────────────

export type SequenceStage = "policy_decided" | "preflight_planned" | "spawn_attempted";

export interface SequenceState {
  readonly stages: readonly SequenceStage[];
  readonly policyOutcome: "allow" | "deny" | null;
}

export function newSequenceState(): SequenceState {
  return { stages: Object.freeze([]), policyOutcome: null };
}

export function checkSequence(
  state: SequenceState,
  next: "record_policy" | "record_plan" | "record_spawn",
  policyOutcome: "allow" | "deny" | null = null
): { ok: true; state: SequenceState } | { ok: false; reason: string } {
  const s = [...state.stages];
  if (next === "record_policy") {
    if (s.includes("policy_decided")) {
      return { ok: false, reason: "policy already decided for this execution id" };
    }
    s.push("policy_decided");
    return { ok: true, state: { stages: s, policyOutcome } };
  }
  if (next === "record_plan") {
    if (!s.includes("policy_decided")) {
      return { ok: false, reason: "sequence violation: isolation preflight before policy decision" };
    }
    if (state.policyOutcome !== "allow") {
      return { ok: false, reason: "sequence violation: policy did not allow; preflight must not run" };
    }
    s.push("preflight_planned");
    return { ok: true, state: { stages: s, policyOutcome: state.policyOutcome } };
  }
  // record_spawn
  if (!s.includes("policy_decided")) {
    return { ok: false, reason: "sequence violation: spawn before policy decision" };
  }
  if (!s.includes("preflight_planned")) {
    return { ok: false, reason: "sequence violation: spawn before isolation preflight" };
  }
  s.push("spawn_attempted");
  return { ok: true, state: { stages: s, policyOutcome: state.policyOutcome } };
}

// ── evidence binding to the existing spine ───────────────────────────────────

export interface BoundEvidenceIds {
  readonly taskId: string;
  readonly agentId: string;
  readonly executionId: string;
  readonly workspaceRoot: string; // redacted before any ledger append
}

export interface BoundExecutionEvidence {
  readonly schemaVersion: typeof ISOLATION_CONTRACT_SCHEMA_VERSION;
  readonly binding: {
    readonly taskId: string;
    readonly agentId: string;
    readonly executionId: string;
    readonly workspaceId: string; // redacted form
  };
  readonly policyRule: string | null;
  readonly outcome: "completed" | "execution_not_started" | "failed";
  readonly enforcedPrimitives: readonly string[];
  readonly evidenceHash: string | null;
  readonly failedPrimitive: string | null;
  readonly exitCode: number | null;
}

/** Redact a workspace path to a bounded, non-reversible label. */
export function redactWorkspace(workspaceRoot: string): string {
  return "workspace:" + createHash("sha256").update(workspaceRoot).digest("hex").slice(0, 12);
}

/**
 * Build the bound evidence record for a policy-allowed, isolation-gated
 * execution. `execution_not_started` covers: preflight abort, orchestrator
 * compile failure, and in-kernel setup failure — i.e. every path where the
 * policy ALLOWed but the target never ran.
 */
export function buildBoundExecutionEvidence(input: {
  readonly ids: BoundEvidenceIds;
  readonly policy: PolicyResult;
  readonly plan: ExecutionPlan;
  readonly run: IsolatedRunResult | null; // null ⇒ never spawned by the orchestrator
}): BoundExecutionEvidence {
  const { ids, policy, plan, run } = input;
  const policyRule =
    (policy.decision as unknown as { matchedRule?: string | null }).matchedRule ?? null;

  let outcome: BoundExecutionEvidence["outcome"];
  let enforced: readonly string[] = [];
  let evidenceHash: string | null = null;
  let failedPrimitive: string | null = null;
  let exitCode: number | null = null;

  if (plan.aborted) {
    outcome = "execution_not_started";
    failedPrimitive = plan.decision.missingRequired[0] ?? null;
  } else if (run === null || !run.targetRan) {
    outcome = "execution_not_started";
    failedPrimitive =
      run?.failureReason?.includes("landlock_fs") === true
        ? "landlock_fs"
        : (Object.entries(run?.evidence?.enforced ?? {}).find(([, v]) => v.applied === false)?.[0] ?? null);
  } else {
    outcome = run.ok ? "completed" : "failed";
    enforced = Object.entries(run.evidence?.enforced ?? {})
      .filter(([, v]) => v.applied)
      .map(([k]) => k);
    evidenceHash = run.evidence?.evidenceHash ?? null;
    exitCode = run.exitCode;
  }

  return {
    schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
    binding: {
      taskId: ids.taskId.slice(0, 64),
      agentId: ids.agentId.slice(0, 64),
      executionId: ids.executionId.slice(0, 64),
      workspaceId: redactWorkspace(ids.workspaceRoot),
    },
    policyRule,
    outcome,
    enforcedPrimitives: enforced,
    evidenceHash,
    failedPrimitive,
    exitCode,
  };
}

/**
 * Append the bound evidence to the ledger (caller retains append authority;
 * binding preserves redaction — only the hashed workspace label is stored).
 */
export function appendBoundEvidence(
  ledger: AppendOnlyLedger,
  evidence: BoundExecutionEvidence,
  actor: Actor
): { ok: boolean; eventId?: string; reason?: string } {
  return ledger.append({
    eventId: "iso-exec-" + evidence.binding.executionId,
    timestamp: new Date().toISOString(),
    eventType: "isolated_execution_evidence",
    actor,
    taskId: evidence.binding.taskId,
    policyDecision: "allow",
    inputSummary: {
      executionClass: "isolated_exec",
      profileId: EXECUTION_BASELINE_PROFILE_ID,
      outcome: evidence.outcome,
      policyRule: evidence.policyRule,
      failedPrimitive: evidence.failedPrimitive,
    },
    resultSummary: {
      outcome: evidence.outcome,
      enforcedPrimitives: evidence.enforcedPrimitives,
      evidenceHash: evidence.evidenceHash,
      exitCode: evidence.exitCode,
      binding: evidence.binding,
    },
  });
}
