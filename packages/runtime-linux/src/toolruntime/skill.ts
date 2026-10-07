/**
 * PRE-21D — skill-to-tool binding and role-distributed execution.
 *
 * A SKILL IS DECLARATIVE, NEVER AUTHORITY. It names an ordered set of tool
 * operations; every capability a step consumes is re-derived per step and
 * must survive the same junction as any direct tool run (21C). Nothing here
 * grants, aggregates, or carries authority between steps.
 *
 * Frozen rules (each test-locked):
 * - Skills are human_reviewed ONLY: agent-authored skill declarations are
 *   refused by validation (no autonomous skill generation).
 * - No aggregate broadening: the skill's declared capability set must equal
 *   the union of its steps' requirements — no capability is claimed that no
 *   step needs, and no step demands beyond the declaration.
 * - Minimum capabilities per step: each step declares exactly what its tool
 *   requires; the registry's tool must be covered by the step scope.
 * - Role distribution: every step must be executable by at least one role
   * whose FROZEN baseline covers the step's requirements — the union of a
 *   skill's steps can never be satisfied by a single role baseline when the
 *   steps span roles, so no unqualified agent receives the full union.
 * - Mediated handoff only: steps never pass authority to each other; the
 *   orchestrator allocates every step and each step is independently
 *   validated, authorized, and isolated. A failed step grants nothing to
 *   later steps.
 * - Evidence: parent skill identity + per-step execution evidence are bound
 *   (skill hash, per-step manifest/execution hashes, deterministic path
 *   hash) so the executed path is reconstructible from evidence alone.
 */

import { isolationEvidenceHash } from "../isolation/canonical.js";
import type { IsolationCapabilitySnapshot } from "../isolation/types.js";
import type { LauncherToolResult, LauncherToolSpec } from "../isolation/enforce/index.js";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import { executeToolRun, type ToolExecutionInput, type ToolExecutionOutcome } from "./execute.js";
import type { ToolExecutionRequest } from "./types.js";
import type { ToolRegistryEntry, LocalToolRegistry } from "./registry.js";

// ── vocabulary ───────────────────────────────────────────────────────────────

export const SKILL_CONTRACT_SCHEMA_VERSION = "menog-skill-binding/v0" as const;
export type SkillContractSchemaVersion = typeof SKILL_CONTRACT_SCHEMA_VERSION;

export type SkillRole = "planner" | "builder" | "reviewer";

export const SKILL_ROLES: readonly SkillRole[] = Object.freeze(["planner", "builder", "reviewer"]);

/**
 * FROZEN role→capability baselines for skill distribution — an exact MIRROR
 * of the authoritative agent profiles in @menog/agents (planner surveys,
 * builder modifies, reviewer validates). Mirroring (not importing) keeps
 * runtime-linux dependency-free; equality with the source of truth is
 * TEST-LOCKED so the two can never drift.
 *
 * Two frozen vocabularies meet here, by design:
 * - STEP scopes and role baselines speak the AGENTS-PROFILE vocabulary
 *   (what each role's identity holds — consumed by allocation).
 * - TOOL manifests speak the DAY-1 POLICY vocabulary (what the engine can
 *   authorize — consumed by the policy port and the 21C gate).
 * The orchestrator enforces BOTH independently per step: allocation proves
 * role qualification, Policy proves capability authorization. No single
 * role is both allowed and qualified for every step of a spanning skill
 * (the human declaration decides allowedRoles per step), so no super-agent
 * arises from aggregation.
 */
export const SKILL_ROLE_BASELINES: Readonly<Record<SkillRole, readonly string[]>> = Object.freeze({
  planner: Object.freeze(["plan:generate", "workspace:read", "workspace:search"]),
  builder: Object.freeze(["workspace:read", "workspace:search", "workspace:write"]),
  reviewer: Object.freeze(["workspace:read", "git:status", "git:diff-read"]),
});

const CAPABILITY_PATTERN = /^[a-z][a-z0-9._-]*:[a-z][a-z0-9._-]{0,63}$/;
const ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;

function isBounded(v: unknown, min: number, max: number): v is string {
  return typeof v === "string" && v.length >= min && v.length <= max;
}

export type SkillResult<T> = { ok: true; value: T } | { ok: false; code: SkillFailureCode; message: string };

export type SkillFailureCode =
  | "SKILL_INVALID"
  | "SKILL_NOT_HUMAN_REVIEWED"
  | "AGGREGATE_BROADENING"
  | "STEP_UNDERSCOPES_TOOL"
  | "STEP_TOOL_UNKNOWN"
  | "STEP_UNQUALIFIED_FOR_ALL_ROLES"
  | "STEP_ALLOCATION_FAILED"
  | "STEP_POLICY_DENIED"
  | "STEP_GATE_DENIED";

// ── declaration types ────────────────────────────────────────────────────────

export interface SkillStep {
  readonly stepId: string;
  readonly description: string;
  readonly toolRef: { readonly toolId: string; readonly version: string };
  /** Minimum capabilities this step consumes (must cover the tool's needs). */
  readonly requiredCapabilities: readonly string[];
  /** Roles that may receive this step (1..3). */
  readonly allowedRoles: readonly SkillRole[];
}

export interface SkillDeclaration {
  readonly schemaVersion: SkillContractSchemaVersion;
  readonly skillId: string;
  readonly version: string;
  readonly displayName: string;
  readonly description: string;
  /** Exactly the union of step capabilities (validated; no broadening). */
  readonly capabilities: readonly string[];
  /** ALWAYS "human_reviewed" — agent-authored skills are refused. */
  readonly trustClass: "human_reviewed";
  readonly declaredBy: string;
  readonly steps: readonly SkillStep[];
}

/** Validate a skill declaration WITHOUT any registry (pure shape + law). */
export function validateSkillDeclaration(input: unknown): SkillResult<SkillDeclaration> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, code: "SKILL_INVALID", message: "skill must be an object" };
  }
  const s = input as Record<string, unknown>;
  if (s.schemaVersion !== SKILL_CONTRACT_SCHEMA_VERSION) {
    return { ok: false, code: "SKILL_INVALID", message: "schemaVersion must be " + SKILL_CONTRACT_SCHEMA_VERSION };
  }
  if (typeof s.skillId !== "string" || !ID_PATTERN.test(s.skillId)) {
    return { ok: false, code: "SKILL_INVALID", message: "skillId must match " + String(ID_PATTERN) };
  }
  if (typeof s.version !== "string" || s.version.length === 0 || s.version.length > 32) {
    return { ok: false, code: "SKILL_INVALID", message: "version must be a non-empty string of at most 32 characters" };
  }
  if (!isBounded(s.displayName, 1, 120) || !isBounded(s.description, 1, 600)) {
    return { ok: false, code: "SKILL_INVALID", message: "displayName/description must be bounded strings" };
  }
  if (s.trustClass !== "human_reviewed") {
    return { ok: false, code: "SKILL_NOT_HUMAN_REVIEWED", message: "skills must be human_reviewed; agent-authored skill generation is refused" };
  }
  if (!isBounded(s.declaredBy, 1, 120)) {
    return { ok: false, code: "SKILL_INVALID", message: "declaredBy must be 1..120 characters" };
  }
  if (!Array.isArray(s.steps) || s.steps.length === 0 || s.steps.length > 16) {
    return { ok: false, code: "SKILL_INVALID", message: "steps must be an array of 1..16 entries" };
  }

  const steps: SkillStep[] = [];
  const union = new Set<string>();
  const stepIds = new Set<string>();
  for (const raw of s.steps) {
    if (typeof raw !== "object" || raw === null) {
      return { ok: false, code: "SKILL_INVALID", message: "each step must be an object" };
    }
    const st = raw as Record<string, unknown>;
    if (typeof st.stepId !== "string" || !ID_PATTERN.test(st.stepId) || stepIds.has(st.stepId)) {
      return { ok: false, code: "SKILL_INVALID", message: "stepId must be a unique bounded id" };
    }
    stepIds.add(st.stepId);
    if (!isBounded(st.description, 1, 300)) {
      return { ok: false, code: "SKILL_INVALID", message: "step description must be 1..300 characters" };
    }
    const ref = st.toolRef;
    if (typeof ref !== "object" || ref === null) {
      return { ok: false, code: "SKILL_INVALID", message: "step.toolRef must be an object" };
    }
    const r = ref as Record<string, unknown>;
    if (typeof r.toolId !== "string" || !ID_PATTERN.test(r.toolId) || typeof r.version !== "string" || r.version.length === 0 || r.version.length > 32) {
      return { ok: false, code: "SKILL_INVALID", message: "step.toolRef must carry a bounded toolId+version" };
    }
    if (!Array.isArray(st.requiredCapabilities) || st.requiredCapabilities.length === 0 || st.requiredCapabilities.length > 16) {
      return { ok: false, code: "SKILL_INVALID", message: "step.requiredCapabilities must be 1..16 capability ids" };
    }
    const caps: string[] = [];
    for (const c of st.requiredCapabilities) {
      if (typeof c !== "string" || !CAPABILITY_PATTERN.test(c)) {
        return { ok: false, code: "SKILL_INVALID", message: "capability ids must be 'scope:name'" };
      }
      caps.push(c);
      union.add(c);
    }
    if (!Array.isArray(st.allowedRoles) || st.allowedRoles.length === 0 || st.allowedRoles.length > 3) {
      return { ok: false, code: "SKILL_INVALID", message: "step.allowedRoles must be 1..3 roles" };
    }
    for (const role of st.allowedRoles) {
      if (typeof role !== "string" || !SKILL_ROLES.includes(role as SkillRole)) {
        return { ok: false, code: "SKILL_INVALID", message: "allowedRoles must contain only planner|builder|reviewer" };
      }
    }
    steps.push({
      stepId: st.stepId,
      description: st.description,
      toolRef: { toolId: r.toolId, version: r.version },
      requiredCapabilities: Object.freeze(caps),
      allowedRoles: Object.freeze((st.allowedRoles as SkillRole[]).slice()),
    });
  }

  // No aggregate broadening: declared capabilities must equal the step union.
  const declared = Array.isArray(s.capabilities) ? (s.capabilities as unknown[]) : null;
  if (!declared || declared.some((c) => typeof c !== "string" || !CAPABILITY_PATTERN.test(c))) {
    return { ok: false, code: "SKILL_INVALID", message: "capabilities must be an array of 'scope:name' ids" };
  }
  const declaredSet = new Set(declared as string[]);
  for (const c of union) {
    if (!declaredSet.has(c)) {
      return { ok: false, code: "AGGREGATE_BROADENING", message: "step capability '" + c + "' is missing from the skill declaration" };
    }
  }
  for (const c of declaredSet) {
    if (!union.has(c)) {
      return { ok: false, code: "AGGREGATE_BROADENING", message: "declared capability '" + c + "' is not required by any step (aggregate broadening)" };
    }
  }

  const skill: SkillDeclaration = Object.freeze({
    schemaVersion: SKILL_CONTRACT_SCHEMA_VERSION,
    skillId: s.skillId,
    version: s.version,
    displayName: s.displayName,
    description: s.description,
    capabilities: Object.freeze([...union].sort()),
    trustClass: "human_reviewed",
    declaredBy: s.declaredBy,
    steps: Object.freeze(steps),
  });
  return { ok: true, value: skill };
}

/** Deterministic skill hash (canonical JSON, sha256). */
export function skillHash(skill: SkillDeclaration): string {
  return isolationEvidenceHash({
    schemaVersion: skill.schemaVersion,
    skillId: skill.skillId,
    version: skill.version,
    displayName: skill.displayName,
    description: skill.description,
    capabilities: skill.capabilities,
    trustClass: skill.trustClass,
    declaredBy: skill.declaredBy,
    steps: skill.steps,
  });
}

// ── pure binding plan (registry + role baselines; no execution) ──────────────

export interface SkillStepPlan {
  readonly stepId: string;
  readonly toolId: string;
  readonly version: string;
  readonly executable: boolean;
  /** Qualifying roles for this step (baseline covers the step scope). */
  readonly qualifyingRoles: readonly SkillRole[];
  readonly blockedReason?: string;
}

export interface SkillPlan {
  readonly skillId: string;
  readonly version: string;
  readonly hash: string;
  readonly steps: readonly SkillStepPlan[];
  readonly executable: boolean;
}

/**
 * Pure binding plan: resolve every step's tool against the registry, check
 * scope coverage and role qualification against the FROZEN baselines. No
 * I/O, no execution; blocked steps are recorded, never repaired.
 */
export function planSkillExecution(skill: SkillDeclaration, registry: LocalToolRegistry): SkillPlan {
  const steps: SkillStepPlan[] = [];
  for (const step of skill.steps) {
    const found = registry.lookup(step.toolRef.toolId, step.toolRef.version);
    if (!found.ok) {
      steps.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        executable: false,
        qualifyingRoles: [],
        blockedReason: "STEP_TOOL_UNKNOWN: no registration for " + step.toolRef.toolId + "@" + step.toolRef.version,
      });
      continue;
    }
    // Role qualification against the frozen baselines: a role qualifies when
    // its baseline COVERS the step scope (every required capability is one
    // the role already holds). Baselines may hold more than a given step
    // needs — that is the role's standing least privilege, not broadening.
    const qualifying = step.allowedRoles.filter((role) =>
      step.requiredCapabilities.every((c) => SKILL_ROLE_BASELINES[role].includes(c))
    );
    if (qualifying.length === 0) {
      steps.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        executable: false,
        qualifyingRoles: [],
        blockedReason: "STEP_UNQUALIFIED_FOR_ALL_ROLES: no frozen role baseline covers this step's scope",
      });
      continue;
    }
    steps.push({
      stepId: step.stepId,
      toolId: step.toolRef.toolId,
      version: step.toolRef.version,
      executable: true,
      qualifyingRoles: qualifying,
    });
  }
  return {
    skillId: skill.skillId,
    version: skill.version,
    hash: skillHash(skill),
    steps,
    executable: steps.every((s) => s.executable),
  };
}

// ── orchestrator (mediated allocation + per-step junction) ───────────────────

/** Structural allocation port (satisfied by @menog/agents TaskAllocator via a thin adapter). */
export interface SkillAllocator {
  allocate(input: {
    allocatedBy: string;
    task: {
      readonly label: string;
      readonly requiredCapabilities: readonly string[];
      readonly allowedRoles: readonly SkillRole[];
      readonly budget: { readonly maxSteps: number };
    };
  }): { ok: true; assignmentId: string; agentId: string; role: SkillRole } | { ok: false; reason: string };
}

/** Structural policy port (satisfied by the Day-1 engine via a thin adapter). */
export interface SkillPolicyPort {
  /**
   * Evaluate the TOOL's manifest-required capabilities (the policy/gate
   * vocabulary) for the assigned agent. The step's agent-profile scope is a
   * separate vocabulary consumed by allocation/qualification only.
   */
  evaluate(toolRequiredCapabilities: readonly string[], agentId: string, workspaceId: string): {
    readonly allowed: readonly string[];
    readonly denied: readonly string[];
    readonly matchedRule: string | null;
  };
}

export interface SkillStepEvidence {
  readonly stepId: string;
  readonly toolId: string;
  readonly version: string;
  readonly assignedAgentId: string | null;
  readonly role: SkillRole | null;
  readonly status: string;
  readonly policyRule: string | null;
  readonly manifestHash: string | null;
  readonly stepEvidenceHash: string | null;
  readonly ledgerEventId: string | null;
  readonly blockedReason: string | null;
}

export interface SkillRunEvidence {
  readonly schemaVersion: SkillContractSchemaVersion;
  readonly skillId: string;
  readonly version: string;
  readonly skillHash: string;
  readonly overall: "completed" | "partial" | "blocked";
  readonly pathHash: string;
  readonly steps: readonly SkillStepEvidence[];
}

export interface SkillRunDeps {
  readonly allocator: SkillAllocator;
  readonly policy: SkillPolicyPort;
  readonly registry: LocalToolRegistry;
  readonly snapshot: IsolationCapabilitySnapshot;
  readonly workspaceRoot: string;
  readonly envValueSource?: (name: string) => string | undefined;
  readonly ledger?: AppendOnlyLedger;
  readonly ledgerActor?: { type: "runtime" | "agent" | "human"; id: string };
  readonly transportOverride?: (spec: LauncherToolSpec) => LauncherToolResult;
}

const ORCHESTRATOR_ID = "menog-skill-orchestrator";

/**
 * Execute a skill as independent, role-distributed governed tool runs.
 * Every step is allocated by the orchestrator (mediated handoff only),
 * evaluated by Policy, and run through the 21C junction. A failed step
 * grants nothing to any other step; evidence binds the parent skill and
 * each step's execution.
 */
export function executeSkillRun(skill: SkillDeclaration, deps: SkillRunDeps): SkillRunEvidence {
  const plan = planSkillExecution(skill, deps.registry);
  const stepEvidence: SkillStepEvidence[] = [];

  const planned = plan.steps;
  for (const step of skill.steps) {
    const stepPlan = planned.find((p) => p.stepId === step.stepId);
    if (stepPlan === undefined) {
      // planSkillExecution maps 1:1 over skill.steps; unreachable by construction.
      continue;
    }

    if (!stepPlan.executable) {
      stepEvidence.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        assignedAgentId: null,
        role: null,
        status: "validation_denied",
        policyRule: null,
        manifestHash: null,
        stepEvidenceHash: null,
        ledgerEventId: null,
        blockedReason: stepPlan.blockedReason ?? "blocked at plan",
      });
      continue;
    }

    // Mediated allocation (the orchestrator allocates; agents never hand
    // authority to each other).
    const alloc = deps.allocator.allocate({
      allocatedBy: ORCHESTRATOR_ID,
      task: {
        label: skill.skillId + "/" + step.stepId,
        requiredCapabilities: step.requiredCapabilities,
        allowedRoles: step.allowedRoles,
        budget: { maxSteps: 4 },
      },
    });
    if (!alloc.ok) {
      stepEvidence.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        assignedAgentId: null,
        role: null,
        status: "validation_denied",
        policyRule: null,
        manifestHash: null,
        stepEvidenceHash: null,
        ledgerEventId: null,
        blockedReason: "STEP_ALLOCATION_FAILED: " + alloc.reason,
      });
      continue;
    }

    // Resolve the registry entry (fail-closed: the plan proved it exists,
    // but the orchestrator re-resolves rather than trusting cross-references).
    const lookedUp = deps.registry.lookup(step.toolRef.toolId, step.toolRef.version);
    if (!lookedUp.ok) {
      stepEvidence.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        assignedAgentId: alloc.agentId,
        role: alloc.role,
        status: "validation_denied",
        policyRule: null,
        manifestHash: null,
        stepEvidenceHash: null,
        ledgerEventId: null,
        blockedReason: "STEP_TOOL_UNKNOWN: registration vanished mid-run",
      });
      continue;
    }
    const entry: ToolRegistryEntry = lookedUp.value;

    // Policy for THIS step, THIS assigned agent, over the TOOL's
    // manifest-required capabilities (the policy/gate vocabulary). The
    // engine verdict is the only authorization; the orchestrator never
    // assumes allow.
    const toolCaps = entry.manifest.capabilities.filter((c) => c.criticality === "required").map((c) => c.capability);
    const policy = deps.policy.evaluate(toolCaps, alloc.agentId, deps.workspaceRoot);
    const uncovered = toolCaps.filter((c) => !policy.allowed.includes(c));
    if (uncovered.length > 0) {
      stepEvidence.push({
        stepId: step.stepId,
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        assignedAgentId: alloc.agentId,
        role: alloc.role,
        status: "policy_denied",
        policyRule: policy.matchedRule,
        manifestHash: null,
        stepEvidenceHash: null,
        ledgerEventId: null,
        blockedReason: "STEP_POLICY_DENIED: required capability '" + uncovered[0] + "' was not allowed",
      });
      continue;
    }

    // The governed junction (21C) — the ONLY execution surface. The entry
    // was already resolved fail-closed at the top of this iteration.
    const request: ToolExecutionRequest = {
      requestId: (skill.skillId + "-" + step.stepId).slice(0, 60),
      toolId: step.toolRef.toolId,
      version: step.toolRef.version,
      envelope: {
        schemaVersion: "menog-tool-runtime-contract/v0",
        toolId: step.toolRef.toolId,
        version: step.toolRef.version,
        input: { step: step.stepId, description: step.description },
        constraints: {},
      },
      requester: { actorType: "agent", id: alloc.agentId },
      // The gate vocabulary is the TOOL's manifest caps, derived from the
      // trusted registry entry — never from agent data. Role distribution
      // was enforced at allocation (unqualified roles never reach this).
      taskScope: toolCaps,
      agentCapabilities: toolCaps,
      policyOutcome: "allow",
      isolation: { profileId: "tool-baseline-v0", canEnforce: true },
    };
    const junctionInput: ToolExecutionInput = {
      request,
      entry,
      snapshot: deps.snapshot,
      workspaceRoot: deps.workspaceRoot,
      policyOutcome: "allow",
      policyRuleId: policy.matchedRule ?? undefined,
      envValueSource: deps.envValueSource,
      ledger: deps.ledger,
      ledgerActor: deps.ledgerActor,
      transportOverride: deps.transportOverride,
    };
    const outcome: ToolExecutionOutcome = executeToolRun(junctionInput);

    stepEvidence.push({
      stepId: step.stepId,
      toolId: step.toolRef.toolId,
      version: step.toolRef.version,
      assignedAgentId: alloc.agentId,
      role: alloc.role,
      status: outcome.decision.status,
      policyRule: policy.matchedRule,
      manifestHash: entry.manifestHash,
      stepEvidenceHash: outcome.evidence.evidenceHash,
      ledgerEventId: outcome.ledgerEventId,
      blockedReason: outcome.decision.status !== "not_started" && outcome.result === null ? outcome.decision.reason ?? null : null,
    });
  }

  const completed = stepEvidence.filter((s) => s.status === "not_started" || s.status === "completed").length;
  const overall: SkillRunEvidence["overall"] =
    completed === stepEvidence.length ? "completed" : completed === 0 ? "blocked" : "partial";

  // Deterministic path hash: binds the skill and the executed step sequence
  // (identity + assignment + status + pinned manifest hash). Wall-clocked
  // per-step evidence hashes are NOT folded in — the path of two identical
  // runs is byte-identical — while each step's actual evidence remains
  // independently reconstructible via its own hash.
  const pathHash = isolationEvidenceHash({
    skillId: skill.skillId,
    version: skill.version,
    hash: skillHash(skill),
    steps: stepEvidence.map((s) => ({
      stepId: s.stepId,
      toolId: s.toolId,
      version: s.version,
      status: s.status,
      assignedAgentId: s.assignedAgentId,
      role: s.role,
      manifestHash: s.manifestHash,
    })),
  });

  return Object.freeze({
    schemaVersion: SKILL_CONTRACT_SCHEMA_VERSION,
    skillId: skill.skillId,
    version: skill.version,
    skillHash: skillHash(skill),
    overall,
    pathHash,
    steps: Object.freeze(stepEvidence),
  });
}
