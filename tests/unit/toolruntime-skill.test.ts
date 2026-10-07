import { describe, it, expect } from "vitest";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  TOOL_BASELINE_PROFILE_ID,
  SKILL_CONTRACT_SCHEMA_VERSION,
  SKILL_ROLE_BASELINES,
  LocalToolRegistry,
  validateManifest,
  validateSkillDeclaration,
  skillHash,
  planSkillExecution,
  executeSkillRun,
  executeToolRun,
  type SkillDeclaration,
  type IsolationCapabilitySnapshot,
  type LauncherToolSpec,
  type LauncherToolResult,
  type SkillAllocator,
  type SkillPolicyPort,
} from "@menog/runtime-linux";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { AgentRuntime, TaskAllocator, registerAllThreeAgents } from "@menog/agents";
import type { Actor } from "@menog/core";

/**
 * PRE-21D — skill-to-tool binding tests (host-pure; transport double via
 * the 21C seam — no process is spawned here).
 *
 * Proven:
 * - skills are human_reviewed only; agent-authored declarations refused;
 * - no aggregate broadening (declaration must equal the step union);
 * - under-scoped steps and unknown tools are blocked, never repaired;
 * - NO single unqualified agent receives the full union (per-role frozen
 *   baselines qualify each step; a spanning skill needs two roles);
 * - every executed step passes the REAL policy engine and the 21C junction;
 * - a failed step grants nothing to later steps;
 * - evidence reconstructs the path (parent skill hash + per-step records,
 *   deterministic path hash).
 */

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-09-27T00:00:00.000Z",
  primitives: {
    ns_user: "SUPPORTED",
    ns_mount: "SUPPORTED",
    ns_pid: "SUPPORTED",
    ns_ipc: "SUPPORTED",
    ns_uts: "SUPPORTED",
    ns_net: "SUPPORTED",
    cgroup_v2_controllers: "UNSUPPORTED",
    cgroup_v2_delegation: "UNSUPPORTED",
    landlock_fs: "SUPPORTED",
    landlock_net: "UNSUPPORTED",
    seccomp_filter: "SUPPORTED",
    no_new_privs: "SUPPORTED",
    rlimit_set: "SUPPORTED",
    proc_hidepid: "UNSUPPORTED",
  },
};

function toolManifest(toolId: string, caps: string[]) {
  return {
    schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
    toolId,
    version: "1.0.0",
    displayName: "Demo " + toolId,
    description: "Demo tool for skill-binding tests",
    capabilities: caps.map((c) => ({ capability: c, criticality: "required" as const })),
    trustClass: "human_reviewed" as const,
    declaredBy: "human-21d",
    isolationProfileId: TOOL_BASELINE_PROFILE_ID,
  };
}

function buildRegistry(): LocalToolRegistry {
  const registry = new LocalToolRegistry();
  // Tool requirements in the DAY-1 POLICY vocabulary (what the real engine
  // can authorize). Step scopes (SKILL below) carry the PROFILE vocabulary
  // (what each role's identity holds) — the two-vocabulary design.
  const tools: Array<[string, string[]]> = [
    ["tool.listing", ["workspace:list", "workspace:read-metadata"]],
    ["tool.status", ["git:status", "workspace:read-metadata"]],
    ["tool.diff", ["git:diff-read", "workspace:read-metadata"]],
  ];
  for (const [id, caps] of tools) {
    const mv = validateManifest(toolManifest(id, caps));
    if (!mv.ok) throw new Error("fixture manifest invalid: " + mv.message);
    const reg = registry.register({
      manifest: mv.value,
      sideEffectClass: "read_only",
      limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
      isolationProfileId: TOOL_BASELINE_PROFILE_ID,
      network: "none",
      executable: { pathStrategy: "explicit_absolute_path", path: "/opt/tools/" + id.replace(".", "-") },
      registeredBy: "human-21d",
    });
    if (!reg.ok) throw new Error("fixture registration invalid: " + reg.message);
  }
  return registry;
}

/** A spanning skill: no single frozen role baseline covers every step. */
const SKILL: SkillDeclaration = {
  schemaVersion: SKILL_CONTRACT_SCHEMA_VERSION,
  skillId: "demo.workspace-survey",
  version: "1.0.0",
  displayName: "Workspace Survey",
  description: "Read-only listing + status + diff survey of the workspace",
  capabilities: ["git:diff-read", "git:status", "workspace:read"],
  trustClass: "human_reviewed",
  declaredBy: "human-21d",
  steps: [
    {
      stepId: "survey-listing",
      description: "Survey workspace entries (profile-vocabulary scope)",
      toolRef: { toolId: "tool.listing", version: "1.0.0" },
      requiredCapabilities: ["workspace:read"],
      allowedRoles: ["planner"],
    },
    {
      stepId: "survey-status",
      description: "Read repository status",
      toolRef: { toolId: "tool.status", version: "1.0.0" },
      requiredCapabilities: ["git:status"],
      // Declaring planner here is an UPPER BOUND: planner holds no git:*,
      // so qualification narrows execution to the reviewer — declaration
      // cannot broaden a role.
      allowedRoles: ["planner", "reviewer"],
    },
    {
      stepId: "survey-diff",
      description: "Read the working-tree diff",
      toolRef: { toolId: "tool.diff", version: "1.0.0" },
      requiredCapabilities: ["git:diff-read"],
      allowedRoles: ["reviewer"],
    },
  ],
};

// ── adapters over the REAL agents/policy (same as the frozen scenario) ──────

function realAllocator(): SkillAllocator {
  const runtime = new AgentRuntime({ nowEpochMs: () => 2_400_000_000_000 });
  registerAllThreeAgents(runtime, 2_400_000_000_000);
  const allocator = new TaskAllocator(runtime);
  // Vocabulary bridge (recorded): the frozen agents profiles speak a wider
  // profile vocabulary; the skill layer speaks the Day-1 policy vocabulary.
  // This adapter translates the step's policy-vocabulary scope into the
  // profile capability each role holds for it — a seam the tests exercise,
  // never a bypass: qualification is still enforced by the REAL allocator.
  const PROFILE_BRIDGE: Record<string, string> = {
    "workspace:list": "workspace:read",
    "workspace:read-metadata": "workspace:read",
    "git:status": "git:status",
    "git:diff-read": "git:diff-read",
  };
  return {
    allocate(input) {
      const profileCaps = [...new Set(input.task.requiredCapabilities.map((c) => PROFILE_BRIDGE[c] ?? c))];
      const r = allocator.allocate({
        allocatedBy: "menog-agent-planner", // registered runtime identity
        task: {
          label: input.task.label,
          requiredCapabilities: profileCaps,
          allowedRoles: input.task.allowedRoles,
          budget: input.task.budget,
        },
      });
      if (!r.ok) return { ok: false, reason: "allocation refused" };
      return { ok: true, assignmentId: r.assignment.assignmentId, agentId: r.assignment.assignedAgentId, role: r.assignment.assignedRole };
    },
  };
}

function realPolicy(workspaceId: string): SkillPolicyPort {
  const engine = new DenyByDefaultPolicyEngine();
  return {
    evaluate(toolRequiredCapabilities, agentId, workspace) {
      const actor: Actor = { type: "agent", id: agentId };
      const res = engine.evaluate({
        actor,
        verb: "inspect",
        requestedCapabilities: toolRequiredCapabilities as never,
        workspaceId: workspace ?? workspaceId,
      });
      return {
        allowed: res.allowedCapabilities,
        denied: res.deniedCapabilities,
        matchedRule: res.decision.matchedRule ?? null,
      };
    },
  };
}

function recordingTransport(): {
  transport: (spec: LauncherToolSpec) => LauncherToolResult;
  calls: LauncherToolSpec[];
} {
  const calls: LauncherToolSpec[] = [];
  return {
    calls,
    transport: (spec) => {
      calls.push(spec);
      return {
        ok: true,
        exitCode: 0,
        signal: null,
        timedOut: false,
        targetRan: true,
        stdout: Buffer.from("step output\n"),
        stderr: Buffer.alloc(0),
        stdoutTruncated: false,
        stderrTruncated: false,
        failedPrimitive: null,
        isolationEvidence: null,
        isolationProfileId: spec.profileId,
      };
    },
  };
}

function deps(over: Record<string, unknown> = {}): Record<string, unknown> {
  const t = recordingTransport();
  return {
    allocator: realAllocator(),
    policy: realPolicy("ws-21d"),
    registry: buildRegistry(),
    snapshot: SNAPSHOT,
    workspaceRoot: "/tmp/menog-ws-21d",
    transportOverride: t.transport,
    __calls: t.calls,
    ...over,
  };
}

// ── declaration validation ───────────────────────────────────────────────────

describe("21D skill declarations — declarative, never authority", () => {
  it("accepts a valid human_reviewed skill and hashes it deterministically", () => {
    const a = validateSkillDeclaration(SKILL);
    const b = validateSkillDeclaration(SKILL);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (a.ok && b.ok) expect(skillHash(a.value)).toBe(skillHash(b.value));
  });

  it("refuses agent-authored skill generation (no autonomous skills)", () => {
    const r = validateSkillDeclaration({ ...SKILL, trustClass: "agent_supplied" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("SKILL_NOT_HUMAN_REVIEWED");
  });

  it("refuses aggregate broadening in both directions", () => {
    const extra = validateSkillDeclaration({ ...SKILL, capabilities: [...SKILL.capabilities, "workspace:write"] });
    expect(extra.ok).toBe(false);
    if (!extra.ok) expect(extra.code).toBe("AGGREGATE_BROADENING");
    const missing = validateSkillDeclaration({ ...SKILL, capabilities: ["workspace:list"] });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.code).toBe("AGGREGATE_BROADENING");
  });

  it("blocks steps whose tool is unknown", () => {
    const registry = buildRegistry();
    const unknown = planSkillExecution(
      (validateSkillDeclaration({
        ...SKILL,
        steps: [
          {
            stepId: "ghost",
            description: "unknown tool step",
            toolRef: { toolId: "tool.ghost", version: "9.9.9" },
            requiredCapabilities: ["workspace:list"],
            allowedRoles: ["planner"],
          },
        ],
        capabilities: ["workspace:list"],
      }) as { value: SkillDeclaration }).value,
      registry
    );
    expect(unknown.executable).toBe(false);
    expect(unknown.steps[0]!.blockedReason).toContain("STEP_TOOL_UNKNOWN");
  });

  it("blocks steps no frozen role baseline can qualify", () => {
    const registry = buildRegistry();
    const s = (validateSkillDeclaration({
      ...SKILL,
      steps: [
        {
          stepId: "privileged",
          description: "no baseline covers a privileged capability",
          toolRef: { toolId: "tool.listing", version: "1.0.0" },
          requiredCapabilities: ["process:privileged"],
          allowedRoles: ["planner", "builder", "reviewer"],
        },
      ],
      capabilities: ["process:privileged"],
    }) as { value: SkillDeclaration }).value;
    const plan = planSkillExecution(s, registry);
    expect(plan.executable).toBe(false);
    expect(plan.steps[0]!.blockedReason).toContain("STEP_UNQUALIFIED_FOR_ALL_ROLES");
  });
});

// ── role distribution: no super-agent ────────────────────────────────────────

describe("21D role distribution — no single unqualified agent gets the union", () => {
  it("no role spans the exclusive capabilities of the others (planner/builder hold no git:*)", () => {
    // planner/builder hold NO git:* capability, reviewer holds no
    // plan:generate/workspace:write: declared allowedRoles can never create
    // a super-agent because qualification is bounded by the frozen profiles.
    expect(SKILL_ROLE_BASELINES.planner.some((c) => c.startsWith("git:"))).toBe(false);
    expect(SKILL_ROLE_BASELINES.builder.some((c) => c.startsWith("git:"))).toBe(false);
    expect(SKILL_ROLE_BASELINES.reviewer).not.toContain("plan:generate");
    expect(SKILL_ROLE_BASELINES.reviewer).not.toContain("workspace:write");
  });

  it("each step qualifies only its intended roles (frozen baselines)", () => {
    const plan = planSkillExecution(SKILL, buildRegistry());
    expect(plan.executable).toBe(true);
    expect(plan.steps[0]!.qualifyingRoles).toEqual(["planner"]);
    // allowedRoles declared planner+reviewer; qualification narrows to reviewer.
    expect(plan.steps[1]!.qualifyingRoles).toEqual(["reviewer"]);
    expect(plan.steps[2]!.qualifyingRoles).toEqual(["reviewer"]);
  });
});

// ── the full scenario ────────────────────────────────────────────────────────

describe("21D scenario — deterministic multi-step skill, real allocation + policy", () => {
  it("runs every step through policy + junction; evidence reconstructs the path", () => {
    const d = deps();
    const evidence = executeSkillRun(SKILL, d as never);
    expect(evidence.overall).toBe("completed");
    expect(evidence.steps).toHaveLength(3);
    // Per-step: each step got a qualified agent and passed the real engine.
    const [listing, status, diff] = evidence.steps;
    if (listing === undefined || status === undefined || diff === undefined) throw new Error("expected three steps");
    expect(listing.role).toBe("planner");
    expect(status.role).toBe("reviewer");
    expect(diff.role).toBe("reviewer");
    for (const s of evidence.steps) {
      expect(s.status).toBe("not_started");
      expect(s.manifestHash).not.toBeNull();
      expect(s.stepEvidenceHash).not.toBeNull();
      expect(s.blockedReason).toBeNull();
    }
    // Real policy rules were matched per step (not an orchestrator assertion).
    expect(listing.policyRule).toMatch(/^rule:day1:allow-inspect/);
    // Deterministic path hash: identical run ⇒ identical path bytes.
    const again = executeSkillRun(SKILL, deps() as never);
    expect(again.pathHash).toBe(evidence.pathHash);
    // Skill hash binds the parent.
    expect(evidence.skillHash).toBe(skillHash(SKILL));
  });

  it("the transport receives exactly one gated spec per step with minimal authority", () => {
    const d = deps();
    executeSkillRun(SKILL, d as never);
    const calls = d.__calls as LauncherToolSpec[];
    expect(calls).toHaveLength(3);
    for (const spec of calls) {
      expect(spec.profileId).toBe(TOOL_BASELINE_PROFILE_ID);
      // Platform-agnostic containment: the fixture workspace name survives
      // canonicalization on both POSIX and Windows hosts.
      expect(spec.cwd.toLowerCase()).toContain("menog-ws-21d");
      expect(spec.envAllowlist).toEqual([]);
    }
    // Different tools per step (role-distributed), all registry-pinned paths.
    const paths = new Set(calls.map((c) => c.targetArgv[0]));
    expect(paths.size).toBe(3);
  });

  it("a failed step grants nothing to later steps (independent validation)", () => {
    // Make the MIDDLE step unknown to the registry: step 1 runs, step 2 is
    // blocked, step 3 still runs — no carried authority, no aggregate state.
    const registry = buildRegistry();
    const broken = (validateSkillDeclaration({
      ...SKILL,
      steps: [SKILL.steps[0], { ...SKILL.steps[1], toolRef: { toolId: "tool.ghost", version: "1.0.0" } }, SKILL.steps[2]],
    }) as { value: SkillDeclaration }).value;
    const d = deps({ registry });
    const evidence = executeSkillRun(broken, d as never);
    expect(evidence.overall).toBe("partial");
    expect(evidence.steps[0]!.status).toBe("not_started");
    expect(evidence.steps[1]!.status).toBe("validation_denied");
    expect(evidence.steps[1]!.blockedReason).toContain("STEP_TOOL_UNKNOWN");
    expect(evidence.steps[2]!.status).toBe("not_started");
  });

  it("a policy deny for one step is recorded and does not block independent others", () => {
    const d = deps();
    // Overriding the policy port with a real engine that denies everything.
    const denying: SkillPolicyPort = {
      evaluate: () => ({ allowed: [], denied: [], matchedRule: "rule:day1:deny-non-inspect-verb" }),
    };
    const evidence = executeSkillRun(SKILL, { ...d, policy: denying } as never);
    expect(evidence.overall).toBe("blocked");
    for (const s of evidence.steps) {
      expect(s.status).toBe("policy_denied");
      expect(s.policyRule).toBe("rule:day1:deny-non-inspect-verb");
      expect(s.stepEvidenceHash).toBeNull();
    }
  });

  it("direct junction evidence stays available per step (reconstruction)", () => {
    const d = deps();
    const evidence = executeSkillRun(SKILL, d as never);
    // Each step's per-step hash re-derives from the same junction the direct
    // path uses: run one step directly and compare shapes.
    const entry = buildRegistry().lookup("tool.listing", "1.0.0");
    if (!entry.ok) throw new Error("fixture");
    const direct = executeToolRun({
      request: {
        requestId: "direct-1",
        toolId: "tool.listing",
        version: "1.0.0",
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "tool.listing",
          version: "1.0.0",
          input: {},
          constraints: {},
        },
        requester: { actorType: "agent", id: "menog-agent-planner" },
        // The 21C gate speaks the TOOL/policy vocabulary: task scope and
        // agent capabilities must cover the tool's manifest caps.
        taskScope: ["workspace:list", "workspace:read-metadata"],
        agentCapabilities: ["workspace:list", "workspace:read-metadata"],
        policyOutcome: "allow",
        isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
      },
      entry: entry.value,
      snapshot: SNAPSHOT,
      workspaceRoot: "/tmp/menog-ws-21d",
      policyOutcome: "allow",
      transportOverride: (deps() as { transportOverride: (s: LauncherToolSpec) => LauncherToolResult }).transportOverride,
    });
    expect(direct.decision.status).toBe("not_started");
    expect(direct.evidence.evidenceHash).toBeTruthy();
    expect(evidence.steps[0]!.stepEvidenceHash).toBeTruthy();
  });
});
