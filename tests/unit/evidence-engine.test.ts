import { describe, it, expect } from "vitest";
import {
  CommitCandidateBuilder,
  explainCandidate,
  generateReplayPlan,
  compareCandidates,
  generateRollbackPlan,
  EVIDENCE_EXPLANATION_SCHEMA_VERSION,
  ROLLBACK_PLAN_SCHEMA_VERSION,
  CANDIDATE_COMPARISON_SCHEMA_VERSION,
  REPLAY_PLAN_SCHEMA_VERSION,
  REPLAY_ENGINE_OVERCLAIM_GUARD,
  type CommitCandidateInput,
  type CommitCandidate,
} from "@menog/commit-engine";
import type { Actor } from "@menog/core";

const ZERO_HASH = "0".repeat(64);
const FAKE_HASH_A = "a".repeat(64);
const FAKE_HASH_B = "b".repeat(64);
const AGENT: Actor = { type: "agent", id: "evidence-test-agent" };

function buildCandidate(overrides: Partial<CommitCandidateInput> = {}): CommitCandidate {
  const input: CommitCandidateInput = {
    candidateId: "cand-15d-" + Math.random().toString(36).slice(2, 10),
    createdAt: new Date().toISOString(),
    agent: AGENT,
    goal: "Add evidence engine to commit-engine package",
    taskId: "task-15d-001",
    verbs: ["inspect", "modify", "validate"],
    files: [
      {
        relativePath: "packages/commit-engine/src/evidenceEngine.ts",
        kind: "added",
        previousHash: ZERO_HASH,
        newHash: FAKE_HASH_A,
        byteDelta: 5000,
      },
      {
        relativePath: "packages/commit-engine/src/index.ts",
        kind: "modified",
        previousHash: FAKE_HASH_B,
        newHash: FAKE_HASH_A,
        byteDelta: 200,
      },
    ],
    diff: {
      diffHash: FAKE_HASH_A,
      additions: 150,
      deletions: 10,
      filesChanged: 2,
      diffAvailable: true,
      unifiedDiff: "--- /dev/null\n+++ b/evidenceEngine.ts\n@@ -0,0 +1,150 @@\n+// evidence engine\n",
    },
    tests: {
      testsRun: true,
      totalTests: 329,
      passedTests: 329,
      failedTests: 0,
      reportHash: FAKE_HASH_A,
    },
    risk: {
      level: "medium",
      rationale: "New module with no side effects",
      requiresHumanApproval: true,
    },
    approvals: [],
    environment: {
      nodeVersion: "v24.20.0",
      pnpmVersion: "10.11.1",
      platform: "win32",
      workspaceRoot: "C:\\repo",
    },
    ledgerEventIds: ["evt-001"],
    previousCandidateHash: ZERO_HASH,
    ...overrides,
  };

  const res = new CommitCandidateBuilder().build(input);
  if (!res.ok || !res.candidate) throw new Error(`build failed: ${res.reason}`);
  return res.candidate;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. EXPLAIN COMPLETENESS
// ─────────────────────────────────────────────────────────────────────────────
describe("15D — Evidence Engine: Explain Completeness", () => {
  it("explainCandidate returns correct schema version and candidateId", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    expect(exp.schemaVersion).toBe(EVIDENCE_EXPLANATION_SCHEMA_VERSION);
    expect(exp.candidateId).toBe(c.candidateId);
    expect(exp.candidateHash).toBe(c.candidateHash);
    expect(typeof exp.generatedAt).toBe("string");
  });

  it("explainCandidate generates all required sections", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    const kinds = exp.sections.map((s) => s.kind);
    expect(kinds).toContain("provenance");
    expect(kinds).toContain("diff");
    expect(kinds).toContain("risk");
    expect(kinds).toContain("approval");
    expect(kinds).toContain("tests");
    expect(kinds).toContain("environment");
  });

  it("isComplete=true and no missing fields for a well-formed candidate", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    expect(exp.isComplete).toBe(true);
    expect(exp.missingFields).toHaveLength(0);
  });

  it("provenance section contains candidateId, goal, agent, verbs, and candidateHash", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    const provenance = exp.sections.find((s) => s.kind === "provenance");
    expect(provenance).toBeDefined();
    expect(provenance!.content).toContain(c.candidateId);
    expect(provenance!.content).toContain(c.goal);
    expect(provenance!.content).toContain(c.agent.id);
    expect(provenance!.content).toContain("inspect");
    expect(provenance!.content).toContain("modify");
    expect(provenance!.content).toContain("validate");
    expect(provenance!.content).toContain(c.candidateHash);
  });

  it("diff section contains additions, deletions, filesChanged, and diffHash", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    const diffSec = exp.sections.find((s) => s.heading === "Diff Summary");
    expect(diffSec).toBeDefined();
    expect(diffSec!.content).toContain("150");
    expect(diffSec!.content).toContain("10");
    expect(diffSec!.content).toContain("2");
    expect(diffSec!.content).toContain(FAKE_HASH_A);
  });

  it("risk section contains risk level and rationale", () => {
    const c = buildCandidate();
    const exp = explainCandidate(c);

    const riskSec = exp.sections.find((s) => s.kind === "risk");
    expect(riskSec).toBeDefined();
    expect(riskSec!.content).toContain("MEDIUM");
    expect(riskSec!.content).toContain("New module with no side effects");
  });

  it("explanation is deterministic — two calls on same candidate produce same content", () => {
    const c = buildCandidate();
    const exp1 = explainCandidate(c);
    const exp2 = explainCandidate(c);

    expect(exp1.candidateHash).toBe(exp2.candidateHash);
    expect(exp1.sections.length).toBe(exp2.sections.length);
    for (let i = 0; i < exp1.sections.length; i++) {
      expect(exp1.sections[i]!.content).toBe(exp2.sections[i]!.content);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. REPLAY PLAN SERIALIZATION
// ─────────────────────────────────────────────────────────────────────────────
describe("15D — Evidence Engine: Replay Plan Serialization", () => {
  it("generateReplayPlan returns correct schema version and candidate linkage", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);

    expect(plan.schemaVersion).toBe(REPLAY_PLAN_SCHEMA_VERSION);
    expect(plan.candidateId).toBe(c.candidateId);
    expect(plan.candidateHash).toBe(c.candidateHash);
    expect(typeof plan.planHash).toBe("string");
    expect(plan.planHash.length).toBe(64);
  });

  it("replay plan explicitly declares isFullDeterministicReplay=false (no overclaim)", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);

    expect(plan.isFullDeterministicReplay).toBe(false);
    expect(plan.caveats.length).toBeGreaterThan(0);
    expect(plan.caveats.some((cv) => cv.includes("ADVISORY ONLY"))).toBe(true);
  });

  it("replay plan includes setup, checkout, verb, file-verify, diff, and test steps", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);

    const kinds = plan.steps.map((s) => s.kind);
    expect(kinds).toContain("setup_environment");
    expect(kinds).toContain("checkout_base");
    expect(kinds).toContain("apply_verb_sequence");
    expect(kinds).toContain("verify_file_hashes");
    expect(kinds).toContain("apply_diff");
    expect(kinds).toContain("run_tests");
  });

  it("replay plan is deterministic — planHash is stable across calls", () => {
    const c = buildCandidate();
    const plan1 = generateReplayPlan(c);
    const plan2 = generateReplayPlan(c);

    expect(plan1.planHash).toBe(plan2.planHash);
    expect(plan1.steps.length).toBe(plan2.steps.length);
  });

  it("replay plan steps are indexed sequentially from 0", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);

    plan.steps.forEach((step, idx) => {
      expect(step.stepIndex).toBe(idx);
    });
  });

  it("replay plan serializes to valid JSON and round-trips", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);
    const serialized = JSON.stringify(plan);
    const parsed = JSON.parse(serialized) as typeof plan;

    expect(parsed.schemaVersion).toBe(REPLAY_PLAN_SCHEMA_VERSION);
    expect(parsed.planHash).toBe(plan.planHash);
    expect(parsed.candidateId).toBe(plan.candidateId);
    expect(parsed.steps.length).toBe(plan.steps.length);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. COMPARISON TESTS
// ─────────────────────────────────────────────────────────────────────────────
describe("15D — Evidence Engine: Comparison Tests", () => {
  it("identical candidates produce areIdentical=true with no changed fields", () => {
    const c = buildCandidate();
    const cmp = compareCandidates(c, c);

    expect(cmp.schemaVersion).toBe(CANDIDATE_COMPARISON_SCHEMA_VERSION);
    expect(cmp.areIdentical).toBe(true);
    expect(cmp.riskEscalated).toBe(false);
    const changed = cmp.fieldDiffs.filter((d) => d.kind === "changed");
    expect(changed).toHaveLength(0);
  });

  it("candidates with different goals produce changed field diff", () => {
    const cA = buildCandidate({ goal: "Goal A" });
    const cB = buildCandidate({ goal: "Goal B — different" });
    const cmp = compareCandidates(cA, cB);

    expect(cmp.areIdentical).toBe(false);
    const goalDiff = cmp.fieldDiffs.find((d) => d.field === "goal");
    expect(goalDiff?.kind).toBe("changed");
    expect(goalDiff?.valueA).toBe("Goal A");
    expect(goalDiff?.valueB).toBe("Goal B — different");
  });

  it("detects risk escalation between candidates", () => {
    const cA = buildCandidate({
      risk: { level: "low", rationale: "Simple change", requiresHumanApproval: false },
    });
    const cB = buildCandidate({
      risk: { level: "critical", rationale: "Privilege escalation risk", requiresHumanApproval: true },
    });
    const cmp = compareCandidates(cA, cB);

    expect(cmp.riskLevelA).toBe("low");
    expect(cmp.riskLevelB).toBe("critical");
    expect(cmp.riskEscalated).toBe(true);
  });

  it("detects added and removed files between candidates", () => {
    const cA = buildCandidate();
    const cB = buildCandidate({
      files: [
        {
          relativePath: "src/newfile.ts",
          kind: "added",
          previousHash: ZERO_HASH,
          newHash: FAKE_HASH_B,
          byteDelta: 100,
        },
      ],
      diff: {
        diffHash: FAKE_HASH_B,
        additions: 5,
        deletions: 0,
        filesChanged: 1,
        diffAvailable: true,
        unifiedDiff: "+// new\n",
      },
    });
    const cmp = compareCandidates(cA, cB);

    expect(cmp.areIdentical).toBe(false);
    const added = cmp.fileDiffs.filter((f) => f.kind === "added");
    const removed = cmp.fileDiffs.filter((f) => f.kind === "removed");
    expect(added.length).toBeGreaterThan(0);
    expect(removed.length).toBeGreaterThan(0);
  });

  it("comparison stats reflect correct file/test counts per candidate", () => {
    const c = buildCandidate();
    const cmp = compareCandidates(c, c);

    expect(cmp.statsA.totalFiles).toBe(2);
    expect(cmp.statsA.additions).toBe(150);
    expect(cmp.statsA.deletions).toBe(10);
    expect(cmp.statsA.totalTests).toBe(329);
    expect(cmp.statsA.passedTests).toBe(329);
    expect(cmp.statsB.totalFiles).toBe(cmp.statsA.totalFiles);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. ROLLBACK PLAN
// ─────────────────────────────────────────────────────────────────────────────
describe("15D — Evidence Engine: Rollback Plan", () => {
  it("generateRollbackPlan returns correct schema version and candidate linkage", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);

    expect(plan.schemaVersion).toBe(ROLLBACK_PLAN_SCHEMA_VERSION);
    expect(plan.candidateId).toBe(c.candidateId);
    expect(plan.candidateHash).toBe(c.candidateHash);
    expect(plan.planHash.length).toBe(64);
  });

  it("rollback plan explicitly declares isExecutionPlan=false and requiresHumanApproval=true (no overclaim)", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);

    expect(plan.isExecutionPlan).toBe(false);
    expect(plan.requiresHumanApproval).toBe(true);
    expect(plan.caveats.some((cv) => cv.includes("ADVISORY ONLY"))).toBe(true);
    expect(plan.caveats.some((cv) => cv.includes("human approval"))).toBe(true);
  });

  it("rollback plan produces revert steps for each changed file", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);

    const revertSteps = plan.steps.filter(
      (s) => s.kind === "revert_file" || s.kind === "restore_previous_hash"
    );
    expect(revertSteps.length).toBe(c.files.length);
    expect(plan.totalFilesToRevert).toBe(c.files.length);
  });

  it("rollback plan always includes a run_tests and human_verify step", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);

    const kinds = plan.steps.map((s) => s.kind);
    expect(kinds).toContain("run_tests");
    expect(kinds).toContain("human_verify");
  });

  it("rollback plan for added file describes deletion, not restoration", () => {
    const c = buildCandidate({
      files: [
        {
          relativePath: "src/new-feature.ts",
          kind: "added",
          previousHash: ZERO_HASH,
          newHash: FAKE_HASH_A,
          byteDelta: 500,
        },
      ],
      diff: {
        diffHash: FAKE_HASH_A,
        additions: 20,
        deletions: 0,
        filesChanged: 1,
        diffAvailable: true,
        unifiedDiff: "+// new feature\n",
      },
    });
    const plan = generateRollbackPlan(c);

    const revertStep = plan.steps.find((s) => s.relativePath === "src/new-feature.ts");
    expect(revertStep).toBeDefined();
    expect(revertStep!.description.toLowerCase()).toContain("delete");
    expect(revertStep!.previousHash).toBe(ZERO_HASH);
  });

  it("rollback planHash is deterministic across multiple calls", () => {
    const c = buildCandidate();
    const plan1 = generateRollbackPlan(c);
    const plan2 = generateRollbackPlan(c);

    expect(plan1.planHash).toBe(plan2.planHash);
    expect(plan1.steps.length).toBe(plan2.steps.length);
  });

  it("rollback plan serializes to valid JSON and round-trips faithfully", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);
    const json = JSON.stringify(plan);
    const parsed = JSON.parse(json) as typeof plan;

    expect(parsed.schemaVersion).toBe(ROLLBACK_PLAN_SCHEMA_VERSION);
    expect(parsed.planHash).toBe(plan.planHash);
    expect(parsed.isExecutionPlan).toBe(false);
    expect(parsed.requiresHumanApproval).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. NO OVERCLAIM
// ─────────────────────────────────────────────────────────────────────────────
describe("15D — Evidence Engine: No Overclaim", () => {
  it("REPLAY_ENGINE_OVERCLAIM_GUARD confirms this is not a full deterministic replay system", () => {
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isFullDeterministicReplay).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isAutoRollbackEngine).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isCommitHistoryRewrite).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isLiveFileSystemMutation).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isExecutionAuthority).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isAdvisoryOnly).toBe(true);
  });

  it("replay plan caveats include advisory-only and determinism disclaimers", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);

    const cvText = plan.caveats.join(" ");
    expect(cvText).toContain("ADVISORY ONLY");
    expect(cvText).toContain("NOT guaranteed");
    expect(cvText).toContain("human approval");
  });

  it("rollback plan caveats include advisory-only and no-auto-execution disclaimers", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);

    const cvText = plan.caveats.join(" ");
    expect(cvText).toContain("ADVISORY ONLY");
    expect(cvText).toContain("filesystem operations");
    expect(cvText).toContain("human approval");
    expect(cvText).toContain("NOT an automatic git revert");
  });

  it("explainCandidate does not mutate the candidate (immutable input check)", () => {
    const c = buildCandidate();
    const hashBefore = c.candidateHash;
    explainCandidate(c);
    expect(c.candidateHash).toBe(hashBefore);
    expect(c.files.length).toBe(2);
  });
});
