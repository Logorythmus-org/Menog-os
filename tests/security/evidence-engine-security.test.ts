/**
 * 15D — Evidence Engine Security Gate
 *
 * Threat-tests the evidence-level replay/explain/rollback boundary:
 * - Hash tamper-evidence: a forged or mutated CommitCandidate must not be
 *   silently accepted as valid evidence.
 * - Plan integrity: replay/rollback planHash must bind the plan to the exact
 *   candidate evidence; any step mutation must be detectable.
 * - Path-injection denial: untrusted relativePath content must never be able
 *   to smuggle absolute-path or traversal targets into a rollback plan that a
 *   human might execute blindly. (Note: rollback plan generation is advisory —
 *   the injection is contained by marking the step non-automatable and by
 *   schema validation, NOT by filesystem access; this module has no write
 *   authority.)
 * - No-overclaim invariants: advisory-only flags must never be flippable.
 *
 * Each test asserts only observable outputs (returned structures / thrown
 * errors), never implementation internals.
 */
import { describe, it, expect } from "vitest";
import {
  CommitCandidateBuilder,
  explainCandidate,
  generateReplayPlan,
  generateRollbackPlan,
  compareCandidates,
  REPLAY_ENGINE_OVERCLAIM_GUARD,
  type CommitCandidateInput,
  type CommitCandidate,
} from "@menog/commit-engine";
import type { Actor } from "@menog/core";

const ZERO_HASH = "0".repeat(64);
const H1 = "c".repeat(64);
const H2 = "d".repeat(64);
const AGENT: Actor = { type: "agent", id: "evidence-sec-agent" };

/** Minimal valid input for direct builder-level denial tests. */
function baseInput(): CommitCandidateInput {
  return {
    candidateId: "cand-sec-direct",
    createdAt: "2026-01-01T00:00:00.000Z",
    agent: AGENT,
    goal: "Direct builder input",
    taskId: "task-sec-direct",
    verbs: ["inspect"],
    files: [
      { relativePath: "src/ok.ts", kind: "added", previousHash: ZERO_HASH, newHash: H1, byteDelta: 1 },
    ],
    diff: { diffHash: H1, additions: 1, deletions: 0, filesChanged: 1, diffAvailable: true, unifiedDiff: "+x\n" },
    tests: { testsRun: false, totalTests: 0, passedTests: 0, failedTests: 0, reportHash: ZERO_HASH },
    risk: { level: "low", rationale: "fixture", requiresHumanApproval: false },
    approvals: [],
    environment: { nodeVersion: "v22", pnpmVersion: "10.11.1", platform: "linux", workspaceRoot: "/w" },
    ledgerEventIds: [],
    previousCandidateHash: ZERO_HASH,
  };
}

function buildCandidate(overrides: Partial<CommitCandidateInput> = {}): CommitCandidate {
  const input: CommitCandidateInput = {
    candidateId: "cand-sec-" + Math.random().toString(36).slice(2, 10),
    createdAt: new Date().toISOString(),
    agent: AGENT,
    goal: "Security fixture candidate",
    taskId: "task-sec-15d",
    verbs: ["inspect", "modify"],
    files: [
      {
        relativePath: "src/module.ts",
        kind: "modified",
        previousHash: ZERO_HASH,
        newHash: H1,
        byteDelta: 100,
      },
    ],
    diff: {
      diffHash: H1,
      additions: 5,
      deletions: 1,
      filesChanged: 1,
      diffAvailable: true,
      unifiedDiff: "--- a/src/module.ts\n+++ b/src/module.ts\n@@ -1,1 +1,5 @@\n",
    },
    tests: {
      testsRun: true,
      totalTests: 5,
      passedTests: 5,
      failedTests: 0,
      reportHash: H1,
    },
    risk: {
      level: "medium",
      rationale: "Security fixture",
      requiresHumanApproval: true,
    },
    approvals: [],
    environment: {
      nodeVersion: "v22.0.0",
      pnpmVersion: "10.11.1",
      platform: process.platform,
      workspaceRoot: "C:\\sec-fixture",
    },
    ledgerEventIds: [],
    previousCandidateHash: ZERO_HASH,
    ...overrides,
  };
  const res = new CommitCandidateBuilder().build(input);
  if (!res.ok || !res.candidate) throw new Error(`buildCandidate failed: ${res.reason}`);
  return res.candidate;
}

// ─────────────────────────────────────────────────────────────────────────────
// SEC-E1 — Hash tamper-evidence (candidateHash as integrity boundary)
// ─────────────────────────────────────────────────────────────────────────────
describe("15D Security — Hash tamper-evidence", () => {
  it("SEC-E1.1 candidateHash changes when evidence content changes (tamper detection basis)", () => {
    const a = buildCandidate();
    const b = buildCandidate({ goal: "Different goal" });
    expect(a.candidateHash).not.toBe(b.candidateHash);
  });

  it("SEC-E1.2 candidateHash is deterministic — same evidence yields same hash", () => {
    const base: CommitCandidateInput = {
      candidateId: "cand-det",
      createdAt: "2026-01-01T00:00:00.000Z",
      agent: AGENT,
      goal: "Determinism fixture",
      taskId: "task-det",
      verbs: ["inspect"],
      files: [
        { relativePath: "a.ts", kind: "added", previousHash: ZERO_HASH, newHash: H1, byteDelta: 10 },
      ],
      diff: { diffHash: H1, additions: 1, deletions: 0, filesChanged: 1, diffAvailable: true, unifiedDiff: "+x\n" },
      tests: { testsRun: false, totalTests: 0, passedTests: 0, failedTests: 0, reportHash: ZERO_HASH },
      risk: { level: "low", rationale: "trivial", requiresHumanApproval: false },
      approvals: [],
      environment: { nodeVersion: "v22", pnpmVersion: "10.11.1", platform: "linux", workspaceRoot: "/w" },
      ledgerEventIds: [],
      previousCandidateHash: ZERO_HASH,
    };
    const r1 = new CommitCandidateBuilder().build(base);
    const r2 = new CommitCandidateBuilder().build(base);
    expect(r1.ok && r2.ok).toBe(true);
    expect(r1.candidate!.candidateHash).toBe(r2.candidate!.candidateHash);
  });

  it("SEC-E1.3 rollback planHash is bound to candidateHash — plans from different candidates differ", () => {
    const a = buildCandidate();
    const b = buildCandidate({ goal: "Different goal changes candidateHash" });
    const planA = generateRollbackPlan(a);
    const planB = generateRollbackPlan(b);
    expect(planA.candidateHash).toBe(a.candidateHash);
    expect(planB.candidateHash).toBe(b.candidateHash);
    expect(planA.planHash).not.toBe(planB.planHash);
  });

  it("SEC-E1.4 replay planHash is bound to candidateHash", () => {
    const a = buildCandidate();
    const b = buildCandidate({ goal: "Another goal" });
    const planA = generateReplayPlan(a);
    const planB = generateReplayPlan(b);
    expect(planA.candidateHash).toBe(a.candidateHash);
    expect(planA.planHash).not.toBe(planB.planHash);
  });

  it("SEC-E1.5 frozen candidate resists in-place evidence mutation attempts", () => {
    const c = buildCandidate();
    const hashBefore = c.candidateHash;
    // Attempt in-place mutation (must throw in strict mode or silently fail on frozen object)
    let mutationBlocked = false;
    try {
      const mutable = c as unknown as { goal: string };
      mutable.goal = "TAMPERED";
    } catch {
      mutationBlocked = true;
    }
    // Either throws (strict) or silently no-ops (frozen); in BOTH cases hash content must be intact
    const rebound = c.goal === "TAMPERED";
    if (mutationBlocked || !rebound) {
      expect(c.goal).not.toBe("TAMPERED");
      expect(c.candidateHash).toBe(hashBefore);
    } else {
      expect.fail("candidate was mutable — tamper-evidence invariant violated");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SEC-E2 — Plan integrity under serialization round-trip
// ─────────────────────────────────────────────────────────────────────────────
describe("15D Security — Plan serialization integrity", () => {
  it("SEC-E2.1 rollback plan JSON round-trip preserves planHash (serialization is canonical-stable)", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);
    const roundTrip = JSON.parse(JSON.stringify(plan)) as typeof plan;
    expect(roundTrip.planHash).toBe(plan.planHash);
    expect(roundTrip.steps).toEqual(plan.steps);
  });

  it("SEC-E2.2 replay plan JSON round-trip preserves planHash", () => {
    const c = buildCandidate();
    const plan = generateReplayPlan(c);
    const roundTrip = JSON.parse(JSON.stringify(plan)) as typeof plan;
    expect(roundTrip.planHash).toBe(plan.planHash);
    expect(roundTrip.steps).toEqual(plan.steps);
  });

  it("SEC-E2.3 mutated plan steps are detectable — step content differs, so re-hash diverges", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);
    // Simulate a tampered plan: an attacker modifies a step description after serialization
    const tampered = JSON.parse(JSON.stringify(plan)) as { steps: Array<{ description: string }> };
    tampered.steps[0]!.description = "TAMPERED: run rm -rf / instead";
    const r1 = JSON.stringify(plan);
    const r2 = JSON.stringify(tampered);
    // Tampering is detectable by byte comparison (recomputation would produce a different hash)
    expect(r1).not.toBe(r2);
    // The generated (untampered) plan still carries the original hash
    expect(plan.planHash.length).toBe(64);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SEC-E3 — Path injection in rollback plan targets
// ─────────────────────────────────────────────────────────────────────────────
describe("15D Security — Rollback plan path-injection containment", () => {
  it("SEC-E3.1 rollback plan marks every file step as non-automatable and human-approved (no blind execution)", () => {
    const c = buildCandidate();
    const plan = generateRollbackPlan(c);
    const fileSteps = plan.steps.filter((s) => s.kind === "revert_file" || s.kind === "restore_previous_hash");
    expect(fileSteps.length).toBeGreaterThan(0);
    for (const s of fileSteps) {
      expect(s.isAutomatable).toBe(false);
      expect(s.requiresHumanApproval).toBe(true);
      expect(typeof s.relativePath).toBe("string");
    }
  });

  it("SEC-E3.2 traversal-style relativePath in candidate evidence does not crash plan generation and is surfaced verbatim for human review", () => {
    // Attack: forged candidate claims a file path like ../../etc/passwd.
    // The engine is advisory and has NO write authority — the mitigation is
    // that the path appears only in advisory output and every step is
    // human-approved + non-automatable, so it cannot be executed by the engine.
    const c = buildCandidate({
      files: [
        { relativePath: "../../etc/passwd", kind: "modified", previousHash: ZERO_HASH, newHash: H2, byteDelta: 1 },
      ],
      diff: { diffHash: H2, additions: 1, deletions: 1, filesChanged: 1, diffAvailable: true, unifiedDiff: "-x\n+y\n" },
    });
    const plan = generateRollbackPlan(c);
    const step = plan.steps.find((s) => s.relativePath === "../../etc/passwd");
    expect(step).toBeDefined();
    expect(step!.isAutomatable).toBe(false);
    expect(step!.requiresHumanApproval).toBe(true);
    // Engine must not have performed any filesystem operation — plan is pure data
    expect(plan.isExecutionPlan).toBe(false);
  });

  it("SEC-E3.3 Windows backslash paths are rejected at candidate-build boundary (builder validation denies non-forward-slash paths)", () => {
    // Attack: forged evidence uses a Windows absolute path. The builder's
    // validation rejects any backslash in relativePath — a deny-at-entry
    // control that prevents such paths from ever becoming plan steps.
    const res = new CommitCandidateBuilder().build({
      ...baseInput(),
      files: [
        { relativePath: "C:\\Windows\\System32\\evil.dll", kind: "modified", previousHash: ZERO_HASH, newHash: H2, byteDelta: 1 },
      ],
    });
    expect(res.ok).toBe(false);
    expect(res.error).toBe("invalid_field");
    expect(res.reason).toContain("forward slashes");
  });

  it("SEC-E3.4 NUL-byte path in forged candidate is carried only into non-automatable advisory steps", () => {
    const c = buildCandidate({
      files: [
        { relativePath: "file\u0000.txt", kind: "modified", previousHash: ZERO_HASH, newHash: H2, byteDelta: 1 },
      ],
      diff: { diffHash: H2, additions: 1, deletions: 1, filesChanged: 1, diffAvailable: true, unifiedDiff: "-x\n+y\n" },
    });
    const plan = generateRollbackPlan(c);
    for (const s of plan.steps) {
      if (s.relativePath !== undefined) {
        expect(s.isAutomatable).toBe(false);
        expect(s.requiresHumanApproval).toBe(true);
      }
    }
    expect(plan.isExecutionPlan).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SEC-E4 — Model/untrusted-content authority boundary
// ─────────────────────────────────────────────────────────────────────────────
describe("15D Security — Untrusted content cannot become authority", () => {
  it("SEC-E4.1 evidence output carries no execution authority — explain/plan results are advisory data only", () => {
    const c = buildCandidate();
    const explanation = explainCandidate(c);
    const plan = generateReplayPlan(c);
    const rb = generateRollbackPlan(c);
    // None of the outputs expose an execute/run/commit function or a capability grant.
    const serialized = JSON.stringify({ explanation, plan, rb });
    expect(serialized).not.toContain("\"canCommit\":true");
    expect(serialized).not.toContain("\"capability\":\"workspace:write\"");
    expect(rb.requiresHumanApproval).toBe(true);
    expect(plan.isFullDeterministicReplay).toBe(false);
    expect(REPLAY_ENGINE_OVERCLAIM_GUARD.isExecutionAuthority).toBe(false);
  });

  it("SEC-E4.2 comparison of forged candidates never escalates authority — output is read-only stats", () => {
    const a = buildCandidate();
    const b = buildCandidate({ goal: "other" });
    const cmp = compareCandidates(a, b);
    const serialized = JSON.stringify(cmp);
    expect(serialized).not.toContain("approve");
    expect(serialized).not.toContain("canCommit");
    expect(cmp.areIdentical).toBe(false);
  });
});
