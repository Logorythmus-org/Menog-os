import { describe, it, expect } from "vitest";
import {
  CommitApprovalWorkflow,
  CommitCandidateBuilder,
  DEFAULT_APPROVAL_TTL_MS,
  CRITICAL_APPROVAL_TTL_MS,
  type CommitCandidate,
  type CommitCandidateInput,
  type HumanApprovalDecision,
} from "@menog/commit-engine";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const ZERO_HASH = "0".repeat(64);
const FAKE_HASH = "a".repeat(64);
const AGENT_AUTHOR: Actor = { type: "agent", id: "autonomous-builder" };
const HUMAN_REVIEWER_1: Actor = { type: "human", id: "lead-dev-alice" };
const HUMAN_REVIEWER_2: Actor = { type: "human", id: "sec-engineer-bob" };
const AGENT_APPROVER: Actor = { type: "agent", id: "ai-reviewer-bot" };

function buildCandidate(overrides: Partial<CommitCandidateInput> = {}): CommitCandidate {
  const input: CommitCandidateInput = {
    candidateId: "cand-" + Math.random().toString(36).slice(2, 10),
    createdAt: new Date().toISOString(),
    agent: AGENT_AUTHOR,
    goal: "Implement critical safety invariants",
    taskId: "task-test-15c",
    verbs: ["modify", "validate"],
    files: [
      {
        relativePath: "src/auth.ts",
        kind: "modified",
        previousHash: ZERO_HASH,
        newHash: FAKE_HASH,
        byteDelta: 120,
      },
    ],
    diff: {
      diffHash: FAKE_HASH,
      additions: 10,
      deletions: 2,
      filesChanged: 1,
      diffAvailable: true,
      unifiedDiff: "--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1,2 +1,10 @@\n",
    },
    tests: {
      testsRun: true,
      totalTests: 10,
      passedTests: 10,
      failedTests: 0,
      reportHash: FAKE_HASH,
    },
    risk: {
      level: "medium",
      rationale: "Standard feature modification with full test coverage",
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
  if (!res.ok || !res.candidate) {
    throw new Error(`buildCandidate failed: ${res.reason}`);
  }
  return res.candidate;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. APPROVAL REQUIRED
// ─────────────────────────────────────────────────────────────────────────────
describe("15C — Commit Approval Workflow: Approval Required", () => {
  it("registered candidate starts in 'pending' state and cannot commit", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    const record = workflow.registerCandidate(candidate);

    expect(record.state).toBe("pending");
    expect(record.approvals).toHaveLength(0);

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("pending");
    expect(check.reason).toContain("approval_required");
  });

  it("rejects non-human actors attempting to approve candidate (fails closed)", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    const agentDecision: HumanApprovalDecision = {
      approvalId: "appr-bot-01",
      approver: AGENT_APPROVER,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    };

    expect(() => workflow.approve(candidate.candidateId, agentDecision)).toThrow(
      /human_actor_required/
    );

    // Verify candidate is still pending and cannot commit
    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("pending");
  });

  it("transitions to 'approved' when human approves and allows commit", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    const humanDecision: HumanApprovalDecision = {
      approvalId: "appr-alice-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
      reason: "Changes reviewed and tested thoroughly",
    };

    const record = workflow.approve(candidate.candidateId, humanDecision);
    expect(record.state).toBe("approved");
    expect(record.approvals).toHaveLength(1);
    expect(record.approvals[0]!.approver.id).toBe(HUMAN_REVIEWER_1.id);

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(true);
    expect(check.state).toBe("approved");
  });

  it("rejected candidate transitions to 'rejected' and cannot commit", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    const record = workflow.reject(
      candidate.candidateId,
      HUMAN_REVIEWER_1,
      "Security flaws identified in diff"
    );
    expect(record.state).toBe("rejected");

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("rejected");
    expect(check.reason).toContain("candidate_rejected");

    // Cannot approve a rejected candidate
    expect(() =>
      workflow.approve(candidate.candidateId, {
        approvalId: "appr-02",
        approver: HUMAN_REVIEWER_1,
        outcome: "approved",
        timestamp: new Date().toISOString(),
      })
    ).toThrow(/cannot_approve_rejected_candidate/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. REVOCATION
// ─────────────────────────────────────────────────────────────────────────────
describe("15C — Commit Approval Workflow: Revocation", () => {
  it("human reviewer can revoke a previously approved candidate", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });

    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);

    // Revoke approval
    const record = workflow.revoke(
      candidate.candidateId,
      HUMAN_REVIEWER_2,
      "New vulnerability discovered post-approval"
    );

    expect(record.state).toBe("revoked");
    expect(record.transitionReason).toContain("New vulnerability");

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("revoked");
    expect(check.reason).toContain("approval_revoked");
  });

  it("rejects non-human actors attempting to revoke approval", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });

    expect(() =>
      workflow.revoke(candidate.candidateId, AGENT_APPROVER, "Agent auto-revoke")
    ).toThrow(/human_actor_required/);

    // Still approved
    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. STALE CANDIDATE INVALIDATION
// ─────────────────────────────────────────────────────────────────────────────
describe("15C — Commit Approval Workflow: Stale Candidate Invalidation", () => {
  it("checkFreshness detects workspace drift and invalidates candidate as stale", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });

    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);

    // Simulate workspace drift: file hash has changed on disk
    const driftedHashes = {
      "src/auth.ts": "b".repeat(64), // drifted hash
    };

    const isFresh = workflow.checkFreshness(candidate.candidateId, driftedHashes);
    expect(isFresh).toBe(false);

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("stale");
    expect(check.reason).toContain("workspace_drift_detected");
  });

  it("checkFreshness returns true when file hashes match", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    const matchingHashes = {
      "src/auth.ts": FAKE_HASH,
    };

    const isFresh = workflow.checkFreshness(candidate.candidateId, matchingHashes);
    expect(isFresh).toBe(true);
  });

  it("manual invalidate marks candidate as stale and blocks commit", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });

    workflow.invalidate(candidate.candidateId, "git_rebase_detected");

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("stale");
    expect(check.reason).toContain("git_rebase_detected");
  });

  it("TTL expiration automatically transitions candidate to stale", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();

    // Register with 1ms TTL
    workflow.registerCandidate(candidate, { ttlMs: 1 });

    // Sleep 10ms to let it expire
    const start = Date.now();
    while (Date.now() - start < 10) { /* busy wait */ }

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("stale");
    expect(check.reason).toContain("approval_ttl_expired");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. RISK ESCALATION & CRITICAL APPROVAL
// ─────────────────────────────────────────────────────────────────────────────
describe("15C — Commit Approval Workflow: Risk Escalation & Critical Approval", () => {
  it("escalating risk revokes existing approved state and requires re-approval", () => {
    const candidate = buildCandidate();
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });

    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);

    // Escalate risk from medium to critical
    const record = workflow.escalate(
      candidate.candidateId,
      "critical",
      HUMAN_REVIEWER_2,
      "Vulnerability analysis indicates privilege escalation potential"
    );

    expect(record.state).toBe("escalated");
    expect(record.riskLevel).toBe("critical");
    expect(record.approvals).toHaveLength(0); // cleared

    const check = workflow.canCommit(candidate.candidateId);
    expect(check.canCommit).toBe(false);
    expect(check.state).toBe("escalated");
    expect(check.reason).toContain("risk_escalated_reapproval_required");
  });

  it("cannot de-escalate risk via escalate()", () => {
    const candidate = buildCandidate({
      risk: {
        level: "critical",
        rationale: "Touches core crypto",
        requiresHumanApproval: true,
      },
    });
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate);

    expect(() =>
      workflow.escalate(candidate.candidateId, "low", HUMAN_REVIEWER_1, "attempt de-escalate")
    ).toThrow(/invalid_escalation/);
  });

  it("critical risk requires explicit criticalRiskAcknowledged: true", () => {
    const candidate = buildCandidate({
      risk: {
        level: "critical",
        rationale: "Alters root access policy",
        requiresHumanApproval: true,
      },
    });
    const workflow = new CommitApprovalWorkflow();
    workflow.registerCandidate(candidate, { twoPersonRule: false });

    // Approval without criticalRiskAcknowledged must fail
    expect(() =>
      workflow.approve(candidate.candidateId, {
        approvalId: "appr-01",
        approver: HUMAN_REVIEWER_1,
        outcome: "approved",
        timestamp: new Date().toISOString(),
      })
    ).toThrow(/critical_risk_acknowledgment_required/);

    // Approval WITH criticalRiskAcknowledged succeeds
    const record = workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
      criticalRiskAcknowledged: true,
    });

    expect(record.state).toBe("approved");
    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);
  });

  it("two-person rule requires two distinct human approvals for critical candidates", () => {
    const candidate = buildCandidate({
      risk: {
        level: "critical",
        rationale: "Core kernel boundary modification",
        requiresHumanApproval: true,
      },
    });
    const workflow = new CommitApprovalWorkflow();
    // Default for critical is twoPersonRule: true
    workflow.registerCandidate(candidate);

    // 1. First approval
    const r1 = workflow.approve(candidate.candidateId, {
      approvalId: "appr-01",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
      criticalRiskAcknowledged: true,
    });

    expect(r1.state).toBe("pending");
    expect(r1.approvals).toHaveLength(1);
    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(false);
    expect(workflow.canCommit(candidate.candidateId).requiredApprovalsRemaining).toBe(1);

    // 2. Same approver cannot approve second time
    expect(() =>
      workflow.approve(candidate.candidateId, {
        approvalId: "appr-02",
        approver: HUMAN_REVIEWER_1, // same approver!
        outcome: "approved",
        timestamp: new Date().toISOString(),
        criticalRiskAcknowledged: true,
      })
    ).toThrow(/two_person_rule_violation/);

    // 3. Second distinct human approver approves
    const r2 = workflow.approve(candidate.candidateId, {
      approvalId: "appr-02",
      approver: HUMAN_REVIEWER_2, // distinct approver!
      outcome: "approved",
      timestamp: new Date().toISOString(),
      criticalRiskAcknowledged: true,
    });

    expect(r2.state).toBe("approved");
    expect(r2.approvals).toHaveLength(2);
    expect(workflow.canCommit(candidate.candidateId).canCommit).toBe(true);
  });

  it("default TTL for critical risk is 30 minutes, 24 hours for non-critical", () => {
    expect(CRITICAL_APPROVAL_TTL_MS).toBe(30 * 60 * 1000);
    expect(DEFAULT_APPROVAL_TTL_MS).toBe(24 * 60 * 60 * 1000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. AUDIT TRAIL (EVENT LEDGER LINKAGE)
// ─────────────────────────────────────────────────────────────────────────────
describe("15C — Commit Approval Workflow: Audit Trail", () => {
  it("emits immutable events for every state transition and verifies hash chain", () => {
    const candidate = buildCandidate();
    const ledger = AppendOnlyLedger.inMemory();
    const workflow = new CommitApprovalWorkflow({ ledger });

    // 1. Register
    workflow.registerCandidate(candidate);
    expect(ledger.length).toBe(1);
    expect(ledger.events()[0]!.eventType).toBe("commit_candidate_registered");

    // 2. Approve
    workflow.approve(candidate.candidateId, {
      approvalId: "appr-alice",
      approver: HUMAN_REVIEWER_1,
      outcome: "approved",
      timestamp: new Date().toISOString(),
    });
    expect(ledger.length).toBe(2);
    expect(ledger.events()[1]!.eventType).toBe("commit_candidate_approved");

    // 3. Revoke
    workflow.revoke(candidate.candidateId, HUMAN_REVIEWER_2, "Audit triggered revocation");
    expect(ledger.length).toBe(3);
    expect(ledger.events()[2]!.eventType).toBe("commit_candidate_revoked");

    // 4. Invalidate
    workflow.invalidate(candidate.candidateId, "Manual invalidation");
    expect(ledger.length).toBe(4);
    expect(ledger.events()[3]!.eventType).toBe("commit_candidate_invalidated");

    // Verify cryptographic hash chain
    const verify = ledger.verify();
    expect(verify.ok).toBe(true);
    expect(verify.verifiedCount).toBe(4);

    const events = ledger.events();
    expect(events[0]!.previousHash).toMatch(/^0{64}$/);
    expect(events[1]!.previousHash).toBe(events[0]!.hash);
    expect(events[2]!.previousHash).toBe(events[1]!.hash);
    expect(events[3]!.previousHash).toBe(events[2]!.hash);
  });
});
