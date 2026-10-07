/**
 * 15A — CommitCandidate Model Tests
 *
 * Five required categories:
 *   1. Schema validation (structural invariants, schemaVersion, risk level enum)
 *   2. Evidence completeness (all required fields present; missing-field rejection)
 *   3. Canonical serialization (determinism, key ordering, stability)
 *   4. Missing-field rejection (each required top-level field absent)
 *   5. Ledger linkage (commit_candidate_created event, hash chain, no event on failure)
 */
import { describe, it, expect } from "vitest";
import {
  CommitCandidateBuilder,
  canonicalSerialize,
  canonicalHash,
  newCandidateId,
  COMMIT_CANDIDATE_SCHEMA_VERSION,
  COMMIT_RISK_LEVELS,
  type CommitCandidateInput,
} from "@menog/commit-engine";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

// ─────────────────────────────────────────────────────────────────────────────
// Shared fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

const ZERO_HASH = "0".repeat(64);
const FAKE_HASH = "a".repeat(64);
const AGENT: Actor = { type: "agent", id: "test-agent-15a" };

function makeInput(overrides: Partial<CommitCandidateInput> = {}): CommitCandidateInput {
  return {
    candidateId: "cand-test-001",
    createdAt: "2026-09-21T12:00:00.000Z",
    agent: AGENT,
    goal: "Implement CommitCandidate runtime evidence model",
    taskId: "task-15a-001",
    verbs: ["inspect", "modify"],
    files: [
      {
        relativePath: "packages/commit-engine/src/types.ts",
        kind: "added",
        previousHash: ZERO_HASH,
        newHash: FAKE_HASH,
        byteDelta: 2048,
      },
    ],
    diff: {
      diffHash: FAKE_HASH,
      additions: 80,
      deletions: 0,
      filesChanged: 1,
      diffAvailable: true,
      unifiedDiff: "--- /dev/null\n+++ b/types.ts\n@@ -0,0 +1,80 @@\n+// types\n",
    },
    tests: {
      testsRun: true,
      totalTests: 245,
      passedTests: 245,
      failedTests: 0,
      reportHash: FAKE_HASH,
    },
    risk: {
      level: "low",
      rationale: "New package with no side effects; all tests pass",
      requiresHumanApproval: false,
    },
    approvals: [],
    environment: {
      nodeVersion: "v22.0.0",
      pnpmVersion: "10.11.1",
      platform: "win32",
      workspaceRoot: "C:/workspace/menog-repo",
    },
    ledgerEventIds: [],
    previousCandidateHash: ZERO_HASH,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SCHEMA VALIDATION
// ─────────────────────────────────────────────────────────────────────────────

describe("15A — CommitCandidate: schema validation", () => {
  it("schemaVersion is always 'menog-commit-candidate/v0' on a built candidate", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    expect(result.candidate!.schemaVersion).toBe(COMMIT_CANDIDATE_SCHEMA_VERSION);
    expect(result.candidate!.schemaVersion).toBe("menog-commit-candidate/v0");
  });

  it("COMMIT_CANDIDATE_SCHEMA_VERSION constant is the frozen string literal", () => {
    expect(COMMIT_CANDIDATE_SCHEMA_VERSION).toBe("menog-commit-candidate/v0");
  });

  it("COMMIT_RISK_LEVELS contains all five levels in correct order", () => {
    expect(COMMIT_RISK_LEVELS).toEqual(["none", "low", "medium", "high", "critical"]);
  });

  it("built candidate has all required fields with correct types", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    const c = result.candidate!;
    expect(typeof c.schemaVersion).toBe("string");
    expect(typeof c.candidateId).toBe("string");
    expect(typeof c.createdAt).toBe("string");
    expect(typeof c.agent).toBe("object");
    expect(typeof c.goal).toBe("string");
    expect(typeof c.taskId).toBe("string");
    expect(Array.isArray(c.verbs)).toBe(true);
    expect(Array.isArray(c.files)).toBe(true);
    expect(typeof c.diff).toBe("object");
    expect(typeof c.tests).toBe("object");
    expect(typeof c.risk).toBe("object");
    expect(Array.isArray(c.approvals)).toBe(true);
    expect(typeof c.environment).toBe("object");
    expect(Array.isArray(c.ledgerEventIds)).toBe(true);
    expect(typeof c.previousCandidateHash).toBe("string");
    expect(typeof c.candidateHash).toBe("string");
  });

  it("built candidate is deeply frozen (Object.isFrozen)", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    const c = result.candidate!;
    expect(Object.isFrozen(c)).toBe(true);
    expect(Object.isFrozen(c.agent)).toBe(true);
    expect(Object.isFrozen(c.diff)).toBe(true);
    expect(Object.isFrozen(c.tests)).toBe(true);
    expect(Object.isFrozen(c.risk)).toBe(true);
    expect(Object.isFrozen(c.environment)).toBe(true);
    expect(Object.isFrozen(c.verbs)).toBe(true);
    expect(Object.isFrozen(c.files)).toBe(true);
    expect(Object.isFrozen(c.approvals)).toBe(true);
    expect(Object.isFrozen(c.ledgerEventIds)).toBe(true);
  });

  it("risk.level must be one of COMMIT_RISK_LEVELS; invalid level rejected", () => {
    const builder = new CommitCandidateBuilder();
    const bad = makeInput({
      risk: { level: "extreme" as "critical", rationale: "r", requiresHumanApproval: true },
    });
    const result = builder.build(bad);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("risk.level");
  });

  it("high risk requires requiresHumanApproval=true; false is rejected", () => {
    const builder = new CommitCandidateBuilder();
    const highNoApproval = makeInput({
      risk: { level: "high", rationale: "risky", requiresHumanApproval: false },
    });
    const result = builder.build(highNoApproval);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("high");
    expect(result.reason).toContain("requiresHumanApproval");
  });

  it("critical risk requires requiresHumanApproval=true; false is rejected", () => {
    const builder = new CommitCandidateBuilder();
    const criticalNoApproval = makeInput({
      risk: { level: "critical", rationale: "very risky", requiresHumanApproval: false },
    });
    const result = builder.build(criticalNoApproval);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("critical");
  });

  it("high risk with requiresHumanApproval=true is accepted", () => {
    const builder = new CommitCandidateBuilder();
    const highApproved = makeInput({
      risk: { level: "high", rationale: "risky change", requiresHumanApproval: true },
    });
    const result = builder.build(highApproved);
    expect(result.ok).toBe(true);
    expect(result.candidate!.risk.level).toBe("high");
    expect(result.candidate!.risk.requiresHumanApproval).toBe(true);
  });

  it("CommitFileChange with backslash path is rejected", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({
      files: [{ relativePath: "src\\bad.ts", kind: "added", previousHash: ZERO_HASH, newHash: FAKE_HASH, byteDelta: 10 }],
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("forward slashes");
  });

  it("passedTests + failedTests exceeding totalTests is rejected", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({
      tests: { testsRun: true, totalTests: 10, passedTests: 8, failedTests: 5, reportHash: FAKE_HASH },
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("passedTests");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. EVIDENCE COMPLETENESS
// ─────────────────────────────────────────────────────────────────────────────

describe("15A — CommitCandidate: evidence completeness", () => {
  it("complete input with all fields builds successfully", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    expect(result.candidate).toBeDefined();
  });

  it("approvals array may be empty (no approval required for low risk)", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({ approvals: [] }));
    expect(result.ok).toBe(true);
    expect(result.candidate!.approvals).toHaveLength(0);
  });

  it("ledgerEventIds may be empty", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({ ledgerEventIds: [] }));
    expect(result.ok).toBe(true);
    expect(result.candidate!.ledgerEventIds).toHaveLength(0);
  });

  it("ledgerEventIds with populated IDs are preserved", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({ ledgerEventIds: ["evt-001", "evt-002"] }));
    expect(result.ok).toBe(true);
    expect(result.candidate!.ledgerEventIds).toEqual(["evt-001", "evt-002"]);
  });

  it("candidate with multiple files, verbs, and an approval record is fully preserved", () => {
    const builder = new CommitCandidateBuilder();
    const input = makeInput({
      verbs: ["inspect", "modify", "validate"],
      files: [
        { relativePath: "src/a.ts", kind: "added", previousHash: ZERO_HASH, newHash: FAKE_HASH, byteDelta: 100 },
        { relativePath: "src/b.ts", kind: "modified", previousHash: FAKE_HASH, newHash: "b".repeat(64), byteDelta: -20 },
      ],
      approvals: [
        {
          approvalId: "appr-001",
          approver: { type: "human", id: "operator-0" },
          outcome: "approved",
          timestamp: "2026-09-21T13:00:00.000Z",
          reason: "LGTM",
        },
      ],
    });
    const result = builder.build(input);
    expect(result.ok).toBe(true);
    const c = result.candidate!;
    expect(c.verbs).toHaveLength(3);
    expect(c.files).toHaveLength(2);
    expect(c.approvals).toHaveLength(1);
    expect(c.approvals[0]!.approvalId).toBe("appr-001");
    expect(c.approvals[0]!.outcome).toBe("approved");
  });

  it("environment fields are fully preserved in output", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    const env = result.candidate!.environment;
    expect(env.nodeVersion).toBe("v22.0.0");
    expect(env.pnpmVersion).toBe("10.11.1");
    expect(env.platform).toBe("win32");
    expect(env.workspaceRoot).toBe("C:/workspace/menog-repo");
  });

  it("diff evidence fields are fully preserved", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    const d = result.candidate!.diff;
    expect(d.diffHash).toBe(FAKE_HASH);
    expect(d.additions).toBe(80);
    expect(d.deletions).toBe(0);
    expect(d.filesChanged).toBe(1);
    expect(d.diffAvailable).toBe(true);
    expect(d.unifiedDiff).toContain("--- /dev/null");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. CANONICAL SERIALIZATION
// ─────────────────────────────────────────────────────────────────────────────

describe("15A — CommitCandidate: canonical serialization", () => {
  it("canonicalSerialize produces identical output for same input on three successive calls", () => {
    const obj = { b: 2, a: 1, c: [3, 1, 2] };
    const s1 = canonicalSerialize(obj);
    const s2 = canonicalSerialize(obj);
    const s3 = canonicalSerialize(obj);
    expect(s1).toBe(s2);
    expect(s2).toBe(s3);
  });

  it("canonicalSerialize sorts object keys alphabetically", () => {
    const result = canonicalSerialize({ z: 1, a: 2, m: 3 });
    // 'a' must appear before 'm' must appear before 'z'
    const posA = result.indexOf('"a"');
    const posM = result.indexOf('"m"');
    const posZ = result.indexOf('"z"');
    expect(posA).toBeLessThan(posM);
    expect(posM).toBeLessThan(posZ);
  });

  it("canonicalSerialize preserves array element order", () => {
    const result = canonicalSerialize([3, 1, 4, 1, 5]);
    expect(result).toBe("[3,1,4,1,5]");
  });

  it("canonicalSerialize handles nested objects with sorted keys at every level", () => {
    const obj = { outer_b: { inner_z: 1, inner_a: 2 }, outer_a: "x" };
    const result = canonicalSerialize(obj);
    // outer_a must come before outer_b; inner_a before inner_z
    expect(result).toBe('{"outer_a":"x","outer_b":{"inner_a":2,"inner_z":1}}');
  });

  it("canonicalSerialize handles null, booleans, numbers, and strings correctly", () => {
    expect(canonicalSerialize(null)).toBe("null");
    expect(canonicalSerialize(true)).toBe("true");
    expect(canonicalSerialize(42)).toBe("42");
    expect(canonicalSerialize("hello")).toBe('"hello"');
  });

  it("canonicalHash produces a 64-char lowercase hex string", () => {
    const hash = canonicalHash({ x: 1 });
    expect(typeof hash).toBe("string");
    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  it("same candidate input always produces identical candidateHash", () => {
    const builder = new CommitCandidateBuilder();
    const input = makeInput({ candidateId: "deterministic-001" });
    const r1 = builder.build(input);
    const r2 = builder.build(input);
    const r3 = builder.build(input);
    expect(r1.ok).toBe(true);
    expect(r1.candidate!.candidateHash).toBe(r2.candidate!.candidateHash);
    expect(r2.candidate!.candidateHash).toBe(r3.candidate!.candidateHash);
  });

  it("different candidateId produces different candidateHash", () => {
    const builder = new CommitCandidateBuilder();
    const r1 = builder.build(makeInput({ candidateId: "id-aaa" }));
    const r2 = builder.build(makeInput({ candidateId: "id-bbb" }));
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r1.candidate!.candidateHash).not.toBe(r2.candidate!.candidateHash);
  });

  it("candidateHash changes when goal changes", () => {
    const builder = new CommitCandidateBuilder();
    const r1 = builder.build(makeInput({ goal: "goal A" }));
    const r2 = builder.build(makeInput({ goal: "goal B" }));
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r1.candidate!.candidateHash).not.toBe(r2.candidate!.candidateHash);
  });

  it("candidateHash is a 64-char lowercase hex string", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    const hash = result.candidate!.candidateHash;
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  it("newCandidateId generates a unique non-empty string each call", () => {
    const id1 = newCandidateId();
    const id2 = newCandidateId();
    const id3 = newCandidateId();
    expect(typeof id1).toBe("string");
    expect(id1.length).toBeGreaterThan(0);
    expect(id1).not.toBe(id2);
    expect(id2).not.toBe(id3);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. MISSING-FIELD REJECTION
// ─────────────────────────────────────────────────────────────────────────────

describe("15A — CommitCandidate: missing-field rejection", () => {
  it("missing candidateId (empty string) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ candidateId: "" }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("candidateId");
  });

  it("missing goal (empty string) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ goal: "" }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("goal");
  });

  it("missing taskId (empty string) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ taskId: "" }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("taskId");
  });

  it("empty verbs array is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ verbs: [] }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("verbs");
  });

  it("empty files array is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ files: [] }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("files");
  });

  it("invalid createdAt (not ISO-8601) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ createdAt: "not-a-date" }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("createdAt");
  });

  it("agent without id is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      agent: { type: "agent", id: "" },
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("agent.id");
  });

  it("missing risk.rationale (empty string) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      risk: { level: "low", rationale: "", requiresHumanApproval: false },
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("risk.rationale");
  });

  it("invalid previousCandidateHash (wrong length) is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      previousCandidateHash: "abc123",
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("previousCandidateHash");
  });

  it("invalid approval timestamp is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      approvals: [{
        approvalId: "appr-bad",
        approver: { type: "human", id: "op" },
        outcome: "approved",
        timestamp: "not-a-timestamp",
      }],
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("timestamp");
  });

  it("invalid approval outcome is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      approvals: [{
        approvalId: "appr-bad",
        approver: { type: "human", id: "op" },
        outcome: "maybe" as "approved",
        timestamp: "2026-09-21T12:00:00.000Z",
      }],
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("outcome");
  });

  it("empty environment.nodeVersion is rejected", () => {
    const result = new CommitCandidateBuilder().build(makeInput({
      environment: { nodeVersion: "", pnpmVersion: "10.0.0", platform: "linux", workspaceRoot: "/ws" },
    }));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("environment.nodeVersion");
  });

  it("ok=false result does not have a candidate field", () => {
    const result = new CommitCandidateBuilder().build(makeInput({ goal: "" }));
    expect(result.ok).toBe(false);
    expect(result.candidate).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. LEDGER LINKAGE
// ─────────────────────────────────────────────────────────────────────────────

describe("15A — CommitCandidate: ledger linkage", () => {
  it("successful build with ledger emits exactly one commit_candidate_created event", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    const result = builder.build(makeInput());

    expect(result.ok).toBe(true);
    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("commit_candidate_created");
  });

  it("ledger event has policyDecision=not_applicable (no git write)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    builder.build(makeInput());
    expect(ledger.events()[0]!.policyDecision).toBe("not_applicable");
  });

  it("ledger event actor matches input agent", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    builder.build(makeInput({ agent: { type: "human", id: "operator-007" } }));
    const ev = ledger.events()[0]!;
    expect(ev.actor.type).toBe("human");
    expect(ev.actor.id).toBe("operator-007");
  });

  it("ledger event verb is 'commit' and capability is 'git:commit'", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    builder.build(makeInput());
    const ev = ledger.events()[0]!;
    expect(ev.verb).toBe("commit");
    expect(ev.capability).toBe("git:commit");
  });

  it("ledger event resultSummary contains candidateHash matching candidate.candidateHash", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    const ev = ledger.events()[0]!;
    const rs = ev.resultSummary as Record<string, unknown>;
    expect(rs.candidateHash).toBe(result.candidate!.candidateHash);
  });

  it("ledger event resultSummary reflects risk level and human approval requirement", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    builder.build(makeInput({
      risk: { level: "high", rationale: "risky", requiresHumanApproval: true },
    }));
    const rs = ledger.events()[0]!.resultSummary as Record<string, unknown>;
    expect(rs.riskLevel).toBe("high");
    expect(rs.requiresHumanApproval).toBe(true);
  });

  it("build result ledgerEventId matches the event in the ledger", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    expect(result.ledgerEventId).toBeDefined();
    const ev = ledger.events()[0]!;
    expect(ev.eventId).toBe(result.ledgerEventId);
  });

  it("failed build does NOT emit a ledger event", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });
    const result = builder.build(makeInput({ goal: "" }));
    expect(result.ok).toBe(false);
    expect(ledger.length).toBe(0);
  });

  it("multiple sequential builds maintain ledger hash chain integrity", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const builder = new CommitCandidateBuilder({ ledger });

    for (let i = 0; i < 4; i++) {
      builder.build(makeInput({ candidateId: `cand-seq-${i}`, goal: `goal ${i}` }));
    }

    expect(ledger.length).toBe(4);
    expect(ledger.verify().ok).toBe(true);

    const events = ledger.events();
    expect(events[0]!.previousHash).toMatch(/^0{64}$/);
    expect(events[1]!.previousHash).toBe(events[0]!.hash);
    expect(events[2]!.previousHash).toBe(events[1]!.hash);
    expect(events[3]!.previousHash).toBe(events[2]!.hash);
  });

  it("builder without ledger produces no event and result.ledgerEventId is undefined", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput());
    expect(result.ok).toBe(true);
    expect(result.ledgerEventId).toBeUndefined();
  });

  it("previousCandidateHash=zero-hash is valid for the first candidate in a chain", () => {
    const builder = new CommitCandidateBuilder();
    const result = builder.build(makeInput({ previousCandidateHash: ZERO_HASH }));
    expect(result.ok).toBe(true);
    expect(result.candidate!.previousCandidateHash).toBe(ZERO_HASH);
  });

  it("previousCandidateHash set to prior candidateHash chains correctly", () => {
    const builder = new CommitCandidateBuilder();
    const first = builder.build(makeInput({ candidateId: "first", goal: "first goal" }));
    expect(first.ok).toBe(true);

    const second = builder.build(makeInput({
      candidateId: "second",
      goal: "second goal",
      previousCandidateHash: first.candidate!.candidateHash,
    }));
    expect(second.ok).toBe(true);
    expect(second.candidate!.previousCandidateHash).toBe(first.candidate!.candidateHash);
  });
});
