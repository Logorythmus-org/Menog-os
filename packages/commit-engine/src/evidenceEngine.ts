import { createHash } from "node:crypto";
import type { CommitCandidate, CommitRiskLevel } from "./types.js";
import { canonicalSerialize } from "./builder.js";

// ─────────────────────────────────────────────────────────────────────────────
// Schema version
// ─────────────────────────────────────────────────────────────────────────────

export const EVIDENCE_EXPLANATION_SCHEMA_VERSION = "menog-evidence-explanation/v0" as const;
export const ROLLBACK_PLAN_SCHEMA_VERSION = "menog-rollback-plan/v0" as const;
export const CANDIDATE_COMPARISON_SCHEMA_VERSION = "menog-candidate-comparison/v0" as const;
export const REPLAY_PLAN_SCHEMA_VERSION = "menog-replay-plan/v0" as const;

// ─────────────────────────────────────────────────────────────────────────────
// Overclaim guard — immutable constant documenting system boundaries
// ─────────────────────────────────────────────────────────────────────────────

/**
 * IMPORTANT: This module provides evidence-level replay/explain/rollback planning.
 * It does NOT provide:
 * - Full deterministic system replay (no execution engine)
 * - Automatic rollback execution (no write authority)
 * - Commit history rewriting (prohibited by architecture invariants)
 * - Live filesystem mutation (read-only evidence analysis)
 *
 * All output is advisory PROPOSAL data. Actual execution requires explicit
 * human approval through CommitApprovalWorkflow.canCommit() = true.
 */
export const REPLAY_ENGINE_OVERCLAIM_GUARD: Readonly<{
  isFullDeterministicReplay: false;
  isAutoRollbackEngine: false;
  isCommitHistoryRewrite: false;
  isLiveFileSystemMutation: false;
  isExecutionAuthority: false;
  isAdvisoryOnly: true;
}> = Object.freeze({
  isFullDeterministicReplay: false,
  isAutoRollbackEngine: false,
  isCommitHistoryRewrite: false,
  isLiveFileSystemMutation: false,
  isExecutionAuthority: false,
  isAdvisoryOnly: true,
});

// ─────────────────────────────────────────────────────────────────────────────
// Explain types
// ─────────────────────────────────────────────────────────────────────────────

export interface EvidenceExplanationSection {
  readonly heading: string;
  readonly content: string;
  readonly kind: "provenance" | "diff" | "risk" | "approval" | "tests" | "environment";
}

export interface EvidenceExplanation {
  readonly schemaVersion: typeof EVIDENCE_EXPLANATION_SCHEMA_VERSION;
  readonly candidateId: string;
  readonly candidateHash: string;
  readonly generatedAt: string;
  readonly sections: readonly EvidenceExplanationSection[];
  readonly isComplete: boolean;
  readonly missingFields: readonly string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay Plan types
// ─────────────────────────────────────────────────────────────────────────────

export type ReplayStepKind =
  | "setup_environment"
  | "checkout_base"
  | "apply_verb_sequence"
  | "apply_diff"
  | "run_tests"
  | "verify_file_hashes";

export interface ReplayStep {
  readonly stepIndex: number;
  readonly kind: ReplayStepKind;
  readonly description: string;
  readonly precondition: string;
  readonly expectedOutcome: string;
  readonly isAutomatable: boolean;
  readonly requiresHumanVerification: boolean;
}

export interface ReplayPlan {
  readonly schemaVersion: typeof REPLAY_PLAN_SCHEMA_VERSION;
  readonly candidateId: string;
  readonly candidateHash: string;
  readonly generatedAt: string;
  readonly planHash: string;
  readonly steps: readonly ReplayStep[];
  readonly isFullDeterministicReplay: false;
  readonly caveats: readonly string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Comparison types
// ─────────────────────────────────────────────────────────────────────────────

export type DiffKind = "added" | "removed" | "changed" | "unchanged";

export interface CandidateFieldDiff {
  readonly field: string;
  readonly kind: DiffKind;
  readonly valueA?: unknown;
  readonly valueB?: unknown;
}

export interface FileDiff {
  readonly path: string;
  readonly kind: DiffKind;
  readonly changeKindA?: string;
  readonly changeKindB?: string;
  readonly byteDeltaDiff?: number;
}

export interface CandidateComparison {
  readonly schemaVersion: typeof CANDIDATE_COMPARISON_SCHEMA_VERSION;
  readonly candidateIdA: string;
  readonly candidateHashA: string;
  readonly candidateIdB: string;
  readonly candidateHashB: string;
  readonly generatedAt: string;
  readonly areIdentical: boolean;
  readonly fieldDiffs: readonly CandidateFieldDiff[];
  readonly fileDiffs: readonly FileDiff[];
  readonly riskLevelA: CommitRiskLevel;
  readonly riskLevelB: CommitRiskLevel;
  readonly riskEscalated: boolean;
  readonly statsA: CandidateStats;
  readonly statsB: CandidateStats;
}

export interface CandidateStats {
  readonly totalFiles: number;
  readonly additions: number;
  readonly deletions: number;
  readonly totalTests: number;
  readonly passedTests: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollback Plan types
// ─────────────────────────────────────────────────────────────────────────────

export type RollbackStepKind =
  | "revert_file"
  | "restore_previous_hash"
  | "run_tests"
  | "human_verify"
  | "noop";

export interface RollbackStep {
  readonly stepIndex: number;
  readonly kind: RollbackStepKind;
  readonly relativePath?: string;
  readonly description: string;
  readonly previousHash: string;
  readonly expectedOutcome: string;
  readonly isAutomatable: boolean;
  readonly requiresHumanApproval: boolean;
}

export interface RollbackPlan {
  readonly schemaVersion: typeof ROLLBACK_PLAN_SCHEMA_VERSION;
  readonly candidateId: string;
  readonly candidateHash: string;
  readonly generatedAt: string;
  readonly planHash: string;
  readonly steps: readonly RollbackStep[];
  readonly isExecutionPlan: false;
  readonly caveats: readonly string[];
  readonly requiresHumanApproval: true;
  readonly totalFilesToRevert: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Explain engine
// ─────────────────────────────────────────────────────────────────────────────

const ZERO_HASH = "0".repeat(64);

function checkField(value: unknown, path: string, missing: string[]): void {
  if (value === undefined || value === null) {
    missing.push(path);
  }
}

/**
 * Produces a structured human-readable explanation of a CommitCandidate's evidence.
 * Read-only, advisory, no side effects.
 */
export function explainCandidate(candidate: CommitCandidate): EvidenceExplanation {
  const now = new Date().toISOString();
  const missing: string[] = [];

  checkField(candidate.candidateId, "candidateId", missing);
  checkField(candidate.goal, "goal", missing);
  checkField(candidate.agent, "agent", missing);
  checkField(candidate.taskId, "taskId", missing);
  checkField(candidate.verbs, "verbs", missing);
  checkField(candidate.files, "files", missing);
  checkField(candidate.diff, "diff", missing);
  checkField(candidate.tests, "tests", missing);
  checkField(candidate.risk, "risk", missing);
  checkField(candidate.environment, "environment", missing);

  if (!Array.isArray(candidate.verbs) || candidate.verbs.length === 0) {
    missing.push("verbs[non-empty]");
  }
  if (!Array.isArray(candidate.files) || candidate.files.length === 0) {
    missing.push("files[non-empty]");
  }

  const sections: EvidenceExplanationSection[] = [];

  // Section 1: Provenance
  sections.push({
    heading: "Provenance",
    kind: "provenance",
    content: [
      `Candidate ID : ${candidate.candidateId}`,
      `Candidate Hash: ${candidate.candidateHash}`,
      `Schema Version: ${candidate.schemaVersion}`,
      `Created At   : ${candidate.createdAt}`,
      `Goal         : ${candidate.goal}`,
      `Task ID      : ${candidate.taskId}`,
      `Agent        : ${candidate.agent?.type ?? "unknown"}:${candidate.agent?.id ?? "unknown"}`,
      `Verbs        : ${(candidate.verbs ?? []).join(", ")}`,
      `Previous Hash: ${candidate.previousCandidateHash ?? ZERO_HASH}`,
      `Ledger Events: ${(candidate.ledgerEventIds ?? []).length} linked event(s)`,
    ].join("\n"),
  });

  // Section 2: Diff summary
  const diff = candidate.diff;
  sections.push({
    heading: "Diff Summary",
    kind: "diff",
    content: diff
      ? [
          `Files Changed : ${diff.filesChanged}`,
          `Additions     : +${diff.additions}`,
          `Deletions     : -${diff.deletions}`,
          `Diff Available: ${diff.diffAvailable}`,
          `Diff Hash     : ${diff.diffHash}`,
          ...(diff.diffAvailable ? ["", "Unified Diff:", "---", diff.unifiedDiff.slice(0, 2000), diff.unifiedDiff.length > 2000 ? "[truncated]" : ""] : ["[diff not available inline]"]),
        ].join("\n")
      : "[diff field missing]",
  });

  // Section 3: File changes
  const fileLines = (candidate.files ?? []).map(
    (f) =>
      `  ${f.kind.padEnd(8)} ${f.relativePath}  prev=${f.previousHash.slice(0, 12)}…  new=${f.newHash.slice(0, 12)}…  Δ${f.byteDelta > 0 ? "+" : ""}${f.byteDelta}B`
  );
  sections.push({
    heading: "File Changes",
    kind: "diff",
    content: fileLines.length > 0 ? fileLines.join("\n") : "[no file changes recorded]",
  });

  // Section 4: Risk
  const risk = candidate.risk;
  sections.push({
    heading: "Risk Assessment",
    kind: "risk",
    content: risk
      ? [
          `Risk Level              : ${risk.level.toUpperCase()}`,
          `Requires Human Approval : ${risk.requiresHumanApproval}`,
          `Rationale               : ${risk.rationale}`,
        ].join("\n")
      : "[risk field missing]",
  });

  // Section 5: Approvals
  const approvalsText = (candidate.approvals ?? []).length === 0
    ? "No approvals recorded."
    : (candidate.approvals ?? []).map(
        (a) => `  [${a.outcome.toUpperCase()}] ${a.approver.type}:${a.approver.id} at ${a.timestamp}${a.reason ? ` — ${a.reason}` : ""}`
      ).join("\n");
  sections.push({
    heading: "Approvals",
    kind: "approval",
    content: approvalsText,
  });

  // Section 6: Test evidence
  const tests = candidate.tests;
  sections.push({
    heading: "Test Evidence",
    kind: "tests",
    content: tests
      ? [
          `Tests Run  : ${tests.testsRun}`,
          `Total Tests: ${tests.totalTests}`,
          `Passed     : ${tests.passedTests}`,
          `Failed     : ${tests.failedTests}`,
          `Report Hash: ${tests.reportHash}`,
        ].join("\n")
      : "[tests field missing]",
  });

  // Section 7: Environment
  const env = candidate.environment;
  sections.push({
    heading: "Environment",
    kind: "environment",
    content: env
      ? [
          `Node.js        : ${env.nodeVersion}`,
          `pnpm           : ${env.pnpmVersion}`,
          `Platform       : ${env.platform}`,
          `Workspace Root : ${env.workspaceRoot}`,
        ].join("\n")
      : "[environment field missing]",
  });

  return Object.freeze({
    schemaVersion: EVIDENCE_EXPLANATION_SCHEMA_VERSION,
    candidateId: candidate.candidateId,
    candidateHash: candidate.candidateHash,
    generatedAt: now,
    sections: Object.freeze(sections.map((s) => Object.freeze(s))),
    isComplete: missing.length === 0,
    missingFields: Object.freeze(missing),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay Plan generator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generates a step-by-step replay PLAN (not execution) for reproducing a commit candidate.
 * This is advisory evidence documentation, NOT an execution engine.
 */
export function generateReplayPlan(candidate: CommitCandidate): ReplayPlan {
  const now = new Date().toISOString();
  const steps: ReplayStep[] = [];
  let idx = 0;

  steps.push({
    stepIndex: idx++,
    kind: "setup_environment",
    description: `Provision identical environment: Node.js ${candidate.environment.nodeVersion}, pnpm ${candidate.environment.pnpmVersion} on ${candidate.environment.platform}`,
    precondition: "Clean workspace at path: " + candidate.environment.workspaceRoot,
    expectedOutcome: "Environment matches snapshot in candidate.environment",
    isAutomatable: false,
    requiresHumanVerification: true,
  });

  steps.push({
    stepIndex: idx++,
    kind: "checkout_base",
    description: `Restore workspace to the state that existed before candidate '${candidate.candidateId}' was applied. Use previousCandidateHash=${candidate.previousCandidateHash} for chain linkage.`,
    precondition: "Previous candidate hash resolvable: " + candidate.previousCandidateHash,
    expectedOutcome: "Workspace matches pre-change state",
    isAutomatable: false,
    requiresHumanVerification: true,
  });

  steps.push({
    stepIndex: idx++,
    kind: "apply_verb_sequence",
    description: `Re-execute verbs in order: [${candidate.verbs.join(", ")}] with goal: "${candidate.goal}"`,
    precondition: "Verb executor available; goal and task context resolvable from taskId=" + candidate.taskId,
    expectedOutcome: "Same verb sequence produces equivalent file mutations (environment-dependent; may not be bit-identical)",
    isAutomatable: false,
    requiresHumanVerification: true,
  });

  for (const file of candidate.files) {
    steps.push({
      stepIndex: idx++,
      kind: "verify_file_hashes",
      description: `Verify file '${file.relativePath}': expected newHash=${file.newHash.slice(0, 16)}…`,
      precondition: `File must exist at workspace path`,
      expectedOutcome: `SHA-256 of '${file.relativePath}' matches newHash=${file.newHash}`,
      isAutomatable: true,
      requiresHumanVerification: false,
    });
  }

  if (candidate.diff.diffAvailable) {
    steps.push({
      stepIndex: idx++,
      kind: "apply_diff",
      description: `Apply unified diff (diffHash=${candidate.diff.diffHash.slice(0, 16)}…) and verify integrity`,
      precondition: "Diff is available and diffHash verifiable",
      expectedOutcome: `Patch applies cleanly; ${candidate.diff.additions} additions, ${candidate.diff.deletions} deletions across ${candidate.diff.filesChanged} file(s)`,
      isAutomatable: false,
      requiresHumanVerification: true,
    });
  }

  if (candidate.tests.testsRun) {
    steps.push({
      stepIndex: idx++,
      kind: "run_tests",
      description: `Run test suite; expected ${candidate.tests.totalTests} tests, ${candidate.tests.passedTests} passing, ${candidate.tests.failedTests} failing`,
      precondition: "Test environment installed and configured",
      expectedOutcome: `Test run matches: total=${candidate.tests.totalTests} passed=${candidate.tests.passedTests} failed=${candidate.tests.failedTests}; reportHash=${candidate.tests.reportHash.slice(0, 16)}…`,
      isAutomatable: true,
      requiresHumanVerification: false,
    });
  }

  const caveats: readonly string[] = Object.freeze([
    "This plan is ADVISORY ONLY. It does NOT execute any operations automatically.",
    "Verb re-execution is NOT guaranteed to produce bit-identical output (environment, time, randomness may differ).",
    "File hash verification is the strongest reproducibility check; diff hash provides integrity evidence.",
    "Full deterministic replay requires deterministic verb implementations which are not mandated at this phase.",
    "Actual execution of rollback or replay steps requires explicit human approval via CommitApprovalWorkflow.",
  ]);

  const planBody = { candidateId: candidate.candidateId, candidateHash: candidate.candidateHash, steps };
  const planHash = createHash("sha256")
    .update(canonicalSerialize(planBody), "utf8")
    .digest("hex");

  return Object.freeze({
    schemaVersion: REPLAY_PLAN_SCHEMA_VERSION,
    candidateId: candidate.candidateId,
    candidateHash: candidate.candidateHash,
    generatedAt: now,
    planHash,
    steps: Object.freeze(steps.map((s) => Object.freeze(s))),
    isFullDeterministicReplay: false,
    caveats,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate comparison
// ─────────────────────────────────────────────────────────────────────────────

const RISK_RANK: Readonly<Record<CommitRiskLevel, number>> = Object.freeze({
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

function collectStats(c: CommitCandidate): CandidateStats {
  return {
    totalFiles: c.files.length,
    additions: c.diff.additions,
    deletions: c.diff.deletions,
    totalTests: c.tests.totalTests,
    passedTests: c.tests.passedTests,
  };
}

/**
 * Compares two CommitCandidates and produces a structured field-by-field diff.
 * Read-only, advisory, no side effects.
 */
export function compareCandidates(
  candidateA: CommitCandidate,
  candidateB: CommitCandidate
): CandidateComparison {
  const now = new Date().toISOString();
  const fieldDiffs: CandidateFieldDiff[] = [];

  function cmpField(field: string, valA: unknown, valB: unknown): void {
    const sA = JSON.stringify(valA);
    const sB = JSON.stringify(valB);
    if (sA === sB) {
      fieldDiffs.push({ field, kind: "unchanged", valueA: valA, valueB: valB });
    } else {
      fieldDiffs.push({ field, kind: "changed", valueA: valA, valueB: valB });
    }
  }

  cmpField("goal", candidateA.goal, candidateB.goal);
  cmpField("taskId", candidateA.taskId, candidateB.taskId);
  cmpField("agent.id", candidateA.agent.id, candidateB.agent.id);
  cmpField("risk.level", candidateA.risk.level, candidateB.risk.level);
  cmpField("risk.requiresHumanApproval", candidateA.risk.requiresHumanApproval, candidateB.risk.requiresHumanApproval);
  cmpField("tests.testsRun", candidateA.tests.testsRun, candidateB.tests.testsRun);
  cmpField("tests.passedTests", candidateA.tests.passedTests, candidateB.tests.passedTests);
  cmpField("tests.failedTests", candidateA.tests.failedTests, candidateB.tests.failedTests);
  cmpField("diff.filesChanged", candidateA.diff.filesChanged, candidateB.diff.filesChanged);
  cmpField("diff.additions", candidateA.diff.additions, candidateB.diff.additions);
  cmpField("diff.deletions", candidateA.diff.deletions, candidateB.diff.deletions);
  cmpField("diff.diffHash", candidateA.diff.diffHash, candidateB.diff.diffHash);
  cmpField("environment.nodeVersion", candidateA.environment.nodeVersion, candidateB.environment.nodeVersion);
  cmpField("environment.platform", candidateA.environment.platform, candidateB.environment.platform);

  // File diffs
  const fileMapA = new Map(candidateA.files.map((f) => [f.relativePath, f]));
  const fileMapB = new Map(candidateB.files.map((f) => [f.relativePath, f]));
  const allPaths = new Set([...fileMapA.keys(), ...fileMapB.keys()]);
  const fileDiffs: FileDiff[] = [];

  for (const path of [...allPaths].sort()) {
    const fA = fileMapA.get(path);
    const fB = fileMapB.get(path);
    if (!fA) {
      fileDiffs.push({ path, kind: "added", changeKindB: fB!.kind });
    } else if (!fB) {
      fileDiffs.push({ path, kind: "removed", changeKindA: fA.kind });
    } else if (fA.newHash === fB.newHash && fA.kind === fB.kind) {
      fileDiffs.push({ path, kind: "unchanged", changeKindA: fA.kind, changeKindB: fB.kind });
    } else {
      fileDiffs.push({
        path,
        kind: "changed",
        changeKindA: fA.kind,
        changeKindB: fB.kind,
        byteDeltaDiff: fB.byteDelta - fA.byteDelta,
      });
    }
  }

  const areIdentical = candidateA.candidateHash === candidateB.candidateHash;

  const riskA = candidateA.risk.level;
  const riskB = candidateB.risk.level;

  return Object.freeze({
    schemaVersion: CANDIDATE_COMPARISON_SCHEMA_VERSION,
    candidateIdA: candidateA.candidateId,
    candidateHashA: candidateA.candidateHash,
    candidateIdB: candidateB.candidateId,
    candidateHashB: candidateB.candidateHash,
    generatedAt: now,
    areIdentical,
    fieldDiffs: Object.freeze(fieldDiffs.map((d) => Object.freeze(d))),
    fileDiffs: Object.freeze(fileDiffs.map((d) => Object.freeze(d))),
    riskLevelA: riskA,
    riskLevelB: riskB,
    riskEscalated: RISK_RANK[riskB] > RISK_RANK[riskA],
    statsA: Object.freeze(collectStats(candidateA)),
    statsB: Object.freeze(collectStats(candidateB)),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollback Plan generator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generates a human-reviewable rollback PLAN for a commit candidate.
 * This is a planning document only — it does NOT execute any filesystem operations.
 * Execution requires human approval via CommitApprovalWorkflow.
 */
export function generateRollbackPlan(candidate: CommitCandidate): RollbackPlan {
  const now = new Date().toISOString();
  const steps: RollbackStep[] = [];
  let idx = 0;

  if (candidate.files.length === 0) {
    steps.push({
      stepIndex: idx++,
      kind: "noop",
      description: "No file changes recorded in candidate; no rollback steps required.",
      previousHash: ZERO_HASH,
      expectedOutcome: "No-op",
      isAutomatable: true,
      requiresHumanApproval: false,
    });
  } else {
    for (const file of candidate.files) {
      switch (file.kind) {
        case "added": {
          steps.push({
            stepIndex: idx++,
            kind: "revert_file",
            relativePath: file.relativePath,
            description: `Delete added file: '${file.relativePath}' (was not present before; previousHash=${ZERO_HASH.slice(0, 12)}…)`,
            previousHash: ZERO_HASH,
            expectedOutcome: `File '${file.relativePath}' no longer exists in workspace`,
            isAutomatable: false,
            requiresHumanApproval: true,
          });
          break;
        }
        case "deleted": {
          steps.push({
            stepIndex: idx++,
            kind: "restore_previous_hash",
            relativePath: file.relativePath,
            description: `Restore deleted file: '${file.relativePath}' to content with hash ${file.previousHash.slice(0, 12)}…`,
            previousHash: file.previousHash,
            expectedOutcome: `File '${file.relativePath}' restored; SHA-256 matches previousHash=${file.previousHash}`,
            isAutomatable: false,
            requiresHumanApproval: true,
          });
          break;
        }
        case "modified":
        case "renamed": {
          steps.push({
            stepIndex: idx++,
            kind: "revert_file",
            relativePath: file.relativePath,
            description: `Revert '${file.kind}' file: '${file.relativePath}' to hash ${file.previousHash.slice(0, 12)}…`,
            previousHash: file.previousHash,
            expectedOutcome: `File '${file.relativePath}' reverted; SHA-256 matches previousHash=${file.previousHash}`,
            isAutomatable: false,
            requiresHumanApproval: true,
          });
          break;
        }
      }
    }
  }

  // Always append a test run step after reverting files
  steps.push({
    stepIndex: idx++,
    kind: "run_tests",
    description: "Run full test suite after reverting all files to confirm rollback integrity",
    previousHash: ZERO_HASH,
    expectedOutcome: "All pre-change tests pass; no regressions introduced by rollback",
    isAutomatable: true,
    requiresHumanApproval: false,
  });

  // Always append human verification
  steps.push({
    stepIndex: idx++,
    kind: "human_verify",
    description: "Human reviewer verifies workspace state matches pre-candidate baseline",
    previousHash: ZERO_HASH,
    expectedOutcome: "Workspace confirmed as equivalent to state before candidate was applied",
    isAutomatable: false,
    requiresHumanApproval: true,
  });

  const caveats: readonly string[] = Object.freeze([
    "This plan is ADVISORY ONLY. It does NOT execute any filesystem operations.",
    "Rollback requires explicit human approval; CommitApprovalWorkflow.canCommit() must evaluate a new candidate.",
    "Content restoration is only possible if previousHash content is available (e.g. from backup or git history).",
    "Binary files and files outside workspace boundary are excluded.",
    "This is NOT an automatic git revert — no git operations are issued by this plan generator.",
  ]);

  const planBody = {
    candidateId: candidate.candidateId,
    candidateHash: candidate.candidateHash,
    steps,
    action: "rollback",
  };
  const planHash = createHash("sha256")
    .update(canonicalSerialize(planBody), "utf8")
    .digest("hex");

  return Object.freeze({
    schemaVersion: ROLLBACK_PLAN_SCHEMA_VERSION,
    candidateId: candidate.candidateId,
    candidateHash: candidate.candidateHash,
    generatedAt: now,
    planHash,
    steps: Object.freeze(steps.map((s) => Object.freeze(s))),
    isExecutionPlan: false,
    caveats,
    requiresHumanApproval: true,
    totalFilesToRevert: candidate.files.length,
  });
}
