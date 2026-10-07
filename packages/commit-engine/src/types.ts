import type { Actor } from "@menog/core";

// ─────────────────────────────────────────────────────────────────────────────
// Schema version
// ─────────────────────────────────────────────────────────────────────────────

export const COMMIT_CANDIDATE_SCHEMA_VERSION = "menog-commit-candidate/v0" as const;
export type CommitCandidateSchemaVersion = typeof COMMIT_CANDIDATE_SCHEMA_VERSION;

// ─────────────────────────────────────────────────────────────────────────────
// Risk classification
// ─────────────────────────────────────────────────────────────────────────────

export type CommitRiskLevel = "none" | "low" | "medium" | "high" | "critical";

export const COMMIT_RISK_LEVELS: readonly CommitRiskLevel[] = Object.freeze([
  "none",
  "low",
  "medium",
  "high",
  "critical",
]);

export interface CommitRiskAssessment {
  /** Overall risk classification for this commit candidate. */
  readonly level: CommitRiskLevel;
  /**
   * Machine-readable rationale for the assigned risk level.
   * Must be non-empty.
   */
  readonly rationale: string;
  /**
   * Whether a human approval gate is required before this candidate
   * may be promoted to an actual commit.
   * Invariant: level === "high" || level === "critical" → requiresHumanApproval === true.
   */
  readonly requiresHumanApproval: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval record
// ─────────────────────────────────────────────────────────────────────────────

export type CommitApprovalOutcome = "approved" | "rejected" | "pending";

export interface CommitApproval {
  readonly approvalId: string;
  readonly approver: Actor;
  readonly outcome: CommitApprovalOutcome;
  readonly timestamp: string;   // ISO-8601
  readonly reason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// File change summary
// ─────────────────────────────────────────────────────────────────────────────

export type CommitFileChangeKind = "added" | "modified" | "deleted" | "renamed";

export interface CommitFileChange {
  /** Relative path within workspace root (forward slashes). */
  readonly relativePath: string;
  readonly kind: CommitFileChangeKind;
  /** SHA-256 hex of file content before change. "0".repeat(64) for new files. */
  readonly previousHash: string;
  /** SHA-256 hex of file content after change. "0".repeat(64) for deleted files. */
  readonly newHash: string;
  /** Byte delta (positive = growth, negative = shrinkage). */
  readonly byteDelta: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Diff summary
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitDiffSummary {
  /**
   * SHA-256 hex of the unified diff content.
   * Must match the diffHash from the DeterministicDiffResult that generated it.
   */
  readonly diffHash: string;
  readonly additions: number;
  readonly deletions: number;
  readonly filesChanged: number;
  /**
   * True when the unified diff text is available inline; false when it was
   * omitted (e.g. too large) — the diffHash still identifies it.
   */
  readonly diffAvailable: boolean;
  /** Inline unified diff text; empty string when diffAvailable === false. */
  readonly unifiedDiff: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test evidence
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitTestEvidence {
  /**
   * Whether tests were run as part of producing this candidate.
   * When false, the candidate must carry risk.level >= "high".
   */
  readonly testsRun: boolean;
  readonly totalTests: number;
  readonly passedTests: number;
  readonly failedTests: number;
  /**
   * SHA-256 hex of the test run report for tamper-evidence.
   * "0".repeat(64) when testsRun === false.
   */
  readonly reportHash: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment snapshot
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitEnvironment {
  /** Node.js version string, e.g. "v22.0.0". */
  readonly nodeVersion: string;
  /** pnpm version string, e.g. "10.11.1". */
  readonly pnpmVersion: string;
  /** Operating system platform identifier, e.g. "win32", "linux", "darwin". */
  readonly platform: string;
  /**
   * Absolute workspace root path at the time the candidate was built.
   * Used to detect workspace-path drift between build and apply.
   */
  readonly workspaceRoot: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// CommitCandidate — top-level runtime evidence object
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitCandidate {
  /**
   * Discriminant schema version — always "menog-commit-candidate/v0".
   * Consumers MUST reject candidates with an unknown schemaVersion.
   */
  readonly schemaVersion: CommitCandidateSchemaVersion;

  /** Unique candidate identifier (UUID or deterministic id). */
  readonly candidateId: string;

  /** ISO-8601 creation timestamp. */
  readonly createdAt: string;

  // ── WHO ──────────────────────────────────────────────────────────────────
  /** The agent/human who authored the candidate. */
  readonly agent: Actor;

  // ── WHAT ─────────────────────────────────────────────────────────────────
  /** Human-readable goal description that motivated the changes. */
  readonly goal: string;

  /** Task identifier correlating to a ledger task chain. */
  readonly taskId: string;

  /**
   * Ordered list of verb IDs executed to produce this candidate.
   * Must be non-empty; order reflects execution sequence.
   */
  readonly verbs: readonly string[];

  // ── WHAT CHANGED ─────────────────────────────────────────────────────────
  /** Per-file change evidence. Must be non-empty. */
  readonly files: readonly CommitFileChange[];

  /** Unified diff summary for the entire candidate. */
  readonly diff: CommitDiffSummary;

  // ── TEST EVIDENCE ─────────────────────────────────────────────────────────
  readonly tests: CommitTestEvidence;

  // ── RISK ──────────────────────────────────────────────────────────────────
  readonly risk: CommitRiskAssessment;

  // ── APPROVALS ─────────────────────────────────────────────────────────────
  /**
   * Ordered list of approval records collected for this candidate.
   * Empty when no approvals have been collected yet.
   */
  readonly approvals: readonly CommitApproval[];

  // ── ENVIRONMENT ───────────────────────────────────────────────────────────
  readonly environment: CommitEnvironment;

  // ── LEDGER LINKAGE ────────────────────────────────────────────────────────
  /**
   * Ordered list of event IDs from the AppendOnlyLedger that are evidence
   * for this candidate. May be empty for candidates built outside a live ledger.
   */
  readonly ledgerEventIds: readonly string[];

  // ── CHAIN ────────────────────────────────────────────────────────────────
  /**
   * SHA-256 hash of the previous CommitCandidate's canonicalHash.
   * "0".repeat(64) for the first candidate in a chain.
   */
  readonly previousCandidateHash: string;

  /**
   * SHA-256 hex of the canonical JSON serialization of this candidate
   * (with canonicalHash field absent). Computed by CommitCandidateBuilder.
   */
  readonly candidateHash: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder input / result types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Input to CommitCandidateBuilder.build(). All required evidence fields.
 * The builder computes candidateHash from these; callers must not supply it.
 */
export type CommitCandidateInput = Omit<CommitCandidate, "schemaVersion" | "candidateHash">;

export interface BuildCommitCandidateResult {
  readonly ok: boolean;
  readonly candidate?: CommitCandidate;
  /** Machine-readable error tag when ok === false. */
  readonly error?: string;
  /** Human-readable detail for the error. */
  readonly reason?: string;
  /** Ledger event ID if a commit_candidate_created event was emitted. */
  readonly ledgerEventId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval State Machine Types (Prompt 15C)
// ─────────────────────────────────────────────────────────────────────────────

export type CommitCandidateState =
  | "pending"
  | "approved"
  | "rejected"
  | "revoked"
  | "stale"
  | "escalated";

export interface HumanApprovalDecision {
  readonly approvalId: string;
  readonly approver: Actor;
  readonly outcome: "approved" | "rejected";
  readonly timestamp: string;
  readonly reason?: string;
  /** Explicit acknowledgment required when risk.level is 'critical'. */
  readonly criticalRiskAcknowledged?: boolean;
}

export interface ApprovalStateTransition {
  readonly fromState: CommitCandidateState;
  readonly toState: CommitCandidateState;
  readonly actor: Actor;
  readonly timestamp: string;
  readonly reason: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CandidateApprovalStateRecord {
  readonly candidateId: string;
  readonly candidateHash: string;
  readonly state: CommitCandidateState;
  readonly riskLevel: CommitRiskLevel;
  readonly approvals: readonly CommitApproval[];
  readonly lastTransitionAt: string;
  readonly transitionReason: string;
  readonly history: readonly ApprovalStateTransition[];
  readonly expiresAt?: string;
  readonly twoPersonRuleRequired?: boolean;
}

export interface CanCommitResult {
  readonly canCommit: boolean;
  readonly state: CommitCandidateState;
  readonly reason?: string;
  readonly requiredApprovalsRemaining?: number;
}
