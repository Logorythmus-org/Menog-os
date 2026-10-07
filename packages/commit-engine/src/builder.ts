import { createHash, randomUUID } from "node:crypto";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import {
  COMMIT_CANDIDATE_SCHEMA_VERSION,
  COMMIT_RISK_LEVELS,
  type CommitCandidate,
  type CommitCandidateInput,
  type BuildCommitCandidateResult,
  type CommitRiskLevel,
} from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const ZERO_HASH = "0".repeat(64);
const HEX64_RE = /^[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

// ─────────────────────────────────────────────────────────────────────────────
// Canonical serialization
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Produces a deterministic, canonical JSON string from any object by
 * recursively sorting object keys. Arrays preserve element order.
 * This is the serialization used to compute candidateHash.
 */
export function canonicalSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalSerialize).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((k) => {
    const v = obj[k];
    return JSON.stringify(k) + ":" + canonicalSerialize(v);
  });
  return "{" + pairs.join(",") + "}";
}

/**
 * Computes SHA-256 hex of the canonical JSON serialization of any value.
 */
export function canonicalHash(value: unknown): string {
  return createHash("sha256")
    .update(canonicalSerialize(value), "utf8")
    .digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────────

function nonEmpty(value: unknown, field: string): string | null {
  if (typeof value !== "string" || value.trim().length === 0) {
    return `missing_field: '${field}' must be a non-empty string`;
  }
  return null;
}

function validIso(value: unknown, field: string): string | null {
  if (typeof value !== "string" || !ISO_RE.test(value)) {
    return `invalid_timestamp: '${field}' must be an ISO-8601 timestamp`;
  }
  return null;
}

function validHash(value: unknown, field: string): string | null {
  if (typeof value !== "string" || (!HEX64_RE.test(value) && value !== ZERO_HASH)) {
    return `invalid_hash: '${field}' must be a 64-char lowercase hex string or the zero-hash`;
  }
  return null;
}

function validateInput(input: CommitCandidateInput): string | null {
  // candidateId
  const errId = nonEmpty(input.candidateId, "candidateId");
  if (errId) return errId;

  // createdAt
  const errTs = validIso(input.createdAt, "createdAt");
  if (errTs) return errTs;

  // agent
  if (!input.agent || typeof input.agent !== "object") {
    return "missing_field: 'agent' must be an Actor object";
  }
  if (typeof input.agent.type !== "string" || input.agent.type.length === 0) {
    return "missing_field: 'agent.type' must be a non-empty string";
  }
  if (typeof input.agent.id !== "string" || input.agent.id.length === 0) {
    return "missing_field: 'agent.id' must be a non-empty string";
  }

  // goal
  const errGoal = nonEmpty(input.goal, "goal");
  if (errGoal) return errGoal;

  // taskId
  const errTask = nonEmpty(input.taskId, "taskId");
  if (errTask) return errTask;

  // verbs
  if (!Array.isArray(input.verbs) || input.verbs.length === 0) {
    return "missing_field: 'verbs' must be a non-empty array of verb IDs";
  }
  for (const v of input.verbs) {
    if (typeof v !== "string" || v.trim().length === 0) {
      return "invalid_field: each entry in 'verbs' must be a non-empty string";
    }
  }

  // files
  if (!Array.isArray(input.files) || input.files.length === 0) {
    return "missing_field: 'files' must be a non-empty array of CommitFileChange";
  }
  for (const f of input.files) {
    if (typeof f.relativePath !== "string" || f.relativePath.trim().length === 0) {
      return "invalid_field: CommitFileChange.relativePath must be non-empty";
    }
    if (f.relativePath.includes("\\")) {
      return `invalid_field: CommitFileChange.relativePath must use forward slashes; got '${f.relativePath}'`;
    }
    const validKinds = ["added", "modified", "deleted", "renamed"] as const;
    if (!(validKinds as readonly string[]).includes(f.kind)) {
      return `invalid_field: CommitFileChange.kind '${String(f.kind)}' is not valid`;
    }
    const errPrev = validHash(f.previousHash, "files[].previousHash");
    if (errPrev) return errPrev;
    const errNew = validHash(f.newHash, "files[].newHash");
    if (errNew) return errNew;
    if (typeof f.byteDelta !== "number" || !Number.isFinite(f.byteDelta)) {
      return "invalid_field: CommitFileChange.byteDelta must be a finite number";
    }
  }

  // diff
  if (!input.diff || typeof input.diff !== "object") {
    return "missing_field: 'diff' must be a CommitDiffSummary object";
  }
  const errDiffHash = validHash(input.diff.diffHash, "diff.diffHash");
  if (errDiffHash) return errDiffHash;
  if (typeof input.diff.additions !== "number" || input.diff.additions < 0) {
    return "invalid_field: 'diff.additions' must be a non-negative number";
  }
  if (typeof input.diff.deletions !== "number" || input.diff.deletions < 0) {
    return "invalid_field: 'diff.deletions' must be a non-negative number";
  }
  if (typeof input.diff.filesChanged !== "number" || input.diff.filesChanged < 0) {
    return "invalid_field: 'diff.filesChanged' must be a non-negative number";
  }
  if (typeof input.diff.diffAvailable !== "boolean") {
    return "missing_field: 'diff.diffAvailable' must be a boolean";
  }
  if (typeof input.diff.unifiedDiff !== "string") {
    return "missing_field: 'diff.unifiedDiff' must be a string";
  }
  // When diffAvailable is true, diffHash must not be the zero hash
  if (input.diff.diffAvailable && input.diff.diffHash === ZERO_HASH && input.diff.additions + input.diff.deletions > 0) {
    return "invalid_field: 'diff.diffHash' must not be zero-hash when diffAvailable=true and changes > 0";
  }

  // tests
  if (!input.tests || typeof input.tests !== "object") {
    return "missing_field: 'tests' must be a CommitTestEvidence object";
  }
  if (typeof input.tests.testsRun !== "boolean") {
    return "missing_field: 'tests.testsRun' must be a boolean";
  }
  if (typeof input.tests.totalTests !== "number" || input.tests.totalTests < 0) {
    return "invalid_field: 'tests.totalTests' must be a non-negative number";
  }
  if (typeof input.tests.passedTests !== "number" || input.tests.passedTests < 0) {
    return "invalid_field: 'tests.passedTests' must be a non-negative number";
  }
  if (typeof input.tests.failedTests !== "number" || input.tests.failedTests < 0) {
    return "invalid_field: 'tests.failedTests' must be a non-negative number";
  }
  if (input.tests.passedTests + input.tests.failedTests > input.tests.totalTests) {
    return "invalid_field: 'tests.passedTests + failedTests' cannot exceed 'tests.totalTests'";
  }
  const errReportHash = validHash(input.tests.reportHash, "tests.reportHash");
  if (errReportHash) return errReportHash;

  // risk
  if (!input.risk || typeof input.risk !== "object") {
    return "missing_field: 'risk' must be a CommitRiskAssessment object";
  }
  if (!(COMMIT_RISK_LEVELS as readonly string[]).includes(input.risk.level)) {
    return `invalid_field: 'risk.level' '${String(input.risk.level)}' is not a valid CommitRiskLevel`;
  }
  const errRationale = nonEmpty(input.risk.rationale, "risk.rationale");
  if (errRationale) return errRationale;
  if (typeof input.risk.requiresHumanApproval !== "boolean") {
    return "missing_field: 'risk.requiresHumanApproval' must be a boolean";
  }
  // Enforce invariant: high/critical → requiresHumanApproval must be true
  const riskLevel = input.risk.level as CommitRiskLevel;
  if ((riskLevel === "high" || riskLevel === "critical") && !input.risk.requiresHumanApproval) {
    return `invalid_field: risk.level '${riskLevel}' requires requiresHumanApproval === true`;
  }

  // approvals — array (may be empty)
  if (!Array.isArray(input.approvals)) {
    return "missing_field: 'approvals' must be an array (may be empty)";
  }
  for (const a of input.approvals) {
    const errApprId = nonEmpty(a.approvalId, "approvals[].approvalId");
    if (errApprId) return errApprId;
    if (!a.approver || typeof a.approver.type !== "string" || typeof a.approver.id !== "string") {
      return "invalid_field: approvals[].approver must be a valid Actor";
    }
    const validOutcomes = ["approved", "rejected", "pending"] as const;
    if (!(validOutcomes as readonly string[]).includes(a.outcome)) {
      return `invalid_field: approvals[].outcome '${String(a.outcome)}' is not valid`;
    }
    const errATs = validIso(a.timestamp, "approvals[].timestamp");
    if (errATs) return errATs;
  }

  // environment
  if (!input.environment || typeof input.environment !== "object") {
    return "missing_field: 'environment' must be a CommitEnvironment object";
  }
  const errNode = nonEmpty(input.environment.nodeVersion, "environment.nodeVersion");
  if (errNode) return errNode;
  const errPnpm = nonEmpty(input.environment.pnpmVersion, "environment.pnpmVersion");
  if (errPnpm) return errPnpm;
  const errPlatform = nonEmpty(input.environment.platform, "environment.platform");
  if (errPlatform) return errPlatform;
  const errWs = nonEmpty(input.environment.workspaceRoot, "environment.workspaceRoot");
  if (errWs) return errWs;

  // ledgerEventIds — array (may be empty)
  if (!Array.isArray(input.ledgerEventIds)) {
    return "missing_field: 'ledgerEventIds' must be an array (may be empty)";
  }
  for (const id of input.ledgerEventIds) {
    if (typeof id !== "string" || id.trim().length === 0) {
      return "invalid_field: each entry in 'ledgerEventIds' must be a non-empty string";
    }
  }

  // previousCandidateHash
  const errPrev = validHash(input.previousCandidateHash, "previousCandidateHash");
  if (errPrev) return errPrev;

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// CommitCandidateBuilder
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitCandidateBuilderOptions {
  /** Optional ledger to emit a commit_candidate_created event upon build. */
  readonly ledger?: AppendOnlyLedger | null;
}

/**
 * Builds and validates a CommitCandidate from input evidence.
 *
 * Authority separation:
 * - Proposal: caller supplies evidence via CommitCandidateInput
 * - Decision: builder validates completeness and structural invariants
 * - Execution: builder computes candidateHash and optionally emits ledger event
 * - Evaluation: external consumer assesses the resulting CommitCandidate
 *
 * NO Git operations are performed. The builder is purely in-memory.
 */
export class CommitCandidateBuilder {
  readonly #ledger: AppendOnlyLedger | null;

  public constructor(options: CommitCandidateBuilderOptions = {}) {
    this.#ledger = options.ledger ?? null;
  }

  /**
   * Validates and builds a CommitCandidate from the supplied input.
   *
   * On success: returns ok=true with a fully-frozen CommitCandidate.
   * On failure: returns ok=false with error tag and reason; no ledger event emitted.
   */
  public build(input: CommitCandidateInput): BuildCommitCandidateResult {
    // 1. Validate
    const validationError = validateInput(input);
    if (validationError) {
      return {
        ok: false,
        error: validationError.split(":")[0] ?? "validation_error",
        reason: validationError,
      };
    }

    // 2. Compute candidateHash from canonical serialization (without the hash field)
    const hashableBody: Record<string, unknown> = {
      schemaVersion: COMMIT_CANDIDATE_SCHEMA_VERSION,
      candidateId: input.candidateId,
      createdAt: input.createdAt,
      agent: input.agent,
      goal: input.goal,
      taskId: input.taskId,
      verbs: input.verbs,
      files: input.files,
      diff: input.diff,
      tests: input.tests,
      risk: input.risk,
      approvals: input.approvals,
      environment: input.environment,
      ledgerEventIds: input.ledgerEventIds,
      previousCandidateHash: input.previousCandidateHash,
    };

    const computedHash = canonicalHash(hashableBody);

    // 3. Assemble frozen candidate
    const candidate: CommitCandidate = Object.freeze({
      schemaVersion: COMMIT_CANDIDATE_SCHEMA_VERSION,
      candidateId: input.candidateId,
      createdAt: input.createdAt,
      agent: Object.freeze({ ...input.agent }),
      goal: input.goal,
      taskId: input.taskId,
      verbs: Object.freeze([...input.verbs]),
      files: Object.freeze(input.files.map((f) => Object.freeze({ ...f }))),
      diff: Object.freeze({ ...input.diff }),
      tests: Object.freeze({ ...input.tests }),
      risk: Object.freeze({ ...input.risk }),
      approvals: Object.freeze(input.approvals.map((a) => Object.freeze({ ...a }))),
      environment: Object.freeze({ ...input.environment }),
      ledgerEventIds: Object.freeze([...input.ledgerEventIds]),
      previousCandidateHash: input.previousCandidateHash,
      candidateHash: computedHash,
    });

    // 4. Emit ledger event (if ledger present)
    let ledgerEventId: string | undefined;
    if (this.#ledger !== null) {
      ledgerEventId = "cce-" + randomUUID().replace(/-/g, "").slice(0, 20);
      this.#ledger.append({
        eventId: ledgerEventId,
        timestamp: new Date().toISOString(),
        eventType: "commit_candidate_created",
        actor: input.agent,
        workspaceId: input.environment.workspaceRoot,
        taskId: input.taskId,
        verb: "commit",
        capability: "git:commit",
        policyDecision: "not_applicable",
        inputSummary: {
          candidateId: input.candidateId,
          goal: input.goal,
          filesChanged: input.files.length,
          verbCount: input.verbs.length,
        },
        resultSummary: {
          candidateHash: computedHash,
          riskLevel: input.risk.level,
          requiresHumanApproval: input.risk.requiresHumanApproval,
          testsRun: input.tests.testsRun,
          passedTests: input.tests.passedTests,
          failedTests: input.tests.failedTests,
        },
      });
    }

    return {
      ok: true,
      candidate,
      ledgerEventId,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone helper: build a candidate ID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generates a new unique candidate ID using crypto.randomUUID.
 * Callers may also supply a deterministic ID for replay or testing.
 */
export function newCandidateId(): string {
  return "cand-" + randomUUID().replace(/-/g, "").slice(0, 24);
}
