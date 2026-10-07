import { randomUUID } from "node:crypto";
import type { Actor } from "@menog/core";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import type {
  CommitCandidate,
  CommitRiskLevel,
  CommitApproval,
  CommitCandidateState,
  HumanApprovalDecision,
  ApprovalStateTransition,
  CandidateApprovalStateRecord,
  CanCommitResult,
} from "./types.js";

export const DEFAULT_APPROVAL_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
export const CRITICAL_APPROVAL_TTL_MS = 30 * 60 * 1000;      // 30 minutes

export interface CommitApprovalWorkflowOptions {
  readonly ledger?: AppendOnlyLedger | null;
  readonly defaultTtlMs?: number;
}

export interface RegisterCandidateOptions {
  readonly ttlMs?: number;
  readonly twoPersonRule?: boolean;
}

const RISK_HIERARCHY: Readonly<Record<CommitRiskLevel, number>> = Object.freeze({
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

/**
 * State machine managing the commit candidate approval lifecycle.
 * Invariant: No commit without approved state from a human actor.
 * Invariant: Critical-risk candidates require stronger approval.
 * Invariant: All state transitions are logged immutably to the event ledger.
 */
export class CommitApprovalWorkflow {
  readonly #ledger: AppendOnlyLedger | null;
  readonly #defaultTtlMs: number;
  readonly #records = new Map<string, CandidateApprovalStateRecord>();
  readonly #candidates = new Map<string, CommitCandidate>();

  public constructor(options: CommitApprovalWorkflowOptions = {}) {
    this.#ledger = options.ledger ?? null;
    this.#defaultTtlMs = options.defaultTtlMs ?? DEFAULT_APPROVAL_TTL_MS;
  }

  public getRecord(candidateId: string): CandidateApprovalStateRecord | undefined {
    const record = this.#records.get(candidateId);
    if (!record) return undefined;

    // Check TTL expiration lazily
    if (record.state !== "stale" && record.state !== "rejected" && record.expiresAt) {
      if (Date.now() > Date.parse(record.expiresAt)) {
        return this.invalidate(
          candidateId,
          "approval_ttl_expired: candidate expired without approval or application",
          { type: "runtime", id: "approval-workflow-timer" }
        );
      }
    }

    return record;
  }

  /**
   * Registers a CommitCandidate into the approval workflow in 'pending' state.
   */
  public registerCandidate(
    candidate: CommitCandidate,
    options: RegisterCandidateOptions = {}
  ): CandidateApprovalStateRecord {
    if (!candidate || typeof candidate !== "object") {
      throw new Error("registerCandidate: candidate must be an object");
    }
    if (!candidate.candidateId || candidate.candidateId.trim().length === 0) {
      throw new Error("registerCandidate: candidateId must be non-empty");
    }

    const now = new Date().toISOString();
    const isCritical = candidate.risk.level === "critical";

    const ttl =
      options.ttlMs ??
      (isCritical ? CRITICAL_APPROVAL_TTL_MS : this.#defaultTtlMs);

    const expiresAt = new Date(Date.now() + ttl).toISOString();
    const twoPersonRule = options.twoPersonRule ?? isCritical;

    const initialTransition: ApprovalStateTransition = {
      fromState: "pending",
      toState: "pending",
      actor: candidate.agent,
      timestamp: now,
      reason: "candidate_registered",
      metadata: {
        riskLevel: candidate.risk.level,
        twoPersonRuleRequired: twoPersonRule,
      },
    };

    const record: CandidateApprovalStateRecord = {
      candidateId: candidate.candidateId,
      candidateHash: candidate.candidateHash,
      state: "pending",
      riskLevel: candidate.risk.level,
      approvals: Object.freeze([]),
      lastTransitionAt: now,
      transitionReason: "candidate_registered",
      history: Object.freeze([initialTransition]),
      expiresAt,
      twoPersonRuleRequired: twoPersonRule,
    };

    this.#records.set(candidate.candidateId, record);
    this.#candidates.set(candidate.candidateId, candidate);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_registered",
      actor: candidate.agent,
      candidateId: candidate.candidateId,
      candidateHash: candidate.candidateHash,
      fromState: "pending",
      toState: "pending",
      reason: "candidate_registered",
      metadata: {
        riskLevel: candidate.risk.level,
        expiresAt,
      },
    });

    return record;
  }

  /**
   * Evaluates a human approval decision for a candidate.
   * Enforces: Human actor ONLY, Critical risk acknowledgment, Multi-approval if configured.
   */
  public approve(
    candidateId: string,
    decision: HumanApprovalDecision,
    _candidate?: CommitCandidate
  ): CandidateApprovalStateRecord {
    const record = this.getRecord(candidateId);
    if (!record) {
      throw new Error(`approve: candidate '${candidateId}' is not registered`);
    }

    // 1. Terminal / non-approvable states check
    if (record.state === "rejected") {
      throw new Error("cannot_approve_rejected_candidate: candidate was previously rejected");
    }
    if (record.state === "revoked") {
      throw new Error("cannot_approve_revoked_candidate: candidate approval was revoked; must re-register or re-escalate");
    }
    if (record.state === "stale") {
      throw new Error("cannot_approve_stale_candidate: candidate is stale due to drift or expiration");
    }

    // 2. Strict HUMAN actor enforcement
    if (decision.approver.type !== "human") {
      throw new Error(
        `human_actor_required: only human actors can approve commit candidates; got '${decision.approver.type}'`
      );
    }

    // 3. Rejection path
    if (decision.outcome === "rejected") {
      return this.reject(candidateId, decision.approver, decision.reason ?? "human_rejected");
    }

    // 4. Critical risk stronger approval requirements
    const isCritical = record.riskLevel === "critical";
    if (isCritical) {
      if (decision.criticalRiskAcknowledged !== true) {
        throw new Error(
          "critical_risk_acknowledgment_required: approving critical-risk commit candidate requires explicit criticalRiskAcknowledged: true"
        );
      }
    }

    const now = decision.timestamp || new Date().toISOString();
    const newApproval: CommitApproval = {
      approvalId: decision.approvalId || ("appr-" + randomUUID().slice(0, 12)),
      approver: decision.approver,
      outcome: "approved",
      timestamp: now,
      reason: decision.reason,
    };

    // 5. Two-Person Rule handling
    if (record.twoPersonRuleRequired) {
      const existingApprovals = record.approvals;

      if (existingApprovals.length === 0) {
        // First approval recorded; remains pending second distinct approver
        const transition: ApprovalStateTransition = {
          fromState: record.state,
          toState: "pending",
          actor: decision.approver,
          timestamp: now,
          reason: "first_approval_recorded_awaiting_second_human",
          metadata: {
            firstApproverId: decision.approver.id,
          },
        };

        const updated: CandidateApprovalStateRecord = {
          ...record,
          approvals: Object.freeze([newApproval]),
          lastTransitionAt: now,
          transitionReason: "first_approval_recorded_awaiting_second_human",
          history: Object.freeze([...record.history, transition]),
        };

        this.#records.set(candidateId, updated);

        this.#emitLedgerEvent({
          eventType: "commit_candidate_partially_approved",
          actor: decision.approver,
          candidateId,
          candidateHash: record.candidateHash,
          fromState: record.state,
          toState: "pending",
          reason: "first_approval_recorded_awaiting_second_human",
          metadata: { approverId: decision.approver.id },
        });

        return updated;
      }

      // Second approval verification: MUST be distinct human
      const firstApproverId = existingApprovals[0]!.approver.id;
      if (decision.approver.id === firstApproverId) {
        throw new Error(
          `two_person_rule_violation: second approver ('${decision.approver.id}') must be distinct from first approver ('${firstApproverId}')`
        );
      }
    }

    // Fully approved
    const allApprovals = Object.freeze([...record.approvals, newApproval]);
    const transition: ApprovalStateTransition = {
      fromState: record.state,
      toState: "approved",
      actor: decision.approver,
      timestamp: now,
      reason: decision.reason ?? "human_approved",
      metadata: {
        approvalCount: allApprovals.length,
        isCritical,
      },
    };

    const updated: CandidateApprovalStateRecord = {
      ...record,
      state: "approved",
      approvals: allApprovals,
      lastTransitionAt: now,
      transitionReason: decision.reason ?? "human_approved",
      history: Object.freeze([...record.history, transition]),
    };

    this.#records.set(candidateId, updated);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_approved",
      actor: decision.approver,
      candidateId,
      candidateHash: record.candidateHash,
      fromState: record.state,
      toState: "approved",
      reason: decision.reason ?? "human_approved",
      metadata: {
        approvalId: newApproval.approvalId,
        approverId: decision.approver.id,
        isCritical,
      },
    });

    return updated;
  }

  /**
   * Explicit human rejection of a commit candidate.
   */
  public reject(
    candidateId: string,
    approver: Actor,
    reason: string
  ): CandidateApprovalStateRecord {
    const record = this.#records.get(candidateId);
    if (!record) {
      throw new Error(`reject: candidate '${candidateId}' is not registered`);
    }

    if (approver.type !== "human") {
      throw new Error(`human_actor_required: only human actors can reject commit candidates; got '${approver.type}'`);
    }

    const now = new Date().toISOString();
    const transition: ApprovalStateTransition = {
      fromState: record.state,
      toState: "rejected",
      actor: approver,
      timestamp: now,
      reason,
    };

    const updated: CandidateApprovalStateRecord = {
      ...record,
      state: "rejected",
      lastTransitionAt: now,
      transitionReason: reason,
      history: Object.freeze([...record.history, transition]),
    };

    this.#records.set(candidateId, updated);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_rejected",
      actor: approver,
      candidateId,
      candidateHash: record.candidateHash,
      fromState: record.state,
      toState: "rejected",
      reason,
    });

    return updated;
  }

  /**
   * Revokes a previously granted approval.
   * State transitions to 'revoked'.
   */
  public revoke(
    candidateId: string,
    revoker: Actor,
    reason: string
  ): CandidateApprovalStateRecord {
    const record = this.#records.get(candidateId);
    if (!record) {
      throw new Error(`revoke: candidate '${candidateId}' is not registered`);
    }

    if (revoker.type !== "human") {
      throw new Error(`human_actor_required: only human actors can revoke approvals; got '${revoker.type}'`);
    }

    const now = new Date().toISOString();
    const transition: ApprovalStateTransition = {
      fromState: record.state,
      toState: "revoked",
      actor: revoker,
      timestamp: now,
      reason,
    };

    const updated: CandidateApprovalStateRecord = {
      ...record,
      state: "revoked",
      lastTransitionAt: now,
      transitionReason: reason,
      history: Object.freeze([...record.history, transition]),
    };

    this.#records.set(candidateId, updated);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_revoked",
      actor: revoker,
      candidateId,
      candidateHash: record.candidateHash,
      fromState: record.state,
      toState: "revoked",
      reason,
    });

    return updated;
  }

  /**
   * Escalates the risk level of a candidate.
   * If candidate was already approved at a lower level, that approval is invalidated and must be re-obtained.
   */
  public escalate(
    candidateId: string,
    newRiskLevel: CommitRiskLevel,
    actor: Actor,
    reason: string
  ): CandidateApprovalStateRecord {
    const record = this.#records.get(candidateId);
    if (!record) {
      throw new Error(`escalate: candidate '${candidateId}' is not registered`);
    }

    const currentRank = RISK_HIERARCHY[record.riskLevel];
    const newRank = RISK_HIERARCHY[newRiskLevel];

    if (newRank < currentRank) {
      throw new Error(
        `invalid_escalation: cannot de-escalate risk from '${record.riskLevel}' to '${newRiskLevel}' via escalate()`
      );
    }

    const now = new Date().toISOString();
    const isCritical = newRiskLevel === "critical";

    // If previously approved, escalating risk invalidates the prior approval!
    const targetState: CommitCandidateState = "escalated";
    const twoPersonRule = record.twoPersonRuleRequired || isCritical;

    // Reset expiration window if escalating to critical
    const expiresAt = isCritical
      ? new Date(Date.now() + CRITICAL_APPROVAL_TTL_MS).toISOString()
      : record.expiresAt;

    const transition: ApprovalStateTransition = {
      fromState: record.state,
      toState: targetState,
      actor,
      timestamp: now,
      reason,
      metadata: {
        oldRiskLevel: record.riskLevel,
        newRiskLevel,
        revokedPriorApprovalsCount: record.approvals.length,
      },
    };

    const updated: CandidateApprovalStateRecord = {
      ...record,
      state: targetState,
      riskLevel: newRiskLevel,
      approvals: Object.freeze([]), // Clear approvals on escalation!
      lastTransitionAt: now,
      transitionReason: reason,
      history: Object.freeze([...record.history, transition]),
      twoPersonRuleRequired: twoPersonRule,
      expiresAt,
    };

    this.#records.set(candidateId, updated);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_escalated",
      actor,
      candidateId,
      candidateHash: record.candidateHash,
      fromState: record.state,
      toState: targetState,
      reason,
      metadata: {
        oldRiskLevel: record.riskLevel,
        newRiskLevel,
      },
    });

    return updated;
  }

  /**
   * Explicitly marks a candidate as stale (e.g. workspace drift, rebase, external modification).
   */
  public invalidate(
    candidateId: string,
    reason: string,
    actor: Actor = { type: "runtime", id: "approval-workflow" }
  ): CandidateApprovalStateRecord {
    const record = this.#records.get(candidateId);
    if (!record) {
      throw new Error(`invalidate: candidate '${candidateId}' is not registered`);
    }

    const now = new Date().toISOString();
    const transition: ApprovalStateTransition = {
      fromState: record.state,
      toState: "stale",
      actor,
      timestamp: now,
      reason,
    };

    const updated: CandidateApprovalStateRecord = {
      ...record,
      state: "stale",
      lastTransitionAt: now,
      transitionReason: reason,
      history: Object.freeze([...record.history, transition]),
    };

    this.#records.set(candidateId, updated);

    this.#emitLedgerEvent({
      eventType: "commit_candidate_invalidated",
      actor,
      candidateId,
      candidateHash: record.candidateHash,
      fromState: record.state,
      toState: "stale",
      reason,
    });

    return updated;
  }

  /**
   * Verifies freshness of a candidate against current workspace file hashes.
   * If any file content hash has drifted, invalidates candidate as stale.
   */
  public checkFreshness(
    candidateId: string,
    currentFileHashes: Readonly<Record<string, string>>
  ): boolean {
    const record = this.getRecord(candidateId);
    if (!record || record.state === "stale") return false;

    const candidate = this.#candidates.get(candidateId);
    if (!candidate) return false;

    for (const file of candidate.files) {
      const current = currentFileHashes[file.relativePath];
      if (current === undefined || current !== file.newHash) {
        this.invalidate(
          candidateId,
          `workspace_drift_detected: file '${file.relativePath}' hash changed from '${file.newHash}' to '${current ?? "missing"}'`,
          { type: "runtime", id: "drift-detector" }
        );
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluates whether a commit candidate is in an approved state and authorized to commit.
   * Fails closed on any non-approved state, expired candidate, or missing requirements.
   */
  public canCommit(candidateId: string): CanCommitResult {
    const record = this.getRecord(candidateId);
    if (!record) {
      return {
        canCommit: false,
        state: "pending",
        reason: `candidate '${candidateId}' is not registered in approval workflow`,
      };
    }

    const state = record.state;

    switch (state) {
      case "approved": {
        // Double-check human authority invariant
        const hasNonHuman = record.approvals.some((a) => a.approver.type !== "human");
        if (hasNonHuman) {
          return {
            canCommit: false,
            state: "approved",
            reason: "corrupted_approval: non-human approver found in approval records",
          };
        }

        if (record.twoPersonRuleRequired && record.approvals.length < 2) {
          return {
            canCommit: false,
            state: "approved",
            reason: "two_person_rule_violation: required 2 approvals but only have 1",
            requiredApprovalsRemaining: 1,
          };
        }

        return {
          canCommit: true,
          state: "approved",
        };
      }

      case "pending": {
        const remaining = record.twoPersonRuleRequired
          ? Math.max(1, 2 - record.approvals.length)
          : 1;
        return {
          canCommit: false,
          state: "pending",
          reason: "approval_required: candidate is pending human review",
          requiredApprovalsRemaining: remaining,
        };
      }

      case "escalated": {
        return {
          canCommit: false,
          state: "escalated",
          reason: "risk_escalated_reapproval_required: risk was escalated; requires fresh human approval",
          requiredApprovalsRemaining: record.twoPersonRuleRequired ? 2 : 1,
        };
      }

      case "rejected": {
        return {
          canCommit: false,
          state: "rejected",
          reason: `candidate_rejected: ${record.transitionReason}`,
        };
      }

      case "revoked": {
        return {
          canCommit: false,
          state: "revoked",
          reason: `approval_revoked: ${record.transitionReason}`,
        };
      }

      case "stale": {
        return {
          canCommit: false,
          state: "stale",
          reason: `candidate_stale: ${record.transitionReason}`,
        };
      }
    }
  }

  #emitLedgerEvent(data: {
    eventType: string;
    actor: Actor;
    candidateId: string;
    candidateHash: string;
    fromState: CommitCandidateState;
    toState: CommitCandidateState;
    reason: string;
    metadata?: Readonly<Record<string, unknown>>;
  }): void {
    if (!this.#ledger) return;

    this.#ledger.append({
      eventId: "appr-evt-" + randomUUID().replace(/-/g, "").slice(0, 20),
      timestamp: new Date().toISOString(),
      eventType: data.eventType,
      actor: data.actor,
      verb: "commit",
      capability: "git:commit",
      policyDecision: data.toState === "approved" ? "allow" : "not_applicable",
      inputSummary: {
        candidateId: data.candidateId,
        candidateHash: data.candidateHash,
        fromState: data.fromState,
        toState: data.toState,
      },
      resultSummary: {
        reason: data.reason,
        ...data.metadata,
      },
    });
  }
}
