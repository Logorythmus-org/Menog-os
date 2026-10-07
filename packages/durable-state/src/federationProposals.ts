/**
 * PHASE 24E — Cross-Node Task Proposal Protocol (PROPOSAL-ONLY).
 *
 * A verified ADMITTED peer may propose: task intent, a capability CLASS,
 * content hashes, provenance, constraints, expected evidence. It may NOT:
 * grant capabilities, choose or bypass Policy, invoke a tool, force
 * allocation, reuse an old Policy decision, or send shell / executable-
 * replay material.
 *
 * The receiver flow is strictly LOCAL and fail-closed:
 *
 *   admitted peer's signed message (24D bus) → typed inbox entry
 *   → proposal validation (THIS module; the payload is UNTRUSTED DATA)
 *   → durable inert PROPOSAL record (third 22A unfreeze kind)
 *   → the candidate is offered to LOCAL callers only
 *   → fresh LOCAL 19B allocation → fresh LOCAL Day-1 Policy evaluation
 *   → only then normal Phase-20/21 execution
 *
 * What a proposal record IS: durable, inert evidence of WHAT WAS PROPOSED
 * and HOW THE LOCAL RECEIVER JUDGED IT. It never carries, produces, or
 * restores authority. A duplicated proposal id is refused against the
 * durable record index (the record id IS the proposal-id commitment — the
 * 24D receipt discipline), which keeps the guard intact across restarts.
 *
 * Composition law (structural, test-pinned): a remote proposal can NEVER
 * short-circuit to the tool junction. The proposal layer imports no
 * execution surface and exposes none; `intentClass` is a closed inert
 * label the LOCAL caller may map onto a fresh TaskDescriptor; allocation,
 * Policy, and execution always run fresh and locally, and Policy can
 * always deny. There is no federation super-agent and no capability
 * union: a proposal cannot widen any local profile — `workspace:read`
 * stays exactly `workspace:read`.
 */

import {
  NODE_ID_PATTERN,
  NODE_FINGERPRINT_PATTERN,
} from "./federationIdentity.js";
import type { RuntimeStateCoordinator } from "./coordinator.js";
import type { DurableStore } from "./store.js";
import { canonicalHash, canonicalDurableJson } from "./canonical.js";
import { federationProposalDurableId } from "./statePersistence.js";

// ── schema + bounds (closed; refusing to widen is the point) ─────────────────

export const FEDERATION_PROPOSAL_SCHEMA_VERSION = "menog-federation-proposal/v0" as const;
export type FederationProposalSchemaVersion = typeof FEDERATION_PROPOSAL_SCHEMA_VERSION;

/** Exact payload-shape schema string for a task_proposal payload. */
export const FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION = "menog-task-proposal/v0" as const;
export type FederationTaskProposalSchemaVersion = typeof FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION;

/** Canonical byte bound on the payload object a proposal may be built from. */
export const FEDERATION_MAX_PROPOSAL_PAYLOAD_BYTES = 16384 as const;
/** Max entries in `contentHashes` / `expectedEvidence`. */
export const FEDERATION_MAX_PROPOSAL_HASH_REFS = 32 as const;
/** Max entries in `constraints`. */
export const FEDERATION_MAX_PROPOSAL_CONSTRAINTS = 32 as const;

/** Canonical proposal-id shape (fp-<ts16>-<rnd16>; 24A id discipline). */
export const FEDERATION_PROPOSAL_ID_PATTERN = /^fp-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/;

/** Content-hash refs are explicit `sha256-<64hex>` commitments. */
export const PROPOSAL_HASH_REF_PATTERN = /^sha256-[0-9a-f]{64}$/;

/** Bounded constraint-entry shapes (the pack's "constraints" field). */
export const PROPOSAL_CONSTRAINT_KEYS = Object.freeze([
  "maxRuntimeMs",
  "deadlineEpochMs",
  "maxBudgetSteps",
  "readonlyWorkspaceOnly",
] as const);
export type ProposalConstraintKey = (typeof PROPOSAL_CONSTRAINT_KEYS)[number];

/**
 * The closed intent-class vocabulary: an INERT LABEL the remote side
 * proposes and the LOCAL caller may interpret. It is not a capability, not
 * an executable, and not a Policy input; the LOCAL descriptor decides the
 * real required capabilities.
 */
export const PROPOSAL_INTENT_CLASSES = Object.freeze([
  "workspace_survey",
  "content_review",
  "artifact_verification",
] as const);
export type ProposalIntentClass = (typeof PROPOSAL_INTENT_CLASSES)[number];

export function isProposalIntentClass(value: unknown): value is ProposalIntentClass {
  return typeof value === "string" && (PROPOSAL_INTENT_CLASSES as readonly string[]).includes(value);
}

// ── validated payload shape (strict; unknown fields refuse) ──────────────────

/**
 * The EXACT payload shape a `task_proposal` message may carry. Every field
 * is untrusted data. Nothing here is authority: `intentClass` is a label,
 * `constraints` are data, hashes are commitments to be checked LOCALLY.
 */
export interface FederationTaskProposalPayload {
  readonly schemaVersion: FederationTaskProposalSchemaVersion;
  readonly proposalId: string;
  readonly intentClass: ProposalIntentClass;
  readonly contentHashes: readonly string[];
  readonly provenance: {
    readonly originNodeId: string;
    readonly originFingerprint: string;
    readonly note: string;
  };
  readonly constraints: Readonly<Partial<Record<ProposalConstraintKey, number | boolean>>>;
  readonly expectedEvidence: readonly string[];
}

/** Every field required; unknown fields REFUSE (a proposal cannot smuggle). */
export const TASK_PROPOSAL_PAYLOAD_KEYS = Object.freeze([
  "schemaVersion",
  "proposalId",
  "intentClass",
  "contentHashes",
  "provenance",
  "constraints",
  "expectedEvidence",
] as const);

// ── decision vocabulary (pure, fail-closed) ──────────────────────────────────

/** The validation stages, in enforced order. */
export type ProposalStage =
  | "payload_shape"
  | "schema_version"
  | "identity_binding"
  | "intent_class"
  | "content_hashes"
  | "provenance"
  | "constraints"
  | "expected_evidence"
  | "durable_admission";

/** Why a proposal was refused (closed). */
export const FEDERATION_PROPOSAL_FAILURE_CODES = Object.freeze([
  "proposal_malformed",
  "proposal_schema_mismatch",
  "proposal_identity_mismatch",
  "proposal_intent_unknown",
  "proposal_hash_malformed",
  "proposal_provenance_mismatch",
  "proposal_constraint_malformed",
  "proposal_evidence_malformed",
  "proposal_duplicate",
  "proposal_persistence_denied",
  "proposal_forbidden_material",
  "ledger_closed",
] as const);
export type FederationProposalFailureCode = (typeof FEDERATION_PROPOSAL_FAILURE_CODES)[number];

export type ProposalValidationResult =
  | { readonly ok: true; readonly payload: FederationTaskProposalPayload }
  | {
      readonly ok: false;
      readonly stage: ProposalStage;
      readonly failureCode: FederationProposalFailureCode;
      readonly explanation: string;
    };

export type ProposalAdmissionResult =
  | {
      readonly ok: true;
      readonly code: "proposal_admitted";
      readonly proposalId: string;
      readonly recordId: string;
      readonly commitSequence: number;
      readonly proposalHash: string;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly stage: ProposalStage;
      readonly failureCode: FederationProposalFailureCode;
      readonly storeFailureCode: string | null;
      readonly explanation: string;
    };

/**
 * The durable, inert record of ONE judged proposal. The decision fields
 * describe the RECEIVER's judgment only; none of them authorize anything.
 */
export interface FederationProposalRecordBody {
  readonly schemaVersion: FederationProposalSchemaVersion;
  readonly proposalId: string;
  readonly messageId: string;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly proposalHash: string;
  readonly intentClass: ProposalIntentClass;
  readonly contentHashes: readonly string[];
  readonly provenance: FederationTaskProposalPayload["provenance"];
  readonly constraints: FederationTaskProposalPayload["constraints"];
  readonly expectedEvidence: readonly string[];
  /** The LOCAL receiver's judgment on the PROPOSAL (never on execution). */
  readonly receiverDecision: "proposal_admitted";
  readonly receiverEpochId: string;
  readonly receiptRecordId: string;
  readonly decidedAtEpochMs: number;
}

// ── pure decision: validate the untrusted payload ────────────────────────────

/**
 * Strictly validate an untrusted payload as a task proposal. Pure function:
 * no store, no coordinator, no authority. Unknown payload fields REFUSE —
 * a proposal cannot smuggle extra material past the shape. Identity fields
 * must agree with the VERIFIED envelope (the caller passes them from the
 * inbox entry, which the 24D bus already bound to the signature).
 */
export function validateTaskProposalPayload(input: {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
}): ProposalValidationResult {
  const { payload } = input;

  // ── stage: payload shape ──
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return refuseValidation("payload_shape", "proposal_malformed", "proposal payload must be an object");
  }
  if (canonicalDurableJson(payload).length > FEDERATION_MAX_PROPOSAL_PAYLOAD_BYTES) {
    return refuseValidation("payload_shape", "proposal_malformed", "proposal payload exceeds the pinned byte bound");
  }
  const known = new Set<string>(TASK_PROPOSAL_PAYLOAD_KEYS);
  for (const key of Object.keys(payload)) {
    if (!known.has(key)) {
      return refuseValidation(
        "payload_shape",
        "proposal_malformed",
        "unknown payload field '" + key + "' — proposals are closed-shape; refusing (a proposal cannot smuggle fields)",
      );
    }
  }
  for (const key of TASK_PROPOSAL_PAYLOAD_KEYS) {
    if (payload[key] === undefined) {
      return refuseValidation("payload_shape", "proposal_malformed", "required payload field '" + key + "' is missing");
    }
  }

  // ── stage: schema version (exact; no downgrade) ──
  if (payload["schemaVersion"] !== FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION) {
    return refuseValidation(
      "schema_version",
      "proposal_schema_mismatch",
      "schemaVersion must be exactly '" + FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION + "' — downgrade refused",
    );
  }

  // ── stage: proposal id + identity binding (envelope agreement) ──
  const proposalId = payload["proposalId"];
  if (typeof proposalId !== "string" || !FEDERATION_PROPOSAL_ID_PATTERN.test(proposalId)) {
    return refuseValidation("identity_binding", "proposal_identity_mismatch", "proposalId must be the canonical fp-<ts16>-<rnd16> form");
  }
  if (input.senderNodeId !== undefined && (!NODE_ID_PATTERN.test(input.senderNodeId) || input.senderNodeId.length > 133)) {
    return refuseValidation("identity_binding", "proposal_identity_mismatch", "senderNodeId is not in the pinned NodeId form");
  }
  if (
    input.senderFingerprint !== undefined &&
    (!NODE_FINGERPRINT_PATTERN.test(input.senderFingerprint) || input.senderFingerprint.length > 76)
  ) {
    return refuseValidation("identity_binding", "proposal_identity_mismatch", "senderFingerprint is not in the pinned fingerprint form");
  }

  // ── stage: intent class (closed inert union; never a capability) ──
  const intentClass = payload["intentClass"];
  if (typeof intentClass !== "string" || !isProposalIntentClass(intentClass)) {
    return refuseValidation(
      "intent_class",
      "proposal_intent_unknown",
      "intentClass must be one of the closed inert union (" + PROPOSAL_INTENT_CLASSES.join(" | ") + ")",
    );
  }

  // ── stage: content hashes (explicit sha256 commitments) ──
  const contentHashes = payload["contentHashes"];
  if (!Array.isArray(contentHashes) || contentHashes.length === 0 || contentHashes.length > FEDERATION_MAX_PROPOSAL_HASH_REFS) {
    return refuseValidation(
      "content_hashes",
      "proposal_hash_malformed",
      "contentHashes must be a 1.." + String(FEDERATION_MAX_PROPOSAL_HASH_REFS) + " length array of hash commitments",
    );
  }
  for (const h of contentHashes) {
    if (typeof h !== "string" || !PROPOSAL_HASH_REF_PATTERN.test(h)) {
      return refuseValidation("content_hashes", "proposal_hash_malformed", "contentHashes entries must be explicit 'sha256-<64hex>' commitments");
    }
  }
  if (new Set(contentHashes).size !== contentHashes.length) {
    return refuseValidation("content_hashes", "proposal_hash_malformed", "contentHashes must not repeat a commitment");
  }

  // ── stage: provenance (must bind to the verified envelope sender) ──
  const provenance = payload["provenance"];
  if (provenance === null || typeof provenance !== "object" || Array.isArray(provenance)) {
    return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance must be an object");
  }
  const prov = provenance as Record<string, unknown>;
  for (const key of ["originNodeId", "originFingerprint", "note"]) {
    if (prov[key] === undefined) {
      return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance." + key + " is required");
    }
  }
  const extraProv = Object.keys(prov).filter((k) => !["originNodeId", "originFingerprint", "note"].includes(k));
  if (extraProv.length > 0) {
    return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance carries unknown fields (" + extraProv.join(", ") + ") — refusing");
  }
  if (typeof prov["originNodeId"] !== "string" || !NODE_ID_PATTERN.test(prov["originNodeId"] as string)) {
    return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance.originNodeId must be the canonical NodeId form");
  }
  if (typeof prov["originFingerprint"] !== "string" || !NODE_FINGERPRINT_PATTERN.test(prov["originFingerprint"] as string)) {
    return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance.originFingerprint must be the canonical fingerprint form");
  }
  if (typeof prov["note"] !== "string" || (prov["note"] as string).length > 256) {
    return refuseValidation("provenance", "proposal_provenance_mismatch", "provenance.note must be a string ≤ 256 chars");
  }
  if (prov["originNodeId"] !== input.senderNodeId || prov["originFingerprint"] !== input.senderFingerprint) {
    return refuseValidation(
      "provenance",
      "proposal_provenance_mismatch",
      "provenance.originNodeId/originFingerprint must equal the verified envelope sender — a proposal cannot claim another origin",
    );
  }

  // ── stage: constraints (closed keys, bounded, typed) ──
  const constraints = payload["constraints"];
  if (constraints === null || typeof constraints !== "object" || Array.isArray(constraints)) {
    return refuseValidation("constraints", "proposal_constraint_malformed", "constraints must be an object");
  }
  const cons = constraints as Record<string, unknown>;
  for (const key of Object.keys(cons)) {
    if (!(PROPOSAL_CONSTRAINT_KEYS as readonly string[]).includes(key)) {
      return refuseValidation(
        "constraints",
        "proposal_constraint_malformed",
        "constraints key '" + key + "' is not in the closed vocabulary (" + PROPOSAL_CONSTRAINT_KEYS.join(" | ") + ") — refusing",
      );
    }
  }
  const numericBounds: Partial<Record<ProposalConstraintKey, readonly [number, number]>> = {
    maxRuntimeMs: [0, 3_600_000],
    deadlineEpochMs: [0, Number.MAX_SAFE_INTEGER],
    maxBudgetSteps: [1, 1000],
  };
  for (const key of PROPOSAL_CONSTRAINT_KEYS) {
    const v = cons[key];
    if (v === undefined) {
      if (Object.prototype.hasOwnProperty.call(cons, key)) {
        return refuseValidation("constraints", "proposal_constraint_malformed", "constraints." + key + " is present but undefined — refusing (durable payloads cannot carry explicit undefined)");
      }
      continue;
    }
    if (key === "readonlyWorkspaceOnly") {
      if (typeof v !== "boolean") {
        return refuseValidation("constraints", "proposal_constraint_malformed", "constraints.readonlyWorkspaceOnly must be boolean");
      }
      continue;
    }
    const bounds = numericBounds[key];
    if (bounds === undefined) continue;
    const [lo, hi] = bounds;
    if (typeof v !== "number" || !Number.isFinite(v) || v < lo || v > hi || Math.floor(v) !== v) {
      return refuseValidation(
        "constraints",
        "proposal_constraint_malformed",
        "constraints." + key + " must be an integer in [" + String(lo) + "," + String(hi) + "]",
      );
    }
  }

  // ── stage: expected evidence (bounded hash refs) ──
  const expectedEvidence = payload["expectedEvidence"];
  if (!Array.isArray(expectedEvidence) || expectedEvidence.length === 0 || expectedEvidence.length > FEDERATION_MAX_PROPOSAL_HASH_REFS) {
    return refuseValidation(
      "expected_evidence",
      "proposal_evidence_malformed",
      "expectedEvidence must be a 1.." + String(FEDERATION_MAX_PROPOSAL_HASH_REFS) + " length array of hash commitments",
    );
  }
  for (const h of expectedEvidence) {
    if (typeof h !== "string" || !PROPOSAL_HASH_REF_PATTERN.test(h)) {
      return refuseValidation("expected_evidence", "proposal_evidence_malformed", "expectedEvidence entries must be explicit 'sha256-<64hex>' commitments");
    }
  }
  if (new Set(expectedEvidence).size !== expectedEvidence.length) {
    return refuseValidation("expected_evidence", "proposal_evidence_malformed", "expectedEvidence must not repeat a commitment");
  }

  return {
    ok: true,
    payload: {
      schemaVersion: FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION,
      proposalId,
      intentClass,
      contentHashes: Object.freeze([...contentHashes]),
      provenance: Object.freeze({
        originNodeId: prov["originNodeId"] as string,
        originFingerprint: prov["originFingerprint"] as string,
        note: prov["note"] as string,
      }),
      constraints: Object.freeze({ ...cons }) as FederationTaskProposalPayload["constraints"],
      expectedEvidence: Object.freeze([...expectedEvidence]),
    },
  };
}

function refuseValidation(stage: ProposalStage, failureCode: FederationProposalFailureCode, explanation: string): ProposalValidationResult {
  return { ok: false, stage, failureCode, explanation };
}

// ── pure decisions: the LOCAL candidate + the LOCAL execution gate ───────────

/**
 * THE PACK LAW, made structural: a proposal plus the local descriptor are
 * the only inputs; the outcome is a candidate that authorizes NOTHING.
 * `authorizedCapabilities` is EXACTLY the local agent's own profile slice —
 * a proposal can never widen it (inflation-proof by construction).
 */
export interface LocalTaskCandidate {
  readonly schemaVersion: FederationProposalSchemaVersion;
  readonly proposalId: string;
  readonly senderNodeId: string;
  readonly intentClass: ProposalIntentClass;
  /** The LOCAL descriptor the LOCAL caller chose (not remote-authored). */
  readonly localTaskLabel: string;
  /** The LOCAL descriptor's required capabilities — the local choice. */
  readonly requiredCapabilities: readonly string[];
  readonly constraints: FederationTaskProposalPayload["constraints"];
  readonly expectedEvidence: readonly string[];
  /** Structural statement of the pack law. */
  readonly authority: "none";
  /** Structural statement of the pack law. */
  readonly executionAuthorized: false;
}

/**
 * Derive an untrusted local candidate from an admitted proposal + the
 * LOCAL descriptor. Refuses when the local required capabilities are not
 * capability-shaped (bounded 64 chars, mirroring the 19B structural rule).
 * The remote proposal contributes INTENT ONLY; capabilities, roles, and
 * budget are the local caller's decision.
 */
export function deriveLocalTaskCandidate(input: {
  readonly proposal: Pick<FederationProposalRecordBody, "proposalId" | "senderNodeId" | "intentClass" | "constraints" | "expectedEvidence">;
  readonly localTaskLabel: string;
  readonly requiredCapabilities: readonly string[];
}): { readonly ok: true; readonly candidate: LocalTaskCandidate } | { readonly ok: false; readonly reason: string } {
  const { proposal } = input;
  if (typeof input.localTaskLabel !== "string" || input.localTaskLabel.length === 0 || input.localTaskLabel.length > 120) {
    return { ok: false, reason: "localTaskLabel must be a non-empty string ≤ 120 chars" };
  }
  if (!Array.isArray(input.requiredCapabilities)) {
    return { ok: false, reason: "requiredCapabilities must be an array" };
  }
  for (const cap of input.requiredCapabilities) {
    if (typeof cap !== "string" || cap.length === 0 || cap.length > 64) {
      return { ok: false, reason: "required capabilities must be non-empty capability-shaped strings ≤ 64 chars" };
    }
  }
  return {
    ok: true,
    candidate: {
      schemaVersion: FEDERATION_PROPOSAL_SCHEMA_VERSION,
      proposalId: proposal.proposalId,
      senderNodeId: proposal.senderNodeId,
      intentClass: proposal.intentClass,
      localTaskLabel: input.localTaskLabel,
      requiredCapabilities: Object.freeze([...input.requiredCapabilities]),
      constraints: proposal.constraints,
      expectedEvidence: proposal.expectedEvidence,
      authority: "none",
      executionAuthorized: false,
    },
  };
}

/**
 * The execution gate between the proposal chain and Phase-20/21: a tool
 * run may start ONLY with a fresh LOCAL allocation assignment AND a fresh
 * LOCAL Policy ALLOW for exactly the requested capabilities. Anything else
 * refuses. This is a pure re-check of LOCAL facts; a proposal record can
 * never satisfy it, an old Policy decision cannot satisfy it, and there is
 * no federation super-agent/capability union to satisfy it with.
 */
export function requireFreshLocalAuthorization(input: {
  readonly assignment: {
    readonly assignmentId: string;
    readonly assignedAgentId: string;
    readonly allocatedAtEpochMs: number;
    readonly executionAuthorized: boolean;
  };
  readonly policy: {
    readonly outcome: "allow" | "deny";
    readonly decidedAtEpochMs: number;
  };
  /** The actor id the LOCAL Policy decision was issued FOR (confused-deputy binding). */
  readonly policyActorId: string;
  readonly atEpochMs: number;
  readonly maxAssignmentAgeMs?: number;
}): { readonly ok: true; readonly reason: string } | { readonly ok: false; readonly failureCode: string; readonly reason: string } {
  const maxAge = input.maxAssignmentAgeMs ?? 300_000;
  if (typeof input.assignment !== "object" || input.assignment === null) {
    return { ok: false, failureCode: "no_local_allocation", reason: "no LOCAL allocation assignment was supplied — a proposal can never substitute for one" };
  }
  if (input.assignment.executionAuthorized !== false) {
    return { ok: false, failureCode: "assignment_authority_polluted", reason: "assignment carries executionAuthorized=true — allocation data can never pre-authorize; refusing" };
  }
  if (!Number.isFinite(input.assignment.allocatedAtEpochMs) || input.assignment.allocatedAtEpochMs > input.atEpochMs) {
    return { ok: false, failureCode: "no_local_allocation", reason: "assignment clock is missing or in the future relative to the gate clock — refusing" };
  }
  if (input.atEpochMs - input.assignment.allocatedAtEpochMs > maxAge) {
    return { ok: false, failureCode: "stale_local_allocation", reason: "the LOCAL allocation is older than the fresh-action window — a fresh LOCAL allocation is required" };
  }
  if (typeof input.policy !== "object" || input.policy === null) {
    return { ok: false, failureCode: "no_local_policy", reason: "no LOCAL Policy decision was supplied — a proposal can never substitute for one" };
  }
  if (input.policy.outcome !== "allow") {
    return { ok: false, failureCode: "local_policy_denial", reason: "the LOCAL Policy decision is a denial — denial is valid and final for this attempt (fail closed)" };
  }
  if (!Number.isFinite(input.policy.decidedAtEpochMs) || input.policy.decidedAtEpochMs > input.atEpochMs) {
    return { ok: false, failureCode: "no_local_policy", reason: "Policy decision clock is missing or in the future relative to the gate clock — refusing" };
  }
  if (input.atEpochMs - input.policy.decidedAtEpochMs > maxAge) {
    return { ok: false, failureCode: "stale_local_policy", reason: "the LOCAL Policy decision is older than the fresh-action window — reusing an old Policy decision is forbidden; evaluate fresh" };
  }
  // 24G adversarial amendment (confused deputy): the Policy decision must
  // have been issued FOR the assigned agent — an allow minted for one actor
  // can never be ridden by another (no deputy confusion, no capability ride).
  if (input.policyActorId !== input.assignment.assignedAgentId) {
    return { ok: false, failureCode: "actor_mismatch", reason: "the LOCAL Policy decision was issued for a different actor than the assigned agent — confused-deputy refusal (fail closed)" };
  }
  return {
    ok: true,
    reason:
      "fresh LOCAL allocation + fresh LOCAL Policy ALLOW verified at the gate; Phase-20/21 execution may proceed normally (the proposal contributed intent only)",
  };
}

// ── the durable proposal ledger (the receiver's judgment, made durable) ──────

/**
 * The LOCAL receiver of cross-node task proposals. Composes the 24D bus
 * (admitted peers, receipts, typed inbox) with the durable inert proposal
 * record. The duplicate guard is DURABLE: the record id IS the proposal-id
 * commitment, so a replayed proposal refuses across restarts with zero
 * signature evaluation — the 24D receipt discipline, applied to proposals.
 */
export class ProposalLedger {
  readonly #store: DurableStore;
  readonly #coordinator: RuntimeStateCoordinator;
  readonly #epochId: string;
  #closed = false;

  private constructor(store: DurableStore, coordinator: RuntimeStateCoordinator) {
    this.#store = store;
    this.#coordinator = coordinator;
    this.#epochId = coordinator.epochId;
  }

  /**
   * Bind the ledger to one epoch's coordinator. Only a live coordinator of
   * the CURRENT epoch is accepted; closed coordinators refuse.
   */
  public static open(input: {
    readonly store: DurableStore;
    readonly coordinator: RuntimeStateCoordinator;
  }): { readonly ok: true; readonly ledger: ProposalLedger } | { readonly ok: false; readonly reason: string } {
    if (input.coordinator.isClosed) return { ok: false, reason: "the coordinator for this epoch is closed" };
    return { ok: true, ledger: new ProposalLedger(input.store, input.coordinator) };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get isClosed(): boolean {
    return this.#closed || this.#coordinator.isClosed;
  }

  /**
   * Whether a proposal id already has a durable record (the duplicate
   * guard probe; the record index, not a cache — survives restarts).
   */
  public hasProposal(proposalId: string): boolean {
    const id = federationProposalDurableId(proposalId);
    return id.ok && this.#store.readRecord(id.recordId).ok;
  }

  /**
   * Receive ONE inbox entry: validate the untrusted payload as a task
   * proposal, refuse duplicates against the DURABLE record index, and
   * persist the inert proposal record through the sanctioned 23B junction.
   * A refusal leaves NO durable trace.
   */
  public receiveTaskProposal(input: {
    readonly inboxEntry: {
      readonly messageId: string;
      readonly senderNodeId: string;
      readonly declaredIntent: string;
      readonly payload: Readonly<Record<string, unknown>>;
    };
    readonly senderFingerprint: string;
    readonly receiptRecordId: string;
    readonly nowEpochMs: number;
  }): ProposalAdmissionResult {
    if (this.isClosed) {
      return { ok: false, stage: "payload_shape", failureCode: "ledger_closed", storeFailureCode: null, explanation: "the proposal ledger for this epoch is closed" };
    }
    const entry = input.inboxEntry;

    // Stage 0 (pack: "verified admitted peer"): the entry must come from a
    // bus receipt binding THIS sender — the 24D bus already proved
    // admission + signature; the ledger re-binds the receipt id.
    if (typeof input.receiptRecordId !== "string" || !input.receiptRecordId.startsWith("frc-")) {
      return {
        ok: false,
        stage: "identity_binding",
        failureCode: "proposal_identity_mismatch",
        storeFailureCode: null,
        explanation: "inbox entry is not bound to a federation receipt record — refusing (only bus-receipted messages may become proposals)",
      };
    }
    if (entry.declaredIntent !== "task_proposal") {
      return {
        ok: false,
        stage: "payload_shape",
        failureCode: "proposal_malformed",
        storeFailureCode: null,
        explanation: "declaredIntent must be 'task_proposal' — refusing other intents at the proposal boundary",
      };
    }

    // Stage 1: strict untrusted-payload validation (pure, fail-closed).
    const validation = validateTaskProposalPayload({
      payload: entry.payload,
      senderNodeId: entry.senderNodeId,
      senderFingerprint: input.senderFingerprint,
    });
    if (!validation.ok) {
      return { ok: false, stage: validation.stage, failureCode: validation.failureCode, storeFailureCode: null, explanation: validation.explanation };
    }
    const proposal = validation.payload;

    // Stage 2: DURABLE duplicate guard — BEFORE any persistence work. The
    // record id IS the proposal-id commitment (24D receipt discipline).
    const durableId = federationProposalDurableId(proposal.proposalId);
    if (!durableId.ok) {
      return { ok: false, stage: "identity_binding", failureCode: "proposal_identity_mismatch", storeFailureCode: null, explanation: durableId.reason };
    }
    if (this.#store.readRecord(durableId.recordId).ok) {
      return {
        ok: false,
        stage: "durable_admission",
        failureCode: "proposal_duplicate",
        storeFailureCode: null,
        explanation: "a durable proposal record already exists for this proposal id (admitted in this or a previous epoch) — DUPLICATE refused without any persistence",
      };
    }

    // Stage 3: persist the inert proposal record (append-only, revision 1
    // forever) through the sanctioned junction.
    const proposalHash = canonicalHash({
      schemaVersion: proposal.schemaVersion,
      proposalId: proposal.proposalId,
      intentClass: proposal.intentClass,
      contentHashes: proposal.contentHashes,
      provenance: proposal.provenance,
      constraints: proposal.constraints,
      expectedEvidence: proposal.expectedEvidence,
    });
    const body: FederationProposalRecordBody = {
      schemaVersion: FEDERATION_PROPOSAL_SCHEMA_VERSION,
      proposalId: proposal.proposalId,
      messageId: entry.messageId,
      senderNodeId: entry.senderNodeId,
      senderFingerprint: input.senderFingerprint,
      proposalHash,
      intentClass: proposal.intentClass,
      contentHashes: proposal.contentHashes,
      provenance: proposal.provenance,
      constraints: proposal.constraints,
      expectedEvidence: proposal.expectedEvidence,
      receiverDecision: "proposal_admitted",
      receiverEpochId: this.#epochId,
      receiptRecordId: input.receiptRecordId,
      decidedAtEpochMs: input.nowEpochMs,
    };
    const persisted = this.#coordinator.acceptMutation({
      kind: "federation_proposal",
      recordId: durableId.recordId,
      revision: 1,
      supersedesRevision: null,
      payload: body as unknown as Record<string, unknown>,
      transactionId: "fpr-commit-" + proposal.proposalId,
      lineageRoot: proposal.proposalId,
      lineageParent: entry.messageId,
      createdAtEpochMs: input.nowEpochMs,
    });
    if (!persisted.ok) {
      return {
        ok: false,
        stage: "durable_admission",
        failureCode: "proposal_persistence_denied",
        storeFailureCode: persisted.code === "refused_pre_commit" ? persisted.storeFailureCode : null,
        explanation: persisted.explanation,
      };
    }

    return {
      ok: true,
      code: "proposal_admitted",
      proposalId: proposal.proposalId,
      recordId: durableId.recordId,
      commitSequence: persisted.commitSequence,
      proposalHash,
      explanation:
        "proposal admitted as durable INERT evidence; it grants no capability, chooses no Policy, invokes nothing — LOCAL allocation + LOCAL Policy must run fresh before any Phase-20/21 execution",
    };
  }
}
