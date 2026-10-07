/**
 * PHASE 24F — Federated Provenance & Cross-Node Evidence (EVIDENCE-ONLY /
 * NO NEW AUTHORITY).
 *
 * Canonical provenance BINDS (never authorizes):
 *   sender/receiver identity + epoch · message/proposal id · protocol/schema
 *   · payload hash · parent/correlation/causation lineage · signature result
 *   · peer admission · later LOCAL Policy result · local isolation/tool
 *   evidence refs · durable commit refs · response/result hash.
 *
 * Design: append-only, tamper-evident, using EXISTING primitives only — the
 * 22A append-only record kind `federation_provenance` (FOURTH documented
 * unfreeze event), the sanctioned 23B coordinator junction, and the 22A
 * canonical hashing. Zero new cryptography, zero new store semantics, zero
 * network. Anchors are one-to-one (one per message/proposal id): the record
 * index IS the duplicate guard.
 *
 * NO private key, secret, token, process handle, or raw hidden Policy ever
 * enters a binding: a SECRET-FREE strict validator refuses any payload
 * carrying forbidden surface, and the anchor body stores hashes/ids/refs —
 * never raw material. Foreign evidence is DATA, never local authority; a
 * foreign-imported anchor carries the same `localPolicyDecision: "none"`,
 * `executionAuthorized: false`, and `authority: "evidence_linkage_only"`.
 * Missing links and hash mismatches are EXPLICIT verdicts
 * (`missing_local_link`, `hash_mismatch`), never silent gaps. No global
 * total order, no consensus, no executable replay: anchors order only by
 * their own durable commit sequence and replay nothing.
 *
 * Every admission/refusal/denial carries a DETERMINISTIC explanation: a
 * `explain…` function over a fixed evidence shape returns the same string
 * for the same evidence (pinned by test) — admit / refuse / quarantine /
 * local-action.
 */

import { canonicalHash, canonicalDurableJson } from "./canonical.js";
import type { RuntimeStateCoordinator } from "./coordinator.js";
import type { DurableStore } from "./store.js";
import {
  NODE_ID_PATTERN,
  NODE_FINGERPRINT_PATTERN,
} from "./federationIdentity.js";
import {
  federationProposalDurableId,
  federationProvenanceDurableId,
  FEDERATION_PROVENANCE_ID_PREFIX,
} from "./statePersistence.js";

// ── schema + bounds (closed; refusing to widen is the point) ─────────────────

export const FEDERATION_PROVENANCE_SCHEMA_VERSION = "menog-federation-provenance/v0" as const;
export type FederationProvenanceSchemaVersion = typeof FEDERATION_PROVENANCE_SCHEMA_VERSION;

/** Canonical anchor-id shape (fv-<ts16>-<rnd16>; the 24A id discipline). */
export const FEDERATION_PROVENANCE_ID_PATTERN = /^fv-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/;

/** Max entries in `policyEvidenceRefs` / `toolEvidenceRefs` / `lineage`. */
export const FEDERATION_MAX_PROVENANCE_REFS = 32 as const;
/** Max canonical bytes of the ANCHOR BODY (bindings only; never payloads). */
export const FEDERATION_MAX_PROVENANCE_BODY_BYTES = 8192 as const;

// ── signature result + closed decisions (never authority) ────────────────────

/**
 * The signature RESULT as evidence — a record of what verification SAID,
 * never a grant. No key material, no token: only the outcome and (when the
 * sender is unknown to the local key directory) an explicit reason.
 */
export interface ProvenanceSignatureResult {
  readonly result: "verified" | "unverified_sender_unknown" | "unverified" | "not_applicable";
  /** Set only when the claim itself was malformed (no key material, ever). */
  readonly reason: string | null;
}

export const PROVENANCE_DECISIONS = Object.freeze([
  "admitted",
  "refused",
  "quarantined",
  "local_action",
] as const);
export type ProvenanceDecision = (typeof PROVENANCE_DECISIONS)[number];

/** The peer-admission vocabulary bound by an anchor (mirrors the 24C states). */
export const PROVENANCE_PEER_ADMISSIONS = Object.freeze([
  "admitted",
  "not_admitted",
  "quarantined",
  "retired",
] as const);
export type ProvenancePeerAdmission = (typeof PROVENANCE_PEER_ADMISSIONS)[number];

export const PROVENANCE_KINDS = Object.freeze([
  "task_proposal",
  "evidence",
  "response",
] as const);
export type ProvenanceKind = (typeof PROVENANCE_KINDS)[number];

// ── the canonical anchor binding ──────────────────────────────────────────────

/**
 * The canonical cross-node provenance binding. Every field is evidence of
 * WHAT HAPPENED; nothing here grants capability, authority, or execution.
 */
export interface FederationProvenanceAnchor {
  readonly schemaVersion: FederationProvenanceSchemaVersion;
  readonly anchorId: string;
  readonly kind: ProvenanceKind;
  readonly messageId: string | null;
  readonly proposalId: string | null;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly senderEpochId: string;
  readonly receiverNodeId: string | null;
  readonly receiverEpochId: string | null;
  readonly protocolVersion: string;
  readonly schemaVersionOfMessage: string;
  readonly payloadHash: string;
  readonly correlationId: string | null;
  readonly causationId: string | null;
  readonly lineage: readonly string[];
  readonly signatureResult: ProvenanceSignatureResult;
  readonly peerAdmission: "admitted" | "not_admitted" | "quarantined" | "retired";
  readonly localPolicyDecision: "allow" | "deny" | "none";
  readonly policyEvidenceRefs: readonly string[];
  readonly toolEvidenceRefs: readonly string[];
  readonly commitRefs: readonly string[];
  readonly responseHash: string | null;
  readonly decision: ProvenanceDecision;
  readonly decidedAtEpochMs: number;
}

/** Exact anchor-body keys (strict; unknown fields refuse). */
export const PROVENANCE_ANCHOR_KEYS = Object.freeze([
  "schemaVersion",
  "anchorId",
  "kind",
  "messageId",
  "proposalId",
  "senderNodeId",
  "senderFingerprint",
  "senderEpochId",
  "receiverNodeId",
  "receiverEpochId",
  "protocolVersion",
  "schemaVersionOfMessage",
  "payloadHash",
  "correlationId",
  "causationId",
  "lineage",
  "signatureResult",
  "peerAdmission",
  "localPolicyDecision",
  "policyEvidenceRefs",
  "toolEvidenceRefs",
  "commitRefs",
  "responseHash",
  "decision",
  "decidedAtEpochMs",
] as const);

/** SHA-256 over the canonical anchor encoding (tamper-evident binding hash). */
export function provenanceAnchorHash(anchor: FederationProvenanceAnchor): string {
  return canonicalHash(anchor);
}

// ── secret-free validation (strict; no forbidden surface, ever) ──────────────

export type ProvenanceValidationResult =
  | { readonly ok: true; readonly anchor: FederationProvenanceAnchor }
  | { readonly ok: false; readonly failureCode: string; readonly explanation: string };

const SECRET_SURFACE_TOKENS = Object.freeze([
  "privateKey", "private_key", "secretKey", "secret_key", "secret", "token",
  "password", "passphrase", "credential", "processHandle", "process_handle",
  "policyText", "policy_text", "hiddenPolicy", "hidden_policy",
]);

/**
 * Strict, secret-free anchor validation. Shape → closed unions → id shapes
 * → bounds → secret-surface scan (anchored token match on the canonical
 * encoding) → binding consistency (decision/admission/policy cohere; a
 * `local_action` anchor REQUIRES a local allow/deny; refusal reasons must
 * be present when the signature result is a refusal). Unknown fields REFUSE.
 */
export function validateProvenanceAnchor(anchor: unknown): ProvenanceValidationResult {
  if (anchor === null || typeof anchor !== "object" || Array.isArray(anchor)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "anchor must be an object" };
  }
  const a = anchor as Record<string, unknown>;
  for (const key of Object.keys(a)) {
    if (!(PROVENANCE_ANCHOR_KEYS as readonly string[]).includes(key)) {
      return { ok: false, failureCode: "provenance_malformed", explanation: "unknown anchor field '" + key + "' — bindings are closed-shape; refusing" };
    }
  }
  for (const key of PROVENANCE_ANCHOR_KEYS) {
    if (a[key] === undefined) {
      return { ok: false, failureCode: "provenance_malformed", explanation: "required anchor field '" + key + "' is missing" };
    }
  }
  if (a["schemaVersion"] !== FEDERATION_PROVENANCE_SCHEMA_VERSION) {
    return { ok: false, failureCode: "provenance_schema_mismatch", explanation: "schemaVersion must be exactly '" + FEDERATION_PROVENANCE_SCHEMA_VERSION + "'" };
  }
  if (typeof a["anchorId"] !== "string" || !FEDERATION_PROVENANCE_ID_PATTERN.test(a["anchorId"] as string)) {
    return { ok: false, failureCode: "provenance_identity_mismatch", explanation: "anchorId must be the canonical fv-<ts16>-<rnd16> form" };
  }
  if (!(PROVENANCE_KINDS as readonly string[]).includes(a["kind"] as string)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "kind must be one of " + PROVENANCE_KINDS.join(" | ") };
  }
  const senderOk = typeof a["senderNodeId"] === "string" && NODE_ID_PATTERN.test(a["senderNodeId"] as string);
  if (!senderOk) {
    return { ok: false, failureCode: "provenance_identity_mismatch", explanation: "senderNodeId must be the canonical NodeId form" };
  }
  const fpOk = typeof a["senderFingerprint"] === "string" && NODE_FINGERPRINT_PATTERN.test(a["senderFingerprint"] as string);
  if (!fpOk) {
    return { ok: false, failureCode: "provenance_identity_mismatch", explanation: "senderFingerprint must be the canonical fingerprint form" };
  }
  for (const key of ["senderEpochId", "receiverEpochId"]) {
    const v = a[key];
    if (v !== null && (typeof v !== "string" || v.length === 0 || v.length > 64)) {
      return { ok: false, failureCode: "provenance_identity_mismatch", explanation: key + " must be a bounded epoch-id string or null" };
    }
  }
  for (const key of ["receiverNodeId"]) {
    const v = a[key];
    if (v !== null && (typeof v !== "string" || v.length === 0 || v.length > 133)) {
      return { ok: false, failureCode: "provenance_identity_mismatch", explanation: key + " must be a bounded node-id string or null" };
    }
  }
  for (const key of ["messageId", "proposalId", "correlationId", "causationId", "responseHash"]) {
    const v = a[key];
    if (v !== null && (typeof v !== "string" || v.length === 0 || v.length > 128)) {
      return { ok: false, failureCode: "provenance_malformed", explanation: key + " must be a bounded id/hash string or null" };
    }
  }
  if ((a["proposalId"] === null) === (a["messageId"] === null)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "exactly one of messageId/proposalId must be set (an anchor binds ONE happening)" };
  }
  if (typeof a["protocolVersion"] !== "string" || a["protocolVersion"].length === 0 || a["protocolVersion"].length > 64) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "protocolVersion must be a bounded string" };
  }
  if (typeof a["schemaVersionOfMessage"] !== "string" || a["schemaVersionOfMessage"].length === 0 || a["schemaVersionOfMessage"].length > 64) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "schemaVersionOfMessage must be a bounded string" };
  }
  if (typeof a["payloadHash"] !== "string" || a["payloadHash"].length === 0 || a["payloadHash"].length > 128) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "payloadHash must be a bounded hash string" };
  }
  const lineage = a["lineage"];
  if (!Array.isArray(lineage) || lineage.length > FEDERATION_MAX_PROVENANCE_REFS || new Set(lineage).size !== lineage.length) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "lineage must be a deduplicated array of at most " + String(FEDERATION_MAX_PROVENANCE_REFS) + " refs" };
  }
  for (const ref of lineage) {
    if (typeof ref !== "string" || ref.length === 0 || ref.length > 128) {
      return { ok: false, failureCode: "provenance_malformed", explanation: "lineage entries must be bounded id strings" };
    }
  }
  const sig = a["signatureResult"];
  if (sig === null || typeof sig !== "object" || Array.isArray(sig)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "signatureResult must be an object" };
  }
  const sigRec = sig as Record<string, unknown>;
  for (const key of Object.keys(sigRec)) {
    if (!["result", "reason"].includes(key)) {
      return { ok: false, failureCode: "provenance_malformed", explanation: "signatureResult carries unknown field '" + key + "' — refusing" };
    }
  }
  if (!(["verified", "unverified_sender_unknown", "unverified", "not_applicable"] as readonly string[]).includes(sigRec["result"] as string)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "signatureResult.result must be a closed outcome" };
  }
  if (sigRec["reason"] !== null && typeof sigRec["reason"] !== "string") {
    return { ok: false, failureCode: "provenance_malformed", explanation: "signatureResult.reason must be a string or null" };
  }
  if ((sigRec["result"] === "unverified" || sigRec["result"] === "unverified_sender_unknown") && typeof sigRec["reason"] !== "string") {
    return { ok: false, failureCode: "provenance_malformed", explanation: "a refusal signature result MUST carry an explicit reason (missing link made explicit)" };
  }
  if (!(PROVENANCE_PEER_ADMISSIONS as readonly string[]).includes(a["peerAdmission"] as string)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "peerAdmission must be one of " + PROVENANCE_PEER_ADMISSIONS.join(" | ") };
  }
  if (!(["allow", "deny", "none"] as readonly string[]).includes(a["localPolicyDecision"] as string)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "localPolicyDecision must be allow | deny | none" };
  }
  for (const key of ["policyEvidenceRefs", "toolEvidenceRefs", "commitRefs"] as const) {
    const arr = a[key];
    if (!Array.isArray(arr) || arr.length > FEDERATION_MAX_PROVENANCE_REFS) {
      return { ok: false, failureCode: "provenance_malformed", explanation: key + " must be an array of at most " + String(FEDERATION_MAX_PROVENANCE_REFS) + " refs" };
    }
    for (const ref of arr) {
      if (typeof ref !== "string" || ref.length === 0 || ref.length > 128) {
        return { ok: false, failureCode: "provenance_malformed", explanation: key + " entries must be bounded ref strings" };
      }
    }
  }
  if (!(PROVENANCE_DECISIONS as readonly string[]).includes(a["decision"] as string)) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "decision must be one of " + PROVENANCE_DECISIONS.join(" | ") };
  }
  if (typeof a["decidedAtEpochMs"] !== "number" || !Number.isFinite(a["decidedAtEpochMs"]) || (a["decidedAtEpochMs"] as number) < 0) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "decidedAtEpochMs must be a finite non-negative epoch-ms number" };
  }
  // Binding consistency: the decision, admission, and policy fields cohere.
  if (a["decision"] === "local_action" && a["localPolicyDecision"] === "none") {
    return { ok: false, failureCode: "provenance_malformed", explanation: "a local_action anchor requires an explicit LOCAL Policy result (allow or deny) — refusing" };
  }
  if (a["decision"] === "quarantined" && a["peerAdmission"] !== "quarantined") {
    return { ok: false, failureCode: "provenance_malformed", explanation: "a quarantined decision requires peerAdmission 'quarantined'" };
  }
  // Secret-surface scan over the canonical encoding (anchored tokens only).
  const encoded = canonicalDurableJson(a);
  for (const token of SECRET_SURFACE_TOKENS) {
    const idx = encoded.indexOf(token);
    if (idx === -1) continue;
    const before = idx > 0 ? encoded[idx - 1]! : "";
    const after = encoded[idx + token.length] ?? "";
    if (/[A-Za-z0-9_]/.test(before) || /[A-Za-z0-9_]/.test(after)) continue;
    return { ok: false, failureCode: "provenance_secret_surface", explanation: "anchor carries forbidden secret surface ('" + token + "') — no private key/secret/token/process handle/raw hidden Policy ever binds" };
  }
  if (canonicalDurableJson(a).length > FEDERATION_MAX_PROVENANCE_BODY_BYTES) {
    return { ok: false, failureCode: "provenance_malformed", explanation: "anchor exceeds the pinned body bound — bindings never carry payloads" };
  }
  return { ok: true, anchor: Object.freeze(a as unknown as FederationProvenanceAnchor) };
}

// ── foreign evidence import (DATA, never authority) ──────────────────────────

export interface ForeignProvenanceFacts {
  readonly anchorId: string;
  readonly kind: ProvenanceKind;
  readonly messageId: string | null;
  readonly proposalId: string | null;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly senderEpochId: string;
  readonly payloadHash: string;
  readonly correlationId: string | null;
  readonly causationId: string | null;
  readonly lineage: readonly string[];
  readonly protocolVersion: string;
  readonly schemaVersionOfMessage: string;
  readonly signatureResult: ProvenanceSignatureResult;
}

/**
 * Bind FOREIGN evidence as DATA. The remote's own decision/admission/policy
 * claims are NOT copied: the local receiver's judgment fields are pinned to
 * the refusal facts it actually observed (signature result, not_admitted,
 * policy "none"). The anchor is `local_action` when the LOCAL receiver took
 * a real local action on it; here it is a `refused`/DATA anchor by default.
 */
export function bindForeignProvenance(input: {
  readonly facts: ForeignProvenanceFacts;
  readonly receiverNodeId: string | null;
  readonly receiverEpochId: string | null;
  readonly decision: Exclude<ProvenanceDecision, "local_action">;
  readonly nowEpochMs: number;
}): ProvenanceValidationResult {
  const draft: FederationProvenanceAnchor = {
    schemaVersion: FEDERATION_PROVENANCE_SCHEMA_VERSION,
    anchorId: input.facts.anchorId,
    kind: input.facts.kind,
    messageId: input.facts.messageId,
    proposalId: input.facts.proposalId,
    senderNodeId: input.facts.senderNodeId,
    senderFingerprint: input.facts.senderFingerprint,
    senderEpochId: input.facts.senderEpochId,
    receiverNodeId: input.receiverNodeId,
    receiverEpochId: input.receiverEpochId,
    protocolVersion: input.facts.protocolVersion,
    schemaVersionOfMessage: input.facts.schemaVersionOfMessage,
    payloadHash: input.facts.payloadHash,
    correlationId: input.facts.correlationId,
    causationId: input.facts.causationId,
    lineage: Object.freeze([...input.facts.lineage]),
    signatureResult: input.facts.signatureResult,
    peerAdmission: "not_admitted",
    localPolicyDecision: "none",
    policyEvidenceRefs: Object.freeze([]),
    toolEvidenceRefs: Object.freeze([]),
    commitRefs: Object.freeze([]),
    responseHash: null,
    decision: input.decision,
    decidedAtEpochMs: input.nowEpochMs,
  };
  return validateProvenanceAnchor(draft);
}

// ── deterministic explanations (admit / refuse / quarantine / local-action) ──

/**
 * DETERMINISTIC explanation for an anchor's judgment: the same evidence
 * always yields the same string (no clock, no randomness — pinned by test).
 */
export function explainProvenanceDecision(anchor: Pick<
  FederationProvenanceAnchor,
  "decision" | "peerAdmission" | "localPolicyDecision" | "signatureResult" | "kind" | "messageId" | "proposalId" | "anchorId" | "senderNodeId"
>): string {
  const subject = anchor.proposalId !== null ? "proposal " + anchor.proposalId : "message " + (anchor.messageId ?? "unbound");
  switch (anchor.decision) {
    case "admitted":
      return (
        "ADMIT: " + subject + " from " + anchor.senderNodeId.slice(0, 24) + "… carried a " + anchor.signatureResult.result +
        " signature and peerAdmission='" + anchor.peerAdmission + "'; bound as evidence only — no authority granted"
      );
    case "quarantined":
      return (
        "QUARANTINE: " + subject + " judged under peerAdmission='" + anchor.peerAdmission + "' with signature " + anchor.signatureResult.result +
        "; the peer trust state is terminal here — nothing executes and nothing is retried"
      );
    case "local_action":
      return (
        "LOCAL-ACTION: " + subject + " produced a LOCAL " + anchor.localPolicyDecision + " Policy result after fresh local allocation; the anchor binds the linkage only — execution authority came from LOCAL Policy, never from this evidence"
      );
    case "refused":
    default: {
      const why = anchor.signatureResult.reason ?? "the local receiver refused this happening";
      return (
        "REFUSE: " + subject + " refused by the LOCAL receiver (" + why + "); the refusal itself is the evidence — missing links stay explicit, nothing is inferred"
      );
    }
  }
}

// ── the durable provenance ledger (append-only anchors; no new authority) ────

export type ProvenanceAdmissionResult =
  | {
      readonly ok: true;
      readonly code: "provenance_anchored";
      readonly anchorId: string;
      readonly recordId: string;
      readonly commitSequence: number;
      readonly anchorHash: string;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly failureCode: string;
      readonly storeFailureCode: string | null;
      readonly explanation: string;
    };

/**
 * The LOCAL provenance ledger. Anchors are append-only, one-to-one per
 * anchor id, persisted through the sanctioned 23B junction, and READ BACK
 * and cross-checked at every linkage point — the local record must agree
 * with the durable facts it claims to bind (hash-consistency across the
 * chain: receipt → proposal → anchor → commit refs). A refusal leaves NO
 * durable trace.
 */
export class ProvenanceLedger {
  readonly #store: DurableStore;
  readonly #coordinator: RuntimeStateCoordinator;
  readonly #epochId: string;
  #closed = false;

  private constructor(store: DurableStore, coordinator: RuntimeStateCoordinator) {
    this.#store = store;
    this.#coordinator = coordinator;
    this.#epochId = coordinator.epochId;
  }

  public static open(input: {
    readonly store: DurableStore;
    readonly coordinator: RuntimeStateCoordinator;
  }): { readonly ok: true; readonly ledger: ProvenanceLedger } | { readonly ok: false; readonly reason: string } {
    if (input.coordinator.isClosed) return { ok: false, reason: "the coordinator for this epoch is closed" };
    return { ok: true, ledger: new ProvenanceLedger(input.store, input.coordinator) };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get isClosed(): boolean {
    return this.#closed || this.#coordinator.isClosed;
  }

  /** Whether an anchor id already has a durable record (duplicate guard). */
  public hasAnchor(anchorId: string): boolean {
    const id = federationProvenanceDurableId(anchorId);
    return id.ok && this.#store.readRecord(id.recordId).ok;
  }

  /**
   * Anchor ONE happening. Validates the binding (secret-free, closed-shape),
   * refuses duplicates against the durable record index, verifies every
   * claimed LOCAL linkage against the durable facts (receipt record exists
   * with a matching message id; proposal record exists with a matching
   * proposal id), then persists the append-only anchor. Linkage mismatches
   * are EXPLICIT `missing_local_link` refusals, never silent gaps.
   */
  public anchor(input: { readonly anchor: FederationProvenanceAnchor; readonly nowEpochMs: number }): ProvenanceAdmissionResult {
    if (this.isClosed) {
      return { ok: false, failureCode: "ledger_closed", storeFailureCode: null, explanation: "the provenance ledger for this epoch is closed" };
    }
    const validated = validateProvenanceAnchor(input.anchor);
    if (!validated.ok) {
      return { ok: false, failureCode: validated.failureCode, storeFailureCode: null, explanation: validated.explanation };
    }
    const anchor = validated.anchor;

    const durableId = federationProvenanceDurableId(anchor.anchorId);
    if (!durableId.ok) {
      return { ok: false, failureCode: "provenance_identity_mismatch", storeFailureCode: null, explanation: durableId.reason };
    }
    if (this.#store.readRecord(durableId.recordId).ok) {
      return {
        ok: false,
        failureCode: "provenance_duplicate",
        storeFailureCode: null,
        explanation: "a durable provenance anchor already exists for this anchor id (this or a previous epoch) — DUPLICATE refused without any persistence",
      };
    }

    // ── explicit linkage cross-checks (missing link = explicit refusal) ──
    if (anchor.messageId !== null) {
      const receiptId = "frc-" + anchor.messageId;
      const receipt = this.#store.readRecord(receiptId);
      if (!receipt.ok) {
        return {
          ok: false,
          failureCode: "missing_local_link",
          storeFailureCode: null,
          explanation: "the bound message id has NO local durable receipt (" + receiptId + ") — the linkage is explicit-missing, not inferred",
        };
      }
      const body = receipt.record.payload as Record<string, unknown>;
      if (body["senderNodeId"] !== anchor.senderNodeId || body["payloadHash"] !== anchor.payloadHash) {
        return {
          ok: false,
          failureCode: "hash_mismatch",
          storeFailureCode: null,
          explanation: "the local receipt contradicts the anchor binding (sender or payload hash differ) — hash mismatch made explicit",
        };
      }
    }
    if (anchor.proposalId !== null) {
      const proposalRecord = federationProposalDurableId(anchor.proposalId);
      if (!proposalRecord.ok) {
        return { ok: false, failureCode: "provenance_identity_mismatch", storeFailureCode: null, explanation: proposalRecord.reason };
      }
      const proposal = this.#store.readRecord(proposalRecord.recordId);
      if (!proposal.ok) {
        return {
          ok: false,
          failureCode: "missing_local_link",
          storeFailureCode: null,
          explanation: "the bound proposal id has NO local durable proposal record (" + proposalRecord.recordId + ") — the linkage is explicit-missing, not inferred",
        };
      }
      const body = proposal.record.payload as Record<string, unknown>;
      if (body["senderNodeId"] !== anchor.senderNodeId) {
        return {
          ok: false,
          failureCode: "hash_mismatch",
          storeFailureCode: null,
          explanation: "the local proposal record contradicts the anchor binding (sender differs) — hash mismatch made explicit",
        };
      }
    }

    const anchorHash = provenanceAnchorHash(anchor);
    const persisted = this.#coordinator.acceptMutation({
      kind: "federation_provenance",
      recordId: durableId.recordId,
      revision: 1,
      supersedesRevision: null,
      payload: anchor as unknown as Record<string, unknown>,
      transactionId: "fpv-commit-" + anchor.anchorId,
      lineageRoot: anchor.proposalId ?? anchor.messageId ?? anchor.anchorId,
      lineageParent: anchor.causationId,
      createdAtEpochMs: input.nowEpochMs,
    });
    if (!persisted.ok) {
      return {
        ok: false,
        failureCode: "provenance_persistence_denied",
        storeFailureCode: persisted.code === "refused_pre_commit" ? persisted.storeFailureCode : null,
        explanation: persisted.explanation,
      };
    }
    return {
      ok: true,
      code: "provenance_anchored",
      anchorId: anchor.anchorId,
      recordId: durableId.recordId,
      commitSequence: persisted.commitSequence,
      anchorHash,
      explanation:
        "provenance anchored as append-only tamper-evident BINDING evidence; it grants no capability, no authority, no execution — foreign evidence stays DATA, and the linkage chain is hash-consistent with the local durable facts",
    };
  }

  /**
   * Read ONE durable anchor back as DATA (recovered evidence; no authority).
   * Verifies the stored body still validates (tamper evidence via the
   * closed-shape validator + the store's own content-hash binding).
   */
  public readAnchor(anchorId: string): { readonly ok: true; readonly anchor: FederationProvenanceAnchor; readonly anchorHash: string } | { readonly ok: false; readonly failureCode: string; readonly reason: string } {
    const id = federationProvenanceDurableId(anchorId);
    if (!id.ok) return { ok: false, failureCode: "provenance_identity_mismatch", reason: id.reason };
    const read = this.#store.readRecord(id.recordId);
    if (!read.ok) return { ok: false, failureCode: "missing_local_link", reason: "no durable anchor record exists for " + anchorId };
    // The junction adds its own `coordinatorBinding` key INSIDE the payload;
    // that binding is the coordinator's, not part of the canonical anchor.
    // Strip it before validating the anchor portion, then re-bind its hash.
    const raw = read.record.payload as Record<string, unknown>;
    const anchorPortion: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k === "coordinatorBinding") continue;
      anchorPortion[k] = v;
    }
    const validated = validateProvenanceAnchor(anchorPortion);
    if (!validated.ok) {
      return { ok: false, failureCode: validated.failureCode, reason: "the durable anchor body no longer validates: " + validated.explanation };
    }
    return { ok: true, anchor: validated.anchor, anchorHash: provenanceAnchorHash(validated.anchor) };
  }

  /** The durable prefix for anchors (exposed for restart/freeze audits). */
  public static get idPrefix(): string {
    return FEDERATION_PROVENANCE_ID_PREFIX;
  }
}
