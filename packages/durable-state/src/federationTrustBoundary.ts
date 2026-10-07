/**
 * PHASE 25A — Operational Federation Threat Model & Trust Boundary
 * (CONTRACT-FIRST / NO NETWORK / NO EXECUTION API / NO NEW AUTHORITY).
 *
 * This module models the OPERATIONAL trust boundary around the frozen
 * Phase-24 federation foundation: the local operator, the runtime epoch,
 * identity key material, peer identity/trust, the key-storage boundary,
 * ingress, egress, durable evidence, Policy, execution, and restart/
 * recovery. It defines a CLOSED operational-risk vocabulary and pure,
 * deterministic, fail-closed decisions about what each boundary plane may
 * and may not do. It implements no transport, no sockets, no discovery,
 * no crypto, no store access, and no execution surface — every authority
 * question is answered by composition of EXISTING frozen gates, and every
 * decision here embeds a deterministic explanation.
 *
 * The pack pins, each enforced structurally below and by the suite:
 *
 *  P1  IDENTITY ≠ AUTHORITY           — a NodeId/instance/epoch is a name,
 *                                       never a permission.
 *  P2  AUTHENTICATION ≠ ADMISSION     — a verified signature proves
 *                                       provenance of DATA; it never moves
 *                                       a peer's trust state by itself.
 *  P3  ADMISSION ≠ EXECUTION          — admitted peers gain communication
 *                                       trust only; execution stays behind
 *                                       fresh LOCAL Allocation → Policy →
 *                                       Phase-20 isolation → Phase-21
 *                                       governed tool runtime.
 *  P4  EVIDENCE ≠ AUTHORITY           — durable evidence records what
 *                                       HAPPENED; it never grants anything.
 *  P5  RECOVERY ≠ AUTHORITY           — recovered facts are recovered_data
 *                                       with zero authority (the frozen 22A
 *                                       decision), across every restart.
 *  P6  KEY_POSSESSION ≠ POLICY_ALLOW  — holding key material (or a copy of
 *                                       it) never produces or substitutes
 *                                       for a local Policy ALLOW.
 *  P7  ROTATION DOES NOT INHERIT TRUST — a rotated identity is a NEW peer;
 *                                       prior trust transfers only through
 *                                       a LOCAL, EVIDENCED decision.
 *
 * The operational-threat surfaces (closed vocabulary OT-01..OT-12): every
 * threat the pack names is modeled as a first-class classification with a
 * deterministic, fail-closed explanation — nothing falls through unnamed.
 */

import type { RuntimeEpochId } from "./continuity.js";
import { canonicalHash } from "./canonical.js";
import { NODE_ID_PATTERN, RUNTIME_INSTANCE_ID_PATTERN } from "./federationIdentity.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Operational trust-boundary contract schema version (25A). */
export const TRUST_BOUNDARY_SCHEMA_VERSION = "menog-trust-boundary/v0" as const;
export type TrustBoundarySchemaVersion = typeof TRUST_BOUNDARY_SCHEMA_VERSION;

// ── the seven operational pins (machine-checkable) ───────────────────────────

/** The seven pins, as a closed, ordered vocabulary (P1..P7). */
export const OPERATIONAL_TRUST_PINS = Object.freeze([
  "IDENTITY_NOT_AUTHORITY",
  "AUTHENTICATION_NOT_ADMISSION",
  "ADMISSION_NOT_EXECUTION",
  "EVIDENCE_NOT_AUTHORITY",
  "RECOVERY_NOT_AUTHORITY",
  "KEY_POSSESSION_NOT_POLICY_ALLOW",
  "ROTATION_NO_TRUST_INHERITANCE",
] as const);
export type OperationalTrustPin = (typeof OPERATIONAL_TRUST_PINS)[number];

/**
 * Deterministic, closed explanations for each pin. The SAME strings are
 * embedded in every decision this module emits, so explanations are
 * stable, greppable, and test-pinned (no free-form authority prose).
 */
export const OPERATIONAL_TRUST_PIN_EXPLANATIONS: Readonly<
  Record<OperationalTrustPin, string>
> = Object.freeze({
  IDENTITY_NOT_AUTHORITY:
    "P1 IDENTITY != AUTHORITY: a node identity, runtime instance, or epoch is a NAME, never a permission; no decision may read identity as authority.",
  AUTHENTICATION_NOT_ADMISSION:
    "P2 AUTHENTICATION != ADMISSION: a verified signature proves provenance of DATA only; trust-state changes require a separate LOCAL evidenced decision.",
  ADMISSION_NOT_EXECUTION:
    "P3 ADMISSION != EXECUTION: peer admission grants communication trust only; every execution remains behind fresh LOCAL Allocation, LOCAL Policy, Phase-20 isolation, and the Phase-21 governed tool runtime.",
  EVIDENCE_NOT_AUTHORITY:
    "P4 EVIDENCE != AUTHORITY: durable evidence records what happened; consuming it never grants, widens, or resumes any authority.",
  RECOVERY_NOT_AUTHORITY:
    "P5 RECOVERY != AUTHORITY: recovered facts enter as recovered_data with executionAuthorized:false and policyAuthorized:false; restart grants nothing.",
  KEY_POSSESSION_NOT_POLICY_ALLOW:
    "P6 KEY_POSSESSION != POLICY_ALLOW: possessing or copying key material never yields a Policy decision; only a fresh LOCAL Policy engine decision authorizes.",
  ROTATION_NO_TRUST_INHERITANCE:
    "P7 ROTATION DOES NOT INHERIT TRUST: a rotated identity is a NEW peer with unknown trust; the old peer's trust transfers only via an explicit LOCAL, evidenced re-admission decision.",
});

// ── operational risk vocabulary (closed) ─────────────────────────────────────

/**
 * The closed operational-risk catalog. Every pack-named operational threat
 * appears exactly once; unknown ids are refused wherever a risk class is
 * consumed (fail closed — an unnamed risk cannot ride through).
 */
export const OPERATIONAL_RISK_IDS = Object.freeze([
  "OT-01_unknown_peer",
  "OT-02_revoked_peer",
  "OT-03_compromised_peer",
  "OT-04_stale_peer",
  "OT-05_copied_key_material",
  "OT-06_malicious_payload",
  "OT-07_replayed_message",
  "OT-08_local_attacker",
  "OT-09_operator_error",
  "OT-10_clock_anomaly",
  "OT-11_crash_during_trust_mutation",
  "OT-12_untrusted_evidence_consumer",
] as const);
export type OperationalRiskId = (typeof OPERATIONAL_RISK_IDS)[number];

/** Boundary planes this contract models (closed; exactly the pack's list). */
export const TRUST_BOUNDARY_PLANES = Object.freeze([
  "local_operator",
  "runtime_epoch",
  "identity_key_material",
  "peer_identity_trust",
  "key_storage",
  "ingress",
  "egress",
  "durable_evidence",
  "policy",
  "execution",
  "restart_recovery",
] as const);
export type TrustBoundaryPlane = (typeof TRUST_BOUNDARY_PLANES)[number];

/**
 * What each boundary plane may DECIDE (closed). Nothing in this table says
 * "execute", "authorize", or "widen": planes either decide nothing, decide
 * facts, or route decisions to the frozen authority surfaces.
 */
export const TRUST_BOUNDARY_PLANE_DECISIONS: Readonly<
  Record<TrustBoundaryPlane, string>
> = Object.freeze({
  local_operator:
    "MAY: create/rotate the local identity, quarantine/retire peers, judge evidence, choose Policy inputs. MAY NOT: mint authority that bypasses fresh LOCAL Policy; a human decision still executes nothing by itself.",
  runtime_epoch:
    "MAY: own the single live-owner claim (23A), invalidate stale epochs, refuse rival epochs. MAY NOT: grant execution; epoch LIVE is process scope only.",
  identity_key_material:
    "MAY: sign local outbound facts (24B). MAY NOT: authorize admission, execution, or Policy; possession is authentication capability only (P6).",
  peer_identity_trust:
    "MAY: hold peer trust STATE per the closed machine (24A/24C). MAY NOT: convert trust state into any execution permission (P3).",
  key_storage:
    "MAY: hold PUBLIC material durably; hold PRIVATE material memory-only per the 24B law. MAY NOT: persist private keys/secrets into durable evidence (pack law); a durable private key is a finding, never a feature.",
  ingress:
    "MAY: deliver untrusted DATA into typed inboxes after admission/signature/replay checks (24D). MAY NOT: execute, persist raw payloads as authority, or bypass the pipeline.",
  egress:
    "MAY: emit locally signed facts the operator chose to share. MAY NOT: disclose private key material or durable evidence beyond what the operator explicitly released.",
  durable_evidence:
    "MAY: record happenings tamper-evidently (22C/24F). MAY NOT: authorize anything on read (P4); consumers must re-derive authority locally.",
  policy:
    "MAY: deny by default; allow only fresh LOCAL decisions for assigned actors. MAY NOT: accept remote claims as policy inputs (L7/P6).",
  execution:
    "MAY: run only behind fresh LOCAL Allocation + Policy + Phase-20 + Phase-21. MAY NOT: exist on any federation→tool path; no capability union (pack law).",
  restart_recovery:
    "MAY: re-derive public facts, expose recovered_data, and require NEW fresh local authority before any execution (P5). MAY NOT: auto-resume, auto-re-admit, or restore pre-restart authority.",
});

// ── key-material classification (P6; the key-storage boundary) ───────────────

/** Closed key-material classes the operational boundary distinguishes. */
export const KEY_MATERIAL_CLASSES = Object.freeze([
  "public_identity_facts",
  "private_signing_key",
  "derived_public_facts",
  "unknown",
] as const);
export type KeyMaterialClass = (typeof KEY_MATERIAL_CLASSES)[number];

export const KEY_STORAGE_LOCATIONS = Object.freeze([
  "memory_only",
  "durable_store",
  "durable_evidence",
  "outbound_message",
  "unknown",
] as const);
export type KeyStorageLocation = (typeof KEY_STORAGE_LOCATIONS)[number];

export type KeyMaterialAuthorization =
  | {
      readonly ok: true;
      readonly code: "key_material_permitted";
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code:
        | "private_key_at_rest_denied"
        | "private_key_in_evidence_denied"
        | "private_key_in_egress_denied"
        | "unknown_material_denied";
      readonly explanation: string;
    };

/**
 * The key-storage boundary decision (pure, fail closed). LAW: private key
 * material may exist ONLY in `memory_only`. Any durable location, any
 * evidence record, or any outbound message carrying it is a FINDING —
 * denied, never normalized. Public/derived facts may live anywhere.
 * (P6: none of the permitted paths grants authority either.)
 */
export function authorizeKeyMaterialPlacement(input: {
  readonly materialClass: KeyMaterialClass;
  readonly storageLocation: KeyStorageLocation;
}): KeyMaterialAuthorization {
  if (input.materialClass === "unknown" || input.storageLocation === "unknown") {
    return {
      ok: false,
      code: "unknown_material_denied",
      explanation:
        "key-material class or storage location is not in the closed vocabulary — refusing rather than guessing (fail closed); classification is the caller's duty",
    };
  }
  if (input.materialClass === "private_signing_key") {
    if (input.storageLocation === "memory_only") {
      return {
        ok: true,
        code: "key_material_permitted",
        explanation:
          "private signing key held memory-only — permitted by the 24B law; this placement authorizes NOTHING (P1/P6)",
      };
    }
    if (input.storageLocation === "durable_store" || input.storageLocation === "durable_evidence") {
      return {
        ok: false,
        code: input.storageLocation === "durable_evidence" ? "private_key_in_evidence_denied" : "private_key_at_rest_denied",
        explanation:
          "PRIVATE KEY MATERIAL in a durable location is a FINDING — private keys never enter durable state or evidence (pack law, fail closed); rotation to a fresh identity is the remediation, never persistence",
      };
    }
    return {
      ok: false,
      code: "private_key_in_egress_denied",
      explanation:
        "PRIVATE KEY MATERIAL in outbound traffic is a FINDING — keys authenticate the local node and are never shared; the peer that receives a private key holds the IDENTITY, so identity separation has failed (P7 applies to the receiver too)",
    };
  }
  return {
    ok: true,
    code: "key_material_permitted",
    explanation:
      "public/derived identity facts may be stored or shared — they authenticate, never authorize (P1/P2/P6)",
  };
}

// ── operational risk classification (deterministic explanations) ─────────────

/**
 * An observed operational fact to classify. Exactly one of the closed
 * signals is present; the classifier maps it to a risk id with a
 * deterministic explanation and a fail-closed disposition.
 */
export type OperationalSignal =
  | { readonly kind: "peer_unknown"; readonly peerId: string }
  | { readonly kind: "peer_revoked"; readonly peerId: string }
  | { readonly kind: "peer_key_changed"; readonly peerId: string }
  | { readonly kind: "peer_epoch_stale"; readonly peerId: string }
  | { readonly kind: "key_material_copy_detected"; readonly peerId: string }
  | { readonly kind: "payload_rejected"; readonly peerId: string }
  | { readonly kind: "message_replayed"; readonly peerId: string }
  | { readonly kind: "local_policy_denied"; readonly peerId: string }
  | { readonly kind: "operator_action_out_of_band"; readonly peerId: string }
  | { readonly kind: "clock_skew_exceeded"; readonly peerId: string }
  | { readonly kind: "trust_mutation_interrupted"; readonly peerId: string }
  | { readonly kind: "evidence_replayed_as_authority"; readonly peerId: string };

export const OPERATIONAL_DISPOSITIONS = Object.freeze([
  "contain",
  "refuse",
  "quarantine",
  "investigate",
  "monitor",
] as const);
export type OperationalDisposition = (typeof OPERATIONAL_DISPOSITIONS)[number];

export interface OperationalRiskClassification {
  readonly riskId: OperationalRiskId;
  readonly disposition: OperationalDisposition;
  /** Deterministic; the same signal always yields the same explanation. */
  readonly explanation: string;
  /** The pins this classification invokes (subset of P1..P7). */
  readonly pins: readonly OperationalTrustPin[];
}

/**
 * Deterministic classification of one operational signal (pure; no I/O).
 * Every mapping fails closed: the safe default for an unmatched signal is
 * a refusal, not a guess. Dispositions affect TRUST STATE or LOCAL
 * JUDGMENT only — none executes anything (P3/P4/P5).
 */
export function classifyOperationalRisk(signal: OperationalSignal): OperationalRiskClassification {
  const peer = signal.peerId;
  switch (signal.kind) {
    case "peer_unknown":
      return {
        riskId: "OT-01_unknown_peer",
        disposition: "monitor",
        explanation:
          "peer '" + peer + "' is not in the local trust registry — treat as untrusted DATA source; first contact may enter only as 'candidate' (24A/24C)",
        pins: ["IDENTITY_NOT_AUTHORITY", "AUTHENTICATION_NOT_ADMISSION"],
      };
    case "peer_revoked":
      return {
        riskId: "OT-02_revoked_peer",
        disposition: "refuse",
        explanation:
          "peer '" + peer + "' is quarantined/retired — terminal states never resurrect (24A L6); its traffic is refused pre-signature with no oracle",
        pins: ["ADMISSION_NOT_EXECUTION"],
      };
    case "peer_key_changed":
      return {
        riskId: "OT-03_compromised_peer",
        disposition: "quarantine",
        explanation:
          "peer '" + peer + "' presented different key material for its identity — treat as COMPROMISED: quarantine pending local evidenced investigation; the old trust does not extend to the new key (P7)",
        pins: ["IDENTITY_NOT_AUTHORITY", "ROTATION_NO_TRUST_INHERITANCE"],
      };
    case "peer_epoch_stale":
      return {
        riskId: "OT-04_stale_peer",
        disposition: "refuse",
        explanation:
          "peer '" + peer + "' presented a stale epoch — older-than-newest epochs fail (24A L5); possibly a replayed or rolled-back sender",
        pins: ["IDENTITY_NOT_AUTHORITY"],
      };
    case "key_material_copy_detected":
      return {
        riskId: "OT-05_copied_key_material",
        disposition: "quarantine",
        explanation:
          "key material for '" + peer + "' observed in more than one trust context — a copied key is a compromised identity, not a second node; quarantine and re-identity are the only exits (P6: possession never authorized anything)",
        pins: ["KEY_POSSESSION_NOT_POLICY_ALLOW", "ROTATION_NO_TRUST_INHERITANCE"],
      };
    case "payload_rejected":
      return {
        riskId: "OT-06_malicious_payload",
        disposition: "contain",
        explanation:
          "payload from '" + peer + "' failed closed-shape validation — untrusted DATA is contained in the typed inbox; it never reaches tools, Policy inputs, or durable authority records (24D/24E)",
        pins: ["ADMISSION_NOT_EXECUTION", "EVIDENCE_NOT_AUTHORITY"],
      };
    case "message_replayed":
      return {
        riskId: "OT-07_replayed_message",
        disposition: "refuse",
        explanation:
          "message from '" + peer + "' re-delivered an observed id — replay refuses with zero signature evaluation once the durable guard holds (24D)",
        pins: ["AUTHENTICATION_NOT_ADMISSION"],
      };
    case "local_policy_denied":
      return {
        riskId: "OT-08_local_attacker",
        disposition: "contain",
        explanation:
          "a request touching '" + peer + "' was DENIED by fresh LOCAL Policy — the deny is final and proven valid; no identity, admission, or evidence may override it (P1/P3/P6)",
        pins: ["KEY_POSSESSION_NOT_POLICY_ALLOW", "ADMISSION_NOT_EXECUTION"],
      };
    case "operator_action_out_of_band":
      return {
        riskId: "OT-09_operator_error",
        disposition: "investigate",
        explanation:
          "operator action affecting '" + peer + "' arrived outside the sanctioned decision surfaces — operator intent is captured only through the frozen decision paths (quarantine/retire/admit with evidence); out-of-band intent is investigated, never applied silently",
        pins: ["AUTHENTICATION_NOT_ADMISSION"],
      };
    case "clock_skew_exceeded":
      return {
        riskId: "OT-10_clock_anomaly",
        disposition: "refuse",
        explanation:
          "timestamp claims involving '" + peer + "' exceeded the skew tolerance — skewed claims are refused, never silently accepted (24A); local clock health is an operator duty",
        pins: ["IDENTITY_NOT_AUTHORITY"],
      };
    case "trust_mutation_interrupted":
      return {
        riskId: "OT-11_crash_during_trust_mutation",
        disposition: "investigate",
        explanation:
          "a trust-state mutation for '" + peer + "' was interrupted — the store's transactional semantics (22B) mean the mutation is committed-or-absent with no third state visible; the recovered view is recovered_data and any completion requires a NEW evidenced decision (P5/P7)",
        pins: ["RECOVERY_NOT_AUTHORITY", "ROTATION_NO_TRUST_INHERITANCE"],
      };
    case "evidence_replayed_as_authority":
      return {
        riskId: "OT-12_untrusted_evidence_consumer",
        disposition: "contain",
        explanation:
          "durable evidence involving '" + peer + "' was presented as if it granted authority — evidence consumers must re-derive authority through fresh LOCAL decisions; the record itself stays inert (P4/P5)",
        pins: ["EVIDENCE_NOT_AUTHORITY", "RECOVERY_NOT_AUTHORITY"],
      };
    default: {
      // Exhaustiveness: `signal` is `never` here when the union is closed.
      const unknown: never = signal;
      void unknown;
      return {
        riskId: "OT-08_local_attacker",
        disposition: "refuse",
        explanation: "unmatched operational signal — refusing (fail closed)",
        pins: ["IDENTITY_NOT_AUTHORITY"],
      };
    }
  }
}

// ── boundary decision: the seven pins over one operational claim ─────────────

/** A claim presented AT the operational boundary (e.g. by a peer or process). */
export type BoundaryClaimKind =
  | "identity_claim"
  | "authentication_claim"
  | "admission_claim"
  | "execution_claim"
  | "evidence_authority_claim"
  | "recovery_authority_claim"
  | "key_possession_authority_claim"
  | "rotation_trust_claim";

export type BoundaryDecision =
  | { readonly ok: true; readonly code: "claim_within_boundary"; readonly explanation: string; readonly provenanceHash: string }
  | { readonly ok: false; readonly code: "claim_crosses_boundary"; readonly violatedPin: OperationalTrustPin; readonly explanation: string; readonly provenanceHash: string };

/**
 * Decide whether a claim stays inside the operational trust boundary.
 * Identity/authentication/admission/evidence/recovery/key-possession/
 * rotation claims are INBOUND FACTS: they are receivable (ok) exactly
 * because they grant nothing. An EXECUTION claim — any claim that
 * execution, authority, or a Policy allow follows from peer-side state —
 * crosses the boundary and is refused, naming the violated pin.
 * Deterministic: the provenance hash binds (kind, peer, epoch, local
 * decision time) canonically.
 */
export function decideBoundaryClaim(input: {
  readonly claimKind: BoundaryClaimKind;
  readonly peerId: string;
  readonly localEpochId: RuntimeEpochId | null;
  readonly decidedAtEpochMs: number;
}): BoundaryDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: TRUST_BOUNDARY_SCHEMA_VERSION,
    claimKind: input.claimKind,
    peerId: input.peerId,
    localEpochId: input.localEpochId,
    decidedAtEpochMs: input.decidedAtEpochMs,
  });
  if (typeof input.peerId !== "string" || input.peerId.length === 0) {
    return {
      ok: false,
      code: "claim_crosses_boundary",
      violatedPin: "IDENTITY_NOT_AUTHORITY",
      explanation:
        "boundary claim carries no peer identity — an anonymous claim cannot even be evaluated as DATA (fail closed)",
      provenanceHash,
    };
  }
  switch (input.claimKind) {
    case "identity_claim":
      return {
        ok: true,
        code: "claim_within_boundary",
        explanation: OPERATIONAL_TRUST_PIN_EXPLANATIONS.IDENTITY_NOT_AUTHORITY + " The claim is receivable as DATA and grants nothing.",
        provenanceHash,
      };
    case "authentication_claim":
      return {
        ok: true,
        code: "claim_within_boundary",
        explanation: OPERATIONAL_TRUST_PIN_EXPLANATIONS.AUTHENTICATION_NOT_ADMISSION + " The claim is receivable as DATA and moves no trust state.",
        provenanceHash,
      };
    case "admission_claim":
      return {
        ok: true,
        code: "claim_within_boundary",
        explanation: OPERATIONAL_TRUST_PIN_EXPLANATIONS.ADMISSION_NOT_EXECUTION + " The claim may at most inform a LOCAL evidenced trust-state decision.",
        provenanceHash,
      };
    case "evidence_authority_claim":
      return {
        ok: true,
        code: "claim_within_boundary",
        explanation: OPERATIONAL_TRUST_PIN_EXPLANATIONS.EVIDENCE_NOT_AUTHORITY + " The claim is receivable as a record of happenings only.",
        provenanceHash,
      };
    case "recovery_authority_claim":
      return {
        ok: true,
        code: "claim_within_boundary",
        explanation: OPERATIONAL_TRUST_PIN_EXPLANATIONS.RECOVERY_NOT_AUTHORITY + " The claim is receivable as recovered_data with zero authority.",
        provenanceHash,
      };
    case "execution_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "ADMISSION_NOT_EXECUTION",
        explanation:
          OPERATIONAL_TRUST_PIN_EXPLANATIONS.ADMISSION_NOT_EXECUTION +
          " A peer-side claim to execution or authority CROSSES the boundary and is refused; execution follows only from fresh LOCAL Allocation + LOCAL Policy + Phase-20 + Phase-21.",
        provenanceHash,
      };
    case "key_possession_authority_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "KEY_POSSESSION_NOT_POLICY_ALLOW",
        explanation:
          OPERATIONAL_TRUST_PIN_EXPLANATIONS.KEY_POSSESSION_NOT_POLICY_ALLOW +
          " A claim that holding keys yields a Policy allow crosses the boundary and is refused.",
        provenanceHash,
      };
    case "rotation_trust_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "ROTATION_NO_TRUST_INHERITANCE",
        explanation:
          OPERATIONAL_TRUST_PIN_EXPLANATIONS.ROTATION_NO_TRUST_INHERITANCE +
          " A claim that a rotated identity inherits prior trust crosses the boundary and is refused; inheritance requires a LOCAL evidenced decision.",
        provenanceHash,
      };
    default: {
      const unknown: never = input.claimKind;
      void unknown;
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "IDENTITY_NOT_AUTHORITY",
        explanation: "unknown claim kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── restart/recovery boundary (P5/P7) ────────────────────────────────────────

/** What survived a restart, as an inert fact (no authority). */
export type RestartSurvivorKind =
  | "peer_trust_registry_fact"
  | "durable_evidence_record"
  | "federation_receipt"
  | "federation_proposal"
  | "federation_provenance_anchor"
  | "interrupted_trust_mutation";

export const RESTART_RECOVERY_DECISIONS = Object.freeze([
  "recovered_as_data_zero_authority",
  "recovered_as_data_requires_fresh_evidence",
  "refused_unknown_survivor",
] as const);
export type RestartRecoveryDecision = (typeof RESTART_RECOVERY_DECISIONS)[number];

export interface RestartRecoveryOutcome {
  readonly decision: RestartRecoveryDecision;
  readonly pins: readonly OperationalTrustPin[];
  /** Deterministic; identical survivors always yield identical explanations. */
  readonly explanation: string;
}

/**
 * The restart/recovery boundary decision (pure). EVERY survivor re-enters
 * as recovered_data with ZERO authority (P5): registries and append-only
 * records restore as FACTS; an interrupted trust mutation additionally
 * requires a NEW evidenced local decision to complete (P7 — never
 * auto-completed). Recovery never re-admits, never auto-resumes, and
 * never restores a pre-restart Policy decision.
 */
export function decideRestartRecovery(survivor: {
  readonly kind: RestartSurvivorKind;
  readonly peerId: string;
}): RestartRecoveryOutcome {
  switch (survivor.kind) {
    case "peer_trust_registry_fact":
      return {
        decision: "recovered_as_data_zero_authority",
        pins: ["RECOVERY_NOT_AUTHORITY", "ADMISSION_NOT_EXECUTION"],
        explanation:
          "peer trust fact for '" + survivor.peerId + "' restores EXACTLY as recorded (terminal stays terminal, 24C); the fact authorizes nothing — execution still needs fresh LOCAL authority (P3/P5)",
      };
    case "durable_evidence_record":
      return {
        decision: "recovered_as_data_zero_authority",
        pins: ["EVIDENCE_NOT_AUTHORITY", "RECOVERY_NOT_AUTHORITY"],
        explanation:
          "durable evidence for '" + survivor.peerId + "' re-verifies with its own vocabulary and stays inert on read (P4/P5); consumers re-derive authority locally",
      };
    case "federation_receipt":
    case "federation_proposal":
    case "federation_provenance_anchor":
      return {
        decision: "recovered_as_data_zero_authority",
        pins: ["EVIDENCE_NOT_AUTHORITY", "RECOVERY_NOT_AUTHORITY"],
        explanation:
          "append-only federation record for '" + survivor.peerId + "' restores as durable DATA with its commitments intact; it never resumes, re-authorizes, or re-admits anything (P4/P5)",
      };
    case "interrupted_trust_mutation":
      return {
        decision: "recovered_as_data_requires_fresh_evidence",
        pins: ["RECOVERY_NOT_AUTHORITY", "ROTATION_NO_TRUST_INHERITANCE"],
        explanation:
          "an interrupted trust mutation for '" + survivor.peerId + "' surfaces as a FACT to investigate — completion requires a NEW local evidenced decision (transactional semantics guarantee committed-or-absent, 22B); it is never auto-completed (P5/P7)",
      };
    default: {
      // Exhaustiveness: `survivor.kind` is `never` here when the union is closed.
      const unknown: never = survivor.kind;
      void unknown;
      return {
        decision: "refused_unknown_survivor",
        pins: ["RECOVERY_NOT_AUTHORITY"],
        explanation: "unknown restart survivor — refusing (fail closed)",
      };
    }
  }
}

// ── boundary self-description (pure) ─────────────────────────────────────────

/**
 * Deterministic, canonical description of the operational trust boundary
 * for provenance bindings (no I/O; pure function of the local facts).
 */
export function trustBoundaryFingerprint(input: {
  readonly localEpochId: RuntimeEpochId | null;
  readonly localNodeId: string | null;
  readonly decidedAtEpochMs: number;
}): string {
  return canonicalHash({
    schemaVersion: TRUST_BOUNDARY_SCHEMA_VERSION,
    localEpochId: input.localEpochId,
    localNodeId: input.localNodeId,
    decidedAtEpochMs: input.decidedAtEpochMs,
    pins: OPERATIONAL_TRUST_PINS,
  });
}

/** Structural identity sanity for boundary claims (reuse 24A shapes). */
export function isWellFormedPeerId(peerId: string): boolean {
  return NODE_ID_PATTERN.test(peerId) || RUNTIME_INSTANCE_ID_PATTERN.test(peerId);
}
