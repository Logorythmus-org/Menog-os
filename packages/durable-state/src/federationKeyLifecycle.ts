/**
 * PHASE 25B — Identity / Key Lifecycle Operations
 * (LOCAL ONLY / NO NETWORK / NO KEY-EXPORT API / PRIVATE KEYS NEVER ENTER
 * ANY RECORD, LEDGER, PROVENANCE, OR REPORT).
 *
 * This module OPERATIONALIZES the frozen 24B cryptographic identity into a
 * local lifecycle state machine over PUBLIC FACTS ONLY:
 *
 *     initialize → active → rotation_requested → rotated → revoked → retired
 *
 * (with the evidenced compromise/retirement shortcuts active → revoked and
 * active → retired, mirroring the 24C `admitted → retired` precedent).
 *
 * What this module IS:
 *  - a closed lifecycle vocabulary (`KEY_LIFECYCLE_STATES`) with a closed
 *    transition table requiring EVIDENCE for every edge;
 *  - a PUBLIC-FACTS identity record (`KeyLifecycleRecord`) that holds
 *    publicKeyHex / fingerprint / NodeId / lifecycle state / an append-only
 *    transition trail — and NOTHING secret (structural: every record is
 *    validated against the 24B secret-key denylist; a secret-shaped key at
 *    any depth refuses the record);
 *  - pure, deterministic, fail-closed decisions for: initialize, rotation
 *    request/execution (duplicate/conflicting/fresh-less rotations refuse),
 *    revocation/retirement, key-use (stale/revoked/rotated keys refuse),
 *    restart/reload (revocation SURVIVES restart), and state-rollback
 *    judgment (a rollback can never resurrect a rotated/revoked/retired
 *    key — lifecycle facts are monotone);
 *  - an explicit trust NON-inheritance decision: a rotated identity is a
 *    NEW peer whose trust starts EMPTY; the old peer's trust transfers only
 *    through a NEW local evidenced re-admission (24C scope, out of here) —
 *    never automatically (25A pin P7).
 *
 * What this module IS NOT (exact, no overclaim):
 *  - NOT a key store: the private key remains inside 24B's module-private
 *    closure (memory-only, process lifetime). This module never receives,
 *    holds, exports, serializes, or observes private key material. There is
 *    no key-export API and no import path for secret material.
 *  - NOT durable storage: records are caller-owned pure values (persisting
 *    them through the sanctioned 23B coordinator junction is the caller's
 *    duty; this module adds no store semantics, no new record kind, no
 *    unfreeze event, no schema change).
 *  - NOT an HSM/TPM/secure-enclave/production-PKI feature: none is used,
 *    none is claimed. Platform crypto means `node:crypto` Ed25519 (24B),
 *    exactly as frozen; NO new dependency is added.
 *  - NOT an authority: lifecycle state gates KEY USE (authentication
 *    operations), never execution, Policy, or admission by itself
 *    (25A P1/P2/P6 apply unchanged).
 *
 * The one-line law of 25B:
 *
 *     a lifecycle record is a public fact about a key; it can refuse a
 *     key's USE, and it can never resurrect, export, or re-pin anything.
 */

import { createHash } from "node:crypto";
import {
  NODE_FINGERPRINT_PATTERN,
  NODE_ID_PATTERN,
} from "./federationIdentity.js";
import { verifyRestartIdentity, payloadContainsSecretKeyMaterial } from "./federationCrypto.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Key-lifecycle contract schema version (25B). */
export const KEY_LIFECYCLE_SCHEMA_VERSION = "menog-key-lifecycle/v0" as const;
export type KeyLifecycleSchemaVersion = typeof KEY_LIFECYCLE_SCHEMA_VERSION;

// ── closed lifecycle vocabulary ──────────────────────────────────────────────

/**
 * The closed lifecycle states, in canonical order. `retired` is the ONLY
 * terminal state. The pack's canonical happy path is
 * initialize → active → rotation_requested → rotated → revoked → retired.
 */
export const KEY_LIFECYCLE_STATES = Object.freeze([
  "uninitialized",
  "active",
  "rotation_requested",
  "rotated",
  "revoked",
  "retired",
] as const);
export type KeyLifecycleState = (typeof KEY_LIFECYCLE_STATES)[number];

/**
 * Monotone rank of each state (a lifecycle fact never un-happens). Used by
 * the rollback judgment: any snapshot EARLIER than a rotated/revoked/
 * retired current state must not be restorable (rollback cannot resurrect
 * keys).
 */
export const KEY_LIFECYCLE_STATE_RANK: Readonly<Record<KeyLifecycleState, number>> = Object.freeze({
  uninitialized: 0,
  active: 1,
  rotation_requested: 2,
  rotated: 3,
  revoked: 4,
  retired: 5,
});

/**
 * The ONLY legal lifecycle transitions (closed). Every edge requires
 * evidence (enforced by `decideLifecycleTransition`):
 *  - uninitialized → active           initialize (with verified public facts)
 *  - active → rotation_requested      operator rotation request
 *  - rotation_requested → active      evidenced ABORT of a pending rotation
 *  - rotation_requested → rotated     locally evidenced rotation/re-identity
 *  - active → revoked                 evidenced revocation (compromise/superseded)
 *  - rotation_requested → revoked     evidenced revocation while pending
 *  - rotated → revoked                the rotated-away key is formally revoked
 *  - active → retired                 evidenced direct operator retirement
 *  - revoked → retired                terminal retirement
 * retired → anything is UNREPRESENTABLE (no resurrection).
 */
export const KEY_LIFECYCLE_TRANSITIONS: Readonly<
  Record<KeyLifecycleState, readonly KeyLifecycleState[]>
> = Object.freeze({
  uninitialized: Object.freeze(["active"] as const),
  active: Object.freeze(["rotation_requested", "revoked", "retired"] as const),
  rotation_requested: Object.freeze(["active", "rotated", "revoked"] as const),
  rotated: Object.freeze(["revoked"] as const),
  revoked: Object.freeze(["retired"] as const),
  retired: Object.freeze([] as const),
});

export function isKeyLifecycleTransition(from: KeyLifecycleState, to: KeyLifecycleState): boolean {
  return (KEY_LIFECYCLE_TRANSITIONS[from] as readonly string[]).includes(to);
}

/**
 * The states in which the key may still SIGN (key-USE gate). Once rotated,
 * revoked, or retired, the key is operationally dead — signatures produced
 * with it must refuse at the lifecycle gate (stale-key refusal). A pending
 * rotation request does NOT stop signing (the rotation is not yet evidenced
 * or executed); execution of the rotation does.
 */
export const KEY_USE_ALLOWED_STATES: readonly KeyLifecycleState[] = Object.freeze([
  "active",
  "rotation_requested",
] as const);

// ── key id (public, canonical, distinct from the fingerprint) ────────────────

/** Key-id prefix: `kid-` + 16 hex of SHA-256 over the raw public key hex. */
export const KEY_ID_PREFIX = "kid-" as const;
export const KEY_ID_PATTERN = /^kid-[0-9a-f]{16}$/;

/**
 * Deterministic key id over the RAW PUBLIC KEY HEX (not the fingerprint, so
 * the two derivations are independent and a mismatch is detectable): the
 * fingerprint is SHA-256 over the raw key BYTES; the key id is the first 16
 * hex chars of SHA-256 over the raw key HEX STRING. Both must re-derive for
 * a record to be well-formed (fingerprint/key-id mismatch refuses).
 */
export function deriveKeyId(publicKeyHex: string): string {
  return KEY_ID_PREFIX + createHash("sha256").update(publicKeyHex, "utf8").digest("hex").slice(0, 16);
}

// ── the lifecycle identity record (PUBLIC FACTS ONLY) ────────────────────────

/** One evidenced lifecycle transition in the append-only trail. */
export interface KeyLifecycleTransitionFact {
  readonly atEpochMs: number;
  readonly from: KeyLifecycleState;
  readonly to: KeyLifecycleState;
  /** Non-empty local evidence binding this transition (hash/reference). */
  readonly evidence: string;
}

/**
 * A lifecycle record over one key identity. PUBLIC FACTS ONLY — the private
 * key never appears here or in any trail entry; a record carrying
 * secret-key-shaped keys at any depth refuses validation outright.
 */
export interface KeyLifecycleRecord {
  readonly schemaVersion: KeyLifecycleSchemaVersion;
  readonly keyId: string;
  readonly publicKeyHex: string;
  readonly fingerprint: string;
  readonly nodeId: string;
  readonly state: KeyLifecycleState;
  readonly createdAtEpochMs: number;
  readonly updatedAtEpochMs: number;
  /** Append-only evidenced trail (initialize is the first entry). */
  readonly trail: readonly KeyLifecycleTransitionFact[];
  /**
   * Trust linkage: the lifecycle layer records NONE. A fresh (rotated-to)
   * identity always starts here with NO inherited trust (P7); any linkage
   * to peer trust is the caller's separate, evidenced 24C duty.
   */
  readonly peerTrustLink: null;
}

// ── record validation (shape + re-derivation + secret scan) ──────────────────

export type KeyLifecycleRecordValidation =
  | { readonly ok: true; readonly explanation: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Validate a lifecycle record: exact public-facts shape, closed state
 * vocabulary, key id/fingerprint/NodeId all re-derive from the public key
 * (24B `verifyRestartIdentity` + `deriveKeyId`), trail entries are
 * well-formed with non-empty evidence, and NO secret-key-shaped key exists
 * anywhere in the record (24B denylist, fail closed).
 */
export function validateLifecycleRecord(record: unknown): KeyLifecycleRecordValidation {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    return { ok: false, reason: "lifecycle record must be a plain object" };
  }
  if (payloadContainsSecretKeyMaterial(record)) {
    return { ok: false, reason: "lifecycle record carries secret-key-shaped keys — private key material never enters records (fail closed)" };
  }
  const r = record as Partial<KeyLifecycleRecord> & Record<string, unknown>;
  if (r.schemaVersion !== KEY_LIFECYCLE_SCHEMA_VERSION) {
    return { ok: false, reason: "lifecycle record schema version mismatch" };
  }
  if (
    typeof r.publicKeyHex !== "string" ||
    typeof r.fingerprint !== "string" ||
    typeof r.nodeId !== "string" ||
    typeof r.keyId !== "string" ||
    typeof r.state !== "string" ||
    typeof r.createdAtEpochMs !== "number" ||
    typeof r.updatedAtEpochMs !== "number" ||
    !Array.isArray(r.trail) ||
    r.peerTrustLink !== null
  ) {
    return { ok: false, reason: "lifecycle record is missing public facts or is structurally malformed" };
  }
  if (!(KEY_LIFECYCLE_STATES as readonly string[]).includes(r.state)) {
    return { ok: false, reason: "lifecycle state is not in the closed vocabulary" };
  }
  const restart = verifyRestartIdentity({
    publicKeyHex: r.publicKeyHex,
    fingerprint: r.fingerprint,
    nodeId: r.nodeId,
  });
  if (!restart.ok) {
    return { ok: false, reason: "public identity facts do not re-derive: " + restart.reason };
  }
  if (!KEY_ID_PATTERN.test(r.keyId) || r.keyId !== deriveKeyId(r.publicKeyHex)) {
    return { ok: false, reason: "key id does not re-derive from the public key — fingerprint/key-id mismatch (fail closed)" };
  }
  if (!NODE_ID_PATTERN.test(r.nodeId) || !NODE_FINGERPRINT_PATTERN.test(r.fingerprint)) {
    return { ok: false, reason: "node id or fingerprint shape malformed" };
  }
  if (r.trail.length === 0) {
    return { ok: false, reason: "lifecycle trail is empty — every record is initialized with evidence" };
  }
  for (const fact of r.trail) {
    if (
      fact === null ||
      typeof fact !== "object" ||
      typeof fact.atEpochMs !== "number" ||
      typeof fact.from !== "string" ||
      typeof fact.to !== "string" ||
      typeof fact.evidence !== "string" ||
      fact.evidence.trim() === "" ||
      !(KEY_LIFECYCLE_STATES as readonly string[]).includes(fact.from) ||
      !(KEY_LIFECYCLE_STATES as readonly string[]).includes(fact.to) ||
      !isKeyLifecycleTransition(fact.from, fact.to)
    ) {
      return { ok: false, reason: "lifecycle trail contains a malformed or unevidenced transition" };
    }
  }
  const first = r.trail[0];
  if (first === undefined || first.from !== "uninitialized" || first.to !== "active") {
    return { ok: false, reason: "lifecycle trail must begin with the evidenced initialize transition" };
  }
  const last = r.trail[r.trail.length - 1];
  if (last === undefined || last.to !== r.state) {
    return { ok: false, reason: "lifecycle trail does not end at the recorded state" };
  }
  const firstFact = r.trail[0];
  if (firstFact === undefined || firstFact.atEpochMs !== r.createdAtEpochMs) {
    return { ok: false, reason: "record creation time does not bind to the initialize trail entry" };
  }
  if (last.atEpochMs !== r.updatedAtEpochMs) {
    return { ok: false, reason: "record update time does not bind to the newest trail entry — tampered or stale record (fail closed)" };
  }
  for (let i = 1; i < r.trail.length; i++) {
    const prev = r.trail[i - 1];
    const curr = r.trail[i];
    if (prev === undefined || curr === undefined || curr.atEpochMs < prev.atEpochMs) {
      return { ok: false, reason: "lifecycle trail timestamps are not monotone — history rewrite refused (fail closed)" };
    }
  }
  return { ok: true, explanation: "lifecycle record is well-formed: public facts re-derive, trail is evidenced and append-only-consistent, no secret material present" };
}

// ── pure transition engine ───────────────────────────────────────────────────

export type KeyLifecycleDecision =
  | { readonly ok: true; readonly record: KeyLifecycleRecord; readonly explanation: string }
  | { readonly ok: false; readonly code: KeyLifecycleDenyCode; readonly explanation: string };

export const KEY_LIFECYCLE_DENY_CODES = Object.freeze([
  "malformed_input",
  "unknown_transition",
  "unevidenced_transition",
  "rotation_already_requested",
  "rotation_not_requested",
  "rotation_not_fresh",
  "already_terminal",
  "record_invalid",
] as const);
export type KeyLifecycleDenyCode = (typeof KEY_LIFECYCLE_DENY_CODES)[number];

function makeRecord(input: {
  readonly publicKeyHex: string;
  readonly fingerprint: string;
  readonly nodeId: string;
  readonly state: KeyLifecycleState;
  readonly createdAtEpochMs: number;
  readonly updatedAtEpochMs: number;
  readonly trail: readonly KeyLifecycleTransitionFact[];
}): KeyLifecycleRecord {
  return Object.freeze({
    schemaVersion: KEY_LIFECYCLE_SCHEMA_VERSION,
    keyId: deriveKeyId(input.publicKeyHex),
    publicKeyHex: input.publicKeyHex,
    fingerprint: input.fingerprint,
    nodeId: input.nodeId,
    state: input.state,
    createdAtEpochMs: input.createdAtEpochMs,
    updatedAtEpochMs: input.updatedAtEpochMs,
    trail: Object.freeze([...input.trail]),
    peerTrustLink: null,
  });
}

/**
 * The ONE sanctioned lifecycle transition decision (pure). Order of
 * refusal: record validity → legality in the closed machine → evidence →
 * rotation-specific freshness/duplicate rules. The returned record is a NEW
 * frozen value with the transition appended to the trail (records are
 * immutable; history is never rewritten).
 */
export function decideLifecycleTransition(input: {
  readonly record: KeyLifecycleRecord | null;
  readonly to: KeyLifecycleState;
  readonly evidence: string;
  readonly nowEpochMs: number;
  /** Required when `to` is "rotated": the FRESH identity's public facts. */
  readonly freshPublicFacts?: {
    readonly publicKeyHex: string;
    readonly fingerprint: string;
    readonly nodeId: string;
  };
}): KeyLifecycleDecision {
  if (typeof input.evidence !== "string" || input.evidence.trim() === "") {
    return { ok: false, code: "unevidenced_transition", explanation: "every lifecycle transition requires non-empty evidence — refusing (fail closed)" };
  }
  if (input.record === null) {
    if (input.to !== "active") {
      return { ok: false, code: "unknown_transition", explanation: "only initialize (→ active) is legal without an existing record" };
    }
    const facts = input.freshPublicFacts;
    if (facts === undefined) {
      return { ok: false, code: "malformed_input", explanation: "initialize requires the verified public facts (publicKeyHex/fingerprint/nodeId)" };
    }
    const restart = verifyRestartIdentity(facts);
    if (!restart.ok) {
      return { ok: false, code: "malformed_input", explanation: "initialize refused: " + restart.reason };
    }
    const record = makeRecord({
      publicKeyHex: facts.publicKeyHex,
      fingerprint: facts.fingerprint,
      nodeId: facts.nodeId,
      state: "active",
      createdAtEpochMs: input.nowEpochMs,
      updatedAtEpochMs: input.nowEpochMs,
      trail: [{ atEpochMs: input.nowEpochMs, from: "uninitialized", to: "active", evidence: input.evidence }],
    });
    return {
      ok: true,
      record,
      explanation: "identity initialized ACTIVE from verified public facts — private key material was never received, held, or recorded (24B closure); this record authorizes nothing by itself",
    };
  }
  const validity = validateLifecycleRecord(input.record);
  if (!validity.ok) {
    return { ok: false, code: "record_invalid", explanation: "existing record failed validation: " + validity.reason };
  }
  const from = input.record.state;
  if (from === "retired" || (from === "revoked" && input.to !== "retired")) {
    return { ok: false, code: "already_terminal", explanation: "state '" + from + "' allows no transition to '" + input.to + "' — lifecycle facts are monotone; no resurrection (fail closed)" };
  }
  // Rotation-specific refusals fire BEFORE the generic legality check so
  // the deny code names the actual operational mistake, not just "illegal":
  if (input.to === "rotated" && from !== "rotation_requested") {
    return { ok: false, code: "rotation_not_requested", explanation: "rotation execution requires a prior evidenced rotation request of state rotation_requested — refusing a direct " + from + "→rotated jump (fail closed)" };
  }
  if (from === "rotation_requested" && input.to === "rotation_requested") {
    return { ok: false, code: "rotation_already_requested", explanation: "a rotation is already requested and pending — duplicate requests refuse; execute or abort the pending one" };
  }
  if (!isKeyLifecycleTransition(from, input.to)) {
    return { ok: false, code: "unknown_transition", explanation: "lifecycle transition " + from + "→" + input.to + " is not in the closed machine — refusing (fail closed)" };
  }
  if (input.to === "rotated") {
    const fresh = input.freshPublicFacts;
    if (fresh === undefined) {
      return { ok: false, code: "malformed_input", explanation: "rotation execution requires the FRESH identity's public facts (from the 24B re-identity)" };
    }
    const freshRestart = verifyRestartIdentity(fresh);
    if (!freshRestart.ok) {
      return { ok: false, code: "malformed_input", explanation: "fresh public facts do not re-derive: " + freshRestart.reason };
    }
    if (fresh.fingerprint === input.record.fingerprint || fresh.nodeId === input.record.nodeId || fresh.publicKeyHex === input.record.publicKeyHex) {
      return { ok: false, code: "rotation_not_fresh", explanation: "rotation must produce a GENUINELY FRESH identity (new key → new fingerprint → new NodeId) — refusing a no-op or self-referential rotation (fail closed)" };
    }
  }
  const trail: KeyLifecycleTransitionFact[] = [
    ...input.record.trail,
    { atEpochMs: input.nowEpochMs, from, to: input.to, evidence: input.evidence },
  ];
  const updated = makeRecord({
    publicKeyHex: input.record.publicKeyHex,
    fingerprint: input.record.fingerprint,
    nodeId: input.record.nodeId,
    state: input.to,
    createdAtEpochMs: input.record.createdAtEpochMs,
    updatedAtEpochMs: input.nowEpochMs,
    trail,
  });
  return {
    ok: true,
    record: updated,
    explanation:
      "lifecycle transition " + from + "→" + input.to + " recorded with evidence — the trail is append-only and the previous record is never mutated" +
      (input.to === "rotated" ? "; the OLD key is now operationally dead (stale-key refusal applies) and the fresh identity starts with NO inherited trust (P7)" : ""),
  };
}

// ── key-use gate (stale/revoked/rotated keys refuse) ─────────────────────────

export const KEY_USE_DENY_CODES = Object.freeze([
  "unknown_record",
  "record_invalid",
  "key_id_mismatch",
  "fingerprint_mismatch",
  "stale_rotated_key",
  "state_revoked",
  "state_retired",
] as const);
export type KeyUseDenyCode = (typeof KEY_USE_DENY_CODES)[number];

export type KeyUseDecision =
  | { readonly ok: true; readonly explanation: string }
  | { readonly ok: false; readonly code: KeyUseDenyCode; readonly explanation: string };

/**
 * The key-USE gate over a signing/verification operation (pure). This is
 * the operational layer 25B adds ON TOP of 24B authentication: the crypto
 * may verify a signature while the lifecycle still refuses its USE.
 * Refusals: unknown/invalid record; key-id or fingerprint claim mismatch
 * against the record; state `rotated` (stale key), `revoked`, or `retired`.
 * A signature produced by a stale key remains CRYPTOGRAPHICALLY checkable
 * (24B) — but every operational use refuses, deterministically.
 */
export function decideKeyUse(input: {
  readonly record: KeyLifecycleRecord | null;
  /** The key id claimed by the operation (must re-derive and match). */
  readonly keyIdClaim?: string;
  /** The fingerprint claimed by the signed subject (must match the record). */
  readonly fingerprintClaim?: string;
}): KeyUseDecision {
  if (input.record === null) {
    return { ok: false, code: "unknown_record", explanation: "no lifecycle record exists for this key — refusing key use (fail closed)" };
  }
  const validity = validateLifecycleRecord(input.record);
  if (!validity.ok) {
    return { ok: false, code: "record_invalid", explanation: "lifecycle record failed validation: " + validity.reason };
  }
  if (input.keyIdClaim !== undefined && input.keyIdClaim !== input.record.keyId) {
    return { ok: false, code: "key_id_mismatch", explanation: "claimed key id '" + input.keyIdClaim + "' does not match the record's canonical key id — fingerprint/key-id mismatch refuses (fail closed)" };
  }
  if (input.fingerprintClaim !== undefined && input.fingerprintClaim !== input.record.fingerprint) {
    return { ok: false, code: "fingerprint_mismatch", explanation: "signed subject claims fingerprint '" + input.fingerprintClaim + "' but the record's key is '" + input.record.fingerprint + "' — identity substitution refuses (fail closed)" };
  }
  if (input.record.state === "rotated") {
    return { ok: false, code: "stale_rotated_key", explanation: "this key was ROTATED AWAY — stale keys refuse all operational use; the fresh identity is the only live one (re-identity, not mutation)" };
  }
  if (input.record.state === "revoked") {
    return { ok: false, code: "state_revoked", explanation: "this key is REVOKED — refusal is permanent across restarts; only retirement (an evidence-bearing fact) follows" };
  }
  if (input.record.state === "retired") {
    return { ok: false, code: "state_retired", explanation: "this key is RETIRED — terminal; no use, no resurrection" };
  }
  return {
    ok: true,
    explanation:
      "key use permitted in state '" + input.record.state + "' — authentication capability only; this grants no authority (25A P1/P6)",
  };
}

// ── restart/reload (revocation survives) ─────────────────────────────────────

export type KeyLifecycleReloadDecision =
  | { readonly ok: true; readonly record: KeyLifecycleRecord; readonly explanation: string }
  | { readonly ok: false; readonly code: "reload_refused"; readonly explanation: string };

/**
 * Reload a lifecycle record after a process restart (pure). The record's
 * PUBLIC facts must re-derive (24B `verifyRestartIdentity` + key id) and
 * the record must validate — INCLUDING its state: a record that was
 * revoked/rotated/retired before the restart is reloaded in exactly that
 * state (RESTART PRESERVES REVOCATION). The private key is NOT part of the
 * reload (it never persisted); signing capability is re-established
 * out-of-band by the operator and remains subject to the key-use gate.
 */
export function reloadLifecycleRecord(record: KeyLifecycleRecord | null): KeyLifecycleReloadDecision {
  if (record === null) {
    return { ok: false, code: "reload_refused", explanation: "nothing to reload — a fresh process starts from verified public facts, never from an invented record" };
  }
  const validity = validateLifecycleRecord(record);
  if (!validity.ok) {
    return { ok: false, code: "reload_refused", explanation: "reload refused: " + validity.reason };
  }
  return {
    ok: true,
    record,
    explanation:
      "lifecycle record reloaded in state '" + record.state + "' — revocation/rotation state SURVIVES restart; the private key was never persisted (24B limitation, exact) and remains subject to the key-use gate",
  };
}

// ── rollback judgment (no resurrection) ──────────────────────────────────────

export type RollbackRestoreDecision =
  | { readonly ok: true; readonly code: "restore_idempotent_noop"; readonly explanation: string }
  | { readonly ok: false; readonly code: "rollback_would_resurrect_key" | "rollback_conflict"; readonly explanation: string };

/**
 * Decide whether a durable-state rollback may restore a lifecycle-record
 * snapshot (pure, fail closed). Lifecycle facts are MONOTONE: a snapshot
 * older than a rotated/revoked/retired current state would resurrect a
 * dead key and REFUSES (`rollback_would_resurrect_key`); any other
 * divergence refuses as a conflict for investigation; only an
 * equal-state snapshot restores, as an idempotent no-op.
 */
export function decideRollbackRestore(input: {
  readonly snapshotState: KeyLifecycleState;
  readonly currentState: KeyLifecycleState;
}): RollbackRestoreDecision {
  if (!(KEY_LIFECYCLE_STATES as readonly string[]).includes(input.snapshotState) || !(KEY_LIFECYCLE_STATES as readonly string[]).includes(input.currentState)) {
    return { ok: false, code: "rollback_conflict", explanation: "rollback judgment over an unknown lifecycle state — refusing (fail closed)" };
  }
  if (input.snapshotState === input.currentState) {
    return { ok: true, code: "restore_idempotent_noop", explanation: "snapshot state equals current state — restore is an idempotent no-op; nothing resurrects" };
  }
  const deadNow = KEY_LIFECYCLE_STATE_RANK[input.currentState] >= KEY_LIFECYCLE_STATE_RANK.rotated;
  const snapshotEarlier = KEY_LIFECYCLE_STATE_RANK[input.snapshotState] < KEY_LIFECYCLE_STATE_RANK[input.currentState];
  if (deadNow && snapshotEarlier) {
    return {
      ok: false,
      code: "rollback_would_resurrect_key",
      explanation:
        "the key is '" + input.currentState + "' and the snapshot predates it (snapshot '" + input.snapshotState + "') — restoring would RESURRECT a rotated/revoked/retired key; lifecycle facts are monotone and the rollback refuses (fail closed)",
    };
  }
  return {
    ok: false,
    code: "rollback_conflict",
    explanation:
      "snapshot state '" + input.snapshotState + "' diverges from current state '" + input.currentState + "' — lifecycle history is never rewritten; investigate, never auto-restore",
  };
}

// ── trust non-inheritance (25A P7 made operational) ──────────────────────────

export type TrustInheritanceDecision =
  | { readonly ok: false; readonly code: "trust_inheritance_refused"; readonly explanation: string };

/**
 * The ONLY decision this module offers about inheriting peer trust across
 * rotation — and it always refuses. A rotated identity is a NEW peer: its
 * trust begins EMPTY, and the old identity must exit through the 24C trust
 * machine (evidenced retirement; no resurrection). Any transfer of trust
 * is a NEW local evidenced re-admission decision (24C scope) — never an
 * automatic inheritance, never a silent re-pin of an admitted peer.
 */
export function decideTrustInheritance(input: {
  readonly oldRecord: KeyLifecycleRecord;
  readonly freshNodeId: string;
}): TrustInheritanceDecision {
  void input;
  return {
    ok: false,
    code: "trust_inheritance_refused",
    explanation:
      "ROTATION NEVER INHERITS TRUST (25A P7): the fresh identity '" +
      (input?.freshNodeId ?? "?") +
      "' starts with NO peer trust; the old identity exits only through an evidenced retirement in the 24C trust machine; any re-admission is a NEW local evidenced decision — never automatic, never a silent re-pin",
  };
}
