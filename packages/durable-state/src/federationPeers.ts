/**
 * PHASE 24C — Peer Registry, Admission & Quarantine
 * (LOCAL STATE MACHINE / NO REMOTE EXECUTION / SANCTIONED PERSISTENCE ONLY).
 *
 * This module is the ONLY sanctioned durable home for federation peer
 * trust facts (new 22A kind `peer_trust_registry` — added through the
 * documented unfreeze-protocol event; classified authoritative +
 * versioned_mutable + terminal-quarantine exactly like the skill/tool
 * registry). Construction is ONLY through `PeerRegistry.open` (the 23C
 * pattern): the registry holds the epoch's store + coordinator pair, and
 * every write goes through the 23B `RuntimeStateCoordinator` junction
 * (sealed canonical envelope, epoch/lineage binding, formal barrier).
 * No direct `store.persist` call exists here (structurally pinned) and no
 * alternate persistence path is representable through this module.
 *
 * Laws (pack + 24A):
 *  - Admission is LOCAL and NEVER execution authority: the registry stores
 *    trust STATE only; every later execution remains behind fresh LOCAL
 *    Allocation → Policy → Phase-20 isolation → Phase-21 governed tool
 *    runtime.
 *  - "Pin fingerprint + protocol/schema + state": the three pins are set
 *    at first contact and can never be rewritten in place. Rotation is
 *    RE-IDENTITY (24B): a new key canonically yields a new NodeId, which
 *    enters as its own first-contact record while the old record is
 *    retired through an evidenced local transition. There is no in-place
 *    re-pinning path — a presented fingerprint/protocol/instance mismatch
 *    refuses.
 *  - Stale epochs fail: the coordinator re-checks the durable live-owner
 *    claim before every persist (a stale LOCAL epoch refuses); PEER epoch
 *    freshness is enforced per-process by the 24A instance tracker, whose
 *    durable counterpart is the pinned (nodeId, fingerprint, instanceId)
 *    triple — an instance re-binding to a different node is refused
 *    upstream and cannot be persisted here.
 *  - Quarantined/retired peers do not resurrect: the trust machine has no
 *    resurrection edge, terminal states are store-pinned facts, and
 *    recovery maps terminal peers onto `terminalPeerIds` (data of record;
 *    they restore EXACTLY terminal — the 22D anti-resurrection law).
 *
 * Reused verbatim from the frozen layers: revision/supersedes semantics,
 * transaction replay idempotency (same content + same transactionId = a
 * no-op replay), duplicate-transaction conflicts (same id/revision with
 * different content = refusal), secret-policy scanning, canonical
 * content-hash binding, terminal-quarantine classification, the 22A
 * recovery decision vocabulary, and the 23A/23B coordination outcomes.
 */

import { canonicalHash } from "./canonical.js";
import {
  NODE_TRUST_STATES,
  PEER_TRUST_TRANSITIONS,
  decideTrustTransition,
  type NodeTrustState,
} from "./federationIdentity.js";
import {
  peerDurableId,
  peerNodeIdOfRecordId,
  type PeerTrustState,
} from "./statePersistence.js";
import type { DurableStore } from "./store.js";
import type { RuntimeStateCoordinator } from "./coordinator.js";

// ── schema + vocabulary ──────────────────────────────────────────────────────

export const PEER_TRUST_SCHEMA_VERSION = "menog-federation-peer-trust/v0" as const;
export type PeerTrustSchemaVersion = typeof PEER_TRUST_SCHEMA_VERSION;

/** Why a trust transition is happening (closed union; evidence-bearing). */
export const PEER_TRANSITION_REASONS = Object.freeze([
  "first_contact_enrolled",
  "admission_request_accepted",
  "admission_request_quarantined",
  "peer_misbehavior_evidenced",
  "operator_retirement",
] as const);
export type PeerTransitionReason = (typeof PEER_TRANSITION_REASONS)[number];

/** Which reason may target which trust state (the evidenced edges). */
const REASON_TARGETS: Readonly<Record<PeerTransitionReason, readonly NodeTrustState[]>> =
  Object.freeze({
    first_contact_enrolled: Object.freeze(["candidate"] as const),
    admission_request_accepted: Object.freeze(["admitted"] as const),
    admission_request_quarantined: Object.freeze(["quarantined"] as const),
    peer_misbehavior_evidenced: Object.freeze(["quarantined"] as const),
    operator_retirement: Object.freeze(["retired"] as const),
  });

export const PEER_REGISTRY_FAILURE_CODES = Object.freeze([
  "coordinator_closed",
  "stale_epoch",
  "malformed_peer_input",
  "unknown_trust_state",
  "peer_unknown",
  "peer_terminal_state",
  "trust_transition_refused",
  "fingerprint_pin_conflict",
  "protocol_pin_conflict",
  "instance_pin_conflict",
  "stale_revision",
  "persistence_denied",
  "read_failed",
  "read_quarantined",
] as const);
export type PeerRegistryFailureCode = (typeof PEER_REGISTRY_FAILURE_CODES)[number];

export type PeerRegistryWriteResult =
  | {
      readonly ok: true;
      readonly code: "peer_state_durable";
      readonly nodeId: string;
      readonly recordId: string;
      readonly revision: number;
      readonly commitSequence: number;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "peer_write_refused";
      readonly failureCode: PeerRegistryFailureCode;
      readonly storeFailureCode: string | null;
      readonly explanation: string;
    };

export type PeerTransitionDecision =
  | {
      readonly ok: true;
      readonly code: "peer_transition_applied";
      readonly nodeId: string;
      readonly from: NodeTrustState | null;
      readonly to: NodeTrustState;
      readonly state: PeerTrustState;
      readonly revision: number;
      readonly idempotentReplay: boolean;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "peer_transition_refused";
      readonly failureCode: PeerRegistryFailureCode;
      readonly storeFailureCode: string | null;
      readonly explanation: string;
    };

export type PeerTrustReadResult =
  | {
      readonly ok: true;
      readonly state: PeerTrustState;
      readonly recordId: string;
      readonly revision: number;
      readonly terminal: boolean;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly failureCode: PeerRegistryFailureCode;
      readonly reason: string;
    };

/** Durable id helper (the `peer-` prefix rule, pinned in one place). */
export function peerRecordId(nodeId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  return peerDurableId(nodeId);
}

/** The trust vocabulary, re-exported for callers (single source: 24A). */
export { NODE_TRUST_STATES, PEER_TRUST_TRANSITIONS };

// ── the registry (23C construction pattern; store + coordinator pair) ────────

/**
 * The ONLY sanctioned durable registry for peer trust facts, bound to ONE
 * epoch over ONE open store. All construction is through `open`
 * (fail-closed); every method returns an EXPLICIT outcome.
 */
export class PeerRegistry {
  readonly #store: DurableStore;
  readonly #coordinator: RuntimeStateCoordinator;
  readonly #epochId: string;
  #closed: boolean = false;

  private constructor(store: DurableStore, coordinator: RuntimeStateCoordinator, epochId: string) {
    this.#store = store;
    this.#coordinator = coordinator;
    this.#epochId = epochId;
  }

  /** Bind the registry to one epoch's coordinator (never constructs its own). */
  public static open(
    store: DurableStore,
    coordinator: RuntimeStateCoordinator
  ): { readonly ok: true; readonly registry: PeerRegistry } | { readonly ok: false; readonly reason: string } {
    if (!store.isOpen) {
      return { ok: false, reason: "the store is closed — no registry can be bound" };
    }
    if (coordinator.isClosed) {
      return { ok: false, reason: "the coordinator for this epoch is closed" };
    }
    return { ok: true, registry: new PeerRegistry(store, coordinator, coordinator.epochId) };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get isClosed(): boolean {
    return this.#closed || this.#coordinator.isClosed;
  }

  // ── read path (fail-closed re-verification on the record's OWN kind) ──

  /**
   * Read one peer's trust state. The stored payload is re-verified: identity
   * binding against the durable id (`peer-<nodeId>`), closed trust
   * vocabulary, and the schema version. Terminal states are reported as
   * terminal (data of record; they restore EXACTLY terminal).
   */
  public readPeer(nodeId: string): PeerTrustReadResult {
    if (this.isClosed) {
      return { ok: false, failureCode: "coordinator_closed", reason: "the registry's coordinator is closed" };
    }
    const id = peerDurableId(nodeId);
    if (!id.ok) {
      return { ok: false, failureCode: "malformed_peer_input", reason: id.reason };
    }
    const read = this.#store.readRecord(id.recordId);
    if (!read.ok) {
      return {
        ok: false,
        failureCode: read.code === "quarantined" ? "read_quarantined" : "peer_unknown",
        reason: read.reason,
      };
    }
    const parsed = (read.record.payload as Record<string, unknown>)["peerTrust"];
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, failureCode: "read_failed", reason: "stored peer payload is missing its record" };
    }
    const state = parsed as PeerTrustState;
    if (state.nodeId !== peerNodeIdOfRecordId(id.recordId)) {
      return { ok: false, failureCode: "read_failed", reason: "stored nodeId disagrees with the durable id (identity binding)" };
    }
    if (state.schemaVersion !== PEER_TRUST_SCHEMA_VERSION) {
      return { ok: false, failureCode: "read_failed", reason: "stored peer record carries a foreign schema version" };
    }
    if (!(NODE_TRUST_STATES as readonly string[]).includes(state.trustState)) {
      return { ok: false, failureCode: "read_failed", reason: "stored trust state is not in the closed vocabulary" };
    }
    const terminal = state.trustState === "quarantined" || state.trustState === "retired";
    return {
      ok: true,
      state,
      recordId: id.recordId,
      revision: read.record.revision,
      terminal,
      explanation: terminal
        ? "peer trust state restored EXACTLY terminal — no resurrection surface exists"
        : "peer trust state read and re-verified on its own kind",
    };
  }

  // ── the local state machine (decide → persist, evidence-bearing) ──────

  /**
   * Decide + persist ONE evidenced trust transition for ONE peer.
   *
   * Fail-closed chain: current state read (fail-closed) → reason/target
   * consistency → closed 24A trust machine → evidence required → terminal
   * refusal (L6) → the three pins (fingerprint/protocol/instance can never
   * be rewritten in place; rotation is re-identity, a NEW NodeId record) →
   * revision chain (current + 1; concurrent writers conflict at the store,
   * never last-writer-wins).
   *
   * A replayed transactionId (crash after commit) is IDEMPOTENT: the store
   * reports its own duplicate-transaction code, the registry re-reads the
   * already-committed state, and reports the ORIGINAL revision — never
   * double-applied. A revision conflict from a DIFFERENT transaction is a
   * concurrent-writer refusal (stale_revision), never a heal.
   */
  public applyTrustTransition(input: {
    readonly nodeId: string;
    readonly fingerprint: string;
    readonly instanceId: string;
    readonly protocolVersion: string;
    readonly reason: PeerTransitionReason;
    readonly evidence: string;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
    readonly nowEpochMs: number;
  }): PeerTransitionDecision {
    if (this.isClosed) {
      return refused("coordinator_closed", null, "the registry's coordinator is closed — no transitions");
    }
    const current = this.readPeer(input.nodeId);
    let from: NodeTrustState | null = null;
    let nextRevision = 1;
    let pinned: PeerTrustState | null = null;
    if (current.ok) {
      from = current.state.trustState;
      pinned = current.state;
      nextRevision = current.revision + 1;
    } else if (current.failureCode !== "peer_unknown") {
      return {
        ok: false,
        code: "peer_transition_refused",
        failureCode: current.failureCode,
        storeFailureCode: null,
        explanation: current.reason,
      };
    }
    const targets = REASON_TARGETS[input.reason];
    const target = targets[0];
    if (targets.length !== 1 || target === undefined) {
      return refused("trust_transition_refused", null, "reason '" + input.reason + "' has no single target state — refusing");
    }
    // State-based idempotency: a transition whose target EQUALS the current
    // persisted state is a NO-OP (the crash-replay case — the transaction
    // already committed and the read shows its effect). It is reported as
    // an idempotent replay at the CURRENT revision, never re-persisted and
    // never double-applied. Identity-binding checks (the three pins) run
    // FIRST — an idempotent no-op must still present the pinned identity.
    if (from !== null && from === target && current.ok) {
      if (current.state.fingerprint !== input.fingerprint) {
        return refused(
          "fingerprint_pin_conflict",
          null,
          "the presented fingerprint differs from the pinned one — pins are immutable; rotation is RE-IDENTITY (a new key yields a new NodeId and a new first-contact record; retire this record with operator_retirement)",
        );
      }
      if (current.state.protocolVersion !== input.protocolVersion) {
        return refused("protocol_pin_conflict", null, "the presented protocol version differs from the pinned one — pins are immutable");
      }
      if (current.state.instanceId !== input.instanceId) {
        return refused("instance_pin_conflict", null, "the presented instance id differs from the pinned one — pins are immutable");
      }
      return {
        ok: true,
        code: "peer_transition_applied",
        nodeId: input.nodeId,
        from,
        to: target,
        state: current.state,
        revision: current.revision,
        idempotentReplay: true,
        explanation: "idempotent no-op: the peer is already in the target state (transaction already committed; never double-applied)",
      };
    }
    if (from !== null) {
      if (from === "quarantined" || from === "retired") {
        return refused(
          "peer_terminal_state",
          null,
          "peer is '" + from + "' — quarantined/retired peers do not resurrect (L6, fail closed); re-entry requires a genuinely new identity",
        );
      }
      // Pin laws: the three pins are immutable for a given NodeId record.
      if (pinned !== null) {
        if (pinned.fingerprint !== input.fingerprint) {
          return refused(
            "fingerprint_pin_conflict",
            null,
            "the presented fingerprint differs from the pinned one — pins are immutable; rotation is RE-IDENTITY (a new key yields a new NodeId and a new first-contact record; retire this record with operator_retirement)",
          );
        }
        if (pinned.protocolVersion !== input.protocolVersion) {
          return refused("protocol_pin_conflict", null, "the presented protocol version differs from the pinned one — pins are immutable");
        }
        if (pinned.instanceId !== input.instanceId) {
          return refused("instance_pin_conflict", null, "the presented instance id differs from the pinned one — pins are immutable");
        }
      }
    } else if (input.reason !== "first_contact_enrolled") {
      return refused(
        "trust_transition_refused",
        null,
        "a peer unknown to the registry enters ONLY as 'candidate' through first_contact_enrolled — admission is a separate evidenced transition",
      );
    }
    const machine = decideTrustTransition({ from: from ?? "unknown", to: target, evidence: input.evidence });
    if (!machine.ok) {
      return refused("trust_transition_refused", null, machine.explanation);
    }
    const state: PeerTrustState = {
      schemaVersion: PEER_TRUST_SCHEMA_VERSION,
      nodeId: input.nodeId,
      fingerprint: input.fingerprint,
      instanceId: input.instanceId,
      trustState: target,
      protocolVersion: input.protocolVersion,
      pinnedAtEpochMs: pinned !== null ? pinned.pinnedAtEpochMs : input.nowEpochMs,
      updatedAtEpochMs: input.nowEpochMs,
      lastTransitionEvidence: input.evidence,
    };
    const write = this.#persist(state, nextRevision, nextRevision === 1 ? null : nextRevision - 1, input);
    if (!write.ok) {
      // Idempotent replay: the store says this exact transaction already
      // committed. Re-read and report the ORIGINAL applied revision.
      if (write.storeFailureCode === "duplicate_transaction") {
        const replayed = this.readPeer(input.nodeId);
        if (replayed.ok) {
          return {
            ok: true,
            code: "peer_transition_applied",
            nodeId: input.nodeId,
            from,
            to: replayed.state.trustState,
            state: replayed.state,
            revision: replayed.revision,
            idempotentReplay: true,
            explanation: "idempotent replay: this transaction already committed (store-level idempotency; never double-applied)",
          };
        }
      }
      return {
        ok: false,
        code: "peer_transition_refused",
        failureCode: write.failureCode === "stale_epoch" ? "stale_epoch" : write.failureCode,
        storeFailureCode: write.storeFailureCode,
        explanation: write.explanation,
      };
    }
    return {
      ok: true,
      code: "peer_transition_applied",
      nodeId: input.nodeId,
      from,
      to: target,
      state,
      revision: write.revision,
      idempotentReplay: false,
      explanation:
        "peer trust transition " + (from ?? "peer_unknown") + "→" + target + " persisted with evidence through the sanctioned junction; communication trust only — no execution authority",
    };
  }

  // ── write path (the ONLY sanctioned persistence for peer facts) ───────

  #persist(
    state: PeerTrustState,
    revision: number,
    supersedesRevision: number | null,
    input: {
      readonly transactionId: string;
      readonly lineageRoot: string;
      readonly lineageParent: string | null;
      readonly nowEpochMs: number;
    }
  ): PeerRegistryWriteResult {
    const id = peerDurableId(state.nodeId);
    if (!id.ok) {
      return refusedWrite("malformed_peer_input", null, id.reason);
    }
    const payload: Record<string, unknown> = {
      stateKind: "peer_trust" as const,
      peerTrust: { ...state },
    };
    const result = this.#coordinator.acceptMutation({
      kind: "peer_trust_registry",
      recordId: id.recordId,
      revision,
      supersedesRevision,
      payload,
      transactionId: input.transactionId,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
      createdAtEpochMs: input.nowEpochMs,
    });
    if (!result.ok) {
      return {
        ok: false,
        code: "peer_write_refused",
        failureCode: result.code === "refused_pre_commit" && result.failureCode === "stale_epoch" ? "stale_epoch" : "persistence_denied",
        storeFailureCode: result.code === "refused_pre_commit" ? result.storeFailureCode : null,
        explanation: result.explanation,
      };
    }
    return {
      ok: true,
      code: "peer_state_durable",
      nodeId: state.nodeId,
      recordId: id.recordId,
      revision: result.revision,
      commitSequence: result.commitSequence,
      explanation:
        "peer trust state persisted through the sanctioned 23B coordinator junction (sealed, epoch-bound, barrier-confirmed); this is DATA about communication trust — it grants no execution authority",
    };
  }
}

function refused(
  failureCode: PeerRegistryFailureCode,
  storeFailureCode: string | null,
  explanation: string
): PeerTransitionDecision {
  return { ok: false, code: "peer_transition_refused", failureCode, storeFailureCode, explanation };
}

function refusedWrite(
  failureCode: PeerRegistryFailureCode,
  storeFailureCode: string | null,
  explanation: string
): PeerRegistryWriteResult {
  return { ok: false, code: "peer_write_refused", failureCode, storeFailureCode, explanation };
}

// ── recovery mapping (facts, not authority; terminal peers stay terminal) ────

export interface PeerRecoveryMapping {
  readonly terminalPeerIds: readonly string[];
  readonly peerRecordsAdmitted: number;
  readonly explanation: string;
}

/**
 * Map a 22E recovery result onto the 24C peer vocabulary: recovered peer
 * facts are DATA (`recovered_data` authority), terminal peers are reported
 * as terminal (they restore EXACTLY terminal), and NOTHING here grants
 * execution authority. Callers use the report to rebuild their in-memory
 * 24A trackers — never to re-admit, resurrect, or authorize.
 */
export function mapPeerRecovery(input: {
  readonly recoveryDecisionAuthority: "recovered_data";
  readonly terminalPeerIds: readonly string[];
  readonly peerRecordsAdmitted: number;
}): PeerRecoveryMapping {
  return Object.freeze({
    terminalPeerIds: Object.freeze([...input.terminalPeerIds]),
    peerRecordsAdmitted: input.peerRecordsAdmitted,
    explanation:
      "recovered peer facts are recovered_data (no authority); terminal peers restored exactly terminal — anti-resurrection holds across restarts",
  });
}

/** Evidence-hash helper for callers building transition evidence strings. */
export function peerTransitionEvidenceHash(input: {
  readonly nodeId: string;
  readonly targetState: NodeTrustState;
  readonly subjectHash: string;
  readonly atEpochMs: number;
}): string {
  return canonicalHash(input);
}
