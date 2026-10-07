/**
 * PHASE 25C — Peer Trust Operations & Local Administration
 * (NO REMOTE CONTROL PLANE / LOCAL OPERATIONS ONLY / SANCTIONED PERSISTENCE
 * ONLY / NO NEW AUTHORITY).
 *
 * A NARROW, locally-initiated administration layer OVER the frozen 24C
 * `PeerRegistry` — it adds ZERO new persistence, ZERO new trust edges, and
 * ZERO new authority. Every mutation delegates to
 * `PeerRegistry.applyTrustTransition` (the sanctioned 23B coordinator
 * junction); this module contains NO store, NO coordinator, NO persist
 * call, and NO new durable kind. Its entire write surface is six decisions
 * that check WHO intends the change and WHY, then delegate:
 *
 *     listPeers / explainPeer        (read-only: inspect/list, explain
 *                                     decision/history)
 *     admitCandidate                 candidate → admitted
 *     quarantinePeer                 → quarantined (any non-terminal peer)
 *     retirePeer                     → retired (the ONE legal exit;
 *                                     quarantined → retired included)
 *     recordReIdentityRelation       old record retired + evidence
 *                                     relation to the fresh NodeId; the
 *                                     replacement identity itself enters
 *                                     ONLY through first_contact_enrolled
 *                                     as its OWN new candidate record
 *
 * The anti-control-plane law (structurally enforced):
 *
 *     A PEER MESSAGE CAN NEVER BE AN ADMIN COMMAND.
 *
 * `assertLocalAdminIntent` requires the caller to present a
 * `LocalAdminIntent` whose `initiatedBy: "local_operator"` — a value that
 * peer traffic cannot mint. `PeerCommandRefusal` analysis exists ONLY to
 * REFUSE: every peer-sourced "admin" claim is refused with the pinned
 * explanation, deterministically, and nothing else in this module accepts
 * a remote origin. Admin mutations additionally require explicit evidence
 * that names the human/operator action — intent metadata is BOUND, never
 * FABRICATED: this layer never signs, asserts, or manufactures a human
 * signature (human signatures remain human-only, per pack law).
 *
 * Inherited verbatim from the frozen layers (nothing re-implemented):
 * revision/idempotency/conflict semantics (22B store + 24C registry),
 * terminal non-resurrection (quarantined → retired only), the three
 * immutable pins (fingerprint/protocol/instance; old fingerprints refuse),
 * stale LOCAL epoch refusal at the coordinator, restart mapping (terminal
 * peers restore EXACTLY terminal — no resurrection), and the law that
 * admin evidence is communication-trust evidence only — it can never serve
 * as execution authority (25A P3/P4).
 */

import { canonicalHash } from "./canonical.js";
import { NODE_ID_PATTERN } from "./federationIdentity.js";
import {
  PEER_TRUST_SCHEMA_VERSION,
  type PeerRegistry,
  type PeerTrustReadResult,
} from "./federationPeers.js";

// ── schema + closed vocabulary ───────────────────────────────────────────────

export const PEER_ADMIN_SCHEMA_VERSION = "menog-peer-admin/v0" as const;
export type PeerAdminSchemaVersion = typeof PEER_ADMIN_SCHEMA_VERSION;

/** The narrow, closed admin-operation vocabulary (25C). */
export const PEER_ADMIN_OPERATIONS = Object.freeze([
  "list_peers",
  "explain_peer",
  "admit_candidate",
  "quarantine_peer",
  "retire_peer",
  "record_re_identity",
] as const);
export type PeerAdminOperation = (typeof PEER_ADMIN_OPERATIONS)[number];

/**
 * WHO initiated the operation. The admin layer accepts ONLY
 * "local_operator" — there is no remote origin in this vocabulary, and a
 * peer message cannot mint one (structural anti-control-plane).
 */
export const PEER_ADMIN_INITIATORS = Object.freeze(["local_operator"] as const);
export type PeerAdminInitiator = (typeof PEER_ADMIN_INITIATORS)[number];

/**
 * Operator-intent metadata BOUND to every admin mutation. Fields are
 * honest-by-construction: `operatorRef` is an opaque local reference to
 * the human/operator action (a session record, an approval note hash, a
 * console transcript id) — NEVER a signature, never fabricated here, and
 * never claimed to authenticate the human cryptographically.
 */
export interface LocalAdminIntent {
  readonly initiatedBy: PeerAdminInitiator;
  /** Opaque local reference for the human/operator action (non-empty). */
  readonly operatorRef: string;
  /** Why the operator is acting (non-empty; recorded verbatim). */
  readonly rationale: string;
  readonly decidedAtEpochMs: number;
  /** The LOCAL epoch in which the operator acted (checked for staleness). */
  readonly localEpochId: string;
}

export const PEER_ADMIN_DENY_CODES = Object.freeze([
  "not_locally_initiated",
  "peer_message_admin_refused",
  "operator_intent_incomplete",
  "stale_admin_epoch",
  "malformed_peer_input",
  "peer_unknown",
  "peer_terminal_state",
  "pin_conflict",
  "machine_refused",
  "persistence_refused",
] as const);
export type PeerAdminDenyCode = (typeof PEER_ADMIN_DENY_CODES)[number];

export type PeerAdminDecision =
  | {
      readonly ok: true;
      readonly operation: PeerAdminOperation;
      readonly nodeId: string;
      readonly from: string | null;
      readonly to: string | null;
      readonly revision: number | null;
      readonly idempotentReplay: boolean;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly operation: PeerAdminOperation;
      readonly denyCode: PeerAdminDenyCode;
      readonly explanation: string;
    };

// ── local-intent gate (the anti-control-plane front door) ────────────────────

export function isWellFormedLocalAdminIntent(intent: unknown): boolean {
  if (intent === null || typeof intent !== "object") return false;
  const i = intent as Partial<LocalAdminIntent> & Record<string, unknown>;
  return (
    i.initiatedBy === "local_operator" &&
    typeof i.operatorRef === "string" &&
    i.operatorRef.trim() !== "" &&
    typeof i.rationale === "string" &&
    i.rationale.trim() !== "" &&
    typeof i.decidedAtEpochMs === "number" &&
    Number.isFinite(i.decidedAtEpochMs) &&
    typeof i.localEpochId === "string" &&
    i.localEpochId.startsWith("re-")
  );
}

export type AdminIntentCheck =
  | { readonly ok: true; readonly intentHash: string; readonly explanation: string }
  | { readonly ok: false; readonly denyCode: PeerAdminDenyCode; readonly explanation: string };

/**
 * The intent gate every ADMIN mutation must pass (pure). Refuses:
 * non-local initiation (`not_locally_initiated`), incomplete intent
 * metadata (`operator_intent_incomplete`), and a stale LOCAL admin epoch
 * (`stale_admin_epoch`) — the pack's "stale admin epoch" case. The intent
 * is hashed canonically so every delegated transition binds WHO decided
 * and WHEN (metadata, never a fabricated human signature).
 */
export function checkLocalAdminIntent(input: {
  readonly intent: LocalAdminIntent;
  /** The registry's (live) epoch id; a mismatch means the operator acted in a stale epoch. */
  readonly liveEpochId: string;
}): AdminIntentCheck {
  if (
    input.intent === null ||
    typeof input.intent !== "object" ||
    (input.intent as unknown as Record<string, unknown>).initiatedBy !== "local_operator"
  ) {
    return {
      ok: false,
      denyCode: "not_locally_initiated",
      explanation:
        "admin operations are LOCAL-ONLY — no remote control plane exists; a peer message can never be an admin command (fail closed)",
    };
  }
  if (!isWellFormedLocalAdminIntent(input.intent)) {
    return {
      ok: false,
      denyCode: "operator_intent_incomplete",
      explanation:
        "operator-intent metadata is incomplete (operatorRef/rationale/decidedAtEpochMs/localEpochId required) — intent is BOUND, never fabricated",
    };
  }
  if (input.intent.localEpochId !== input.liveEpochId) {
    return {
      ok: false,
      denyCode: "stale_admin_epoch",
      explanation:
        "the operator intent was formed in epoch '" + input.intent.localEpochId + "' but the live epoch is '" +
        input.liveEpochId + "' — stale admin epochs fail (fail closed); re-issue the intent in the live epoch",
    };
  }
  return {
    ok: true,
    intentHash: canonicalHash({
      schemaVersion: PEER_ADMIN_SCHEMA_VERSION,
      initiatedBy: input.intent.initiatedBy,
      operatorRef: input.intent.operatorRef,
      rationale: input.intent.rationale,
      decidedAtEpochMs: input.intent.decidedAtEpochMs,
      localEpochId: input.intent.localEpochId,
    }),
    explanation:
      "local operator intent verified and hashed — metadata binds WHO/WHEN/WHY without fabricating any human signature",
  };
}

// ── peer-message admin refusal (analysis ONLY; always refuses) ───────────────

/**
 * The kind of remote "admin" claim a peer message might carry. This
 * vocabulary exists SOLELY to name the refusal deterministically; no code
 * path in this module acts on any of them.
 */
export const PEER_COMMAND_CLAIMS = Object.freeze([
  "self_admit",
  "self_unquarantine",
  "trust_inheritance_claim",
  "admin_evidence_claim",
] as const);
export type PeerCommandClaim = (typeof PEER_COMMAND_CLAIMS)[number];

export interface PeerCommandRefusal {
  readonly refused: true;
  readonly claim: PeerCommandClaim;
  readonly explanation: string;
}

const PEER_COMMAND_REFUSALS: Readonly<Record<PeerCommandClaim, string>> = Object.freeze({
  self_admit:
    "REFUSED (self_admit): a peer can never admit itself — admission is a LOCAL operator decision through the 24C trust machine; a peer message is untrusted DATA, never an admin command",
  self_unquarantine:
    "REFUSED (self_unquarantine): a peer can never lift its own quarantine — quarantined/retired are terminal (no resurrection); re-entry requires a genuinely NEW identity evaluated as a new candidate",
  trust_inheritance_claim:
    "REFUSED (trust_inheritance_claim): a peer claim that a rotated/replacement identity inherits prior trust is void — inheritance is ALWAYS refused (25A P7); the replacement enters as a new candidate with empty trust",
  admin_evidence_claim:
    "REFUSED (admin_evidence_claim): peer-supplied 'admin evidence' is data about a peer, never authorization — admin evidence is communication-trust evidence only and can never serve as execution authority (25A P3/P4)",
});

/** Deterministic refusal of any peer-sourced admin claim (pure; total). */
export function refusePeerCommand(claim: PeerCommandClaim, peerId: string): PeerCommandRefusal {
  void peerId;
  return { refused: true, claim, explanation: PEER_COMMAND_REFUSALS[claim] };
}

// ── the admin session (binds ONE registry; read + narrow mutations) ──────────

export interface PeerAdminSummary {
  readonly nodeId: string;
  readonly trustState: string;
  readonly fingerprint: string;
  readonly instanceId: string;
  readonly protocolVersion: string;
  readonly revision: number;
  readonly terminal: boolean;
  readonly lastTransitionEvidence: string;
}

export interface PeerAdminExplanation {
  readonly nodeId: string;
  readonly trustState: string;
  readonly terminal: boolean;
  readonly revision: number;
  readonly history: readonly string[];
  readonly explanation: string;
}

/**
 * A locally-initiated administration session over ONE 24C registry.
 * Constructed ONLY with an existing `PeerRegistry` (never its own store or
 * coordinator). Read operations are informational; every mutation is
 * intent-gated and delegates to `PeerRegistry.applyTrustTransition` — the
 * ONLY persistence path (no direct-store bypass exists in this module,
 * structurally pinned by the suite).
 */
export class PeerAdminSession {
  readonly #registry: PeerRegistry;
  readonly #sessionId: string;

  private constructor(registry: PeerRegistry, sessionId: string) {
    this.#registry = registry;
    this.#sessionId = sessionId;
  }

  /** The opaque session id (appears in delegated evidence bindings). */
  public get sessionId(): string {
    return this.#sessionId;
  }

  /** Open a session over an existing registry (fail-closed). */
  public static open(
    registry: PeerRegistry,
    sessionId: string
  ): { readonly ok: true; readonly session: PeerAdminSession } | { readonly ok: false; readonly reason: string } {
    if (registry.isClosed) {
      return { ok: false, reason: "the underlying peer registry is closed" };
    }
    if (typeof sessionId !== "string" || sessionId.trim() === "") {
      return { ok: false, reason: "a non-empty session id is required" };
    }
    return { ok: true, session: new PeerAdminSession(registry, sessionId) };
  }

  public get epochId(): string {
    return this.#registry.epochId;
  }

  // ── read-only operations ──────────────────────────────────────────────

  /** Inspect ONE peer (read-only). */
  public inspectPeer(nodeId: string): PeerTrustReadResult {
    return this.#registry.readPeer(nodeId);
  }

  /**
   * List KNOWN peers (read-only). The admin layer reads only node ids it is
   * TOLD about (the registry's read path is by-id; there is no scan-the-
   * store escape hatch here — listing is over the caller's known-peer set,
   * which comes from message/proposal/receipt observations, i.e. DATA).
   */
  public listPeers(knownNodeIds: readonly string[]): { readonly peers: readonly PeerAdminSummary[]; readonly unreadable: readonly string[]; readonly explanation: string } {
    const peers: PeerAdminSummary[] = [];
    const unreadable: string[] = [];
    for (const nodeId of knownNodeIds) {
      const read = this.#registry.readPeer(nodeId);
      if (!read.ok) {
        unreadable.push(nodeId);
        continue;
      }
      peers.push({
        nodeId: read.state.nodeId,
        trustState: read.state.trustState,
        fingerprint: read.state.fingerprint,
        instanceId: read.state.instanceId,
        protocolVersion: read.state.protocolVersion,
        revision: read.revision,
        terminal: read.terminal,
        lastTransitionEvidence: read.state.lastTransitionEvidence,
      });
    }
    return {
      peers: Object.freeze(peers),
      unreadable: Object.freeze(unreadable),
      explanation: "read-only listing over the caller's known-peer set; unreadable/unknown ids reported explicitly, never guessed",
    };
  }

  /**
   * Explain ONE peer's decision/history (read-only): the current state,
   * its terminality, and the deterministic explanation family for how a
   * peer in this state behaves (admission/trust machine semantics).
   */
  public explainPeer(nodeId: string): PeerAdminExplanation {
    const read = this.#registry.readPeer(nodeId);
    if (!read.ok) {
      return {
        nodeId,
        trustState: "unknown",
        terminal: false,
        revision: 0,
        history: [],
        explanation: "peer is unknown or unreadable (" + read.failureCode + ": " + read.reason + ") — first contact may enroll it only as a candidate",
      };
    }
    const state = read.state.trustState;
    const perState: Readonly<Record<string, string>> = Object.freeze({
      candidate:
        "candidate — first contact enrolled; admission to 'admitted' requires a LOCAL evidenced operator decision (admit_candidate); the candidate itself cannot cause it",
      admitted:
        "admitted — communication trust only; every execution still requires fresh LOCAL Allocation → Policy → Phase-20 → Phase-21; the peer can be quarantined/retired by the operator",
      quarantined:
        "quarantined — TERMINAL-facing: the only exit is evidenced retirement; the peer cannot self-unquarantine and its traffic refuses pre-signature",
      retired:
        "retired — TERMINAL: no transitions exist; a replacement identity enters only as a NEW candidate (re-identity, never resurrection)",
    });
    return {
      nodeId: read.state.nodeId,
      trustState: state,
      terminal: read.terminal,
      revision: read.revision,
      history: [
        "pinned at " + new Date(read.state.pinnedAtEpochMs).toISOString() + " (fingerprint/protocol/instance immutable)",
        "last transition evidence: " + read.state.lastTransitionEvidence,
        "updated at " + new Date(read.state.updatedAtEpochMs).toISOString() + " (revision " + read.revision + ")",
      ],
      explanation: perState[state] ?? "state '" + state + "' — closed 24A vocabulary; transitions only through the evidenced local machine",
    };
  }

  // ── mutations (intent-gated; delegate ONLY to the 24C registry) ───────

  /**
   * Admit a candidate (local operator decision). Refuses non-candidates
     * (the machine has no other admission edge).
   */
  public admitCandidate(input: {
    readonly nodeId: string;
    readonly fingerprint: string;
    readonly instanceId: string;
    readonly protocolVersion: string;
    readonly intent: LocalAdminIntent;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
  }): PeerAdminDecision {
    return this.#mutate("admit_candidate", input.nodeId, input.intent, "admission_request_accepted", {
      fingerprint: input.fingerprint,
      instanceId: input.instanceId,
      protocolVersion: input.protocolVersion,
      evidence:
        "LOCAL operator admission (" + input.intent.operatorRef + "): " + input.intent.rationale,
      transactionId: input.transactionId,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
    });
  }

  /** Quarantine a peer (local operator decision, evidence-bearing). */
  public quarantinePeer(input: {
    readonly nodeId: string;
    readonly fingerprint: string;
    readonly instanceId: string;
    readonly protocolVersion: string;
    readonly intent: LocalAdminIntent;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
  }): PeerAdminDecision {
    return this.#mutate("quarantine_peer", input.nodeId, input.intent, "peer_misbehavior_evidenced", {
      fingerprint: input.fingerprint,
      instanceId: input.instanceId,
      protocolVersion: input.protocolVersion,
      evidence:
        "LOCAL operator quarantine (" + input.intent.operatorRef + "): " + input.intent.rationale,
      transactionId: input.transactionId,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
    });
  }

  /**
   * Retire a peer (local operator decision) — the ONE legal exit for a
   * quarantined peer and the direct exit for an admitted one.
   */
  public retirePeer(input: {
    readonly nodeId: string;
    readonly fingerprint: string;
    readonly instanceId: string;
    readonly protocolVersion: string;
    readonly intent: LocalAdminIntent;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
  }): PeerAdminDecision {
    return this.#mutate("retire_peer", input.nodeId, intentOf(input, "retirement"), "operator_retirement", {
      fingerprint: input.fingerprint,
      instanceId: input.instanceId,
      protocolVersion: input.protocolVersion,
      evidence:
        "LOCAL operator retirement (" + input.intent.operatorRef + "): " + input.intent.rationale,
      transactionId: input.transactionId,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
    });
  }

  /**
   * Record a RE-IDENTITY relation: retire the OLD identity record with
   * evidence naming the replacement, and pin the RELATION (deterministic
   * hash over old→new) in the returned explanation. The replacement
   * identity does NOT inherit anything and is NOT admitted here — it
   * enters only through first_contact_enrolled as its OWN new candidate
   * record (24C law), at most with this session's separate admit decision.
   */
  public recordReIdentityRelation(input: {
    readonly oldNodeId: string;
    readonly newNodeId: string;
    readonly oldFingerprint: string;
    readonly newInstanceRef: string;
    readonly oldProtocolVersion: string;
    readonly oldInstanceId: string;
    readonly intent: LocalAdminIntent;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
  }): PeerAdminDecision {
    if (typeof input.newNodeId !== "string" || !NODE_ID_PATTERN.test(input.newNodeId)) {
      return {
        ok: false,
        operation: "record_re_identity",
        denyCode: "malformed_peer_input",
        explanation: "the replacement NodeId is malformed — refusing to record a relation to a non-identity (fail closed)",
      };
    }
    if (input.oldNodeId === input.newNodeId) {
      return {
        ok: false,
        operation: "record_re_identity",
        denyCode: "malformed_peer_input",
        explanation: "re-identity requires a genuinely different NodeId — the old and new ids are equal (fail closed)",
      };
    }
    const relationHash = canonicalHash({
      schemaVersion: PEER_ADMIN_SCHEMA_VERSION,
      relation: "re_identity",
      oldNodeId: input.oldNodeId,
      newNodeId: input.newNodeId,
      operatorRef: input.intent.operatorRef,
      decidedAtEpochMs: input.intent.decidedAtEpochMs,
    });
    return this.#mutate("record_re_identity", input.oldNodeId, input.intent, "operator_retirement", {
      fingerprint: input.oldFingerprint,
      instanceId: input.oldInstanceId,
      protocolVersion: input.oldProtocolVersion,
      evidence:
        "LOCAL operator re-identity relation (" + input.intent.operatorRef + "): " + input.intent.rationale +
        " — replacement identity " + input.newNodeId + " (" + input.newInstanceRef + ") relation " + relationHash +
        "; the replacement enters ONLY as a new candidate with NO inherited trust (P7)",
      transactionId: input.transactionId,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
    });
  }

  // ── the single mutation funnel ────────────────────────────────────────

  #mutate(
    operation: PeerAdminOperation,
    nodeId: string,
    intent: LocalAdminIntent,
    reason: "admission_request_accepted" | "peer_misbehavior_evidenced" | "operator_retirement",
    params: {
      readonly fingerprint: string;
      readonly instanceId: string;
      readonly protocolVersion: string;
      readonly evidence: string;
      readonly transactionId: string;
      readonly lineageRoot: string;
      readonly lineageParent: string | null;
    }
  ): PeerAdminDecision {
    const gate = checkLocalAdminIntent({ intent, liveEpochId: this.epochId });
    if (!gate.ok) {
      return { ok: false, operation, denyCode: gate.denyCode, explanation: gate.explanation };
    }
    if (typeof nodeId !== "string" || !NODE_ID_PATTERN.test(nodeId)) {
      return { ok: false, operation, denyCode: "malformed_peer_input", explanation: "peer id is malformed — refusing (fail closed)" };
    }
    // Delegate to the ONLY sanctioned persistence path (24C → 23B). No
    // direct store access exists in this module (structurally pinned).
    const applied = this.#registry.applyTrustTransition({
      nodeId,
      fingerprint: params.fingerprint,
      instanceId: params.instanceId,
      protocolVersion: params.protocolVersion,
      reason,
      evidence: params.evidence,
      transactionId: params.transactionId,
      lineageRoot: params.lineageRoot,
      lineageParent: params.lineageParent,
      nowEpochMs: intent.decidedAtEpochMs,
    });
    if (!applied.ok) {
      const denyCode: PeerAdminDenyCode =
        applied.failureCode === "peer_terminal_state"
          ? "peer_terminal_state"
          : applied.failureCode === "peer_unknown"
            ? "peer_unknown"
            : applied.failureCode === "stale_epoch"
              ? "stale_admin_epoch"
              : applied.failureCode === "malformed_peer_input"
                ? "malformed_peer_input"
                : applied.failureCode === "fingerprint_pin_conflict" ||
                    applied.failureCode === "protocol_pin_conflict" ||
                    applied.failureCode === "instance_pin_conflict"
                  ? "pin_conflict"
                  : applied.failureCode === "stale_revision" || applied.failureCode === "persistence_denied" || applied.failureCode === "coordinator_closed"
                    ? "persistence_refused"
                    : "machine_refused";
      return {
        ok: false,
        operation,
        denyCode,
        explanation: "24C registry refused (" + applied.failureCode + "): " + applied.explanation,
      };
    }
    return {
      ok: true,
      operation,
      nodeId: applied.nodeId,
      from: applied.from,
      to: applied.to,
      revision: applied.revision,
      idempotentReplay: applied.idempotentReplay,
      explanation:
        applied.explanation +
        " — operator intent bound (" + gate.intentHash.slice(0, 16) + "), locally initiated; communication trust only, no execution authority",
    };
  }
}

function intentOf<T extends { readonly intent: LocalAdminIntent }>(input: T, what: string): LocalAdminIntent {
  void what;
  return input.intent;
}

/** Schema version re-export (single source of the admin record vocabulary). */
export { PEER_TRUST_SCHEMA_VERSION };
