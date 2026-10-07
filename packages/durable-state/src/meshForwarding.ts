/**
 * PHASE 27F — Multi-Hop Proposal Forwarding (GOVERNED LOGICAL FORWARDING
 * OVER THE EXISTING SANCTIONED TRANSPORT / FORWARD != ENDORSE).
 *
 * This module is the LOCAL logical decision layer for forwarding a
 * proposal onward through a chain of forwarders. It decides WHETHER and
 * UNDER WHAT GOVERNED CONDITIONS a forward may proceed; the bytes ride
 * the caller's existing sanctioned transport (24D/26 fixture discipline)
 * — this module opens no socket, spawns nothing, and adds no network
 * surface of any kind.
 *
 * THE LAWS IT ENFORCES
 *   · FORWARD != ENDORSE — every successful forward carries
 *     endorsement: "none" and authority: "none" as STRUCTURAL LITERALS:
 *     relaying inert DATA endorses nothing, grants no trust, no
 *     admission, no authority. The registry has no endorse/approve/
 *     grant/authorize method (prototype method set suite-pinned).
 *   · ORIGIN IS IMMUTABLE (27A M4) — originNodeId is fixed at first
 *     forward; a forwarder presenting itself as origin refuses
 *     `refused_origin_substitution` (composing the frozen 27A
 *     `decideMeshClaim` forwarder_origin_claim refusal so the
 *     FORWARDER_NOT_ORIGIN pin names the law), and a later hop that
 *     changes the recorded origin refuses too. forwardCount chains
 *     accumulate every forwarder; nothing is replaced.
 *   · PROPOSAL IDENTITY IS BINDING — proposalId (24E fp- pattern) and
 *     proposalHash (sha256- ref pattern) are bound TOGETHER at first
 *     forward: the same id with a different hash, or the same hash
 *     under a different id, refuses `refused_identity_mutation`; a
 *     changed destination refuses `refused_destination_mutation`.
 *   · PROVENANCE IS APPEND-ONLY — presented provenanceRefs must
 *     CONTAIN every previously recorded ref: stripping refuses
 *     `refused_provenance_stripped`; new refs append (never removed,
 *     never reordered).
 *   · BOUNDED HOP BUDGET — frozen `FORWARDING_BOUNDS.maxHops` caps the
 *     budget at first forward; every forward consumes EXACTLY one unit
 *     (budget must descend by exactly one — a caller may exceed a
 *     bound, never redefine the descent); exhausted or over-bound
 *     budgets refuse `refused_hop_limit`; skipped hops refuse
 *     `refused_hop_out_of_sequence`.
 *   · REPLAY CONTEXT — a completed hop re-presented, or a forwarder
 *     that already forwarded this proposal, refuses
 *     `refused_replay`; refusals leave the registry EXACTLY as it was.
 *   · TRANSPORT-BOUNDARY HYGIENE — every string surface is scanned by
 *     the frozen 25D egress classifier before anything is recorded
 *     (secret / executable / forbidden material refuse), so nothing
 *     unsafe rides the sanctioned transport.
 *   · DESTINATION EXECUTION IS NOT HERE — forwarding never executes:
 *     executionAuthorized stays structurally false; destination
 *     execution still requires fresh LOCAL allocation + fresh LOCAL
 *     Policy for the assigned actor + frozen Phase-20/21.
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/
 * consensus/global authority; no socket, no listener, no spawn, no
 * clock (caller-supplied epochs only), no store access (in-memory
 * bounded registry only); no alternate listener/spawn/persist/control
 * path; no tool or Policy surface. Observability is read-only
 * (snapshot/fingerprint), never control.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import { findEgressFindings } from "./federationEgress.js";
import {
  FEDERATION_PROPOSAL_ID_PATTERN,
  PROPOSAL_HASH_REF_PATTERN,
} from "./federationProposals.js";
import {
  decideMeshClaim,
  MESH_TRUST_PIN_EXPLANATIONS,
} from "./meshTopologyTrust.js";

/** Forwarding schema version (27F). */
export const FORWARDING_SCHEMA_VERSION = "menog-mesh-forwarding/v0" as const;
export type ForwardingSchemaVersion = typeof FORWARDING_SCHEMA_VERSION;

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/**
 * Hard caps on the forwarding registry. The hop budget starts within
 * `maxHops` and descends by exactly one per forward; refusals never
 * evict, never grow past a bound, never re-inflate a budget.
 */
export const FORWARDING_BOUNDS = Object.freeze({
  maxHops: 8,
  maxTrackedProposals: 64,
  maxProvenanceRefs: 16,
  maxNodeIdChars: 128,
  maxProvenanceRefChars: 128,
});
export type ForwardingBoundName = keyof typeof FORWARDING_BOUNDS;

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed forwarding refusal codes (fail-closed; no silent handling). */
export const FORWARDING_REFUSAL_CODES = Object.freeze([
  "refused_invalid_forward",
  "refused_field_bound",
  "refused_secret_material",
  "refused_executable_material",
  "refused_forbidden_material",
  "refused_origin_substitution",
  "refused_identity_mutation",
  "refused_destination_mutation",
  "refused_provenance_stripped",
  "refused_replay",
  "refused_hop_out_of_sequence",
  "refused_hop_limit",
  "refused_registry_bound",
  "refused_unknown",
] as const);
export type ForwardRefusalCode = (typeof FORWARDING_REFUSAL_CODES)[number];

// ── inputs and records ───────────────────────────────────────────────────────

/**
 * Caller-supplied forward: ONE hop of ONE proposal through ONE
 * forwarder. `provenanceRefs` carries the proposal's provenance
 * references AS PRESENTED (append-only history: must contain everything
 * recorded so far). `hopBudgetRemaining` is the budget BEFORE this
 * forward; forwarding consumes exactly one.
 */
export interface ForwardInput {
  readonly proposalId: string;
  readonly proposalHash: string;
  readonly originNodeId: string;
  readonly destinationNodeId: string;
  readonly forwarderNodeId: string;
  readonly hopIndex: number;
  readonly hopBudgetRemaining: number;
  readonly provenanceRefs: readonly string[];
  readonly observedAtEpochMs: number;
}

/** A stored forwarding record: append-only knowledge for one proposal. */
export interface ForwardingRecord {
  readonly proposalId: string;
  readonly proposalHash: string;
  readonly originNodeId: string;
  readonly destinationNodeId: string;
  readonly forwarderChain: readonly string[];
  readonly provenanceRefs: readonly string[];
  readonly hopIndex: number;
  readonly hopBudgetRemaining: number;
  readonly forwardCount: number;
  readonly observedAtEpochMs: number;
}

// ── decisions ────────────────────────────────────────────────────────────────

/**
 * Outcome of forwarding one hop. Every SUCCESS carries the
 * zero-authority structural literals: `authority: "none"`,
 * `endorsement: "none"` (FORWARD != ENDORSE), `originFixed: true` (M4),
 * `capabilityWidened: false`, `admissionBypassed: false`,
 * `executionAuthorized: false`.
 */
export type ForwardDecision =
  | {
      readonly ok: true;
      readonly code: "proposal_forwarded";
      readonly proposalId: string;
      readonly proposalHash: string;
      readonly originNodeId: string;
      readonly destinationNodeId: string;
      readonly forwarderChain: readonly string[];
      readonly provenanceRefs: readonly string[];
      readonly hopIndex: number;
      readonly hopBudgetRemaining: number;
      readonly forwardCount: number;
      readonly authority: "none";
      readonly endorsement: "none";
      readonly originFixed: true;
      readonly capabilityWidened: false;
      readonly admissionBypassed: false;
      readonly executionAuthorized: false;
      readonly explanation: string;
      readonly forwardHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "forward_refused";
      readonly proposalId: string;
      readonly refusal: ForwardRefusalCode;
      readonly explanation: string;
      readonly forwardHash: string;
    };

// ── refusal explanations (every refusal is explained; no silent handling) ────

const REFUSAL_EXPLANATIONS: Readonly<Record<ForwardRefusalCode, string>> =
  Object.freeze({
    refused_invalid_forward:
      "malformed forward — refusing (fail closed); a proposal must carry its 24E identity (fp- id, sha256- hash), distinct origin/destination/forwarder, a non-negative hop index, a safe integer budget, an array of non-empty provenance refs, and a finite caller-supplied time",
    refused_field_bound:
      "field over frozen bound — refusing (fail closed); a caller may exceed a bound, never redefine one; node ids, provenance refs, and their count are hard-capped; never truncate, never evict",
    refused_secret_material:
      "secret material in forward payload — refusing (fail closed); proposals are DATA and secret material never rides the sanctioned transport, including nested inside JSON strings",
    refused_executable_material:
      "executable material in forward payload — refusing (fail closed); a proposal is never a command",
    refused_forbidden_material:
      "forbidden material in forward payload — refusing (fail closed); local paths, handles, raw output, and policy text are not proposal content",
    refused_origin_substitution:
      "origin substitution — refusing (fail closed); a forwarder can never be or replace the origin (27A M4 FORWARDER != ORIGIN), so origin attribution is fixed at creation and is not moved by any hop",
    refused_identity_mutation:
      "proposal identity mutation — refusing (fail closed); the proposalId ↔ proposalHash binding is fixed at first forward and a later hop may never rewrite it (first evidenced binding stands)",
    refused_destination_mutation:
      "destination mutation — refusing (fail closed); the destination is preserved across every hop and can never be redirected in flight",
    refused_provenance_stripped:
      "provenance stripped — refusing (fail closed); presented provenanceRefs must CONTAIN every ref recorded on earlier hops — history is append-only, additions allowed, removals never",
    refused_replay:
      "replay detected — refusing (fail closed); this proposal's hop was already completed or this forwarder already forwarded it — the replay context stays intact and the registry is unchanged",
    refused_hop_out_of_sequence:
      "hop out of sequence — refusing (fail closed); hops advance by exactly one from the recorded position (a new proposal starts at 0), so no unseen hop can skip into the chain",
    refused_hop_limit:
      "hop budget refused — refusing (fail closed); the budget starts within the frozen bound, descends by EXACTLY one per forward, and never re-inflates — exhausted or over-bound budgets never forward",
    refused_registry_bound:
      "registry bound reached — refusing (fail closed); never evict, never grow past the frozen per-registry proposal bound",
    refused_unknown:
      "unmapped forwarding condition — refusing (fail closed)",
  });

// ── shared guards ────────────────────────────────────────────────────────────

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// ── the bounded forwarding registry ──────────────────────────────────────────

/**
 * The LOCAL forwarding registry: ONE bounded in-memory state object
 * tracking governed multi-hop forwards. Every mutation goes through
 * `forward`, which validates in a pinned order (first match wins) and
 * leaves the registry EXACTLY as it was on any refusal. Forwarding
 * stores append-only knowledge — origin, chain, identity, provenance,
 * budget, replay context — and grants nothing (FORWARD != ENDORSE).
 */
export class ProposalForwardingRegistry {
  readonly #records = new Map<string, ForwardingRecord>();
  readonly #hashIndex = new Map<string, string>();

  private constructor() {}

  /**
   * Open an empty registry. Opening cannot fail: bounds and
   * vocabularies are frozen constants, so there is no configuration to
   * reject.
   */
  static open(): ProposalForwardingRegistry {
    return new ProposalForwardingRegistry();
  }

  get proposalCount(): number {
    return this.#records.size;
  }

  has(proposalId: string): boolean {
    return this.#records.has(proposalId);
  }

  get(proposalId: string): ForwardingRecord | null {
    return this.#records.get(proposalId) ?? null;
  }

  /**
   * Forward ONE hop of ONE proposal through ONE forwarder. Pinned
   * validation order (first match wins):
   *   1. shape (24E id + hash patterns, distinct origin/destination/
   *      forwarder, non-negative hop index, safe integer budget,
   *      non-empty string refs, finite caller-supplied time)
   *   2. field bounds (node id / ref char caps, ref count cap)
   *   3. material scan over every string surface (25D egress
   *      classifier — secret / executable / forbidden material refuse)
   *   4. forwarder == origin => origin substitution (27A M4 composed)
   *   5. proposalHash already bound to ANOTHER proposalId => identity
   *      mutation
   *   6. registry capacity (new proposals only)
   *   7. recorded proposal: origin → hash → destination immutability,
   *      provenance append-only (stripping refuses), replay (chain
   *      membership or completed hop), exact hop sequence, budget
   *      descends by exactly one within the frozen bound
   *   8. new proposal: hop index must be 0; budget within [1, maxHops]
   *   9. record updated (append-only, frozen) + success literals
   * Any refusal leaves the registry untouched (count + fingerprint
   * invariance suite-pinned).
   */
  forward(input: ForwardInput): ForwardDecision {
    const forwardHash = canonicalHash({
      schemaVersion: FORWARDING_SCHEMA_VERSION,
      proposalId: input.proposalId,
      proposalHash: input.proposalHash,
      originNodeId: input.originNodeId,
      destinationNodeId: input.destinationNodeId,
      forwarderNodeId: input.forwarderNodeId,
      hopIndex: input.hopIndex,
      hopBudgetRemaining: input.hopBudgetRemaining,
      provenanceRefs: input.provenanceRefs,
      observedAtEpochMs: input.observedAtEpochMs,
    });
    const refuse = (
      refusal: ForwardRefusalCode,
      explanation?: string,
    ): ForwardDecision => {
      let text = explanation ?? REFUSAL_EXPLANATIONS[refusal];
      if (refusal === "refused_origin_substitution") {
        // Compose the frozen 27A claim decision so the FORWARDER_NOT_ORIGIN
        // pin names the law at the moment substitution is detected.
        const claim = decideMeshClaim({
          claimKind: "forwarder_origin_claim",
          subject:
            typeof input.proposalId === "string" && input.proposalId.length > 0
              ? input.proposalId
              : "unknown-proposal",
          observedAtEpochMs:
            typeof input.observedAtEpochMs === "number" &&
            Number.isFinite(input.observedAtEpochMs) &&
            input.observedAtEpochMs >= 0
              ? input.observedAtEpochMs
              : 0,
        });
        text = text + " " + claim.explanation;
      }
      return {
        ok: false,
        code: "forward_refused",
        proposalId:
          typeof input.proposalId === "string" ? input.proposalId : "",
        refusal,
        explanation: text,
        forwardHash,
      };
    };
    const succeed = (record: ForwardingRecord): ForwardDecision => ({
      ok: true,
      code: "proposal_forwarded",
      proposalId: record.proposalId,
      proposalHash: record.proposalHash,
      originNodeId: record.originNodeId,
      destinationNodeId: record.destinationNodeId,
      forwarderChain: record.forwarderChain,
      provenanceRefs: record.provenanceRefs,
      hopIndex: record.hopIndex,
      hopBudgetRemaining: record.hopBudgetRemaining,
      forwardCount: record.forwardCount,
      authority: "none",
      endorsement: "none",
      originFixed: true,
      capabilityWidened: false,
      admissionBypassed: false,
      executionAuthorized: false,
      explanation:
        "proposal '" +
        record.proposalId +
        "' forwarded at hop " +
        record.hopIndex +
        " by '" +
        input.forwarderNodeId +
        "' (forwarder #" +
        record.forwardCount +
        " of at most " +
        FORWARDING_BOUNDS.maxHops +
        ") — FORWARD != ENDORSE: relaying inert DATA endorses nothing; endorsement stays 'none', authority stays 'none', origin stays fixed (M4), no capability widened, no admission surface, executionAuthorized stays false — destination execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21. " +
        MESH_TRUST_PIN_EXPLANATIONS.FORWARDER_NOT_ORIGIN,
      forwardHash,
    });

    // 1. shape
    if (
      !FEDERATION_PROPOSAL_ID_PATTERN.test(input.proposalId) ||
      !PROPOSAL_HASH_REF_PATTERN.test(input.proposalHash) ||
      !isNonEmptyString(input.originNodeId) ||
      !isNonEmptyString(input.destinationNodeId) ||
      !isNonEmptyString(input.forwarderNodeId) ||
      input.originNodeId === input.destinationNodeId ||
      input.forwarderNodeId === input.destinationNodeId ||
      typeof input.hopIndex !== "number" ||
      !Number.isSafeInteger(input.hopIndex) ||
      input.hopIndex < 0 ||
      typeof input.hopBudgetRemaining !== "number" ||
      !Number.isSafeInteger(input.hopBudgetRemaining) ||
      !Array.isArray(input.provenanceRefs) ||
      !input.provenanceRefs.every((ref) => isNonEmptyString(ref)) ||
      typeof input.observedAtEpochMs !== "number" ||
      !Number.isFinite(input.observedAtEpochMs) ||
      input.observedAtEpochMs < 0
    ) {
      return refuse("refused_invalid_forward");
    }
    // 2. field bounds
    if (
      input.originNodeId.length > FORWARDING_BOUNDS.maxNodeIdChars ||
      input.destinationNodeId.length > FORWARDING_BOUNDS.maxNodeIdChars ||
      input.forwarderNodeId.length > FORWARDING_BOUNDS.maxNodeIdChars ||
      input.provenanceRefs.length > FORWARDING_BOUNDS.maxProvenanceRefs ||
      input.provenanceRefs.some(
        (ref) => ref.length > FORWARDING_BOUNDS.maxProvenanceRefChars,
      )
    ) {
      return refuse("refused_field_bound");
    }
    // 3. material scan (25D egress classifier over every string surface)
    const findings = findEgressFindings({
      proposalId: input.proposalId,
      proposalHash: input.proposalHash,
      originNodeId: input.originNodeId,
      destinationNodeId: input.destinationNodeId,
      forwarderNodeId: input.forwarderNodeId,
      provenanceRefs: input.provenanceRefs,
    });
    const firstFinding = findings[0];
    if (firstFinding !== undefined) {
      if (firstFinding.egressClass === "secret_material") {
        return refuse(
          "refused_secret_material",
          "secret material in forward payload (" +
            firstFinding.field +
            ": " +
            firstFinding.reason +
            ") — refusing (fail closed); proposals are DATA and secret material never rides the sanctioned transport",
        );
      }
      if (firstFinding.egressClass === "executable_material") {
        return refuse(
          "refused_executable_material",
          "executable material in forward payload (" +
            firstFinding.field +
            ": " +
            firstFinding.reason +
            ") — refusing (fail closed); a proposal is never a command",
        );
      }
      return refuse(
        "refused_forbidden_material",
        "forbidden material in forward payload (" +
          firstFinding.field +
          ": " +
          firstFinding.reason +
          ") — refusing (fail closed)",
      );
    }
    // 4. forwarder can never be the origin (27A M4 composed on refusal)
    if (input.forwarderNodeId === input.originNodeId) {
      return refuse("refused_origin_substitution");
    }
    // 5. a hash is bound to ONE proposal id (first binding stands)
    const hashOwner = this.#hashIndex.get(input.proposalHash);
    if (hashOwner !== undefined && hashOwner !== input.proposalId) {
      return refuse("refused_identity_mutation");
    }
    const existing = this.#records.get(input.proposalId);
    // 6. registry capacity (new proposals only; recorded ones advance)
    if (
      existing === undefined &&
      this.#records.size >= FORWARDING_BOUNDS.maxTrackedProposals
    ) {
      return refuse("refused_registry_bound");
    }
    // 7. recorded proposal: append-only governed continuation
    if (existing !== undefined) {
      if (existing.originNodeId !== input.originNodeId) {
        return refuse("refused_origin_substitution");
      }
      if (existing.proposalHash !== input.proposalHash) {
        return refuse("refused_identity_mutation");
      }
      if (existing.destinationNodeId !== input.destinationNodeId) {
        return refuse("refused_destination_mutation");
      }
      const presented = new Set(input.provenanceRefs);
      for (const recordedRef of existing.provenanceRefs) {
        if (!presented.has(recordedRef)) {
          return refuse("refused_provenance_stripped");
        }
      }
      if (existing.forwarderChain.includes(input.forwarderNodeId)) {
        return refuse("refused_replay");
      }
      if (input.hopIndex < existing.forwardCount) {
        return refuse("refused_replay");
      }
      if (input.hopIndex !== existing.forwardCount) {
        return refuse("refused_hop_out_of_sequence");
      }
      if (
        existing.forwardCount >= FORWARDING_BOUNDS.maxHops ||
        existing.hopBudgetRemaining < 1 ||
        input.hopBudgetRemaining !== existing.hopBudgetRemaining
      ) {
        // Continuity: the presented budget must be exactly what the last
        // hop left (each hop stores presented - 1, so the stored AND the
        // presented sequence both descend by exactly one — no re-inflation,
        // no skip, no exhaustion bypass).
        return refuse("refused_hop_limit");
      }
      const accumulated: string[] = [...existing.provenanceRefs];
      const accumulatedSet = new Set(accumulated);
      for (const ref of input.provenanceRefs) {
        if (!accumulatedSet.has(ref)) {
          accumulatedSet.add(ref);
          accumulated.push(ref);
        }
      }
      const record: ForwardingRecord = Object.freeze({
        proposalId: existing.proposalId,
        proposalHash: existing.proposalHash,
        originNodeId: existing.originNodeId,
        destinationNodeId: existing.destinationNodeId,
        forwarderChain: Object.freeze([
          ...existing.forwarderChain,
          input.forwarderNodeId,
        ]),
        provenanceRefs: Object.freeze(accumulated),
        hopIndex: input.hopIndex,
        hopBudgetRemaining: input.hopBudgetRemaining - 1,
        forwardCount: existing.forwardCount + 1,
        observedAtEpochMs: existing.observedAtEpochMs,
      });
      this.#records.set(record.proposalId, record);
      return succeed(record);
    }
    // 8. new proposal: starts at hop 0 within the frozen budget
    if (input.hopIndex !== 0) {
      return refuse("refused_hop_out_of_sequence");
    }
    if (
      input.hopBudgetRemaining < 1 ||
      input.hopBudgetRemaining > FORWARDING_BOUNDS.maxHops
    ) {
      return refuse("refused_hop_limit");
    }
    const freshRefs: string[] = [];
    const freshRefSet = new Set<string>();
    for (const ref of input.provenanceRefs) {
      if (!freshRefSet.has(ref)) {
        freshRefSet.add(ref);
        freshRefs.push(ref);
      }
    }
    const record: ForwardingRecord = Object.freeze({
      proposalId: input.proposalId,
      proposalHash: input.proposalHash,
      originNodeId: input.originNodeId,
      destinationNodeId: input.destinationNodeId,
      forwarderChain: Object.freeze([input.forwarderNodeId]),
      provenanceRefs: Object.freeze(freshRefs),
      hopIndex: input.hopIndex,
      hopBudgetRemaining: input.hopBudgetRemaining - 1,
      forwardCount: 1,
      observedAtEpochMs: input.observedAtEpochMs,
    });
    this.#records.set(record.proposalId, record);
    this.#hashIndex.set(record.proposalHash, record.proposalId);
    return succeed(record);
  }

  /**
   * Frozen, canonically ordered snapshot (by proposalId) — read-only
   * knowledge. Independent of insertion order: two registries holding
   * the same records snapshot identically and fingerprint identically.
   */
  snapshot(): readonly ForwardingRecord[] {
    const records = [...this.#records.values()]
      .sort((a, b) =>
        a.proposalId < b.proposalId
          ? -1
          : a.proposalId > b.proposalId
            ? 1
            : 0,
      )
      .map((record) =>
        Object.freeze({
          ...record,
          forwarderChain: Object.freeze([...record.forwarderChain]),
          provenanceRefs: Object.freeze([...record.provenanceRefs]),
        }),
      );
    return Object.freeze(records);
  }

  /**
   * Deterministic canonical fingerprint of the registry's knowledge
   * (order-insensitive): identical records in any order, same
   * fingerprint. Pure; no I/O; no clock.
   */
  fingerprint(): string {
    const recordHashes = [...this.#records.values()]
      .map((record) => canonicalHash(record))
      .sort();
    return canonicalHash({
      schemaVersion: FORWARDING_SCHEMA_VERSION,
      proposalCount: this.#records.size,
      recordHashes,
    });
  }
}
