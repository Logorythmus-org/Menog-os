/**
 * PHASE 27B — Explicit Topology Graph (DETERMINISTIC / BOUNDED / LOCAL /
 * CONFIG-AND-EVIDENCE ONLY / NO DISCOVERY / NO POLICY / NO TOOL / NO
 * AUTHORITY).
 *
 * This module implements the explicit local topology graph: ONE bounded,
 * deterministic, in-memory state object over the frozen 27A mesh trust
 * contract. Every node and edge record carries provenance (which of the
 * two sanctioned sources produced it) and the epoch it was recorded in.
 * Records arrive ONLY from explicit local configuration or governed
 * evidence — the provenance vocabulary is closed and anything else refuses
 * (fail closed). There is no discovery, no scanning, no gossip, no
 * membership channel: an unnamed source cannot contribute knowledge.
 *
 * THE LAWS IT ENFORCES
 *   · TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY — graph records carry NO trust,
 *     admission, membership, authority, execution, or Policy field of any
 *     kind. Topology state and peer-trust state stay structurally separate:
 *     the graph cannot be read as, written to, or merged with the frozen
 *     24C peer registry (27C owns lifecycle; this gate owns the record).
 *   · BOUNDED — node and edge counts are capped by frozen CONSTANTS. A
 *     caller may send MORE; it can never redefine a bound. Refuse, never
 *     evict, never grow, never drop-and-continue.
 *   · DUPLICATES IDEMPOTENT — re-recording the identical record is a no-op
 *     (same id, same content => ok, counts unchanged); the same id with
 *     DIFFERENT content refuses (conflict) and never overwrites.
 *   · STALE / INVALID FAIL CLOSED — a record whose epoch does not match the
 *     graph's epoch, a malformed record, an unknown kind, a dangling edge,
 *     or an unknown provenance source all refuse with a closed code and
 *     leave the graph EXACTLY as it was.
 *   · DETERMINISTIC — identical input sequences yield identical graphs and
 *     identical fingerprints; snapshots are canonically sorted; the module
 *     never reads a wall clock (caller-supplied recordedAtEpochMs only).
 *   · NO POLICY, NO TOOL, NO AUTHORITY FIELD EVER BECOMES TRUE — this
 *     module has no such field, no such vocabulary, and no path to either.
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/consensus/
 * global authority. No socket, no listener, no spawn, no store access
 * (in-memory bounded state only — persistence, if ever sanctioned, is a
 * later gate's explicit problem, never an alternate path from here).
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import {
  decideMeshEdge,
  decideMeshNode,
  type MeshEdgeKind,
  type MeshNodeKind,
} from "./meshTopologyTrust.js";

/** Topology graph contract schema version (27B). */
export const TOPOLOGY_GRAPH_SCHEMA_VERSION = "menog-mesh-topology-graph/v0" as const;
export type TopologyGraphSchemaVersion = typeof TOPOLOGY_GRAPH_SCHEMA_VERSION;

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/** Hard caps on the graph. Refusal, never eviction, past a bound. */
export const TOPOLOGY_GRAPH_BOUNDS = Object.freeze({
  maxNodes: 64,
  maxEdges: 256,
});
export type TopologyGraphBoundName = keyof typeof TOPOLOGY_GRAPH_BOUNDS;

// ── provenance vocabulary (closed — the ONLY sanctioned sources) ─────────────

/**
 * The closed provenance sources. Topology knowledge enters the graph from
 * explicit local configuration or from governed evidence — nothing else.
 * `unknown_source` exists so an unnamed source can be REFUSED (fail closed),
 * never recorded.
 */
export const TOPOLOGY_PROVENANCE_SOURCES = Object.freeze([
  "local_configuration",
  "governed_evidence",
  "unknown_source",
] as const);
export type TopologyProvenanceSource =
  (typeof TOPOLOGY_PROVENANCE_SOURCES)[number];

/**
 * Provenance attached to every node and edge record: which sanctioned
 * source produced the record, the evidence it cites (governed evidence
 * MUST cite one; local configuration MUST NOT pretend to), and the
 * caller-supplied time it was recorded.
 */
export interface TopologyProvenance {
  readonly source: TopologyProvenanceSource;
  readonly evidenceId: string | null;
  readonly recordedAtEpochMs: number;
}

// ── record vocabulary (closed) ───────────────────────────────────────────────

/** A node record as stored: knowledge + provenance + epoch, nothing else. */
export interface TopologyNodeRecord {
  readonly nodeId: string;
  readonly kind: MeshNodeKind;
  readonly epochId: string;
  readonly provenance: TopologyProvenance;
}

/** An edge record as stored: directed knowledge + provenance + epoch. */
export interface TopologyEdgeRecord {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly kind: MeshEdgeKind;
  readonly epochId: string;
  readonly provenance: TopologyProvenance;
}

/** Caller-supplied node record (input). */
export interface TopologyNodeInput {
  readonly nodeId: string;
  readonly kind: MeshNodeKind;
  readonly epochId: string;
  readonly provenance: TopologyProvenance;
}

/** Caller-supplied edge record (input). */
export interface TopologyEdgeInput {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly kind: MeshEdgeKind;
  readonly epochId: string;
  readonly provenance: TopologyProvenance;
}

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed topology-graph refusal codes (fail-closed; no silent handling). */
export const TOPOLOGY_GRAPH_REFUSAL_CODES = Object.freeze([
  "refused_invalid_epoch",
  "refused_unknown_provenance_source",
  "refused_invalid_provenance",
  "refused_invalid_record",
  "refused_stale_epoch",
  "refused_unknown_node_kind",
  "refused_unknown_edge_kind",
  "refused_conflicting_record",
  "refused_dangling_edge",
  "refused_graph_bound",
  "refused_unknown",
] as const);
export type TopologyGraphRefusalCode =
  (typeof TOPOLOGY_GRAPH_REFUSAL_CODES)[number];

// ── decisions ────────────────────────────────────────────────────────────────

/** Outcome of opening a graph. */
export type TopologyOpenDecision =
  | {
      readonly ok: true;
      readonly code: "topology_graph_opened";
      readonly graph: LocalTopologyGraph;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "topology_graph_refused";
      readonly refusal: TopologyGraphRefusalCode;
      readonly explanation: string;
    };

/**
 * Outcome of recording one node or edge. Every decision reports the
 * post-decision counts so bounds are observable (read-only knowledge).
 */
export type TopologyRecordDecision =
  | {
      readonly ok: true;
      readonly code: "record_added" | "duplicate_idempotent";
      readonly nodeCount: number;
      readonly edgeCount: number;
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "record_refused";
      readonly refusal: TopologyGraphRefusalCode;
      readonly nodeCount: number;
      readonly edgeCount: number;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/** A frozen, canonically ordered view of the graph (read-only). */
export interface TopologyGraphSnapshot {
  readonly epochId: string;
  readonly nodes: readonly TopologyNodeRecord[];
  readonly edges: readonly TopologyEdgeRecord[];
}

// ── the bounded graph ────────────────────────────────────────────────────────

/**
 * The explicit local topology graph: ONE bounded in-memory state object.
 * All mutation goes through `addNode` / `addEdge`, which validate in a
 * pinned order (first match wins) and leave the graph untouched on any
 * refusal. Pure knowledge: no trust, no admission, no authority fields.
 */
export class LocalTopologyGraph {
  readonly #epochId: string;
  readonly #nodes = new Map<string, TopologyNodeRecord>();
  readonly #edges = new Map<string, TopologyEdgeRecord>();
  readonly #nodeHashes = new Map<string, string>();
  readonly #edgeHashes = new Map<string, string>();

  private constructor(epochId: string) {
    this.#epochId = epochId;
  }

  /**
   * Open a graph for ONE epoch. The epoch id is the graph's identity:
   * records from any other epoch refuse (stale records fail closed).
   */
  static open(input: { readonly epochId: string }): TopologyOpenDecision {
    if (typeof input.epochId !== "string" || input.epochId.length === 0) {
      return {
        ok: false,
        code: "topology_graph_refused",
        refusal: "refused_invalid_epoch",
        explanation:
          "a topology graph requires a non-empty epoch id — refusing (fail closed); an un-epoch'd graph would make staleness unrepresentable",
      };
    }
    return {
      ok: true,
      code: "topology_graph_opened",
      graph: new LocalTopologyGraph(input.epochId),
      explanation:
        "topology graph opened for epoch '" +
        input.epochId +
        "' — bounded, deterministic, LOCAL; TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY (no trust, admission, membership, authority, execution, or Policy field exists on any record)",
    };
  }

  get epochId(): string {
    return this.#epochId;
  }

  get nodeCount(): number {
    return this.#nodes.size;
  }

  get edgeCount(): number {
    return this.#edges.size;
  }

  hasNode(nodeId: string): boolean {
    return this.#nodes.has(nodeId);
  }

  hasEdge(edgeId: string): boolean {
    return this.#edges.has(edgeId);
  }

  /**
   * Record one node. Pinned validation order (first match wins):
   *   1. provenance source in the closed vocabulary
   *   2. provenance shape (governed evidence cites evidenceId; local
   *      configuration does not; recordedAtEpochMs is a finite number)
   *   3. record shape (non-empty ids)
   *   4. epoch matches this graph (stale refuses)
   *   5. node kind valid under the frozen 27A contract (unknown refuses)
   *   6. existing id: identical => idempotent no-op; different => conflict
   *      refuses (never overwrites)
   *   7. bound: a NEW node at maxNodes refuses (never evicts)
   *   8. record added
   * Any refusal leaves the graph EXACTLY as it was.
   */
  addNode(input: TopologyNodeInput): TopologyRecordDecision {
    const provenanceHash = canonicalHash({
      schemaVersion: TOPOLOGY_GRAPH_SCHEMA_VERSION,
      recordKind: "node",
      nodeId: input.nodeId,
      kind: input.kind,
      epochId: input.epochId,
      provenance: input.provenance,
    });
    const counts = (): { nodeCount: number; edgeCount: number } => ({
      nodeCount: this.#nodes.size,
      edgeCount: this.#edges.size,
    });
    const provenanceCheck = validateProvenance(input.provenance);
    if (provenanceCheck !== null) {
      return this.#refuse(provenanceCheck, provenanceHash, counts());
    }
    if (typeof input.nodeId !== "string" || input.nodeId.length === 0) {
      return this.#refuse(
        "refused_invalid_record",
        provenanceHash,
        counts(),
        "node record carries an empty nodeId — refusing (fail closed); an unkeyed record cannot be deduplicated or bounded",
      );
    }
    if (input.epochId !== this.#epochId) {
      return this.#refuse(
        "refused_stale_epoch",
        provenanceHash,
        counts(),
        "node record carries epoch '" +
          input.epochId +
          "' but the graph is epoch '" +
          this.#epochId +
          "' — a stale-epoch record refuses and changes nothing (stale/invalid records fail closed)",
      );
    }
    const kindDecision = decideMeshNode({
      node: {
        nodeId: input.nodeId,
        kind: input.kind,
        observedAtEpochMs: input.provenance.recordedAtEpochMs,
      },
      observedAtEpochMs: input.provenance.recordedAtEpochMs,
    });
    if (!kindDecision.ok) {
      // any kind-decision failure IS a node-kind failure at this layer
      // (unknown_node sentinel or an out-of-vocabulary cast value)
      return this.#refuse("refused_unknown_node_kind", provenanceHash, counts());
    }
    if (this.#nodes.has(input.nodeId)) {
      const existingHash = this.#nodeHashes.get(input.nodeId);
      if (existingHash === provenanceHash) {
        return {
          ok: true,
          code: "duplicate_idempotent",
          ...counts(),
          explanation:
            "node '" +
            input.nodeId +
            "' is already recorded with identical content — duplicate is idempotent (no-op, counts unchanged); knowledge is never duplicated, widened, or re-sourced",
          provenanceHash,
        };
      }
      return this.#refuse(
        "refused_conflicting_record",
        provenanceHash,
        counts(),
        "node '" +
          input.nodeId +
          "' is already recorded with DIFFERENT content — a conflicting record refuses and never overwrites (fail closed; first evidenced knowledge stands)",
      );
    }
    if (this.#nodes.size >= TOPOLOGY_GRAPH_BOUNDS.maxNodes) {
      return this.#refuse(
        "refused_graph_bound",
        provenanceHash,
        counts(),
        "node bound " +
          TOPOLOGY_GRAPH_BOUNDS.maxNodes +
          " reached — a new node refuses (never evict, never grow past the frozen bound; a caller may exceed a bound, never redefine one)",
      );
    }
    const record: TopologyNodeRecord = Object.freeze({
      nodeId: input.nodeId,
      kind: input.kind,
      epochId: input.epochId,
      provenance: Object.freeze({ ...input.provenance }),
    });
    this.#nodes.set(input.nodeId, record);
    this.#nodeHashes.set(input.nodeId, provenanceHash);
    return {
      ok: true,
      code: "record_added",
      ...counts(),
      explanation:
        "node '" +
        input.nodeId +
        "' recorded from " +
        input.provenance.source +
        " in epoch '" +
        input.epochId +
        "' — pure topology knowledge with provenance; no trust, no membership, no authority attaches (M6)",
      provenanceHash,
    };
  }

  /**
   * Record one edge. Pinned validation order (first match wins):
   *   1. provenance source   2. provenance shape   3. record shape
   *   4. epoch               5. edge kind (27A contract)
   *   6. existing id: identical => idempotent; different => conflict refuses
   *   7. BOTH endpoints must already be recorded nodes (dangling refuses —
   *      an edge can never conjure a node into the graph)
   *   8. bound: a NEW edge at maxEdges refuses (never evicts)
   *   9. record added
   * Any refusal leaves the graph EXACTLY as it was.
   */
  addEdge(input: TopologyEdgeInput): TopologyRecordDecision {
    const provenanceHash = canonicalHash({
      schemaVersion: TOPOLOGY_GRAPH_SCHEMA_VERSION,
      recordKind: "edge",
      edgeId: input.edgeId,
      fromNodeId: input.fromNodeId,
      toNodeId: input.toNodeId,
      kind: input.kind,
      epochId: input.epochId,
      provenance: input.provenance,
    });
    const counts = (): { nodeCount: number; edgeCount: number } => ({
      nodeCount: this.#nodes.size,
      edgeCount: this.#edges.size,
    });
    const provenanceCheck = validateProvenance(input.provenance);
    if (provenanceCheck !== null) {
      return this.#refuse(provenanceCheck, provenanceHash, counts());
    }
    if (
      typeof input.edgeId !== "string" ||
      input.edgeId.length === 0 ||
      typeof input.fromNodeId !== "string" ||
      input.fromNodeId.length === 0 ||
      typeof input.toNodeId !== "string" ||
      input.toNodeId.length === 0
    ) {
      return this.#refuse(
        "refused_invalid_record",
        provenanceHash,
        counts(),
        "edge record carries an empty edgeId/fromNodeId/toNodeId — refusing (fail closed); an unkeyed record cannot be deduplicated or validated",
      );
    }
    if (input.epochId !== this.#epochId) {
      return this.#refuse(
        "refused_stale_epoch",
        provenanceHash,
        counts(),
        "edge record carries epoch '" +
          input.epochId +
          "' but the graph is epoch '" +
          this.#epochId +
          "' — a stale-epoch record refuses and changes nothing (stale/invalid records fail closed)",
      );
    }
    const kindDecision = decideMeshEdge({
      edge: {
        edgeId: input.edgeId,
        fromNodeId: input.fromNodeId,
        toNodeId: input.toNodeId,
        kind: input.kind,
        observedAtEpochMs: input.provenance.recordedAtEpochMs,
      },
      observedAtEpochMs: input.provenance.recordedAtEpochMs,
    });
    if (!kindDecision.ok) {
      // any kind-decision failure IS an edge-kind failure at this layer
      // (unknown_edge sentinel or an out-of-vocabulary cast value)
      return this.#refuse("refused_unknown_edge_kind", provenanceHash, counts());
    }
    if (this.#edges.has(input.edgeId)) {
      const existingHash = this.#edgeHashes.get(input.edgeId);
      if (existingHash === provenanceHash) {
        return {
          ok: true,
          code: "duplicate_idempotent",
          ...counts(),
          explanation:
            "edge '" +
            input.edgeId +
            "' is already recorded with identical content — duplicate is idempotent (no-op, counts unchanged); knowledge is never duplicated, widened, or re-sourced",
          provenanceHash,
        };
      }
      return this.#refuse(
        "refused_conflicting_record",
        provenanceHash,
        counts(),
        "edge '" +
          input.edgeId +
          "' is already recorded with DIFFERENT content — a conflicting record refuses and never overwrites (fail closed; first evidenced knowledge stands)",
      );
    }
    if (!this.#nodes.has(input.fromNodeId) || !this.#nodes.has(input.toNodeId)) {
      return this.#refuse(
        "refused_dangling_edge",
        provenanceHash,
        counts(),
        "edge '" +
          input.edgeId +
          "' references endpoint node(s) not recorded in the graph — a dangling edge refuses (fail closed); an edge can never conjure a node into existence, and topology knowledge is built only from recorded facts",
      );
    }
    if (this.#edges.size >= TOPOLOGY_GRAPH_BOUNDS.maxEdges) {
      return this.#refuse(
        "refused_graph_bound",
        provenanceHash,
        counts(),
        "edge bound " +
          TOPOLOGY_GRAPH_BOUNDS.maxEdges +
          " reached — a new edge refuses (never evict, never grow past the frozen bound; a caller may exceed a bound, never redefine one)",
      );
    }
    const record: TopologyEdgeRecord = Object.freeze({
      edgeId: input.edgeId,
      fromNodeId: input.fromNodeId,
      toNodeId: input.toNodeId,
      kind: input.kind,
      epochId: input.epochId,
      provenance: Object.freeze({ ...input.provenance }),
    });
    this.#edges.set(input.edgeId, record);
    this.#edgeHashes.set(input.edgeId, provenanceHash);
    return {
      ok: true,
      code: "record_added",
      ...counts(),
      explanation:
        "edge '" +
        input.edgeId +
        "' recorded from " +
        input.provenance.source +
        " in epoch '" +
        input.epochId +
        "' — directed topology knowledge with provenance; trust stays structurally absent (M1)",
      provenanceHash,
    };
  }

  /**
   * Frozen, canonically sorted snapshot (nodes by id, edges by id) —
   * read-only knowledge. Independent of insertion order: two graphs with
   * the same records snapshot identically.
   */
  snapshot(): TopologyGraphSnapshot {
    const nodes = [...this.#nodes.values()]
      .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0))
      .map((r) => Object.freeze({ ...r, provenance: Object.freeze({ ...r.provenance }) }));
    const edges = [...this.#edges.values()]
      .sort((a, b) => (a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0))
      .map((r) => Object.freeze({ ...r, provenance: Object.freeze({ ...r.provenance }) }));
    return Object.freeze({
      epochId: this.#epochId,
      nodes: Object.freeze(nodes),
      edges: Object.freeze(edges),
    });
  }

  /**
   * Deterministic canonical fingerprint of the graph's knowledge
   * (order-insensitive): identical records in any order, same epoch,
   * same fingerprint. Pure; no I/O; no clock.
   */
  fingerprint(): string {
    const nodeHashes = [...this.#nodeHashes.values()].sort();
    const edgeHashes = [...this.#edgeHashes.values()].sort();
    return canonicalHash({
      schemaVersion: TOPOLOGY_GRAPH_SCHEMA_VERSION,
      epochId: this.#epochId,
      nodeHashes,
      edgeHashes,
    });
  }

  #refuse(
    refusal: TopologyGraphRefusalCode,
    provenanceHash: string,
    counts: { nodeCount: number; edgeCount: number },
    explanation?: string,
  ): TopologyRecordDecision {
    const EXPLANATIONS: Readonly<Record<TopologyGraphRefusalCode, string>> = {
      refused_invalid_epoch:
        "invalid epoch — refusing (fail closed); staleness must be representable",
      refused_unknown_provenance_source:
        "unknown provenance source — refusing (fail closed); topology knowledge enters ONLY from explicit local configuration or governed evidence, so an unnamed source is never recorded (no discovery, no gossip, no unnamed channel)",
      refused_invalid_provenance:
        "invalid provenance — refusing (fail closed); governed evidence must cite its evidence id and local configuration must not pretend to",
      refused_invalid_record:
        "invalid record — refusing (fail closed); a malformed record cannot be deduplicated, bounded, or audited",
      refused_stale_epoch:
        "stale-epoch record — refusing (fail closed); the record changes nothing",
      refused_unknown_node_kind:
        "unknown node kind — refusing (fail closed) under the frozen 27A contract",
      refused_unknown_edge_kind:
        "unknown edge kind — refusing (fail closed) under the frozen 27A contract",
      refused_conflicting_record:
        "conflicting record — refusing (fail closed); first evidenced knowledge stands and is never overwritten",
      refused_dangling_edge:
        "dangling edge — refusing (fail closed); both endpoints must already be recorded nodes",
      refused_graph_bound:
        "graph bound reached — refusing (fail closed); never evict, never grow, never redefine a frozen bound",
      refused_unknown:
        "unmapped topology-graph condition — refusing (fail closed)",
    };
    return {
      ok: false,
      code: "record_refused",
      refusal,
      ...counts,
      explanation: explanation ?? EXPLANATIONS[refusal],
      provenanceHash,
    };
  }
}

// ── provenance validation (shared, pinned order step 1–2) ────────────────────

/**
 * Validate provenance BEFORE anything else: the source must be in the
 * closed vocabulary, governed evidence must cite an evidence id, local
 * configuration must not, and the recorded time must be a finite number.
 * Returns the refusal code, or null when valid.
 */
function validateProvenance(
  provenance: TopologyProvenance,
): TopologyGraphRefusalCode | null {
  if (
    typeof provenance !== "object" ||
    provenance === null ||
    !(
      (TOPOLOGY_PROVENANCE_SOURCES as readonly string[]).includes(
        (provenance as { source?: unknown }).source as string,
      )
    ) ||
    (provenance as { source?: unknown }).source === "unknown_source"
  ) {
    return "refused_unknown_provenance_source";
  }
  if (provenance.source === "governed_evidence") {
    if (
      typeof provenance.evidenceId !== "string" ||
      provenance.evidenceId.length === 0
    ) {
      return "refused_invalid_provenance";
    }
  } else if (provenance.evidenceId !== null) {
    return "refused_invalid_provenance";
  }
  if (
    typeof provenance.recordedAtEpochMs !== "number" ||
    !Number.isFinite(provenance.recordedAtEpochMs) ||
    provenance.recordedAtEpochMs < 0
  ) {
    return "refused_invalid_provenance";
  }
  return null;
}
