/**
 * PHASE 27B — Explicit Topology Graph Tests
 * (DETERMINISTIC / BOUNDED / LOCAL / CONFIG-AND-EVIDENCE ONLY /
 * NO DISCOVERY / NO POLICY / NO TOOL / NO AUTHORITY).
 *
 * Pins the graph's laws structurally and behaviorally:
 *   · closed provenance vocabulary (local_configuration | governed_evidence
 *     | unknown_source) with unknown source refusing;
 *   · every node/edge carries provenance + epoch;
 *   · topology and peer-trust state stay SEPARATE (no trust/admission/
 *     membership/authority/execution/Policy field exists anywhere in the
 *     module or on any record);
 *   · duplicates idempotent (identical re-record = no-op), conflicts
 *     refuse (never overwrite);
 *   · stale epoch / malformed / unknown kind / dangling edge / over-bound
 *     all fail closed with the graph EXACTLY as it was;
 *   · frozen bounds (callers may exceed, never redefine);
 *   · determinism: identical input sequences yield identical fingerprints
 *     and snapshots.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TOPOLOGY_GRAPH_SCHEMA_VERSION,
  TOPOLOGY_GRAPH_BOUNDS,
  TOPOLOGY_PROVENANCE_SOURCES,
  TOPOLOGY_GRAPH_REFUSAL_CODES,
  LocalTopologyGraph,
  type TopologyProvenance,
  type TopologyNodeInput,
  type TopologyEdgeInput,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27B module must NEVER contain (structural pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
  "node:sqlite",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
  "createSocket",
  "createHash",
  "DatabaseSync",
  "acceptMutation",
  "setInterval",
  "setTimeout",
  "Date.now",
  "performance.now",
]);

const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27b-1";
const NODE_A = "node-a";
const NODE_B = "node-b";

const CFG = (): TopologyProvenance => ({
  source: "local_configuration",
  evidenceId: null,
  recordedAtEpochMs: NOW,
});
const GOV = (evidenceId: string): TopologyProvenance => ({
  source: "governed_evidence",
  evidenceId,
  recordedAtEpochMs: NOW,
});

const NODE = (nodeId: string, over: Partial<TopologyNodeInput> = {}): TopologyNodeInput => ({
  nodeId,
  kind: "observed_node",
  epochId: EPOCH,
  provenance: CFG(),
  ...over,
});

const EDGE = (edgeId: string, fromNodeId: string, toNodeId: string, over: Partial<TopologyEdgeInput> = {}): TopologyEdgeInput => ({
  edgeId,
  fromNodeId,
  toNodeId,
  kind: "observed_edge",
  epochId: EPOCH,
  provenance: CFG(),
  ...over,
});

const openGraph = (): LocalTopologyGraph => {
  const d = LocalTopologyGraph.open({ epochId: EPOCH });
  if (!d.ok) throw new Error("expected open to succeed");
  return d.graph;
};

/** A graph with NODE_A and NODE_B recorded (the common fixture). */
const twoNodeGraph = (): LocalTopologyGraph => {
  const g = openGraph();
  g.addNode(NODE(NODE_A));
  g.addNode(NODE(NODE_B));
  return g;
};

// ── structural pins ──────────────────────────────────────────────────────────

describe("27B structure — bounded LOCAL graph, no forbidden surfaces", () => {
  it("forbidden surfaces list is pinned and the module contains none of them", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "node:crypto",
      "node:sqlite",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
      "createSocket",
      "createHash",
      "DatabaseSync",
      "acceptMutation",
      "setInterval",
      "setTimeout",
      "Date.now",
      "performance.now",
    ]);
    const code = codeOnly(SRC("meshTopologyGraph.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain(".persist(");
  });

  it("the module has NO trust/admission/membership/authority/execution/Policy field or vocabulary (topology and peer-trust state stay separate)", () => {
    const src = codeOnly(SRC("meshTopologyGraph.ts"));
    // field-shaped occurrences: `trust:` / `admission:` / `authority:` etc.
    // must not exist anywhere in code (comment lines already stripped) —
    // the graph structurally CANNOT express authority.
    expect(src).not.toMatch(/\btrust\s*:/);
    expect(src).not.toMatch(/\badmission\s*:/);
    expect(src).not.toMatch(/\bmembership\s*:/);
    expect(src).not.toMatch(/\bauthority\s*:/);
    expect(src).not.toMatch(/executionAuthorized\s*:/);
    expect(src).not.toMatch(/policyAuthorized\s*:/);
    expect(src).not.toMatch(/policyDecision/i);
    expect(src).not.toMatch(/DenyByDefault/);
    // no tool runtime path
    expect(src).not.toContain("executeToolRun");
    expect(src).not.toContain("runIsolated");
    expect(src).not.toContain("toolJunction");
    expect(src).not.toContain("requireTool");
    // no discovery / gossip / relay / consensus outside refusal prose
    expect(src).not.toMatch(/\bmdns\b/);
    expect(src).not.toMatch(/\bssdp\b/);
    expect(src).not.toMatch(/\bunicast\b/);
    expect(src).not.toMatch(/resolveDns|dns\.lookup/);
  });

  it("schema version, bounds, provenance sources, and refusal codes are pinned exactly", () => {
    expect(TOPOLOGY_GRAPH_SCHEMA_VERSION).toBe("menog-mesh-topology-graph/v0");
    expect(TOPOLOGY_GRAPH_BOUNDS).toEqual({ maxNodes: 64, maxEdges: 256 });
    expect(Object.isFrozen(TOPOLOGY_GRAPH_BOUNDS)).toBe(true);
    expect([...TOPOLOGY_PROVENANCE_SOURCES]).toEqual([
      "local_configuration",
      "governed_evidence",
      "unknown_source",
    ]);
    expect(Object.isFrozen(TOPOLOGY_PROVENANCE_SOURCES)).toBe(true);
    expect([...TOPOLOGY_GRAPH_REFUSAL_CODES]).toEqual([
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
    ]);
    expect(Object.isFrozen(TOPOLOGY_GRAPH_REFUSAL_CODES)).toBe(true);
  });
});

// ── open / epoch ─────────────────────────────────────────────────────────────

describe("27B open — one epoch per graph", () => {
  it("opens with a non-empty epoch and starts empty", () => {
    const d = LocalTopologyGraph.open({ epochId: EPOCH });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.graph.epochId).toBe(EPOCH);
      expect(d.graph.nodeCount).toBe(0);
      expect(d.graph.edgeCount).toBe(0);
      expect(d.explanation).toContain("TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY");
    }
  });

  it("an empty epoch id refuses (fail closed)", () => {
    const d = LocalTopologyGraph.open({ epochId: "" });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.code).toBe("topology_graph_refused");
      expect(d.refusal).toBe("refused_invalid_epoch");
    }
  });
});

// ── provenance (the ONLY sanctioned sources) ─────────────────────────────────

describe("27B provenance — closed sources; unknown refuses", () => {
  it("local_configuration (evidenceId null) records with provenance + epoch on the stored record", () => {
    const g = openGraph();
    const r = g.addNode(NODE(NODE_A));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.code).toBe("record_added");
    const snap = g.snapshot();
    expect(snap.epochId).toBe(EPOCH);
    expect(snap.nodes).toHaveLength(1);
    const rec = snap.nodes[0];
    expect(rec).toBeDefined();
    if (rec) {
      expect(rec.nodeId).toBe(NODE_A);
      expect(rec.epochId).toBe(EPOCH);
      expect(rec.provenance.source).toBe("local_configuration");
      expect(rec.provenance.evidenceId).toBeNull();
      expect(rec.provenance.recordedAtEpochMs).toBe(NOW);
    }
  });

  it("governed_evidence records only when they cite an evidence id", () => {
    const g = openGraph();
    const ok = g.addNode(NODE(NODE_A, { provenance: GOV("ev-001") }));
    expect(ok.ok).toBe(true);
    const snap = g.snapshot();
    expect(snap.nodes[0]?.provenance.evidenceId).toBe("ev-001");
  });

  it("governed_evidence WITHOUT an evidence id refuses (fail closed)", () => {
    const g = openGraph();
    const r = g.addNode(
      NODE(NODE_A, { provenance: { source: "governed_evidence", evidenceId: null, recordedAtEpochMs: NOW } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_invalid_provenance");
    expect(g.nodeCount).toBe(0);
  });

  it("local_configuration PRETENDING to cite evidence refuses (fail closed)", () => {
    const g = openGraph();
    const r = g.addNode(NODE(NODE_A, { provenance: GOV("ev-001") }));
    expect(r.ok).toBe(true); // sanity: GOV passes
    const g2 = openGraph();
    const r2 = g2.addNode(NODE(NODE_B, { provenance: { source: "local_configuration", evidenceId: "ev-001", recordedAtEpochMs: NOW } }));
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.refusal).toBe("refused_invalid_provenance");
    expect(g2.nodeCount).toBe(0);
  });

  it("an unknown provenance source refuses (no discovery/gossip/unnamed channel can contribute)", () => {
    const g = openGraph();
    const r = g.addNode(
      NODE(NODE_A, { provenance: { source: "gossip" as unknown as TopologyProvenance["source"], evidenceId: null, recordedAtEpochMs: NOW } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_unknown_provenance_source");
      expect(r.explanation).toContain("local configuration or governed evidence");
    }
    expect(g.nodeCount).toBe(0);
    const unknown = g.addNode(
      NODE(NODE_B, { provenance: { source: "unknown_source", evidenceId: null, recordedAtEpochMs: NOW } }),
    );
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.refusal).toBe("refused_unknown_provenance_source");
  });

  it("a non-finite recordedAtEpochMs refuses (fail closed)", () => {
    const g = openGraph();
    const r = g.addNode(
      NODE(NODE_A, { provenance: { source: "local_configuration", evidenceId: null, recordedAtEpochMs: Number.NaN } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_invalid_provenance");
  });
});

// ── epoch (stale fails closed) ───────────────────────────────────────────────

describe("27B epoch — stale records fail closed", () => {
  it("a node record from another epoch refuses and changes nothing", () => {
    const g = twoNodeGraph();
    const before = g.fingerprint();
    const r = g.addNode(NODE("node-c", { epochId: "epoch-old" }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_stale_epoch");
      expect(r.nodeCount).toBe(2);
    }
    expect(g.nodeCount).toBe(2);
    expect(g.hasNode("node-c")).toBe(false);
    expect(g.fingerprint()).toBe(before);
  });

  it("an edge record from another epoch refuses and changes nothing", () => {
    const g = twoNodeGraph();
    const before = g.fingerprint();
    const r = g.addEdge(EDGE("edge-1", NODE_A, NODE_B, { epochId: "epoch-old" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_stale_epoch");
    expect(g.edgeCount).toBe(0);
    expect(g.fingerprint()).toBe(before);
  });
});

// ── kinds (27A contract fails closed here too) ───────────────────────────────

describe("27B kinds — unknown kinds refuse under the frozen 27A contract", () => {
  it("an unknown node kind refuses with refused_unknown_node_kind", () => {
    const g = openGraph();
    const r = g.addNode(NODE(NODE_A, { kind: "mystery_node" as unknown as TopologyNodeInput["kind"] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_unknown_node_kind");
    expect(g.nodeCount).toBe(0);
  });

  it("an unknown edge kind refuses with refused_unknown_edge_kind", () => {
    const g = twoNodeGraph();
    const r = g.addEdge(EDGE("edge-1", NODE_A, NODE_B, { kind: "mystery_edge" as unknown as TopologyEdgeInput["kind"] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_unknown_edge_kind");
    expect(g.edgeCount).toBe(0);
  });

  it("the 27A unknown_* sentinels refuse here as well", () => {
    const g = openGraph();
    const r = g.addNode(NODE(NODE_A, { kind: "unknown_node" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_unknown_node_kind");
  });
});

// ── duplicates idempotent / conflicts refuse ─────────────────────────────────

describe("27B duplicates — identical is idempotent; different refuses", () => {
  it("re-recording an identical node is an idempotent no-op (counts unchanged)", () => {
    const g = twoNodeGraph();
    const before = g.fingerprint();
    const r = g.addNode(NODE(NODE_A));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.code).toBe("duplicate_idempotent");
      expect(r.nodeCount).toBe(2);
      expect(r.explanation).toContain("idempotent");
    }
    expect(g.nodeCount).toBe(2);
    expect(g.snapshot().nodes).toHaveLength(2);
    expect(g.fingerprint()).toBe(before);
  });

  it("re-recording an identical edge is an idempotent no-op", () => {
    const g = twoNodeGraph();
    g.addEdge(EDGE("edge-1", NODE_A, NODE_B));
    const before = g.fingerprint();
    const r = g.addEdge(EDGE("edge-1", NODE_A, NODE_B));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.code).toBe("duplicate_idempotent");
    expect(g.edgeCount).toBe(1);
    expect(g.fingerprint()).toBe(before);
  });

  it("a CONFLICTING node (same id, different content) refuses and never overwrites", () => {
    const g = openGraph();
    g.addNode(NODE(NODE_A, { provenance: GOV("ev-001") }));
    const original = g.snapshot().nodes[0];
    const r = g.addNode(NODE(NODE_A, { kind: "admitted_node" }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_conflicting_record");
      expect(r.explanation).toContain("never overwrites");
    }
    // original knowledge stands
    expect(g.snapshot().nodes[0]?.kind).toBe(original?.kind);
    expect(g.snapshot().nodes[0]?.provenance.evidenceId).toBe("ev-001");
    expect(g.nodeCount).toBe(1);
  });

  it("a CONFLICTING edge (same id, different endpoints) refuses and never overwrites", () => {
    const g = twoNodeGraph();
    g.addNode(NODE("node-c"));
    g.addEdge(EDGE("edge-1", NODE_A, NODE_B));
    const r = g.addEdge(EDGE("edge-1", NODE_A, "node-c"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_conflicting_record");
    expect(g.snapshot().edges[0]?.toNodeId).toBe(NODE_B);
    expect(g.edgeCount).toBe(1);
  });
});

// ── edges — dangling refuses (an edge cannot conjure a node) ─────────────────

describe("27B edges — both endpoints must already be recorded", () => {
  it("an edge to an unrecorded node refuses (dangling) and changes nothing", () => {
    const g = openGraph();
    g.addNode(NODE(NODE_A));
    const before = g.fingerprint();
    const r = g.addEdge(EDGE("edge-1", NODE_A, NODE_B));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_dangling_edge");
      expect(r.explanation).toContain("conjure");
    }
    expect(g.edgeCount).toBe(0);
    expect(g.fingerprint()).toBe(before);
    expect(g.hasNode(NODE_B)).toBe(false);
  });

  it("a valid edge between recorded nodes records with provenance + epoch", () => {
    const g = twoNodeGraph();
    const r = g.addEdge(EDGE("edge-1", NODE_A, NODE_B, { provenance: GOV("ev-002") }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.code).toBe("record_added");
    const rec = g.snapshot().edges[0];
    expect(rec).toBeDefined();
    if (rec) {
      expect(rec.edgeId).toBe("edge-1");
      expect(rec.epochId).toBe(EPOCH);
      expect(rec.provenance.source).toBe("governed_evidence");
      expect(rec.provenance.evidenceId).toBe("ev-002");
    }
  });

  it("an edge with an empty endpoint id refuses (malformed fails closed)", () => {
    const g = twoNodeGraph();
    const r = g.addEdge(EDGE("edge-1", "", NODE_B));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_invalid_record");
    expect(g.edgeCount).toBe(0);
  });

  it("a node with an empty id refuses (malformed fails closed)", () => {
    const g = openGraph();
    const r = g.addNode(NODE(""));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_invalid_record");
    expect(g.nodeCount).toBe(0);
  });
});

// ── bounds (frozen constants: refuse, never evict) ───────────────────────────

describe("27B bounds — frozen caps refuse new records and never evict", () => {
  it("the node bound refuses a NEW node at capacity; duplicates at capacity stay idempotent", () => {
    const g = openGraph();
    for (let i = 0; i < TOPOLOGY_GRAPH_BOUNDS.maxNodes; i++) {
      const r = g.addNode(NODE(`node-${String(i).padStart(3, "0")}`));
      expect(r.ok).toBe(true);
    }
    expect(g.nodeCount).toBe(TOPOLOGY_GRAPH_BOUNDS.maxNodes);
    const r = g.addNode(NODE("node-new"));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_graph_bound");
      expect(r.nodeCount).toBe(TOPOLOGY_GRAPH_BOUNDS.maxNodes);
    }
    expect(g.nodeCount).toBe(TOPOLOGY_GRAPH_BOUNDS.maxNodes); // nothing evicted
    // idempotent duplicate STILL works at capacity (no growth)
    const dup = g.addNode(NODE("node-000"));
    expect(dup.ok).toBe(true);
    if (dup.ok) expect(dup.code).toBe("duplicate_idempotent");
  });

  it("the edge bound refuses a NEW edge at capacity and never evicts", () => {
    const g = openGraph();
    // record a full clique of nodes, then fill edges between node-000 and the rest
    const n = 8;
    for (let i = 0; i < n; i++) g.addNode(NODE(`node-${String(i).padStart(3, "0")}`));
    // we cannot reach 256 edges with 8 nodes (max 56 unique pairs), so drive
    // the bound with multiple distinct edge ids between the same endpoints
    let added = 0;
    for (let i = 0; i < TOPOLOGY_GRAPH_BOUNDS.maxEdges; i++) {
      const r = g.addEdge(EDGE(`edge-${String(i).padStart(4, "0")}`, "node-000", "node-001"));
      expect(r.ok).toBe(true);
      added++;
    }
    expect(added).toBe(TOPOLOGY_GRAPH_BOUNDS.maxEdges);
    expect(g.edgeCount).toBe(TOPOLOGY_GRAPH_BOUNDS.maxEdges);
    const r = g.addEdge(EDGE("edge-new", "node-000", "node-001"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_graph_bound");
    expect(g.edgeCount).toBe(TOPOLOGY_GRAPH_BOUNDS.maxEdges);
    // a stale/dangling record at capacity still refuses with ITS OWN code
    // (first-match order: validation before bound)
    const stale = g.addEdge(EDGE("edge-stale", "node-000", "node-001", { epochId: "epoch-old" }));
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.refusal).toBe("refused_stale_epoch");
  });

  it("a caller cannot redefine a bound (bounds object is frozen)", () => {
    expect(Object.isFrozen(TOPOLOGY_GRAPH_BOUNDS)).toBe(true);
    expect(() => {
      (TOPOLOGY_GRAPH_BOUNDS as { maxNodes?: number }).maxNodes = 1;
    }).toThrow();
    expect(TOPOLOGY_GRAPH_BOUNDS.maxNodes).toBe(64);
  });
});

// ── validation order (first match wins) ──────────────────────────────────────

describe("27B validation order — pinned, first match wins", () => {
  it("provenance is checked BEFORE epoch (unknown source wins over stale epoch)", () => {
    const g = openGraph();
    const r = g.addNode(
      NODE(NODE_A, {
        epochId: "epoch-old",
        provenance: { source: "unknown_source", evidenceId: null, recordedAtEpochMs: NOW },
      }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_unknown_provenance_source");
  });

  it("epoch is checked BEFORE kind (stale wins over unknown kind)", () => {
    const g = openGraph();
    const r = g.addNode(
      NODE(NODE_A, { epochId: "epoch-old", kind: "mystery" as unknown as TopologyNodeInput["kind"] }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_stale_epoch");
  });

  it("conflict is checked BEFORE bound (a conflicting record at capacity reports conflict)", () => {
    const g = openGraph();
    for (let i = 0; i < TOPOLOGY_GRAPH_BOUNDS.maxNodes; i++) g.addNode(NODE(`node-${String(i).padStart(3, "0")}`));
    const r = g.addNode(NODE("node-000", { kind: "admitted_node" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_conflicting_record");
  });
});

// ── refusal leaves the graph EXACTLY as it was ───────────────────────────────

describe("27B fail-closed — every refusal is a no-op for state", () => {
  it("the fingerprint is unchanged after each of a representative refusal set", () => {
    const g = twoNodeGraph();
    g.addEdge(EDGE("edge-1", NODE_A, NODE_B));
    const before = g.fingerprint();
    const refusals = [
      g.addNode(NODE("x", { provenance: { source: "unknown_source", evidenceId: null, recordedAtEpochMs: NOW } })),
      g.addNode(NODE("x", { epochId: "epoch-old" })),
      g.addNode(NODE("x", { kind: "unknown_node" })),
      g.addNode(NODE("")),
      g.addEdge(EDGE("e", NODE_A, "node-missing")),
      g.addEdge(EDGE("edge-1", NODE_A, NODE_A)), // conflict
    ];
    for (const r of refusals) expect(r.ok).toBe(false);
    expect(g.nodeCount).toBe(2);
    expect(g.edgeCount).toBe(1);
    expect(g.fingerprint()).toBe(before);
  });
});

// ── separation: topology is NOT peer-trust state ─────────────────────────────

describe("27B separation — graph records carry no trust/authority field", () => {
  it("stored records expose only nodeId/kind/epochId/provenance (nodes) and edge fields + provenance (edges)", () => {
    const g = twoNodeGraph();
    g.addEdge(EDGE("edge-1", NODE_A, NODE_B, { provenance: GOV("ev-003") }));
    const snap = g.snapshot();
    for (const n of snap.nodes) {
      expect(Object.keys(n).sort()).toEqual(["epochId", "kind", "nodeId", "provenance"]);
      expect(Object.keys(n.provenance).sort()).toEqual(["evidenceId", "recordedAtEpochMs", "source"]);
    }
    for (const e of snap.edges) {
      expect(Object.keys(e).sort()).toEqual(["edgeId", "epochId", "fromNodeId", "kind", "provenance", "toNodeId"]);
    }
    // no authority-shaped key anywhere in the serialized graph
    const json = JSON.stringify(snap);
    expect(json).not.toMatch(/"trust"|"admission"|"membership"|"authority"|"executionAuthorized"|"policy"/);
  });

  it("the module source contains no acceptMutation/persist path (no alternate persist path)", () => {
    const src = codeOnly(SRC("meshTopologyGraph.ts"));
    expect(src).not.toContain("acceptMutation");
    expect(src).not.toContain(".persist(");
    expect(src).not.toContain("DurableStore");
    expect(src).not.toContain("RuntimeStateCoordinator");
    expect(src).not.toContain("PeerRegistry");
  });
});

// ── determinism ──────────────────────────────────────────────────────────────

describe("27B determinism — identical inputs, identical knowledge", () => {
  it("identical input sequences yield identical fingerprints; different content differs", () => {
    const a = twoNodeGraph();
    a.addEdge(EDGE("edge-1", NODE_A, NODE_B, { provenance: GOV("ev-1") }));
    const b = twoNodeGraph();
    b.addEdge(EDGE("edge-1", NODE_A, NODE_B, { provenance: GOV("ev-1") }));
    expect(a.fingerprint()).toBe(b.fingerprint());

    const c = twoNodeGraph();
    c.addEdge(EDGE("edge-1", NODE_A, NODE_B, { provenance: GOV("ev-2") }));
    expect(c.fingerprint()).not.toBe(a.fingerprint());

    const d = twoNodeGraph(); // no edge
    expect(d.fingerprint()).not.toBe(a.fingerprint());
  });

  it("fingerprints are order-insensitive (same records, different insertion order)", () => {
    const a = openGraph();
    a.addNode(NODE(NODE_A));
    a.addNode(NODE(NODE_B));
    const b = openGraph();
    b.addNode(NODE(NODE_B));
    b.addNode(NODE(NODE_A));
    expect(a.fingerprint()).toBe(b.fingerprint());
    expect(a.snapshot().nodes.map((n) => n.nodeId)).toEqual(b.snapshot().nodes.map((n) => n.nodeId));
  });

  it("snapshots are frozen (read-only knowledge)", () => {
    const g = twoNodeGraph();
    const snap = g.snapshot();
    expect(Object.isFrozen(snap)).toBe(true);
    expect(Object.isFrozen(snap.nodes)).toBe(true);
    expect(Object.isFrozen(snap.nodes[0])).toBe(true);
    expect(Object.isFrozen(snap.nodes[0]?.provenance)).toBe(true);
  });

  it("a different epoch yields a different fingerprint (epoch binds knowledge)", () => {
    const a = openGraph();
    a.addNode(NODE(NODE_A));
    const openB = LocalTopologyGraph.open({ epochId: "epoch-27b-2" });
    expect(openB.ok).toBe(true);
    if (!openB.ok) return;
    openB.graph.addNode(NODE(NODE_A));
    expect(openB.graph.fingerprint()).not.toBe(a.fingerprint());
  });
});
