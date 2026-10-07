/**
 * PHASE 28F — PROVENANCE & EXPLANATION GRAPH
 * (TRACEABILITY / READ-ONLY / BOUNDED / CYCLE-SAFE / ZERO-AUTHORITY)
 *
 * The prompt pins five separations and two failure behaviours. Each has its own
 * block, and each is driven through the real code path:
 *
 *   provenance metadata != evidence content  → refuses rather than sanitises
 *   explanation        != authorization     → structural zeros + a trust guard
 *   forwarder          != origin            → role carried, substitution refused
 *   evidence link      != trust             → structural false on every node/edge
 *   route evidence     != execution permission → confersAuthority false everywhere
 *
 *   missing provenance → explicit unknown, never fabricated
 *   provenance stripping / role substitution → fail closed
 *
 * Plus cycle-safety, which is enforced by an explicit visited set and tested
 * against a genuinely cyclic graph rather than asserted in a comment.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildGetigExplanationGraph,
  explainGetigSubject,
  refuseProvenanceAsTrust,
  buildGetigFrame,
  GETIG_EXPLANATION_NODE_KINDS,
  GETIG_EXPLANATION_RELATIONS,
  GETIG_EXPLANATION_ROLES,
  GETIG_FORBIDDEN_CONTENT_FIELDS,
  GETIG_GRAPH_REFUSAL_CODES,
  GETIG_GRAPH_BOUNDS,
  GETIG_GRAPH_SCHEMA_VERSION,
  type GetigExplanationGraph,
  type SubjectExplanation,
  type GetigFrameInput,
  type VisibleEntity,
} from "../../packages/durable-state/dist/index.js";

const SRC_PATH = join(process.cwd(), "packages", "durable-state", "src", "getigProvenance.ts");
const DTS_PATH = join(process.cwd(), "packages", "durable-state", "dist", "getigProvenance.d.ts");
const HEX64 = /^[0-9a-f]{64}$/;
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-28f";
const OBSERVER = "observer-local-1";

function readSourceOrThrow(path: string): string {
  const text = readFileSync(path, "utf8");
  if (text.length === 0) throw new Error(`audit input is empty: ${path}`);
  return text;
}

const hex = (d: string) => d.repeat(64);
const observer = { observerId: OBSERVER, observerKind: "local_runtime" as const, epochId: EPOCH, isGlobalTruth: false as const };

const prov = (refId: string, over: Record<string, unknown> = {}) => ({
  refId,
  recordedAtEpochMs: NOW,
  sourceKind: "governed_evidence" as const,
  evidenceId: `ev-${refId}`,
  confersTrust: false as const,
  ...over,
});

const ent = (visibleId: string, over: Partial<VisibleEntity> = {}): VisibleEntity => ({
  visibleId,
  kind: "runtime_node",
  label: `label-${visibleId}`,
  isRuntimeObject: false,
  grant: "none",
  freshness: "current",
  lifecycle: "observed",
  provenanceRefs: [],
  representsRuntimeId: null,
  ...over,
});

const frameOf = (over: Record<string, unknown> = {}) => ({
  schemaVersion: "menog-getig/v0",
  frameId: "frame-a",
  observer,
  epochId: EPOCH,
  asOfEpochMs: NOW,
  sourceProjectionHash: hex("a"),
  canonicalVisibleHash: hex("b"),
  entities: [] as unknown[],
  relations: [] as unknown[],
  events: [] as unknown[],
  conflicts: [] as unknown[],
  refusals: [] as unknown[],
  routes: [] as unknown[],
  proposalFlows: [] as unknown[],
  authority: "none",
  controlPlane: "none",
  readOnly: true,
  replaySemantics: "visual_only_not_executable" as const,
  globalTruth: false as const,
  visibleCapabilities: [] as string[],
  ...over,
});

const graphOf = (frameOver: Record<string, unknown> = {}, records: readonly unknown[] = []) =>
  buildGetigExplanationGraph({ graphId: "graph-1", frame: frameOf(frameOver), provenanceRecords: records });

function built(frameOver: Record<string, unknown> = {}, records: readonly unknown[] = []): GetigExplanationGraph {
  const decision = graphOf(frameOver, records);
  if (!decision.ok) throw new Error(`expected a built graph, got ${decision.refusal}: ${decision.explanation}`);
  return decision.graph;
}

function traced(graph: unknown, subject: string): SubjectExplanation {
  const decision = explainGetigSubject(graph, subject);
  if (!decision.ok) throw new Error(`expected a trace, got ${decision.refusal}: ${decision.explanation}`);
  return decision.trace;
}

// ── construction ─────────────────────────────────────────────────────────────

describe("28F — explanation graph construction", () => {
  it("builds deterministically from the same frame", () => {
    const a = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    const b = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    expect(a.graphHash).toBe(b.graphHash);
    expect(a.graphHash).toMatch(HEX64);
  });

  it("is insensitive to the order entities arrive in", () => {
    const a = built({ entities: [ent("n1"), ent("n2"), ent("n3")] });
    const b = built({ entities: [ent("n3"), ent("n1"), ent("n2")] });
    expect(a.graphHash).toBe(b.graphHash);
    expect(a.nodes.map((n) => n.nodeId)).toEqual(b.nodes.map((n) => n.nodeId));
  });

  it("freezes the graph, its nodes and its edges", () => {
    const g = built({ entities: [ent("n1")] });
    expect(Object.isFrozen(g)).toBe(true);
    expect(Object.isFrozen(g.nodes)).toBe(true);
    expect(Object.isFrozen(g.nodes[0])).toBe(true);
    expect(Object.isFrozen(g.edges)).toBe(true);
    expect(Object.isFrozen(g.edges[0])).toBe(true);
  });

  it("links every subject to the observer and the frame", () => {
    const g = built({ entities: [ent("n1"), ent("n2")] });
    for (const id of ["n1", "n2"]) {
      const relations = g.edges.filter((e) => e.fromNodeId === `entities:${id}`).map((e) => e.relation);
      expect(relations).toContain("observed_by");
      expect(relations).toContain("projected_in");
    }
    expect(g.nodes.some((n) => n.kind === "observer" && n.label === OBSERVER)).toBe(true);
    expect(g.nodes.some((n) => n.kind === "frame" && n.label === "frame-a")).toBe(true);
  });

  it("carries lifecycle and freshness facts for entities", () => {
    const g = built({ entities: [ent("n1", { lifecycle: "quarantined", freshness: "stale" })] });
    const labels = g.nodes.filter((n) => n.kind === "lifecycle_fact" || n.kind === "freshness_fact").map((n) => n.label).sort();
    expect(labels).toEqual(["freshness=stale", "lifecycle=quarantined"]);
  });

  it("pins its structural zeros", () => {
    const g = built({ entities: [ent("n1")] });
    expect(g.schemaVersion).toBe(GETIG_GRAPH_SCHEMA_VERSION);
    expect(g.explainsWhy).toBe(true);
    // EXPLANATION != AUTHORIZATION
    expect(g.authorizes).toBe(false);
    expect(g.cycleSafe).toBe(true);
    expect(g.bounded).toBe(true);
    expect(g.readOnly).toBe(true);
    expect(g.authority).toBe("none");
  });

  it("refuses a malformed frame rather than building half a graph", () => {
    for (const bad of [null, undefined, 42, "frame", {}]) {
      const decision = buildGetigExplanationGraph({ graphId: "g", frame: bad });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_graph_frame_invalid");
    }
  });
});

// ── the question: WHY AM I SEEING THIS? ──────────────────────────────────────

describe("28F — every visible object answers why it is visible", () => {
  it("traces a subject to its observer, frame, provenance and facts", () => {
    const g = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    const trace = traced(g, "n1");
    const kinds = new Set(trace.hops.map((h) => h.kind));
    for (const kind of ["observer", "frame", "provenance_ref", "lifecycle_fact", "freshness_fact"]) {
      expect(kinds.has(kind as never), `trace is missing ${kind}`).toBe(true);
    }
    expect(trace.hopCount).toBeGreaterThan(0);
    expect(trace.questionAnswered).toBe("why:n1");
  });

  it("accepts a fully qualified subject id as well as a bare one", () => {
    const g = built({ entities: [ent("n1")] });
    expect(traced(g, "n1").subjectVisibleId).toBe("n1");
    expect(traced(g, "entities:n1").subjectVisibleId).toBe("n1");
    // One subject, one answer: the graph key is an internal detail and must not
    // leak into the trace, or the same question would get two different answers.
    expect(traced(g, "entities:n1")).toEqual(traced(g, "n1"));
  });

  it("reports an unqualified subject collection rather than chopping the id", () => {
    const g = built({ entities: [ent("n1")] });
    expect(traced(g, "n1").subjectCollection).toBe("entities");
    // A graph whose node keys carry no collection prefix must not lose a character.
    const plain = { nodes: [{ nodeId: "solo", kind: "subject", label: "solo" }], edges: [] };
    const decision = explainGetigSubject(plain, "solo");
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.trace.subjectVisibleId).toBe("solo");
      expect(decision.trace.subjectCollection).toBe("unqualified");
    }
  });

  it("refuses to explain a subject that is not in the graph", () => {
    const g = built({ entities: [ent("n1")] });
    const decision = explainGetigSubject(g, "not-here");
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_explain_subject_unknown");
      expect(decision.trace).toBeNull();
    }
  });

  it("refuses to explain using something that is not a graph", () => {
    for (const bad of [null, undefined, 42, "graph", {}, { nodes: "no" }]) {
      const decision = explainGetigSubject(bad, "n1");
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_explain_not_a_graph");
    }
  });

  it("traces a conflict to the observer it is attributed to", () => {
    const g = built({
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: OBSERVER, subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
    });
    const trace = traced(g, "c1");
    expect(trace.hops.some((h) => h.kind === "conflict_attribution" && h.relation === "attributed_to")).toBe(true);
  });
});

// ── missing provenance is explicit, never fabricated ─────────────────────────

describe("28F — missing provenance becomes an explicit unknown", () => {
  it("records a subject with no provenance refs as unknown", () => {
    const g = built({ entities: [ent("bare")] });
    expect(g.unknownProvenanceSubjects).toEqual(["bare"]);
    expect(g.missingProvenanceCount).toBe(1);
    expect(g.nodes.some((n) => n.kind === "unknown")).toBe(true);
  });

  it("connects the subject to that unknown with a named relation", () => {
    const g = built({ entities: [ent("bare")] });
    const trace = traced(g, "bare");
    expect(trace.hops.some((h) => h.kind === "unknown" && h.relation === "provenance_missing")).toBe(true);
  });

  it("never fabricates a refId for a missing one", () => {
    const g = built({ entities: [ent("bare")] });
    const ids = g.nodes.map((n) => n.nodeId);
    expect(ids.some((id) => /provenance:(undefined|null|)$/.test(id))).toBe(false);
    expect(ids.every((id) => !id.endsWith(":undefined"))).toBe(true);
  });

  it("treats a cited reference nobody describes as an unknown too", () => {
    // The frame cites it, but no record describes it. Inventing one would be
    // fabrication; calling it known would be a lie.
    const g = built({ entities: [ent("ghosted", { provenanceRefs: [{ ...prov("ref-ghost"), evidenceId: null }] })] }, []);
    expect(g.unknownProvenanceSubjects).toEqual(["ghosted"]);
    expect(g.nodes.some((n) => n.kind === "provenance_ref")).toBe(false);
  });

  it("resolves to a provenance_ref once the record is supplied", () => {
    const g = built({ entities: [ent("known", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    expect(g.unknownProvenanceSubjects).toEqual([]);
    expect(g.nodes.some((n) => n.kind === "provenance_ref")).toBe(true);
  });

  it("counts each affected subject once however many refs are missing", () => {
    const g = built({ entities: [ent("dup", { provenanceRefs: [{ ...prov("r1"), evidenceId: null }, { ...prov("r2"), evidenceId: null }] })] }, []);
    expect(g.missingProvenanceCount).toBe(1);
  });
});

// ── PROVENANCE METADATA != EVIDENCE CONTENT ──────────────────────────────────

describe("28F — provenance metadata is not evidence content", () => {
  it("refuses a record carrying a secret, rather than sanitising it", () => {
    const decision = graphOf({ entities: [] }, [{ ...prov("ref-1"), secret: "hunter2" }]);
    expect(decision.ok).toBe(false);
    // Refuse, do not strip: silently dropping it would leave the caller
    // believing the secret had been recorded.
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_graph_provenance_content_present");
      expect(decision.graph).toBeNull();
      expect(decision.explanation).toContain("secret");
    }
  });

  it("catches every forbidden field, whatever its spelling", () => {
    const fields = ["content", "raw_text", "rawText", "privateKey", "toolOutput", "policyText", "storeContent", "payload", "filePath", "apiKey", "password"];
    for (const field of fields) {
      const decision = graphOf({ entities: [] }, [{ ...prov("ref-1"), [field]: "x" }]);
      expect(decision.ok, `field "${field}" was accepted`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_graph_provenance_content_present");
    }
  });

  it("names the forbidden fields it checks, and the list is not empty", () => {
    expect(GETIG_FORBIDDEN_CONTENT_FIELDS.length).toBeGreaterThan(10);
    expect([...GETIG_FORBIDDEN_CONTENT_FIELDS]).toEqual(
      expect.arrayContaining(["content", "secret", "privatekey", "policytext", "rawtext"]),
    );
  });

  it("the forbidden-field matcher actually detects a planted violation", () => {
    // Self-test for the matcher itself: normalising must defeat spacing.
    const normalise = (n: string) => n.toLowerCase().replace(/[^a-z0-9]/g, "");
    expect(GETIG_FORBIDDEN_CONTENT_FIELDS.map(normalise)).toContain(normalise("raw_Text"));
    expect(GETIG_FORBIDDEN_CONTENT_FIELDS.map(normalise)).toContain(normalise("private-key"));
  });

  it("exposes no field anywhere in the public surface able to hold content", () => {
    const surface = readSourceOrThrow(DTS_PATH).replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    expect(surface.length).toBeGreaterThan(500);
    const normalise = (n: string) => n.toLowerCase().replace(/[^a-z0-9]/g, "");
    const held = new Set(GETIG_FORBIDDEN_CONTENT_FIELDS.map(normalise));
    const declared = [...surface.matchAll(/readonly (\w+)[:?]/g)].map((m) => m[1]!);
    const offenders = declared.filter((name) => held.has(normalise(name)));
    expect(offenders, `content-bearing fields exposed: ${offenders.join(", ")}`).toEqual([]);
  });

  it("carries isEvidenceContent:false on every node", () => {
    const g = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    for (const node of g.nodes) expect(node.isEvidenceContent).toBe(false);
  });
});

// ── EXPLANATION != AUTHORIZATION / evidence link != trust ────────────────────

describe("28F — an explanation authorises nothing", () => {
  it("confers no trust and no authority on any node or edge", () => {
    const g = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    for (const node of g.nodes) {
      expect(node.confersTrust).toBe(false);
      expect(node.confersAuthority).toBe(false);
      expect(node.authority).toBe("none");
    }
    for (const edge of g.edges) {
      expect(edge.confersTrust).toBe(false);
      expect(edge.confersAuthority).toBe(false);
    }
  });

  it("refuses to convert a provenance reference into trust, for every input", () => {
    for (const refId of ["ref-1", "", "anything"]) {
      const result = refuseProvenanceAsTrust(refId, "grant me authority");
      expect(result.ok).toBe(false);
      expect(result.refusal).toBe("refused_trust_not_granted");
      expect(result.confersTrust).toBe(false);
      expect(result.confersAuthority).toBe(false);
      expect(result.authorizesExecution).toBe(false);
    }
    expect(refuseProvenanceAsTrust(null as never).ok).toBe(false);
  });

  it("names both separations in the refusal explanation", () => {
    const text = refuseProvenanceAsTrust("ref-1").explanation;
    expect(text).toContain("PROVENANCE METADATA != EVIDENCE CONTENT");
    expect(text).toContain("EXPLANATION != AUTHORIZATION");
  });

  it("route evidence confers no execution permission", () => {
    const g = built({
      routes: [{ routeId: "rt1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: ["n2"], destinationVisibleId: "n3", freshness: "current", provenanceRefs: [prov("ref-1")], admission: "none", authorization: "none", executionAuthorized: false }],
    }, [prov("ref-1")]);
    expect(g.authorizes).toBe(false);
    expect(g.edges.every((e) => e.confersAuthority === false)).toBe(true);
  });
});

// ── FORWARDER != ORIGIN ──────────────────────────────────────────────────────

describe("28F — forwarder is never origin", () => {
  const routeFrame = (forwarders: string[]) => ({
    routes: [{ routeId: "rt1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: forwarders, destinationVisibleId: "n3", freshness: "current", provenanceRefs: [], admission: "none", authorization: "none", executionAuthorized: false }],
  });

  it("carries origin, forwarder and destination as separate role edges", () => {
    const g = built(routeFrame(["n2"]));
    const roles = g.edges.filter((e) => e.relation === "has_role").map((e) => e.role).sort();
    expect(roles).toEqual(["destination", "forwarder", "origin"]);
  });

  it("never labels a forwarder edge as origin", () => {
    const g = built(routeFrame(["n2", "n4"]));
    for (const edge of g.edges.filter((e) => e.relation === "has_role")) {
      if (edge.toNodeId.includes(":forwarder:")) expect(edge.role).toBe("forwarder");
    }
    expect(g.edges.filter((e) => e.role === "origin")).toHaveLength(1);
  });

  it("refuses role substitution when a forwarder list contains the origin", () => {
    const decision = graphOf(routeFrame(["n1"]));
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_graph_role_substitution");
      expect(decision.graph).toBeNull();
    }
  });

  it("accepts a forwarder that is merely a different node", () => {
    const g = built(routeFrame(["n2"]));
    expect(g.nodes.some((n) => n.kind === "route_role" && n.label === "origin=n1")).toBe(true);
  });

  it("keeps the role vocabulary closed", () => {
    expect([...GETIG_EXPLANATION_ROLES].sort()).toEqual(["destination", "forwarder", "none", "origin"]);
  });
});

// ── cycle safety ─────────────────────────────────────────────────────────────

describe("28F — the explanation walk is cycle-safe", () => {
  const cyclicGraph = {
    graphId: "cyclic",
    nodes: [{ nodeId: "entities:a", kind: "subject", label: "a" }, { nodeId: "entities:b", kind: "subject", label: "b" }],
    edges: [
      { edgeId: "e1", fromNodeId: "entities:a", toNodeId: "entities:b", relation: "observed_by", role: "none" },
      { edgeId: "e2", fromNodeId: "entities:b", toNodeId: "entities:a", relation: "observed_by", role: "none" },
      { edgeId: "e3", fromNodeId: "entities:a", toNodeId: "entities:a", relation: "projected_in", role: "none" },
    ],
  };

  it("terminates on a genuinely cyclic graph", () => {
    const decision = explainGetigSubject(cyclicGraph, "a");
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.trace.hopCount).toBeLessThanOrEqual(GETIG_GRAPH_BOUNDS.maxExplainNodes);
  });

  it("reports that a cycle was broken rather than pretending the walk completed", () => {
    const trace = traced(cyclicGraph, "a");
    expect(trace.cycleBroken).toBe(true);
  });

  it("terminates on a 5000-edge self-loop storm", () => {
    const storm = {
      nodes: [{ nodeId: "entities:a", kind: "subject", label: "a" }],
      edges: Array.from({ length: 5_000 }, (_, i) => ({ edgeId: `e${i}`, fromNodeId: "entities:a", toNodeId: "entities:a", relation: "projected_in" as const, role: "none" as const })),
    };
    const decision = explainGetigSubject(storm, "a");
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.trace.hopCount).toBeLessThanOrEqual(GETIG_GRAPH_BOUNDS.maxExplainNodes);
  });

  it("terminates on a deep chain rather than recursing to death", () => {
    const deep = {
      nodes: Array.from({ length: 500 }, (_, i) => ({ nodeId: `n${i}`, kind: "subject" as const, label: `n${i}` })),
      edges: Array.from({ length: 499 }, (_, i) => ({ edgeId: `e${i}`, fromNodeId: `n${i}`, toNodeId: `n${i + 1}`, relation: "observed_by" as const, role: "none" as const })),
    };
    const decision = explainGetigSubject(deep, "n0");
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.trace.maxDepthReached).toBeLessThanOrEqual(GETIG_GRAPH_BOUNDS.maxExplainDepth);
    expect(decision.trace.boundedStop).toBe(true);
  });

  it("produces the same trace for the same graph, every time", () => {
    const g = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    expect(JSON.stringify(traced(g, "n1"))).toBe(JSON.stringify(traced(g, "n1")));
  });
});

// ── refusals ─────────────────────────────────────────────────────────────────

describe("28F — refusals", () => {
  it("refuses a provenance record with no usable refId", () => {
    const decision = buildGetigExplanationGraph({ graphId: "g", frame: frameOf(), provenanceRecords: [{}] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_graph_provenance_record_invalid");
  });

  it("refuses the same refId supplied twice", () => {
    const decision = buildGetigExplanationGraph({ graphId: "g", frame: frameOf(), provenanceRecords: [prov("r"), prov("r")] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_graph_provenance_record_invalid");
  });

  it("refuses a graph beyond its node bound", () => {
    const many = { entities: Array.from({ length: 2_000 }, (_, i) => ent(`n${i}`)) };
    const decision = graphOf(many);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_graph_bounds_exceeded");
  });

  it("refuses a subject with no usable id", () => {
    const decision = graphOf({ entities: [{ ...ent("x"), visibleId: "" }] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_explain_subject_unknown");
  });

  it("exposes no partial graph on refusal", () => {
    const decision = graphOf({ entities: [] }, [{ ...prov("r"), secret: "x" }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(Object.prototype.hasOwnProperty.call(decision, "graph")).toBe(true);
      expect(decision.graph).toBeNull();
    }
  });

  it("drives every declared refusal code from a real input", () => {
    const produced = new Map<string, string>();
    const record = (name: string, d: { ok: boolean; refusal?: string }) => {
      if (!d.ok) produced.set(d.refusal!, name);
    };
    const g = built({ entities: [ent("n1")] });
    record("frame invalid", buildGetigExplanationGraph({ graphId: "g", frame: null }));
    record("record invalid", buildGetigExplanationGraph({ graphId: "g", frame: frameOf(), provenanceRecords: [{}] }));
    record("content present", graphOf({ entities: [] }, [{ ...prov("r"), secret: "x" }]));
    record("role substitution", graphOf({ routes: [{ routeId: "rt1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: ["n1"], destinationVisibleId: "n3", freshness: "current", provenanceRefs: [], admission: "none", authorization: "none", executionAuthorized: false }] }));
    record("bounds", graphOf({ entities: Array.from({ length: 2_000 }, (_, i) => ent(`n${i}`)) }));
    record("not a graph", explainGetigSubject(null, "n1"));
    record("subject unknown", explainGetigSubject(g, "nope"));
    record("trust", refuseProvenanceAsTrust("r"));

    const unreachable = GETIG_GRAPH_REFUSAL_CODES.filter((c) => !produced.has(c));
    expect(unreachable, `refusal codes no input can produce: ${unreachable.join(", ")}`).toEqual([]);
    expect(produced.size).toBe(GETIG_GRAPH_REFUSAL_CODES.length);
  });

  it("has no duplicate refusal codes", () => {
    expect(new Set(GETIG_GRAPH_REFUSAL_CODES).size).toBe(GETIG_GRAPH_REFUSAL_CODES.length);
  });
});

// ── law audits ───────────────────────────────────────────────────────────────

describe("28F — law audit: no execution, network, renderer or policy path", () => {
  const FORBIDDEN_CAPABILITY = [
    "child_process", "node:child_process", "execSync", "spawnSync", "node:worker_threads",
    "node:net", "node:http", "node:fs", "WebGPU", "GPUDevice", "three.js", "@babylonjs",
    "playcanvas", "requestAnimationFrame", "eval(", "new Function", "@menog/policy", "@menog/runtime-linux",
  ] as const;

  const scan = (text: string): string[] => {
    const lower = text.toLowerCase();
    return FORBIDDEN_CAPABILITY.filter((token) => {
      const t = token.toLowerCase();
      if (/^[a-z0-9_]+$/.test(t)) return new RegExp(`\\b${t}\\b`).test(lower);
      return lower.includes(t);
    });
  };

  it("the capability scan actually detects a planted violation", () => {
    expect(scan("const cp = require('node:child_process')")).toEqual(["child_process", "node:child_process"]);
    expect(scan("import { evaluate } from '@menog/policy'")).toEqual(["@menog/policy"]);
    expect(scan("the three node kinds are closed")).toEqual([]);
  });

  it("finds none in the source", () => {
    const found = scan(readSourceOrThrow(SRC_PATH));
    expect(found, `forbidden capabilities present: ${found.join(", ")}`).toEqual([]);
  });

  it("reports a non-empty audit input", () => {
    const text = readSourceOrThrow(SRC_PATH);
    expect(text.length).toBeGreaterThan(2_000);
    expect(text).toContain("buildGetigExplanationGraph");
    expect(text).toContain("refuseProvenanceAsTrust");
  });

  it("exports no mutating or executing function", () => {
    const decls = readSourceOrThrow(DTS_PATH);
    const exported = [...decls.matchAll(/export declare (?:function|const) (\w+)/g)].map((m) => m[1]!);
    expect(exported.length).toBeGreaterThan(0);
    const mutating = exported.filter((n) =>
      /^(apply|mutate|set|update|write|delete|remove|insert|patch|put|grant|authorize|admit|trust|attest|sign)$/i.test(n),
    );
    expect(mutating, `mutating/trusting exports present: ${mutating.join(", ")}`).toEqual([]);
  });

  it("keeps the vocabularies closed and distinct", () => {
    expect(new Set(GETIG_EXPLANATION_NODE_KINDS).size).toBe(GETIG_EXPLANATION_NODE_KINDS.length);
    expect(new Set(GETIG_EXPLANATION_RELATIONS).size).toBe(GETIG_EXPLANATION_RELATIONS.length);
    expect(GETIG_EXPLANATION_NODE_KINDS).toContain("unknown");
  });

  it("only emits relations and roles from the closed vocabularies", () => {
    const g = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
    for (const edge of g.edges) {
      expect(GETIG_EXPLANATION_RELATIONS).toContain(edge.relation);
      expect(GETIG_EXPLANATION_ROLES).toContain(edge.role);
    }
    for (const node of g.nodes) expect(GETIG_EXPLANATION_NODE_KINDS).toContain(node.kind);
  });
});

// ── integration ──────────────────────────────────────────────────────────────

describe("28F — integration with real 28A frames", () => {
  function frame28a(frameId: string, entities: GetigFrameInput["entities"]) {
    const decision = buildGetigFrame({ frameId, observer, epochId: EPOCH, asOfEpochMs: NOW, sourceProjectionHash: hex("1"), entities } as GetigFrameInput);
    if (!decision.ok) throw new Error(`28A refused: ${decision.refusal}`);
    return decision.frame;
  }

  it("explains a real 28A frame's entity end to end", () => {
    const f = frame28a("frame-real", [ent("n1", { provenanceRefs: [prov("ref-1")] })]);
    const decision = buildGetigExplanationGraph({ graphId: "g", frame: f, provenanceRecords: [prov("ref-1")] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.graph.frameId).toBe("frame-real");
    expect(decision.graph.observerId).toBe(OBSERVER);
    const trace = explainGetigSubject(decision.graph, "n1");
    expect(trace.ok).toBe(true);
  });

  it("records a real 28A entity with no provenance as unknown", () => {
    const f = frame28a("frame-real", [ent("bare")]);
    const decision = buildGetigExplanationGraph({ graphId: "g", frame: f });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.graph.unknownProvenanceSubjects).toEqual(["bare"]);
  });

  it("still refuses to grant trust after explaining a real frame", () => {
    const f = frame28a("frame-real", [ent("n1", { provenanceRefs: [prov("ref-1")] })]);
    const g = buildGetigExplanationGraph({ graphId: "g", frame: f, provenanceRecords: [prov("ref-1")] });
    expect(g.ok).toBe(true);
    if (!g.ok) return;
    traced(g.graph, "n1");
    expect(refuseProvenanceAsTrust("ref-1", "authorise a route").ok).toBe(false);
  });
});