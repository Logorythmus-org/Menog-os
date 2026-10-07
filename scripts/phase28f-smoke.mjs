/**
 * PHASE 28F — out-of-suite smoke check against the BUILT artefact.
 *
 * Development probe, not a gate test. Two earlier gates shipped real defects
 * that a suite alone did not catch (28D's dead partition token, 28E's hidden
 * lifecycle difference), so every Phase-28 gate is probed against `dist/`
 * independently of its suite.
 */
import {
  buildGetigExplanationGraph,
  explainGetigSubject,
  refuseProvenanceAsTrust,
  GETIG_GRAPH_REFUSAL_CODES,
  GETIG_FORBIDDEN_CONTENT_FIELDS,
  GETIG_GRAPH_BOUNDS,
  GETIG_EXPLANATION_NODE_KINDS,
} from "../packages/durable-state/dist/index.js";

let failures = 0;
const check = (name, ok, observed) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${observed}`);
};

const hex = (d) => String(d).repeat(64);
const EPOCH = "epoch-28f";
const OBSERVER = "observer-local-1";
const observer = { observerId: OBSERVER, observerKind: "local_runtime", epochId: EPOCH, isGlobalTruth: false };

const prov = (refId) => ({
  refId,
  recordedAtEpochMs: 1_700_000_000_000,
  sourceKind: "governed_evidence",
  evidenceId: `ev-${refId}`,
  confersTrust: false,
});

const ent = (visibleId, over = {}) => ({
  visibleId, kind: "runtime_node", label: `l-${visibleId}`, isRuntimeObject: false, grant: "none",
  freshness: "current", lifecycle: "observed", provenanceRefs: [], representsRuntimeId: null, ...over,
});

const frameOf = (over = {}) => ({
  schemaVersion: "menog-getig/v0", frameId: "frame-a", observer, epochId: EPOCH,
  asOfEpochMs: 1_700_000_000_000, sourceProjectionHash: hex("a"), canonicalVisibleHash: hex("b"),
  entities: [], relations: [], events: [], conflicts: [], refusals: [], routes: [], proposalFlows: [],
  authority: "none", controlPlane: "none", readOnly: true, replaySemantics: "visual_only_not_executable",
  globalTruth: false, visibleCapabilities: [], ...over,
});

const graph = (frameOver = {}, records = []) =>
  buildGetigExplanationGraph({ graphId: "graph-1", frame: frameOf(frameOver), provenanceRecords: records });

const built = (frameOver = {}, records = []) => {
  const d = graph(frameOver, records);
  if (!d.ok) throw new Error(`expected a built graph, got ${d.refusal}: ${d.explanation}`);
  return d.graph;
};

// ── the graph answers "why am I seeing this" ────────────────────────────────
const g1 = built({ entities: [ent("n1", { provenanceRefs: [prov("ref-1")] })] }, [prov("ref-1")]);
check("graph builds", g1.nodeCount > 0, `${g1.nodeCount} nodes, ${g1.edgeCount} edges`);

const trace = explainGetigSubject(g1, "n1");
check("a subject can be explained", trace.ok, trace.ok ? `${trace.trace.hopCount} hops` : trace.explanation);
if (trace.ok) {
  const kinds = new Set(trace.trace.hops.map((h) => h.kind));
  check("the trace reaches observer, frame and provenance",
    kinds.has("observer") && kinds.has("frame") && kinds.has("provenance_ref"),
    [...kinds].join(","));
  check("the trace reaches lifecycle and freshness facts",
    kinds.has("lifecycle_fact") && kinds.has("freshness_fact"), [...kinds].join(","));
  check("graph denies authorization", g1.explainsWhy === true && g1.authorizes === false && g1.authority === "none");
  check("every node is metadata, not content",
    g1.nodes.every((n) => n.isEvidenceContent === false && n.confersTrust === false && n.confersAuthority === false));
  check("every edge confers nothing",
    g1.edges.every((e) => e.confersTrust === false && e.confersAuthority === false));
}

// ── missing provenance is EXPLICIT, never fabricated ─────────────────────────
const g2 = built({ entities: [ent("noRefs")] });
check("a subject with no provenance gets an explicit unknown", g2.unknownProvenanceSubjects.includes("noRefs"),
  JSON.stringify(g2.unknownProvenanceSubjects));
check("and is counted", g2.missingProvenanceCount === 1, String(g2.missingProvenanceCount));
check("a described reference resolves to a provenance_ref, not an unknown",
  g1.nodes.some((n) => n.kind === "provenance_ref") && g1.unknownProvenanceSubjects.length === 0,
  JSON.stringify(g1.unknownProvenanceSubjects));
const t2 = explainGetigSubject(g2, "noRefs");
check("the trace shows the unknown rather than inventing a ref",
  t2.ok && t2.trace.hops.some((h) => h.kind === "unknown" && h.relation === "provenance_missing"),
  t2.ok ? JSON.stringify(t2.trace.hops.map((h) => `${h.relation}:${h.kind}`)) : t2.refusal);
check("no fabricated refId appears in the graph", !JSON.stringify(g2.nodes).includes("provenance:undefined"),
  "no undefined ref");

// a CITED ref nobody describes is also unknown
const g3 = built({ entities: [ent("cited", { provenanceRefs: [{ refId: "ref-ghost", recordedAtEpochMs: 1, sourceKind: "governed_evidence", evidenceId: null, confersTrust: false }] })] }, []);
check("a cited reference nobody describes is an unknown, not a blank",
  g3.unknownProvenanceSubjects.includes("cited"), JSON.stringify(g3.unknownProvenanceSubjects));

// ── raw content / secrets are REFUSED, not sanitised ────────────────────────
const secret = graph({ entities: [] }, [{ ...prov("ref-1"), secret: "hunter2" }]);
check("a record carrying a secret is refused", !secret.ok && secret.refusal === "refused_graph_provenance_content_present",
  secret.ok ? "BUILT (wrong)" : secret.refusal);
check("and exposes no partial graph", !secret.ok && secret.graph === null, secret.ok ? "graph present" : "null");
for (const field of ["raw_text", "privateKey", "toolOutput", "policyText", "storeContent", "payload", "filePath"]) {
  const attempt = graph({ entities: [] }, [{ ...prov("ref-1"), [field]: "x" }]);
  check(`field "${field}" is caught`, !attempt.ok && attempt.refusal === "refused_graph_provenance_content_present",
    attempt.ok ? "BUILT (wrong)" : attempt.refusal);
}
check("the forbidden-field scan matches a normalised name", GETIG_FORBIDDEN_CONTENT_FIELDS.includes("rawtext"),
  "rawText normalises to rawtext");

// ── role substitution fails closed ───────────────────────────────────────────
const routeFrame = (forwarders) => ({
  routes: [{
    routeId: "rt1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: forwarders,
    destinationVisibleId: "n3", freshness: "current", provenanceRefs: [], admission: "none",
    authorization: "none", executionAuthorized: false,
  }],
});
const legit = built(routeFrame(["n2"]));
check("a legitimate forwarder builds", legit.nodeCount > 0, `${legit.nodeCount} nodes`);
const roleEdges = legit.edges.filter((e) => e.relation === "has_role");
check("origin, forwarder and destination each carry their own role",
  roleEdges.map((e) => e.role).sort().join(",") === "destination,forwarder,origin",
  roleEdges.map((e) => e.role).join(","));
check("no forwarder edge is labelled origin",
  roleEdges.filter((e) => e.toNodeId.includes("#forwarder") || e.role === "forwarder").every((e) => e.role === "forwarder"),
  "forwarder edges carry role=forwarder");

const substituted = graph(routeFrame(["n1"]));
check("a route listing its own origin as a forwarder is REFUSED",
  !substituted.ok && substituted.refusal === "refused_graph_role_substitution",
  substituted.ok ? "BUILT (wrong)" : substituted.refusal);

// ── conflict attribution ────────────────────────────────────────────────────
const withConflict = built({
  conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: OBSERVER, subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
});
check("a conflict carries its attribution node",
  withConflict.nodes.some((n) => n.kind === "conflict_attribution"),
  withConflict.nodes.filter((n) => n.kind === "conflict_attribution").map((n) => n.label).join(","));
check("a conflict with no provenance is still explicit",
  withConflict.unknownProvenanceSubjects.includes("c1"), JSON.stringify(withConflict.unknownProvenanceSubjects));

// ── cycle safety: a genuinely cyclic graph must terminate ───────────────────
const cyclic = {
  graphId: "cyclic", frameId: "f", observerId: OBSERVER, epochId: EPOCH,
  nodes: [{ nodeId: "entities:a", kind: "subject", label: "a" }, { nodeId: "entities:b", kind: "subject", label: "b" }],
  edges: [
    { edgeId: "e1", fromNodeId: "entities:a", toNodeId: "entities:b", relation: "observed_by", role: "none" },
    { edgeId: "e2", fromNodeId: "entities:b", toNodeId: "entities:a", relation: "observed_by", role: "none" },
    { edgeId: "e3", fromNodeId: "entities:a", toNodeId: "entities:a", relation: "projected_in", role: "none" },
  ],
};
const started = Date.now();
const cyc = explainGetigSubject(cyclic, "a");
const elapsed = Date.now() - started;
check("a cyclic graph terminates with a bounded trace",
  cyc.ok && cyc.trace.hopCount <= GETIG_GRAPH_BOUNDS.maxExplainNodes && elapsed < 2000,
  cyc.ok ? `${cyc.trace.hopCount} hops in ${elapsed}ms` : cyc.refusal);
check("and reports that a cycle was broken rather than pretending otherwise",
  cyc.ok && cyc.trace.cycleBroken === true, cyc.ok ? String(cyc.trace.cycleBroken) : "n/a");

// a self-loop storm must also terminate
const storm = {
  nodes: [{ nodeId: "entities:a", kind: "subject", label: "a" }],
  edges: Array.from({ length: 5_000 }, (_, i) => ({
    edgeId: `e${i}`, fromNodeId: "entities:a", toNodeId: `entities:a`, relation: "projected_in", role: "none",
  })),
};
const stormResult = explainGetigSubject(storm, "a");
// Termination alone is not the claim: the hop budget must hold *within* a single
// expansion. One node here carries 5000 outgoing edges against a budget of 128, so
// a bound checked only between queue items would report 5000 hops and still pass.
check("a 5000-edge self-loop storm still terminates", stormResult.ok, stormResult.ok ? `${stormResult.trace.hopCount} hops` : stormResult.refusal);
check("and the storm stays inside the hop budget rather than merely terminating",
  stormResult.ok
    && stormResult.trace.hopCount <= GETIG_GRAPH_BOUNDS.maxExplainNodes
    && stormResult.trace.boundedStop === true,
  stormResult.ok ? `${stormResult.trace.hopCount}/${GETIG_GRAPH_BOUNDS.maxExplainNodes} hops, boundedStop=${stormResult.trace.boundedStop}` : stormResult.refusal);

// The same subject addressed two ways must produce one identical trace: the graph
// key is internal and must not leak into the answer.
const bareTrace = explainGetigSubject(g1, "n1");
const keyedTrace = explainGetigSubject(g1, "entities:n1");
check("a bare and a collection-qualified subject id yield one identical trace",
  bareTrace.ok && keyedTrace.ok
    && JSON.stringify(bareTrace.trace) === JSON.stringify(keyedTrace.trace),
  bareTrace.ok && keyedTrace.ok ? `${keyedTrace.trace.subjectVisibleId} / ${keyedTrace.trace.questionAnswered}` : "n/a");

// ── refusals ────────────────────────────────────────────────────────────────
const refusals = [];
const notAGraph = explainGetigSubject(null, "a");
refusals.push(["not a graph", notAGraph]);
const noSubject = explainGetigSubject(g1, "does-not-exist");
refusals.push(["subject unknown", noSubject]);
const badGraph = buildGetigExplanationGraph({ graphId: "g", frame: null });
refusals.push(["frame invalid", badGraph]);
const badRecordRes = buildGetigExplanationGraph({ graphId: "g", frame: frameOf(), provenanceRecords: [{}] });
refusals.push(["record invalid", badRecordRes]);
const dupRecord = buildGetigExplanationGraph({ graphId: "g", frame: frameOf(), provenanceRecords: [prov("r"), prov("r")] });
refusals.push(["duplicate record", dupRecord]);
refusals.push(["role substitution", substituted]);
refusals.push(["content present", secret]);
const bigFrame = frameOf({ entities: Array.from({ length: 2_000 }, (_, i) => ent(`n${i}`)) });
const bounds = buildGetigExplanationGraph({ graphId: "g", frame: bigFrame });
refusals.push(["bounds", bounds]);
const trust = refuseProvenanceAsTrust("ref-1");
refusals.push(["trust", trust]);

const produced = new Set(refusals.filter(([, d]) => d.ok === false).map(([, d]) => d.refusal));
const missing = [...GETIG_GRAPH_REFUSAL_CODES].filter((c) => !produced.has(c));
check("every declared refusal code is reachable", missing.length === 0,
  missing.length === 0 ? `all ${GETIG_GRAPH_REFUSAL_CODES.length} produced` : `unreachable: ${missing.join(", ")}`);

check("provenance never grants trust, authority or execution",
  trust.refusal === "refused_trust_not_granted" && trust.confersTrust === false
  && trust.confersAuthority === false && trust.authorizesExecution === false, trust.refusal);
check("node kinds are closed and include unknown", GETIG_EXPLANATION_NODE_KINDS.includes("unknown"),
  GETIG_EXPLANATION_NODE_KINDS.join(","));

console.log(`\n28F smoke: ${failures === 0 ? "ALL PASS" : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);