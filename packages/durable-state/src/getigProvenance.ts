/**
 * PHASE 28F — PROVENANCE & EXPLANATION GRAPH
 * (TRACEABILITY / READ-ONLY / BOUNDED / CYCLE-SAFE / ZERO-AUTHORITY)
 *
 * Every visible object should be able to answer one question: WHY AM I SEEING
 * THIS? This module builds the graph that answers it — linking visible
 * objects to the observer, the frame they were projected in, their provenance
 * references, their route roles, their lifecycle and freshness facts, and the
 * observer any conflict is attributed to.
 *
 * ── WHAT A PROVENANCE REFERENCE IS NOT ──────────────────────────────────────
 *
 * A 28A `VisibleProvenanceRef` is METADATA about an evidence record. The
 * record itself is never inlined, and this module never asks for it. Every
 * node and edge carries `isEvidenceContent: false` and `confersTrust: false`,
 * and — importantly — there is simply no field in which evidence content could
 * be placed. A suite audit reads the emitted declarations and fails if any
 * field name suggests a blob, body, payload, raw text, secret, key or path.
 *
 * A caller that tries to smuggle one in is REFUSED, not sanitised: the graph
 * refuses on `refused_graph_provenance_content_present` and produces nothing.
 * Silently dropping a secret would leave the caller believing it was recorded.
 *
 * ── EXPLANATION IS NOT AUTHORIZATION ────────────────────────────────────────
 *
 * Knowing WHY something is visible tells you nothing about whether you may act
 * on it. Every node and edge carries `confersAuthority: false`, the graph
 * carries `authorizes: false`, and `refuseProvenanceAsTrust()` is the only
 * trust-adjacent export — it cannot succeed under any input.
 *
 * ── FORWARDER IS NOT ORIGIN ─────────────────────────────────────────────────
 *
 * Route roles are carried as an explicit `role` on every edge, and a route
 * whose forwarder list contains its own origin is REFUSED as role substitution.
 * That is the concrete fail-closed check: the one way this graph could promote
 * a forwarder into an origin is to let a frame assert the promotion itself.
 *
 * ── MISSING PROVENANCE IS EXPLICIT, NEVER FABRICATED ────────────────────────
 *
 * A visible subject with no provenance reference gets an explicit `unknown`
 * node and a `provenance_missing` edge, is counted in `missingProvenanceCount`,
 * and is listed in `unknownProvenanceSubjects`. It does not get a plausible
 * reference, an empty string, or a silent omission. "We do not know why this is
 * visible" is an answer; "here is a refId we made up" is a lie.
 *
 * ── CYCLE-SAFETY IS ENFORCED, NOT ASSUMED ───────────────────────────────────
 *
 * `explainGetigSubject()` walks the graph breadth-first with an explicit visited
 * set and hard caps on depth and node count. A graph that referred back to
 * itself — which a hand-built or corrupted one could — terminates instead of
 * hanging. The suite plants a genuinely cyclic graph and asserts it terminates
 * with a bounded trace.
 */

import { canonicalHash } from "./canonical.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

export const GETIG_EXPLANATION_NODE_KINDS = Object.freeze([
  "subject",
  "observer",
  "frame",
  "provenance_ref",
  "route_role",
  "lifecycle_fact",
  "freshness_fact",
  "conflict_attribution",
  "unknown",
] as const);
export type GetigExplanationNodeKind = (typeof GETIG_EXPLANATION_NODE_KINDS)[number];

export const GETIG_EXPLANATION_RELATIONS = Object.freeze([
  "observed_by",
  "projected_in",
  "has_provenance_ref",
  "provenance_missing",
  "has_role",
  "attributed_to",
  "has_lifecycle_fact",
  "has_freshness_fact",
] as const);
export type GetigExplanationRelation = (typeof GETIG_EXPLANATION_RELATIONS)[number];

/** Roles are carried explicitly and never merged. */
export const GETIG_EXPLANATION_ROLES = Object.freeze(["none", "origin", "forwarder", "destination"] as const);
export type GetigExplanationRole = (typeof GETIG_EXPLANATION_ROLES)[number];

/**
 * Field names that would carry evidence CONTENT rather than metadata about it.
 * A record carrying any of these is refused outright.
 */
export const GETIG_FORBIDDEN_CONTENT_FIELDS = Object.freeze([
  "content", "raw", "rawtext", "text", "body", "payload", "prompt", "tooloutput",
  "secret", "privatekey", "apikey", "token", "password", "credential", "path",
  "filepath", "privatepath", "policytext", "memorycontent", "storecontent", "blob", "data",
] as const);

export const GETIG_GRAPH_REFUSAL_CODES = Object.freeze([
  "refused_graph_frame_invalid",
  "refused_graph_provenance_record_invalid",
  "refused_graph_provenance_content_present",
  "refused_graph_role_substitution",
  "refused_graph_bounds_exceeded",
  "refused_explain_not_a_graph",
  "refused_explain_subject_unknown",
  "refused_trust_not_granted",
] as const);
export type GetigGraphRefusalCode = (typeof GETIG_GRAPH_REFUSAL_CODES)[number];

export const GETIG_GRAPH_BOUNDS = Object.freeze({
  maxNodes: 4_096,
  maxEdges: 8_192,
  maxExplainDepth: 8,
  maxExplainNodes: 128,
  maxIdChars: 128,
});

export const GETIG_GRAPH_SCHEMA_VERSION = "menog-getig-explain/v0" as const;

// ── the shapes ───────────────────────────────────────────────────────────────

/**
 * One node in the explanation graph.
 *
 * Note what is NOT here: any field able to hold evidence content. A node is a
 * name, a kind, and a promise that it confers nothing.
 */
export interface ExplanationNode {
  readonly nodeId: string;
  readonly kind: GetigExplanationNodeKind;
  readonly label: string;
  /** Structural: PROVENANCE METADATA != EVIDENCE CONTENT. */
  readonly isEvidenceContent: false;
  /** Structural: an evidence link is not trust. */
  readonly confersTrust: false;
  /** Structural: an explanation is not authorization. */
  readonly confersAuthority: false;
  readonly authority: "none";
}

export interface ExplanationEdge {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly relation: GetigExplanationRelation;
  /** `none` for every relation that is not a route role. */
  readonly role: GetigExplanationRole;
  readonly confersTrust: false;
  readonly confersAuthority: false;
}

export interface GetigExplanationGraph {
  readonly schemaVersion: typeof GETIG_GRAPH_SCHEMA_VERSION;
  readonly graphId: string;
  readonly frameId: string;
  readonly observerId: string;
  readonly epochId: string;
  readonly nodes: readonly ExplanationNode[];
  readonly edges: readonly ExplanationEdge[];
  readonly nodeCount: number;
  readonly edgeCount: number;
  /** Subjects visible with no provenance reference at all. Never fabricated. */
  readonly unknownProvenanceSubjects: readonly string[];
  readonly missingProvenanceCount: number;
  readonly graphHash: string;
  /** Structural: the graph answers WHY, and never authorises anything. */
  readonly explainsWhy: true;
  readonly authorizes: false;
  readonly cycleSafe: true;
  readonly bounded: true;
  readonly readOnly: true;
  readonly authority: "none";
}

export interface ExplanationHop {
  readonly nodeId: string;
  readonly kind: GetigExplanationNodeKind;
  readonly relation: GetigExplanationRelation;
  readonly role: GetigExplanationRole;
  readonly depth: number;
}

export interface SubjectExplanation {
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  readonly hops: readonly ExplanationHop[];
  readonly hopCount: number;
  readonly maxDepthReached: number;
  /** True when traversal stopped at a bound rather than exhausting the graph. */
  readonly boundedStop: boolean;
  readonly cycleBroken: boolean;
  readonly questionAnswered: string;
}

// ── decisions ────────────────────────────────────────────────────────────────

export type GraphBuilt = { readonly ok: true; readonly code: "explanation_graph_built"; readonly graph: GetigExplanationGraph };
export type GraphRefused = {
  readonly ok: false;
  readonly code: "explanation_graph_refused";
  readonly refusal: GetigGraphRefusalCode;
  readonly explanation: string;
  readonly graph: null;
};
export type GraphDecision = GraphBuilt | GraphRefused;

export type ExplainBuilt = { readonly ok: true; readonly code: "subject_explained"; readonly trace: SubjectExplanation };
export type ExplainRefused = {
  readonly ok: false;
  readonly code: "subject_explanation_refused";
  readonly refusal: GetigGraphRefusalCode;
  readonly explanation: string;
  readonly trace: null;
};
export type ExplainDecision = ExplainBuilt | ExplainRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= GETIG_GRAPH_BOUNDS.maxIdChars;
}

/** Code-unit comparison, never `localeCompare`: a locale-dependent ordering
 *  would make `graphHash` machine-dependent. */
function byKey<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

/** Case- and separator-insensitive, so `raw_text` cannot smuggle past `rawText`. */
function normaliseField(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// ── the ONE graph builder ────────────────────────────────────────────────────

/**
 * Build the explanation graph for one 28A frame.
 *
 * `provenanceRecords` supplies the metadata for evidence references the frame
 * cites. A reference the frame cites but no record describes is NOT invented:
 * it becomes an explicit `unknown` node, which is the honest answer and the one
 * the prompt demands.
 */
export function buildGetigExplanationGraph(input: {
  readonly graphId: string;
  readonly frame: unknown;
  readonly provenanceRecords?: readonly unknown[];
}): GraphDecision {
  const refuse = (refusal: GetigGraphRefusalCode, detail: string): GraphRefused => ({
    ok: false,
    code: "explanation_graph_refused",
    refusal,
    explanation: `the graph was refused and no partial graph was produced: ${detail}`,
    graph: null,
  });

  if (!isRecord(input)) return refuse("refused_graph_frame_invalid", "the builder input must be an object");
  if (!isId(input.graphId)) return refuse("refused_graph_frame_invalid", "graphId is missing or over-long");
  const frame = input.frame;
  if (!isRecord(frame)) return refuse("refused_graph_frame_invalid", "the frame must be an object");
  if (!isId(frame.frameId)) return refuse("refused_graph_frame_invalid", "frame.frameId is required");
  if (!isRecord(frame.observer) || !isId(frame.observer.observerId)) {
    return refuse("refused_graph_frame_invalid", "frame.observer.observerId is required");
  }
  if (!isId(frame.epochId)) return refuse("refused_graph_frame_invalid", "frame.epochId is required");

  // ── provenance records: metadata only, and never evidence content ─────────
  const records = new Map<string, Record<string, unknown>>();
  const supplied = input.provenanceRecords ?? [];
  if (!Array.isArray(supplied)) return refuse("refused_graph_provenance_record_invalid", "provenanceRecords must be an array");
  for (const raw of supplied) {
    if (!isRecord(raw)) return refuse("refused_graph_provenance_record_invalid", "a provenance record is not an object");
    // Refuse rather than sanitise: dropping a secret would leave the caller
    // believing it had been recorded.
    const offending = Object.keys(raw).find((k) => (GETIG_FORBIDDEN_CONTENT_FIELDS as readonly string[]).includes(normaliseField(k)));
    if (offending !== undefined) {
      return refuse("refused_graph_provenance_content_present", `record carries "${offending}", which would place evidence CONTENT in a metadata field`);
    }
    if (!isId(raw.refId)) return refuse("refused_graph_provenance_record_invalid", "a provenance record has no usable refId");
    if (records.has(raw.refId)) return refuse("refused_graph_provenance_record_invalid", `refId "${raw.refId}" is supplied twice`);
    records.set(raw.refId, raw);
  }

  const nodes = new Map<string, ExplanationNode>();
  const edges: ExplanationEdge[] = [];

  const addNode = (nodeId: string, kind: GetigExplanationNodeKind, label: string): void => {
    if (nodes.has(nodeId)) return;
    nodes.set(
      nodeId,
      Object.freeze({
        nodeId,
        kind,
        label,
        isEvidenceContent: false,
        confersTrust: false,
        confersAuthority: false,
        authority: "none" as const,
      }),
    );
  };

  const addEdge = (
    fromNodeId: string,
    toNodeId: string,
    relation: GetigExplanationRelation,
    role: GetigExplanationRole = "none",
  ): void => {
    edges.push(
      Object.freeze({
        edgeId: `${fromNodeId}|${relation}|${toNodeId}`,
        fromNodeId,
        toNodeId,
        relation,
        role,
        confersTrust: false,
        confersAuthority: false,
      }),
    );
  };

  // The observer and the frame every subject hangs from.
  const observerNodeId = `observer:${frame.observer.observerId}`;
  const frameNodeId = `frame:${frame.frameId}`;
  addNode(observerNodeId, "observer", frame.observer.observerId);
  addNode(frameNodeId, "frame", frame.frameId);

  const unknownProvenanceSubjects: string[] = [];

  const attach = (collection: string, subjectVisibleId: string, refs: readonly string[]): void => {
    const subjectNodeId = `${collection}:${subjectVisibleId}`;
    addNode(subjectNodeId, "subject", subjectVisibleId);
    addEdge(subjectNodeId, observerNodeId, "observed_by");
    addEdge(subjectNodeId, frameNodeId, "projected_in");

    if (refs.length === 0) {
      // Explicit unknown. Never fabricated, never an empty string, never omitted.
      const unknownNodeId = `unknown:${subjectNodeId}`;
      addNode(unknownNodeId, "unknown", "provenance unknown");
      addEdge(subjectNodeId, unknownNodeId, "provenance_missing");
      unknownProvenanceSubjects.push(subjectVisibleId);
      return;
    }
    for (const refId of refs) {
      const record = records.get(refId);
      const refNodeId = `provenance:${refId}`;
      // A cited reference nobody describes is an unknown, not a blank.
      addNode(refNodeId, record ? "provenance_ref" : "unknown", refId);
      addEdge(subjectNodeId, refNodeId, "has_provenance_ref");
      if (!record) unknownProvenanceSubjects.push(subjectVisibleId);
    }
  };

  const refsOf = (item: Record<string, unknown>): readonly string[] => {
    const refs = item.provenanceRefs;
    if (!Array.isArray(refs)) return [];
    const out: string[] = [];
    for (const r of refs) {
      if (!isRecord(r)) continue;
      if (isId(r.refId)) out.push(r.refId);
    }
    return byKey(out, (id) => id);
  };

  const itemsOf = (key: string): readonly Record<string, unknown>[] => {
    const raw = frame[key];
    if (!Array.isArray(raw)) return [];
    return raw.filter(isRecord);
  };

  for (const e of itemsOf("entities")) {
    if (!isId(e.visibleId)) return refuse("refused_explain_subject_unknown", "an entity has no usable visibleId");
    attach("entities", e.visibleId, refsOf(e));
    const lifecycle = typeof e.lifecycle === "string" ? e.lifecycle : "unknown";
    const freshness = typeof e.freshness === "string" ? e.freshness : "unknown";
    const lifeNode = `fact:${e.visibleId}:lifecycle:${lifecycle}`;
    const freshNode = `fact:${e.visibleId}:freshness:${freshness}`;
    addNode(lifeNode, "lifecycle_fact", `lifecycle=${lifecycle}`);
    addNode(freshNode, "freshness_fact", `freshness=${freshness}`);
    addEdge(`entities:${e.visibleId}`, lifeNode, "has_lifecycle_fact");
    addEdge(`entities:${e.visibleId}`, freshNode, "has_freshness_fact");
  }

  for (const r of itemsOf("relations")) {
    if (!isId(r.relationId)) return refuse("refused_explain_subject_unknown", "a relation has no usable relationId");
    attach("relations", r.relationId, refsOf(r));
  }

  for (const ev of itemsOf("events")) {
    if (!isId(ev.eventId)) return refuse("refused_explain_subject_unknown", "an event has no usable eventId");
    attach("events", ev.eventId, refsOf(ev));
  }

  for (const rt of itemsOf("routes")) {
    if (!isId(rt.routeId)) return refuse("refused_explain_subject_unknown", "a route has no usable routeId");
    const origin = rt.originVisibleId;
    if (!isId(origin)) return refuse("refused_explain_subject_unknown", `route ${rt.routeId} has no usable originVisibleId`);
    const destination = rt.destinationVisibleId;
    if (!isId(destination)) return refuse("refused_explain_subject_unknown", `route ${rt.routeId} has no usable destinationVisibleId`);
    const forwarders = Array.isArray(rt.forwarderVisibleIds) ? rt.forwarderVisibleIds.filter(isId) : [];

    // ROLE SUBSTITUTION FAILS CLOSED. A forwarder list containing the origin is
    // the one shape that would promote a forwarder into an origin, and it is
    // refused rather than normalised.
    if (forwarders.includes(origin)) {
      return refuse("refused_graph_role_substitution", `route ${rt.routeId} lists its own origin "${origin}" as a forwarder`);
    }

    attach("routes", rt.routeId, refsOf(rt));

    for (const [role, id] of [["origin", origin], ["destination", destination]] as const) {
      const nodeId = `role:${rt.routeId}:${role}:${id}`;
      addNode(nodeId, "route_role", `${role}=${id}`);
      addEdge(`routes:${rt.routeId}`, nodeId, "has_role", role);
    }
    for (const f of byKey(forwarders, (x) => x)) {
      const nodeId = `role:${rt.routeId}:forwarder:${f}`;
      addNode(nodeId, "route_role", `forwarder=${f}`);
      addEdge(`routes:${rt.routeId}`, nodeId, "has_role", "forwarder");
    }
  }

  for (const c of itemsOf("conflicts")) {
    if (!isId(c.conflictId)) return refuse("refused_explain_subject_unknown", "a conflict has no usable conflictId");
    attach("conflicts", c.conflictId, refsOf(c));
    // Conflict attribution: WHO reported this view.
    const attributed = c.attributedToObserverId;
    if (isId(attributed)) {
      const attrNode = `attribution:${c.conflictId}:${attributed}`;
      addNode(attrNode, "conflict_attribution", attributed);
      addEdge(`conflicts:${c.conflictId}`, attrNode, "attributed_to");
    }
  }

  for (const rf of itemsOf("refusals")) {
    if (!isId(rf.refusalId)) return refuse("refused_explain_subject_unknown", "a refusal has no usable refusalId");
    attach("refusals", rf.refusalId, refsOf(rf));
  }

  if (nodes.size > GETIG_GRAPH_BOUNDS.maxNodes) {
    return refuse("refused_graph_bounds_exceeded", `${nodes.size} nodes exceeds the bound of ${GETIG_GRAPH_BOUNDS.maxNodes}`);
  }
  if (edges.length > GETIG_GRAPH_BOUNDS.maxEdges) {
    return refuse("refused_graph_bounds_exceeded", `${edges.length} edges exceeds the bound of ${GETIG_GRAPH_BOUNDS.maxEdges}`);
  }

  const orderedNodes = byKey([...nodes.values()], (n) => n.nodeId);
  const orderedEdges = byKey(edges, (e) => e.edgeId);
  const identity = {
    graphId: input.graphId,
    frameId: frame.frameId,
    observerId: frame.observer.observerId,
    epochId: frame.epochId,
  };

  return {
    ok: true,
    code: "explanation_graph_built",
    graph: Object.freeze({
      schemaVersion: GETIG_GRAPH_SCHEMA_VERSION,
      ...identity,
      nodes: Object.freeze(orderedNodes),
      edges: Object.freeze(orderedEdges),
      nodeCount: orderedNodes.length,
      edgeCount: orderedEdges.length,
      unknownProvenanceSubjects: Object.freeze(byKey([...new Set(unknownProvenanceSubjects)], (s) => s)),
      missingProvenanceCount: new Set(unknownProvenanceSubjects).size,
      graphHash: canonicalHash({
        schemaVersion: GETIG_GRAPH_SCHEMA_VERSION,
        ...identity,
        nodes: orderedNodes.map((n) => n.nodeId),
        edges: orderedEdges.map((e) => e.edgeId),
      }),
      explainsWhy: true,
      authorizes: false,
      cycleSafe: true,
      bounded: true,
      readOnly: true,
      authority: "none" as const,
    }),
  };
}

// ── the ONE explainer ────────────────────────────────────────────────────────

/**
 * Answer "why am I seeing this?" for one subject.
 *
 * Breadth-first, with an explicit visited set and hard caps on depth and node
 * count. A graph that referred back to itself terminates with a bounded trace
 * instead of hanging — which is the property `cycleSafe: true` is claiming, and
 * it is tested against a genuinely cyclic graph rather than asserted.
 */
export function explainGetigSubject(graph: unknown, subjectVisibleId: string): ExplainDecision {
  const refuse = (refusal: GetigGraphRefusalCode, detail: string): ExplainRefused => ({
    ok: false,
    code: "subject_explanation_refused",
    refusal,
    explanation: `the explanation was refused and no partial trace was produced: ${detail}`,
    trace: null,
  });

  if (!isRecord(graph) || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    return refuse("refused_explain_not_a_graph", "the graph must be a built explanation graph");
  }
  if (!isId(subjectVisibleId)) return refuse("refused_explain_subject_unknown", "subjectVisibleId is missing or over-long");

  const nodes = new Map<string, Record<string, unknown>>();
  for (const n of graph.nodes) {
    if (!isRecord(n) || !isId(n.nodeId)) continue;
    nodes.set(n.nodeId, n);
  }

  // Accept `entities:n1` or a bare `n1`; the graph is keyed by collection.
  let startId: string | undefined;
  if (nodes.has(`${subjectVisibleId}`)) startId = subjectVisibleId;
  if (!startId) {
    for (const key of byKey([...nodes.keys()], (k) => k)) {
      const bare = key.slice(key.indexOf(":") + 1);
      if (bare === subjectVisibleId && nodes.get(key)!.kind === "subject") {
        startId = key;
        break;
      }
    }
  }
  if (!startId) return refuse("refused_explain_subject_unknown", `no subject "${subjectVisibleId}" is in this graph`);

  // The answer is about a VISIBLE OBJECT, so the trace speaks the visible-world
  // id rather than the internal graph key. `entities:n1` and `n1` name one
  // subject and must produce one identical trace — canonical visible content
  // (law 11) forbids the answer depending on how the caller spelled the query.
  const colon = startId.indexOf(":");
  const canonicalSubjectId = colon === -1 ? startId : startId.slice(colon + 1);
  const collection = colon === -1 ? "unqualified" : startId.slice(0, colon);

  const outgoing = new Map<string, Record<string, unknown>[]>();
  for (const e of graph.edges) {
    if (!isRecord(e) || !isId(e.fromNodeId) || !isId(e.toNodeId)) continue;
    const list = outgoing.get(e.fromNodeId) ?? [];
    list.push(e);
    outgoing.set(e.fromNodeId, list);
  }

  const hops: ExplanationHop[] = [];
  const visited = new Set<string>([startId]);
  const queue: { nodeId: string; depth: number }[] = [{ nodeId: startId, depth: 0 }];
  let cycleBroken = false;
  let boundedStop = false;
  let maxDepthReached = 0;

  while (queue.length > 0) {
    if (hops.length >= GETIG_GRAPH_BOUNDS.maxExplainNodes) {
      boundedStop = true;
      break;
    }
    const { nodeId, depth } = queue.shift()!;
    if (depth >= GETIG_GRAPH_BOUNDS.maxExplainDepth) {
      boundedStop = true;
      continue;
    }
    if (depth > maxDepthReached) maxDepthReached = depth;
    for (const e of byKey(outgoing.get(nodeId) ?? [], (x) => String(x.edgeId))) {
      // The cap must hold per expansion, not only between queue items: a single
      // node may carry more outgoing edges than the entire hop budget.
      if (hops.length >= GETIG_GRAPH_BOUNDS.maxExplainNodes) {
        boundedStop = true;
        break;
      }
      const target = String(e.toNodeId);
      hops.push(
        Object.freeze({
          nodeId: target,
          kind: (nodes.get(target)?.kind ?? "unknown") as GetigExplanationNodeKind,
          relation: e.relation as GetigExplanationRelation,
          role: e.role as GetigExplanationRole,
          depth: depth + 1,
        }),
      );
      if (visited.has(target)) {
        // The edge is recorded; the node is not re-expanded.
        cycleBroken = true;
        continue;
      }
      visited.add(target);
      queue.push({ nodeId: target, depth: depth + 1 });
    }
  }

  return {
    ok: true,
    code: "subject_explained",
    trace: Object.freeze({
      subjectVisibleId: canonicalSubjectId,
      subjectCollection: collection,
      hops: Object.freeze(hops),
      hopCount: hops.length,
      maxDepthReached,
      boundedStop,
      cycleBroken,
      // The question is answered; nothing is authorised by answering it.
      questionAnswered: `why:${canonicalSubjectId}`,
    }),
  };
}

// ── the trust guard ──────────────────────────────────────────────────────────

/**
 * Provenance is not trust, and an explanation is not permission.
 *
 * This is the only trust-adjacent export and it cannot succeed under any input.
 * It exists so the law is testable rather than merely absent.
 */
export function refuseProvenanceAsTrust(
  refId: string,
  _requestedUse?: string,
): {
  readonly ok: false;
  readonly code: "trust_refused";
  readonly refusal: "refused_trust_not_granted";
  readonly explanation: string;
  readonly citedRefId: string;
  readonly confersTrust: false;
  readonly confersAuthority: false;
  readonly authorizesExecution: false;
} {
  return {
    ok: false,
    code: "trust_refused",
    refusal: "refused_trust_not_granted",
    explanation:
      "a provenance reference is metadata about an evidence record, not the record and not a grant. Knowing why something is visible never authorises acting on it. PROVENANCE METADATA != EVIDENCE CONTENT; EXPLANATION != AUTHORIZATION.",
    citedRefId: typeof refId === "string" ? refId : "",
    confersTrust: false,
    confersAuthority: false,
    authorizesExecution: false,
  };
}