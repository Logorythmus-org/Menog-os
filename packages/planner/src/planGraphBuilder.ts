import type {
  Plan,
  PlanGraph,
  PlanGraphCycle,
  PlanGraphDisposition,
  PlanGraphEdge,
  PlanGraphNodeId,
  PlanDependencyKind,
  PlanStep,
} from "@menog/core";

const PLAN_GRAPH_SCHEMA_VERSION: PlanGraph["schemaVersion"] = "menog-plangraph/v0";

const DEP_KINDS: readonly PlanDependencyKind[] = Object.freeze([
  "sequential",
  "capability",
  "dataflow",
  "approval",
]);

export interface BuildPlanGraphOptions {
  readonly explicitDependencies?: Readonly<Record<number, readonly number[]>>;
  readonly explicitDependencyKind?: PlanDependencyKind;
  readonly includeSequentialChainEdges?: boolean;
}

export interface CanonicalPlanGraphForSerialize {
  readonly $schema: typeof PLAN_GRAPH_SCHEMA_VERSION;
  readonly graphId: string;
  readonly planId: string;
  readonly goalId: string;
  readonly disposition: PlanGraphDisposition;
  readonly nodeIds: readonly PlanGraphNodeId[];
  readonly nodeStepIndexes: Readonly<Record<PlanGraphNodeId, number>>;
  readonly edges: readonly PlanGraphEdge[];
  readonly adjacency: Readonly<Record<PlanGraphNodeId, readonly PlanGraphNodeId[]>>;
  readonly inDegree: Readonly<Record<PlanGraphNodeId, number>>;
  readonly topologicalOrder: readonly PlanGraphNodeId[];
  readonly cyclesFound: readonly PlanGraphCycle[];
  readonly rejectedEdgeIndex?: number;
  readonly rejectedEdgeReason?: string;
  readonly reason?: string;
}

export function stepIndexToNodeId(stepIndex: number): PlanGraphNodeId {
  return "step-" + String(stepIndex);
}

function isValidDependencyKind(value: unknown): value is PlanDependencyKind {
  return typeof value === "string" && (DEP_KINDS as readonly string[]).includes(value);
}

export function canonicalSerializePlanGraph(graph: PlanGraph): string {
  const serializable: CanonicalPlanGraphForSerialize = {
    $schema: PLAN_GRAPH_SCHEMA_VERSION,
    graphId: graph.graphId,
    planId: graph.planId,
    goalId: graph.goalId,
    disposition: graph.disposition,
    nodeIds: Object.freeze([...graph.nodeIds].sort()),
    nodeStepIndexes: sortRecordKeys(graph.nodeStepIndexes),
    edges: Object.freeze(
      [...graph.edges]
        .map((e) => ({
          from: e.from,
          to: e.to,
          kind: e.kind,
          ...(e.label !== undefined ? { label: e.label } : {}),
        }))
        .sort((a, b) => {
          const fromCmp = a.from.localeCompare(b.from);
          if (fromCmp !== 0) return fromCmp;
          const toCmp = a.to.localeCompare(b.to);
          if (toCmp !== 0) return toCmp;
          return a.kind.localeCompare(b.kind);
        })
    ),
    adjacency: sortRecordKeys(
      Object.fromEntries(
        Object.entries(graph.adjacency).map(([k, v]) => [k, [...v].sort()])
      ) as Readonly<Record<PlanGraphNodeId, readonly PlanGraphNodeId[]>>
    ),
    inDegree: sortRecordKeys(graph.inDegree),
    topologicalOrder: Object.freeze([...graph.topologicalOrder]),
    cyclesFound: Object.freeze(
      [...graph.cyclesFound]
        .map((c) => ({
          nodeIds: Object.freeze([...c.nodeIds]),
          entryPoint: c.entryPoint,
        }))
        .sort((a, b) => a.entryPoint.localeCompare(b.entryPoint))
    ),
    ...(graph.rejectedEdgeIndex !== undefined
      ? { rejectedEdgeIndex: graph.rejectedEdgeIndex }
      : {}),
    ...(graph.rejectedEdgeReason !== undefined
      ? { rejectedEdgeReason: graph.rejectedEdgeReason }
      : {}),
    ...(graph.reason !== undefined ? { reason: graph.reason } : {}),
  };
  return JSON.stringify(serializable, replacerSortKeys, 0);
}

function replacerSortKeys(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const k of keys) {
      out[k] = (value as Record<string, unknown>)[k];
    }
    return out;
  }
  return value;
}

function sortRecordKeys<T>(
  rec: Readonly<Record<string, T>>
): Readonly<Record<string, T>> {
  const out: Record<string, T> = {};
  const keys = Object.keys(rec).sort();
  for (const k of keys) {
    const v = rec[k];
    if (v !== undefined) out[k] = v;
  }
  return Object.freeze(out);
}

export function hash64(input: string, prefix: string): string {
  let h1 = 1779033703;
  let h2 = 3144134277;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h1 = (h1 << 13) | (h1 >>> 19);
    h2 = Math.imul(h2 ^ c, 1597334677);
    h2 = (h2 << 11) | (h2 >>> 21);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(h1 >>> 0, 0);
  buf.writeUInt32BE(h2 >>> 0, 4);
  const hex = buf.toString("hex");
  return prefix + hex;
}

export function detectCycles(
  nodeIds: readonly PlanGraphNodeId[],
  adjacency: Readonly<Record<PlanGraphNodeId, readonly PlanGraphNodeId[]>>
): readonly PlanGraphCycle[] {
  const cycles: PlanGraphCycle[] = [];
  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color: Record<string, 0 | 1 | 2> = {};
  for (const n of nodeIds) color[n] = WHITE;
  const seenCycleSignatures = new Set<string>();
  const stack: PlanGraphNodeId[] = [];
  for (const start of [...nodeIds].sort()) {
    if (color[start] !== WHITE) continue;
    dfs(start);
  }
  return Object.freeze(cycles);

  function dfs(node: PlanGraphNodeId): void {
    color[node] = GRAY;
    stack.push(node);
    const neighbors = [...(adjacency[node] ?? [])].sort();
    for (const next of neighbors) {
      if (color[next] === GRAY) {
        const idx = stack.indexOf(next);
        if (idx !== -1) {
          const cycleNodes = Object.freeze(stack.slice(idx));
          const sig = cycleNodes.join("|");
          if (!seenCycleSignatures.has(sig)) {
            seenCycleSignatures.add(sig);
            cycles.push(
              Object.freeze({
                nodeIds: cycleNodes,
                entryPoint: next,
              })
            );
          }
        }
      } else if (color[next] === WHITE) {
        dfs(next);
      }
    }
    stack.pop();
    color[node] = BLACK;
  }
}

export function topologicalSort(
  nodeIds: readonly PlanGraphNodeId[],
  adjacency: Readonly<Record<PlanGraphNodeId, readonly PlanGraphNodeId[]>>,
  nodeStepIndexes: Readonly<Record<PlanGraphNodeId, number>>
): readonly PlanGraphNodeId[] {
  const inDeg: Record<PlanGraphNodeId, number> = {};
  for (const n of nodeIds) inDeg[n] = 0;
  for (const n of nodeIds) {
    for (const m of adjacency[n] ?? []) {
      inDeg[m] = (inDeg[m] ?? 0) + 1;
    }
  }
  const queue: PlanGraphNodeId[] = [];
  for (const n of nodeIds) {
    if (inDeg[n] === 0) queue.push(n);
  }
  queue.sort((a, b) => (nodeStepIndexes[a] ?? 0) - (nodeStepIndexes[b] ?? 0));
  const order: PlanGraphNodeId[] = [];
  while (queue.length > 0) {
    queue.sort((a, b) => (nodeStepIndexes[a] ?? 0) - (nodeStepIndexes[b] ?? 0));
    const n = queue.shift()!;
    order.push(n);
    const neighbors = [...(adjacency[n] ?? [])].sort();
    for (const m of neighbors) {
      inDeg[m] = inDeg[m]! - 1;
      if (inDeg[m] === 0) queue.push(m);
    }
  }
  return Object.freeze(order);
}

export function buildPlanGraph(
  plan: Plan,
  options: BuildPlanGraphOptions = {}
): PlanGraph {
  if (!plan || typeof plan !== "object") {
    return failEmpty("plan must be an object");
  }
  if (typeof plan.planId !== "string" || plan.planId.length === 0) {
    return failEmpty("plan.planId must be a non-empty string");
  }
  if (typeof plan.goalId !== "string" || plan.goalId.length === 0) {
    return failEmpty("plan.goalId must be a non-empty string");
  }
  if (!Array.isArray(plan.steps)) {
    return failEmpty("plan.steps must be an array");
  }
  const steps: readonly PlanStep[] = plan.steps;
  if (steps.length === 0) {
    return rejectEmpty(plan, "plan.steps is empty; no nodes to graph");
  }
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i]!;
    if (!s || typeof s !== "object") return failEmpty("plan.steps[" + i + "] must be an object");
    if (typeof s.stepIndex !== "number" || s.stepIndex !== i) {
      return failEmpty(
        "plan.steps[" + i + "].stepIndex must equal array index " + i
      );
    }
  }

  const includeSequential =
    typeof options.includeSequentialChainEdges === "boolean"
      ? options.includeSequentialChainEdges
      : true;
  const explicitKind: PlanDependencyKind =
    options.explicitDependencyKind !== undefined &&
    isValidDependencyKind(options.explicitDependencyKind)
      ? options.explicitDependencyKind
      : "dataflow";

  const nodeIds: PlanGraphNodeId[] = [];
  const nodeStepIndexes: Record<PlanGraphNodeId, number> = {};
  for (const s of steps) {
    const id = stepIndexToNodeId(s.stepIndex);
    nodeIds.push(id);
    nodeStepIndexes[id] = s.stepIndex;
  }
  Object.freeze(nodeIds);
  Object.freeze(nodeStepIndexes);
  const nodeSet = new Set<PlanGraphNodeId>(nodeIds);

  const explicitDeps = options.explicitDependencies ?? {};
  const edges: PlanGraphEdge[] = [];
  const seenEdges = new Set<string>();

  for (const [rawIdx, rawDepList] of Object.entries(explicitDeps)) {
    const stepIdx = Number(rawIdx);
    if (!Number.isFinite(stepIdx) || Math.floor(stepIdx) !== stepIdx || stepIdx < 0) {
      return buildInvalidEdge(
        plan,
        Object.freeze([...nodeIds]),
        Object.freeze({ ...nodeStepIndexes }),
        Object.freeze([...edges]),
        edges.length,
        "explicitDependencies key '" + rawIdx + "' is not a valid non-negative integer step index"
      );
    }
    if (!Array.isArray(rawDepList)) {
      return buildInvalidEdge(
        plan,
        Object.freeze([...nodeIds]),
        Object.freeze({ ...nodeStepIndexes }),
        Object.freeze([...edges]),
        edges.length,
        "explicitDependencies[" + stepIdx + "] must be an array of step indexes"
      );
    }
    const targetId = stepIndexToNodeId(stepIdx);
    if (!nodeSet.has(targetId)) {
      return buildInvalidEdge(
        plan,
        Object.freeze([...nodeIds]),
        Object.freeze({ ...nodeStepIndexes }),
        Object.freeze([...edges]),
        edges.length,
        "explicitDependencies references step " +
          stepIdx +
          " which is not a node in the plan (" +
          steps.length +
          " steps present)"
      );
    }
    for (const dep of rawDepList) {
      if (!Number.isFinite(dep) || Math.floor(dep) !== dep || dep < 0) {
        return buildInvalidEdge(
          plan,
          Object.freeze([...nodeIds]),
          Object.freeze({ ...nodeStepIndexes }),
          Object.freeze([...edges]),
          edges.length,
          "explicitDependencies[" +
            stepIdx +
            "] contains an invalid non-negative integer dep '" +
            String(dep) +
            "'"
        );
      }
      const fromId = stepIndexToNodeId(dep);
      const edge: PlanGraphEdge = Object.freeze({
        from: fromId,
        to: targetId,
        kind: explicitKind,
      });
      if (!nodeSet.has(fromId)) {
        return buildInvalidEdge(
          plan,
          Object.freeze([...nodeIds]),
          Object.freeze({ ...nodeStepIndexes }),
          Object.freeze([...edges, edge]),
          edges.length,
          "edge from '" +
            fromId +
            "' references step " +
            dep +
            " which is not a node in the plan"
        );
      }
      if (fromId === targetId) {
        return buildInvalidEdge(
          plan,
          Object.freeze([...nodeIds]),
          Object.freeze({ ...nodeStepIndexes }),
          Object.freeze([...edges, edge]),
          edges.length,
          "self-loop edge is forbidden: " + fromId + " -> " + targetId
        );
      }
      const sig = edge.from + "|" + edge.to + "|" + edge.kind;
      if (!seenEdges.has(sig)) {
        seenEdges.add(sig);
        edges.push(edge);
      }
    }
  }

  if (includeSequential) {
    for (let i = 0; i + 1 < steps.length; i++) {
      const fromId = stepIndexToNodeId(steps[i]!.stepIndex);
      const toId = stepIndexToNodeId(steps[i + 1]!.stepIndex);
      const edge: PlanGraphEdge = Object.freeze({
        from: fromId,
        to: toId,
        kind: "sequential",
      });
      const sig = edge.from + "|" + edge.to + "|" + edge.kind;
      if (!seenEdges.has(sig)) {
        seenEdges.add(sig);
        edges.push(edge);
      }
    }
  }

  const adjacency: Record<PlanGraphNodeId, readonly PlanGraphNodeId[]> = {};
  const mutableAdj: Record<PlanGraphNodeId, PlanGraphNodeId[]> = {};
  for (const n of nodeIds) {
    mutableAdj[n] = [];
    adjacency[n] = mutableAdj[n]!;
  }
  const inDegree: Record<PlanGraphNodeId, number> = {};
  for (const n of nodeIds) inDegree[n] = 0;
  for (const e of edges) {
    if (!nodeSet.has(e.from) || !nodeSet.has(e.to)) {
      return buildInvalidEdge(
        plan,
        Object.freeze([...nodeIds]),
        Object.freeze({ ...nodeStepIndexes }),
        Object.freeze([...edges]),
        edges.indexOf(e),
        "edge endpoint references unknown node"
      );
    }
    mutableAdj[e.from]!.push(e.to);
    inDegree[e.to] = (inDegree[e.to] ?? 0) + 1;
  }
  for (const n of nodeIds) {
    adjacency[n] = Object.freeze([...new Set(mutableAdj[n]!)].sort());
  }
  Object.freeze(adjacency);
  Object.freeze(inDegree);
  Object.freeze(edges);

  const cyclesFound = detectCycles(nodeIds, adjacency);
  let disposition: PlanGraphDisposition =
    cyclesFound.length === 0 ? "dag_built" : "cycle_detected_rejected";

  let topologicalOrder: readonly PlanGraphNodeId[] = [];
  if (disposition === "dag_built") {
    topologicalOrder = topologicalSort(nodeIds, adjacency, nodeStepIndexes);
    if (topologicalOrder.length !== nodeIds.length) {
      disposition = "cycle_detected_rejected";
      topologicalOrder = Object.freeze([]);
    }
  }

  const graphIdSeed =
    "graph|planId=" +
    plan.planId +
    "|nodes=" +
    String(nodeIds.length) +
    "|edges=" +
    String(edges.length) +
    "|schema=" +
    PLAN_GRAPH_SCHEMA_VERSION;
  const graphId = hash64(graphIdSeed, "graph-");

  const partialGraph: PlanGraph = Object.freeze({
    graphId,
    planId: plan.planId,
    goalId: plan.goalId,
    disposition,
    schemaVersion: PLAN_GRAPH_SCHEMA_VERSION,
    nodeIds: Object.freeze([...nodeIds]),
    nodeStepIndexes: Object.freeze({ ...nodeStepIndexes }),
    edges: Object.freeze([...edges]),
    adjacency: Object.freeze({ ...adjacency }),
    inDegree: Object.freeze({ ...inDegree }),
    topologicalOrder,
    cyclesFound,
    ...(disposition === "cycle_detected_rejected"
      ? { reason: "cycles detected: " + String(cyclesFound.length) }
      : {}),
    serializedCanonical: "",
    serializedCanonicalHash: "",
  });

  const serialized = canonicalSerializePlanGraph(partialGraph);
  const serializedHash = hash64(serialized, "graphhash-");

  return Object.freeze({
    ...partialGraph,
    serializedCanonical: serialized,
    serializedCanonicalHash: serializedHash,
  });
}

function failEmpty(reason: string): PlanGraph {
  const disposition: PlanGraphDisposition = "empty_plan_rejected";
  const graph: PlanGraph = Object.freeze({
    graphId: hash64("empty|" + reason, "graph-"),
    planId: "",
    goalId: "",
    disposition,
    schemaVersion: PLAN_GRAPH_SCHEMA_VERSION,
    nodeIds: Object.freeze([]),
    nodeStepIndexes: Object.freeze({}),
    edges: Object.freeze([]),
    adjacency: Object.freeze({}),
    inDegree: Object.freeze({}),
    topologicalOrder: Object.freeze([]),
    cyclesFound: Object.freeze([]),
    reason,
    serializedCanonical: "",
    serializedCanonicalHash: "",
  });
  const serialized = canonicalSerializePlanGraph(graph);
  return Object.freeze({
    ...graph,
    serializedCanonical: serialized,
    serializedCanonicalHash: hash64(serialized, "graphhash-"),
  });
}

function rejectEmpty(plan: Plan, reason: string): PlanGraph {
  const disposition: PlanGraphDisposition = "empty_plan_rejected";
  const graph: PlanGraph = Object.freeze({
    graphId: hash64(
      "empty-reject|planId=" + plan.planId + "|goalId=" + plan.goalId + "|reason=" + reason,
      "graph-"
    ),
    planId: plan.planId,
    goalId: plan.goalId,
    disposition,
    schemaVersion: PLAN_GRAPH_SCHEMA_VERSION,
    nodeIds: Object.freeze([]),
    nodeStepIndexes: Object.freeze({}),
    edges: Object.freeze([]),
    adjacency: Object.freeze({}),
    inDegree: Object.freeze({}),
    topologicalOrder: Object.freeze([]),
    cyclesFound: Object.freeze([]),
    reason,
    serializedCanonical: "",
    serializedCanonicalHash: "",
  });
  const serialized = canonicalSerializePlanGraph(graph);
  return Object.freeze({
    ...graph,
    serializedCanonical: serialized,
    serializedCanonicalHash: hash64(serialized, "graphhash-"),
  });
}

function buildInvalidEdge(
  plan: Plan,
  nodeIds: readonly PlanGraphNodeId[],
  nodeStepIndexes: Readonly<Record<PlanGraphNodeId, number>>,
  edges: readonly PlanGraphEdge[],
  rejectedEdgeIndex: number,
  rejectedEdgeReason: string
): PlanGraph {
  const disposition: PlanGraphDisposition = "invalid_edge_rejected";
  const adjacency: Record<PlanGraphNodeId, readonly PlanGraphNodeId[]> = {};
  const mutableAdj: Record<PlanGraphNodeId, PlanGraphNodeId[]> = {};
  for (const n of nodeIds) {
    mutableAdj[n] = [];
    adjacency[n] = mutableAdj[n]!;
  }
  const inDeg: Record<PlanGraphNodeId, number> = {};
  for (const n of nodeIds) inDeg[n] = 0;
  const frozenNodeSet = new Set(nodeIds);
  for (const e of edges) {
    if (!frozenNodeSet.has(e.from) || !frozenNodeSet.has(e.to)) continue;
    mutableAdj[e.from]!.push(e.to);
    inDeg[e.to] = (inDeg[e.to] ?? 0) + 1;
  }
  for (const n of nodeIds) adjacency[n] = Object.freeze([...new Set(mutableAdj[n]!)].sort());
  const graph: PlanGraph = Object.freeze({
    graphId: hash64(
      "invalid-edge|planId=" +
        plan.planId +
        "|goalId=" +
        plan.goalId +
        "|idx=" +
        String(rejectedEdgeIndex) +
        "|reason=" +
        rejectedEdgeReason,
      "graph-"
    ),
    planId: plan.planId,
    goalId: plan.goalId,
    disposition,
    schemaVersion: PLAN_GRAPH_SCHEMA_VERSION,
    nodeIds: Object.freeze([...nodeIds]),
    nodeStepIndexes: Object.freeze({ ...nodeStepIndexes }),
    edges: Object.freeze([...edges]),
    adjacency: Object.freeze({ ...adjacency }),
    inDegree: Object.freeze({ ...inDeg }),
    topologicalOrder: Object.freeze([]),
    cyclesFound: Object.freeze([]),
    rejectedEdgeIndex,
    rejectedEdgeReason,
    reason: "invalid_edge at index " + String(rejectedEdgeIndex) + ": " + rejectedEdgeReason,
    serializedCanonical: "",
    serializedCanonicalHash: "",
  });
  const serialized = canonicalSerializePlanGraph(graph);
  return Object.freeze({
    ...graph,
    serializedCanonical: serialized,
    serializedCanonicalHash: hash64(serialized, "graphhash-"),
  });
}
