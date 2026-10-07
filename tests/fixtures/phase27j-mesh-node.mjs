#!/usr/bin/env node
/**
 * PHASE 27J — Mesh Node (TWO OS PROCESSES / REAL SOCKET / LOOPBACK ONLY).
 *
 * role B = the RECEIVER. Opens the REAL Phase-26 26B `LocalEndpointListener`
 *   on an explicit loopback port and reads ONE line-delimited JSON payload
 *   through the ONE sanctioned `onConnection` handler. What arrives is DATA.
 * role A = the SENDER. Builds its OWN mesh knowledge, then dials 127.0.0.1
 *   with `node:net` and sends ONE line of JSON.
 *
 * Each side, independently and with no shared state:
 *   · opens a REAL 27B `LocalTopologyGraph` on its OWN epoch;
 *   · records ITSELF as a `local_node` (local_configuration provenance) and
 *     its peer as an `observed_node` (governed_evidence provenance);
 *   · plans a route with the REAL 27E `planRoute` over its OWN graph;
 *   · projects its OWN world with the REAL 27H `buildMeshObservabilitySnapshot`.
 *
 * The point of the scenario is that the two snapshots are OBSERVER-RELATIVE
 * and DIFFER. Neither is a global truth, and nothing that crosses the wire
 * carries authority: an observation arrives as knowledge, never as admission,
 * authorization or execution.
 *
 * SCOPE HONESTY: loopback only. No Internet or public endpoint, no discovery,
 * no relay, no NAT traversal, no consensus, no remote authority, no
 * deployment. This is a PROCESS scenario, not a power-cut one: no power-loss,
 * controller-cache, hardware-failure, DDoS, WAN or production-capacity claim.
 *
 * Usage:
 *   node phase27j-mesh-node.mjs <role> <listenPort> <peerPort> <outFile> <epoch> <nowMs>
 */
import { connect } from "node:net";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ds = await import(new URL("../../packages/durable-state/dist/index.js", import.meta.url).href);

const [role, listenPortRaw, peerPortRaw, outFile, epochId, nowRaw] = process.argv.slice(2);
const LISTEN_PORT = Number(listenPortRaw);
const PEER_PORT = Number(peerPortRaw);
const NOW = Number(nowRaw);
const SELF = `node-${role.toLowerCase()}`;
const PEER = `node-${role === "A" ? "b" : "a"}`;

const out = (obj) => {
  process.stdout.write(JSON.stringify(obj) + "\n");
};
const fail = (code, detail) => {
  writeFileSync(outFile, JSON.stringify({ ok: false, code, detail }, null, 2), "utf8");
  out({ ok: false, code, detail });
  process.exit(3);
};

/**
 * Provenance is METADATA and is validated fail-closed by 27B:
 * `governed_evidence` MUST cite a non-empty evidence id, and
 * `local_configuration` MUST NOT pretend to cite one (`evidenceId: null`).
 * Getting this wrong refuses the record and cascades into a dangling edge and
 * an unplanned route — which is exactly what the first 27J draft did.
 */
const prov = (source, evidenceId) => ({
  source,
  evidenceId: source === "local_configuration" ? null : evidenceId,
  recordedAtEpochMs: NOW,
});

/**
 * Build this node's OWN world: graph → route plan → observability snapshot.
 * Nothing here is shared with the peer; each side derives its own view.
 */
function buildLocalWorld(extraNodes = [], extraEdges = [], extraRoutes = []) {
  const opened = ds.LocalTopologyGraph.open({ epochId });
  if (!opened.ok) return { ok: false, code: "graph_refused", detail: opened.refusal };
  const graph = opened.graph;

  const selfNode = graph.addNode({
    nodeId: SELF,
    kind: "local_node",
    epochId,
    provenance: prov("local_configuration", `ev-${role}-self`),
  });
  const peerNode = graph.addNode({
    nodeId: PEER,
    kind: "observed_node",
    epochId,
    provenance: prov("governed_evidence", `ev-${role}-peer`),
  });
  const link = graph.addEdge({
    edgeId: `edge-${role}-self-peer`,
    fromNodeId: SELF,
    toNodeId: PEER,
    kind: "observed_edge",
    epochId,
    provenance: prov("governed_evidence", `ev-${role}-link`),
  });

  const graphSnapshot = graph.snapshot();

  const routePlan = ds.planRoute({
    routeId: `route-${role}`,
    epochId,
    fromNodeId: SELF,
    toNodeId: PEER,
    observedAtEpochMs: NOW,
    graph: graphSnapshot,
    nodeStates: { [SELF]: "observed", [PEER]: "observed" },
    edgeStates: { [`edge-${role}-self-peer`]: "observed" },
  });

  const obsNodes = graphSnapshot.nodes.map((n) => ({
    nodeId: n.nodeId,
    kind: n.kind,
    epochId: n.epochId,
    observationState: "observed",
    provenance: n.provenance,
  }));
  const obsEdges = graphSnapshot.edges.map((e) => ({
    edgeId: e.edgeId,
    fromNodeId: e.fromNodeId,
    toNodeId: e.toNodeId,
    kind: e.kind,
    epochId: e.epochId,
    provenance: e.provenance,
  }));

  const plannedRoutes = [];
  if (routePlan.ok) {
    // Turn the plan into a MeshRoute so the route is VISIBLE in this node's own
    // snapshot — as knowledge, with the origin fixed and no authorization.
    const path = routePlan.path;
    plannedRoutes.push({
      epochId,
      route: {
        routeId: routePlan.routeId,
        state: "route_planned",
        origin: { nodeId: SELF, originFixed: true },
        hops: path.map((nodeId, index) => ({
          hopIndex: index,
          nodeId,
          role: index === 0 ? "origin" : index === path.length - 1 ? "destination" : "forwarder",
        })),
        destination: { nodeId: path[path.length - 1], role: "destination" },
        observedAtEpochMs: NOW,
      },
    });
  }

  const obs = ds.buildMeshObservabilitySnapshot({
    snapshotId: `snap-${role}`,
    epochId,
    asOfEpochMs: NOW,
    nodes: [...obsNodes, ...extraNodes],
    edges: [...obsEdges, ...extraEdges],
    routes: [...plannedRoutes, ...extraRoutes],
    refusals: [],
    partitions: [],
  });

  // A SECOND projection under a SHARED snapshot id. This removes the label as a
  // confound: if two nodes still disagree when everything except their vantage
  // point is identical, the difference is genuinely observer-relative and not
  // merely two differently-named snapshots.
  const sharedIdInput = {
    snapshotId: "shared-id",
    epochId,
    asOfEpochMs: NOW,
    nodes: [...obsNodes, ...extraNodes],
    edges: [...obsEdges, ...extraEdges],
    routes: [...plannedRoutes, ...extraRoutes],
    refusals: [],
    partitions: [],
  };
  const sharedIdSnapshot = ds.buildMeshObservabilitySnapshot(sharedIdInput);
  // A THIRD projection with byte-identical inputs from the SAME vantage. If
  // this repeated hash drifts, the cross-node difference would be noise; if it
  // matches, the difference between the nodes is content-derived. Same vantage
  // ⇒ same hash, different vantage ⇒ different hash: that is the whole claim.
  const sharedIdRepeat = ds.buildMeshObservabilitySnapshot({
    ...sharedIdInput,
    nodes: [...sharedIdInput.nodes],
    edges: [...sharedIdInput.edges],
    routes: [...sharedIdInput.routes],
  });

  return {
    ok: true,
    graph: graphSnapshot,
    graphFingerprint: graph.fingerprint(),
    selfNodeId: SELF,
    peerNodeId: PEER,
    decisions: {
      selfNode: selfNode.code ?? null,
      peerNode: peerNode.code ?? null,
      link: link.code ?? null,
    },
    routePlan,
    observability: obs,
    vantage: sharedIdSnapshot.ok
      ? {
          sharedSnapshotId: sharedIdSnapshot.snapshot.snapshotId,
          sharedProjectionHash: sharedIdSnapshot.snapshot.projectionHash,
          sharedOriginNodeId: sharedIdSnapshot.snapshot.routes[0]?.originNodeId ?? null,
          sharedRepeatProjectionHash: sharedIdRepeat.ok
            ? sharedIdRepeat.snapshot.projectionHash
            : null,
          sharedRepeatSnapshotId: sharedIdRepeat.ok
            ? sharedIdRepeat.snapshot.snapshotId
            : null,
        }
      : null,
  };
}

// ── role B: the sanctioned listener ──────────────────────────────────────────

async function runReceiver() {
  const listener = new ds.LocalEndpointListener({
    source: "explicit_local_config",
    host: "127.0.0.1",
    port: LISTEN_PORT,
    connections: 4,
    queue: 8,
  });
  const decision = listener.decision();
  if (!decision.ok) fail("endpoint_refused", decision.refusal ?? decision.code);

  const received = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("receive timeout")), 15_000);
    listener.onConnection((socket) => {
      let buffer = "";
      socket.setEncoding("utf8");
      socket.on("data", (chunk) => {
        buffer += chunk;
        const nl = buffer.indexOf("\n");
        if (nl < 0) return;
        clearTimeout(timer);
        let parsed = null;
        try {
          parsed = JSON.parse(buffer.slice(0, nl));
        } catch (err) {
          reject(new Error("unparseable wire payload: " + err.message));
          return;
        }
        // Echo an acknowledgement so the sender knows the bytes landed.
        try {
          socket.write(JSON.stringify({ ok: true, received: parsed.observations?.length ?? 0 }) + "\n");
        } catch {
          /* the peer may already be gone; the payload is already captured */
        }
        socket.end();
        resolve(parsed);
      });
      socket.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    listener.start().then((started) => {
      if (!started.ok) {
        clearTimeout(timer);
        reject(new Error("listener_start_refused: " + started.code));
      } else {
        out({ ok: true, event: "listening", port: LISTEN_PORT });
      }
    });
  });

  await listener.stop();

  // Everything the wire carried is treated as DATA and folded into B's OWN
  // view — never as authority. The observer-relative law is enforced here.
  const peerNodes = (received.observations?.nodes ?? []).map((n) => ({
    nodeId: n.nodeId,
    kind: n.kind ?? "observed_node",
    epochId: n.epochId ?? epochId,
    observationState: n.observationState ?? "observed",
    provenance: prov("governed_evidence", `ev-${role}-wire-${n.nodeId}`),
  }));

  const world = buildLocalWorld(peerNodes, [], []);
  if (!world.ok) fail("world_build_failed", world.detail);

  writeFileSync(
    outFile,
    JSON.stringify(
      {
        ok: true,
        role,
        epochId,
        listenerState: "stopped",
        received,
        world,
      },
      null,
      2,
    ),
    "utf8",
  );
  out({ ok: true, event: "done", role });
}

// ── role A: the dialler ──────────────────────────────────────────────────────

async function runSender() {
  const world = buildLocalWorld();
  if (!world.ok) fail("world_build_failed", world.detail);

  const payload = {
    from: SELF,
    epochId,
    // What A asserts, as OBSERVATION. It carries no authority and asks for none.
    observations: world.graph.nodes.map((n) => ({
      nodeId: n.nodeId,
      kind: n.kind,
      epochId: n.epochId,
      observationState: "observed",
      provenance: n.provenance,
    })),
  };

  const ack = await new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port: PEER_PORT });
    let buffer = "";
    const timer = setTimeout(() => reject(new Error("ack timeout")), 15_000);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(JSON.stringify(payload) + "\n"));
    socket.on("data", (chunk) => {
      buffer += chunk;
      const nl = buffer.indexOf("\n");
      if (nl >= 0) {
        clearTimeout(timer);
        try {
          resolve(JSON.parse(buffer.slice(0, nl)));
        } catch (err) {
          reject(new Error("unparseable ack: " + err.message));
        }
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  writeFileSync(
    outFile,
    JSON.stringify({ ok: true, role, epochId, sent: payload, ack, world }, null, 2),
    "utf8",
  );
  out({ ok: true, event: "done", role });
}

try {
  if (role === "B") await runReceiver();
  else await runSender();
} catch (err) {
  fail("scenario_failed", String(err && err.message ? err.message : err));
}