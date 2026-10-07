/**
 * PHASE 27H — Mesh Observability Tests (DETERMINISTIC REDACTED
 * READ-ONLY PROJECTION / VISUALIZATION != CONTROL PLANE).
 *
 * Pins the projector's laws structurally and behaviorally:
 *   · closed vocabularies + frozen bounds (pinned exact values);
 *   · structural zero-authority literals on EVERY snapshot (authority
 *     "none", controlPlane false, readOnly true) + pinned scope text;
 *   · no network/store/clock/tool surface, no forbidden law token,
 *     imports pinned to the five consumed local modules;
 *   · REDACTION: no free-text channel exists in the schema (word pin)
 *     and every string in a maximally-stuffed snapshot stays ≤128;
 *   · DETERMINISM: identical inputs → byte-identical snapshots and
 *     equal hashes; shuffled section order → identical output;
 *   · PURITY: deep-frozen inputs stay byte-identical (success+refusal);
 *   · UNKNOWN STAYS UNKNOWN: unknown_node/edge/route/role/source and
 *     unknown_observation project exactly as recorded; empty sections
 *     project explicit empties + zero lifecycle counts;
 *   · lifecycle counts exact over the frozen 27C vocabulary;
 *   · routes expose origin/forwarders/destination as knowledge
 *     (forwarders grouped by role, unknown_role never promoted);
 *   · freshness classified, never decided: within/outside window and
 *     unknown_freshness for un-orderable times; no clock anywhere;
 *   · fail-closed inputs: cross-epoch sections, unknown vocabulary,
 *     malformed shapes, bound violations, duplicates — every refusal
 *     explained, closed-set, with NO snapshot escaping;
 *   · decision shape pinned: refusal exposes no snapshot/authority.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  OBSERVABILITY_SCHEMA_VERSION,
  OBSERVABILITY_BOUNDS,
  OBSERVABILITY_REFUSAL_CODES,
  OBSERVABILITY_FRESHNESS,
  OBSERVABILITY_CONFLICT_RESOLUTIONS,
  OBSERVABILITY_CODE_PATTERN,
  OBSERVABILITY_SCOPE_TEXT,
  buildMeshObservabilitySnapshot,
  MESH_NODE_KINDS,
  MESH_EDGE_KINDS,
  MESH_ROUTE_STATES,
  MESH_HOP_ROLES,
  TOPOLOGY_OBSERVATION_STATES,
  type ObservabilityDecision,
  type ObservabilityInput,
  type ObservabilityRefusalCode,
  type ObservabilityNodeInput,
  type ObservabilityEdgeInput,
  type ObservabilityRouteInput,
  type ObservabilityRefusalInput,
  type ObservabilityPartitionInput,
  type ObservabilitySnapshot,
  type MeshRoute,
  type ConflictResolution,
  type TopologyProvenance,
  type TopologyObservationState,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27H module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
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
  ".persist(",
  "DurableStore",
  "PeerRegistry",
  "executeToolRun",
  "runIsolated",
  "toolJunction",
  "requireTool",
]);

/** Free-text / content channels the projection schema must never expose. */
const REDACTION_TOKENS: readonly string[] = Object.freeze([
  "payload",
  "freeText",
  "storeContent",
  "rawBody",
  "plaintext",
  "credential",
  "password",
  "secret",
]);

/** The ONLY modules the 27H module may import (pinned). */
const ALLOWED_IMPORTS = Object.freeze([
  "./canonical.js",
  "./meshPartitionReconciliation.js",
  "./meshTopologyGraph.js",
  "./meshTopologyLifecycle.js",
  "./meshTopologyTrust.js",
]);

/** Law/consensus tokens that must never appear in the module's CODE. */
const FORBIDDEN_LAW_TOKENS: readonly string[] = Object.freeze([
  "isPeerTrustTransition",
  "PEER_TRUST_TRANSITIONS",
  "trustState",
  "policyEngine",
  "evaluatePolicy",
  "authorize(",
  "admit(",
  "granted",
  "Paxos",
  "quorum",
  "leaderElect",
]);

const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27h";

const prov = (over: Partial<TopologyProvenance> = {}): TopologyProvenance => ({
  source: "governed_evidence",
  evidenceId: "ev-1",
  recordedAtEpochMs: NOW,
  ...over,
});

const node = (
  nodeId: string,
  over: Partial<ObservabilityNodeInput> = {},
): ObservabilityNodeInput => ({
  nodeId,
  kind: "observed_node",
  epochId: EPOCH,
  observationState: "observed",
  provenance: prov(),
  ...over,
});

const edge = (
  edgeId: string,
  fromNodeId: string,
  toNodeId: string,
  over: Partial<ObservabilityEdgeInput> = {},
): ObservabilityEdgeInput => ({
  edgeId,
  fromNodeId,
  toNodeId,
  kind: "observed_edge",
  epochId: EPOCH,
  provenance: prov(),
  ...over,
});

const mkRoute = (over: Partial<MeshRoute> = {}): MeshRoute => ({
  routeId: "route-1",
  state: "route_planned",
  origin: { nodeId: "node-a", originFixed: true },
  hops: [
    { hopIndex: 0, nodeId: "node-a", role: "origin" },
    { hopIndex: 1, nodeId: "node-b", role: "forwarder" },
    { hopIndex: 2, nodeId: "node-c", role: "destination" },
  ],
  destination: { nodeId: "node-c", role: "destination" },
  observedAtEpochMs: NOW,
  ...over,
});

const routeEntry = (
  route: MeshRoute = mkRoute(),
  over: { epochId?: string } = {},
): ObservabilityRouteInput => ({ epochId: EPOCH, route, ...over });

const refusal = (
  subjectId: string,
  code: string,
  over: { epochId?: string } = {},
): ObservabilityRefusalInput => ({ subjectId, code, epochId: EPOCH, ...over });

const partition = (
  reconciliationId: string,
  over: Partial<ObservabilityPartitionInput> = {},
): ObservabilityPartitionInput => ({
  reconciliationId,
  epochId: EPOCH,
  agreementCount: 1,
  localExclusiveCount: 0,
  remoteExclusiveCount: 0,
  conflicts: [],
  ...over,
});

const INPUT = (over: Partial<ObservabilityInput> = {}): ObservabilityInput => ({
  snapshotId: "snap-1",
  epochId: EPOCH,
  asOfEpochMs: NOW,
  nodes: [],
  edges: [],
  routes: [],
  refusals: [],
  partitions: [],
  ...over,
});

/** Every built snapshot carries the structural zero-authority literals. */
function expectBuilt(d: ObservabilityDecision): ObservabilitySnapshot {
  expect(d.ok).toBe(true);
  if (!d.ok) {
    throw new Error("expected a built snapshot");
  }
  expect(d.code).toBe("snapshot_built");
  const snapshot = d.snapshot;
  expect(snapshot.authority).toBe("none");
  expect(snapshot.controlPlane).toBe(false);
  expect(snapshot.readOnly).toBe(true);
  expect(snapshot.projectionHash).toMatch(/^[0-9a-f]{64}$/);
  expect(snapshot.schemaVersion).toBe(OBSERVABILITY_SCHEMA_VERSION);
  expect(Object.isFrozen(snapshot)).toBe(true);
  expect(Object.isFrozen(snapshot.nodes)).toBe(true);
  expect(Object.isFrozen(snapshot.edges)).toBe(true);
  expect(Object.isFrozen(snapshot.routes)).toBe(true);
  expect(Object.isFrozen(snapshot.lifecycle)).toBe(true);
  expect(Object.isFrozen(snapshot.refusals)).toBe(true);
  expect(Object.isFrozen(snapshot.partitions)).toBe(true);
  for (const n of snapshot.nodes) {
    expect(Object.isFrozen(n)).toBe(true);
    expect(Object.isFrozen(n.provenance)).toBe(true);
  }
  for (const e of snapshot.edges) {
    expect(Object.isFrozen(e)).toBe(true);
    expect(Object.isFrozen(e.provenance)).toBe(true);
  }
  for (const r of snapshot.routes) {
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.hops)).toBe(true);
    expect(Object.isFrozen(r.forwarderNodeIds)).toBe(true);
  }
  for (const p of snapshot.partitions) {
    expect(Object.isFrozen(p)).toBe(true);
    expect(Object.isFrozen(p.conflicts)).toBe(true);
    for (const c of p.conflicts) {
      expect(Object.isFrozen(c)).toBe(true);
    }
  }
  expect(d.explanation).toContain("VISUALIZATION != CONTROL PLANE");
  expect(d.explanation).toContain("fresh LOCAL allocation");
  return snapshot;
}

function expectRefused(d: ObservabilityDecision, refusalCode: ObservabilityRefusalCode): void {
  expect(d.ok).toBe(false);
  if (d.ok) {
    return;
  }
  expect(d.code).toBe("snapshot_refused");
  expect(d.refusal).toBe(refusalCode);
  expect(d.explanation.length).toBeGreaterThan(20);
  expect(d.explanation).toMatch(/refus/);
  expect(d.projectionHash).toMatch(/^[0-9a-f]{64}$/);
  expect("snapshot" in d).toBe(false);
  expect("authority" in d).toBe(false);
}

/** Every string value in a parsed snapshot tree stays within maxIdChars. */
function everyStringWithin(value: unknown, bound: number, path = "$"): void {
  if (typeof value === "string") {
    expect(value.length, path).toBeLessThanOrEqual(bound);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => everyStringWithin(item, bound, `${path}[${i}]`));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      everyStringWithin(item, bound, `${path}.${key}`);
    }
  }
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("27H structure — closed vocabulary, frozen bounds, zero-authority source", () => {
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
      ".persist(",
      "DurableStore",
      "PeerRegistry",
      "executeToolRun",
      "runIsolated",
      "toolJunction",
      "requireTool",
    ]);
    const code = codeOnly(SRC("meshObservability.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("redaction word pin: no free-text/content channel token exists in module code", () => {
    expect(REDACTION_TOKENS).toEqual([
      "payload",
      "freeText",
      "storeContent",
      "rawBody",
      "plaintext",
      "credential",
      "password",
      "secret",
    ]);
    const code = codeOnly(SRC("meshObservability.ts"));
    for (const token of REDACTION_TOKENS) {
      expect(code).not.toMatch(new RegExp(`\\b${token}\\b`, "i"));
    }
  });

  it("module imports ONLY the pinned local modules (no network, no store, no clock)", () => {
    const src = SRC("meshObservability.ts");
    const imports = [
      ...[...src.matchAll(/^import [^\n]* from "([^"]+)"/gm)].map((m) => m[1] as string),
      ...[...src.matchAll(/^\} from "([^"]+)"/gm)].map((m) => m[1] as string),
    ].sort();
    expect(imports).toEqual([...ALLOWED_IMPORTS].sort());
  });

  it("schema version, bounds, freshness, and code pattern are pinned frozen constants", () => {
    expect(OBSERVABILITY_SCHEMA_VERSION).toBe("menog-mesh-observability/v0");
    expect(OBSERVABILITY_BOUNDS).toEqual({
      maxNodes: 64,
      maxEdges: 256,
      maxRoutes: 64,
      maxHopsPerRoute: 16,
      maxRefusals: 64,
      maxPartitions: 64,
      maxConflictsPerPartition: 64,
      maxIdChars: 128,
      maxCodeChars: 64,
      freshnessWindowMs: 300_000,
    });
    expect(Object.isFrozen(OBSERVABILITY_BOUNDS)).toBe(true);
    expect(OBSERVABILITY_CODE_PATTERN.test("refused_replay")).toBe(true);
    expect(OBSERVABILITY_CODE_PATTERN.test("Refused_replay")).toBe(false);
    expect(OBSERVABILITY_CODE_PATTERN.test("refused-replay")).toBe(false);
    expect(OBSERVABILITY_CODE_PATTERN.source).toBe("^[a-z][a-z0-9_]*$");
  });

  it("refusal, freshness, and conflict-resolution vocabularies are pinned frozen closed sets", () => {
    expect([...OBSERVABILITY_REFUSAL_CODES]).toEqual([
      "refused_invalid_input",
      "refused_field_bound",
      "refused_epoch_mismatch",
      "refused_unknown_vocabulary",
      "refused_invalid_provenance",
      "refused_non_finite_time",
      "refused_duplicate_entry",
      "refused_unknown",
    ]);
    expect(Object.isFrozen(OBSERVABILITY_REFUSAL_CODES)).toBe(true);
    expect([...OBSERVABILITY_FRESHNESS]).toEqual([
      "within_window",
      "outside_window",
      "unknown_freshness",
    ]);
    expect(Object.isFrozen(OBSERVABILITY_FRESHNESS)).toBe(true);
    expect([...OBSERVABILITY_CONFLICT_RESOLUTIONS]).toEqual([
      "terminal_retained",
      "quarantine_retained",
      "no_consensus_unknown",
    ]);
    expect(Object.isFrozen(OBSERVABILITY_CONFLICT_RESOLUTIONS)).toBe(true);
    // shared vocabularies consumed read-only from their owning gates
    expect([...MESH_NODE_KINDS]).toEqual([
      "local_node",
      "admitted_node",
      "observed_node",
      "unknown_node",
    ]);
    expect([...MESH_EDGE_KINDS]).toEqual([
      "configured_edge",
      "observed_edge",
      "advertised_edge",
      "unknown_edge",
    ]);
    expect([...MESH_ROUTE_STATES]).toEqual([
      "route_planned",
      "route_unverified",
      "route_unavailable",
      "unknown_route",
    ]);
    expect([...MESH_HOP_ROLES]).toEqual([
      "origin",
      "forwarder",
      "destination",
      "unknown_role",
    ]);
    expect([...TOPOLOGY_OBSERVATION_STATES]).toEqual([
      "observed",
      "stale",
      "quarantined_observation",
      "retired_observation",
      "unknown_observation",
    ]);
  });

  it("scope text pins VISUALIZATION != CONTROL PLANE, unknown-stays-unknown, fresh LOCAL allocation", () => {
    expect(OBSERVABILITY_SCOPE_TEXT).toContain("VISUALIZATION != CONTROL PLANE");
    expect(OBSERVABILITY_SCOPE_TEXT).toContain("unknown stays unknown");
    expect(OBSERVABILITY_SCOPE_TEXT).toContain("fresh LOCAL allocation");
    expect(OBSERVABILITY_SCOPE_TEXT).toContain("never auto-resumes");
    expect(OBSERVABILITY_SCOPE_TEXT.length).toBeGreaterThan(100);
  });

  it("every authority/controlPlane/readOnly literal in source is structural (no law token)", () => {
    const code = codeOnly(SRC("meshObservability.ts"));
    for (const match of code.matchAll(/authority:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('authority: "none"');
    }
    for (const match of code.matchAll(/controlPlane:\s*(?:true|false)/g)) {
      expect(match[0]).toBe("controlPlane: false");
    }
    for (const match of code.matchAll(/readOnly:\s*(?:true|false)/g)) {
      expect(match[0]).toBe("readOnly: true");
    }
    expect(code).not.toContain("controlPlane: true");
    expect(code).not.toContain("readOnly: false");
    for (const token of FORBIDDEN_LAW_TOKENS) {
      expect(code).not.toContain(token);
    }
  });

  it("export surface: exactly ONE pure builder, no class, no action/authority export", () => {
    const code = codeOnly(SRC("meshObservability.ts"));
    const functions = [...code.matchAll(/^export function (\w+)/gm)].map((m) => m[1] as string);
    expect(functions).toEqual(["buildMeshObservabilitySnapshot"]);
    expect(code).not.toContain("export class");
    const exportNames = [...code.matchAll(/^export (?:const|type|interface) (\w+)/gm)].map(
      (m) => m[1] as string,
    );
    for (const name of exportNames) {
      expect(name).not.toMatch(/authoriz|approv|admit|grant|leader|quorum|mutat|execut|trigger|action|updat|apply|writ/i);
    }
    expect(typeof buildMeshObservabilitySnapshot).toBe("function");
  });
});

// ── snapshot schema + zero-authority state ──────────────────────────────────

describe("27H snapshot schema — exact keys, zero-authority state, redaction", () => {
  const fullInput = () =>
    INPUT({
      nodes: [
        node("node-a"),
        node("node-b", { observationState: "stale", kind: "unknown_node" }),
      ],
      edges: [edge("edge-1", "node-a", "node-b")],
      routes: [routeEntry()],
      refusals: [refusal("node-c", "refused_replay")],
      partitions: [
        partition("rec-1", {
          conflicts: [
            {
              subjectNodeId: "node-b",
              localState: "observed",
              remoteState: "stale",
              resolution: "no_consensus_unknown",
              localRecordedAtEpochMs: NOW - 1_000,
              remoteRecordedAtEpochMs: NOW - 500,
            },
          ],
        }),
      ],
    });

  it("snapshot, sections, and elements expose EXACTLY the pinned keys", () => {
    const snapshot = expectBuilt(buildMeshObservabilitySnapshot(fullInput()));
    expect(Object.keys(snapshot).sort()).toEqual(
      [
        "schemaVersion",
        "snapshotId",
        "epochId",
        "asOfEpochMs",
        "nodes",
        "edges",
        "routes",
        "lifecycle",
        "refusals",
        "partitions",
        "authority",
        "controlPlane",
        "readOnly",
        "projectionHash",
      ].sort(),
    );
    const n = snapshot.nodes[0] as (typeof snapshot.nodes)[number];
    expect(Object.keys(n).sort()).toEqual(
      ["nodeId", "kind", "observationState", "provenance", "ageMs", "freshness"].sort(),
    );
    expect(Object.keys(n.provenance).sort()).toEqual(
      ["source", "evidenceId", "recordedAtEpochMs"].sort(),
    );
    const e = snapshot.edges[0] as (typeof snapshot.edges)[number];
    expect(Object.keys(e).sort()).toEqual(
      ["edgeId", "fromNodeId", "toNodeId", "kind", "provenance", "ageMs", "freshness"].sort(),
    );
    const r = snapshot.routes[0] as (typeof snapshot.routes)[number];
    expect(Object.keys(r).sort()).toEqual(
      [
        "routeId",
        "state",
        "originNodeId",
        "originFixed",
        "forwarderNodeIds",
        "destinationNodeId",
        "hops",
        "observedAtEpochMs",
        "ageMs",
        "freshness",
      ].sort(),
    );
    const h = r.hops[0] as (typeof r.hops)[number];
    expect(Object.keys(h).sort()).toEqual(["hopIndex", "nodeId", "role"].sort());
    expect(Object.keys(snapshot.lifecycle)).toEqual([...TOPOLOGY_OBSERVATION_STATES]);
    const ref = snapshot.refusals[0] as (typeof snapshot.refusals)[number];
    expect(Object.keys(ref).sort()).toEqual(["subjectId", "code"].sort());
    const p = snapshot.partitions[0] as (typeof snapshot.partitions)[number];
    expect(Object.keys(p).sort()).toEqual(
      [
        "reconciliationId",
        "agreementCount",
        "localExclusiveCount",
        "remoteExclusiveCount",
        "conflictCount",
        "conflicts",
      ].sort(),
    );
    const c = p.conflicts[0] as (typeof p.conflicts)[number];
    expect(Object.keys(c).sort()).toEqual(
      [
        "subjectNodeId",
        "localState",
        "remoteState",
        "resolution",
        "localRecordedAtEpochMs",
        "remoteRecordedAtEpochMs",
      ].sort(),
    );
  });

  it("zero-authority state: structural literals present, no authority-family token in snapshot JSON", () => {
    const snapshot = expectBuilt(buildMeshObservabilitySnapshot(fullInput()));
    const json = JSON.stringify(snapshot);
    expect(json).toContain('"authority":"none"');
    expect(json).toContain('"controlPlane":false');
    expect(json).toContain('"readOnly":true');
    expect(json).not.toMatch(/trust|grant|quorum|leader|authoriz|admit|consensusReached|"consensus":/i);
    expect(json).toContain('"resolution":"no_consensus_unknown"'); // vocabulary label, not a claim
  });

  it("redaction: a maximally-stuffed snapshot keeps every string within maxIdChars and the hash at 64", () => {
    const long = "k".repeat(OBSERVABILITY_BOUNDS.maxIdChars);
    const longCode = "r".repeat(OBSERVABILITY_BOUNDS.maxCodeChars);
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          snapshotId: long,
          nodes: [node(long, { provenance: prov({ evidenceId: long }) })],
          edges: [edge(long, long, long)],
          refusals: [refusal(long, longCode)],
        }),
      ),
    );
    everyStringWithin(JSON.parse(JSON.stringify(snapshot)), OBSERVABILITY_BOUNDS.maxIdChars);
    expect(snapshot.projectionHash).toHaveLength(64);
    expect(JSON.stringify(snapshot.refusals)).toContain(longCode);
  });

  it("decision shape pinned: refusal exposes NO snapshot, NO authority; success is ok/code/snapshot/explanation", () => {
    const built = buildMeshObservabilitySnapshot(INPUT());
    expect(Object.keys(built).sort()).toEqual(["ok", "code", "snapshot", "explanation"].sort());
    const refused = buildMeshObservabilitySnapshot(
      INPUT({ nodes: [node("node-a", { epochId: "epoch-other" })] }),
    );
    expectRefused(refused, "refused_epoch_mismatch");
    if (!refused.ok) {
      expect(Object.keys(refused).sort()).toEqual(
        ["ok", "code", "snapshotId", "refusal", "explanation", "projectionHash"].sort(),
      );
      expect(refused.snapshotId).toBe("snap-1");
    }
  });
});

// ── determinism + purity ─────────────────────────────────────────────────────

describe("27H determinism and purity — byte-identical duplicates, frozen inputs", () => {
  const buildFresh = () =>
    INPUT({
      nodes: [node("node-b"), node("node-a")],
      edges: [edge("edge-2", "node-b", "node-a"), edge("edge-1", "node-a", "node-b")],
      routes: [routeEntry(mkRoute({ routeId: "route-2" })), routeEntry()],
      refusals: [refusal("node-b", "refused_replay"), refusal("node-a", "refused_epoch_mismatch")],
      partitions: [partition("rec-2"), partition("rec-1")],
    });

  it("identical content built twice is byte-identical with an equal hash", () => {
    const first = buildMeshObservabilitySnapshot(buildFresh());
    const second = buildMeshObservabilitySnapshot(buildFresh());
    expectBuilt(first);
    expectBuilt(second);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    if (first.ok && second.ok) {
      expect(second.snapshot.projectionHash).toBe(first.snapshot.projectionHash);
    }
  });

  it("shuffled section order produces the byte-identical canonical snapshot", () => {
    const ordered = buildMeshObservabilitySnapshot(buildFresh());
    const base = buildFresh();
    const shuffled = buildMeshObservabilitySnapshot(
      INPUT({
        nodes: [...base.nodes].reverse(),
        edges: [...base.edges].reverse(),
        routes: [...base.routes].reverse(),
        refusals: [...base.refusals].reverse(),
        partitions: [...base.partitions].reverse(),
      }),
    );
    expectBuilt(ordered);
    expectBuilt(shuffled);
    // Canonical CONTENT is byte-identical across input orders. projectionHash is
    // input-derived by design (canonicalHash over schema + input), so a shuffled
    // input is a DIFFERENT input and may hash differently — compare without it.
    const withoutHash = (d: ObservabilityDecision): string => {
      if (!d.ok) return "";
      const clone = JSON.parse(JSON.stringify(d)) as {
        snapshot: { projectionHash?: string } & Record<string, unknown>;
      };
      delete clone.snapshot.projectionHash;
      return JSON.stringify(clone);
    };
    expect(withoutHash(shuffled)).toBe(withoutHash(ordered));
    if (ordered.ok && shuffled.ok) {
      expect(ordered.snapshot.projectionHash).toMatch(/^[0-9a-f]{64}$/);
      expect(shuffled.snapshot.projectionHash).toMatch(/^[0-9a-f]{64}$/);
      expect(shuffled.snapshot.nodes.map((n) => n.nodeId)).toEqual(["node-a", "node-b"]);
      expect(shuffled.snapshot.edges.map((e) => e.edgeId)).toEqual(["edge-1", "edge-2"]);
      expect(shuffled.snapshot.routes.map((r) => r.routeId)).toEqual(["route-1", "route-2"]);
      expect(shuffled.snapshot.partitions.map((p) => p.reconciliationId)).toEqual([
        "rec-1",
        "rec-2",
      ]);
    }
  });

  it("neither input is ever mutated — deep-frozen inputs stay byte-identical (success and refusal)", () => {
    const deepFreeze = <T,>(value: T): T => {
      if (value !== null && typeof value === "object") {
        for (const key of Object.keys(value as Record<string, unknown>)) {
          deepFreeze((value as Record<string, unknown>)[key]);
        }
        Object.freeze(value);
      }
      return value;
    };
    const successInput = deepFreeze(buildFresh());
    const before = JSON.stringify(successInput);
    expectBuilt(buildMeshObservabilitySnapshot(successInput));
    expect(JSON.stringify(successInput)).toBe(before);
    const refusalInput = deepFreeze(
      INPUT({ nodes: [node("node-a", { epochId: "epoch-other" })] }),
    );
    const refusalBefore = JSON.stringify(refusalInput);
    expectRefused(buildMeshObservabilitySnapshot(refusalInput), "refused_epoch_mismatch");
    expect(JSON.stringify(refusalInput)).toBe(refusalBefore);
  });
});

// ── unknown stays unknown + lifecycle distinctions ───────────────────────────

describe("27H unknown stays unknown — no promotion, no invention, explicit empties", () => {
  it("every unknown-vocabulary member projects exactly as recorded", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [
            node("node-u", { kind: "unknown_node", observationState: "unknown_observation", provenance: prov({ source: "unknown_source", evidenceId: null }) }),
          ],
          edges: [edge("edge-u", "node-u", "node-v", { kind: "unknown_edge" })],
          routes: [
            routeEntry(
              mkRoute({
                state: "unknown_route",
                hops: [
                  { hopIndex: 0, nodeId: "node-u", role: "unknown_role" },
                  { hopIndex: 1, nodeId: "node-v", role: "destination" },
                ],
                destination: { nodeId: "node-v", role: "destination" },
              }),
            ),
          ],
        }),
      ),
    );
    const n = snapshot.nodes[0] as (typeof snapshot.nodes)[number];
    expect(n.kind).toBe("unknown_node");
    expect(n.observationState).toBe("unknown_observation");
    expect(n.provenance.source).toBe("unknown_source");
    expect(n.provenance.evidenceId).toBeNull();
    const e = snapshot.edges[0] as (typeof snapshot.edges)[number];
    expect(e.kind).toBe("unknown_edge");
    const r = snapshot.routes[0] as (typeof snapshot.routes)[number];
    expect(r.state).toBe("unknown_route");
    expect((r.hops[0] as { role: string }).role).toBe("unknown_role");
    expect(r.forwarderNodeIds).toEqual([]); // unknown_role never becomes a forwarder
    expect(snapshot.lifecycle.unknown_observation).toBe(1);
  });

  it("lifecycle counts are exact over the frozen 27C vocabulary and sum to node count", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [
            node("n1"),
            node("n2"),
            node("n3", { observationState: "stale" }),
            node("n4", { observationState: "quarantined_observation" }),
            node("n5", { observationState: "retired_observation" }),
            node("n6", { observationState: "unknown_observation" }),
          ],
        }),
      ),
    );
    expect(Object.keys(snapshot.lifecycle)).toEqual([...TOPOLOGY_OBSERVATION_STATES]);
    expect(snapshot.lifecycle).toEqual({
      observed: 2,
      stale: 1,
      quarantined_observation: 1,
      retired_observation: 1,
      unknown_observation: 1,
    });
    const total = Object.values(snapshot.lifecycle).reduce((a, b) => a + b, 0);
    expect(total).toBe(snapshot.nodes.length);
    expect(Object.isFrozen(snapshot.lifecycle)).toBe(true);
  });

  it("empty sections project explicit empties with zero lifecycle counts (nothing invented)", () => {
    const snapshot = expectBuilt(buildMeshObservabilitySnapshot(INPUT()));
    expect(snapshot.nodes).toEqual([]);
    expect(snapshot.edges).toEqual([]);
    expect(snapshot.routes).toEqual([]);
    expect(snapshot.refusals).toEqual([]);
    expect(snapshot.partitions).toEqual([]);
    expect(snapshot.lifecycle).toEqual({
      observed: 0,
      stale: 0,
      quarantined_observation: 0,
      retired_observation: 0,
      unknown_observation: 0,
    });
    expect(snapshot.authority).toBe("none");
  });
});

// ── routes expose origin / forwarders / destination ─────────────────────────

describe("27H routes — origin/forwarders/destination exposed as knowledge", () => {
  it("roles project as recorded: origin fixed, forwarders grouped, destination named", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          routes: [
            routeEntry(
              mkRoute({
                hops: [
                  { hopIndex: 0, nodeId: "node-a", role: "origin" },
                  { hopIndex: 1, nodeId: "node-b", role: "forwarder" },
                  { hopIndex: 2, nodeId: "node-d", role: "forwarder" },
                  { hopIndex: 3, nodeId: "node-c", role: "destination" },
                ],
              }),
            ),
          ],
        }),
      ),
    );
    const r = snapshot.routes[0] as (typeof snapshot.routes)[number];
    expect(r.originNodeId).toBe("node-a");
    expect(r.originFixed).toBe(true);
    expect(r.forwarderNodeIds).toEqual(["node-b", "node-d"]);
    expect(r.destinationNodeId).toBe("node-c");
    expect(r.hops).toHaveLength(4);
    expect(r.hops.map((h) => h.role)).toEqual([
      "origin",
      "forwarder",
      "forwarder",
      "destination",
    ]);
    expect(r.hops.map((h) => h.hopIndex)).toEqual([0, 1, 2, 3]);
  });

  it("the projection grants the route nothing: state stays route_planned, authority stays none", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(INPUT({ routes: [routeEntry(mkRoute({ state: "route_unverified" }))] })),
    );
    const r = snapshot.routes[0] as (typeof snapshot.routes)[number];
    expect(r.state).toBe("route_unverified");
    expect(snapshot.authority).toBe("none");
    expect(snapshot.controlPlane).toBe(false);
    expect(JSON.stringify(snapshot.routes)).not.toMatch(/authoriz|grant|admit/i);
  });
});

// ── freshness classification ─────────────────────────────────────────────────

describe("27H freshness — classified, never decided; no clock anywhere", () => {
  it("within-window, boundary, and outside-window classifications are exact", () => {
    const window = OBSERVABILITY_BOUNDS.freshnessWindowMs;
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          asOfEpochMs: NOW + window + 1,
          nodes: [
            node("n-now", { provenance: prov({ recordedAtEpochMs: NOW + window + 1 }) }), // age 0
            node("n-edge", { provenance: prov({ recordedAtEpochMs: NOW + 1 }) }), // age = window
            node("n-out", { provenance: prov({ recordedAtEpochMs: NOW }) }), // age = window + 1
          ],
        }),
      ),
    );
    const byId = new Map(snapshot.nodes.map((n) => [n.nodeId, n]));
    expect(byId.get("n-now")?.freshness).toBe("within_window");
    expect(byId.get("n-now")?.ageMs).toBe(0);
    expect(byId.get("n-edge")?.ageMs).toBe(window);
    expect(byId.get("n-edge")?.freshness).toBe("within_window");
    expect(byId.get("n-out")?.ageMs).toBe(window + 1);
    expect(byId.get("n-out")?.freshness).toBe("outside_window");
  });

  it("a record AFTER asOf cannot be ordered — unknown_freshness, never a negative verdict", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [node("n-future", { provenance: prov({ recordedAtEpochMs: NOW + 60_000 }) })],
          routes: [routeEntry(mkRoute({ observedAtEpochMs: NOW + 60_000 }))],
        }),
      ),
    );
    const n = snapshot.nodes[0] as (typeof snapshot.nodes)[number];
    expect(n.ageMs).toBe(-60_000);
    expect(n.freshness).toBe("unknown_freshness");
    const r = snapshot.routes[0] as (typeof snapshot.routes)[number];
    expect(r.freshness).toBe("unknown_freshness");
    expect(snapshot.edges).toEqual([]);
  });

  it("non-finite or negative times refuse — asOf, node provenance, and route time alike", () => {
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ asOfEpochMs: Number.NaN })),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ asOfEpochMs: Number.POSITIVE_INFINITY })),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ asOfEpochMs: -1 })),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ nodes: [node("n1", { provenance: prov({ recordedAtEpochMs: Number.NaN }) })] }),
      ),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ nodes: [node("n1", { provenance: prov({ recordedAtEpochMs: -5 }) })] }),
      ),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ routes: [routeEntry(mkRoute({ observedAtEpochMs: Number.POSITIVE_INFINITY }))] }),
      ),
      "refused_non_finite_time",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          partitions: [
            partition("rec-1", {
              conflicts: [
                {
                  subjectNodeId: "n1",
                  localState: "observed",
                  remoteState: "stale",
                  resolution: "no_consensus_unknown",
                  localRecordedAtEpochMs: NOW,
                  remoteRecordedAtEpochMs: Number.NaN,
                },
              ],
            }),
          ],
        }),
      ),
      "refused_non_finite_time",
    );
  });
});

// ── partitions + refusal records ───────────────────────────────────────────

describe("27H partitions and refusals — attributed knowledge, code-only records", () => {
  it("partition counts, conflictCount, and conflicts (sorted) project exactly", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          partitions: [
            partition("rec-1", {
              agreementCount: 3,
              localExclusiveCount: 2,
              remoteExclusiveCount: 1,
              conflicts: [
                {
                  subjectNodeId: "z-node",
                  localState: "retired_observation",
                  remoteState: "observed",
                  resolution: "terminal_retained",
                  localRecordedAtEpochMs: NOW - 2_000,
                  remoteRecordedAtEpochMs: NOW - 1_000,
                },
                {
                  subjectNodeId: "a-node",
                  localState: "observed",
                  remoteState: "quarantined_observation",
                  resolution: "quarantine_retained",
                  localRecordedAtEpochMs: NOW - 4_000,
                  remoteRecordedAtEpochMs: NOW - 3_000,
                },
              ],
            }),
          ],
        }),
      ),
    );
    const p = snapshot.partitions[0] as (typeof snapshot.partitions)[number];
    expect(p.reconciliationId).toBe("rec-1");
    expect(p.agreementCount).toBe(3);
    expect(p.localExclusiveCount).toBe(2);
    expect(p.remoteExclusiveCount).toBe(1);
    expect(p.conflictCount).toBe(2);
    // conflicts are canonically sorted by subject — both claims kept, never a winner
    expect(p.conflicts.map((c) => c.subjectNodeId)).toEqual(["a-node", "z-node"]);
    const first = p.conflicts[0] as (typeof p.conflicts)[number];
    expect(first.localState).toBe("observed");
    expect(first.remoteState).toBe("quarantined_observation");
    expect(first.resolution).toBe("quarantine_retained");
    expect(first.localRecordedAtEpochMs).toBe(NOW - 4_000);
    expect(first.remoteRecordedAtEpochMs).toBe(NOW - 3_000);
    // conflict states are NOT node states — lifecycle counts only from nodes
    expect(snapshot.lifecycle).toEqual({
      observed: 0,
      stale: 0,
      quarantined_observation: 0,
      retired_observation: 0,
      unknown_observation: 0,
    });
  });

  it("refusal records are code-only: token shape enforced, 65-char code refuses bound", () => {
    const snapshot = expectBuilt(
      buildMeshObservabilitySnapshot(
        INPUT({
          refusals: [
            refusal("node-x", "refused_replay"),
            refusal("node-x", "refused_hop_limit"), // same subject, distinct code — both kept
          ],
        }),
      ),
    );
    expect(snapshot.refusals).toHaveLength(2);
    const badShape = [
      "Refused_replay",
      "refused-replay",
      "REFUSED_REPLAY",
      "refused.replay",
    ];
    for (const code of badShape) {
      expectRefused(
        buildMeshObservabilitySnapshot(INPUT({ refusals: [refusal("node-x", code)] })),
        "refused_invalid_input",
      );
    }
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ refusals: [refusal("node-x", "")] })),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ refusals: [refusal("node-x", "r".repeat(OBSERVABILITY_BOUNDS.maxCodeChars + 1))] }),
      ),
      "refused_field_bound",
    );
  });

  it("duplicate identifiers refuse in EVERY section (including partition conflicts)", () => {
    const cases: readonly { input: ObservabilityInput; code: ObservabilityRefusalCode }[] = [
      { input: INPUT({ nodes: [node("n1"), node("n1")] }), code: "refused_duplicate_entry" },
      {
        input: INPUT({ edges: [edge("e1", "a", "b"), edge("e1", "b", "c")] }),
        code: "refused_duplicate_entry",
      },
      {
        input: INPUT({ routes: [routeEntry(), routeEntry()] }),
        code: "refused_duplicate_entry",
      },
      {
        input: INPUT({ refusals: [refusal("n1", "refused_replay"), refusal("n1", "refused_replay")] }),
        code: "refused_duplicate_entry",
      },
      {
        input: INPUT({ partitions: [partition("rec-1"), partition("rec-1")] }),
        code: "refused_duplicate_entry",
      },
      {
        input: INPUT({
          partitions: [
            partition("rec-1", {
              conflicts: [
                {
                  subjectNodeId: "n1",
                  localState: "observed",
                  remoteState: "stale",
                  resolution: "no_consensus_unknown",
                  localRecordedAtEpochMs: NOW,
                  remoteRecordedAtEpochMs: NOW,
                },
                {
                  subjectNodeId: "n1",
                  localState: "stale",
                  remoteState: "observed",
                  resolution: "no_consensus_unknown",
                  localRecordedAtEpochMs: NOW,
                  remoteRecordedAtEpochMs: NOW,
                },
              ],
            }),
          ],
        }),
        code: "refused_duplicate_entry",
      },
    ];
    for (const c of cases) {
      expectRefused(buildMeshObservabilitySnapshot(c.input), c.code);
    }
  });
});

// ── fail-closed inputs ───────────────────────────────────────────────────────

describe("27H fail-closed inputs — shape, bounds, epoch, vocabulary, provenance", () => {
  it("malformed shapes refuse (null input, missing sections, non-array, empty ids)", () => {
    expectRefused(
      buildMeshObservabilitySnapshot(null as unknown as ObservabilityInput),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot({
        snapshotId: "snap-1",
        epochId: EPOCH,
      } as unknown as ObservabilityInput),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ nodes: "not-an-array" as unknown as readonly ObservabilityNodeInput[] }),
      ),
      "refused_invalid_input",
    );
    expectRefused(buildMeshObservabilitySnapshot(INPUT({ snapshotId: "" })), "refused_invalid_input");
    expectRefused(buildMeshObservabilitySnapshot(INPUT({ epochId: "" })), "refused_invalid_input");
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ nodes: [null as unknown as ObservabilityNodeInput] })),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ nodes: [node("n1", { provenance: null as unknown as TopologyProvenance })] }),
      ),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ routes: [routeEntry(mkRoute({ hops: null as unknown as MeshRoute["hops"] }))] }),
      ),
      "refused_invalid_input",
    );
  });

  it("frozen bounds refuse — 64 nodes reconcile, 65 and every oversize field refuse", () => {
    const atBound = Array.from({ length: 64 }, (_, i) => node(`n${String(i).padStart(2, "0")}`));
    expectBuilt(buildMeshObservabilitySnapshot(INPUT({ nodes: atBound })));
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ nodes: [...atBound, node("n64")] })),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ edges: Array.from({ length: 257 }, (_, i) => edge(`e${i}`, "a", "b")) }),
      ),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ snapshotId: "k".repeat(129) })),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ nodes: [node("k".repeat(129))] })),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          routes: [
            routeEntry(
              mkRoute({
                hops: Array.from({ length: 17 }, (_, i) => ({
                  hopIndex: i,
                  nodeId: `h${i}`,
                  role: "forwarder" as const,
                })),
              }),
            ),
          ],
        }),
      ),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [node("n1", { provenance: prov({ evidenceId: "e".repeat(129) }) })],
        }),
      ),
      "refused_field_bound",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ partitions: [partition("k".repeat(129))] })),
      "refused_field_bound",
    );
  });

  it("cross-epoch records refuse in EVERY section (epoch substitution never projects)", () => {
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ nodes: [node("n1", { epochId: "epoch-x" })] })),
      "refused_epoch_mismatch",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ edges: [edge("e1", "a", "b", { epochId: "epoch-x" })] }),
      ),
      "refused_epoch_mismatch",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ routes: [routeEntry(mkRoute(), { epochId: "epoch-x" })] })),
      "refused_epoch_mismatch",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ refusals: [refusal("n1", "refused_replay", { epochId: "epoch-x" })] })),
      "refused_epoch_mismatch",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ partitions: [partition("rec-1", { epochId: "epoch-x" })] })),
      "refused_epoch_mismatch",
    );
  });

  it("every enum field is validated against its frozen vocabulary (unnamed never projects)", () => {
    const cases: readonly { input: ObservabilityInput; code: ObservabilityRefusalCode }[] = [
      { input: INPUT({ nodes: [node("n1", { kind: "weird_kind" })] }), code: "refused_unknown_vocabulary" },
      {
        input: INPUT({
          nodes: [node("n1", { observationState: "bogus_state" as unknown as TopologyObservationState })],
        }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({ edges: [edge("e1", "a", "b", { kind: "weird_edge" })] }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({
          routes: [routeEntry(mkRoute({ state: "weird_route" as unknown as MeshRoute["state"] }))],
        }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({
          routes: [
            routeEntry(
              mkRoute({
                hops: [
                  { hopIndex: 0, nodeId: "node-a", role: "weird_role" as unknown as "origin" },
                ],
              }),
            ),
          ],
        }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({
          nodes: [
            node("n1", {
              provenance: prov({ source: "gossip" as unknown as TopologyProvenance["source"] }),
            }),
          ],
        }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({
          partitions: [
            partition("rec-1", {
              conflicts: [
                {
                  subjectNodeId: "n1",
                  localState: "bogus_state" as unknown as TopologyObservationState,
                  remoteState: "stale",
                  resolution: "no_consensus_unknown",
                  localRecordedAtEpochMs: NOW,
                  remoteRecordedAtEpochMs: NOW,
                },
              ],
            }),
          ],
        }),
        code: "refused_unknown_vocabulary",
      },
      {
        input: INPUT({
          partitions: [
            partition("rec-1", {
              conflicts: [
                {
                  subjectNodeId: "n1",
                  localState: "observed",
                  remoteState: "stale",
                  resolution: "weird_resolution" as unknown as ConflictResolution,
                  localRecordedAtEpochMs: NOW,
                  remoteRecordedAtEpochMs: NOW,
                },
              ],
            }),
          ],
        }),
        code: "refused_unknown_vocabulary",
      },
    ];
    for (const c of cases) {
      expectRefused(buildMeshObservabilitySnapshot(c.input), c.code);
    }
  });

  it("provenance shape failures refuse: non-object invalid_input, wrong field types invalid_provenance", () => {
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [
            node("n1", {
              provenance: { source: 42, evidenceId: "ev-1", recordedAtEpochMs: NOW } as unknown as TopologyProvenance,
            }),
          ],
        }),
      ),
      "refused_invalid_provenance",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [
            node("n1", {
              provenance: { source: "governed_evidence", evidenceId: 42, recordedAtEpochMs: NOW } as unknown as TopologyProvenance,
            }),
          ],
        }),
      ),
      "refused_invalid_provenance",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [
            node("n1", {
              provenance: { source: "governed_evidence", evidenceId: "ev-1", recordedAtEpochMs: "x" } as unknown as TopologyProvenance,
            }),
          ],
        }),
      ),
      "refused_invalid_provenance",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          nodes: [node("n1", { provenance: undefined as unknown as TopologyProvenance })],
        }),
      ),
      "refused_invalid_input",
    );
  });

  it("structure violations refuse: hop sequence, role binding, and count integrity", () => {
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          routes: [
            routeEntry(
              mkRoute({
                hops: [
                  { hopIndex: 7, nodeId: "node-a", role: "origin" },
                ],
              }),
            ),
          ],
        }),
      ),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          routes: [
            routeEntry(
              mkRoute({ origin: { nodeId: "node-a", originFixed: false as unknown as true } }),
            ),
          ],
        }),
      ),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({
          routes: [
            routeEntry(
              mkRoute({ destination: { nodeId: "node-c", role: "origin" as unknown as "destination" } }),
            ),
          ],
        }),
      ),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ partitions: [partition("rec-1", { agreementCount: -1 })] })),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(INPUT({ partitions: [partition("rec-1", { agreementCount: 1.5 })] })),
      "refused_invalid_input",
    );
    expectRefused(
      buildMeshObservabilitySnapshot(
        INPUT({ partitions: [partition("rec-1", { localExclusiveCount: Number.NaN })] }),
      ),
      "refused_invalid_input",
    );
  });

  it("every observed refusal is a closed-set code with an explained refus-al and NO snapshot", () => {
    const bad: readonly ObservabilityInput[] = [
      null as unknown as ObservabilityInput,
      INPUT({ snapshotId: "k".repeat(129) }),
      INPUT({ nodes: [node("n1", { epochId: "epoch-x" })] }),
      INPUT({ nodes: [node("n1", { kind: "weird_kind" })] }),
      INPUT({
        nodes: [
          node("n1", {
            provenance: { source: 42, evidenceId: null, recordedAtEpochMs: NOW } as unknown as TopologyProvenance,
          }),
        ],
      }),
      INPUT({ asOfEpochMs: Number.NaN }),
      INPUT({ nodes: [node("n1"), node("n1")] }),
    ];
    const observed = new Set<string>();
    for (const input of bad) {
      const d = buildMeshObservabilitySnapshot(input);
      expect(d.ok).toBe(false);
      if (d.ok) continue;
      expect((OBSERVABILITY_REFUSAL_CODES as readonly string[]).includes(d.refusal)).toBe(true);
      observed.add(d.refusal);
      expect(d.explanation).toMatch(/refus/);
      expect(d.explanation.length).toBeGreaterThan(20);
      expect("snapshot" in d).toBe(false);
      expect("authority" in d).toBe(false);
      expect("controlPlane" in d).toBe(false);
    }
    // 7 of the 8 closed codes are reachable by construction; refused_unknown is
    // the unmapped catch-all (fail-closed by definition, never asserted reachable).
    expect(observed.size).toBe(7);
  });
});
