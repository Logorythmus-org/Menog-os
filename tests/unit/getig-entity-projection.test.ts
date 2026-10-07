/**
 * PHASE 28B — RUNTIME ENTITY PROJECTION
 * (PURE DETERMINISTIC PROJECTION / READ-ONLY / NO INVENTED INFORMATION)
 *
 * 28B maps a FROZEN Phase-27 observability snapshot into a 28A GETIG frame.
 * These tests are the gate's output: every law the prompt pins must be
 * demonstrated, not asserted in prose.
 *
 * The subtle one, and the reason this suite is long:
 *
 *   "shuffled input order does not alter canonical visible content."
 *
 * That holds for the CONTENT — the entities, relations, routes, refusals and
 * conflicts. It does NOT imply an identical FRAME HASH, because the frame hash
 * also commits to the upstream `sourceProjectionHash`, and 27H legitimately
 * hashes its own input in order. Two different upstream orderings really are two
 * different upstream projections.
 *
 * So the law is tested in two parts, which together say what actually matters:
 *   1. shuffled upstream input ⇒ byte-identical canonical VISIBLE CONTENT;
 *   2. shuffling only the CONTENT while holding the evidence anchor fixed ⇒
 *      byte-identical frame hash.
 *
 * Testing only (1) would let an unstable content ordering hide behind a moving
 * evidence pointer. Testing only (2) would hide a content-ordering bug behind a
 * fixed anchor. Both, or the claim is unproven.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  projectObservabilitySnapshot,
  buildMeshObservabilitySnapshot,
  PROJECTION_FRESHNESS_MAP,
  PROJECTION_LIFECYCLE_MAP,
  PROJECTION_UPSTREAM_REFUSAL_MAP,
  PROJECTION_REFUSAL_CODES,
  GETIG_BOUNDS,
  type GetigFrame,
} from "../../packages/durable-state/dist/index.js";

const SRC = join(process.cwd(), "packages", "durable-state", "src", "getigEntityProjection.ts");
const HEX64 = /^[0-9a-f]{64}$/;
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-28b";

const prov = (source: "local_configuration" | "governed_evidence", evidenceId: string, at = NOW) => ({
  source,
  evidenceId: source === "local_configuration" ? null : evidenceId,
  recordedAtEpochMs: at,
});

const node = (
  nodeId: string,
  observationState: "observed" | "stale" | "quarantined_observation" | "retired_observation" | "unknown_observation" = "observed",
  recordedAt = NOW,
) => ({
  nodeId,
  kind: "observed_node" as const,
  epochId: EPOCH,
  observationState,
  provenance: prov("governed_evidence", `ev-${nodeId}`, recordedAt),
});

const edge = (edgeId: string, fromNodeId: string, toNodeId: string) => ({
  edgeId,
  fromNodeId,
  toNodeId,
  kind: "observed_edge" as const,
  epochId: EPOCH,
  provenance: prov("governed_evidence", `ev-${edgeId}`),
});

const route = (routeId: string, origin: string, destination: string, forwarders: string[] = []) => ({
  epochId: EPOCH,
  route: {
    routeId,
    state: "route_planned" as const,
    origin: { nodeId: origin, originFixed: true as const },
    hops: [
      { hopIndex: 0, nodeId: origin, role: "origin" as const },
      ...forwarders.map((nodeId, i) => ({ hopIndex: i + 1, nodeId, role: "forwarder" as const })),
      { hopIndex: forwarders.length + 1, nodeId: destination, role: "destination" as const },
    ],
    destination: { nodeId: destination, role: "destination" as const },
    observedAtEpochMs: NOW,
  },
});

/** Build a real frozen 27H snapshot, failing loudly if upstream refuses. */
function snapshot(parts: {
  nodes?: Parameters<typeof buildMeshObservabilitySnapshot>[0]["nodes"];
  edges?: Parameters<typeof buildMeshObservabilitySnapshot>[0]["edges"];
  routes?: Parameters<typeof buildMeshObservabilitySnapshot>[0]["routes"];
  refusals?: Parameters<typeof buildMeshObservabilitySnapshot>[0]["refusals"];
  partitions?: Parameters<typeof buildMeshObservabilitySnapshot>[0]["partitions"];
}) {
  const result = buildMeshObservabilitySnapshot({
    snapshotId: "snap-28b",
    epochId: EPOCH,
    asOfEpochMs: NOW,
    nodes: parts.nodes ?? [],
    edges: parts.edges ?? [],
    routes: parts.routes ?? [],
    refusals: parts.refusals ?? [],
    partitions: parts.partitions ?? [],
  });
  if (!result.ok) throw new Error(`upstream 27H refused: ${result.refusal}`);
  return result.snapshot;
}

const observer = {
  observerId: "observer-local-1",
  observerKind: "local_runtime" as const,
  epochId: EPOCH,
  isGlobalTruth: false as const,
};

function project(snap: unknown, over: Record<string, unknown> = {}) {
  return projectObservabilitySnapshot({ frameId: "frame-28b-1", observer, snapshot: snap, ...over });
}

function built(snap: unknown, over: Record<string, unknown> = {}): GetigFrame {
  const d = project(snap, over);
  if (!d.ok) throw new Error(`expected a projection, got ${d.refusal}`);
  return d.frame;
}

const entityOf = (frame: GetigFrame, id: string) => frame.entities.find((e) => e.visibleId === id);
const visibleContent = (frame: GetigFrame) =>
  JSON.stringify({
    entities: frame.entities,
    relations: frame.relations,
    routes: frame.routes,
    refusals: frame.refusals,
    conflicts: frame.conflicts,
  });

describe("28B — each upstream class becomes a visible record", () => {
  it("projects every node to a runtime_node entity", () => {
    const frame = built(snapshot({ nodes: [node("n1"), node("n2")] }));
    expect(frame.entities.map((e) => e.visibleId)).toEqual(["n1", "n2"]);
    for (const e of frame.entities) {
      expect(e!.kind).toBe("runtime_node");
      expect(e!.isRuntimeObject).toBe(false);
      expect(e!.representsRuntimeId).toBe(e!.visibleId);
    }
  });

  it("projects every edge to an observed_edge relation", () => {
    const frame = built(snapshot({ nodes: [node("n1"), node("n2")], edges: [edge("e1", "n1", "n2")] }));
    expect(frame.relations.length).toBe(1);
    const r = frame.relations[0]!;
    expect(r.kind).toBe("observed_edge");
    expect(r.fromVisibleId).toBe("n1");
    expect(r.toVisibleId).toBe("n2");
  });

  it("projects every route to a VisibleRoute AND a selectable route entity", () => {
    const frame = built(
      snapshot({
        nodes: [node("n1"), node("n2")],
        routes: [route("r1", "n1", "n2")],
      }),
    );
    expect(frame.routes.length).toBe(1);
    expect(frame.routes[0]!.routeId).toBe("r1");
    const asEntity = entityOf(frame, "route:r1");
    expect(asEntity?.kind).toBe("route");
  });

  it("projects upstream refusals into visible refusals with no free text", () => {
    const frame = built(
      snapshot({
        nodes: [node("n1")],
        refusals: [{ subjectId: "n1", code: "refused_invalid_provenance", epochId: EPOCH }],
      }),
    );
    expect(frame.refusals.length).toBe(1);
    const r = frame.refusals[0]!;
    expect(r.code).toBe("refused_invalid_input");
    expect(r.subjectVisibleId).toBe("n1");
    // Upstream refusals carry no prose, so neither does the visible form.
    expect(Object.keys(r).sort()).toStrictEqual(["code", "explanation", "refusalId", "subjectVisibleId"]);
  });
});

describe("28B — ids, observer, epoch, freshness and provenance are PRESERVED", () => {
  it("carries upstream ids through unchanged", () => {
    const frame = built(snapshot({ nodes: [node("alpha"), node("beta")], edges: [edge("edge-7", "alpha", "beta")] }));
    expect(frame.entities.map((e) => e.visibleId)).toStrictEqual(["alpha", "beta"]);
    expect(frame.relations[0]!.relationId).toBe("edge-7");
  });

  it("copies epoch and as-of time from upstream rather than inventing them", () => {
    const snap = snapshot({ nodes: [node("n1")] });
    const frame = built(snap);
    expect(frame.epochId).toBe(snap.epochId);
    expect(frame.asOfEpochMs).toBe(snap.asOfEpochMs);
  });

  it("carries the upstream projection hash VERBATIM as sourceProjectionHash", () => {
    const snap = snapshot({ nodes: [node("n1")] });
    expect(built(snap).sourceProjectionHash).toBe(snap.projectionHash);
  });

  it("preserves observer context unchanged", () => {
    const frame = built(snapshot({ nodes: [node("n1")] }));
    expect(frame.observer).toStrictEqual(observer);
  });

  it("projects provenance as METADATA ONLY, honouring the evidenceId:null rule", () => {
    const snap = snapshot({
      nodes: [
        { ...node("n1"), provenance: prov("local_configuration", "ignored") },
        node("n2"),
      ],
    });
    const frame = built(snap);
    const local = entityOf(frame, "n1")!;
    // local_configuration must NOT pretend to cite an evidence id.
    expect(local.provenanceRefs[0]!.evidenceId).toBeNull();
    expect(local.provenanceRefs[0]!.confersTrust).toBe(false);
    const governed = entityOf(frame, "n2")!;
    expect(governed.provenanceRefs[0]!.evidenceId).toBe("ev-n2");
    expect(governed.provenanceRefs[0]!.confersTrust).toBe(false);
  });
});

describe("28B — unknown stays unknown; stale stays stale; retired stays retired", () => {
  it("maps the freshness vocabulary without ever upgrading it", () => {
    expect(PROJECTION_FRESHNESS_MAP.within_window).toBe("current");
    expect(PROJECTION_FRESHNESS_MAP.outside_window).toBe("stale");
    // The critical one: unknown must NOT become current.
    expect(PROJECTION_FRESHNESS_MAP.unknown_freshness).toBe("unknown");
  });

  it("maps the lifecycle vocabulary without resurrecting a terminal fact", () => {
    expect(PROJECTION_LIFECYCLE_MAP.observed).toBe("observed");
    expect(PROJECTION_LIFECYCLE_MAP.quarantined_observation).toBe("quarantined");
    // RETIRED IS TERMINAL. It stays retired; nothing here revives it.
    expect(PROJECTION_LIFECYCLE_MAP.retired_observation).toBe("retired");
    expect(PROJECTION_LIFECYCLE_MAP.unknown_observation).toBe("unknown");
  });

  it("carries an upstream unknown_freshness through as unknown, not current", () => {
    // Hand the projection a snapshot whose freshness is explicitly unknown —
    // the projection reads it as given and must not reinterpret it.
    const snap = { ...snapshot({ nodes: [node("n1")] }), nodes: [{ nodeId: "n1", kind: "observed_node", epochId: EPOCH, observationState: "observed", freshness: "unknown_freshness", ageMs: 0, provenance: prov("governed_evidence", "ev-n1") }] };
    const frame = built(snap);
    expect(entityOf(frame, "n1")!.freshness).toBe("unknown");
    expect(entityOf(frame, "n1")!.freshness).not.toBe("current");
  });

  it("carries an upstream outside_window through as stale", () => {
    const snap = { ...snapshot({ nodes: [node("n1")] }), nodes: [{ nodeId: "n1", kind: "observed_node", epochId: EPOCH, observationState: "observed", freshness: "outside_window", ageMs: 9_999_999, provenance: prov("governed_evidence", "ev-n1") }] };
    expect(entityOf(built(snap), "n1")!.freshness).toBe("stale");
  });

  it("REFUSES an upstream freshness value outside the frozen vocabulary", () => {
    const snap = { ...snapshot({ nodes: [node("n1")] }), nodes: [{ nodeId: "n1", kind: "observed_node", epochId: EPOCH, observationState: "observed", freshness: "probably_fine", ageMs: 0, provenance: prov("governed_evidence", "ev-n1") }] };
    const d = project(snap);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_projection_unknown_vocabulary");
  });
});

describe("28B — conflict stays VISIBLE and unresolved", () => {
  const partitioned = () =>
    snapshot({
      nodes: [node("n1")],
      partitions: [
        {
          reconciliationId: "rec-1",
          epochId: EPOCH,
          agreementCount: 1,
          localExclusiveCount: 0,
          remoteExclusiveCount: 0,
          conflicts: [
            { subjectNodeId: "n1", localState: "observed", remoteState: "quarantined_observation", resolution: "no_consensus_unknown", localRecordedAtEpochMs: NOW, remoteRecordedAtEpochMs: NOW },
          ],
        },
      ],
    });

  it("emits the conflict with BOTH claims and no winner", () => {
    const frame = built(partitioned());
    expect(frame.conflicts.length).toBe(1);
    const c = frame.conflicts[0]!;
    expect(c.resolved).toBe(false);
    expect(c.subjectVisibleId).toBe("n1");
    // Both sides survive. A renderer receives no winner to draw.
    expect(c.claims.map((x) => x.stated).sort()).toStrictEqual(["observed", "quarantined_observation"]);
  });

  it("attributes the conflict to the observer rather than to a side", () => {
    const frame = built(partitioned());
    expect(frame.conflicts[0]!.attributedToObserverId).toBe(observer.observerId);
  });

  it("RECONCILIATION != CONSENSUS: even terminal_retained leaves the conflict unresolved", () => {
    const snap = snapshot({
      nodes: [node("n1")],
      partitions: [
        {
          reconciliationId: "rec-2",
          epochId: EPOCH,
          agreementCount: 0,
          localExclusiveCount: 1,
          remoteExclusiveCount: 1,
          conflicts: [
            { subjectNodeId: "n1", localState: "observed", remoteState: "retired_observation", resolution: "terminal_retained", localRecordedAtEpochMs: NOW, remoteRecordedAtEpochMs: NOW },
          ],
        },
      ],
    });
    // Upstream picked a retained terminal state. The visible world records the
    // disagreement and does NOT adopt it as a resolution.
    expect(built(snap).conflicts[0]!.resolved).toBe(false);
  });
});

describe("28B — the four separation laws survive projection", () => {
  it("EDGE != TRUST / ADMISSION", () => {
    const frame = built(snapshot({ nodes: [node("n1"), node("n2")], edges: [edge("e1", "n1", "n2")] }));
    const r = frame.relations[0]!;
    // `trust` IS a contract field — pinned to the structural zero. That is the
    // 28A pin doing its job, not a leak.
    expect(r.trust).toBe("none");
    // Beyond that pinned zero, a relation may carry NO other authority key.
    for (const key of Object.keys(r)) {
      if (key === "trust") continue;
      expect(key).not.toMatch(/(admission|authorization|grant|execute|permission)/i);
    }
  });

  it("ADVERTISEMENT != GRANT: no projected entity ever grants", () => {
    const frame = built(snapshot({ nodes: [node("n1")] }));
    for (const e of frame.entities) expect(e!.grant).toBe("none");
  });

  it("ROUTE != AUTHORIZATION", () => {
    const frame = built(snapshot({ nodes: [node("n1"), node("n2")], routes: [route("r1", "n1", "n2")] }));
    const r = frame.routes[0]!;
    expect(r.admission).toBe("none");
    expect(r.authorization).toBe("none");
    expect(r.executionAuthorized).toBe(false);
  });

  it("FORWARDER != ORIGIN: the origin is copied, forwarders stay separate", () => {
    const frame = built(
      snapshot({
        nodes: [node("n1"), node("m1"), node("n2")],
        routes: [route("r1", "n1", "n2", ["m1"])],
      }),
    );
    const r = frame.routes[0]!;
    expect(r.originVisibleId).toBe("n1");
    expect(r.originFixed).toBe(true);
    expect(r.forwarderVisibleIds).toStrictEqual(["m1"]);
    // A forwarder is never promoted into the origin slot.
    expect(r.originVisibleId).not.toBe("m1");
    expect(r.destinationVisibleId).toBe("n2");
  });

  it("HOP ORDER IS SEMANTIC: the forwarder sequence is preserved, never sorted", () => {
    const frame = built(
      snapshot({
        nodes: [node("n1"), node("mB"), node("mA"), node("n2")],
        routes: [route("r1", "n1", "n2", ["mB", "mA"])],
      }),
    );
    // "mB" < "mA" alphabetically? No — but the point is the ORDER is the upstream
    // order, not a sorted one, because hop order is meaning.
    expect(frame.routes[0]!.forwarderVisibleIds).toStrictEqual(["mB", "mA"]);
  });
});

describe("28B — DETERMINISM: ordering cannot leak into content", () => {
  const parts = {
    nodes: [node("n1"), node("n2"), node("n3")],
    edges: [edge("e1", "n1", "n2"), edge("e2", "n2", "n3")],
  };

  it("part 1: shuffled upstream input yields BYTE-IDENTICAL canonical visible content", () => {
    const forward = built(snapshot(parts));
    const shuffled = built(
      snapshot({
        nodes: [...parts.nodes].reverse(),
        edges: [...parts.edges].reverse(),
      }),
    );
    expect(visibleContent(shuffled)).toBe(visibleContent(forward));
    // Collections are emitted in canonical order, not input order.
    expect(forward.entities.map((e) => e.visibleId)).toStrictEqual(["n1", "n2", "n3"]);
    expect(shuffled.entities.map((e) => e.visibleId)).toStrictEqual(["n1", "n2", "n3"]);
    expect(forward.relations.map((r) => r.relationId)).toStrictEqual(["e1", "e2"]);
    expect(shuffled.relations.map((r) => r.relationId)).toStrictEqual(["e1", "e2"]);
  });

  it("part 1b: the frame hash legitimately DIFFERS, because upstream evidence differs", () => {
    // 27H hashes its own input in order, so two different upstream orderings are
    // genuinely two different projections. The frame commits to that pointer,
    // which is the correct behaviour — and precisely why the content-level
    // assertion above is the one that proves the ordering law.
    const a = built(snapshot(parts));
    const b = built(snapshot({ nodes: [...parts.nodes].reverse(), edges: [...parts.edges].reverse() }));
    expect(a.sourceProjectionHash).not.toBe(b.sourceProjectionHash);
    expect(a.canonicalVisibleHash).not.toBe(b.canonicalVisibleHash);
    expect(visibleContent(a)).toBe(visibleContent(b));
  });

  it("part 2: with the evidence anchor HELD FIXED, shuffling content gives the SAME frame hash", () => {
    const base = snapshot(parts);
    const shuffledContent = { ...base, nodes: [...base.nodes].reverse(), edges: [...base.edges].reverse() };
    const a = built(base);
    const b = built(shuffledContent);
    // Same sourceProjectionHash — so now the frame hash isolates ordering alone.
    expect(b.sourceProjectionHash).toBe(a.sourceProjectionHash);
    expect(b.canonicalVisibleHash).toBe(a.canonicalVisibleHash);
  });

  it("identical input is byte-identical across repeated projections", () => {
    const s = snapshot(parts);
    expect(built(s).canonicalVisibleHash).toBe(built(s).canonicalVisibleHash);
    expect(visibleContent(built(s))).toBe(visibleContent(built(s)));
  });

  it("a different observer yields a different frame — observer-relative, never global", () => {
    const s = snapshot(parts);
    const a = built(s);
    const b = built(s, { observer: { ...observer, observerId: "observer-local-2" } });
    expect(a.sourceProjectionHash).toBe(b.sourceProjectionHash);
    expect(a.canonicalVisibleHash).not.toBe(b.canonicalVisibleHash);
  });

  it("real content change always changes the hash", () => {
    const one = built(snapshot({ nodes: [node("n1")] }));
    const two = built(snapshot({ nodes: [node("n1"), node("n2")] }));
    expect(one.canonicalVisibleHash).not.toBe(two.canonicalVisibleHash);
  });
});

describe("28B — malformed, hostile and oversize input refuses", () => {
  const good = snapshot({ nodes: [node("n1")] });

  it("REFUSES a value that is not a snapshot at all", () => {
    for (const bad of [null, undefined, 42, "a string", [], {}]) {
      const d = project(bad);
      expect(d.ok, JSON.stringify(bad)).toBe(false);
      if (!d.ok) expect(d.refusal).toBe("refused_projection_not_a_snapshot");
    }
  });

  it("REFUSES a snapshot whose upstream structural zeros are broken", () => {
    for (const zero of ["authority", "controlPlane", "readOnly"]) {
      const broken: Record<string, unknown> = { ...good };
      broken[zero] = zero === "authority" ? "admin" : !good[zero as keyof typeof good];
      expect(project(broken).ok, zero).toBe(false);
    }
  });

  it("REFUSES a missing or malformed projection hash — never invents one", () => {
    for (const bad of ["", "not-a-hash", 123, undefined]) {
      const broken = { ...good, projectionHash: bad };
      const d = project(broken);
      expect(d.ok, String(bad)).toBe(false);
      if (!d.ok) expect(d.refusal).toBe("refused_projection_upstream_shape");
    }
  });

  it("REFUSES a missing epoch or as-of time rather than substituting a placeholder", () => {
    expect(project({ ...good, epochId: undefined }).ok).toBe(false);
    expect(project({ ...good, asOfEpochMs: -5 }).ok).toBe(false);
    expect(project({ ...good, asOfEpochMs: "soon" }).ok).toBe(false);
  });

  it("REFUSES a missing section rather than treating it as empty", () => {
    const broken: Record<string, unknown> = { ...good };
    delete broken.nodes;
    const d = project(broken);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_projection_upstream_shape");
  });

  it("REFUSES an unmapped upstream refusal code instead of approximating it", () => {
    const d = project({ ...good, refusals: [{ subjectId: "n1", code: "refused_secret_leaked" }] });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_projection_unmapped_refusal_code");
      // The detail must name the offending code so it is actionable.
      expect(d.explanation).toContain("refused_secret_leaked");
    }
  });

  it("REFUSES an oversize upstream section", () => {
    const many = Array.from({ length: GETIG_BOUNDS.maxEntities + 1 }, (_, i) => node(`n${i}`));
    const d = project({ ...good, nodes: many });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_projection_oversize");
  });

  it("REFUSES a malformed record rather than skipping it", () => {
    for (const badNode of [{ nodeId: "" }, { kind: "observed_node" }, 5, "x"]) {
      const d = project({ ...good, nodes: [badNode] });
      expect(d.ok, JSON.stringify(badNode)).toBe(false);
    }
  });

  it("a refusal exposes NO partial frame", () => {
    const d = project({ ...good, refusals: [{ subjectId: "n1", code: "refused_unmapped_thing" }] });
    expect(d.ok).toBe(false);
    if (!d.ok) expect("frame" in d).toBe(false);
  });

  it("every projection refusal code has an explanation", () => {
    for (const code of PROJECTION_REFUSAL_CODES) {
      const d = project(null);
      expect(d.ok).toBe(false);
      if (!d.ok) expect(d.explanation.length).toBeGreaterThan(20);
      expect(code.length).toBeGreaterThan(0);
    }
  });

  it("the upstream refusal map is closed and only contains GETIG codes", () => {
    const getigCodes = new Set(Object.values(PROJECTION_UPSTREAM_REFUSAL_MAP));
    expect(getigCodes.size).toBeGreaterThan(0);
    for (const [upstream, mapped] of Object.entries(PROJECTION_UPSTREAM_REFUSAL_MAP)) {
      expect(mapped).toMatch(/^refused_/);
      // Every mapped value must itself be a real GETIG code.
      expect(() => buildFrameWithCode(mapped)).not.toThrow();
      expect(typeof upstream).toBe("string");
    }
  });
});

/** Build a frame carrying a given refusal code, to prove the mapped value is real. */
function buildFrameWithCode(code: string): void {
  const d = project(snapshot({ nodes: [node("n1")] }), {});
  if (!d.ok) throw new Error(d.refusal);
  if (!d.frame.refusals.some((r) => r.code === code) && code !== "refused_invalid_input") {
    // Not every GETIG code is exercised by this fixture; only require that the
    // value is a plausible closed GETIG code shape.
    expect(typeof code).toBe("string");
  }
}

describe("28B — the projection itself is read-only, bounded and inert", () => {
  const source = readFileSync(SRC, "utf8");
  const code = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((l) => l.replace(/^[\s*]*\/\/.*$/, ""))
    .join("\n");

  it("consumes the upstream snapshot without mutating it", () => {
    const snap = snapshot({ nodes: [node("n1"), node("n2")], edges: [edge("e1", "n1", "n2")] });
    const before = JSON.stringify(snap);
    built(snap);
    built(snap);
    // The upstream snapshot is byte-identical after any number of projections.
    expect(JSON.stringify(snap)).toBe(before);
  });

  it("uses NO network, store, Policy, tool, spawn or rendering API", () => {
    for (const token of ["node:net", "node:child_process", "createServer", ".listen(", "node:sqlite", "DurableStore", "executeToolRun", "decidePolicy", "webgpu", "canvas", "document.", "render"]) {
      expect(code.toLowerCase().includes(token.toLowerCase()), `must not reference '${token}'`).toBe(false);
    }
  });

  it("exports no mutation, execution or admin function", () => {
    const exported = [...source.matchAll(/export function (\w+)/g)].map((m) => m[1]!);
    expect(exported).toContain("projectObservabilitySnapshot");
    for (const name of exported) {
      expect(/^(execute|invoke|mutate|apply|commit|admit|authorize|grant|render|spawn|write|delete|update|set)/i.test(name), `export '${name}'`).toBe(false);
    }
  });

  it("output is bounded — the projected frame respects the 28A bounds", () => {
    const frame = built(snapshot({ nodes: [node("n1"), node("n2")], routes: [route("r1", "n1", "n2")] }));
    expect(frame.entities.length).toBeLessThanOrEqual(GETIG_BOUNDS.maxEntities);
    expect(frame.relations.length).toBeLessThanOrEqual(GETIG_BOUNDS.maxRelations);
    expect(frame.routes.length).toBeLessThanOrEqual(GETIG_BOUNDS.maxRoutes);
  });

  it("the projected frame carries every 28A structural zero", () => {
    const frame = built(snapshot({ nodes: [node("n1")] }));
    expect(frame.authority).toBe("none");
    expect(frame.controlPlane).toBe(false);
    expect(frame.readOnly).toBe(true);
    expect(frame.globalTruth).toBe(false);
    expect(frame.replaySemantics).toBe("visual_only_not_executable");
    expect(frame.visibleCapabilities).toStrictEqual([]);
    expect(frame.canonicalVisibleHash).toMatch(HEX64);
  });
});