/**
 * PHASE 29R1 — ROUTE ENDPOINT ANCHOR REPAIR (29D-OBS-2) — REGRESSION SUITE
 *
 * MODE: NARROW REPAIR PROOF / NO GPU / NO NEW DEPENDENCY.
 *
 * 29D-OBS-2: 29B emitted relation endpoints as synthetic `route:<role>`
 * anchors. No drawable primitive resolves that name, so all three frozen route
 * relations entered the GPU plan carrying the no-anchor sentinel and a route
 * could not be drawn faithfully. This suite proves the repair, not the defect:
 *
 *   1. all three frozen route relations resolve (compiler AND plan bytes)
 *   2. roles stay distinct
 *   3. an invalid endpoint refuses (fails closed, never maps to 0)
 *   4. a duplicate/colliding anchor refuses (never silently resolved)
 *   5. deterministic hashes remain — sceneHash/layoutHash are the exact
 *      pre-repair values, because the repair changed no semantic content and
 *      no coordinate
 *   6. Phase-28 semantics unchanged — the relation (relationId, role)
 *      projection is byte-for-byte the pre-repair projection
 *
 * The pre-repair values pinned below were measured by running the frozen
 * compile BEFORE the source edit (transcript + PROMPT_29R1_REPORT.md), not
 * derived from the repaired code.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import {
  ROUTE_ROLE_ORDER,
  SCENE_COMPILER_REFUSAL_CODES,
  buildGpuRenderPlan,
  compileGetigScene,
  getigVisualSemanticRank,
  runGetigEndToEndScenario,
  type GpuRenderPlanValue,
} from "../../packages/durable-state/src/index.js";

const RUNTIME_HASH = "5555666677778888";

// ── pre-repair snapshot (measured BEFORE any source edit) ────────────────────
const PRE_REPAIR_SCENE_HASH = "7c7540f8d4b6d31bcfd15af7668009c2050f248524581299b260f3544e034f91";
const PRE_REPAIR_LAYOUT_HASH = "de62ad3848d8246262d98dbcecf841e4debc0479b63d1c47ff09f53bb58e5b9f";
/** sha256 of the topology buffer when every endpoint was the sentinel. */
const PRE_REPAIR_TOPOLOGY_SENTINEL_HASH = "318020b006c186d3475a7583bb45227bd1a46817a2e53f703444ebec01d1b4b4";

const scenario = runGetigEndToEndScenario();
if (!scenario.ok) throw new Error(`frozen Phase-28 scenario refused: ${scenario.refusal}`);
const MAPPING = scenario.scenario.mapping;

const compiled = compileGetigScene({ mapping: MAPPING, runtimeStateHash: RUNTIME_HASH });
if (!compiled.ok) throw new Error(`frozen 29B compile refused: ${compiled.refusal}`);
const SCENE = compiled.scene;

const planDecision = buildGpuRenderPlan({ scene: SCENE });
if (!planDecision.ok) throw new Error(`frozen 29D plan refused: ${planDecision.refusal}`);
const PLAN: GpuRenderPlanValue = planDecision.plan;

const PRIMITIVE_IDS = new Set(SCENE.primitives.map((p) => p.primitiveId));

const sha256OfWords = (words: Uint32Array): string =>
  createHash("sha256").update(Buffer.from(words.buffer, words.byteOffset, words.byteLength)).digest("hex");

const token = (over: Record<string, unknown>): Record<string, unknown> => ({
  tokenId: `t:${String(over.subjectVisibleId ?? "s")}:${String(over.axis ?? "knowledge")}`,
  axis: over.axis ?? "knowledge",
  semanticValue: over.semanticValue ?? "unknown",
  semanticRank: 0,
  subjectVisibleId: over.subjectVisibleId ?? "s1",
  subjectCollection: over.subjectCollection ?? "entities",
  claim: "descriptive_only",
  authority: "none",
  mutation: "none",
  executable: false,
  ...over,
});

const mini = (tokens: readonly unknown[]) => ({
  schemaVersion: "menog-getig-visual/v0",
  frameId: "frame-29r1",
  observerId: "obs-29r1",
  mappingHash: "abcdef0123456789",
  tokens,
});

const routeRootToken = (subjectVisibleId: string) =>
  token({
    axis: "route_state",
    semanticValue: "unknown",
    semanticRank: getigVisualSemanticRank("route_state", "unknown"),
    subjectVisibleId,
    subjectCollection: "routes",
  });

const routeRoleToken = (subjectVisibleId: string, role: string) =>
  token({
    axis: "route_role",
    semanticValue: role,
    semanticRank: getigVisualSemanticRank("route_role", role),
    subjectVisibleId,
    subjectCollection: "routes",
  });

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — all three frozen route relations resolve", () => {
  it("every fromId and toId names a drawable primitive — no synthetic anchor survives", () => {
    expect(SCENE.relations).toHaveLength(3);
    for (const rel of SCENE.relations) {
      expect(PRIMITIVE_IDS.has(rel.fromId), `${rel.relationId}.fromId=${rel.fromId} is not drawable`).toBe(true);
      expect(PRIMITIVE_IDS.has(rel.toId), `${rel.relationId}.toId=${rel.toId} is not drawable`).toBe(true);
      // The exact defect: `route:origin` / `route:forwarder` / `route:destination`.
      expect(rel.fromId).not.toMatch(/^route:(origin|forwarder|destination)$/);
      expect(rel.toId).not.toMatch(/^route:(origin|forwarder|destination)$/);
    }
  });

  it("the chain runs route root -> origin -> forwarder -> destination (order preserved)", () => {
    const byRole = new Map(SCENE.relations.map((r) => [r.role as string, r] as const));
    expect([...byRole.keys()].sort()).toEqual(["destination", "forwarder", "origin"]);
    const origin = byRole.get("origin");
    const forwarder = byRole.get("forwarder");
    const destination = byRole.get("destination");
    if (!origin || !forwarder || !destination) throw new Error("a frozen route relation is missing");
    // Phase-28 emits role subjects as `${routeId}#${role...}`; the route root
    // is the subject carrying the route_state token.
    expect(origin.fromId).toBe("route-28j-1");
    expect(origin.toId).toBe("route-28j-1#origin");
    expect(forwarder.fromId).toBe(origin.toId);
    expect(forwarder.toId).toBe("route-28j-1#forwarder:node-relay");
    expect(destination.fromId).toBe(forwarder.toId);
    expect(destination.toId).toBe("route-28j-1#destination");
  });

  it("the GPU plan's topology buffer holds REAL indices — no sentinel word, byte-verified", () => {
    // Reconstruct what the plan must have written: relations sorted by
    // relationId, endpoints as indices into the primitiveId-sorted list.
    const sortedPrimitiveIds = SCENE.primitives.map((p) => p.primitiveId).sort((a, b) => a.localeCompare(b));
    const indexOf = new Map(sortedPrimitiveIds.map((id, i) => [id, i] as const));
    const sortedRelations = [...SCENE.relations].sort((a, b) => a.relationId.localeCompare(b.relationId));
    const expected = new Uint32Array(sortedRelations.length * 2);
    sortedRelations.forEach((r, i) => {
      expected[i * 2 + 0] = indexOf.get(r.fromId) as number;
      expected[i * 2 + 1] = indexOf.get(r.toId) as number;
    });
    expect([...expected].every((w) => w !== 0xffffffff), "a sentinel word reached the frozen topology buffer").toBe(true);

    const topology = PLAN.buffers.find((b) => b.bufferId === "buf.index.topology");
    expect(topology).toBeDefined();
    expect(topology?.recordCount).toBe(3 * 2);
    expect(topology?.contentHash).toBe(sha256OfWords(expected));
    // And those bytes are NOT the pre-repair sentinel bytes: the repair moved
    // the hash honestly, by changing the content.
    expect(topology?.contentHash).not.toBe(PRE_REPAIR_TOPOLOGY_SENTINEL_HASH);
  });

  it("the plan no longer reports an unresolved relation endpoint", () => {
    const text = PLAN.notProven.join(" | ");
    expect(text).not.toContain("relation endpoint");
    expect(text).not.toContain("no-anchor sentinel");
    // The honest incompleteness lines remain — the repair proves endpoints,
    // not rendering.
    expect(text).toContain("no pixel readback was verified");
    expect(PLAN.pixelOutputVerified).toBe(false);
    expect(PLAN.completeness).toBe("incomplete");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — roles stay distinct", () => {
  it("the three frozen relations carry three distinct roles in ROUTE_ROLE_ORDER", () => {
    const roles = SCENE.relations.map((r) => r.role);
    expect(new Set(roles).size).toBe(3);
    expect(roles).toEqual([...ROUTE_ROLE_ORDER]);
  });

  it("role identity stays separate from endpoint identity (role is not encoded in an endpoint)", () => {
    for (const rel of SCENE.relations) {
      // The old defect fused role INTO the endpoint (`route:origin`). Endpoints
      // must now be plain subject ids, and the role lives only in `role`.
      expect(rel.fromId).not.toContain(rel.role);
      expect(rel.toId.endsWith(`#${rel.role}`) || rel.toId.includes(`#${rel.role}:`)).toBe(true);
      expect(rel.authorizes).toBe(false);
      expect(rel.trust).toBe("none");
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — an invalid endpoint refuses (fails closed, never maps to 0)", () => {
  it("a role subject whose route root does not exist is refused", () => {
    const r = compileGetigScene({
      mapping: mini([routeRoleToken("orphan#origin", "origin")]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_scene_route_anchor_unresolved");
    expect(r.explanation).toContain("orphan#origin");
    expect(r.code).toBe("scene_refused");
    expect(r.scene).toBeNull();
    expect(r.partialSceneEmitted).toBe(false);
    expect(r.authority).toBe("none");
    expect(SCENE_COMPILER_REFUSAL_CODES).toContain(r.refusal);
  });

  it("a role subject with no route structure at all is refused", () => {
    const r = compileGetigScene({
      mapping: mini([routeRoleToken("bare-role", "origin")]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_scene_route_anchor_unresolved");
    expect(r.scene).toBeNull();
  });

  it("a prefix subject that is NOT a route does not anchor a relation", () => {
    // `x` exists as an ordinary entity, so a naive prefix match would anchor
    // `x#origin` to it. Only a subject carrying route_state is a route root;
    // anything else must refuse rather than bind to the wrong drawable.
    const r = compileGetigScene({
      mapping: mini([
        token({ axis: "knowledge", semanticValue: "known", semanticRank: 1, subjectVisibleId: "x" }),
        routeRoleToken("x#origin", "origin"),
      ]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_scene_route_anchor_unresolved");
  });

  it("the refusal is real: the same shape compiles once the route root exists", () => {
    // Positive control so the three refusals above prove the branch fires on
    // the missing root, not on some incidental property of the input.
    const r = compileGetigScene({
      mapping: mini([routeRootToken("x"), routeRoleToken("x#origin", "origin")]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok, r.ok ? "" : r.refusal).toBe(true);
    if (!r.ok) return;
    expect(r.scene.relations).toHaveLength(1);
    expect(r.scene.relations[0]?.fromId).toBe("x");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — a duplicate/colliding anchor refuses (never silently resolved)", () => {
  it("a role subject claimed by two route roots is refused as ambiguous", () => {
    // Routes `a` and `a#b` both exist; `a#b#origin` prefix-matches BOTH
    // (`a` + `#b#origin`, and `a#b` + `#origin`). Guessing the longest prefix
    // would bind silently — the repair refuses instead, so a colliding anchor
    // can never resolve to one of two routes by accident of ordering.
    const r = compileGetigScene({
      mapping: mini([routeRootToken("a"), routeRootToken("a#b"), routeRoleToken("a#b#origin", "origin")]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_scene_route_anchor_ambiguous");
    expect(r.explanation).toContain("more than one route root");
    expect(r.explanation).toContain("a, a#b");
    expect(r.scene).toBeNull();
    expect(r.partialSceneEmitted).toBe(false);
    expect(SCENE_COMPILER_REFUSAL_CODES).toContain(r.refusal);
  });

  it("the non-colliding subject in the same mapping still binds (the refusal is the branch, not the input)", () => {
    const r = compileGetigScene({
      mapping: mini([routeRootToken("a"), routeRootToken("a#b"), routeRoleToken("a#origin", "origin")]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok, r.ok ? "" : r.refusal).toBe(true);
    if (!r.ok) return;
    // `a#origin` is claimed only by `a` — `a#b` fails the `#` boundary.
    expect(r.scene.relations).toHaveLength(1);
    expect(r.scene.relations[0]?.fromId).toBe("a");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — deterministic hashes remain", () => {
  it("sceneHash and layoutHash are the exact pre-repair values", () => {
    // The repair changed only which drawable primitive an endpoint names;
    // sceneHash covers {relationId, role} and subjects, layoutHash covers
    // coordinates — neither may move, and pinning both proves it did not.
    expect(compiled.sceneHash).toBe(PRE_REPAIR_SCENE_HASH);
    expect(compiled.layoutHash).toBe(PRE_REPAIR_LAYOUT_HASH);
    expect(compiled.sceneHash).not.toBe(compiled.layoutHash);
  });

  it("repeated and order-shuffled compiles yield identical relations, fromId included", () => {
    const again = compileGetigScene({ mapping: MAPPING, runtimeStateHash: RUNTIME_HASH });
    const reversed = compileGetigScene({
      mapping: { ...MAPPING, tokens: [...MAPPING.tokens].reverse() },
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(again.ok && reversed.ok).toBe(true);
    if (!again.ok || !reversed.ok) return;
    expect(again.sceneHash).toBe(compiled.sceneHash);
    expect(reversed.sceneHash).toBe(compiled.sceneHash);
    expect(reversed.layoutHash).toBe(compiled.layoutHash);
    expect(JSON.stringify(reversed.scene.relations)).toBe(JSON.stringify(SCENE.relations));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29R1 — Phase-28 semantics unchanged", () => {
  it("the relation (relationId, role) projection is exactly the pre-repair projection", () => {
    expect(SCENE.relations.map((r) => ({ relationId: r.relationId, role: r.role }))).toEqual([
      { relationId: "route-28j-1#origin", role: "origin" },
      { relationId: "route-28j-1#forwarder:node-relay", role: "forwarder" },
      { relationId: "route-28j-1#destination", role: "destination" },
    ]);
  });

  it("counts are unchanged: 35 primitives, 3 relations, 9 mandatory markers", () => {
    expect(SCENE.primitives).toHaveLength(35);
    expect(SCENE.relations).toHaveLength(3);
    expect(SCENE.overlays).toHaveLength(9);
  });

  it("the frozen mapping is read, never mutated", () => {
    const before = JSON.stringify(MAPPING);
    compileGetigScene({ mapping: MAPPING, runtimeStateHash: RUNTIME_HASH });
    expect(JSON.stringify(MAPPING)).toBe(before);
  });

  it("mandatory markers survive the repair untouched (same ids, same texts)", () => {
    const texts = SCENE.overlays.map((o) => `${o.overlayId}:${o.text}`).sort();
    expect(texts).toHaveLength(9);
    expect(new Set(texts).size).toBe(9);
    // The 29D-OBS-3 identities (token-unique overlay ids) are still in force.
    expect(texts.some((t) => t.startsWith("overlay:conflicts:conflict:recon-28j-1:node-remote:"))).toBe(true);
  });
});
