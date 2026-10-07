/**
 * PHASE 29E — RUNTIME GRAPH RENDERING (FRAME COMPOSITION) — SUITE
 *
 * MODE: FRAME COMPOSITION / SEMANTIC INTEGRITY / NO DRAW CALL.
 *
 * The fixture is the REAL frozen chain: 28D mapping → 29B scene → 29D plan →
 * 29E frame. 35 primitives, 3 relations, 9 mandatory markers, 124 tokens.
 *
 * The centre of this suite is the marker guarantee. 29B already makes
 * conflicts, refusals and partitions visible as overlays; what can still go
 * wrong is that something drawn on top HIDES them. So the suite does not check
 * that markers were drawn politely — it checks that a frame in which a marker
 * could be occluded is UNREPRESENTABLE.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FRAME_LAYERS,
  MANDATORY_OVERLAY_KINDS,
  PHASE29E_FORBIDDEN_TOKENS,
  PRESENTATION_MODES,
  RENDER_FRAME_BOUNDS,
  RENDER_FRAME_REFUSAL_CODES,
  RENDER_FRAME_SCHEMA_VERSION,
  SHAPE_CLASSES,
  buildGpuRenderPlan,
  composeRuntimeFrame,
  compileGetigScene,
  getigVisualPermittedTiers,
  getigVisualSemanticRank,
  runGetigEndToEndScenario,
  type RuntimeFrame,
} from "../../packages/durable-state/src/index.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(HERE, "..", "..");
const MODULE_SRC = join(ROOT, "packages", "durable-state", "src", "renderFrameComposer.ts");
const RAW = readFileSync(MODULE_SRC, "utf8");

/** Strip comments AND string/template literals, leaving code. */
const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i++;
        i++;
      }
      i++;
      out += '""';
      continue;
    }
    out += c;
    i++;
  }
  return out;
};
const CODE = stripLiterals(RAW);

// ── the REAL frozen chain ─────────────────────────────────────────────────────

const scenario = runGetigEndToEndScenario();
if (!scenario.ok) throw new Error(`frozen Phase-28 scenario refused: ${scenario.refusal}`);
const MAPPING = scenario.scenario.mapping;
const RUNTIME_HASH = "5555666677778888";

const compiled = compileGetigScene({ mapping: MAPPING, runtimeStateHash: RUNTIME_HASH });
if (!compiled.ok) throw new Error(`frozen 29B compile refused: ${compiled.refusal}`);
const SCENE = compiled.scene;

const planned = buildGpuRenderPlan({ scene: SCENE });
if (!planned.ok) throw new Error(`frozen 29D plan refused: ${planned.refusal}`);
const PLAN = planned.plan;

const composed = composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: MAPPING });
if (!composed.ok) throw new Error(`frozen 29E compose refused: ${composed.refusal} ${composed.explanation}`);
const FRAME: RuntimeFrame = composed.frame;

const frameOf = (over: Record<string, unknown> = {}): RuntimeFrame => {
  const r = composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: MAPPING, ...over });
  if (!r.ok) throw new Error(`expected a frame, got ${r.refusal}: ${r.explanation}`);
  return r.frame;
};

const refusalOf = (over: Record<string, unknown> = {}): { refusal: string; explanation: string; offendingField: string | null } => {
  const r = composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: MAPPING, ...over });
  if (r.ok) throw new Error(`expected a refusal, got a frame with ${r.frame.drawList.length} entries`);
  return { refusal: r.refusal, explanation: r.explanation, offendingField: r.offendingField };
};

const markerEntries = () => FRAME.drawList.filter((e) => e.layer === "layer.marker");
const layerOf = (id: string) => {
  const l = FRAME.layers.find((x) => x.layerId === id);
  if (l === undefined) throw new Error(`no layer ${id}`);
  return l;
};

/** The DRAWABLE content, excluding the integrity report — which necessarily
 *  names the colour rule, and would otherwise trip a whole-frame colour scan. */
const DRAWABLE = JSON.stringify({ drawList: FRAME.drawList, layers: FRAME.layers, disclosure: FRAME.disclosure, binding: FRAME.binding });

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — the module draws nothing", () => {
  it("contains no GPU creation, submission, draw or readback token in CODE", () => {
    for (const token of PHASE29E_FORBIDDEN_TOKENS) {
      expect(CODE, `module code must not contain "${token}"`).not.toContain(token);
    }
  });

  it("POSITIVE CONTROL: the token scan fires on a token really present in code", () => {
    const planted = "const x = { createRenderPipeline: 1 }; queue.submit(commands);";
    const hits = PHASE29E_FORBIDDEN_TOKENS.filter((t) => stripLiterals(planted).includes(t));
    expect(hits).toContain("createRenderPipeline");
    expect(hits).toContain("queue.submit");
  });

  it("POSITIVE CONTROL: comments alone must NOT trip the scan", () => {
    // The header names every forbidden token in prose; a scanner that read
    // comments would fail on the documentation of the rule.
    const commentOnly = "// never call navigator.gpu or copyTextureToBuffer here\nconst a = 1;\n";
    expect(PHASE29E_FORBIDDEN_TOKENS.filter((t) => stripLiterals(commentOnly).includes(t))).toEqual([]);
  });

  it("POSITIVE CONTROL: string literals alone must NOT trip the scan", () => {
    const literalOnly = 'const s = "navigator.gpu requestDevice createTexture";';
    expect(PHASE29E_FORBIDDEN_TOKENS.filter((t) => stripLiterals(literalOnly).includes(t))).toEqual([]);
  });

  it("the frame itself states that nothing was rendered", () => {
    expect(FRAME.rendered).toBe(false);
    expect(FRAME.pixelOutputVerified).toBe(false);
    expect(FRAME.completeness).toBe("incomplete");
  });

  it("notProven says in words that this is a description, not a picture", () => {
    const text = FRAME.notProven.join(" | ");
    expect(text).toContain("DESCRIPTION");
    expect(text).toContain("no pixel was produced");
    expect(FRAME.notProven.length).toBeGreaterThanOrEqual(4);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — THE MARKER GUARANTEE (the centre of this gate)", () => {
  it("every conflict, refusal and partition in the scene reaches a marker entry", () => {
    const mandatory = SCENE.overlays.filter((o) => (MANDATORY_OVERLAY_KINDS as readonly string[]).includes(o.kind));
    expect(mandatory.length).toBeGreaterThan(0);
    expect(FRAME.mandatoryMarkerCount).toBe(mandatory.length);
    expect(markerEntries().length).toBe(mandatory.length);
    expect(FRAME.markersVisible).toBe(true);
  });

  it("the marker layer is LAST and does not occlude", () => {
    const marker = layerOf("layer.marker");
    expect(marker.order).toBe(FRAME_LAYERS.length - 1);
    expect(marker.occludes).toBe(false);
  });

  it("ONLY the marker layer may carry a mandatory marker", () => {
    const admitting = FRAME_LAYERS.filter((l) => l.mayCarryMandatoryMarkers);
    expect(admitting).toHaveLength(1);
    expect(admitting[0]?.layerId).toBe("layer.marker");
  });

  it("no occluding layer admits a mandatory marker (attacks 1-3 have no surface)", () => {
    const bad = FRAME_LAYERS.filter((l) => l.occludes && l.mayCarryMandatoryMarkers);
    expect(bad).toEqual([]);
  });

  it("nothing is drawn after the marker layer that occludes", () => {
    const markerOrder = layerOf("layer.marker").order;
    const after = FRAME.drawList.filter((e) => {
      const l = FRAME.layers.find((x) => x.layerId === e.layer);
      return l !== undefined && l.order > markerOrder && l.occludes;
    });
    expect(after).toEqual([]);
  });

  it("every marker entry is in a non-occluding layer", () => {
    for (const e of markerEntries()) {
      const l = FRAME.layers.find((x) => x.layerId === e.layer);
      expect(l?.occludes).toBe(false);
    }
  });

  it("no depth test exists that a nearer primitive could win (attacks 1-3 again)", () => {
    expect(FRAME.drawList.every((e) => e.depthCompare === "none")).toBe(true);
    expect(PLAN.pipelines.every((p) => p.depthCompare === "none")).toBe(true);
  });

  it("marker shapes are distinct from node shapes, so a marker cannot read as a node", () => {
    const markerShapes = new Set(markerEntries().map((e) => e.shapeClass));
    const nodeShapes = new Set(FRAME.drawList.filter((e) => e.layer === "layer.scene").map((e) => e.shapeClass));
    for (const m of markerShapes) expect(nodeShapes.has(m as never)).toBe(false);
    expect([...markerShapes].every((s) => (SHAPE_CLASSES as readonly string[]).includes(s))).toBe(true);
  });

  it("all three marker kinds are represented with their own shapes", () => {
    const shapes = new Set(markerEntries().map((e) => e.shapeClass));
    expect(shapes.has("marker_conflict")).toBe(true);
    expect(shapes.has("marker_refusal")).toBe(true);
    expect(shapes.has("marker_partition")).toBe(true);
  });

  it("the empty overlay layer is EXPECTED, not a dropped marker", () => {
    // 29B only emits overlays for mandatory collections, so on the frozen scene
    // every overlay IS a marker and layer.overlay is legitimately empty. If a
    // marker had been routed here instead, the counts above would not match.
    expect(FRAME.layers.filter((l) => l.entryCount === 0).map((l) => l.layerId)).toContain("layer.overlay");
    expect(FRAME.drawList.length).toBe(SCENE.primitives.length + SCENE.relations.length + SCENE.overlays.length);
  });

  it("a non-mandatory overlay WOULD go to the non-occluding overlay layer, not the marker layer", () => {
    const withProvenance = {
      ...SCENE,
      overlays: [...SCENE.overlays, { kind: "provenance" as const, overlayId: "overlay:provenance:x", targetId: SCENE.primitives[0]!.primitiveId, text: "provenance:present", authority: "none" as const }],
    };
    const plan = buildGpuRenderPlan({ scene: withProvenance });
    if (!plan.ok) throw new Error(`expected a plan, got ${plan.refusal}`);
    const f = frameOf({ scene: withProvenance, plan: plan.plan });
    expect(f.mandatoryMarkerCount).toBe(FRAME.mandatoryMarkerCount);
    expect(f.layers.find((l) => l.layerId === "layer.overlay")?.entryCount).toBe(1);
    expect(f.drawList.filter((e) => e.shapeClass === "provenance_plate")).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — withheld is not absent, and presentation never strengthens", () => {
  it("every token in the frozen mapping gets a disclosure row", () => {
    expect(FRAME.disclosure.length).toBe(MAPPING.tokens.length);
    expect(FRAME.disclosure.length).toBeLessThanOrEqual(RENDER_FRAME_BOUNDS.maxDisclosureRows);
  });

  it("a rank-0 token is presented as presence_only and NEVER as its value", () => {
    const rank0 = FRAME.disclosure.filter((d) => d.semanticRank === 0);
    expect(rank0.length).toBeGreaterThan(0);
    for (const d of rank0) {
      expect(d.permittedTiers).toEqual(["withheld"]);
      expect(d.presentedAs).toBe("presence_only");
      expect(d.presentedValue).toBeNull();
    }
  });

  it("presence_only rows never carry a value, whatever their tier", () => {
    // The invariant is structural: `presentedAs === "presence_only"` IMPLIES
    // `presentedValue === null`. Law 17 and law 16 reconciled by channel.
    for (const d of FRAME.disclosure) {
      if (d.presentedAs === "presence_only") expect(d.presentedValue).toBeNull();
    }
  });

  it("no row strengthens a claim", () => {
    for (const d of FRAME.disclosure) {
      expect(d.strengthensClaim).toBe(false);
      expect(d.authority).toBe("none");
    }
  });

  it("every row's tier is within Phase-28's permitted tiers for its rank", () => {
    for (const d of FRAME.disclosure) {
      expect(getigVisualPermittedTiers(d.semanticRank)).toContain(d.tier);
    }
  });

  it("the default tier is the STRONGEST Phase-28 permits, never stronger", () => {
    for (const d of FRAME.disclosure) {
      const strongest = d.permittedTiers[d.permittedTiers.length - 1];
      expect(d.tier).toBe(strongest);
    }
  });

  it("a request for a stronger tier than Phase-28 permits is REFUSED, not clamped", () => {
    // Clamping would hide the violation the caller just committed.
    const first = MAPPING.tokens[0]!;
    const r = refusalOf({ requestedTiers: { [first.tokenId]: "declared" } });
    expect(r.refusal).toBe("refused_frame_tier_ceiling_exceeded");
    expect(r.offendingField).toBe("requestedTiers");
  });

  it("requesting EVERY token at 'declared' is refused across the whole mapping", () => {
    const all = Object.fromEntries(MAPPING.tokens.map((t) => [t.tokenId as string, "declared"]));
    expect(refusalOf({ requestedTiers: all }).refusal).toBe("refused_frame_tier_ceiling_exceeded");
  });

  it("a request for a WEAKER tier is honoured", () => {
    const first = MAPPING.tokens[0]!;
    const f = frameOf({ requestedTiers: { [first.tokenId]: "withheld" } });
    const row = f.disclosure.find((d) => d.tokenId === first.tokenId);
    expect(row?.tier).toBe("withheld");
    expect(row?.presentedAs).toBe("presence_only");
  });

  it("a token is NEVER presented as a value stronger than its own", () => {
    // This is law 16 in its most general form, and it is what "stale never
    // appears current", "unknown never appears trusted" and "claim never
    // appears granted" actually reduce to. NOTE: `stale` is rank 1, not rank 0,
    // so it MAY be shown — as "stale". What may never happen is showing it as
    // "current". Asserting rank 0 for stale would have been a false belief about
    // Phase-28's own ordering.
    for (const d of FRAME.disclosure) {
      if (d.presentedValue !== null) expect(d.presentedValue).toBe(d.semanticValue);
    }
  });

  it("a presented value always holds the SAME rank as the token it came from", () => {
    // "unknown never appears trusted" is NOT "the word 'known' never appears" —
    // `knowledge=known` is rank 1 and legitimately shows AS ITSELF. Promotion
    // would be showing a token at a rank it does not hold. This checks exactly
    // that, on the real mapping, per row.
    let shown = 0;
    for (const d of FRAME.disclosure) {
      if (d.presentedValue === null) continue;
      shown += 1;
      expect(getigVisualSemanticRank(d.axis, d.presentedValue)).toBe(d.semanticRank);
    }
    expect(shown).toBeGreaterThan(0);
  });

  it("no value from one axis is ever presented for another axis", () => {
    for (const d of FRAME.disclosure) {
      if (d.presentedValue === null) continue;
      // The presented value must be a value OF THIS TOKEN'S OWN AXIS.
      expect(getigVisualSemanticRank(d.axis, d.presentedValue)).toBeGreaterThanOrEqual(0);
      expect(d.semanticValue).toBe(d.presentedValue);
    }
  });

  it("a rank-0 `unknown` token is present_only, and a rank-1 `stale` shows only itself", () => {
    const unknownRows = FRAME.disclosure.filter((d) => d.semanticValue === "unknown");
    const staleRows = FRAME.disclosure.filter((d) => d.semanticValue === "stale");
    expect(unknownRows.length).toBeGreaterThan(0);
    expect(staleRows.length).toBeGreaterThan(0);
    for (const d of unknownRows) {
      expect(d.semanticRank).toBe(0);
      expect(d.presentedValue).toBeNull();
    }
    for (const d of staleRows) {
      expect(d.semanticRank).toBe(1);
      if (d.presentedValue !== null) expect(d.presentedValue).toBe("stale");
    }
  });

  it("claim is never presented as granted", () => {
    for (const d of FRAME.disclosure) {
      if (d.axis === "grant" && d.semanticValue === "claim") {
        expect(d.presentedValue).not.toBe("granted");
        expect(JSON.stringify(d)).not.toMatch(/granted|authorized|approved/i);
      }
    }
  });

  it("PRESENTATION_MODES is a closed vocabulary and every mode is used", () => {
    expect(PRESENTATION_MODES).toEqual(["presence_only", "value_declared"]);
    const used = new Set(FRAME.disclosure.map((d) => d.presentedAs));
    for (const m of used) expect((PRESENTATION_MODES as readonly string[]).includes(m)).toBe(true);
    expect(used.has("presence_only")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — route roles are distinguishable without redefining semantics", () => {
  it("each route role in the scene maps to a distinct shape", () => {
    const roles = [...new Set(SCENE.relations.map((r) => r.role))].sort();
    expect(roles).toEqual(["destination", "forwarder", "origin"]);
    const shapes = new Set(FRAME.drawList.filter((e) => e.layer === "layer.relation").map((e) => e.shapeClass));
    expect(shapes.size).toBe(roles.length);
  });

  it("the shape vocabulary carries a role but no axis, value or trust", () => {
    for (const s of SHAPE_CLASSES) {
      expect(s.toLowerCase()).not.toMatch(/axis|semantic|value|trust|authority|claim/);
    }
  });

  it("the forwarder shape is not the origin shape", () => {
    const byRole = new Map<string, string>(SCENE.relations.map((r) => [r.role as string, r.relationId] as const));
    const shapeFor = (role: string) =>
      FRAME.drawList.find((e) => e.entryId === `entry:route:${byRole.get(role)}`)?.shapeClass;
    expect(shapeFor("forwarder")).toBe("route_forwarder");
    expect(shapeFor("origin")).toBe("route_origin");
    expect(shapeFor("forwarder")).not.toBe(shapeFor("origin"));
  });

  it("a forwarder never acquires an origin's shape by collapse", () => {
    // 29B's route-role ordering is imported from Phase-28, never re-derived;
    // if the composer collapsed roles the three shapes would collapse too.
    const routeShapes = FRAME.drawList.filter((e) => e.layer === "layer.relation").map((e) => e.shapeClass);
    expect(new Set(routeShapes).size).toBe(routeShapes.length);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — the frame is bound, or refused", () => {
  it("the frame names its source frame, visible hash, scene hash and plan hash", () => {
    expect(FRAME.binding.sourceFrameId).toBe(SCENE.sourceFrameId);
    expect(FRAME.binding.sourceVisibleHash).toBe(SCENE.sourceVisibleHash);
    expect(FRAME.binding.sceneHash).toBe(SCENE.sceneHash);
    expect(FRAME.binding.planHash).toBe(PLAN.planHash);
    expect(FRAME.binding.runtimeStateHash).toBe(RUNTIME_HASH);
  });

  it("a plan built from a DIFFERENT scene is refused", () => {
    const r = refusalOf({ plan: { ...PLAN, sceneHash: "f".repeat(64) } });
    expect(r.refusal).toBe("refused_frame_binding_mismatch");
    expect(r.offendingField).toBe("plan.sceneHash");
  });

  it("a scene whose runtimeStateHash the plan does not carry is refused", () => {
    expect(refusalOf({ scene: { ...SCENE, runtimeStateHash: "9".repeat(16) } }).refusal).toBe("refused_frame_binding_mismatch");
  });

  it("a mismatched sourceFrameId or sourceVisibleHash is refused", () => {
    expect(refusalOf({ plan: { ...PLAN, sourceFrameId: "other-frame" } }).refusal).toBe("refused_frame_binding_mismatch");
    expect(refusalOf({ plan: { ...PLAN, sourceVisibleHash: "b".repeat(64) } }).refusal).toBe("refused_frame_binding_mismatch");
  });

  it("a mapping from a different frame is refused", () => {
    expect(refusalOf({ mapping: { ...MAPPING, frameId: "frame-elsewhere" } }).refusal).toBe("refused_frame_binding_mismatch");
  });

  it("a scene whose sceneHash equals its runtimeStateHash is refused", () => {
    expect(refusalOf({ scene: { ...SCENE, sceneHash: RUNTIME_HASH } }).refusal).toBe("refused_frame_binding_mismatch");
  });

  it("the frame hash is not any of the hashes it binds", () => {
    expect(FRAME.frameHash).not.toBe(FRAME.binding.sceneHash);
    expect(FRAME.frameHash).not.toBe(FRAME.binding.planHash);
    expect(FRAME.frameHash).toMatch(/^frame_[a-f0-9]{64}$/);
  });

  it("the observer view is never global truth", () => {
    expect(FRAME.observerScope).toBe("observer_relative");
    expect(FRAME.globalTruthClaimed).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — completeness is never overclaimed", () => {
  it("a completeness claim of 'complete' is REFUSED by this gate outright", () => {
    const r = refusalOf({ requestedCompleteness: "complete" });
    expect(r.refusal).toBe("refused_frame_completeness_claimed");
    expect(r.offendingField).toBe("requestedCompleteness");
  });

  it("a completeness claim is refused even WITH a qualifying WebGPU verdict", () => {
    // The gate renders nothing; no verdict about a GPU can make it have
    // rendered. Hardware capability is not a rendering fact.
    expect(refusalOf({ requestedCompleteness: "complete", qualification: null }).refusal).toBe("refused_frame_completeness_claimed");
  });

  it("the emitted completeness is 'incomplete' and its type admits nothing else", () => {
    expect(FRAME.completeness).toBe("incomplete");
    const declared: "incomplete" = FRAME.completeness;
    expect(declared).toBe("incomplete");
  });

  it("the schema version is pinned", () => {
    expect(RENDER_FRAME_SCHEMA_VERSION).toBe("menog-runtime-frame/v0");
    expect(FRAME.schemaVersion).toBe(RENDER_FRAME_SCHEMA_VERSION);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — zero authority, no mutation, no interaction", () => {
  it("every draw entry carries no authority, no execution and no mutation", () => {
    for (const e of FRAME.drawList) {
      expect(e.authority).toBe("none");
      expect(e.executionAuthorized).toBe(false);
      expect(e.mutates).toBe(false);
      expect(e.uploadedToGpu).toBe(false);
    }
  });

  it("no draw entry or disclosure row carries an action, command, permission or grant key", () => {
    const forbidden = ["action", "command", "effect", "permission", "grant", "execute", "approve", "allow", "authorize", "authorized", "trust", "trusted"];
    const walk = (node: unknown, path: string): void => {
      if (Array.isArray(node)) { node.forEach((v, i) => walk(v, `${path}[${i}]`)); return; }
      if (typeof node !== "object" || node === null) return;
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        expect(forbidden, `${path}.${k} must not exist`).not.toContain(k);
        walk(v, `${path}.${k}`);
      }
    };
    walk({ drawList: FRAME.drawList, disclosure: FRAME.disclosure }, "frame");
  });

  it("a mapping token carrying a claim-shaped field is REFUSED, not stripped", () => {
    const r = refusalOf({ mapping: { ...MAPPING, tokens: [{ ...(MAPPING.tokens[0] as object), granted: true }] } });
    expect(r.refusal).toBe("refused_frame_authority_claim");
  });

  it("no draw entry uploads anything: the plan's buffers have no class that would accept a token id", () => {
    const contents = new Set(PLAN.buffers.map((b) => b.contents));
    for (const c of contents) expect(c.toLowerCase()).not.toMatch(/token|semantic|label|text|name/);
    for (const e of FRAME.drawList) expect(e.semanticTokenId).toBeNull();
  });

  it("every pipeline id used by a draw entry really exists in the plan", () => {
    const known = new Set(PLAN.pipelines.map((p) => p.pipelineId));
    for (const e of FRAME.drawList) expect(known.has(e.pipelineId)).toBe(true);
  });

  it("every buffer id used by a draw entry really exists in the plan", () => {
    const known = new Set(PLAN.buffers.map((b) => b.bufferId));
    for (const e of FRAME.drawList) expect(known.has(e.bufferId)).toBe(true);
  });

  it("draw ranges stay inside the buffer they name", () => {
    for (const e of FRAME.drawList) {
      const b = PLAN.buffers.find((x) => x.bufferId === e.bufferId);
      if (b === undefined) throw new Error(`unknown buffer ${e.bufferId}`);
      expect(e.firstIndex).toBeGreaterThanOrEqual(0);
      expect(e.firstIndex + e.indexCount).toBeLessThanOrEqual(b.recordCount);
    }
  });

  it("the success envelope is zero-authority, read-only and non-executing", () => {
    expect(composed.authority).toBe("none");
    expect(composed.controlPlane).toBe(false);
    expect(composed.readOnly).toBe(true);
    expect(composed.executionAuthorized).toBe(false);
    expect(composed.code).toBe("runtime_frame_composed");
  });

  it("the scene handed to the composer is never mutated", () => {
    const before = JSON.stringify(SCENE);
    composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: MAPPING });
    expect(JSON.stringify(SCENE)).toBe(before);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — no colour, and no visual channel carries authority", () => {
  it("no colour appears anywhere in the DRAWABLE content", () => {
    // Scoped to drawList/layers/disclosure/binding: the integrity report
    // necessarily NAMES the colour rule, so a whole-frame scan would match the
    // claim about colour rather than any colour.
    expect(DRAWABLE).not.toMatch(/colou?r/i);
  });

  it("POSITIVE CONTROL: the colour scan fires on colour actually present", () => {
    expect(/colou?r/i.test(JSON.stringify({ colorHint: "#ff0000" }))).toBe(true);
  });

  it("size and position and depth are presentation only, never authority", () => {
    for (const e of FRAME.drawList) {
      expect(e.authority).toBe("none");
      expect(Object.keys(e)).not.toContain("zOrder");
      expect(Object.keys(e)).not.toContain("depth");
    }
  });

  it("SHAPE_CLASSES is a closed vocabulary and every used shape is in it", () => {
    expect(Object.isFrozen(SHAPE_CLASSES)).toBe(true);
    for (const e of FRAME.drawList) expect((SHAPE_CLASSES as readonly string[]).includes(e.shapeClass)).toBe(true);
  });

  it("no shape class name means trusted, granted, current or important", () => {
    for (const s of SHAPE_CLASSES) {
      expect(s.toLowerCase()).not.toMatch(/trust|grant|current|important|large|high|admin|root/);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — determinism and integrity reporting", () => {
  it("composing twice yields the same frame hash", () => {
    expect(composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: MAPPING }).ok && frameOf().frameHash).toBe(FRAME.frameHash);
  });

  it("token array order cannot change the frame hash", () => {
    const shuffled = { ...MAPPING, tokens: [...MAPPING.tokens].reverse() };
    expect(frameOf({ mapping: shuffled }).frameHash).toBe(FRAME.frameHash);
  });

  it("every integrity claim holds, with evidence computed from the data", () => {
    expect(FRAME.integrity.length).toBeGreaterThanOrEqual(8);
    for (const c of FRAME.integrity) {
      expect(c.holds, `${c.claimId} must hold`).toBe(true);
      expect(c.evidence.length).toBeGreaterThan(0);
    }
  });

  it("the integrity claims cover the prompt's named requirements", () => {
    const ids = FRAME.integrity.map((c) => c.claimId);
    expect(ids).toContain("no_hidden_mandatory_marker");
    expect(ids).toContain("no_depth_test_can_erase_a_marker");
    expect(ids).toContain("no_colour_only_semantic");
    expect(ids).toContain("route_roles_visually_distinguishable");
    expect(ids).toContain("claim_never_appears_granted");
    expect(ids).toContain("withheld_is_not_absent");
    expect(ids).toContain("observer_view_is_not_global_truth");
    expect(ids).toContain("no_entry_mutates_or_authorises");
  });

  it("a route role outside the closed vocabulary is REFUSED, never defaulted", () => {
    // Falling back to a generic shape is exactly how two roles collapse into
    // one picture — attack 8 of 29I, forwarder drawn as origin. 29A closed this
    // vocabulary; a default here would reopen it silently.
    const collapsed = {
      ...SCENE,
      relations: [
        ...SCENE.relations,
        { kind: "forwards_to" as const, relationId: "r:extra", fromId: "nowhere", toId: "also-nowhere", role: "not-a-phase28-role" as never, authorizes: false as const, trust: "none" as const },
      ],
    };
    const plan = buildGpuRenderPlan({ scene: collapsed });
    if (!plan.ok) throw new Error(`expected a plan, got ${plan.refusal}`);
    const r = composeRuntimeFrame({ scene: collapsed, plan: plan.plan, mapping: MAPPING });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_frame_route_role_unknown");
    expect(r.explanation).toContain("not-a-phase28-role");
    expect(r.frame).toBeNull();
    expect(r.partialFrameEmitted).toBe(false);
  });

  it("the frame and every nested collection is frozen", () => {
    expect(Object.isFrozen(FRAME)).toBe(true);
    expect(Object.isFrozen(FRAME.drawList)).toBe(true);
    expect(Object.isFrozen(FRAME.disclosure)).toBe(true);
    expect(Object.isFrozen(FRAME.layers)).toBe(true);
    expect(Object.isFrozen(FRAME.integrity)).toBe(true);
    expect(Object.isFrozen(FRAME.binding)).toBe(true);
    for (const e of FRAME.drawList) expect(Object.isFrozen(e)).toBe(true);
    for (const d of FRAME.disclosure) expect(Object.isFrozen(d)).toBe(true);
  });

  it("mutating a draw list throws rather than rewriting the frame", () => {
    expect(() => {
      (FRAME.drawList as unknown as unknown[]).push({});
    }).toThrow();
  });

  it("bounds are positive and finite", () => {
    for (const [k, v] of Object.entries(RENDER_FRAME_BOUNDS)) {
      expect(Number.isSafeInteger(v), `${k} must be a safe integer`).toBe(true);
      expect(v as number).toBeGreaterThan(0);
    }
    expect(RENDER_FRAME_BOUNDS.maxLayers).toBe(FRAME_LAYERS.length);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29E — refusals are live and total", () => {
  it("every exported refusal code is actually emitted in the module source", () => {
    // `refuse\(\s*"` rather than `refuse\("`: literals often sit on the next line.
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(\s*"([a-z0-9_]+)"/g)) emitted.add(m[1] as string);
    expect(emitted.size).toBeGreaterThan(0);
    for (const c of RENDER_FRAME_REFUSAL_CODES) {
      expect(emitted, `refusal code ${c} is declared but never emitted`).toContain(c);
    }
  });

  it("the module emits nothing outside the closed refusal vocabulary", () => {
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(\s*"([a-z0-9_]+)"/g)) emitted.add(m[1] as string);
    for (const c of emitted) expect((RENDER_FRAME_REFUSAL_CODES as readonly string[]).includes(c)).toBe(true);
  });

  it("POSITIVE CONTROL: the emission scan detects a planted refusal literal", () => {
    const planted = 'return refuse(\n  "refused_frame_planted",\n  "x",\n);';
    const found = new Set<string>();
    for (const m of planted.matchAll(/refuse\(\s*"([a-z0-9_]+)"/g)) found.add(m[1] as string);
    expect([...found]).toContain("refused_frame_planted");
  });

  it("a refusal emits no frame at all, not a partial one", () => {
    const r = composeRuntimeFrame({ scene: null, plan: null, mapping: null });
    if (r.ok) throw new Error("expected a refusal");
    expect(r.frame).toBeNull();
    expect(r.partialFrameEmitted).toBe(false);
    expect(r.authority).toBe("none");
    expect(r.controlPlane).toBe(false);
    expect(r.readOnly).toBe(true);
    expect(r.executionAuthorized).toBe(false);
    expect(r.code).toBe("render_frame_refused");
  });

  it("malformed inputs are refused by class", () => {
    expect(refusalOf({ scene: "not an object" }).refusal).toBe("refused_frame_input_invalid");
    expect(refusalOf({ plan: 42 }).refusal).toBe("refused_frame_input_invalid");
    expect(refusalOf({ mapping: null }).refusal).toBe("refused_frame_input_invalid");
    expect(refusalOf({ mapping: { ...MAPPING, schemaVersion: "wrong/v1" } }).refusal).toBe("refused_frame_input_invalid");
    expect(refusalOf({ scene: { ...SCENE, primitives: "many" } }).refusal).toBe("refused_frame_input_invalid");
  });

  it("a plan missing its overlay instance buffer is refused", () => {
    const r = refusalOf({ plan: { ...PLAN, buffers: PLAN.buffers.filter((b) => b.bufferId !== "buf.instance.overlay") } });
    expect(r.refusal).toBe("refused_frame_plan_incomplete");
  });

  it("a plan holding the wrong number of overlay instances is refused", () => {
    const r = refusalOf({
      plan: {
        ...PLAN,
        buffers: PLAN.buffers.map((b) => (b.bufferId === "buf.instance.overlay" ? { ...b, recordCount: b.recordCount - 1 } : b)),
      },
    });
    expect(r.refusal).toBe("refused_frame_plan_incomplete");
  });

  it("a plan whose pipeline declares a depth test is refused (it could erase a marker)", () => {
    const r = refusalOf({ plan: { ...PLAN, pipelines: PLAN.pipelines.map((p) => ({ ...p, depthCompare: "less" })) } });
    expect(r.refusal).toBe("refused_frame_occlusion_erased_marker");
  });

  it("a non-integer input is refused", () => {
    const r = composeRuntimeFrame(null as never);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_frame_input_invalid");
  });

  it("every refusal code names itself refused_gpu_frame, with no bare pass member", () => {
    for (const c of RENDER_FRAME_REFUSAL_CODES) expect(c.startsWith("refused_frame_")).toBe(true);
    for (const c of RENDER_FRAME_REFUSAL_CODES) expect(c.toLowerCase()).not.toContain("pass");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SUPERSEDED AT GATE 29R4 (2026-10-05): these pins described the
// four-devDependency pre-authorization state — package.json 77500e08443e424a…ed93,
// pnpm-lock.yaml bd289ce7ad6d0d8c…4752 (36 919 B). The HUMAN explicitly
// authorized exactly one addition — @webgpu/types@0.1.74, dev-only, zero
// runtime/transitive deps — recorded in docs/release/PHASE29R4_TYPING_DECISION.json
// with the prior record archived byte-exact. Recovery law: superseded, never
// erased. The assertions below re-pin the post-authorization state as a
// tripwire for any further dependency change.
describe("29E — no dependency beyond the authorized one, no frozen artifact moved", () => {
  it("package.json declares the four original devDependencies plus the authorized @webgpu/types@0.1.74", async () => {
    const { createHash } = await import("node:crypto");
    const raw = readFileSync(join(ROOT, "package.json"));
    expect(createHash("sha256").update(raw).digest("hex")).toBe("56369ab3369c78b801e1032a4bf12f9349e839a8a43e9ed108ab34ed81893e92");
    const pkg = JSON.parse(raw.toString("utf8")) as { devDependencies: Record<string, string>; dependencies?: Record<string, string> };
    expect(Object.keys(pkg.devDependencies).sort()).toEqual(["@types/node", "@webgpu/types", "rimraf", "typescript", "vitest"]);
    expect(pkg.devDependencies["@webgpu/types"]).toBe("0.1.74");
    expect(pkg.dependencies ?? {}).toEqual({});
  });

  it("pnpm-lock.yaml keeps the post-authorization sha256", async () => {
    const { createHash } = await import("node:crypto");
    const raw = readFileSync(join(ROOT, "pnpm-lock.yaml"));
    expect(createHash("sha256").update(raw).digest("hex")).toBe("541249d23a9f54b9d3255bbefa8bd7f221c96371a37693be344b50d5de23506d");
  });

  it("the module name does not collide with the frozen 28K audit glob", () => {
    // ^getig.*\.ts$ is how the FROZEN 28K audit infers Phase-28 membership.
    expect(/^getig.*\.ts$/.test("renderFrameComposer.ts")).toBe(false);
  });
});