/**
 * PHASE 29G — PICKING & READ-ONLY INTERACTION — REGRESSION SUITE
 *
 * MODE: SELECTION / INSPECTION ONLY / NO GPU / NO RUNTIME / NO DEPENDENCY.
 *
 * Central laws under test:
 *   PICKING != EXECUTION
 *   SELECTION != PERMISSION
 *
 * One describe block per pack requirement:
 *   1. picking ids opaque / bounded / deterministic within scene
 *   2. stale picking id after scene change refuses
 *   3. subject-id substitution refuses
 *   4. index-to-subject semantic identity stays CPU-side
 *   5. selection cannot hide mandatory conflict/refusal/partition markers
 *   6. no action/command/permission/grant/execute/approve surface
 *   7. only Phase-28 read-only inspection reachable
 *
 * Plus the pack's named probes: stale scene, cross-scene substitution,
 * marker/overlay picks, route-role picks, explanation binding, control-path
 * scans — and set-equality reachability over every declared refusal code.
 *
 * The happy path runs on the REAL frozen chain (28J scenario -> 29B scene ->
 * 29D plan). Synthetic scenes/plans appear only where a case needs an input the
 * frozen chain cannot produce (a second scene, a tampered table, an oversized
 * table) — and each such case asserts a REFUSAL, never a successful identity.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  GETIG_PICKING_ACTION_FIELDS,
  GETIG_PICKING_INPUT_FIELDS,
  GETIG_PICKING_INSPECTION_FIELDS,
  GETIG_PICKING_MARKER_FIELDS,
  GETIG_PICKING_REFUSAL_CODES,
  INSPECTION_FORBIDDEN_ACTIONS,
  MANDATORY_OVERLAY_KINDS,
  PHASE29G_FORBIDDEN_TOKENS,
  PICKING_BOUNDS,
  buildGpuRenderPlan,
  compileGetigScene,
  getigVisualSemanticRank,
  inspectPickedSubject,
  refusePickedSelectionExecution,
  resolvePickingSelection,
  runGetigEndToEndScenario,
} from "../../packages/durable-state/src/index.js";
import { canonicalHash } from "../../packages/durable-state/src/canonical.js";
import * as pickingSurface from "../../packages/durable-state/src/pickingResolver.js";

// ── the REAL frozen chain ─────────────────────────────────────────────────────

const scenario = runGetigEndToEndScenario();
if (!scenario.ok) throw new Error(`frozen Phase-28 scenario refused: ${scenario.refusal}`);
const SC = scenario.scenario;
const RUNTIME_HASH = "5555666677778888";

const compiledA = compileGetigScene({ mapping: SC.mapping, runtimeStateHash: RUNTIME_HASH });
if (!compiledA.ok) throw new Error(`frozen 29B compile refused: ${compiledA.refusal}`);
const SCENE = compiledA.scene;

const planA = buildGpuRenderPlan({ scene: SCENE });
if (!planA.ok) throw new Error(`frozen 29D plan refused: ${planA.refusal}`);
const PLAN = planA.plan;

/** A REAL second scene (different mapping -> different sceneHash) for staleness. */
const token = (over: Record<string, unknown>): Record<string, unknown> => ({
  tokenId: `t:${String(over.subjectVisibleId ?? "s")}:${String(over.axis ?? "knowledge")}`,
  axis: over.axis ?? "knowledge",
  semanticValue: over.semanticValue ?? "unknown",
  semanticRank: getigVisualSemanticRank(
    String(over.axis ?? "knowledge") as Parameters<typeof getigVisualSemanticRank>[0],
    String(over.semanticValue ?? "unknown"),
  ),
  subjectVisibleId: over.subjectVisibleId ?? "node-local",
  subjectCollection: over.subjectCollection ?? "entities",
  claim: "descriptive_only",
  authority: "none",
  mutation: "none",
  executable: false,
  ...over,
});
const compiledB = compileGetigScene({
  mapping: {
    schemaVersion: "menog-getig-visual/v0",
    frameId: "frame-29g-b",
    observerId: "observer-local-a",
    mappingHash: "abcdef0123456789",
    tokens: [token({ axis: "knowledge", semanticValue: "known", subjectVisibleId: "node-local" })],
  },
  runtimeStateHash: RUNTIME_HASH,
});
if (!compiledB.ok) throw new Error(`second scene compile refused: ${compiledB.refusal}`);
const SCENE_B = compiledB.scene;
const planB = buildGpuRenderPlan({ scene: SCENE_B });
if (!planB.ok) throw new Error(`second plan refused: ${planB.refusal}`);
const PLAN_B = planB.plan;
expect(SCENE_B.sceneHash).not.toBe(SCENE.sceneHash);

const BINDING = {
  frameId: SC.frame.frameId,
  observerId: SC.frame.observer.observerId,
  canonicalVisibleHash: SC.frame.canonicalVisibleHash,
  viewHash: SC.viewLocal.viewHash,
};

const hex64 = (seed: string): string => createHash("sha256").update(seed).digest("hex");

const SUBJECTS = SCENE.primitives.map((p) => p.primitiveId);
const idxOf = (subject: string): number => {
  const i = PLAN.pickingResolutions.findIndex((r) => r.subjectVisibleId === subject);
  if (i < 0) throw new Error(`no picking row for ${subject}`);
  return i;
};

type Target = Record<string, unknown>;
const resolveWith = (target: Target, over: Target = {}) =>
  resolvePickingSelection({ scene: SCENE, plan: PLAN, ...target, ...over });
const refusalOf = (target: Target, over: Target = {}) => {
  const d = resolveWith(target, over);
  if (d.ok) throw new Error(`expected a refusal, got subject ${d.selection.subjectVisibleId}`);
  return d;
};
const selectionOf = (subject: string, over: Target = {}) => {
  const d = resolveWith({ pickingIndex: idxOf(subject) }, over);
  if (!d.ok) throw new Error(`expected a selection for ${subject}, got ${d.refusal}: ${d.explanation}`);
  return d.selection;
};
const inspectOf = (target: Target, over: Target = {}) =>
  inspectPickedSubject({
    scene: SCENE,
    plan: PLAN,
    view: SC.viewLocal,
    graph: SC.graph,
    binding: BINDING,
    ...target,
    ...over,
  });

const tamperedPlan = (): Record<string, unknown> =>
  JSON.parse(JSON.stringify(PLAN)) as Record<string, unknown>;
const rowOf = (plan: Record<string, unknown>, subject: string): Record<string, unknown> => {
  const rows = plan["pickingResolutions"] as Record<string, unknown>[];
  const i = rows.findIndex((r) => r["subjectVisibleId"] === subject);
  if (i < 0) throw new Error(`no row for ${subject}`);
  return rows[i] as Record<string, unknown>;
};

// ── source scanner (29E/29F technique: comments and strings stripped) ─────────

const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
};

const MODULE_SRC = readFileSync(
  new URL("../../packages/durable-state/src/pickingResolver.ts", import.meta.url),
  "utf8",
);
const MODULE_CODE = stripLiterals(MODULE_SRC);

/** Every key appearing anywhere in a JSON value. */
const collectKeys = (value: unknown, out: Set<string> = new Set()): Set<string> => {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.add(k);
      collectKeys(v, out);
    }
  }
  return out;
};

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-1 — picking ids are opaque, bounded and deterministic within the scene", () => {
  it("every pickingId is pick_ + 64 hex and contains no subject name", () => {
    for (const row of PLAN.pickingResolutions) {
      expect(row.pickingId, row.subjectVisibleId).toMatch(/^pick_[0-9a-f]{64}$/);
      expect(row.pickingId.includes(row.subjectVisibleId)).toBe(false);
      expect(row.subjectVisibleId.includes(row.pickingId)).toBe(false);
    }
  });

  it("the id re-derives from sceneHash + subjectVisibleId (independent computation)", () => {
    for (const row of PLAN.pickingResolutions) {
      const expected = `pick_${canonicalHash({ sceneHash: SCENE.sceneHash, subjectVisibleId: row.subjectVisibleId })}`;
      expect(row.pickingId).toBe(expected);
    }
  });

  it("29B's compile-time ids and 29D's plan rows agree — one id per subject, cross-layer", () => {
    expect(compiledA.pickingIds.length).toBe(PLAN.pickingResolutions.length);
    for (const entry of compiledA.pickingIds) {
      const row = PLAN.pickingResolutions.find((r) => r.subjectVisibleId === entry.subjectVisibleId);
      expect(row, entry.subjectVisibleId).toBeDefined();
      expect(row?.pickingId).toBe(entry.pickingId);
    }
    const ids = compiledA.pickingIds.map((p) => p.pickingId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("the same input resolves to a byte-identical selection every time", () => {
    const a = resolveWith({ pickingIndex: idxOf("node-local") });
    const b = resolveWith({ pickingIndex: idxOf("node-local") });
    if (!a.ok || !b.ok) throw new Error("resolve failed");
    expect(JSON.stringify(a.selection)).toBe(JSON.stringify(b.selection));
    expect(a.selection.pickingId).toBe(b.selection.pickingId);
  });

  it("a table over the bound refuses instead of truncating", () => {
    const hex = hex64("oversized");
    const d = resolvePickingSelection({
      scene: { sceneHash: hex, primitives: [], relations: [], overlays: [] },
      plan: {
        sceneHash: hex,
        planHash: "plan_syn",
        pickingResolutions: Array.from({ length: PICKING_BOUNDS.maxResolutions + 1 }, () => ({})),
      },
      pickingIndex: 0,
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.refusal).toBe("refused_picking_bound_exceeded");
    expect(d.selection).toBeNull();
    expect(d.explanation).toContain("exceeds the bound");
  });

  it("unknown input fields are refused, not ignored — and inspection fields don't belong to the bare resolver", () => {
    const unknownField = refusalOf({ pickingIndex: 0, bogusField: 1 });
    expect(unknownField.refusal).toBe("refused_picking_input_invalid");
    for (const field of GETIG_PICKING_INSPECTION_FIELDS) {
      const d = refusalOf({ pickingIndex: 0, [field]: {} });
      expect(d.refusal, field).toBe("refused_picking_input_invalid");
      expect(d.explanation).toContain("belongs to inspectPickedSubject");
    }
    // The declared input vocabulary is exactly what a caller may send.
    expect([...GETIG_PICKING_INPUT_FIELDS].sort()).toEqual(
      [
        "scene", "plan", "pickingIndex", "pickingId", "claimedSubjectVisibleId",
        "currentSceneHash", ...GETIG_PICKING_INSPECTION_FIELDS,
      ].sort(),
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-2 — a stale picking id after a scene change refuses", () => {
  it("a plan built for scene A is stale against scene B — no lookup is attempted", () => {
    const d = refusalOf({ pickingIndex: 0 }, { scene: SCENE_B });
    expect(d.refusal).toBe("refused_picking_stale_scene");
    expect(d.explanation).toContain("stale after the scene changes");
    expect(d.selection).toBeNull();
    // ...and symmetrically, scene B's own plan against scene A.
    const back = resolvePickingSelection({ scene: SCENE, plan: PLAN_B, pickingIndex: 0 });
    expect(back.ok).toBe(false);
    if (!back.ok) expect(back.refusal).toBe("refused_picking_stale_scene");
  });

  it("a caller whose currentSceneHash disagrees with the scene is stale", () => {
    const d = refusalOf({ pickingIndex: 0, currentSceneHash: SCENE_B.sceneHash });
    expect(d.refusal).toBe("refused_picking_stale_scene");
    expect(d.explanation).toContain("changed after this picking id was issued");
    const nonString = refusalOf({ pickingIndex: 0, currentSceneHash: 42 });
    expect(nonString.refusal).toBe("refused_picking_input_invalid");
    // The matching hash is accepted.
    const ok = resolveWith({ pickingIndex: 0, currentSceneHash: SCENE.sceneHash });
    expect(ok.ok).toBe(true);
  });

  it("scene B's real picking id presented against scene A's table is UNKNOWN, not resolved", () => {
    const foreignRow = PLAN_B.pickingResolutions[0];
    if (!foreignRow) throw new Error("the second scene has no picking rows");
    const d = refusalOf({ pickingId: foreignRow.pickingId });
    expect(d.refusal).toBe("refused_picking_unknown_id");
    expect(d.selection).toBeNull();
    // A syntactically perfect but never-issued id fails the same way.
    const fabricated = refusalOf({ pickingId: `pick_${hex64("never issued")}` });
    expect(fabricated.refusal).toBe("refused_picking_unknown_id");
  });

  it("stale detection fires BEFORE any index is read (an invalid index against a stale plan reports STALE)", () => {
    const d = resolvePickingSelection({ scene: SCENE_B, plan: PLAN, pickingIndex: 9999 });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_picking_stale_scene");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-3 — subject-id substitution refuses", () => {
  it("an index and an id that resolve to different rows refuse", () => {
    const d = refusalOf({
      pickingIndex: idxOf("node-local"),
      pickingId: PLAN.pickingResolutions[idxOf("node-relay")]?.pickingId,
    });
    expect(d.refusal).toBe("refused_picking_subject_substitution");
    expect(d.selection).toBeNull();
  });

  it("a caller's claimedSubjectVisibleId never overrides the table — and the refusal reveals nothing", () => {
    const d = refusalOf({
      pickingIndex: idxOf("node-local"),
      claimedSubjectVisibleId: "node-relay",
    });
    expect(d.refusal).toBe("refused_picking_subject_substitution");
    expect(d.selection).toBeNull();
    // The refusal must NOT name the true subject: a failed substitution learns nothing.
    expect(d.explanation).not.toContain("node-local");
    // The matching claim is accepted.
    const ok = resolveWith({ pickingIndex: idxOf("node-local"), claimedSubjectVisibleId: "node-local" });
    expect(ok.ok).toBe(true);
  });

  it("a tampered table row does not re-derive and is refused as plan_invalid", () => {
    const plan = tamperedPlan();
    rowOf(plan, "node-local")["pickingId"] = `pick_${"0".repeat(64)}`;
    const d = resolvePickingSelection({ scene: SCENE, plan, pickingIndex: idxOf("node-local") });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_picking_plan_invalid");

    // A row whose OWN index disagrees with its position is inconsistent.
    const plan2 = tamperedPlan();
    rowOf(plan2, "node-local")["pickingIndex"] = 17;
    const d2 = resolvePickingSelection({ scene: SCENE, plan: plan2, pickingIndex: idxOf("node-local") });
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_picking_plan_invalid");
  });

  it("a row naming a subject absent from the scene, or with wrong relations, refuses", () => {
    const plan = tamperedPlan();
    rowOf(plan, "route-28j-1")["relationIds"] = [];
    const d = resolvePickingSelection({ scene: SCENE, plan, pickingIndex: idxOf("route-28j-1") });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_picking_plan_invalid");

    const plan2 = tamperedPlan();
    rowOf(plan2, "node-local")["overlayIds"] = ["overlay:injected"];
    const d2 = resolvePickingSelection({ scene: SCENE, plan: plan2, pickingIndex: idxOf("node-local") });
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_picking_plan_invalid");
  });

  it("a malformed plan or scene is refused, not guessed at", () => {
    for (const badPlan of [{}, { sceneHash: SCENE.sceneHash }, { sceneHash: SCENE.sceneHash, planHash: "p" }, null]) {
      const d = resolvePickingSelection({ scene: SCENE, plan: badPlan, pickingIndex: 0 });
      expect(d.ok).toBe(false);
      if (!d.ok) expect(d.refusal).toBe("refused_picking_input_invalid");
    }
    const d2 = resolvePickingSelection({ scene: { sceneHash: "not-hex" }, plan: PLAN, pickingIndex: 0 });
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_picking_input_invalid");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-4 — index-to-subject semantic identity stays CPU-side", () => {
  it("the selection states the identity never left the CPU and no pixel was verified", () => {
    const s = selectionOf("node-local");
    expect(s.uploadedToGpu).toBe(false);
    expect(s.resolvedCpuSide).toBe(true);
    expect(s.pixelOutputVerified).toBe(false); // 29C measured readback all zeros
    expect(s.authority).toBe("none");
    expect(s.controlPlane).toBe(false);
    expect(s.readOnly).toBe(true);
    expect(s.executionAuthorized).toBe(false);
    expect(s.selectionConfersPermission).toBe(false);
    expect(s.isExecution).toBe(false);
    expect(s.schemaVersion).toBe("menog-picking-resolution/v0");
    expect(s.sceneHash).toBe(SCENE.sceneHash);
    expect(s.planHash).toBe(PLAN.planHash);
  });

  it("an unusable index produces a refusal with NO fallback identity leaked", () => {
    for (const bad of [-1, 1.5, PLAN.pickingResolutions.length, "0", null]) {
      const d = resolveWith({ pickingIndex: bad });
      expect(d.ok, String(bad)).toBe(false);
      if (d.ok) continue;
      expect(d.refusal).toBe("refused_picking_index_invalid");
      expect(d.selection).toBeNull();
      for (const subject of SUBJECTS) expect(d.explanation).not.toContain(subject);
    }
  });

  it("neither an index nor an id is refused as input_invalid, with no selection", () => {
    const d = refusalOf({});
    expect(d.refusal).toBe("refused_picking_input_invalid");
    expect(d.selection).toBeNull();
  });

  it("every refusal shape carries selection: null — no partial identity, ever", () => {
    const refusals = [
      refusalOf({ pickingIndex: -1 }),
      refusalOf({ pickingId: `pick_${hex64("x")}` }),
      refusalOf({ pickingIndex: idxOf("node-local"), claimedSubjectVisibleId: "other" }),
      refusalOf({ pickingIndex: 0 }, { scene: SCENE_B }),
      resolvePickingSelection(null),
      resolvePickingSelection({ execute: true }),
      resolvePickingSelection({ hideMarkers: true }),
    ];
    for (const d of refusals) {
      expect(d.ok).toBe(false);
      if (d.ok) continue;
      expect(d.selection).toBeNull();
      expect(d.explanation).toContain("no selection was produced");
      expect(d.executionAuthorized).toBe(false);
      expect(d.readOnly).toBe(true);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-5 — selection cannot hide mandatory conflict/refusal/partition markers", () => {
  it("picking a CONFLICT subject carries its own markers AND the scene-wide inventory", () => {
    const s = selectionOf("conflict:recon-28j-1:node-remote");
    expect(s.mandatoryMarkerCount).toBeGreaterThan(0);
    for (const m of s.mandatoryMarkers) {
      expect([...MANDATORY_OVERLAY_KINDS]).toContain(m.kind);
      expect(m.targetId).toBe(s.subjectVisibleId);
      expect(m.authority).toBe("none");
    }
    expect(s.sceneMandatoryMarkerCount).toBe(9);
    expect(s.sceneMandatoryMarkers.map((m) => m.kind).sort()).toEqual([
      "conflict", "conflict", "partition",
      "refusal", "refusal", "refusal", "refusal", "refusal", "refusal",
    ]);
    expect(s.markersPreserved).toBe(true);
    expect(s.hidesMandatoryMarkers).toBe(false);
  });

  it("picking a plain subject still carries the scene-wide inventory — nothing vanishes", () => {
    const s = selectionOf("node-local");
    expect(s.sceneMandatoryMarkerCount).toBe(9);
    expect(s.markersPreserved).toBe(true);
    expect(s.hidesMandatoryMarkers).toBe(false);
    expect(s.overlayCount).toBe(0);
    expect(s.mandatoryMarkerCount).toBe(0);
  });

  it("picking a REFUSAL subject and an OVERLAY-bearing subject both surface their markers", () => {
    const s = selectionOf("refusal:policy-gate");
    expect(s.overlayCount).toBe(2);
    expect(s.mandatoryMarkerCount).toBe(2);
    expect(s.overlays.map((o) => o.kind)).toEqual(["refusal", "refusal"]);
    expect(s.sceneMandatoryMarkerCount).toBe(9);
  });

  it("every marker-suppression-shaped input field refuses (driven set === vocabulary)", () => {
    const driven = new Set<string>();
    for (const field of GETIG_PICKING_MARKER_FIELDS) {
      const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: 0, [field]: true });
      expect(d.ok, field).toBe(false);
      if (d.ok) continue;
      expect(d.refusal, field).toBe("refused_picking_marker_suppression");
      expect(d.selection).toBeNull();
      driven.add(d.refusal);
    }
    expect(driven.size).toBe(1);
    expect([...GETIG_PICKING_MARKER_FIELDS].length).toBeGreaterThan(0);
  });

  it("no output key asks for, or reports, a hidden marker", () => {
    const s = selectionOf("conflict:recon-28j-1:node-remote");
    const keys = collectKeys(s);
    for (const banned of ["hidden", "occluded", "suppressed", "dismissed", "dropped"]) {
      expect([...keys].some((k) => k.toLowerCase().includes(banned))).toBe(false);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-6 — route-role picks keep roles distinct (29R1 chain honoured)", () => {
  it("the route root's relation anchors AT the root, with role origin", () => {
    const s = selectionOf("route-28j-1");
    expect(s.relationCount).toBe(1);
    const rel = s.relations[0];
    expect(rel).toBeDefined();
    if (!rel) return;
    expect(rel.relationId).toBe("route-28j-1#origin");
    expect(rel.role).toBe("origin");
    expect(rel.fromId).toBe("route-28j-1");
    expect(rel.authorizes).toBe(false);
    expect(rel.trust).toBe("none");
  });

  it("each role subject sees its own link plus the next hop — forwarder is never origin", () => {
    const origin = selectionOf("route-28j-1#origin");
    expect(origin.relations.map((r) => r.role).sort()).toEqual(["forwarder", "origin"]);
    expect(origin.relations.find((r) => r.role === "forwarder")?.fromId).toBe("route-28j-1#origin");

    const forwarder = selectionOf("route-28j-1#forwarder:node-relay");
    expect(forwarder.relations.map((r) => r.role).sort()).toEqual(["destination", "forwarder"]);
    expect(forwarder.relations.find((r) => r.role === "forwarder")?.toId).toBe(
      "route-28j-1#forwarder:node-relay",
    );

    const destination = selectionOf("route-28j-1#destination");
    expect(destination.relations.map((r) => r.role)).toEqual(["destination"]);
    for (const s of [origin, forwarder, destination]) {
      for (const r of s.relations) {
        expect(r.authorizes).toBe(false);
        expect(r.trust).toBe("none");
      }
    }
  });

  it("the four route subjects and the standalone route primitive are five DISTINCT identities", () => {
    const subjects = [
      "route-28j-1",
      "route-28j-1#origin",
      "route-28j-1#forwarder:node-relay",
      "route-28j-1#destination",
      "route:route-28j-1",
    ];
    const selections = subjects.map((s) => selectionOf(s));
    expect(new Set(selections.map((s) => s.subjectVisibleId)).size).toBe(5);
    expect(new Set(selections.map((s) => s.pickingId)).size).toBe(5);
    // Each id is resolvable only against its own row — no cross-talk.
    for (const s of selections) {
      const again = resolveWith({ pickingId: s.pickingId });
      if (!again.ok) throw new Error(`id failed: ${again.refusal}`);
      expect(again.selection.subjectVisibleId).toBe(s.subjectVisibleId);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-7 — only Phase-28 read-only inspection/explanation is reachable", () => {
  it("a pick resolves, 28G selects the SAME subject, and the selection confers nothing", () => {
    const d = inspectOf({ pickingIndex: idxOf("node-local") });
    if (!d.ok) throw new Error(`inspect refused: ${d.refusal}: ${d.explanation}`);
    expect(d.selection.subjectVisibleId).toBe("node-local");
    expect(d.inspection.ok).toBe(true);
    if (!d.inspection.ok) return;
    expect(d.inspection.operation).toBe("select");
    expect(d.inspection.mutatedCanonicalState).toBe(false);
    expect(d.inspection.authority).toBe("none");
    expect(d.inspection.readOnly).toBe(true);
    const result = d.inspection.result as unknown as Record<string, unknown>;
    expect(result["subjectVisibleId"]).toBe("node-local");
    expect(result["confersPermission"]).toBe(false);
    expect(result["isExecution"]).toBe(false);
    expect(result["grantsNothing"]).toBe(true);
    const binding = result["binding"] as Record<string, unknown>;
    expect(binding["frameId"]).toBe(BINDING.frameId);
    expect(binding["viewHash"]).toBe(BINDING.viewHash);
    expect(d.executionAuthorized).toBe(false);
    expect(d.controlPlane).toBe(false);
  });

  it("the explanation trace is BOUND to the resolved subject", () => {
    const d = inspectOf({ pickingIndex: idxOf("node-local") });
    if (!d.ok || !d.subjectExplanation) throw new Error("no explanation");
    expect(d.subjectExplanation.ok).toBe(true);
    if (!d.subjectExplanation.ok) return;
    expect(d.subjectExplanation.trace.subjectVisibleId).toBe(d.selection.subjectVisibleId);
    expect(d.subjectExplanation.trace.questionAnswered.length).toBeGreaterThan(0);
    expect(d.subjectExplanation.trace.subjectCollection.length).toBeGreaterThan(0);
  });

  it("28G's refusal for a marker subject is surfaced VERBATIM — never softened — while the explanation still binds", () => {
    const d = inspectOf({ pickingIndex: idxOf("refusal:policy-gate") });
    if (!d.ok) throw new Error(`unexpected refusal: ${d.refusal}`);
    expect(d.selection.mandatoryMarkerCount).toBe(2);
    expect(d.inspection.ok).toBe(false);
    if (d.inspection.ok) return;
    expect(d.inspection.refusal).toBe("refused_subject_unknown");
    expect(d.inspection.result).toBeNull();
    expect(d.inspection.mutatedCanonicalState).toBe(false);
    // ...and 28F still explains it, bound to the same subject.
    expect(d.subjectExplanation?.ok).toBe(true);
    if (d.subjectExplanation?.ok) {
      expect(d.subjectExplanation.trace.subjectVisibleId).toBe("refusal:policy-gate");
    }
  });

  it("a binding mismatch is 28G's refusal, passed through untouched", () => {
    const d = inspectOf(
      { pickingIndex: idxOf("node-local") },
      { binding: { ...BINDING, viewHash: hex64("wrong view") } },
    );
    if (!d.ok) throw new Error(`unexpected refusal: ${d.refusal}`);
    expect(d.inspection.ok).toBe(false);
    if (d.inspection.ok) return;
    expect(d.inspection.refusal).toMatch(/^refused_binding_/);
  });

  it("with no graph supplied the explanation is honestly null, not invented", () => {
    const d = inspectPickedSubject({
      scene: SCENE,
      plan: PLAN,
      pickingIndex: idxOf("node-local"),
      view: SC.viewLocal,
      binding: BINDING,
    });
    if (!d.ok) throw new Error(`refused: ${d.refusal}`);
    expect(d.subjectExplanation).toBeNull();
    expect(d.inspection.ok).toBe(true);
  });

  it("a resolver-level refusal from inspectPickedSubject carries inspection and explanation null too", () => {
    const d = inspectPickedSubject({
      scene: SCENE_B,
      plan: PLAN,
      pickingIndex: 0,
      view: SC.viewLocal,
      graph: SC.graph,
      binding: BINDING,
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.refusal).toBe("refused_picking_stale_scene");
    expect(d.selection).toBeNull();
    expect(d.inspection).toBeNull();
    expect(d.subjectExplanation).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-8 — no action/command/permission/grant/execute/approve surface (control-path scans)", () => {
  it("the module exports EXACTLY the resolver, the inspector, and an always-refusing guard", () => {
    const fnNames = Object.entries(pickingSurface)
      .filter(([, v]) => typeof v === "function")
      .map(([k]) => k)
      .sort();
    expect(fnNames).toEqual(
      ["inspectPickedSubject", "refusePickedSelectionExecution", "resolvePickingSelection"].sort(),
    );
  });

  it("the module's CODE contains no action verb call, GPU token, store path, clock or randomness", () => {
    for (const token of PHASE29G_FORBIDDEN_TOKENS) {
      expect(MODULE_CODE, `module code must not contain "${token}"`).not.toContain(token);
    }
  });

  it("POSITIVE CONTROL: the token scan fires on a token really present in code", () => {
    const planted = "execute(x); approve(x); queue.submit(cmd);";
    const hits = PHASE29G_FORBIDDEN_TOKENS.filter((t) => stripLiterals(planted).includes(t));
    expect(hits).toContain("execute(");
    expect(hits).toContain("approve(");
    expect(hits).toContain("queue.submit");
  });

  it("POSITIVE CONTROL: comments and string literals alone must NOT trip the scan", () => {
    const commentOnly = "// never execute( or grant( anything here\nconst a = 1;\n";
    expect(PHASE29G_FORBIDDEN_TOKENS.filter((t) => stripLiterals(commentOnly).includes(t))).toEqual([]);
    const literalOnly = 'const s = "navigator requestDevice draw(";';
    expect(PHASE29G_FORBIDDEN_TOKENS.filter((t) => stripLiterals(literalOnly).includes(t))).toEqual([]);
  });

  it("the import surface is EXACTLY the four allowed modules — no store, no coordinator, no runtime", () => {
    const imports = [...MODULE_SRC.matchAll(/from\s+"(\.[^"]+)"/g)].map((m) => m[1]);
    expect([...new Set(imports)].sort()).toEqual(
      ["./canonical.js", "./getigInspectionRuntime.js", "./getigProvenance.js", "./renderFrameComposer.js"].sort(),
    );
    for (const forbidden of ["./store.js", "./coordinator.js", "./statePersistence.js", "node:child_process"]) {
      expect(imports).not.toContain(forbidden);
    }
  });

  it("every declared ACTION field refuses, and the driven set equals the vocabulary", () => {
    const driven = new Set<string>();
    for (const field of GETIG_PICKING_ACTION_FIELDS) {
      const d = resolvePickingSelection({ [field]: true });
      expect(d.ok, field).toBe(false);
      if (d.ok) continue;
      expect(d.refusal, field).toBe("refused_picking_action_surface");
      expect(d.explanation).toContain("SELECTION != PERMISSION");
      expect(d.selection).toBeNull();
      driven.add(d.refusal);
    }
    expect(driven.size).toBe(1);
    expect(GETIG_PICKING_ACTION_FIELDS.length).toBeGreaterThanOrEqual(15);
    // And 28G's own forbidden-action names are refused by the same gate.
    for (const field of INSPECTION_FORBIDDEN_ACTIONS) {
      const d = resolvePickingSelection({ [field]: true });
      expect(d.ok, field).toBe(false);
      if (!d.ok) expect(d.refusal, field).toBe("refused_picking_action_surface");
    }
  });

  it("no output key is an exact forbidden action name from 28G's list", () => {
    const d = inspectOf({ pickingIndex: idxOf("node-local") });
    const keys = collectKeys(d);
    for (const forbidden of INSPECTION_FORBIDDEN_ACTIONS) {
      expect([...keys].includes(forbidden), forbidden).toBe(false);
    }
  });

  it("the guard can only refuse, under any input — PICKING != EXECUTION, SELECTION != PERMISSION", () => {
    for (const subject of ["node-local", "", "💥", 42 as unknown as string]) {
      const r = refusePickedSelectionExecution(subject);
      expect(r.ok).toBe(false);
      expect(r.code).toBe("execution_refused");
      expect(r.refusal).toBe("refused_picking_execution_not_permitted");
      expect(r.executed).toBe(false);
      expect(r.permissionGranted).toBe(false);
      expect(r.authority).toBe("none");
      expect(r.explanation).toContain("PICKING != EXECUTION");
      expect([...GETIG_PICKING_REFUSAL_CODES]).toContain(r.refusal);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29G-R — every declared refusal code is reachable from a real input (set equality)", () => {
  it("driven codes === declared codes: nothing unreachable, nothing undeclared", () => {
    const driven = new Set<string>();
    const drive = (d: ReturnType<typeof resolvePickingSelection>): void => {
      expect(d.ok).toBe(false);
      if (!d.ok) driven.add(d.refusal);
    };

    drive(resolvePickingSelection(null)); // input_invalid
    drive(resolvePickingSelection({ execute: true })); // action_surface
    drive(resolvePickingSelection({ hideMarkers: true })); // marker_suppression
    // plan_invalid: tampered row
    const plan = tamperedPlan();
    rowOf(plan, "node-local")["pickingId"] = `pick_${"1".repeat(64)}`;
    drive(resolvePickingSelection({ scene: SCENE, plan, pickingIndex: idxOf("node-local") }));
    drive(resolveWith({ pickingIndex: -1 })); // index_invalid
    drive(resolveWith({ pickingIndex: 0 }, { scene: SCENE_B })); // stale_scene
    drive(resolveWith({ pickingId: `pick_${hex64("nope")}` })); // unknown_id
    drive(resolveWith({ pickingIndex: 0, claimedSubjectVisibleId: "not-this" })); // subject_substitution
    // bound_exceeded: oversized table
    const hex = hex64("big");
    drive(
      resolvePickingSelection({
        scene: { sceneHash: hex, primitives: [], relations: [], overlays: [] },
        plan: {
          sceneHash: hex,
          planHash: "plan_syn",
          pickingResolutions: Array.from({ length: PICKING_BOUNDS.maxResolutions + 1 }, () => ({})),
        },
        pickingIndex: 0,
      }),
    );
    // execution_not_permitted: the guard
    const guard = refusePickedSelectionExecution("node-local");
    expect(guard.ok).toBe(false);
    driven.add(guard.refusal);

    expect([...driven].sort()).toEqual([...GETIG_PICKING_REFUSAL_CODES].sort());
  });
});
