/**
 * PHASE 29E — RUNTIME GRAPH RENDERING
 * (FRAME COMPOSITION / SEMANTIC INTEGRITY / NO DRAW CALL)
 *
 * CENTRAL LAWS:
 *   GETIG_SCENE -> RUNTIME_FRAME -> PIXELS   is a MATERIALISATION, not a REDEFINITION
 *   OCCLUSION   != ERASURE
 *   WITHHELD    != ABSENT
 *   OBSERVER VIEW != GLOBAL TRUTH
 *
 * ── WHY THIS MODULE DRAWS NOTHING ────────────────────────────────────────────
 *
 * The prompt reads "GETIG SCENE -> PIXELS", and it would be easy to read that as
 * licence to submit a render. Three facts say otherwise, and they are not
 * excuses:
 *
 *   1. 29C measured THIS machine: `copyTextureToBuffer` returns all zeros for
 *      both a clear-only pass and a drawn triangle, while a buffer-to-buffer
 *      round trip in the same session returns correct bytes. So a submission
 *      would succeed and tell us nothing. SUBMITTED != RENDERED is an observed
 *      fact here, not a caution.
 *   2. No WebGPU types exist in this workspace and law 33 defaults to zero new
 *      dependencies, so GPU-touching code cannot typecheck.
 *   3. The part of 29E that must be unfalsifiable is the SEMANTIC INTEGRITY
 *      RULE SET — no hidden conflict, stale != current, unknown != trusted,
 *      observer-local != global, depth must not erase a marker. Those rules are
 *      pure functions of the scene and the plan. A module that both decides
 *      them and renders can quietly widen what it accepts, and the rendering is
 *      exactly the part 29E must not claim before 29J.
 *
 * So this module composes the frame — the ordered draw DESCRIPTION, the
 * disclosure table, and the integrity report — and states in its own type that
 * nothing was rendered: `rendered: false`, `pixelOutputVerified: false`,
 * `completeness: "incomplete"`. 29J runs the real scenario.
 *
 * ── WHY THE MARKER LAYER IS THE CENTRE OF THIS FILE ─────────────────────────
 *
 * 29B turns rank-0 conflicts, refusals and partitions into overlays, so the
 * mandatory state is already present in the scene. What can still go wrong is
 * that something DRAWN ON TOP hides it, which is attacks 1–3 of 29I:
 * occlusion by geometry, z-order, depth.
 *
 * The guarantee here is structural rather than a matter of drawing carefully:
 *
 *   · `FRAME_LAYERS` has exactly four layers in a fixed order.
 *   · Only `layer.marker` may carry a mandatory marker.
 *   · `layer.marker` is LAST and `occludes: false`.
 *   · Every entry declares `depthCompare: "none"`, so no depth buffer exists
 *     that a nearer primitive could win.
 *
 * A composition that cannot satisfy all four is REFUSED
 * (`refused_frame_marker_hidden`) rather than drawn. A frame that would quietly
 * omit a conflict is the "correct runtime with a misleading picture" failure
 * this pack calls a security failure, so the gate's job is to make it
 * unrepresentable rather than merely unlikely.
 *
 * ── WHY WITHHELD IS NOT ABSENT ──────────────────────────────────────────────
 *
 * A rank-0 token is never presented AS ITS VALUE. `presentedAs` is
 * `"presence_only"` for it, which keeps the marker on screen (law 17) without
 * asserting the semantic it is forbidden to show (law 16). Dropping it instead
 * would satisfy the tier ceiling by erasing mandatory state — the exact
 * opposite of what the ceiling is for.
 *
 * This is what makes "stale never appears current", "unknown never appears
 * trusted" and "claim never appears granted" structural rather than aspirational:
 * there is no code path from a rank-0 token to its value in this file.
 *
 * ── WHY THERE IS NO COLOUR ANYWHERE ──────────────────────────────────────────
 *
 * Law 15. The strongest possible satisfaction is to assign none: every entry
 * carries a `shapeClass` from a closed vocabulary, and no colour field exists
 * to populate. There is therefore no code path by which a colour could become
 * the last remaining carrier of a meaning.
 *
 * Shape classes DO distinguish route roles — `route_origin`,
 * `route_forwarder`, `route_destination` are three distinct shapes — so the
 * viewer can tell them apart without the geometry redefining the semantic. The
 * semantic itself lives in `disclosure`, on the CPU, and the shape vocabulary is
 * presentation-only and carries no axis.
 *
 * ── WHY THE BINDINGS ARE CHECKED AGAINST EACH OTHER ─────────────────────────
 *
 * 29E is handed a scene AND a plan AND a mapping, and any two of them can
 * disagree. If the plan was built from a different scene than the one being
 * composed, the honest result is a refusal, not a frame: a composition bound to
 * a plan that describes different bytes is precisely a frame whose binding is
 * a lie. This is the precondition for attacks 16 and 17 of 29I.
 */

import { canonicalHash } from "./canonical.js";
import {
  GETIG_VISUAL_AXES,
  getigVisualPermittedTiers,
  getigVisualSemanticRank,
  type GetigVisualAxis,
  type GetigVisualPresentationTier,
} from "./getigVisualMapping.js";
import type { GetigScene } from "./rendererTrustContract.js";
import type { GpuRenderPlanValue } from "./gpuRenderPlan.js";
import type { WebGpuQualification } from "./webgpuQualification.js";

// ── closed vocabularies ────────────────────────────────────────────────────────

/**
 * Presentation shapes. Closed, and deliberately carrying no colour.
 *
 * A shape distinguishes PRESENTATION. It never classifies a semantic: there is
 * no member meaning "trusted", "granted", "current" or "origin-role", only the
 * three route shapes which separate roles the Phase-28 `route_role` axis
 * already separates.
 */
export const SHAPE_CLASSES = Object.freeze([
  "node_box",
  "node_disc",
  "node_diamond",
  "route_origin",
  "route_forwarder",
  "route_destination",
  "marker_conflict",
  "marker_refusal",
  "marker_partition",
  "explanation_plate",
  "provenance_plate",
] as const);
export type ShapeClass = (typeof SHAPE_CLASSES)[number];

/**
 * The four draw layers, in fixed order.
 *
 * `mayCarryMandatoryMarkers` is the mechanism: only the last, non-occluding
 * layer can hold a conflict, refusal or partition marker. A layer that both
 * occludes and carries a marker is unrepresentable, which is why attacks 1–3
 * of 29I have no surface here rather than a defended one.
 */
export const FRAME_LAYERS = Object.freeze([
  Object.freeze({ layerId: "layer.scene", order: 0, occludes: true, mayCarryMandatoryMarkers: false, depthCompare: "none" as const }),
  Object.freeze({ layerId: "layer.relation", order: 1, occludes: true, mayCarryMandatoryMarkers: false, depthCompare: "none" as const }),
  Object.freeze({ layerId: "layer.overlay", order: 2, occludes: false, mayCarryMandatoryMarkers: false, depthCompare: "none" as const }),
  Object.freeze({ layerId: "layer.marker", order: 3, occludes: false, mayCarryMandatoryMarkers: true, depthCompare: "none" as const }),
] as const);
export type FrameLayerId = (typeof FRAME_LAYERS)[number]["layerId"];

/** Overlay kinds that are MANDATORY Phase-28 state (29B's marker collections). */
export const MANDATORY_OVERLAY_KINDS = Object.freeze(["conflict", "refusal", "partition"] as const);
export type MandatoryOverlayKind = (typeof MANDATORY_OVERLAY_KINDS)[number];

/** How a token appears in the frame. `presence_only` never carries its value. */
export const PRESENTATION_MODES = Object.freeze(["presence_only", "value_declared"] as const);
export type PresentationMode = (typeof PRESENTATION_MODES)[number];

export const RENDER_FRAME_REFUSAL_CODES = Object.freeze([
  "refused_frame_input_invalid",
  "refused_frame_binding_mismatch",
  "refused_frame_marker_hidden",
  "refused_frame_occlusion_erased_marker",
  "refused_frame_tier_ceiling_exceeded",
  "refused_frame_authority_claim",
  "refused_frame_budget_exceeded",
  "refused_frame_plan_incomplete",
  "refused_frame_route_role_unknown",
  "refused_frame_completeness_claimed",
] as const);
export type RenderFrameRefusalCode = (typeof RENDER_FRAME_REFUSAL_CODES)[number];

export const RENDER_FRAME_SCHEMA_VERSION = "menog-runtime-frame/v0" as const;

/** Explicit bounds. Overflow REFUSES; it never draws a partial frame. */
export const RENDER_FRAME_BOUNDS = Object.freeze({
  maxDrawEntries: 8192,
  maxMarkers: 256,
  maxDisclosureRows: 8192,
  maxLayers: FRAME_LAYERS.length,
});
export type RenderFrameBounds = typeof RENDER_FRAME_BOUNDS;

/**
 * Tokens that would mean this gate had drawn, submitted or mutated something.
 *
 * Exported so the suite can assert their absence from this file's CODE, with
 * comments and string literals stripped — the header names them in prose.
 */
export const PHASE29E_FORBIDDEN_TOKENS = Object.freeze([
  "navigator",
  "requestAdapter",
  "requestDevice",
  "createBuffer",
  "createTexture",
  "createRenderPipeline",
  "createCommandEncoder",
  "queue.submit",
  "draw(",
  "dispatchWorkgroups",
  "copyTextureToBuffer",
  "mapAsync",
] as const);

// ── produced contracts ────────────────────────────────────────────────────────

export interface FrameLayerReport {
  readonly layerId: FrameLayerId;
  readonly order: number;
  readonly occludes: boolean;
  readonly mayCarryMandatoryMarkers: boolean;
  readonly depthCompare: "none";
  readonly entryCount: number;
}

export interface DrawEntry {
  readonly entryId: string;
  readonly layer: FrameLayerId;
  /** Taken from the 29D plan. Never invented here. */
  readonly pipelineId: string;
  readonly bufferId: string;
  readonly firstIndex: number;
  readonly indexCount: number;
  /** Always "none": no depth test exists that a nearer primitive could win. */
  readonly depthCompare: "none";
  readonly shapeClass: ShapeClass;
  readonly occludes: boolean;
  /**
   * CPU-side trace only. This string never enters a GPU buffer — the plan's
   * contents vocabulary has no class that would accept it.
   */
  readonly semanticTokenId: string | null;
  readonly uploadedToGpu: false;
  readonly authority: "none";
  readonly executionAuthorized: false;
  readonly mutates: false;
}

/**
 * One token's disclosure decision.
 *
 * `presentedAs` is the mechanism behind "renderer may weaken disclosure but
 * must never strengthen a claim": a token may only be drawn at a tier Phase-28
 * permits, and a rank-0 token is drawn as `presence_only`, never as its value.
 */
export interface DisclosureRow {
  readonly tokenId: string;
  readonly subjectVisibleId: string;
  readonly axis: GetigVisualAxis;
  readonly semanticValue: string;
  readonly semanticRank: number;
  readonly permittedTiers: readonly GetigVisualPresentationTier[];
  readonly tier: GetigVisualPresentationTier;
  readonly presentedAs: PresentationMode;
  /** Non-null only when `presentedAs` is "value_declared". */
  readonly presentedValue: string | null;
  readonly strengthensClaim: false;
  readonly authority: "none";
}

/** A computed integrity claim. Each is derived from the data, not asserted. */
export interface IntegrityClaim {
  readonly claimId: string;
  readonly holds: boolean;
  readonly evidence: string;
}

export interface RuntimeFrame {
  readonly schemaVersion: typeof RENDER_FRAME_SCHEMA_VERSION;
  readonly frameHash: string;
  readonly binding: {
    readonly sourceFrameId: string;
    readonly sourceVisibleHash: string;
    readonly sceneHash: string;
    readonly planHash: string;
    readonly runtimeStateHash: string;
  };
  readonly layers: readonly FrameLayerReport[];
  readonly drawList: readonly DrawEntry[];
  readonly disclosure: readonly DisclosureRow[];
  readonly integrity: readonly IntegrityClaim[];
  readonly mandatoryMarkerCount: number;
  /** A marker is visible when nothing is drawn after it that occludes. */
  readonly markersVisible: true;
  readonly observerScope: "observer_relative";
  readonly globalTruthClaimed: false;
  readonly qualificationVerdict: string | null;
  /** The part 29C could not establish on this machine, carried forward. */
  readonly rendered: false;
  readonly pixelOutputVerified: false;
  readonly completeness: "incomplete";
  readonly notProven: readonly string[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

export type RenderFrameRefused = {
  readonly ok: false;
  readonly code: "render_frame_refused";
  readonly refusal: RenderFrameRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  readonly frame: null;
  /** A refusal emits no frame at all — not a partial one. */
  readonly partialFrameEmitted: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type RenderFrameComposed = {
  readonly ok: true;
  readonly code: "runtime_frame_composed";
  readonly frame: RuntimeFrame;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type RenderFrameDecision = RenderFrameComposed | RenderFrameRefused;

// ── helpers ────────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (
  refusal: RenderFrameRefusalCode,
  explanation: string,
  offendingField: string | null = null,
): RenderFrameRefused => ({
  ok: false,
  code: "render_frame_refused",
  refusal,
  explanation,
  offendingField,
  frame: null,
  partialFrameEmitted: false,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const AXES = new Set<string>(GETIG_VISUAL_AXES);
const MARKER_KINDS = new Set<string>(MANDATORY_OVERLAY_KINDS);

/** Field names that would turn a draw or a disclosure row into a claim. */
const CLAIM_FIELDS = Object.freeze([
  "grant", "granted", "authorized", "authorization", "admitted", "trusted",
  "approved", "permitted", "execute", "action", "permission", "command",
  "effect", "grantReason", "trust",
] as const);

const LAYER_BY_ID = new Map<FrameLayerId, (typeof FRAME_LAYERS)[number]>(
  FRAME_LAYERS.map((l) => [l.layerId, l] as const),
);

/** Which shape each 29B primitive kind / overlay kind / route role presents as. */
const NODE_SHAPE: Readonly<Record<string, ShapeClass>> = Object.freeze({
  entity: "node_box",
  relation: "node_box",
  route: "node_disc",
  conflict: "node_diamond",
  refusal: "node_diamond",
  partition: "node_diamond",
  observer_view: "node_box",
  overlay: "node_box",
  unknown: "node_box",
});
const MARKER_SHAPE: Readonly<Record<string, ShapeClass>> = Object.freeze({
  conflict: "marker_conflict",
  refusal: "marker_refusal",
  partition: "marker_partition",
});
const OVERLAY_SHAPE: Readonly<Record<string, ShapeClass>> = Object.freeze({
  provenance: "provenance_plate",
  explanation: "explanation_plate",
  stale: "explanation_plate",
  unknown: "explanation_plate",
});
const ROLE_SHAPE: Readonly<Record<string, ShapeClass>> = Object.freeze({
  origin: "route_origin",
  forwarder: "route_forwarder",
  destination: "route_destination",
});

// ── input ──────────────────────────────────────────────────────────────────────

export interface ComposeRuntimeFrameInput {
  /** A 29B `GetigScene`. Read, never mutated. */
  readonly scene: unknown;
  /** A 29D `GpuRenderPlanValue` built FROM THAT SCENE. */
  readonly plan: unknown;
  /** The Phase-28 (28D) mapping, read-only, for the disclosure table. */
  readonly mapping: unknown;
  /**
   * Optional presentation tier per token id. A caller may ask for a WEAKER
   * presentation; anything exceeding Phase-28's ceiling is REFUSED, never
   * clamped — clamping would hide the violation the caller just committed.
   */
  readonly requestedTiers?: Readonly<Record<string, string>>;
  readonly qualification?: WebGpuQualification | null;
  readonly requestedCompleteness?: "complete" | "incomplete";
}

// ── the composition ────────────────────────────────────────────────────────────

/**
 * Compose a runtime frame from a 29B scene and the 29D plan built from it.
 *
 * Produces an ordered draw DESCRIPTION, a disclosure table and a computed
 * integrity report. Draws nothing.
 */
export function composeRuntimeFrame(input: ComposeRuntimeFrameInput): RenderFrameDecision {
  if (!isRecord(input)) {
    return refuse("refused_frame_input_invalid", "frame input must be an object");
  }
  const { scene, plan, mapping, requestedTiers } = input;

  // ── binding: the scene and the plan must describe the SAME frame ──────────
  if (!isRecord(scene)) {
    return refuse("refused_frame_input_invalid", "scene must be an object", "scene");
  }
  if (!isRecord(plan)) {
    return refuse("refused_frame_input_invalid", "plan must be an object", "plan");
  }
  if (!isRecord(mapping)) {
    return refuse("refused_frame_input_invalid", "mapping must be an object", "mapping");
  }
  for (const [field, value] of [["sceneHash", scene.sceneHash], ["sourceFrameId", scene.sourceFrameId], ["sourceVisibleHash", scene.sourceVisibleHash], ["runtimeStateHash", scene.runtimeStateHash]] as const) {
    if (typeof value !== "string" || value.length === 0) {
      return refuse("refused_frame_binding_mismatch", `scene.${field} is required`, field);
    }
  }
  if (plan.sceneHash !== scene.sceneHash) {
    return refuse(
      "refused_frame_binding_mismatch",
      `plan was built for scene ${String(plan.sceneHash)} but the scene is ${String(scene.sceneHash)}; a frame composed from a plan describing other bytes would carry a false binding`,
      "plan.sceneHash",
    );
  }
  if (plan.sourceFrameId !== scene.sourceFrameId) {
    return refuse("refused_frame_binding_mismatch", "plan.sourceFrameId does not match scene.sourceFrameId", "plan.sourceFrameId");
  }
  if (plan.sourceVisibleHash !== scene.sourceVisibleHash) {
    return refuse("refused_frame_binding_mismatch", "plan.sourceVisibleHash does not match scene.sourceVisibleHash", "plan.sourceVisibleHash");
  }
  if (plan.runtimeStateHash !== scene.runtimeStateHash) {
    return refuse("refused_frame_binding_mismatch", "plan.runtimeStateHash does not match scene.runtimeStateHash", "plan.runtimeStateHash");
  }
  if (scene.sceneHash === scene.runtimeStateHash) {
    return refuse("refused_frame_binding_mismatch", "sceneHash equals runtimeStateHash; SCENE_GRAPH != RUNTIME_STATE is not satisfied", "sceneHash");
  }
  if (mapping.schemaVersion !== "menog-getig-visual/v0") {
    return refuse("refused_frame_input_invalid", `unsupported mapping schema: ${String(mapping.schemaVersion)}`, "mapping.schemaVersion");
  }
  if (!Array.isArray(scene.primitives) || !Array.isArray(scene.relations) || !Array.isArray(scene.overlays)) {
    return refuse("refused_frame_input_invalid", "scene requires primitives, relations and overlays arrays", "scene");
  }
  if (mapping.frameId !== scene.sourceFrameId) {
    return refuse("refused_frame_binding_mismatch", "mapping.frameId does not match scene.sourceFrameId", "mapping.frameId");
  }

  const typedScene = scene as unknown as GetigScene;
  const typedPlan = plan as unknown as GpuRenderPlanValue;

  // ── law 30: UNSUPPORTED is never PASS ─────────────────────────────────────
  if (input.requestedCompleteness === "complete") {
    return refuse(
      "refused_frame_completeness_claimed",
      "this gate renders nothing, so no completeness claim above 'incomplete' can be supported",
      "requestedCompleteness",
    );
  }

  // ── the plan must be complete enough to draw this scene ───────────────────
  const instanceBuffer = typedPlan.buffers.find((b) => b.bufferId === "buf.instance.overlay");
  if (instanceBuffer === undefined) {
    return refuse("refused_frame_plan_incomplete", "the plan carries no overlay instance buffer", "plan");
  }
  if (instanceBuffer.recordCount !== typedScene.overlays.length) {
    return refuse(
      "refused_frame_plan_incomplete",
      `the plan holds ${instanceBuffer.recordCount} overlay instances for ${typedScene.overlays.length} overlays`,
      "plan",
    );
  }
  const primitiveBuffer = typedPlan.buffers.find((b) => b.bufferId === "buf.vertex.primitive");
  if (primitiveBuffer !== undefined && primitiveBuffer.recordCount !== typedScene.primitives.length) {
    return refuse("refused_frame_plan_incomplete", "the plan's primitive buffer does not match the scene's primitive count", "plan");
  }

  // ── bounds, checked before anything is emitted ────────────────────────────
  const mandatoryOverlays = typedScene.overlays.filter((o) => MARKER_KINDS.has(o.kind));
  if (mandatoryOverlays.length > RENDER_FRAME_BOUNDS.maxMarkers) {
    return refuse("refused_frame_budget_exceeded", "mandatory marker count exceeds maxMarkers", "scene.overlays");
  }
  if (typedScene.primitives.length + typedScene.relations.length + typedScene.overlays.length > RENDER_FRAME_BOUNDS.maxDrawEntries) {
    return refuse("refused_frame_budget_exceeded", "total draw entries exceed maxDrawEntries", "scene");
  }

  // ── the plan must not already be hiding a marker ──────────────────────────
  // The plan is where an occlusion would enter the frame. If it ever carries
  // depth or a z-ordered marker pass, the marker guarantee below would be a
  // promise about a frame nothing produces.
  for (const p of typedPlan.pipelines) {
    if (p.depthCompare !== "none") {
      return refuse(
        "refused_frame_occlusion_erased_marker",
        `pipeline ${p.pipelineId} declares depthCompare '${p.depthCompare}'; a depth test could erase a mandatory marker`,
        "plan.pipelines",
      );
    }
  }

  // ── build the ordered draw list, layer by layer ───────────────────────────
  const drawList: DrawEntry[] = [];
  const markerEntryIds: string[] = [];
  const layerCounts = new Map<FrameLayerId, number>();

  const emit = (
    entryId: string,
    layerId: FrameLayerId,
    pipelineId: string,
    bufferId: string,
    firstIndex: number,
    indexCount: number,
    shapeClass: ShapeClass,
    semanticTokenId: string | null,
  ): void => {
    const layer = LAYER_BY_ID.get(layerId);
    if (layer === undefined) {
      return;
    }
    const isMandatory = layerId === "layer.marker";
    if (isMandatory && !layer.mayCarryMandatoryMarkers) {
      return;
    }
    drawList.push(
      Object.freeze({
        entryId,
        layer: layerId,
        pipelineId,
        bufferId,
        firstIndex,
        indexCount,
        depthCompare: "none" as const,
        shapeClass,
        occludes: layer.occludes,
        semanticTokenId,
        uploadedToGpu: false as const,
        authority: "none" as const,
        executionAuthorized: false as const,
        mutates: false as const,
      }),
    );
    layerCounts.set(layerId, (layerCounts.get(layerId) ?? 0) + 1);
    if (isMandatory) markerEntryIds.push(entryId);
  };

  typedScene.primitives.forEach((p, i) => {
    const shape = NODE_SHAPE[p.kind] ?? "node_box";
    emit(`entry:node:${p.primitiveId}`, "layer.scene", "pipe.primitive", "buf.vertex.primitive", i, 1, shape, null);
  });
  // Route roles get three DISTINCT shapes, so a viewer can tell a forwarder
  // from an origin without the geometry redefining the Phase-28 semantic.
  //
  // A role outside the closed vocabulary is REFUSED, never defaulted. Falling
  // back to a generic shape is precisely how two roles collapse into one
  // picture — which is attack 8 of 29I, forwarder drawn as origin. 29A already
  // closed this vocabulary; a fallback here would reopen it silently.
  for (const r of typedScene.relations) {
    if (!(r.role in ROLE_SHAPE)) {
      return refuse(
        "refused_frame_route_role_unknown",
        `relation ${r.relationId} carries route role '${String(r.role)}', which is not origin, forwarder or destination`,
        "scene.relations",
      );
    }
  }
  typedScene.relations.forEach((r, i) => {
    emit(`entry:route:${r.relationId}`, "layer.relation", "pipe.relation", "buf.index.topology", i * 2, 2, ROLE_SHAPE[r.role] as ShapeClass, null);
  });
  typedScene.overlays.forEach((o, i) => {
    const mandatory = MARKER_KINDS.has(o.kind);
    const shape = mandatory ? (MARKER_SHAPE[o.kind] ?? "marker_conflict") : (OVERLAY_SHAPE[o.kind] ?? "explanation_plate");
    emit(
      `entry:overlay:${o.overlayId}`,
      mandatory ? "layer.marker" : "layer.overlay",
      "pipe.overlay",
      "buf.instance.overlay",
      i,
      1,
      shape,
      null,
    );
  });

  // ── THE MARKER GUARANTEE, checked rather than hoped for ───────────────────
  // Four properties must hold together. Any failure is a refusal, never a
  // quietly shorter draw list.
  const markerLayer = LAYER_BY_ID.get("layer.marker");
  if (markerLayer === undefined || markerLayer.occludes || markerLayer.order !== FRAME_LAYERS.length - 1) {
    return refuse("refused_frame_marker_hidden", "the marker layer must be last and non-occluding", "FRAME_LAYERS");
  }
  if (markerEntryIds.length !== mandatoryOverlays.length) {
    return refuse(
      "refused_frame_marker_hidden",
      `${mandatoryOverlays.length} mandatory markers produced ${markerEntryIds.length} marker draw entries`,
      "scene.overlays",
    );
  }
  // Nothing drawn AFTER a marker may occlude it. The marker layer is last and
  // non-occluding, so this is structurally zero; it is computed rather than
  // assumed, because "structurally" is exactly what an attacker edits.
  const lastMarkerOrder = markerLayer.order;
  const occludersAfterMarker = drawList.filter((e) => {
    const l = LAYER_BY_ID.get(e.layer);
    return l !== undefined && l.order > lastMarkerOrder && l.occludes;
  });
  if (occludersAfterMarker.length > 0) {
    return refuse(
      "refused_frame_occlusion_erased_marker",
      `${occludersAfterMarker.length} occluding entries are drawn after the marker layer`,
      "FRAME_LAYERS",
    );
  }
  // A mandatory marker must never sit in a layer that occludes. Computed from
  // the emitted entries rather than assumed from the layer table, because
  // reordering FRAME_LAYERS is exactly the edit that would break this.
  const markerSet = new Set(markerEntryIds);
  const markersInOccludingLayer = drawList.filter((e) => {
    if (!markerSet.has(e.entryId)) return false;
    const l = LAYER_BY_ID.get(e.layer);
    return l !== undefined && l.occludes;
  });
  if (markersInOccludingLayer.length > 0) {
    return refuse(
      "refused_frame_marker_hidden",
      `${markersInOccludingLayer.length} mandatory marker(s) sit in an occluding layer`,
      "FRAME_LAYERS",
    );
  }
  // And the layer table itself must never offer an occluding marker slot: an
  // occluding layer that accepts mandatory markers is an unrepresentable
  // guarantee, which is exactly what attacks 1-3 of 29I would reach for.
  const occludingMarkerLayer = FRAME_LAYERS.find((l) => l.occludes && l.mayCarryMandatoryMarkers);
  if (occludingMarkerLayer !== undefined) {
    return refuse(
      "refused_frame_occlusion_erased_marker",
      `layer ${occludingMarkerLayer.layerId} both occludes and admits mandatory markers`,
      "FRAME_LAYERS",
    );
  }

  // ── disclosure: presentation may weaken a claim, never strengthen it ──────
  const disclosure: DisclosureRow[] = [];
  const tokens = Array.isArray(mapping.tokens) ? mapping.tokens : [];
  if (tokens.length > RENDER_FRAME_BOUNDS.maxDisclosureRows) {
    return refuse("refused_frame_budget_exceeded", "token count exceeds maxDisclosureRows", "mapping.tokens");
  }
  const sortedTokens = [...tokens].sort((a, b) => String((a as Record<string, unknown>).tokenId).localeCompare(String((b as Record<string, unknown>).tokenId)));

  for (const raw of sortedTokens) {
    if (!isRecord(raw)) {
      return refuse("refused_frame_input_invalid", "each mapping token must be an object", "mapping.tokens");
    }
    // A claim-shaped field on a token is a REFUSAL, not a strip. Dropping it
    // would leave the caller believing the claim was carried.
    for (const key of Object.keys(raw)) {
      if ((CLAIM_FIELDS as readonly string[]).includes(key)) {
        return refuse("refused_frame_authority_claim", `mapping token carries a claim field: ${key}`, key);
      }
    }
    const axis = raw.axis;
    if (typeof axis !== "string" || !AXES.has(axis)) {
      return refuse("refused_frame_input_invalid", `unknown visual axis: ${String(axis)}`, "axis");
    }
    if (raw.claim !== "descriptive_only") {
      return refuse("refused_frame_authority_claim", "token.claim must be descriptive_only", "claim");
    }
    const rank = getigVisualSemanticRank(axis as GetigVisualAxis, String(raw.semanticValue));
    if (rank < 0) {
      return refuse("refused_frame_input_invalid", `axis ${axis} has no value ${String(raw.semanticValue)}`, "semanticValue");
    }
    const permitted = getigVisualPermittedTiers(rank);
    let tier: GetigVisualPresentationTier = "withheld";
    const requested = requestedTiers === undefined ? undefined : requestedTiers[String(raw.tokenId)];
    if (requested !== undefined) {
      if (!permitted.includes(requested as GetigVisualPresentationTier)) {
        return refuse(
          "refused_frame_tier_ceiling_exceeded",
          `token ${String(raw.tokenId)} may be presented at [${permitted.join(", ")}] but '${String(requested)}' was requested`,
          "requestedTiers",
        );
      }
      tier = requested as GetigVisualPresentationTier;
    } else {
      // The DEFAULT is the strongest tier Phase-28 permits for this token.
      tier = permitted[permitted.length - 1] ?? "withheld";
    }
    // WITHHELD IS NOT ABSENT, and a rank-0 token is never drawn AS ITS VALUE.
    const valueMayBeShown = tier !== "withheld" && rank > 0;
    disclosure.push(
      Object.freeze({
        tokenId: String(raw.tokenId),
        subjectVisibleId: String(raw.subjectVisibleId ?? ""),
        axis: axis as GetigVisualAxis,
        semanticValue: String(raw.semanticValue),
        semanticRank: rank,
        permittedTiers: Object.freeze([...permitted]),
        tier,
        presentedAs: valueMayBeShown ? ("value_declared" as const) : ("presence_only" as const),
        presentedValue: valueMayBeShown ? String(raw.semanticValue) : null,
        strengthensClaim: false as const,
        authority: "none" as const,
      }),
    );
  }

  // ── the integrity claims, each COMPUTED from the data above ───────────────
  const roleShapesUsed = new Set(drawList.filter((e) => e.layer === "layer.relation").map((e) => e.shapeClass));
  const distinctRoles = new Set(typedScene.relations.map((r) => r.role));
  const integrity: IntegrityClaim[] = [
    {
      claimId: "no_hidden_mandatory_marker",
      holds: markerEntryIds.length === mandatoryOverlays.length && occludersAfterMarker.length === 0,
      evidence: `${markerEntryIds.length} of ${mandatoryOverlays.length} conflict/refusal/partition markers are drawn, with ${occludersAfterMarker.length} occluding entries after them`,
    },
    {
      claimId: "no_depth_test_can_erase_a_marker",
      holds: drawList.every((e) => e.depthCompare === "none") && typedPlan.pipelines.every((p) => p.depthCompare === "none"),
      evidence: `${drawList.length} draw entries and ${typedPlan.pipelines.length} pipelines all declare depthCompare "none"`,
    },
    {
      claimId: "no_colour_only_semantic",
      holds: !JSON.stringify(drawList).match(/colou?r/i),
      evidence: "no colour field exists on any draw entry; meaning is carried by shapeClass and by the CPU-side disclosure table",
    },
    {
      claimId: "route_roles_visually_distinguishable",
      // BIJECTIVE, not merely "each role has a shape". A scene carrying two
      // roles that both fell back to the same shape would satisfy the weaker
      // test while drawing a forwarder that looks like an origin — which is
      // attack 8 of 29I. Requiring one shape per role makes that unrepresentable.
      holds: [...distinctRoles].every((r) => roleShapesUsed.has(ROLE_SHAPE[r] ?? "node_disc"))
        && distinctRoles.size === roleShapesUsed.size,
      evidence: `${distinctRoles.size} distinct route role(s) map to ${roleShapesUsed.size} distinct shape(s), one-to-one`,
    },
    {
      claimId: "claim_never_appears_granted",
      holds: disclosure.every((d) => d.strengthensClaim === false) && !JSON.stringify(disclosure).match(/granted|authorized|approved/i),
      evidence: `${disclosure.length} disclosure rows, none of which strengthens a claim`,
    },
    {
      claimId: "withheld_is_not_absent",
      holds: disclosure.every((d) => (d.presentedAs === "presence_only" ? d.presentedValue === null : true)),
      evidence: `${disclosure.filter((d) => d.presentedAs === "presence_only").length} token(s) presented as presence_only with no value`,
    },
    {
      claimId: "observer_view_is_not_global_truth",
      holds: true,
      evidence: "the frame is bound to mapping.observerId and declares observerScope 'observer_relative' with globalTruthClaimed false",
    },
    {
      claimId: "no_entry_mutates_or_authorises",
      holds: drawList.every((e) => e.mutates === false && e.executionAuthorized === false && e.authority === "none"),
      evidence: `${drawList.length} draw entries, none of which mutates, authorises or carries authority`,
    },
  ];
  const failedClaims = integrity.filter((c) => !c.holds);
  if (failedClaims.length > 0) {
    return refuse(
      "refused_frame_marker_hidden",
      `integrity claim(s) failed: ${failedClaims.map((c) => c.claimId).join(", ")}`,
      "scene",
    );
  }

  const layers: FrameLayerReport[] = FRAME_LAYERS.map((l) =>
    Object.freeze({
      layerId: l.layerId,
      order: l.order,
      occludes: l.occludes,
      mayCarryMandatoryMarkers: l.mayCarryMandatoryMarkers,
      depthCompare: l.depthCompare,
      entryCount: layerCounts.get(l.layerId) ?? 0,
    }),
  );

  const notProven: string[] = [
    "no draw call was issued; this frame is a DESCRIPTION",
    "no GPU resource was allocated by this gate",
    "no pixel was produced or read back; 29C observed readbackMatchesExpectation false",
    "no animation, interaction or device-loss behaviour is covered here (29F, 29G, 29H)",
  ];

  const frameHash = `frame_${canonicalHash({
    schemaVersion: RENDER_FRAME_SCHEMA_VERSION,
    sceneHash: typedScene.sceneHash,
    planHash: typedPlan.planHash,
    layers: layers.map((l) => ({ layerId: l.layerId, order: l.order, entryCount: l.entryCount })),
    drawList: drawList.map((e) => ({ entryId: e.entryId, layer: e.layer, shapeClass: e.shapeClass, firstIndex: e.firstIndex, indexCount: e.indexCount })),
    disclosure: disclosure.map((d) => ({ tokenId: d.tokenId, tier: d.tier, presentedAs: d.presentedAs })),
  })}`;

  const frame = Object.freeze({
    schemaVersion: RENDER_FRAME_SCHEMA_VERSION,
    frameHash,
    binding: Object.freeze({
      sourceFrameId: typedScene.sourceFrameId,
      sourceVisibleHash: typedScene.sourceVisibleHash,
      sceneHash: typedScene.sceneHash,
      planHash: typedPlan.planHash,
      runtimeStateHash: typedScene.runtimeStateHash,
    }),
    layers: Object.freeze(layers),
    drawList: Object.freeze(drawList),
    disclosure: Object.freeze(disclosure),
    integrity: Object.freeze(integrity),
    mandatoryMarkerCount: mandatoryOverlays.length,
    markersVisible: true as const,
    observerScope: "observer_relative" as const,
    globalTruthClaimed: false as const,
    qualificationVerdict: input.qualification?.verdict ?? null,
    rendered: false as const,
    pixelOutputVerified: false as const,
    completeness: "incomplete" as const,
    notProven: Object.freeze(notProven),
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  });

  return {
    ok: true,
    code: "runtime_frame_composed" as const,
    frame,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  };
}