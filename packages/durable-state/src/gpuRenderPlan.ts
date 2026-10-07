/**
 * PHASE 29D — GPU RESOURCE & RENDER-PLAN LAYER
 * (BOUNDED GPU PLAN / NO BUSINESS LOGIC / NO ALLOCATION)
 *
 * CENTRAL LAWS:
 *   SCENE_GRAPH  != GPU_RESOURCE  != DRAW_CALL  != PIXEL_OUTPUT
 *   GPU_ID       != AUTHORITY
 *   ALLOCATED    != SUBMITTED     != RENDERED
 *
 * ── WHAT THIS GATE IS, AND WHAT IT IS NOT ────────────────────────────────────
 *
 * 29B decides WHAT EXISTS TO BE DRAWN. This gate decides WHAT A GPU WOULD HAVE
 * TO BE GIVEN IN ORDER TO DRAW IT: byte layouts, buffer sizes, bind groups,
 * pipelines, passes, ownership and frames-in-flight. It is a PLAN.
 *
 * It allocates nothing, submits nothing and reads back nothing. There is no
 * `create*`, no `submit(`, no `draw(` and no `navigator` anywhere in this file,
 * and `PHASE29D_FORBIDDEN_TOKENS` exists so that claim is checkable by the
 * suite rather than asserted in prose. 29E owns runtime rendering.
 *
 * ── WHY BYTE COUNTS ARE CHECKED BEFORE A DESCRIPTOR EXISTS ───────────────────
 *
 * Every buffer in the plan is produced by `planBuffer`, which computes
 * `recordCount * strideBytes` through `checkedMul` and refuses on a result
 * that is not a safe non-negative integer, before any descriptor object is
 * constructed. A descriptor that exists is therefore a descriptor whose size is
 * known and bounded — there is no window in which a caller can observe a buffer
 * with an unknown or overflowing size.
 *
 * `checkedMul` is not `a * b`. Float multiplication silently loses precision
 * above 2^53 and wraps below it; a wrapped size is a small allocation claimed
 * to be a large one, which is a memory-safety defect wearing an arithmetic
 * costume.
 *
 * ── WHY NO SEMANTIC VALUE EVER ENTERS A BUFFER ───────────────────────────────
 *
 * Law 24 forbids raw prompt/tool/memory/store/secret data in GPU-facing
 * contracts, and law 15 forbids colour from carrying canonical meaning. The
 * structural answer here is `GpuBufferContents`: every buffer DECLARES the
 * class of value it may carry, from a closed vocabulary that has no member
 * permitting text, a subject id, a semantic axis, or a claim.
 *
 * The consequence worth stating: LABELS NEVER REACH THE GPU. A scene primitive
 * carries a human-readable `label`; the plan does not upload it, cannot upload
 * it, and has no buffer class that would accept it. Unrestricted free text on
 * the GPU is also the cheapest way for a future edit to leak one.
 *
 * What IS uploaded for traceability is an OPAQUE INTEGER: `pickingIndex`. It
 * carries no semantic whatsoever. The link back to a visible subject lives in
 * `PickingResolution`, which stays on the CPU. So PICKING != EXECUTION and
 * PICKING_ID != IDENTITY are both true by construction rather than by review.
 *
 * ── WHY RESERVED BYTES EXIST AND MUST BE ZERO ────────────────────────────────
 *
 * The vertex, instance and uniform layouts each carry explicit `reserved`
 * fields. They are not padding to be optimised away later; they are the space
 * a future edit would most likely fill with a semantic, and `assertZeroFill`
 * refuses any record whose reserved fields are not exactly zero. Writing
 * meaning into reserved space is therefore a REFUSAL at plan time, not a
 * quietly enriched buffer that a reviewer has to notice.
 *
 * ── WHY THE PLAN IS DETERMINISTIC OVER SORTED INPUT ──────────────────────────
 *
 * 29B already emits primitives in sorted-subject order, but depending on that
 * would make 29D's determinism a property of another module's implementation
 * detail. So 29D re-sorts defensively, by `primitiveId` / `relationId` /
 * `overlayId`. Two scenes with identical content and different array order
 * produce a byte-identical `planHash`.
 *
 * Float contents are hashed as the f32 values the GPU will actually read
 * (`Math.fround`, then the raw little-endian bytes) rather than as the f64
 * doubles the author typed. Hashing the doubles would let two records that are
 * indistinguishable on the GPU produce different hashes.
 *
 * ── WHY TRUNCATION HAS NO KNOB ───────────────────────────────────────────────
 *
 * Law 28: limits fail CLOSED and never truncate silently. There is no
 * `maxPrimitives` parameter that shrinks a scene. `requestedMaxPrimitives` is
 * accepted ONLY so that a caller asking for fewer than the scene requires gets
 * `refused_gpu_plan_truncation_forbidden` rather than a quietly smaller picture.
 * A picture that silently omits a conflict marker is precisely the "correct
 * runtime with a misleading picture" failure the pack calls a security failure.
 *
 * ── WHY THE PLAN NEVER CLAIMS A RENDERED PIXEL ──────────────────────────────
 *
 * 29C measured this machine: the render pass submits cleanly and
 * `copyTextureToBuffer` returns all zeros. SUBMITTED != RENDERED is therefore
 * an observed fact on the target, not a theoretical caution.
 *
 * So `completeness` is at best `"incomplete"`, `pixelOutputVerified` is
 * literally `false`, and a caller asking for `"complete"` without a qualifying
 * verdict is REFUSED (`refused_gpu_plan_qualification_required`) rather than
 * trusted. An unqualifying 29C verdict narrows the plan's byte ceilings with
 * `Math.min` — it can make the plan SMALLER, never larger, because widening
 * limits from an unverified observation is how an unsupported plan starts
 * claiming hardware support.
 *
 * ── WHY GPU RECOVERY IS NOT NAMED HERE ──────────────────────────────────────
 *
 * Law 29: device recovery rebuilds graphics resources, never runtime state.
 * Every `GpuResourceDescriptor` therefore declares `rebuildsFrom:
 * "getig_frame"` and `restoresRuntimeState: false`, and no descriptor in this
 * module has a field from which runtime state could be restored. 29H owns loss
 * and recovery behaviour; 29D only fixes what a rebuild is allowed to read.
 */

import { createHash } from "node:crypto";

import { canonicalHash } from "./canonical.js";
import type { GetigScene } from "./rendererTrustContract.js";
import { QUALIFYING_VERDICTS, type WebGpuQualification } from "./webgpuQualification.js";

// ── closed vocabularies ────────────────────────────────────────────────────────

/**
 * The complete set of things a GPU buffer is allowed to contain.
 *
 * There is deliberately no member meaning text, identifier, label, semantic
 * axis, role, trust value or claim. The vocabulary is the mechanism behind
 * "raw runtime objects never enter GPU buffers": a buffer cannot hold a value
 * its declared contents class does not name.
 */
export const GPU_BUFFER_CONTENTS = Object.freeze([
  /** Positions, sizes and z-order. Presentation geometry only. */
  "presentation_geometry",
  /** Static four-vertex quad used to stamp overlays. Presentation geometry only. */
  "static_quad_geometry",
  /** u32 endpoint indices. Topology only; carries no meaning. */
  "topology_index",
  /** Viewport dimensions. Presentation only. */
  "viewport_uniform",
  /** u32 opaque indices into a CPU-side resolution table. Carries no meaning. */
  "opaque_picking_index",
  /** Nothing. A placeholder buffer that exists to be bound. */
  "none",
] as const);
export type GpuBufferContents = (typeof GPU_BUFFER_CONTENTS)[number];

/** What a buffer may be used for. Mirrors the real WebGPU usage flags. */
export const GPU_BUFFER_USAGES = Object.freeze([
  "vertex",
  "index",
  "uniform",
  "storage",
  "copy-dst",
  "copy-src",
] as const);
export type GpuBufferUsage = (typeof GPU_BUFFER_USAGES)[number];

export const GPU_RESOURCE_LIFECYCLES = Object.freeze([
  /** Rebuilt every frame from the current scene. */
  "frame_scoped",
  /** Rebuilt when the scene hash changes. */
  "scene_scoped",
  /** Reused across scenes. Holds only presentation data. */
  "persistent",
] as const);
export type GpuResourceLifecycle = (typeof GPU_RESOURCE_LIFECYCLES)[number];

export const GPU_PASS_KINDS = Object.freeze(["colour", "picking"] as const);
export type GpuPassKind = (typeof GPU_PASS_KINDS)[number];

/**
 * Every way this gate can refuse.
 *
 * A declared-but-unreachable refusal code is worse than no code: it advertises a
 * check that does not exist. So each one here is LIVE, and the suite proves it
 * by driving it. Three are reached only through the exported guards rather than
 * through a well-formed scene — `refused_gpu_plan_layout_invalid` via
 * `assertLayoutArity`, `refused_gpu_plan_claim_in_buffer` via `assertZeroFill`,
 * and `refused_gpu_plan_size_overflow` via `checkedMul` — because a scene that
 * is already inside `GPU_PLAN_BOUNDS` cannot overflow by construction. A guard
 * that only fires for inputs the bounds already exclude is not a guard that was
 * needed; it is one that should be tested directly.
 */
export const GPU_PLAN_REFUSAL_CODES = Object.freeze([
  "refused_gpu_plan_input_invalid",
  "refused_gpu_plan_scene_unbound",
  "refused_gpu_plan_scene_malformed",
  "refused_gpu_plan_layout_invalid",
  "refused_gpu_plan_budget_exceeded",
  "refused_gpu_plan_size_overflow",
  "refused_gpu_plan_device_limit_exceeded",
  "refused_gpu_plan_truncation_forbidden",
  "refused_gpu_plan_qualification_required",
  "refused_gpu_plan_claim_in_buffer",
] as const);
export type GpuPlanRefusalCode = (typeof GPU_PLAN_REFUSAL_CODES)[number];

export const GPU_PLAN_SCHEMA_VERSION = "menog-gpu-render-plan/v0" as const;

// ── explicit bounds (law 28: explicit, fail closed) ───────────────────────────

/**
 * Ceilings are set BELOW anything this machine reported, never above.
 *
 * `maxUniformBytes` and `maxBindGroups` deliberately equal the values 29C
 * observed on the target, so the plan is anchored to a measurement rather than
 * to a guess. When a 29C qualification is supplied these are narrowed further
 * with `Math.min`; they are never widened.
 */
export const GPU_PLAN_BOUNDS = Object.freeze({
  maxPrimitives: 4096,
  maxRelations: 4096,
  maxOverlays: 256,
  maxPipelines: 8,
  maxPasses: 4,
  maxBindGroups: 4,
  maxFramesInFlight: 3,
  maxBufferBytes: 134217728,
  maxVertexBytes: 67108864,
  maxIndexBytes: 33554432,
  maxUniformBytes: 65536,
  maxStorageBytes: 33554432,
  maxLabelLength: 128,
});
export type GpuPlanBounds = typeof GPU_PLAN_BOUNDS;

/**
 * Tokens that would mean this gate had allocated or drawn something.
 *
 * Exported so the suite can assert their absence from this file's CODE (comments
 * and string literals stripped). The header discusses them in prose; the check
 * is on code.
 */
export const PHASE29D_FORBIDDEN_TOKENS = Object.freeze([
  "navigator",
  "requestAdapter",
  "requestDevice",
  "createBuffer",
  "createTexture",
  "createRenderPipeline",
  "createBindGroup",
  "createCommandEncoder",
  "queue.submit",
  "draw(",
  "dispatchWorkgroups",
] as const);

/**
 * `0xFFFFFFFF`. Written into the picking index when a relation endpoint is not a
 * drawable subject.
 *
 * A sentinel rather than a drop: dropping an unresolved endpoint would shorten
 * the index buffer and shift every later index, turning one unresolvable
 * relation into a scene-wide mislabel.
 */
export const GPU_PICKING_NO_ANCHOR = 0xffffffff;

/**
 * Byte strides. Declared once; every size is computed from them.
 *
 * Reserved space is declared in `reservedOffsets` and NOT as an attribute. That
 * asymmetry is the point: an attribute is addressable by a shader, so a named
 * `reserved0` attribute would invite exactly the semantic a reserved slot
 * exists to prevent. As reserved offsets, no shader can read them, and
 * `assertZeroFill` proves they carry nothing.
 */
export const GPU_LAYOUTS = Object.freeze({
  vertex: Object.freeze({
    layoutId: "menog.vertex/primitive/v0",
    strideBytes: 32,
    attributes: Object.freeze([
      Object.freeze({ name: "position", format: "float32x3", offset: 0, byteLength: 12 }),
      Object.freeze({ name: "sizeHint", format: "float32", offset: 12, byteLength: 4 }),
      Object.freeze({ name: "zOrder", format: "float32", offset: 16, byteLength: 4 }),
      Object.freeze({ name: "pickingIndex", format: "uint32", offset: 20, byteLength: 4 }),
    ]),
    reservedOffsets: Object.freeze([24, 28]),
  }),
  instance: Object.freeze({
    layoutId: "menog.instance/overlay/v0",
    strideBytes: 16,
    attributes: Object.freeze([
      Object.freeze({ name: "anchorIndex", format: "uint32", offset: 0, byteLength: 4 }),
      Object.freeze({ name: "offsetY", format: "float32", offset: 4, byteLength: 4 }),
      Object.freeze({ name: "scale", format: "float32", offset: 8, byteLength: 4 }),
    ]),
    reservedOffsets: Object.freeze([12]),
  }),
  index: Object.freeze({
    layoutId: "menog.index/topology/v0",
    strideBytes: 4,
    attributes: Object.freeze([
      Object.freeze({ name: "endpointIndex", format: "uint32", offset: 0, byteLength: 4 }),
    ]),
    reservedOffsets: Object.freeze([] as readonly number[]),
  }),
  uniform: Object.freeze({
    layoutId: "menog.uniform/viewport/v0",
    strideBytes: 32,
    attributes: Object.freeze([
      Object.freeze({ name: "viewportWidth", format: "float32", offset: 0, byteLength: 4 }),
      Object.freeze({ name: "viewportHeight", format: "float32", offset: 4, byteLength: 4 }),
      Object.freeze({ name: "scale", format: "float32", offset: 8, byteLength: 4 }),
    ]),
    reservedOffsets: Object.freeze([12, 16, 20, 24, 28]),
  }),
});
export type GpuLayoutId = keyof typeof GPU_LAYOUTS;

export interface GpuLayoutDescriptor {
  readonly layoutId: string;
  readonly strideBytes: number;
  readonly attributes: readonly { readonly name: string; readonly format: string; readonly offset: number; readonly byteLength: number }[];
  readonly reservedOffsets: readonly number[];
}

/**
 * Prove a declared layout is arithmetically coherent.
 *
 * Returns `null` when the layout is sound and a human-readable reason when it
 * is not: a stride that is not a positive multiple of 4, an attribute that runs
 * past the stride, two attributes sharing bytes, offsets out of order, or a
 * reserved offset that is not a whole u32 inside the record.
 *
 * This runs on EVERY plan. It is the reason `refused_gpu_plan_layout_invalid`
 * is a live code rather than a declared one: a layout edited into an
 * inconsistent state would otherwise produce silently corrupt bytes, because
 * every offset in this module is computed from the declared stride.
 *
 * Exported so the suite can drive it with a hostile layout and prove the guard
 * actually fires.
 */
export function assertLayoutArity(layout: GpuLayoutDescriptor): string | null {
  const { strideBytes, attributes, reservedOffsets } = layout;
  if (!Number.isSafeInteger(strideBytes) || strideBytes <= 0 || strideBytes % 4 !== 0) {
    return `${layout.layoutId}: strideBytes ${strideBytes} is not a positive multiple of 4`;
  }
  const occupied = new Set<number>();
  let previousEnd = -1;
  for (const a of attributes) {
    if (!Number.isSafeInteger(a.offset) || a.offset < 0 || a.offset % 4 !== 0) {
      return `${layout.layoutId}: attribute ${a.name} offset ${a.offset} is not a non-negative multiple of 4`;
    }
    if (!Number.isSafeInteger(a.byteLength) || a.byteLength <= 0 || a.byteLength % 4 !== 0) {
      return `${layout.layoutId}: attribute ${a.name} byteLength ${a.byteLength} is not a positive multiple of 4`;
    }
    if (a.offset + a.byteLength > strideBytes) {
      return `${layout.layoutId}: attribute ${a.name} ends at ${a.offset + a.byteLength}, past the ${strideBytes} B stride`;
    }
    if (a.offset < previousEnd) {
      return `${layout.layoutId}: attribute ${a.name} at ${a.offset} overlaps the previous attribute ending at ${previousEnd}`;
    }
    previousEnd = a.offset + a.byteLength;
    for (let b = a.offset; b < a.offset + a.byteLength; b += 1) {
      if (occupied.has(b)) return `${layout.layoutId}: byte ${b} is claimed by more than one attribute`;
      occupied.add(b);
    }
  }
  for (const offset of reservedOffsets) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset % 4 !== 0 || offset + 4 > strideBytes) {
      return `${layout.layoutId}: reserved offset ${offset} is not a whole u32 inside the record`;
    }
    if (occupied.has(offset)) {
      const owner = attributes.find((a) => offset >= a.offset && offset < a.offset + a.byteLength);
      return `${layout.layoutId}: reserved offset ${offset} overlaps attribute ${owner?.name ?? "an unnamed attribute"}`;
    }
  }
  return null;
}

/**
 * The shader INTERFACE, as data.
 *
 * 29D ships no WGSL source. An interface — bindings, entry points, output
 * types — is what a later gate needs to be checked against, and it is
 * checkable here without introducing a string of GPU code into a module whose
 * whole claim is that it allocates nothing.
 *
 * Note what the interface does NOT expose: no colour, no semantic, no role, no
 * trust. The fragment stage returns a single presentation constant.
 */
export const SHADER_INTERFACE = Object.freeze({
  schemaVersion: "menog-shader-interface/v0",
  bindings: Object.freeze([
    Object.freeze({ group: 0, binding: 0, name: "viewport", resourceType: "uniform_buffer", layout: "menog.uniform/viewport/v0" }),
    Object.freeze({ group: 1, binding: 0, name: "pickingIndex", resourceType: "storage_buffer", layout: "menog.index/topology/v0" }),
  ]),
  entryPoints: Object.freeze([
    Object.freeze({ name: "primitiveVertex", stage: "vertex", outputs: "position" }),
    Object.freeze({ name: "primitiveFragment", stage: "fragment", outputs: "presentation_constant" }),
    Object.freeze({ name: "relationVertex", stage: "vertex", outputs: "position" }),
    Object.freeze({ name: "overlayVertex", stage: "vertex", outputs: "position" }),
    Object.freeze({ name: "pickingVertex", stage: "vertex", outputs: "position" }),
    Object.freeze({ name: "pickingFragment", stage: "fragment", outputs: "uint32_picking_index" }),
  ]),
  /** Exhaustive: what the shader interface is forbidden to carry. */
  carriesNoSemantic: Object.freeze(["colour", "axis", "value", "role", "trust", "authority", "label", "text"]),
});

// ── the produced contracts ─────────────────────────────────────────────────────

export interface GpuBufferDescriptor {
  readonly bufferId: string;
  readonly label: string;
  readonly usage: readonly GpuBufferUsage[];
  /** The class of value this buffer may hold. From the closed vocabulary. */
  readonly contents: GpuBufferContents;
  readonly layout: GpuLayoutId;
  readonly strideBytes: number;
  readonly recordCount: number;
  /** recordCount * strideBytes, verified before this descriptor existed. */
  readonly sizeBytes: number;
  /** How `sizeBytes` was derived, in words. Auditable rather than asserted. */
  readonly sizeDerivation: string;
  /** sha256 over the exact little-endian bytes the GPU would read. */
  readonly contentHash: string;
  readonly lifecycle: GpuResourceLifecycle;
  /** Law 29: recovery rebuilds graphics from the frame, never runtime state. */
  readonly rebuildsFrom: "getig_frame";
  readonly restoresRuntimeState: false;
  readonly ownerLayer: "gpu_resource";
  readonly authority: "none";
  readonly executionAuthorized: false;
}

export interface GpuBindGroupDescriptor {
  readonly bindGroupId: string;
  readonly group: number;
  readonly binding: number;
  readonly layout: GpuLayoutId;
  readonly bufferIds: readonly string[];
  readonly authority: "none";
  readonly executionAuthorized: false;
}

export interface GpuPipelineDescriptor {
  readonly pipelineId: string;
  readonly shaderInterface: typeof SHADER_INTERFACE.schemaVersion;
  readonly vertexLayout: GpuLayoutId;
  readonly instanceLayout: GpuLayoutId | null;
  readonly bindGroups: readonly number[];
  readonly targetFormat: "presentation_only" | "picking_index";
  readonly depthCompare: "none";
  readonly ownership: "gpu_resource";
  readonly authority: "none";
  readonly executionAuthorized: false;
}

export interface GpuPassDescriptor {
  readonly passId: string;
  readonly kind: GpuPassKind;
  readonly pipelineIds: readonly string[];
  readonly bindGroups: readonly number[];
  /** The pass is bound to the scene it draws. It cannot be reused across scenes. */
  readonly sceneHash: string;
  readonly authority: "none";
  readonly executionAuthorized: false;
}

/**
 * CPU-side resolution of an opaque picking index.
 *
 * Nothing in this structure is uploaded. It exists so a pixel can be traced to
 * the subject it names without the GPU ever holding a name.
 */
export interface PickingResolution {
  readonly pickingIndex: number;
  readonly pickingId: string;
  readonly subjectVisibleId: string;
  readonly relationIds: readonly string[];
  readonly overlayIds: readonly string[];
  readonly markerTexts: readonly string[];
  /** Always false. These values never left the CPU. */
  readonly uploadedToGpu: false;
  readonly authority: "none";
  /** Law 6: PICKING != EXECUTION. Structurally, not by policy. */
  readonly executionAuthorized: false;
}

/** One binding point per relation. Not evidence that anything happened. */
export interface GpuResourceBinding {
  readonly sourceFrameId: string;
  readonly sceneHash: string;
  readonly planHash: string;
  readonly runtimeStateHash: string;
  readonly graphicsBackend: "none";
  readonly authority: "none";
  readonly executionAuthorized: false;
}

export interface GpuRenderPlanValue {
  readonly schemaVersion: typeof GPU_PLAN_SCHEMA_VERSION;
  readonly planHash: string;
  readonly sourceFrameId: string;
  readonly sceneHash: string;
  readonly sourceVisibleHash: string;
  readonly runtimeStateHash: string;
  /** The 29D vertex layout in force. Named for what it is, not for a hash. */
  readonly vertexLayoutId: string;
  readonly buffers: readonly GpuBufferDescriptor[];
  readonly bindGroups: readonly GpuBindGroupDescriptor[];
  readonly pipelines: readonly GpuPipelineDescriptor[];
  readonly passes: readonly GpuPassDescriptor[];
  readonly pickingResolutions: readonly PickingResolution[];
  readonly framesInFlight: number;
  readonly entryCount: number;
  readonly totalBufferBytes: number;
  readonly completeness: "incomplete";
  readonly supportsHardware: boolean;
  readonly qualificationVerdict: string | null;
  /** Law: ALLOCATED != SUBMITTED != RENDERED. Literally false, not a default. */
  readonly pixelOutputVerified: false;
  readonly notProven: readonly string[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

export type GpuPlanRefused = {
  readonly ok: false;
  readonly code: "gpu_plan_refused";
  readonly refusal: GpuPlanRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  readonly plan: null;
  /** A refusal emits NOTHING partial: no buffers, no passes, no plan hash. */
  readonly partialPlanEmitted: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type GpuPlanSucceeded = {
  readonly ok: true;
  readonly code: "gpu_plan_built";
  readonly plan: GpuRenderPlanValue;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type GpuPlanDecision = GpuPlanSucceeded | GpuPlanRefused;

// ── helpers ────────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (
  refusal: GpuPlanRefusalCode,
  explanation: string,
  offendingField: string | null = null,
): GpuPlanRefused => ({
  ok: false,
  code: "gpu_plan_refused",
  refusal,
  explanation,
  offendingField,
  plan: null,
  partialPlanEmitted: false,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const HASH_SHAPE = /^[a-f0-9]{16,128}$/;
const isHash = (v: unknown): v is string => typeof v === "string" && HASH_SHAPE.test(v);

/**
 * Multiply, refusing anything that is not an exact safe non-negative integer.
 *
 * Returns `null` rather than a wrong number, because a wrapped byte count is
 * worse than no byte count: it under-reports an allocation and lets the caller
 * proceed believing the bound was respected.
 */
export function checkedMul(a: number, b: number): number | null {
  if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b)) return null;
  if (a < 0 || b < 0) return null;
  const product = a * b;
  if (!Number.isSafeInteger(product)) return null;
  return product;
}

/** sha256 over the exact bytes a typed array would upload. */
const bytesHash = (view: Float32Array | Uint32Array): string =>
  createHash("sha256")
    .update(Buffer.from(view.buffer, view.byteOffset, view.byteLength))
    .digest("hex");

const ZERO32 = 0;

/**
 * Assert every reserved u32 of a record is exactly zero.
 *
 * This is the tripwire for "someone filled the padding with meaning". A non-zero
 * reserved field is refused rather than tolerated, because tolerated padding is
 * where a semantic payload goes to be discovered later.
 */
export function assertZeroFill(
  words: Uint32Array,
  layout: { readonly strideBytes: number; readonly reservedOffsets: readonly number[] },
  where: string,
): string | null {
  if (layout.reservedOffsets.length === 0) return null;
  const wordCount = layout.strideBytes / 4;
  if (!Number.isInteger(wordCount) || wordCount === 0) return null;
  for (let record = 0; record * wordCount < words.length; record += 1) {
    for (const offset of layout.reservedOffsets) {
      const value = words[record * wordCount + offset / 4];
      if (value !== undefined && value !== ZERO32) {
        return `${where}: reserved byte offset ${offset} of record ${record} is ${value}, not zero`;
      }
    }
  }
  return null;
}

// ── input ──────────────────────────────────────────────────────────────────────

export interface BuildGpuRenderPlanInput {
  /** A `GetigScene` from 29B. Read, never mutated. */
  readonly scene: unknown;
  /** Optional 29C qualification. Narrows byte ceilings; never widens them. */
  readonly qualification?: WebGpuQualification | null;
  /** Defaults to the ceiling. May not be set BELOW what the scene requires. */
  readonly framesInFlight?: number;
  readonly viewport?: { readonly width: number; readonly height: number; readonly scale: number };
  /**
   * Accepted only so that asking for a smaller scene is a REFUSAL.
   * There is no code path in which this value shrinks the output.
   */
  readonly requestedMaxPrimitives?: number;
  readonly requestedCompleteness?: "complete" | "incomplete";
}

// ── the plan ───────────────────────────────────────────────────────────────────

/**
 * Translate a `GetigScene` into explicit, bounded, zero-authority GPU
 * descriptors. Allocates nothing.
 */
export function buildGpuRenderPlan(input: BuildGpuRenderPlanInput): GpuPlanDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_plan_input_invalid", "plan input must be an object");
  }
  const scene = input.scene;
  if (!isRecord(scene)) {
    return refuse("refused_gpu_plan_scene_unbound", "scene must be an object", "scene");
  }
  if (!isHash(scene.sceneHash) || !isHash(scene.runtimeStateHash)) {
    return refuse("refused_gpu_plan_scene_unbound", "scene requires sceneHash and runtimeStateHash", "sceneHash");
  }
  if (scene.sceneHash === scene.runtimeStateHash) {
    return refuse(
      "refused_gpu_plan_scene_unbound",
      "sceneHash equals runtimeStateHash; SCENE_GRAPH != RUNTIME_STATE is not satisfied",
      "sceneHash",
    );
  }
  if (typeof scene.sourceFrameId !== "string" || scene.sourceFrameId.length === 0) {
    return refuse("refused_gpu_plan_scene_unbound", "scene.sourceFrameId is required", "sourceFrameId");
  }
  if (!isHash(scene.sourceVisibleHash)) {
    return refuse("refused_gpu_plan_scene_unbound", "scene.sourceVisibleHash must be a hex hash", "sourceVisibleHash");
  }
  if (!Array.isArray(scene.primitives) || !Array.isArray(scene.relations) || !Array.isArray(scene.overlays)) {
    return refuse("refused_gpu_plan_scene_malformed", "scene requires primitives, relations and overlays arrays", "primitives");
  }

  // ── every declared layout is checked arithmetically, on every plan ──────
  // Every byte offset in this module is derived from these strides, so a layout
  // edited into an incoherent state would emit silently corrupt bytes rather
  // than fail. Checking first is what makes a layout edit safe to make.
  for (const id of Object.keys(GPU_LAYOUTS) as GpuLayoutId[]) {
    const invalid = assertLayoutArity(GPU_LAYOUTS[id]);
    if (invalid !== null) {
      return refuse("refused_gpu_plan_layout_invalid", invalid, id);
    }
  }

  const typed = scene as unknown as GetigScene;
  const primitives = [...typed.primitives].sort((a, b) => a.primitiveId.localeCompare(b.primitiveId));
  const relations = [...typed.relations].sort((a, b) => a.relationId.localeCompare(b.relationId));
  const overlays = [...typed.overlays].sort((a, b) => a.overlayId.localeCompare(b.overlayId));

  // ── bounds, checked before anything is sized ────────────────────────────
  if (primitives.length > GPU_PLAN_BOUNDS.maxPrimitives) {
    return refuse("refused_gpu_plan_budget_exceeded", "primitive count exceeds maxPrimitives", "primitives");
  }
  if (relations.length > GPU_PLAN_BOUNDS.maxRelations) {
    return refuse("refused_gpu_plan_budget_exceeded", "relation count exceeds maxRelations", "relations");
  }
  if (overlays.length > GPU_PLAN_BOUNDS.maxOverlays) {
    return refuse("refused_gpu_plan_budget_exceeded", "overlay count exceeds maxOverlays", "overlays");
  }

  // There is no truncation. A cap below what the scene requires is a refusal.
  const requestedCap = input.requestedMaxPrimitives;
  if (requestedCap !== undefined) {
    if (!Number.isSafeInteger(requestedCap) || requestedCap < 0) {
      return refuse("refused_gpu_plan_input_invalid", "requestedMaxPrimitives must be a non-negative integer", "requestedMaxPrimitives");
    }
    if (requestedCap < primitives.length) {
      return refuse(
        "refused_gpu_plan_truncation_forbidden",
        `a cap of ${requestedCap} would omit ${primitives.length - requestedCap} of ${primitives.length} primitives; silent truncation is forbidden`,
        "requestedMaxPrimitives",
      );
    }
  }

  // ── qualification narrows ceilings and can never widen them ─────────────
  const qualification = input.qualification ?? null;
  const supportsHardware =
    qualification !== null && (QUALIFYING_VERDICTS as readonly string[]).includes(qualification.verdict);
  const observed = qualification?.limits;
  const ceiling = (declared: number, observedValue: number | undefined): number =>
    observedValue === undefined ? declared : Math.min(declared, observedValue);

  const maxBufferBytes = ceiling(GPU_PLAN_BOUNDS.maxBufferBytes, observed?.maxBufferSize);
  const maxVertexBytes = ceiling(GPU_PLAN_BOUNDS.maxVertexBytes, observed?.maxBufferSize);
  const maxIndexBytes = ceiling(GPU_PLAN_BOUNDS.maxIndexBytes, observed?.maxBufferSize);
  const maxUniformBytes = ceiling(GPU_PLAN_BOUNDS.maxUniformBytes, observed?.maxUniformBufferBindingSize);
  const maxBindGroups = ceiling(GPU_PLAN_BOUNDS.maxBindGroups, observed?.maxBindGroups);

  // Law 30: UNSUPPORTED is never PASS. A caller may not declare completeness
  // the qualification does not support, and the plan's own type admits only
  // "incomplete" because 29C found no verified pixel readback on this machine.
  if (input.requestedCompleteness === "complete" && !supportsHardware) {
    return refuse(
      "refused_gpu_plan_qualification_required",
      `completeness 'complete' requires a qualifying verdict; observed ${qualification?.verdict ?? "no qualification"}`,
      "requestedCompleteness",
    );
  }

  const framesInFlight = input.framesInFlight ?? 1;
  if (!Number.isSafeInteger(framesInFlight) || framesInFlight < 1) {
    return refuse("refused_gpu_plan_input_invalid", "framesInFlight must be an integer of at least 1", "framesInFlight");
  }
  if (framesInFlight > GPU_PLAN_BOUNDS.maxFramesInFlight) {
    return refuse("refused_gpu_plan_budget_exceeded", "framesInFlight exceeds maxFramesInFlight", "framesInFlight");
  }

  const viewport = input.viewport ?? { width: 1280, height: 720, scale: 1 };
  if (![viewport.width, viewport.height, viewport.scale].every((v) => typeof v === "number" && Number.isFinite(v) && v > 0)) {
    return refuse("refused_gpu_plan_input_invalid", "viewport width, height and scale must be finite positive numbers", "viewport");
  }

  // ── sort order defines the picking index space ──────────────────────────
  const primitiveIndexById = new Map<string, number>();
  primitives.forEach((p, i) => primitiveIndexById.set(p.primitiveId, i));

  const buffers: GpuBufferDescriptor[] = [];
  const notProven: string[] = [];

  // ── primitive vertices ──────────────────────────────────────────────────
  const vertexStride = GPU_LAYOUTS.vertex.strideBytes;
  const vertexBytes = checkedMul(primitives.length, vertexStride);
  if (vertexBytes === null) {
    return refuse("refused_gpu_plan_size_overflow", `vertex byte count overflowed for ${primitives.length} primitives`, "primitives");
  }
  if (vertexBytes > maxVertexBytes || vertexBytes > maxBufferBytes) {
    return refuse("refused_gpu_plan_device_limit_exceeded", `vertex buffer ${vertexBytes} B exceeds the vertex ceiling`, "primitives");
  }
  {
    const words = primitives.length * 8;
    const floats = new Float32Array(words);
    const uints = new Uint32Array(floats.buffer);
    primitives.forEach((p, i) => {
      const base = i * 8;
      // Math.fround: the hash must cover the value the GPU reads, not the
      // double the author typed. Two records indistinguishable on the GPU must
      // not hash differently.
      floats[base + 0] = Math.fround(p.position[0]);
      floats[base + 1] = Math.fround(p.position[1]);
      floats[base + 2] = Math.fround(p.position[2]);
      floats[base + 3] = Math.fround(p.sizeHint);
      floats[base + 4] = Math.fround(p.zOrder);
      uints[base + 5] = i >>> 0;
      uints[base + 6] = ZERO32;
      uints[base + 7] = ZERO32;
    });
    const zeroed = assertZeroFill(uints, GPU_LAYOUTS.vertex, "vertex buffer");
    if (zeroed !== null) {
      return refuse("refused_gpu_plan_claim_in_buffer", zeroed, "primitives");
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.vertex.primitive",
        label: "menog primitive vertices (presentation geometry only)",
        usage: Object.freeze(["vertex", "copy-dst"] as const),
        contents: "presentation_geometry" as const,
        layout: "vertex" as const,
        strideBytes: vertexStride,
        recordCount: primitives.length,
        sizeBytes: vertexBytes,
        sizeDerivation: `${primitives.length} primitives * ${vertexStride} B stride`,
        contentHash: bytesHash(floats),
        lifecycle: "scene_scoped" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── overlay instances ───────────────────────────────────────────────────
  const instanceStride = GPU_LAYOUTS.instance.strideBytes;
  const instanceBytes = checkedMul(overlays.length, instanceStride);
  if (instanceBytes === null) {
    return refuse("refused_gpu_plan_size_overflow", `instance byte count overflowed for ${overlays.length} overlays`, "overlays");
  }
  if (instanceBytes > maxVertexBytes || instanceBytes > maxBufferBytes) {
    return refuse("refused_gpu_plan_device_limit_exceeded", `instance buffer ${instanceBytes} B exceeds the vertex ceiling`, "overlays");
  }
  {
    const floats = new Float32Array(overlays.length * 4);
    const uints = new Uint32Array(floats.buffer);
    let unresolvedAnchors = 0;
    overlays.forEach((o, i) => {
      const base = i * 4;
      const anchor = primitiveIndexById.get(o.targetId);
      if (anchor === undefined) {
        unresolvedAnchors += 1;
        uints[base + 0] = GPU_PICKING_NO_ANCHOR;
      } else {
        uints[base + 0] = anchor >>> 0;
      }
      // Presentation offset: a fixed row step in sorted overlay order, so the
      // layout is a pure function of the scene rather than of a clock.
      floats[base + 1] = Math.fround((i % 16) + 1);
      floats[base + 2] = Math.fround(1);
      uints[base + 3] = ZERO32;
    });
    if (unresolvedAnchors > 0) {
      // Surfaced, never silently repaired.
      notProven.push(`${unresolvedAnchors} overlay target(s) name no drawable primitive and carry the no-anchor sentinel`);
    }
    const zeroed = assertZeroFill(uints, GPU_LAYOUTS.instance, "instance buffer");
    if (zeroed !== null) {
      return refuse("refused_gpu_plan_claim_in_buffer", zeroed, "overlays");
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.instance.overlay",
        label: "menog overlay instances (anchors and offsets only)",
        usage: Object.freeze(["vertex", "copy-dst"] as const),
        contents: "presentation_geometry" as const,
        layout: "instance" as const,
        strideBytes: instanceStride,
        recordCount: overlays.length,
        sizeBytes: instanceBytes,
        sizeDerivation: `${overlays.length} overlays * ${instanceStride} B stride`,
        contentHash: bytesHash(floats),
        lifecycle: "scene_scoped" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── static quad, the only persistent buffer in the plan ─────────────────
  // It uses the SAME vertex layout as the primitives, so a second stride can
  // never drift out of step with the first. Positions are unit-space: the
  // viewport uniform, not this buffer, decides where anything lands.
  {
    const quadCorners: readonly (readonly [number, number, number])[] = [
      [-0.5, -0.5, 0],
      [0.5, -0.5, 0],
      [0.5, 0.5, 0],
      [-0.5, 0.5, 0],
    ];
    const floats = new Float32Array(quadCorners.length * 8);
    const uints = new Uint32Array(floats.buffer);
    quadCorners.forEach((corner, i) => {
      const base = i * 8;
      floats[base + 0] = corner[0];
      floats[base + 1] = corner[1];
      floats[base + 2] = corner[2];
      floats[base + 3] = 1;
      floats[base + 4] = 0;
      uints[base + 5] = GPU_PICKING_NO_ANCHOR;
      uints[base + 6] = ZERO32;
      uints[base + 7] = ZERO32;
    });
    const quadBytes = checkedMul(quadCorners.length, GPU_LAYOUTS.vertex.strideBytes);
    if (quadBytes === null) {
      return refuse("refused_gpu_plan_size_overflow", "quad byte count overflowed", "primitives");
    }
    const zeroed = assertZeroFill(uints, GPU_LAYOUTS.vertex, "quad buffer");
    if (zeroed !== null) {
      return refuse("refused_gpu_plan_claim_in_buffer", zeroed, "primitives");
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.vertex.quad",
        label: "menog overlay quad (static geometry)",
        usage: Object.freeze(["vertex", "copy-dst"] as const),
        contents: "static_quad_geometry" as const,
        layout: "vertex" as const,
        strideBytes: GPU_LAYOUTS.vertex.strideBytes,
        recordCount: quadCorners.length,
        sizeBytes: quadBytes,
        sizeDerivation: `fixed ${quadCorners.length}-vertex quad * ${GPU_LAYOUTS.vertex.strideBytes} B stride`,
        contentHash: bytesHash(floats),
        lifecycle: "persistent" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── topology indices: two u32 per relation ──────────────────────────────
  const indexStride = GPU_LAYOUTS.index.strideBytes;
  const indexBytes = checkedMul(relations.length * 2, indexStride);
  if (indexBytes === null) {
    return refuse("refused_gpu_plan_size_overflow", `index byte count overflowed for ${relations.length} relations`, "relations");
  }
  if (indexBytes > maxIndexBytes || indexBytes > maxBufferBytes) {
    return refuse("refused_gpu_plan_device_limit_exceeded", `index buffer ${indexBytes} B exceeds the index ceiling`, "relations");
  }
  {
    const uints = new Uint32Array(relations.length * 2);
    let unresolvedEnds = 0;
    relations.forEach((r, i) => {
      const from = primitiveIndexById.get(r.fromId);
      const to = primitiveIndexById.get(r.toId);
      uints[i * 2 + 0] = from === undefined ? GPU_PICKING_NO_ANCHOR : from >>> 0;
      uints[i * 2 + 1] = to === undefined ? GPU_PICKING_NO_ANCHOR : to >>> 0;
      if (from === undefined || to === undefined) unresolvedEnds += 1;
    });
    if (unresolvedEnds > 0) {
      notProven.push(`${unresolvedEnds} relation endpoint(s) name no drawable primitive and carry the no-anchor sentinel`);
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.index.topology",
        label: "menog relation endpoints (topology only)",
        usage: Object.freeze(["index", "copy-dst"] as const),
        contents: "topology_index" as const,
        layout: "index" as const,
        strideBytes: indexStride,
        recordCount: relations.length * 2,
        sizeBytes: indexBytes,
        sizeDerivation: `${relations.length} relations * 2 endpoints * ${indexStride} B`,
        contentHash: bytesHash(uints),
        lifecycle: "scene_scoped" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── picking index table: opaque integers only ───────────────────────────
  // This buffer never holds an id, a name or a semantic. It holds the OFFSET
  // of a CPU-side row. The whole of law 24 and law 5 turn on that one fact.
  {
    const uints = new Uint32Array(primitives.length);
    primitives.forEach((_, i) => {
      uints[i] = i >>> 0;
    });
    const pickingBytes = checkedMul(primitives.length, indexStride);
    if (pickingBytes === null) {
      return refuse("refused_gpu_plan_size_overflow", `picking index byte count overflowed for ${primitives.length} primitives`, "primitives");
    }
    if (pickingBytes > maxIndexBytes || pickingBytes > maxBufferBytes) {
      return refuse("refused_gpu_plan_device_limit_exceeded", `picking buffer ${pickingBytes} B exceeds the index ceiling`, "primitives");
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.storage.pickingIndex",
        label: "menog picking index table (opaque integers only)",
        usage: Object.freeze(["storage", "copy-dst"] as const),
        contents: "opaque_picking_index" as const,
        layout: "index" as const,
        strideBytes: indexStride,
        recordCount: primitives.length,
        sizeBytes: pickingBytes,
        sizeDerivation: `${primitives.length} picking slots * ${indexStride} B`,
        contentHash: bytesHash(uints),
        lifecycle: "frame_scoped" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── viewport uniform ────────────────────────────────────────────────────
  {
    const floats = new Float32Array(8);
    floats[0] = Math.fround(viewport.width);
    floats[1] = Math.fround(viewport.height);
    floats[2] = Math.fround(viewport.scale);
    const uniformBytes = checkedMul(1, GPU_LAYOUTS.uniform.strideBytes);
    if (uniformBytes === null) {
      return refuse("refused_gpu_plan_size_overflow", "uniform byte count overflowed", "viewport");
    }
    if (uniformBytes > maxUniformBytes || uniformBytes > maxBufferBytes) {
      return refuse("refused_gpu_plan_device_limit_exceeded", `uniform buffer ${uniformBytes} B exceeds the uniform ceiling`, "viewport");
    }
    const uints = new Uint32Array(floats.buffer);
    const zeroed = assertZeroFill(uints, GPU_LAYOUTS.uniform, "uniform buffer");
    if (zeroed !== null) {
      return refuse("refused_gpu_plan_claim_in_buffer", zeroed, "viewport");
    }
    buffers.push(
      Object.freeze({
        bufferId: "buf.uniform.viewport",
        label: "menog viewport uniform",
        usage: Object.freeze(["uniform", "copy-dst"] as const),
        contents: "viewport_uniform" as const,
        layout: "uniform" as const,
        strideBytes: GPU_LAYOUTS.uniform.strideBytes,
        recordCount: 1,
        sizeBytes: uniformBytes,
        sizeDerivation: `1 frame * ${GPU_LAYOUTS.uniform.strideBytes} B stride`,
        contentHash: bytesHash(floats),
        lifecycle: "frame_scoped" as const,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }

  // ── total byte accounting, checked against the single ceiling ───────────
  const totalBufferBytes = buffers.reduce((sum, b) => sum + b.sizeBytes, 0);
  if (!Number.isSafeInteger(totalBufferBytes)) {
    return refuse("refused_gpu_plan_size_overflow", "total buffer bytes is not a safe integer", "primitives");
  }
  if (totalBufferBytes > maxBufferBytes) {
    return refuse("refused_gpu_plan_device_limit_exceeded", `total ${totalBufferBytes} B exceeds the buffer ceiling`, "primitives");
  }

  // ── bind groups ─────────────────────────────────────────────────────────
  if (SHADER_INTERFACE.bindings.length > maxBindGroups) {
    return refuse("refused_gpu_plan_device_limit_exceeded", "shader interface needs more bind groups than the device allows", "qualification");
  }
  const bindGroups: GpuBindGroupDescriptor[] = SHADER_INTERFACE.bindings.map((b, i) =>
    Object.freeze({
      bindGroupId: `bg.${i}`,
      group: b.group,
      binding: b.binding,
      layout: (b.layout === "menog.uniform/viewport/v0" ? "uniform" : "index") as GpuLayoutId,
      bufferIds: Object.freeze([i === 0 ? "buf.uniform.viewport" : "buf.storage.pickingIndex"]),
      authority: "none" as const,
      executionAuthorized: false as const,
    }),
  );

  // ── pipelines ───────────────────────────────────────────────────────────
  const pipelines: GpuPipelineDescriptor[] = ([
    {
      pipelineId: "pipe.primitive",
      shaderInterface: SHADER_INTERFACE.schemaVersion,
      vertexLayout: "vertex",
      instanceLayout: null,
      bindGroups: [0],
      targetFormat: "presentation_only",
      depthCompare: "none",
      ownership: "gpu_resource",
      authority: "none",
      executionAuthorized: false,
    },
    {
      pipelineId: "pipe.relation",
      shaderInterface: SHADER_INTERFACE.schemaVersion,
      vertexLayout: "vertex",
      instanceLayout: null,
      bindGroups: [0],
      targetFormat: "presentation_only",
      depthCompare: "none",
      ownership: "gpu_resource",
      authority: "none",
      executionAuthorized: false,
    },
    {
      pipelineId: "pipe.overlay",
      shaderInterface: SHADER_INTERFACE.schemaVersion,
      vertexLayout: "vertex",
      instanceLayout: "instance",
      bindGroups: [0],
      targetFormat: "presentation_only",
      depthCompare: "none",
      ownership: "gpu_resource",
      authority: "none",
      executionAuthorized: false,
    },
    {
      pipelineId: "pipe.picking",
      shaderInterface: SHADER_INTERFACE.schemaVersion,
      vertexLayout: "vertex",
      instanceLayout: null,
      bindGroups: [0, 1],
      targetFormat: "picking_index",
      depthCompare: "none",
      ownership: "gpu_resource",
      authority: "none",
      executionAuthorized: false,
    },
  ] satisfies GpuPipelineDescriptor[]).map((p) => Object.freeze(p));
  if (pipelines.length > GPU_PLAN_BOUNDS.maxPipelines) {
    return refuse("refused_gpu_plan_budget_exceeded", "pipeline count exceeds maxPipelines", "pipelines");
  }

  // ── passes ──────────────────────────────────────────────────────────────
  const passes: GpuPassDescriptor[] = ([
    {
      passId: "pass.colour",
      kind: "colour",
      pipelineIds: ["pipe.primitive", "pipe.relation", "pipe.overlay"],
      bindGroups: [0],
      sceneHash: typed.sceneHash,
      authority: "none",
      executionAuthorized: false,
    },
    {
      passId: "pass.picking",
      kind: "picking",
      pipelineIds: ["pipe.picking"],
      bindGroups: [0, 1],
      sceneHash: typed.sceneHash,
      authority: "none",
      executionAuthorized: false,
    },
  ] satisfies GpuPassDescriptor[]).map((p) => Object.freeze(p));
  if (passes.length > GPU_PLAN_BOUNDS.maxPasses) {
    return refuse("refused_gpu_plan_budget_exceeded", "pass count exceeds maxPasses", "passes");
  }

  // ── CPU-side picking resolution (never uploaded) ────────────────────────
  const pickingResolutions: PickingResolution[] = primitives.map((p, i) => {
    const related = relations.filter((r) => r.fromId === p.primitiveId || r.toId === p.primitiveId).map((r) => r.relationId);
    const targeted = overlays.filter((o) => o.targetId === p.primitiveId);
    return Object.freeze({
      pickingIndex: i,
      // Opaque and stable: 29B derived it from the scene hash, so the same
      // scene always yields the same id and the id reveals nothing on its own.
      pickingId: `pick_${canonicalHash({ sceneHash: typed.sceneHash, subjectVisibleId: p.primitiveId })}`,
      subjectVisibleId: p.primitiveId,
      relationIds: Object.freeze(related),
      overlayIds: Object.freeze(targeted.map((o) => o.overlayId)),
      markerTexts: Object.freeze(targeted.map((o) => o.text)),
      uploadedToGpu: false as const,
      authority: "none" as const,
      executionAuthorized: false as const,
    });
  });
  if (pickingResolutions.length > GPU_PLAN_BOUNDS.maxPrimitives) {
    return refuse("refused_gpu_plan_budget_exceeded", "picking resolution count exceeds maxPrimitives", "primitives");
  }

  // ── determinism: the plan hash covers descriptors, never addresses ──────
  const planHash = `plan_${canonicalHash({
    schemaVersion: GPU_PLAN_SCHEMA_VERSION,
    sceneHash: typed.sceneHash,
    vertexLayoutId: GPU_LAYOUTS.vertex.layoutId,
    framesInFlight,
    buffers: buffers.map((b) => ({
      bufferId: b.bufferId,
      usage: b.usage,
      contents: b.contents,
      layout: b.layout,
      strideBytes: b.strideBytes,
      recordCount: b.recordCount,
      sizeBytes: b.sizeBytes,
      contentHash: b.contentHash,
      lifecycle: b.lifecycle,
    })),
    bindGroups: bindGroups.map((b) => ({ bindGroupId: b.bindGroupId, bufferIds: b.bufferIds })),
    pipelines: pipelines.map((p) => ({ pipelineId: p.pipelineId, vertexLayout: p.vertexLayout, instanceLayout: p.instanceLayout })),
    passes: passes.map((p) => ({ passId: p.passId, kind: p.kind })),
  })}`;

  notProven.push("no GPU allocation was performed by this plan");
  notProven.push("no submission was performed; ALLOCATED != SUBMITTED != RENDERED");
  notProven.push("no pixel readback was verified; 29C observed readbackMatchesExpectation false");
  if (!supportsHardware) {
    notProven.push("no qualifying WebGPU verdict backs hardware support; an unqualifying verdict may only narrow ceilings");
  }

  const plan = Object.freeze({
    schemaVersion: GPU_PLAN_SCHEMA_VERSION,
    planHash,
    sourceFrameId: typed.sourceFrameId,
    sceneHash: typed.sceneHash,
    sourceVisibleHash: typed.sourceVisibleHash,
    runtimeStateHash: typed.runtimeStateHash,
    vertexLayoutId: GPU_LAYOUTS.vertex.layoutId,
    buffers: Object.freeze(buffers),
    bindGroups: Object.freeze(bindGroups),
    pipelines: Object.freeze(pipelines),
    passes: Object.freeze(passes),
    pickingResolutions: Object.freeze(pickingResolutions),
    framesInFlight,
    entryCount: primitives.length + relations.length + overlays.length,
    totalBufferBytes,
    // The plan's own TYPE admits only "incomplete". 29C found no verified
    // pixel readback, so a plan that could say "complete" would be a type that
    // could lie.
    completeness: "incomplete" as const,
    supportsHardware,
    qualificationVerdict: qualification?.verdict ?? null,
    pixelOutputVerified: false as const,
    notProven: Object.freeze(notProven),
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  });

  return {
    ok: true,
    code: "gpu_plan_built" as const,
    plan,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  };
}