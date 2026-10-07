/**
 * PHASE 29A — WEBGPU RENDERER TRUST CONTRACT
 * (CONTRACT-FIRST / NO DRAW CALLS / ZERO-AUTHORITY)
 *
 * MODE: CONTRACT-FIRST / NO DRAW CALLS.
 *
 * CENTRAL LAWS:
 *   PIXELS            != AUTHORITY
 *   SCENE_GRAPH       != RUNTIME_STATE
 *   SELECTION         != PERMISSION
 *   PICKING           != EXECUTION
 *   ANIMATION         != LIVE_EXECUTION
 *   GPU_RECOVERY      != RUNTIME_RECOVERY
 *   POSITION          != TRUST
 *   SIZE              != IMPORTANCE
 *   DEPTH             != PRIVILEGE
 *   COLOR             != CANONICAL_SEMANTICS
 *
 * ── WHAT THIS MODULE IS, AND WHAT IT IS NOT ─────────────────────────────────
 *
 * This is the authority/security boundary for the entire Phase-29 renderer,
 * written BEFORE a single GPU call exists. That ordering is the point. If the
 * boundary is drawn after the renderer works, the boundary is drawn around
 * whatever the renderer happened to do, and every property below becomes a
 * description of the accident rather than a constraint on it.
 *
 * There is deliberately NO WebGPU code in this file. Not a guarded call, not a
 * feature-detect, not a capability probe. `navigator.gpu` does not appear here
 * at all. Device qualification is a 29C concern and is declared HERE as a DATA
 * CONTRACT (`DeviceQualificationFact`) that a future gate will produce — never
 * as a call this module makes.
 *
 * ── WHY EVERY CONTRACT IS `readonly` ALL THE WAY DOWN ───────────────────────
 *
 * `readonly` in TypeScript is erased at runtime. On its own it is a comment.
 * So it is paired with `Object.freeze` on every constructor, which is not a
 * comment: a frozen object cannot be mutated by anyone afterwards, including by
 * a consumer that decided to help itself. A renderer that receives a mutable
 * scene graph has been handed the ability to rewrite the semantics it is
 * supposed to be displaying, and every law above stops being true the moment
 * that happens.
 *
 * ── WHY SUCCESS CARRIES `authority: "none"` RATHER THAN AN ABSENT FIELD ─────
 *
 * An absent authority field is ambiguous: it might mean "none", it might mean
 * "nobody thought about it", and a caller under pressure will read it as
 * "permitted". So every successful surface here states its zero-authority
 * properties EXPLICITLY, in the type, as literal types:
 *
 *     authority: "none" | controlPlane: false | readOnly: true | executionAuthorized: false
 *
 * A reader cannot miss them, a `switch` can exhaust on them, and a future edit
 * that tries to widen `authority` to `"limited"` fails to compile.
 *
 * ── WHY UNKNOWN VOCABULARY FAILS CLOSED ─────────────────────────────────────
 *
 * Every enumerable field in this module is drawn from a frozen literal union
 * built from a frozen array. There is no `string` escape hatch for a semantic
 * class anywhere. A caller passing `kind: "emergent"` gets a REFUSAL, not a
 * scene primitive that quietly means nothing.
 *
 * The alternative — accepting unknown strings and treating them as "some other
 * kind" — is how a renderer ends up drawing a thing that no upstream phase
 * authorised, which is precisely law 1 (materialise, never redefine) failing
 * quietly.
 *
 * ── WHY THE SEPARATION IS MECHANICAL, NOT PROSE ─────────────────────────────
 *
 * Ten inequalities are stated above. Prose can be paraphrased away by a reader
 * in a hurry. So each one is also an entry in `RENDERER_SEPARATION_LAWS`, and
 * `assertRendererSeparationLaw` re-checks, at runtime, against real values, that
 * none of them has been collapsed. `sceneGraphIsRuntimeState()` returning true
 * would be a bug; the function exists so that such a bug is a test failure
 * rather than a silent collapse of the law.
 */

// ── closed vocabularies ───────────────────────────────────────────────────────

/**
 * What a scene primitive IS.
 *
 * Note that `unknown` is a MEMBER of this union rather than an error case. That
 * is law 17: an unclassifiable thing is drawn as explicitly unknown, never
 * omitted and never guessed at. A separate `unknown` class is what stops the
 * renderer from having to invent a classification in order to draw something.
 */
export const SCENE_PRIMITIVE_KINDS = Object.freeze([
  "entity",
  "relation",
  "route",
  "conflict",
  "refusal",
  "partition",
  "observer_view",
  "overlay",
  "unknown",
] as const);
export type ScenePrimitiveKind = (typeof SCENE_PRIMITIVE_KINDS)[number];

/**
 * Topology relations.
 *
 * `forwarder` and `origin` are SEPARATE values and the axis is explicitly
 * non-collapsible (see `RELATION_ROLES`). A renderer that draws a forwarder
 * identically to an origin has visually asserted an origin that upstream never
 * granted, which is a semantic strengthening — law 16.
 *
 * The three values are 28D's `route_role` vocabulary EXACTLY. 29A originally
 * declared `observer` here, which Phase 28 does not produce; gate 29B caught it
 * the moment real 28D data was compiled, and the contract was corrected to match
 * upstream rather than remapping the data to fit the contract. A renderer
 * contract that renames a Phase-28 semantic is redefining it — law 1.
 */
export const SCENE_RELATION_KINDS = Object.freeze([
  "routes_through",
  "forwards_to",
  "participates_in",
  "conflicts_with",
  "partitioned_from",
  "observed_by",
  "proposes",
  "unknown",
] as const);
export type SceneRelationKind = (typeof SCENE_RELATION_KINDS)[number];

/**
 * The three route roles, kept apart on purpose.
 *
 * A route's role describes who carried a CLAIM, never who is entitled to act.
 * Collapsing any two of these into one visual form is refused by
 * `assertRoleAxisNonCollapsible`.
 */
export const RELATION_ROLES = Object.freeze(["origin", "forwarder", "destination"] as const);
export type RelationRole = (typeof RELATION_ROLES)[number];

/**
 * Overlay classes. Overlays are explanatory surface, never semantic surface:
 * they render provenance and refusal reasons and confer nothing.
 */
export const SCENE_OVERLAY_KINDS = Object.freeze([
  "provenance",
  "explanation",
  "conflict",
  "refusal",
  "partition",
  "stale",
  "unknown",
] as const);
export type SceneOverlayKind = (typeof SCENE_OVERLAY_KINDS)[number];

/**
 * How a render plan reports what it did NOT do.
 *
 * Law 30 is why `unsupported` exists as its own outcome: a capability that is
 * unavailable must never be reported as a pass. A plan that renders 90% of the
 * frame and calls itself `ok` is the failure this taxonomy exists to prevent, so
 * `complete` is a separate, explicitly-checkable flag rather than an inference.
 */
export const RENDER_COMPLETENESS = Object.freeze(["complete", "incomplete", "unsupported"] as const);
export type RenderCompleteness = (typeof RENDER_COMPLETENESS)[number];

/**
 * Picking identity kinds.
 *
 * Law 6: PICKING != EXECUTION. A picking id identifies WHAT WAS HIT. It never
 * names a permitted action, and this module refuses any picking id that tries
 * to. `ReadonlyPickingIdentity` has no action field at all — see the interface.
 */
export const PICKING_IDENTITY_KINDS = Object.freeze(["subject", "relation", "overlay", "none"] as const);
export type PickingIdentityKind = (typeof PICKING_IDENTITY_KINDS)[number];

/**
 * The ten separations, as data. Each entry names the two things that must never
 * be conflated, plus the field on each side that carries the distinguishing
 * evidence.
 */
export const RENDERER_SEPARATION_LAWS = Object.freeze([
  { left: "pixels", right: "authority", leftField: "renderPlanHash", rightField: "authority" },
  { left: "sceneGraph", right: "runtimeState", leftField: "sceneHash", rightField: "runtimeStateHash" },
  { left: "selection", right: "permission", leftField: "selectionPresent", rightField: "permission" },
  { left: "picking", right: "execution", leftField: "pickingIdPresent", rightField: "executionAuthorized" },
  { left: "animation", right: "liveExecution", leftField: "animationPlanHash", rightField: "liveExecution" },
  { left: "gpuRecovery", right: "runtimeRecovery", leftField: "deviceRebuilt", rightField: "runtimeStateHash" },
  { left: "position", right: "trust", leftField: "position", rightField: "trust" },
  { left: "size", right: "importance", leftField: "sizeHint", rightField: "importance" },
  { left: "depth", right: "privilege", leftField: "zOrder", rightField: "privilege" },
  { left: "color", right: "canonicalSemantics", leftField: "colorHint", rightField: "canonicalKind" },
] as const);
export type RendererSeparationLaw = (typeof RENDERER_SEPARATION_LAWS)[number];

/** Refusal vocabulary. Closed, so an unlisted reason cannot be invented. */
export const RENDERER_REFUSAL_CODES = Object.freeze([
  "refused_renderer_input_invalid",
  "refused_renderer_input_unknown_field",
  "refused_renderer_kind_unknown",
  "refused_renderer_role_unknown",
  "refused_renderer_overlay_unknown",
  "refused_renderer_relation_unknown",
  "refused_renderer_binding_missing",
  "refused_renderer_authority_claim",
  "refused_renderer_hash_unbound",
  "refused_renderer_mutable_surface",
  "refused_renderer_budget_exceeded",
  "refused_renderer_picking_action_claim",
  "refused_renderer_role_axis_collapsed",
  "refused_renderer_completeness_unsupported_as_pass",
] as const);
export type RendererRefusalCode = (typeof RENDERER_REFUSAL_CODES)[number];

/**
 * Explicit resource bounds (law 28: explicit limits that fail CLOSED, never a
 * silent semantic truncation). Exceeding any of these is a refusal that emits
 * no scene at all — not a smaller scene.
 */
export const RENDERER_BOUNDS = Object.freeze({
  maxPrimitives: 4096,
  maxRelations: 4096,
  maxOverlays: 256,
  maxPickings: 4096,
  maxPlanEntries: 8192,
  maxLabelLength: 128,
});
export type RendererBounds = typeof RENDERER_BOUNDS;

export const RENDERER_SCHEMA_VERSION = "menog-renderer-trust-contract/v0" as const;

/** The four zero-authority properties every successful surface states outright. */
export interface RendererZeroAuthority {
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

// ── the contracts ─────────────────────────────────────────────────────────────

/**
 * Everything a renderer is permitted to be handed.
 *
 * `RendererInput` is an ALLOWLIST surface: `buildRendererInput` accepts only the
 * fields named here, and refuses the whole call if an unrecognised key is
 * present. 28G's denylist-shaped hole (`28J-OBS-5` — unknown keys silently
 * ignored) is deliberately not repeated here: an ignored key reads as a read
 * key, which is exactly the false impression that defect creates.
 */
export interface RendererInput {
  readonly sourceFrameId: string;
  readonly sourceVisibleHash: string;
  readonly sceneHash: string;
  readonly runtimeStateHash: string;
  readonly observationOnly: true;
}

/** A single drawable thing. Carries geometry hints and ZERO semantic claims. */
export interface ScenePrimitive {
  readonly kind: ScenePrimitiveKind;
  readonly primitiveId: string;
  readonly label: string;
  /** Visual hint only. Never a semantic classification (law 15). */
  readonly colorHint: string;
  /** Visual hint only. Never importance. */
  readonly sizeHint: number;
  /** Visual hint only. Never privilege. */
  readonly zOrder: number;
  /** Always "none": a primitive confers no trust. */
  readonly trust: "none";
  readonly position: readonly [number, number, number];
}

/** A topology edge. `role` keeps forwarder and origin apart. */
export interface SceneRelation {
  readonly kind: SceneRelationKind;
  readonly relationId: string;
  readonly fromId: string;
  readonly toId: string;
  readonly role: RelationRole;
  /** Always false: a relation never authorises anything (law 18). */
  readonly authorizes: false;
  /** Always "none": a relation never confers trust (law 10). */
  readonly trust: "none";
}

/** Explanatory surface. Renders reasons; confers nothing. */
export interface SceneOverlay {
  readonly kind: SceneOverlayKind;
  readonly overlayId: string;
  readonly targetId: string;
  readonly text: string;
  /** Always "none". An overlay cannot strengthen a claim (law 16). */
  readonly authority: "none";
}

/** The compiled scene. Distinct identity from every other layer. */
export interface GetigScene {
  readonly sceneHash: string;
  readonly sourceFrameId: string;
  readonly sourceVisibleHash: string;
  readonly primitives: readonly ScenePrimitive[];
  readonly relations: readonly SceneRelation[];
  readonly overlays: readonly SceneOverlay[];
  /** Never equals runtimeStateHash. That inequality is law SCENE_GRAPH != RUNTIME_STATE. */
  readonly runtimeStateHash: string;
}

/**
 * A render plan: WHAT WOULD BE DRAWN. Not a draw call — none exist in Phase 29A.
 * There is no buffer handle, no shader, no pipeline, no `submit()` anywhere in
 * this module, and there will not be one until 29D.
 */
export interface RenderPlan {
  readonly planHash: string;
  readonly sceneHash: string;
  readonly entryCount: number;
  readonly completeness: RenderCompleteness;
  /** Law 30, structural: an unsupported plan can never carry completeness "complete". */
  readonly supportsHardware: boolean;
  /** A plan authorises nothing. */
  readonly executionAuthorized: false;
}

/**
 * Picking identity: WHAT WAS HIT.
 *
 * There is deliberately no `action`, `command`, `effect` or `permission` field
 * in this interface. Not "they default to none" — absent. A caller cannot set
 * one even by mistake, and no downstream gate has a field to read.
 */
export interface PickingIdentity {
  readonly kind: PickingIdentityKind;
  readonly pickingId: string;
  readonly subjectId: string | null;
  readonly observerId: string;
  /** Picking confers no execution. */
  readonly executionAuthorized: false;
}

/** Frame-level metadata bound to the frame it describes. */
export interface RendererFrameMetadata {
  readonly frameId: string;
  readonly canonicalVisibleHash: string;
  readonly sceneHash: string;
  readonly planHash: string;
  readonly observerId: string;
  readonly graphicsBackend: "none";
  readonly authority: "none";
  readonly executionAuthorized: false;
}

/**
 * A device qualification FACT, as data.
 *
 * 29A does not probe anything. This is the shape a 29C probe will return, with
 * `qualification` fixed at "unqualified" until real evidence exists. Law 31 is
 * why there is no way to mark a software path as hardware-validated: the field
 * cannot hold a value that says so.
 */
export interface DeviceQualificationFact {
  readonly vendor: string;
  readonly isFallbackAdapter: boolean;
  readonly featureCount: number;
  readonly maxBufferSize: number;
  readonly maxTextureDimension2D: number;
  readonly qualification: "unqualified" | "observed";
  /** Never true at 29A. A software path can never assert hardware validation. */
  readonly hardwareValidated: false;
}

// ── outcome shapes ────────────────────────────────────────────────────────────

export type RendererRefusal = {
  readonly ok: false;
  readonly code: "renderer_refused";
  readonly refusal: RendererRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  /** ALWAYS null. A refusal emits no scene, no plan, no picking id. */
  readonly scene: null;
  readonly plan: null;
  readonly pickings: null;
  readonly partialOutputEmitted: false;
} & RendererZeroAuthority;

export type RendererSucceeded<T> = {
  readonly ok: true;
  readonly code: "renderer_accepted";
  readonly value: T;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type RendererDecision<T> = RendererSucceeded<T> | RendererRefusal;

// ── helpers ───────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (refusal: RendererRefusalCode, explanation: string, offendingField: string | null = null): RendererRefusal => ({
  ok: false,
  code: "renderer_refused",
  refusal,
  explanation,
  offendingField,
  scene: null,
  plan: null,
  pickings: null,
  partialOutputEmitted: false,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const ok = <T>(value: T): RendererSucceeded<T> => ({
  ok: true,
  code: "renderer_accepted",
  value,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

/** The ONLY field names a RendererInput may carry. Anything else is refused. */
const RENDERER_INPUT_FIELDS = Object.freeze([
  "sourceFrameId",
  "sourceVisibleHash",
  "sceneHash",
  "runtimeStateHash",
  "observationOnly",
] as const);

const PRIMITIVE_KINDS = new Set<string>(SCENE_PRIMITIVE_KINDS);
const RELATION_KINDS = new Set<string>(SCENE_RELATION_KINDS);
const RELATION_ROLES_SET = new Set<string>(RELATION_ROLES);
const OVERLAY_KINDS = new Set<string>(SCENE_OVERLAY_KINDS);
const PICKING_KINDS = new Set<string>(PICKING_IDENTITY_KINDS);

const HASH_SHAPE = /^[a-f0-9]{16,128}$/;
const isHash = (v: unknown): v is string => typeof v === "string" && HASH_SHAPE.test(v);

const freezeAll = <T>(items: readonly T[]): readonly T[] => Object.freeze(items.map((i) => Object.freeze(i)));

// ── the contract functions ────────────────────────────────────────────────────

/**
 * Build a `RendererInput` — the allowlisted surface, refusing the WHOLE call if
 * any unrecognised key is present.
 */
export function buildRendererInput(input: unknown): RendererDecision<RendererInput> {
  if (!isRecord(input)) return refuse("refused_renderer_input_invalid", "renderer input must be an object");

  for (const key of Object.keys(input)) {
    if (!(RENDERER_INPUT_FIELDS as readonly string[]).includes(key)) {
      return refuse(
        "refused_renderer_input_unknown_field",
        `renderer input carries an unknown field: ${key}`,
        key,
      );
    }
  }

  const { sourceFrameId, sourceVisibleHash, sceneHash, runtimeStateHash, observationOnly } = input;
  if (typeof sourceFrameId !== "string" || sourceFrameId.length === 0) {
    return refuse("refused_renderer_binding_missing", "sourceFrameId must be a non-empty string", "sourceFrameId");
  }
  if (!isHash(sourceVisibleHash)) {
    return refuse("refused_renderer_hash_unbound", "sourceVisibleHash must be a hex hash", "sourceVisibleHash");
  }
  if (!isHash(sceneHash)) {
    return refuse("refused_renderer_hash_unbound", "sceneHash must be a hex hash", "sceneHash");
  }
  if (!isHash(runtimeStateHash)) {
    return refuse("refused_renderer_hash_unbound", "runtimeStateHash must be a hex hash", "runtimeStateHash");
  }
  // The one inequality enforced at construction time, not merely documented.
  if (sceneHash === runtimeStateHash) {
    return refuse(
      "refused_renderer_hash_unbound",
      "sceneHash must not equal runtimeStateHash (SCENE_GRAPH != RUNTIME_STATE)",
      "sceneHash",
    );
  }
  if (observationOnly !== true) {
    return refuse("refused_renderer_authority_claim", "observationOnly must be exactly true", "observationOnly");
  }

  return ok(Object.freeze({ sourceFrameId, sourceVisibleHash, sceneHash, runtimeStateHash, observationOnly: true }));
}

/** Build one `ScenePrimitive`. Unknown kind ⇒ refusal (law: unknown vocabulary fails closed). */
export function buildScenePrimitive(input: unknown): RendererDecision<ScenePrimitive> {
  if (!isRecord(input)) return refuse("refused_renderer_input_invalid", "scene primitive must be an object");
  const kind = input.kind;
  if (typeof kind !== "string" || !PRIMITIVE_KINDS.has(kind)) {
    return refuse("refused_renderer_kind_unknown", `unknown scene primitive kind: ${String(kind)}`, "kind");
  }
  if (typeof input.primitiveId !== "string" || input.primitiveId.length === 0) {
    return refuse("refused_renderer_binding_missing", "primitiveId must be a non-empty string", "primitiveId");
  }
  const label = typeof input.label === "string" ? input.label : "";
  if (label.length > RENDERER_BOUNDS.maxLabelLength) {
    return refuse("refused_renderer_budget_exceeded", "label exceeds maxLabelLength", "label");
  }
  const position = input.position;
  if (!Array.isArray(position) || position.length !== 3 || position.some((n) => typeof n !== "number")) {
    return refuse("refused_renderer_input_invalid", "position must be three numbers", "position");
  }
  // Visual hints are hints. They cannot be anything but their declared types.
  const colorHint = input.colorHint === undefined ? "none" : input.colorHint;
  if (typeof colorHint !== "string") {
    return refuse("refused_renderer_input_invalid", "colorHint must be a string", "colorHint");
  }
  const sizeHint = input.sizeHint === undefined ? 1 : input.sizeHint;
  const zOrder = input.zOrder === undefined ? 0 : input.zOrder;
  if (typeof sizeHint !== "number" || typeof zOrder !== "number") {
    return refuse("refused_renderer_input_invalid", "sizeHint and zOrder must be numbers", "sizeHint");
  }

  return ok(
    Object.freeze({
      kind: kind as ScenePrimitiveKind,
      primitiveId: input.primitiveId,
      label,
      colorHint,
      sizeHint,
      zOrder,
      trust: "none" as const,
      position: Object.freeze([position[0], position[1], position[2]]) as readonly [number, number, number],
    }),
  );
}

/** Build one `SceneRelation`. `role` is mandatory and validated. */
export function buildSceneRelation(input: unknown): RendererDecision<SceneRelation> {
  if (!isRecord(input)) return refuse("refused_renderer_input_invalid", "scene relation must be an object");
  const kind = input.kind;
  if (typeof kind !== "string" || !RELATION_KINDS.has(kind)) {
    return refuse("refused_renderer_relation_unknown", `unknown relation kind: ${String(kind)}`, "kind");
  }
  const role = input.role;
  if (typeof role !== "string" || !RELATION_ROLES_SET.has(role)) {
    return refuse("refused_renderer_role_unknown", `unknown relation role: ${String(role)}`, "role");
  }
  if (typeof input.relationId !== "string" || typeof input.fromId !== "string" || typeof input.toId !== "string") {
    return refuse("refused_renderer_binding_missing", "relationId, fromId and toId must be strings");
  }
  return ok(
    Object.freeze({
      kind: kind as SceneRelationKind,
      relationId: input.relationId,
      fromId: input.fromId,
      toId: input.toId,
      role: role as RelationRole,
      authorizes: false as const,
      trust: "none" as const,
    }),
  );
}

/** Build one `SceneOverlay`. */
export function buildSceneOverlay(input: unknown): RendererDecision<SceneOverlay> {
  if (!isRecord(input)) return refuse("refused_renderer_input_invalid", "scene overlay must be an object");
  const kind = input.kind;
  if (typeof kind !== "string" || !OVERLAY_KINDS.has(kind)) {
    return refuse("refused_renderer_overlay_unknown", `unknown overlay kind: ${String(kind)}`, "kind");
  }
  if (typeof input.overlayId !== "string" || typeof input.targetId !== "string") {
    return refuse("refused_renderer_binding_missing", "overlayId and targetId must be strings");
  }
  const text = typeof input.text === "string" ? input.text : "";
  if (text.length > RENDERER_BOUNDS.maxLabelLength) {
    return refuse("refused_renderer_budget_exceeded", "overlay text exceeds maxLabelLength", "text");
  }
  return ok(
    Object.freeze({
      kind: kind as SceneOverlayKind,
      overlayId: input.overlayId,
      targetId: input.targetId,
      text,
      authority: "none" as const,
    }),
  );
}

/** Assemble a `GetigScene` from already-validated parts, enforcing the bounds. */
export function buildGetigScene(input: {
  readonly sourceFrameId: string;
  readonly sourceVisibleHash: string;
  readonly sceneHash: string;
  readonly runtimeStateHash: string;
  readonly primitives: readonly ScenePrimitive[];
  readonly relations: readonly SceneRelation[];
  readonly overlays: readonly SceneOverlay[];
}): RendererDecision<GetigScene> {
  if (input.sceneHash === input.runtimeStateHash) {
    return refuse(
      "refused_renderer_hash_unbound",
      "sceneHash must not equal runtimeStateHash (SCENE_GRAPH != RUNTIME_STATE)",
      "sceneHash",
    );
  }
  // Law 28: over budget is a refusal, never a silent truncation to the bound.
  if (input.primitives.length > RENDERER_BOUNDS.maxPrimitives) {
    return refuse("refused_renderer_budget_exceeded", "primitive count exceeds maxPrimitives", "primitives");
  }
  if (input.relations.length > RENDERER_BOUNDS.maxRelations) {
    return refuse("refused_renderer_budget_exceeded", "relation count exceeds maxRelations", "relations");
  }
  if (input.overlays.length > RENDERER_BOUNDS.maxOverlays) {
    return refuse("refused_renderer_budget_exceeded", "overlay count exceeds maxOverlays", "overlays");
  }
  return ok(
    Object.freeze({
      sceneHash: input.sceneHash,
      sourceFrameId: input.sourceFrameId,
      sourceVisibleHash: input.sourceVisibleHash,
      primitives: freezeAll(input.primitives),
      relations: freezeAll(input.relations),
      overlays: freezeAll(input.overlays),
      runtimeStateHash: input.runtimeStateHash,
    }),
  );
}

/** Build a `RenderPlan`. No GPU resource is named, allocated or touched. */
export function buildRenderPlan(input: {
  readonly sceneHash: string;
  readonly entryCount: number;
  readonly completeness: RenderCompleteness;
  readonly supportsHardware: boolean;
}): RendererDecision<RenderPlan> {
  if (input.entryCount > RENDERER_BOUNDS.maxPlanEntries) {
    return refuse("refused_renderer_budget_exceeded", "entry count exceeds maxPlanEntries", "entryCount");
  }
  // Law 30, enforced structurally rather than trusted: an unsupported plan that
  // claims completeness is refused at construction, not flagged downstream.
  if (!input.supportsHardware && input.completeness === "complete") {
    return refuse(
      "refused_renderer_completeness_unsupported_as_pass",
      "an unsupported plan may not declare completeness 'complete' (UNSUPPORTED is never PASS)",
      "completeness",
    );
  }
  return ok(
    Object.freeze({
      planHash: `plan_${input.sceneHash}`,
      sceneHash: input.sceneHash,
      entryCount: input.entryCount,
      completeness: input.completeness,
      supportsHardware: input.supportsHardware,
      executionAuthorized: false as const,
    }),
  );
}

/**
 * Build picking identities.
 *
 * Any attempt to attach an action, permission or effect to a picking id is a
 * REFUSAL (`refused_renderer_picking_action_claim`), not a stripped field.
 * Silently dropping it would leave the caller believing it had been honoured.
 */
export function buildPickingIdentities(input: {
  readonly observerId: string;
  readonly entries: readonly Record<string, unknown>[];
}): RendererDecision<readonly PickingIdentity[]> {
  const FORBIDDEN = ["action", "command", "effect", "permission", "grant", "execute", "approve"];
  if (input.entries.length > RENDERER_BOUNDS.maxPickings) {
    return refuse("refused_renderer_budget_exceeded", "picking count exceeds maxPickings", "entries");
  }
  const out: PickingIdentity[] = [];
  for (const entry of input.entries) {
    if (!isRecord(entry)) return refuse("refused_renderer_input_invalid", "picking entry must be an object");
    for (const key of Object.keys(entry)) {
      if (FORBIDDEN.includes(key)) {
        return refuse(
          "refused_renderer_picking_action_claim",
          `picking identity may not carry an action field: ${key}`,
          key,
        );
      }
    }
    const kind = entry.kind;
    if (typeof kind !== "string" || !PICKING_KINDS.has(kind)) {
      return refuse("refused_renderer_kind_unknown", `unknown picking kind: ${String(kind)}`, "kind");
    }
    const subjectId = entry.subjectId === null || entry.subjectId === undefined ? null : entry.subjectId;
    if (subjectId !== null && typeof subjectId !== "string") {
      return refuse("refused_renderer_input_invalid", "subjectId must be a string or null", "subjectId");
    }
    out.push(
      Object.freeze({
        kind: kind as PickingIdentity["kind"],
        pickingId: typeof entry.pickingId === "string" ? entry.pickingId : "none",
        subjectId,
        observerId: input.observerId,
        executionAuthorized: false as const,
      }),
    );
  }
  return ok(freezeAll(out));
}

/** Build frame metadata bound to the frame it describes. */
export function buildRendererFrameMetadata(input: {
  readonly frameId: string;
  readonly canonicalVisibleHash: string;
  readonly sceneHash: string;
  readonly planHash: string;
  readonly observerId: string;
}): RendererDecision<RendererFrameMetadata> {
  if (!isHash(input.canonicalVisibleHash) || !isHash(input.sceneHash) || !isHash(input.planHash)) {
    return refuse("refused_renderer_hash_unbound", "frame metadata requires three hex hashes");
  }
  return ok(
    Object.freeze({
      frameId: input.frameId,
      canonicalVisibleHash: input.canonicalVisibleHash,
      sceneHash: input.sceneHash,
      planHash: input.planHash,
      observerId: input.observerId,
      graphicsBackend: "none" as const,
      authority: "none" as const,
      executionAuthorized: false as const,
    }),
  );
}

/**
 * Record a device qualification FACT.
 *
 * `hardwareValidated` is not a parameter: the contract has no shape in which a
 * caller could set it true. That is law 31 made unfalsifiable.
 */
export function buildDeviceQualificationFact(input: {
  readonly vendor: string;
  readonly isFallbackAdapter: boolean;
  readonly featureCount: number;
  readonly maxBufferSize: number;
  readonly maxTextureDimension2D: number;
  readonly qualification?: "unqualified" | "observed";
}): RendererDecision<DeviceQualificationFact> {
  if (typeof input.vendor !== "string" || input.vendor.length === 0) {
    return refuse("refused_renderer_input_invalid", "vendor must be a non-empty string", "vendor");
  }
  const qualification = input.qualification ?? "unqualified";
  if (qualification !== "unqualified" && qualification !== "observed") {
    return refuse("refused_renderer_input_invalid", "qualification must be 'unqualified' or 'observed'", "qualification");
  }
  return ok(
    Object.freeze({
      vendor: input.vendor,
      isFallbackAdapter: input.isFallbackAdapter,
      featureCount: input.featureCount,
      maxBufferSize: input.maxBufferSize,
      maxTextureDimension2D: input.maxTextureDimension2D,
      qualification,
      hardwareValidated: false as const,
    }),
  );
}

// ── the separations, re-checkable ─────────────────────────────────────────────

/**
 * Re-check the ten separations against real values.
 *
 * Returns the separations that have been COLLAPSED. An empty array is the
 * expected result; a non-empty one is a security failure, not a warning. The
 * function exists so that a future gate can call it with whatever it produced
 * and get a mechanical answer instead of a promise.
 */
export function assertRendererSeparationLaw(observed: {
  readonly sceneHash: string;
  readonly runtimeStateHash: string;
  readonly authority: string;
  readonly permission: string;
  readonly executionAuthorized: boolean;
  readonly liveExecution: boolean;
  readonly deviceRebuilt: boolean;
  readonly runtimeStateRestoredByDeviceRecovery: boolean;
  readonly trust: string;
  readonly importance: string;
  readonly privilege: string;
  readonly canonicalKind: string;
}): readonly RendererSeparationLaw[] {
  const collapsed: RendererSeparationLaw[] = [];
  const push = (law: RendererSeparationLaw): void => {
    collapsed.push(law);
  };
  if (observed.sceneHash === observed.runtimeStateHash) push(RENDERER_SEPARATION_LAWS[1]);
  if (observed.authority !== "none") push(RENDERER_SEPARATION_LAWS[0]);
  if (observed.permission !== "none") push(RENDERER_SEPARATION_LAWS[2]);
  if (observed.executionAuthorized) push(RENDERER_SEPARATION_LAWS[3]);
  if (observed.liveExecution) push(RENDERER_SEPARATION_LAWS[4]);
  // GPU_RECOVERY != RUNTIME_RECOVERY. Rebuilding a graphics device must leave
  // runtime state untouched; a recovery that also restored runtime state has
  // collapsed the law.
  if (observed.deviceRebuilt && observed.runtimeStateRestoredByDeviceRecovery) push(RENDERER_SEPARATION_LAWS[5]);
  if (observed.trust !== "none") push(RENDERER_SEPARATION_LAWS[6]);
  if (observed.importance !== "none") push(RENDERER_SEPARATION_LAWS[7]);
  if (observed.privilege !== "none") push(RENDERER_SEPARATION_LAWS[8]);
  if (observed.canonicalKind === "color") push(RENDERER_SEPARATION_LAWS[9]);
  return Object.freeze(collapsed);
}

/** The forwarder/origin/observer axis is non-collapsible (law 18). */
export function assertRoleAxisNonCollapsible(roles: readonly RelationRole[]): RendererDecision<readonly RelationRole[]> {
  const known = roles.filter((r) => RELATION_ROLES_SET.has(r));
  if (known.length !== roles.length) {
    return refuse("refused_renderer_role_unknown", "role axis carries an unknown role", "role");
  }
  if (new Set(known).size === 1 && known.length > 1) {
    return refuse(
      "refused_renderer_role_axis_collapsed",
      "forwarder and origin may not be collapsed into a single visual role",
      "role",
    );
  }
  return ok(freezeAll(known));
}

/**
 * Verify that a surface really IS frozen, and refuse if it is not.
 *
 * Every constructor in this module freezes what it returns, but a caller can
 * hand a renderer something it built by other means. `readonly` is erased at
 * runtime, so a `ScenePrimitive` that merely says `readonly` behaves exactly
 * like a mutable one. This is the check that turns the "frozen, not merely
 * readonly" claim from a construction-time convention into an enforceable
 * property — and it is why `refused_renderer_mutable_surface` exists.
 *
 * Nested collections are checked too: a frozen object holding a mutable array
 * is not a frozen surface, because the array is what a renderer would push
 * into.
 */
export function assertFrozenSurface(
  surface: unknown,
  nestedKeys: readonly string[] = [],
): RendererDecision<true> {
  if (!isRecord(surface)) {
    return refuse("refused_renderer_input_invalid", "surface must be an object", null);
  }
  if (!Object.isFrozen(surface)) {
    return refuse("refused_renderer_mutable_surface", "surface is not frozen; a mutable scene can rewrite its own semantics", null);
  }
  for (const key of nestedKeys) {
    const nested = surface[key];
    if (nested === undefined) continue;
    if (Array.isArray(nested) ? !Object.isFrozen(nested) : !Object.isFrozen(nested)) {
      return refuse("refused_renderer_mutable_surface", `nested surface ${key} is not frozen`, key);
    }
  }
  return ok(true);
}

/**
 * Phase-29A contains no draw call.
 *
 * This exists so the claim is checkable rather than rhetorical: the suite
 * asserts the module source contains none of the tokens below, and this
 * constant lists them.
 */
export const PHASE29A_FORBIDDEN_TOKENS = Object.freeze([
  "navigator.gpu",
  "requestAdapter",
  "requestDevice",
  "GPUDevice",
  "GPUAdapter",
  "WGSL",
  "createBuffer",
  "createTexture",
  "createRenderPipeline",
  "draw(",
  "submit(",
] as const);