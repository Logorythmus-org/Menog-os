/**
 * PHASE 29G — PICKING & READ-ONLY INTERACTION
 * (SELECTION / INSPECTION ONLY)
 *
 * CENTRAL LAWS:
 *   PICKING != EXECUTION
 *   SELECTION != PERMISSION
 *
 * ── WHAT THIS MODULE IS ──────────────────────────────────────────────────────
 *
 * The CPU half of picking. 29D uploads an OPAQUE INTEGER (`pickingIndex`) so a
 * picking pass can name a pixel; nothing semantic ever leaves the CPU. This
 * module is where that integer — or the opaque `pickingId` a UI holds — is
 * resolved back to the visible subject it names, and from there handed to the
 * Phase-28 read-only inspection runtime (28G) and explanation graph (28F).
 *
 * There are exactly THREE functions here:
 *   · `resolvePickingSelection`  — index/id -> subject + relations + markers
 *   · `inspectPickedSubject`     — resolve, then run 28G select + 28F explain
 *   · `refusePickedSelectionExecution` — can ONLY refuse (the law, made testable)
 *
 * No apply, no command, no dispatch, no store import, no GPU call. The module
 * IMPORTS the Phase-28 read-only runtimes and nothing else that could act —
 * the suite asserts the full import list, so "only Phase-28 read-only
 * inspection reachable" is checked against the file rather than trusted.
 *
 * ── WHY A PICKING ID IS OPAQUE, BOUNDED, DETERMINISTIC ───────────────────────
 *
 * The id is `pick_` + a canonical hash of (sceneHash, subjectVisibleId): a
 * 64-hex string that reveals NOTHING about the subject — it does not contain
 * the subject's name, its collection, or its role. It is deterministic WITHIN
 * a scene (the same scene always yields the same id — proven by re-deriving it
 * in the suite from both the 29B compile and the 29D plan) and meaningless
 * outside it, because the scene hash is part of the input. Tables are bounded
 * (`PICKING_BOUNDS`); an over-bound scene or plan is REFUSED, never truncated,
 * because a truncated picking table silently misnames pixels.
 *
 * ── WHY STALE AND SUBSTITUTED IDS REFUSE ─────────────────────────────────────
 *
 * A picking id is an identity claim about ONE scene. When the scene changes,
 * every old id is a name for something that may no longer be drawn — so:
 *   · a plan whose `sceneHash` disagrees with the supplied scene is STALE
 *     (`refused_picking_stale_scene`) and no lookup happens at all;
 *   · a `currentSceneHash` that disagrees with the scene is stale too;
 *   · an id absent from the current table is unknown
 *     (`refused_picking_unknown_id`) — this is how a foreign, cross-scene id
 *     fails when it is presented against a consistent scene/plan pair;
 *   · an index and an id that name DIFFERENT rows, or a caller's
 *     `claimedSubjectVisibleId` that disagrees with the resolved row, is a
 *     SUBSTITUTION attempt (`refused_picking_subject_substitution`) — the
 *     caller's claim is never trusted, and the refusal text never reveals the
 *     true subject, so a failed substitution learns nothing.
 * Every refusal carries `selection: null`: no partial identity ever leaks.
 *
 * ── WHY THE SEMANTIC IDENTITY STAYS CPU-SIDE ────────────────────────────────
 *
 * The integer alone carries nothing: an out-of-range, fractional or non-numeric
 * index produces a REFUSAL with no subject, not a fallback. Identity exists
 * only as a row of the CPU table, and each row is re-derived before use
 * (`pick_ + canonicalHash(sceneHash, subjectVisibleId)` must equal the row's
 * own id, the row's subject must exist as a primitive of the supplied scene,
 * and the row's relation/overlay projections must byte-match the scene) — so a
 * tampered table cannot smuggle an identity in. The selection states
 * `uploadedToGpu: false`, `resolvedCpuSide: true`, and — because 29C measured
 * this machine's readback returning all zeros — `pixelOutputVerified: false`:
 * resolving an index is not evidence that any pixel was ever read back.
 *
 * ── WHY SELECTION CANNOT HIDE MANDATORY MARKERS ──────────────────────────────
 *
 * There is no field that could exclude them. Every selection carries the
 * subject's OWN mandatory markers AND the scene-WIDE mandatory inventory
 * (conflict / refusal / partition, from 29E's MANDATORY_OVERLAY_KINDS —
 * imported, not re-declared), plus `markersPreserved: true` and
 * `hidesMandatoryMarkers: false` as literal types. A request-shaped input that
 * tries (`hideMarkers`, `suppressMarkers`, ...) is refused up front with
 * `refused_picking_marker_suppression`. Picking something must never make the
 * conflicts around it disappear — that is how a viewer ends up watching a calm
 * scene that the evidence never described.
 *
 * ── WHY ANY ACTION-SHAPED REQUEST REFUSES ────────────────────────────────────
 *
 * Input keys drawn from the action vocabulary (`execute`, `approve`, `grant`,
 * `command`, `permission`, ...) are refused with
 * `refused_picking_action_surface` before anything else is considered: this
 * module has no such operation, and a caller who believes it happened is the
 * exact failure the refusal exists to prevent (SELECTION != PERMISSION). The
 * same discipline that makes 28G's forbidden-action list testable makes this
 * one testable: the suite drives EVERY declared field name and compares the
 * driven set against the vocabulary.
 *
 * ── WHY THE INSPECTION IS PHASE-28'S, VERBATIM ───────────────────────────────
 *
 * `inspectPickedSubject` constructs the query ITSELF — `{kind: "select",
 * operation: "select", subjectVisibleId: <resolved>}` — so a caller cannot
 * smuggle in a different operation, and the operation it does send is drawn
 * from 28G's closed allowed list. 28G's and 28F's decisions are surfaced AS
 * DECISIONS: when 28G refuses (a conflict subject is not selectable in the
 * view; a binding mismatch), that refusal is content and is returned intact —
 * 29G does not soften a Phase-28 refusal to make a pick look successful. The
 * explanation trace is bound to the RESOLVED subject (`trace.subjectVisibleId
 * === selection.subjectVisibleId`), which is the binding the suite proves.
 *
 * NO GPU TOKEN, NO STORE, NO COMMAND SURFACE in this file; the forbidden-token
 * list below is scanned against the CODE (comments and string literals
 * stripped) by the suite, with planted positive controls.
 */

import { canonicalHash } from "./canonical.js";
import {
  INSPECTION_FORBIDDEN_ACTIONS,
  inspect,
  type InspectionDecision,
} from "./getigInspectionRuntime.js";
import { explainGetigSubject, type ExplainDecision } from "./getigProvenance.js";
import { MANDATORY_OVERLAY_KINDS } from "./renderFrameComposer.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

/**
 * 29G's refusals. Every code here is driven from a real input by the suite and
 * compared as a SET against this vocabulary — nothing unreachable, nothing
 * undeclared.
 */
export const GETIG_PICKING_REFUSAL_CODES = Object.freeze([
  "refused_picking_input_invalid",
  "refused_picking_action_surface",
  "refused_picking_marker_suppression",
  "refused_picking_plan_invalid",
  "refused_picking_index_invalid",
  "refused_picking_stale_scene",
  "refused_picking_unknown_id",
  "refused_picking_subject_substitution",
  "refused_picking_bound_exceeded",
  "refused_picking_execution_not_permitted",
] as const);
export type GetigPickingRefusalCode = (typeof GETIG_PICKING_REFUSAL_CODES)[number];

/**
 * Input keys that would make this look like an action surface. The suite
 * drives EVERY name here, so a declared-but-unreachable field cannot hide.
 */
export const GETIG_PICKING_ACTION_FIELDS = Object.freeze([
  "execute",
  "execution",
  "command",
  "commands",
  "approve",
  "approval",
  "permission",
  "permissions",
  "grant",
  "grants",
  "apply",
  "commit",
  "mutate",
  "dispatch",
  "invoke",
  "invokeTool",
  "run",
  "submit",
  "admit",
] as const);

/** Input keys that ask for the one thing a selection must never do: hide a marker. */
export const GETIG_PICKING_MARKER_FIELDS = Object.freeze([
  "hideMarkers",
  "hideMandatoryMarkers",
  "suppressMarkers",
  "occludeMarkers",
  "dismissMarkers",
  "removeMarkers",
  "dropMarkers",
] as const);

/** Inspection-side inputs. Only `inspectPickedSubject` accepts these. */
export const GETIG_PICKING_INSPECTION_FIELDS = Object.freeze([
  "view",
  "sequence",
  "graph",
  "binding",
] as const);

/** The complete input vocabulary. Any other key is refused, fail-closed. */
export const GETIG_PICKING_INPUT_FIELDS = Object.freeze([
  "scene",
  "plan",
  "pickingIndex",
  "pickingId",
  "claimedSubjectVisibleId",
  "currentSceneHash",
  ...GETIG_PICKING_INSPECTION_FIELDS,
] as const);

/** Explicit bounds. Over-bound input REFUSES; nothing is ever truncated. */
export const PICKING_BOUNDS = Object.freeze({
  maxResolutions: 2048,
  maxScenePrimitives: 2048,
  maxSceneRelations: 4096,
  maxSceneOverlays: 4096,
  maxRelationsPerSubject: 512,
  maxOverlaysPerSubject: 512,
  maxSceneMandatoryMarkers: 512,
  maxIdChars: 128,
});

export const PICKING_SCHEMA_VERSION = "menog-picking-resolution/v0" as const;

/**
 * Tokens that would mean this resolver acted, rendered, or drove anything.
 * Scanned against the module's CODE with comments and string literals stripped;
 * the suite plants each one to prove the scanner fires.
 */
export const PHASE29G_FORBIDDEN_TOKENS = Object.freeze([
  "execute(",
  "approve(",
  "grant(",
  "command(",
  "dispatch(",
  "mutate(",
  "apply(",
  "commit(",
  "invoke(",
  "queue.submit",
  "draw(",
  "navigator",
  "requestAdapter",
  "requestDevice",
  "createBuffer",
  "createTexture",
  "createRenderPipeline",
  "createCommandEncoder",
  "requestAnimationFrame",
  "setTimeout",
  "setInterval",
  "Date.now",
  "Math.random",
  "performance.now",
] as const);

// ── the shapes ───────────────────────────────────────────────────────────────

/** One scene relation, as a selection reports it: role preserved, authority zero. */
export interface PickedRelation {
  readonly relationId: string;
  readonly role: string;
  readonly fromId: string;
  readonly toId: string;
  readonly authorizes: false;
  readonly trust: "none";
}

/** One overlay carried by a selection. `kind` is the scene's own kind. */
export interface PickedOverlay {
  readonly overlayId: string;
  readonly kind: string;
  readonly text: string;
  readonly targetId: string;
  readonly authority: "none";
}

/**
 * The resolved selection. This is the ENTIRE output of picking: an identity,
 * its topology, its markers, and a wall of structural zeros.
 */
export interface PickedSelection {
  readonly schemaVersion: typeof PICKING_SCHEMA_VERSION;
  /** From the CPU table — the row's own index, never renumbered here. */
  readonly pickingIndex: number;
  /** Opaque: `pick_` + 64 hex. Contains no subject name, ever. */
  readonly pickingId: string;
  readonly subjectVisibleId: string;
  /** The scene primitive's kind (entity/relation/route/conflict/refusal/...). */
  readonly primitiveKind: string;
  /** The scene this identity belongs to. Another scene's id dies here. */
  readonly sceneHash: string;
  readonly planHash: string;
  /** Route roles ride along, so forwarder is never read as origin. */
  readonly relations: readonly PickedRelation[];
  readonly relationCount: number;
  /** Every overlay targeting the subject. */
  readonly overlays: readonly PickedOverlay[];
  readonly overlayCount: number;
  /** The subject's OWN mandatory markers (conflict/refusal/partition). */
  readonly mandatoryMarkers: readonly PickedOverlay[];
  readonly mandatoryMarkerCount: number;
  /** The scene-WIDE mandatory inventory — rides along EVERY selection. */
  readonly sceneMandatoryMarkers: readonly PickedOverlay[];
  readonly sceneMandatoryMarkerCount: number;
  /** Structural: a selection has no field that could drop a marker. */
  readonly markersPreserved: true;
  readonly hidesMandatoryMarkers: false;
  /** Structural: identity never left this process's CPU table. */
  readonly uploadedToGpu: false;
  readonly resolvedCpuSide: true;
  /** 29C measured readback all zeros: resolving an index is not a read pixel. */
  readonly pixelOutputVerified: false;
  /** SELECTION != PERMISSION, PICKING != EXECUTION — as literal types. */
  readonly selectionConfersPermission: false;
  readonly isExecution: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

export type PickingResolved = {
  readonly ok: true;
  readonly code: "picking_resolved";
  readonly selection: PickedSelection;
};

export type PickingRefused = {
  readonly ok: false;
  readonly code: "picking_refused";
  readonly refusal: GetigPickingRefusalCode;
  readonly explanation: string;
  /** Fail-closed: a refusal exposes NO partial identity. */
  readonly selection: null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type PickingDecision = PickingResolved | PickingRefused;

export type PickedInspected = {
  readonly ok: true;
  readonly code: "picked_subject_inspected";
  readonly selection: PickedSelection;
  /** 28G's decision, verbatim — success or refusal, both are content. */
  readonly inspection: InspectionDecision;
  /** 28F's decision when a graph was supplied; null when none was. */
  readonly subjectExplanation: ExplainDecision | null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type PickedInspectionRefused = {
  readonly ok: false;
  readonly code: "picking_refused";
  readonly refusal: GetigPickingRefusalCode;
  readonly explanation: string;
  readonly selection: null;
  readonly inspection: null;
  readonly subjectExplanation: null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type PickedInspectionDecision = PickedInspected | PickedInspectionRefused;

// ── structural views of the inputs (read as unknown, validated fail-closed) ──

interface SceneRelationRef {
  readonly relationId: string;
  readonly role: string;
  readonly fromId: string;
  readonly toId: string;
}
interface SceneOverlayRef {
  readonly overlayId: string;
  readonly kind: string;
  readonly text: string;
  readonly targetId: string;
}
interface PlanRowLike {
  readonly pickingIndex: unknown;
  readonly pickingId: unknown;
  readonly subjectVisibleId: unknown;
  readonly relationIds: unknown;
  readonly overlayIds: unknown;
  readonly markerTexts: unknown;
}

type BindingLike = {
  readonly frameId?: unknown;
  readonly observerId?: unknown;
  readonly canonicalVisibleHash?: unknown;
  readonly viewHash?: unknown;
};

// ── helpers ──────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

const isHex64 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);

const isId = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= PICKING_BOUNDS.maxIdChars;

const isMandatoryKind = (kind: unknown): kind is string =>
  typeof kind === "string" && (MANDATORY_OVERLAY_KINDS as readonly string[]).includes(kind);

/** The ONLY way a picking id is ever derived. */
const derivePickingId = (sceneHash: string, subjectVisibleId: string): string =>
  `pick_${canonicalHash({ sceneHash, subjectVisibleId })}`;

const refuseSelection = (
  refusal: GetigPickingRefusalCode,
  detail: string,
): PickingRefused => ({
  ok: false,
  code: "picking_refused",
  refusal,
  explanation: `the picking resolution was refused and no selection was produced: ${detail}`,
  selection: null,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

type ResolveOutcome =
  | { readonly ok: true; readonly input: Record<string, unknown>; readonly selection: PickedSelection }
  | PickingRefused;

// ── the ONE resolution core ──────────────────────────────────────────────────

/**
 * Resolve an opaque picking index/id to a subject, fail-closed throughout.
 *
 * `allowInspectionFields` distinguishes the two public entry points: the bare
 * resolver accepts only resolution fields, while `inspectPickedSubject` also
 * accepts the Phase-28 inspection inputs it will forward.
 */
function resolveSelectionCore(input: unknown, allowInspectionFields: boolean): ResolveOutcome {
  if (!isRecord(input)) {
    return refuseSelection("refused_picking_input_invalid", "the resolver input must be an object");
  }

  // ── 1. request-shaped fields refuse BEFORE anything else ──
  for (const key of Object.keys(input)) {
    if (
      (GETIG_PICKING_ACTION_FIELDS as readonly string[]).includes(key) ||
      (INSPECTION_FORBIDDEN_ACTIONS as readonly string[]).includes(key)
    ) {
      return refuseSelection(
        "refused_picking_action_surface",
        `input field "${key}" names an action this module does not have; SELECTION != PERMISSION and a pick executes nothing`,
      );
    }
    if ((GETIG_PICKING_MARKER_FIELDS as readonly string[]).includes(key)) {
      return refuseSelection(
        "refused_picking_marker_suppression",
        `input field "${key}" asks a selection to hide a mandatory marker; conflict, refusal and partition markers cannot be hidden by picking`,
      );
    }
    if (
      !allowInspectionFields &&
      (GETIG_PICKING_INSPECTION_FIELDS as readonly string[]).includes(key)
    ) {
      return refuseSelection(
        "refused_picking_input_invalid",
        `input field "${key}" belongs to inspectPickedSubject, not to the bare resolver`,
      );
    }
    if (!(GETIG_PICKING_INPUT_FIELDS as readonly string[]).includes(key)) {
      return refuseSelection(
        "refused_picking_input_invalid",
        `input field "${key}" is not in the resolver's vocabulary; unknown fields are refused rather than ignored`,
      );
    }
  }

  // ── 2. scene shape + bounds ──
  const scene = input["scene"];
  if (!isRecord(scene)) {
    return refuseSelection("refused_picking_input_invalid", "scene must be an object");
  }
  if (!isHex64(scene["sceneHash"])) {
    return refuseSelection("refused_picking_input_invalid", "scene.sceneHash must be a 64-hex hash");
  }
  const primitives = scene["primitives"];
  const relations = scene["relations"];
  const overlays = scene["overlays"];
  if (!Array.isArray(primitives) || !Array.isArray(relations) || !Array.isArray(overlays)) {
    return refuseSelection(
      "refused_picking_input_invalid",
      "scene.primitives, scene.relations and scene.overlays must be arrays",
    );
  }
  if (primitives.length > PICKING_BOUNDS.maxScenePrimitives) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${primitives.length} scene primitives exceeds the bound of ${PICKING_BOUNDS.maxScenePrimitives}`,
    );
  }
  if (relations.length > PICKING_BOUNDS.maxSceneRelations) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${relations.length} scene relations exceeds the bound of ${PICKING_BOUNDS.maxSceneRelations}`,
    );
  }
  if (overlays.length > PICKING_BOUNDS.maxSceneOverlays) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${overlays.length} scene overlays exceeds the bound of ${PICKING_BOUNDS.maxSceneOverlays}`,
    );
  }

  // ── 3. plan shape + bounds ──
  const plan = input["plan"];
  if (!isRecord(plan)) {
    return refuseSelection("refused_picking_input_invalid", "plan must be an object");
  }
  if (!isHex64(plan["sceneHash"])) {
    return refuseSelection("refused_picking_input_invalid", "plan.sceneHash must be a 64-hex hash");
  }
  if (!isId(plan["planHash"])) {
    return refuseSelection("refused_picking_input_invalid", "plan.planHash must be a non-empty string");
  }
  const table = plan["pickingResolutions"];
  if (!Array.isArray(table)) {
    return refuseSelection("refused_picking_input_invalid", "plan.pickingResolutions must be an array");
  }
  if (table.length > PICKING_BOUNDS.maxResolutions) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${table.length} picking resolutions exceeds the bound of ${PICKING_BOUNDS.maxResolutions}`,
    );
  }

  // ── 4. staleness: a picking id is an identity claim about ONE scene ──
  if (plan["sceneHash"] !== scene["sceneHash"]) {
    return refuseSelection(
      "refused_picking_stale_scene",
      "the picking table was built for a different scene than the one supplied; a picking id is stale after the scene changes and no lookup is attempted",
    );
  }
  const currentSceneHash = input["currentSceneHash"];
  if (currentSceneHash !== undefined) {
    if (typeof currentSceneHash !== "string") {
      return refuseSelection(
        "refused_picking_input_invalid",
        "currentSceneHash must be a string when supplied",
      );
    }
    if (currentSceneHash !== scene["sceneHash"]) {
      return refuseSelection(
        "refused_picking_stale_scene",
        "the caller's currentSceneHash does not match the supplied scene; the scene changed after this picking id was issued",
      );
    }
  }

  // ── 5. the target row ──
  const hasIndex = input["pickingIndex"] !== undefined;
  const hasId = input["pickingId"] !== undefined;
  if (!hasIndex && !hasId) {
    return refuseSelection(
      "refused_picking_input_invalid",
      "a pickingIndex or a pickingId is required to resolve a selection",
    );
  }

  let rowIndex = -1;
  if (hasIndex) {
    const index = input["pickingIndex"];
    if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= table.length) {
      return refuseSelection(
        "refused_picking_index_invalid",
        `pickingIndex must be an integer in [0, ${table.length - 1}]; an unusable index produces no fallback identity`,
      );
    }
    rowIndex = index;
  }
  if (hasId) {
    const pickingId = input["pickingId"];
    if (typeof pickingId !== "string") {
      return refuseSelection("refused_picking_input_invalid", "pickingId must be a string");
    }
    const found = table.findIndex((r) => isRecord(r) && r["pickingId"] === pickingId);
    if (found === -1) {
      return refuseSelection(
        "refused_picking_unknown_id",
        "the picking id is not in this scene's resolution table — it was issued for another scene, or it is not a picking id at all",
      );
    }
    if (hasIndex && found !== rowIndex) {
      return refuseSelection(
        "refused_picking_subject_substitution",
        "the supplied pickingIndex and pickingId resolve to different rows; the two claims disagree and neither is trusted",
      );
    }
    if (!hasIndex) rowIndex = found;
  }

  const row: PlanRowLike | null = isRecord(table[rowIndex]) ? (table[rowIndex] as PlanRowLike) : null;
  if (
    row === null ||
    typeof row.pickingIndex !== "number" ||
    !isId(row.pickingId) ||
    !isId(row.subjectVisibleId) ||
    !Array.isArray(row.relationIds) ||
    !Array.isArray(row.overlayIds) ||
    !Array.isArray(row.markerTexts)
  ) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the resolution table row is malformed; the plan cannot be trusted for this index",
    );
  }
  const subjectVisibleId = row.subjectVisibleId as string;

  // ── 6. table integrity: the row must re-derive, or it is not this scene's ──
  if (row.pickingIndex !== rowIndex) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the resolution table row's own pickingIndex disagrees with its position; the table is not internally consistent",
    );
  }
  if (row.pickingId !== derivePickingId(scene["sceneHash"] as string, subjectVisibleId)) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the resolution table row does not re-derive from sceneHash and subjectVisibleId; refusing a tampered identity mapping",
    );
  }

  // ── 7. the caller's claim is verified, never trusted ──
  const claim = input["claimedSubjectVisibleId"];
  if (claim !== undefined && claim !== subjectVisibleId) {
    return refuseSelection(
      "refused_picking_subject_substitution",
      "the caller's claimedSubjectVisibleId disagrees with the resolved row; a claim never overrides the table, and the refusal does not reveal the true subject",
    );
  }

  // ── 8. the subject must exist in the SUPPLIED scene ──
  let primitiveKind: string | null = null;
  for (const p of primitives) {
    if (!isRecord(p) || !isId(p["primitiveId"]) || typeof p["kind"] !== "string") {
      return refuseSelection(
        "refused_picking_input_invalid",
        "scene.primitives contains a malformed primitive",
      );
    }
    if (p["primitiveId"] === subjectVisibleId) {
      primitiveKind = p["kind"] as string;
    }
  }
  if (primitiveKind === null) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the resolution table names a subject that is not a primitive of the supplied scene; the plan and the scene disagree",
    );
  }

  // ── 9. topology: scene is the source of truth, plan row must byte-match ──
  const sceneRelations: SceneRelationRef[] = [];
  for (const r of relations) {
    if (
      !isRecord(r) ||
      !isId(r["relationId"]) ||
      typeof r["role"] !== "string" ||
      !isId(r["fromId"]) ||
      !isId(r["toId"])
    ) {
      return refuseSelection(
        "refused_picking_input_invalid",
        "scene.relations contains a malformed relation",
      );
    }
    if (r["fromId"] === subjectVisibleId || r["toId"] === subjectVisibleId) {
      sceneRelations.push({
        relationId: r["relationId"],
        role: r["role"],
        fromId: r["fromId"],
        toId: r["toId"],
      });
    }
  }
  if (sceneRelations.length > PICKING_BOUNDS.maxRelationsPerSubject) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${sceneRelations.length} relations on the subject exceeds the bound of ${PICKING_BOUNDS.maxRelationsPerSubject}`,
    );
  }
  const planRelationIds = (row.relationIds as unknown[]).map((v) => String(v)).sort();
  const sceneRelationIds = sceneRelations.map((r) => r.relationId).sort();
  if (JSON.stringify(planRelationIds) !== JSON.stringify(sceneRelationIds)) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the plan row's relationIds do not match the scene's relation SET for this subject; the plan does not describe the scene it claims",
    );
  }

  const sceneOverlays: SceneOverlayRef[] = [];
  for (const o of overlays) {
    if (
      !isRecord(o) ||
      !isId(o["overlayId"]) ||
      typeof o["kind"] !== "string" ||
      typeof o["text"] !== "string" ||
      !isId(o["targetId"])
    ) {
      return refuseSelection(
        "refused_picking_input_invalid",
        "scene.overlays contains a malformed overlay",
      );
    }
    if (o["targetId"] === subjectVisibleId) {
      sceneOverlays.push({
        overlayId: o["overlayId"],
        kind: o["kind"],
        text: o["text"],
        targetId: o["targetId"],
      });
    }
  }
  if (sceneOverlays.length > PICKING_BOUNDS.maxOverlaysPerSubject) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${sceneOverlays.length} overlays on the subject exceeds the bound of ${PICKING_BOUNDS.maxOverlaysPerSubject}`,
    );
  }
  const planOverlayIds = (row.overlayIds as unknown[]).map((v) => String(v)).sort();
  const sceneOverlayIds = sceneOverlays.map((o) => o.overlayId).sort();
  const planMarkerTexts = (row.markerTexts as unknown[]).map((v) => String(v)).sort();
  const sceneMarkerTexts = sceneOverlays.map((o) => o.text).sort();
  if (
    JSON.stringify(planOverlayIds) !== JSON.stringify(sceneOverlayIds) ||
    JSON.stringify(planMarkerTexts) !== JSON.stringify(sceneMarkerTexts)
  ) {
    return refuseSelection(
      "refused_picking_plan_invalid",
      "the plan row's overlayIds/markerTexts do not match the scene's overlay SET for this subject; the plan does not describe the scene it claims",
    );
  }

  // ── 10. mandatory markers: the subject's, AND the scene-wide inventory ──
  const sceneMandatory: SceneOverlayRef[] = [];
  for (const o of overlays) {
    const ov = o as Record<string, unknown>;
    if (isMandatoryKind(ov["kind"])) {
      sceneMandatory.push({
        overlayId: String(ov["overlayId"]),
        kind: String(ov["kind"]),
        text: String(ov["text"]),
        targetId: String(ov["targetId"]),
      });
    }
  }
  if (sceneMandatory.length > PICKING_BOUNDS.maxSceneMandatoryMarkers) {
    return refuseSelection(
      "refused_picking_bound_exceeded",
      `${sceneMandatory.length} mandatory markers exceeds the bound of ${PICKING_BOUNDS.maxSceneMandatoryMarkers}`,
    );
  }
  const subjectMandatory = sceneOverlays.filter((o) => isMandatoryKind(o.kind));

  const toOverlay = (o: SceneOverlayRef): PickedOverlay =>
    Object.freeze({
      overlayId: o.overlayId,
      kind: o.kind,
      text: o.text,
      targetId: o.targetId,
      authority: "none" as const,
    });

  const selection: PickedSelection = Object.freeze({
    schemaVersion: PICKING_SCHEMA_VERSION,
    pickingIndex: row.pickingIndex as number,
    pickingId: row.pickingId as string,
    subjectVisibleId,
    primitiveKind,
    sceneHash: scene["sceneHash"] as string,
    planHash: plan["planHash"] as string,
    relations: Object.freeze(
      sceneRelations.map((r) =>
        Object.freeze({
          relationId: String(r.relationId),
          role: String(r.role),
          fromId: String(r.fromId),
          toId: String(r.toId),
          authorizes: false as const,
          trust: "none" as const,
        }),
      ),
    ),
    relationCount: sceneRelations.length,
    overlays: Object.freeze(sceneOverlays.map(toOverlay)),
    overlayCount: sceneOverlays.length,
    mandatoryMarkers: Object.freeze(subjectMandatory.map(toOverlay)),
    mandatoryMarkerCount: subjectMandatory.length,
    // The scene-wide inventory rides along every selection: picking one subject
    // cannot make the conflicts/refusals/partitions around it vanish.
    sceneMandatoryMarkers: Object.freeze(sceneMandatory.map(toOverlay)),
    sceneMandatoryMarkerCount: sceneMandatory.length,
    markersPreserved: true as const,
    hidesMandatoryMarkers: false as const,
    uploadedToGpu: false as const,
    resolvedCpuSide: true as const,
    pixelOutputVerified: false as const,
    selectionConfersPermission: false as const,
    isExecution: false as const,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  });

  return { ok: true, input, selection };
}

// ── the public surface: exactly three functions ──────────────────────────────

/**
 * Resolve an opaque picking index (or pickingId) to a visible subject.
 *
 * Fail-closed: any refusal returns `selection: null` and names its code. The
 * caller's `claimedSubjectVisibleId` and `currentSceneHash` are VERIFIED
 * against the table and the scene, never trusted.
 */
export function resolvePickingSelection(input: unknown): PickingDecision {
  const outcome = resolveSelectionCore(input, false);
  if (!outcome.ok) return outcome;
  return { ok: true, code: "picking_resolved", selection: outcome.selection };
}

/**
 * Resolve, then hand the subject to Phase-28's OWN read-only surfaces.
 *
 * The 28G query is constructed here — `kind: "select"`, `operation: "select"`,
 * the RESOLVED subject — so the caller cannot supply a different operation,
 * and the only operation used is one of 28G's closed allowed list. 28G's and
 * 28F's decisions come back intact: a refusal from either is content, not a
 * failure of this module, and it is never softened. When no graph is supplied,
 * `subjectExplanation` is honestly null rather than invented.
 */
export function inspectPickedSubject(input: unknown): PickedInspectionDecision {
  const outcome = resolveSelectionCore(input, true);
  if (!outcome.ok) {
    return {
      ok: false,
      code: "picking_refused",
      refusal: outcome.refusal,
      explanation: outcome.explanation,
      selection: null,
      inspection: null,
      subjectExplanation: null,
      authority: "none",
      controlPlane: false,
      readOnly: true,
      executionAuthorized: false,
    };
  }
  const src = outcome.input;

  const inspection = inspect({
    query: {
      kind: "select",
      operation: "select",
      // focusScope "subject" is what makes 28G's select NARROW to this
      // subject (its closed vocabulary; without it a select describes the
      // whole view and the selection names the view's first subject instead).
      // The picked identity must be the identity inspected — that is the
      // binding this gate exists to guarantee.
      focusScope: "subject",
      subjectVisibleId: outcome.selection.subjectVisibleId,
    },
    view: src["view"],
    sequence: src["sequence"],
    graph: src["graph"],
    binding: src["binding"] as BindingLike | undefined,
  });

  const subjectExplanation =
    src["graph"] !== undefined
      ? explainGetigSubject(src["graph"], outcome.selection.subjectVisibleId)
      : null;

  return {
    ok: true,
    code: "picked_subject_inspected",
    selection: outcome.selection,
    inspection,
    subjectExplanation,
    authority: "none",
    controlPlane: false,
    readOnly: true,
    executionAuthorized: false,
  };
}

/**
 * Executing a selection NEVER happens.
 *
 * The third and last export, and it cannot succeed under any input: a picked
 * subject may be LOOKED AT (28G) and EXPLAINED (28F), and that is the whole
 * of what picking confers. The guard exists so "PICKING != EXECUTION" and
 * "SELECTION != PERMISSION" have exit codes a suite can drive, rather than
 * being merely the absence of a function someone might later add.
 */
export function refusePickedSelectionExecution(subjectVisibleId: string): {
  readonly ok: false;
  readonly code: "execution_refused";
  readonly refusal: "refused_picking_execution_not_permitted";
  readonly explanation: string;
  readonly lookedAtSubjectVisibleId: string;
  readonly executed: false;
  readonly permissionGranted: false;
  readonly authority: "none";
} {
  return {
    ok: false,
    code: "execution_refused",
    refusal: "refused_picking_execution_not_permitted",
    explanation:
      "a resolved selection is an IDENTITY for something on screen; acting on it is not a power this module has. PICKING != EXECUTION and SELECTION != PERMISSION: the subject may be inspected (28G) and explained (28F), and nothing else.",
    lookedAtSubjectVisibleId: typeof subjectVisibleId === "string" ? subjectVisibleId : "",
    executed: false,
    permissionGranted: false,
    authority: "none",
  };
}
