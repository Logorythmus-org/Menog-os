/**
 * PHASE 29B — GETIG SCENE GRAPH COMPILER
 * (CPU-SIDE / DETERMINISTIC / AUTHORITY-FREE)
 *
 * CENTRAL LAWS:
 *   GETIG_FRAME  -> SCENE_GRAPH           is a MATERIALISATION, never a REDEFINITION
 *   LAYOUT_CHANGE != RUNTIME_CHANGE
 *   SEMANTICS != PRESENTATION
 *
 * ── WHY A COMPILER AND NOT A RENDERER ───────────────────────────────────────
 *
 * This module turns a Phase-28 semantic mapping into a scene graph. It runs on
 * the CPU, allocates no GPU resource, names no shader, and issues no draw call.
 * Everything later in Phase 29 draws; this decides WHAT EXISTS TO BE DRAWN.
 *
 * ── WHY THE SEMANTIC ORDERING IS IMPORTED, NOT REIMPLEMENTED ───────────────
 *
 * Each axis in Phase 28 is ordered from weakest claim to strongest, and a
 * presentation may never exceed a value's rank. That ordering is 28D's, and it
 * is the thing this gate is required to obey. So `getigVisualSemanticRank` and
 * `getigVisualPermittedTiers` are IMPORTED from `getigVisualMapping` rather than
 * re-derived here.
 *
 * Re-deriving it would have been shorter and would have been a second source of
 * truth for the strongest property in the chain: a layout rule that disagreed
 * with 28D by one position would silently let a renderer overstate a claim,
 * which is law 16 (a renderer may weaken disclosure but never strengthen a
 * claim) failing silently.
 *
 * ── WHY LAYOUT IS DERIVED FROM SORTED IDENTIFIERS ───────────────────────────
 *
 * Layout is a pure function of the SORTED SET of subject identifiers. Input
 * order is therefore irrelevant: two mappings that differ only in the order of
 * their `tokens` array compile to a byte-identical scene. That is the "identical
 * semantic input -> stable deterministic layout" requirement, and it is also what
 * makes a layout reproducible by a third party who never saw the original array.
 *
 * ── WHY sceneHash AND layoutHash ARE SEPARATE ───────────────────────────────
 *
 * `sceneHash` is computed over SEMANTIC content only: identifiers, axes,
 * values, ranks, roles. It contains no coordinate.
 *
 * `layoutHash` is computed over COORDINATES only. It contains no semantic.
 *
 * The separation is what makes LAYOUT_CHANGE != RUNTIME_CHANGE checkable rather
 * than aspirational: re-laying-out a scene changes `layoutHash` and leaves
 * `sceneHash` byte-identical, and changing a semantic value changes `sceneHash`
 * and leaves `layoutHash` byte-identical. Both directions are asserted by the
 * suite, because a single combined hash would make the law untestable.
 *
 * ── WHY CONFLICTS, REFUSALS AND PARTITIONS BECOME OVERLAYS ──────────────────
 *
 * Phase-28 law 17 requires mandatory conflict/refusal/partition state to remain
 * VISIBLE. Phase-28 rank ceilings require a rank-0 value to be drawn only at the
 * `withheld` tier. These look contradictory and are not.
 *
 * They are reconciled by CHANNEL rather than by promotion:
 *
 *   · A rank-0 token may NOT be promoted into a ScenePrimitive, because that
 *     would assert its semantic VALUE visually and break the ceiling.
 *   · It IS emitted as a SceneOverlay — an explanatory surface carrying
 *     `authority: "none"` — which makes the marker's PRESENCE and IDENTITY
 *     visible while its VALUE stays withheld.
 *
 * So nothing is hidden and nothing is overstated. A renderer that draws only
 * primitives would show a scene with no conflicts in it, which is exactly the
 * "correct runtime with a misleading picture" failure the pack calls a security
 * failure — so overlays are part of the compiled output, not an optional extra.
 *
 * A token from these collections that produced NO marker is a REFUSAL, never a
 * silent drop (law 17, law 28).
 *
 * ── WHY COLOUR IS NEVER ASSIGNED HERE ──────────────────────────────────────
 *
 * Law 15: COLOR != CANONICAL SEMANTICS. The strongest way to satisfy it is to
 * assign no colour at all: every compiled primitive carries `colorHint: "none"`.
 * There is therefore no code path by which a colour could become the only
 * remaining carrier of a meaning, and no future edit can introduce one without
 * visibly adding colour assignment to this file.
 *
 * ── WHY NOTHING IS INFERRED ─────────────────────────────────────────────────
 *
 * The compiler copies `authority: "none"`, `authorizes: false` and `trust:
 * "none"` onto everything it emits and derives them from nothing. No input
 * field can raise them: a mapping token carrying a claim-shaped field is
 * REFUSED rather than sanitised, because silently dropping a claim is the
 * denylist mistake `28J-OBS-5` records.
 */

import { canonicalHash } from "./canonical.js";
import {
  GETIG_VISUAL_AXES,
  getigVisualPermittedTiers,
  getigVisualSemanticRank,
  type GetigVisualAxis,
} from "./getigVisualMapping.js";
import {
  RENDERER_BOUNDS,
  buildGetigScene,
  buildScenePrimitive,
  buildSceneRelation,
  buildSceneOverlay,
  type GetigScene,
  type RendererDecision,
  type SceneOverlay,
  type ScenePrimitive,
  type SceneRelation,
} from "./rendererTrustContract.js";

// ── closed vocabularies ───────────────────────────────────────────────────────

/**
 * Collections whose tokens MUST produce a visible marker.
 *
 * This list is the mechanism behind "conflicts/refusals/partitions are never
 * silently dropped". A token from one of these collections that emits no marker
 * is a refusal.
 */
export const MANDATORY_MARKER_COLLECTIONS = Object.freeze([
  "conflicts",
  "refusals",
  "partitions",
] as const);
export type MandatoryMarkerCollection = (typeof MANDATORY_MARKER_COLLECTIONS)[number];

/**
 * Route roles in their REQUIRED ORDER: origin before forwarder before observer.
 *
 * The order is preserved in the compiled output regardless of the order the
 * tokens arrived in, so a viewer cannot be shown a forwarder before its origin
 * and be invited to read the forwarder as the source.
 */
export const ROUTE_ROLE_ORDER = Object.freeze(["origin", "forwarder", "destination"] as const) as readonly string[];

/** Explicit bounds. Overflow REFUSES; it never truncates (law 28). */
export const SCENE_COMPILER_BOUNDS = Object.freeze({
  maxTokens: 8192,
  maxSubjects: RENDERER_BOUNDS.maxPrimitives,
  maxMarkers: RENDERER_BOUNDS.maxOverlays,
  maxLabelLength: RENDERER_BOUNDS.maxLabelLength,
  maxPickingIds: RENDERER_BOUNDS.maxPickings,
  maxColumns: 64,
});

export const SCENE_COMPILER_REFUSAL_CODES = Object.freeze([
  "refused_scene_input_invalid",
  "refused_scene_mapping_schema",
  "refused_scene_token_invalid",
  "refused_scene_token_unknown_axis",
  "refused_scene_binding_missing",
  "refused_scene_rank_ceiling_exceeded",
  "refused_scene_mandatory_marker_dropped",
  "refused_scene_authority_claim",
  "refused_scene_budget_exceeded",
  // 29R1 (29D-OBS-2): a relation endpoint must bind to exactly one drawable
  // route root. Zero candidates and two-or-more candidates are DIFFERENT
  // failures and are refused under different codes so an auditor can tell an
  // unanchorable endpoint from a colliding one without parsing prose.
  "refused_scene_route_anchor_unresolved",
  "refused_scene_route_anchor_ambiguous",
] as const);
export type SceneCompilerRefusalCode = (typeof SCENE_COMPILER_REFUSAL_CODES)[number];

export const SCENE_COMPILER_SCHEMA_VERSION = "menog-getig-scene-compiler/v0" as const;

/** Claim-shaped field names. Their presence is a REFUSAL, never a strip. */
const CLAIM_FIELDS = Object.freeze([
  "grant",
  "granted",
  "authorized",
  "authorization",
  "admitted",
  "admissionGranted",
  "trusted",
  "approved",
  "permitted",
  "execute",
  "action",
  "permission",
] as const);

// ── the input token, as it arrives from 28D ──────────────────────────────────

interface MappingToken {
  readonly tokenId: string;
  readonly axis: GetigVisualAxis;
  readonly semanticValue: string;
  readonly semanticRank: number;
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  readonly claim: "descriptive_only";
  readonly authority: "none";
  readonly executable: false;
}

// ── outcomes ──────────────────────────────────────────────────────────────────

export type SceneCompilerRefused = {
  readonly ok: false;
  readonly code: "scene_refused";
  readonly refusal: SceneCompilerRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  readonly scene: null;
  readonly layoutHash: null;
  readonly pickingIds: null;
  readonly partialSceneEmitted: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type CompiledScene = {
  readonly ok: true;
  readonly code: "scene_compiled";
  readonly scene: GetigScene;
  /** Hash over SEMANTIC content only. Contains no coordinate. */
  readonly sceneHash: string;
  /** Hash over COORDINATES only. Contains no semantic. */
  readonly layoutHash: string;
  /** The Phase-28 mapping this scene was compiled from. */
  readonly sourceMappingHash: string;
  readonly pickingIds: readonly { readonly pickingId: string; readonly subjectVisibleId: string }[];
  /** Every mandatory marker that was emitted, for audit. */
  readonly mandatoryMarkers: readonly string[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type SceneCompilerDecision = CompiledScene | SceneCompilerRefused;

// ── helpers ───────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (refusal: SceneCompilerRefusalCode, explanation: string, offendingField: string | null = null): SceneCompilerRefused => ({
  ok: false,
  code: "scene_refused",
  refusal,
  explanation,
  offendingField,
  scene: null,
  layoutHash: null,
  pickingIds: null,
  partialSceneEmitted: false,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const AXES = new Set<string>(GETIG_VISUAL_AXES);
const MARKERS = new Set<string>(MANDATORY_MARKER_COLLECTIONS);
const HASH_SHAPE = /^[a-f0-9]{16,128}$/;
const isHash = (v: unknown): v is string => typeof v === "string" && HASH_SHAPE.test(v);

// ── the compiler ──────────────────────────────────────────────────────────────

export interface CompileGetigSceneInput {
  /** A Phase-28 (28D) visual mapping. Read, never mutated. */
  readonly mapping: unknown;
  readonly runtimeStateHash: string;
  /**
   * Optional presentation tier per token id.
   *
   * A caller may ask for a WEAKER presentation, never a stronger one. Anything
   * exceeding 28D's ceiling for that token is refused rather than clamped —
   * clamping would hide the violation the caller just committed.
   */
  readonly requestedTiers?: Readonly<Record<string, string>>;
}

/**
 * Compile a Phase-28 mapping into an authority-free scene graph.
 *
 * Deterministic: identical semantic input always yields an identical
 * `sceneHash` AND an identical `layoutHash`, whatever order the tokens arrived
 * in.
 */
export function compileGetigScene(input: CompileGetigSceneInput): SceneCompilerDecision {
  if (!isRecord(input)) {
    return refuse("refused_scene_input_invalid", "compiler input must be an object");
  }
  const { mapping, runtimeStateHash, requestedTiers } = input;

  if (!isRecord(mapping)) {
    return refuse("refused_scene_mapping_schema", "mapping must be an object");
  }
  if (mapping.schemaVersion !== "menog-getig-visual/v0") {
    return refuse("refused_scene_mapping_schema", `unsupported mapping schema: ${String(mapping.schemaVersion)}`, "schemaVersion");
  }
  if (typeof mapping.frameId !== "string" || mapping.frameId.length === 0) {
    return refuse("refused_scene_binding_missing", "mapping.frameId is required", "frameId");
  }
  if (typeof mapping.observerId !== "string" || mapping.observerId.length === 0) {
    return refuse("refused_scene_binding_missing", "mapping.observerId is required", "observerId");
  }
  if (!isHash(mapping.mappingHash)) {
    return refuse("refused_scene_binding_missing", "mapping.mappingHash must be a hex hash", "mappingHash");
  }
  if (!isHash(runtimeStateHash)) {
    return refuse("refused_scene_binding_missing", "runtimeStateHash must be a hex hash", "runtimeStateHash");
  }
  if (!Array.isArray(mapping.tokens)) {
    return refuse("refused_scene_mapping_schema", "mapping.tokens must be an array", "tokens");
  }
  if (mapping.tokens.length > SCENE_COMPILER_BOUNDS.maxTokens) {
    return refuse("refused_scene_budget_exceeded", "token count exceeds maxTokens", "tokens");
  }

  // ── validate every token BEFORE emitting anything ─────────────────────────
  const tokens: MappingToken[] = [];
  for (const raw of mapping.tokens) {
    if (!isRecord(raw)) {
      return refuse("refused_scene_token_invalid", "each token must be an object");
    }
    // A claim-shaped field is refused outright. Stripping it would produce a
    // record that looks sanitised while the caller still believes the claim was
    // carried — the 28J-OBS-5 denylist mistake in a new place.
    for (const key of Object.keys(raw)) {
      if ((CLAIM_FIELDS as readonly string[]).includes(key)) {
        return refuse("refused_scene_authority_claim", `mapping token carries a claim field: ${key}`, key);
      }
    }
    const axis = raw.axis;
    if (typeof axis !== "string" || !AXES.has(axis)) {
      return refuse("refused_scene_token_unknown_axis", `unknown visual axis: ${String(axis)}`, "axis");
    }
    if (typeof raw.tokenId !== "string" || raw.tokenId.length === 0) {
      return refuse("refused_scene_token_invalid", "token.tokenId is required", "tokenId");
    }
    if (typeof raw.subjectVisibleId !== "string" || raw.subjectVisibleId.length === 0) {
      return refuse("refused_scene_token_invalid", "token.subjectVisibleId is required", "subjectVisibleId");
    }
    if (typeof raw.subjectCollection !== "string" || raw.subjectCollection.length === 0) {
      return refuse("refused_scene_token_invalid", "token.subjectCollection is required", "subjectCollection");
    }
    if (typeof raw.semanticValue !== "string") {
      return refuse("refused_scene_token_invalid", "token.semanticValue must be a string", "semanticValue");
    }
    if (raw.claim !== "descriptive_only") {
      return refuse("refused_scene_authority_claim", "token.claim must be descriptive_only", "claim");
    }
    if (raw.authority !== "none" || raw.executable !== false) {
      return refuse("refused_scene_authority_claim", "token must carry authority 'none' and executable false", "authority");
    }
    if (raw.mutation !== undefined && raw.mutation !== "none") {
      return refuse("refused_scene_authority_claim", "token.mutation must be 'none'", "mutation");
    }
    // The rank MUST agree with 28D's own ordering. A token claiming a rank it
    // does not hold would let a caller buy a higher presentation ceiling.
    const actualRank = getigVisualSemanticRank(axis as GetigVisualAxis, raw.semanticValue);
    if (actualRank < 0) {
      return refuse("refused_scene_token_unknown_axis", `axis ${axis} has no value ${String(raw.semanticValue)}`, "semanticValue");
    }
    if (actualRank !== raw.semanticRank) {
      return refuse(
        "refused_scene_token_invalid",
        `token ${String(raw.tokenId)} claims rank ${String(raw.semanticRank)} but Phase-28 ranks it ${actualRank}`,
        "semanticRank",
      );
    }
    // Rank ceiling: a requested tier may never exceed 28D's permitted tiers.
    const permitted = getigVisualPermittedTiers(actualRank);
    const requested = requestedTiers === undefined ? undefined : requestedTiers[raw.tokenId];
    if (requested !== undefined) {
      if (!permitted.includes(requested as never)) {
        return refuse(
          "refused_scene_rank_ceiling_exceeded",
          `token ${String(raw.tokenId)} may be presented at [${permitted.join(", ")}] but '${String(requested)}' was requested`,
          "requestedTiers",
        );
      }
    }
    tokens.push({
      tokenId: raw.tokenId,
      axis: axis as GetigVisualAxis,
      semanticValue: raw.semanticValue,
      semanticRank: actualRank,
      subjectVisibleId: raw.subjectVisibleId,
      subjectCollection: raw.subjectCollection,
      claim: "descriptive_only",
      authority: "none",
      executable: false,
    });
  }

  // ── group by subject, in SORTED order so input order cannot matter ───────
  const bySubject = new Map<string, MappingToken[]>();
  for (const t of tokens) {
    const list = bySubject.get(t.subjectVisibleId);
    if (list === undefined) bySubject.set(t.subjectVisibleId, [t]);
    else list.push(t);
  }
  const subjectIds = [...bySubject.keys()].sort();
  if (subjectIds.length > SCENE_COMPILER_BOUNDS.maxSubjects) {
    return refuse("refused_scene_budget_exceeded", "subject count exceeds maxSubjects", "tokens");
  }

  // ── layout: a pure function of the SORTED subject list ───────────────────
  // No coordinate depends on input order, token order, or any clock. Two
  // mappings differing only in array order therefore produce identical layout.
  const layout = new Map<string, readonly [number, number, number]>();
  subjectIds.forEach((id, i) => {
    const col = i % SCENE_COMPILER_BOUNDS.maxColumns;
    const row = Math.floor(i / SCENE_COMPILER_BOUNDS.maxColumns);
    layout.set(id, [col, row, 0] as const);
  });

  const canonicalVisibleHash = canonicalHash(
    subjectIds.map((id) => ({ subjectVisibleId: id, axes: (bySubject.get(id) ?? []).map((t) => `${t.axis}=${t.semanticValue}`).sort() })),
  );

  // ── emit primitives (one per subject, bound to its principal token) ──────
  const primitives: ScenePrimitive[] = [];
  const semanticEntries: { subjectVisibleId: string; principalTokenId: string; axes: string[] }[] = [];

  for (const id of subjectIds) {
    const group = bySubject.get(id) ?? [];
    // The principal token is the one whose axis/value string sorts first, so
    // the choice cannot depend on array order either.
    const principal = [...group].sort((a, b) => `${a.axis}=${a.semanticValue}`.localeCompare(`${b.axis}=${b.semanticValue}`))[0];
    if (principal === undefined) {
      return refuse("refused_scene_token_invalid", `subject ${id} has no token`);
    }
    const collection = principal.subjectCollection;
    const kind = COLLECTION_TO_PRIMITIVE_KIND[collection] ?? "unknown";
    const pos = layout.get(id) ?? [0, 0, 0];

    const built = buildScenePrimitive({
      kind,
      primitiveId: id,
      label: id.length > SCENE_COMPILER_BOUNDS.maxLabelLength ? id.slice(0, SCENE_COMPILER_BOUNDS.maxLabelLength) : id,
      // Law 15: no colour is assigned by this compiler, ever. There is no code
      // path by which a colour could become the only carrier of a meaning.
      colorHint: "none",
      sizeHint: 1,
      zOrder: principal.semanticRank,
      position: [pos[0], pos[1], pos[2]],
    });
    if (!built.ok) {
      return refuse("refused_scene_token_invalid", `primitive for ${id} refused: ${built.refusal}`);
    }
    primitives.push(built.value);
    semanticEntries.push({
      subjectVisibleId: id,
      principalTokenId: principal.tokenId,
      axes: group.map((t) => `${t.axis}=${t.semanticValue}`).sort(),
    });
  }

  // ── emit relations, preserving REQUIRED ROUTE ROLE ORDER ─────────────────
  const routeRoleSubjects = new Map<string, MappingToken>();
  for (const t of tokens) {
    if (t.axis !== "route_role") continue;
    // Deterministic when a subject carries more than one role token: the
    // lowest-ordered role wins, so origin is never displaced by forwarder.
    const current = routeRoleSubjects.get(t.subjectVisibleId);
    if (current === undefined) {
      routeRoleSubjects.set(t.subjectVisibleId, t);
      continue;
    }
    const a = ROUTE_ROLE_ORDER.indexOf(current.semanticValue);
    const b = ROUTE_ROLE_ORDER.indexOf(t.semanticValue);
    if (b >= 0 && (a < 0 || b < a)) routeRoleSubjects.set(t.subjectVisibleId, t);
  }

  const orderedRoleEntries = [...routeRoleSubjects.entries()].sort((x, y) => {
    const rx = ROUTE_ROLE_ORDER.indexOf(x[1].semanticValue);
    const ry = ROUTE_ROLE_ORDER.indexOf(y[1].semanticValue);
    if (rx !== ry) return rx - ry;
    return x[0].localeCompare(y[0]);
  });

  // ── 29R1 (29D-OBS-2): relation endpoints BIND to drawable primitives ──────
  // The old emitter wrote `fromId: route:<role>` — a synthetic anchor naming
  // no primitive, so every relation entering the GPU plan carried the
  // no-anchor sentinel and could not be drawn faithfully. Endpoints are now
  // derived from Phase-28's OWN route structure instead of invented:
  //
  //   · a route root is a subject that carries a `route_state` token;
  //   · a role subject `${routeId}#${role}` must bind to EXACTLY ONE route
  //     root. Candidates are COUNTED, never guessed: zero refuses as
  //     unresolved, two or more refuse as ambiguous — a colliding anchor is
  //     a refusal, never silently resolved by prefix length or input order;
  //   · within a route the chain runs origin -> forwarder -> destination by
  //     ROUTE_ROLE_ORDER, so each relation's fromId is the PREVIOUS drawable
  //     subject in that chain and the first relation anchors at the route root.
  //
  // Role identity stays in `role`; endpoints are plain subject ids. Every
  // endpoint names a primitive that exists or the compile FAILS CLOSED:
  // nothing is mapped to 0, no relation is dropped, and no trust, admission
  // or authorization is invented by the binding.
  const routeRootIds = new Set<string>();
  for (const [subjectId, list] of bySubject) {
    if (list.some((t) => t.axis === "route_state")) routeRootIds.add(subjectId);
  }

  const chainByAnchor = new Map<string, string[]>();
  for (const [id] of orderedRoleEntries) {
    const matches = [...routeRootIds].filter((root) => id.startsWith(`${root}#`)).sort();
    if (matches.length === 0) {
      return refuse(
        "refused_scene_route_anchor_unresolved",
        `relation endpoint ${id} names no route root that is a drawable primitive`,
        "subjectVisibleId",
      );
    }
    if (matches.length > 1) {
      return refuse(
        "refused_scene_route_anchor_ambiguous",
        `relation endpoint ${id} is claimed by more than one route root: ${matches.join(", ")}`,
        "subjectVisibleId",
      );
    }
    const anchor = matches[0] as string;
    const chain = chainByAnchor.get(anchor);
    if (chain === undefined) chainByAnchor.set(anchor, [id]);
    else chain.push(id);
  }

  // Input-order invariant: orderedRoleEntries is already sorted by role order
  // then subject id, so every chain — and therefore every fromId — is a pure
  // function of the mapping, whatever order the tokens arrived in.
  const fromIdBySubject = new Map<string, string>();
  for (const [anchor, chain] of chainByAnchor) {
    let previous = anchor;
    for (const member of chain) {
      fromIdBySubject.set(member, previous);
      previous = member;
    }
  }

  const relations: SceneRelation[] = [];
  for (const [id, token] of orderedRoleEntries) {
    const built = buildSceneRelation({
      kind: "forwards_to",
      relationId: id,
      fromId: fromIdBySubject.get(id) as string,
      toId: id,
      role: token.semanticValue,
    });
    if (!built.ok) {
      return refuse("refused_scene_token_invalid", `relation for ${id} refused: ${built.refusal}`);
    }
    relations.push(built.value);
  }

  // ── emit mandatory markers as OVERLAYS: present, value withheld ───────────
  const overlays: SceneOverlay[] = [];
  const mandatoryMarkers: string[] = [];
  const markerTokens = tokens
    .filter((t) => MARKERS.has(t.subjectCollection))
    .sort((a, b) => a.tokenId.localeCompare(b.tokenId));

  for (const t of markerTokens) {
    const permitted = getigVisualPermittedTiers(t.semanticRank);
    const built = buildSceneOverlay({
      kind: OVERLAY_KIND_FOR_COLLECTION[t.subjectCollection] ?? "explanation",
      // The id names ONE marker TOKEN, not merely the subject it attaches to.
      // 29D-OBS-3: `overlay:<collection>:<subject>` collides when a subject
      // carries two marker tokens of the same collection — the frozen 28D
      // mapping produces exactly that (a `conflicts:known` and a
      // `conflicts:present` on one subject), so two distinct mandatory markers
      // shared one identity. Any keyed structure over overlay ids then merged
      // them, which is the "correct runtime with a misleading picture" failure:
      // a marker the runtime knows about becomes unreachable by id. The
      // tokenId is unique by construction, so the identity becomes unique too.
      overlayId: `overlay:${t.subjectCollection}:${t.subjectVisibleId}:${t.tokenId}`,
      targetId: t.subjectVisibleId,
      // The marker's PRESENCE is visible; its VALUE stays withheld unless Phase-28
      // permits it. This is the reconciliation described in the header.
      text: permitted.includes("minimal") ? `${t.subjectCollection}:${t.semanticValue}` : `${t.subjectCollection}:present`,
    });
    if (!built.ok) {
      return refuse("refused_scene_token_invalid", `overlay for ${t.tokenId} refused: ${built.refusal}`);
    }
    overlays.push(built.value);
    mandatoryMarkers.push(t.tokenId);
  }
  if (overlays.length > SCENE_COMPILER_BOUNDS.maxMarkers) {
    return refuse("refused_scene_budget_exceeded", "marker count exceeds maxMarkers", "tokens");
  }

  // ── law 17 as a REFUSAL, not a hope: nothing mandatory may be missing ────
  // Identity uniqueness is part of that. Two mandatory markers sharing an
  // overlayId would both be emitted yet only one would be reachable by id, so
  // a duplicate is a collision that hides a marker — refused, not tolerated.
  const overlayIds = overlays.map((o) => o.overlayId);
  const duplicateOverlays = [...new Set(overlayIds.filter((id, i) => overlayIds.indexOf(id) !== i))];
  if (duplicateOverlays.length > 0) {
    return refuse(
      "refused_scene_mandatory_marker_dropped",
      `mandatory markers collided on overlay id: ${duplicateOverlays.join(", ")}`,
      "tokens",
    );
  }

  const emitted = new Set<string>(mandatoryMarkers);
  const dropped = markerTokens.filter((t) => !emitted.has(t.tokenId)).map((t) => t.tokenId);
  if (dropped.length > 0) {
    return refuse("refused_scene_mandatory_marker_dropped", `mandatory markers were dropped: ${dropped.join(", ")}`, "tokens");
  }

  // ── the TWO hashes, over DISJOINT content ───────────────────────────────
  // sceneHash: semantics only, no coordinate. layoutHash: coordinates only.
  const sceneHash = canonicalHash({
    frameId: mapping.frameId,
    observerId: mapping.observerId,
    sourceMappingHash: mapping.mappingHash,
    subjects: semanticEntries,
    relations: relations.map((r) => ({ relationId: r.relationId, role: r.role })),
    markers: overlays.map((o) => ({ overlayId: o.overlayId, kind: o.kind, text: o.text })),
  });
  const layoutHash = canonicalHash(primitives.map((p) => ({ primitiveId: p.primitiveId, position: p.position })));

  if (sceneHash === layoutHash) {
    return refuse("refused_scene_mapping_schema", "sceneHash and layoutHash collapsed; the two separations are not distinct");
  }

  const sceneBuild = buildGetigScene({
    sourceFrameId: mapping.frameId,
    sourceVisibleHash: canonicalVisibleHash,
    sceneHash,
    runtimeStateHash,
    primitives,
    relations,
    overlays,
  });
  if (!sceneBuild.ok) {
    return refuse("refused_scene_budget_exceeded", `scene assembly refused: ${sceneBuild.refusal}`);
  }

  // ── opaque, bounded, deterministic picking ids ───────────────────────────
  // Opaque: an id reveals nothing about the subject it names. Deterministic
  // within a scene: derived from the scene hash, so the same scene always yields
  // the same id. It carries no semantic role whatsoever (law 3).
  const pickingIds = Object.freeze(
    primitives
      .slice()
      .sort((a, b) => a.primitiveId.localeCompare(b.primitiveId))
      .map((p) => Object.freeze({
        pickingId: `pick_${canonicalHash({ sceneHash, subjectVisibleId: p.primitiveId })}`,
        subjectVisibleId: p.primitiveId,
      })),
  );
  if (pickingIds.length > SCENE_COMPILER_BOUNDS.maxPickingIds) {
    return refuse("refused_scene_budget_exceeded", "picking id count exceeds maxPickingIds", "tokens");
  }

  return Object.freeze({
    ok: true,
    code: "scene_compiled" as const,
    scene: sceneBuild.value,
    sceneHash,
    layoutHash,
    sourceMappingHash: mapping.mappingHash,
    pickingIds,
    mandatoryMarkers: Object.freeze(mandatoryMarkers.slice()),
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  });
}

/** Which primitive kind each Phase-28 collection compiles to. Unknown => "unknown". */
const COLLECTION_TO_PRIMITIVE_KIND: Readonly<Record<string, "entity" | "relation" | "route" | "conflict" | "refusal" | "partition" | "observer_view" | "overlay" | "unknown">> = Object.freeze({
  entities: "entity",
  events: "entity",
  proposalFlows: "route",
  relations: "relation",
  routes: "route",
  conflicts: "conflict",
  refusals: "refusal",
  partitions: "partition",
});

const OVERLAY_KIND_FOR_COLLECTION: Readonly<Record<string, "provenance" | "explanation" | "conflict" | "refusal" | "partition" | "stale" | "unknown">> = Object.freeze({
  conflicts: "conflict",
  refusals: "refusal",
  partitions: "partition",
});

export type { RendererDecision as SceneCompilerRendererDecision };