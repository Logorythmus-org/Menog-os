/**
 * PHASE 29H — GPU RESOURCE SAFETY & DEVICE-LOSS RECOVERY
 * (GRAPHICS-ONLY RECOVERY / CONTRACT LIFECYCLE / NO RUNTIME PATH)
 *
 * CENTRAL LAWS:
 *   GPU_RECOVERY   != RUNTIME_RECOVERY
 *   ALLOCATED      != SUBMITTED        != RENDERED
 *   GPU_ID / OLD HANDLE != AUTHORITY
 *   SIMULATED CONTRACT EVIDENCE != REAL DEVICE EVIDENCE
 *
 * ── WHAT THIS GATE IS, AND WHAT IT IS NOT ────────────────────────────────────
 *
 * 29D plans what a GPU would be given. This gate decides what happens to those
 * resources across their whole life: creation, allocation, upload, surface
 * resize, device loss, recreation and cleanup. It is a STATE MACHINE OVER
 * CONTRACT VALUES. It allocates nothing real, submits nothing, draws nothing
 * and reads nothing back — there is no `navigator`, no `create*`, no
 * `queue.submit`, no clock and no randomness anywhere in this file's code, and
 * `PHASE29H_FORBIDDEN_TOKENS` exists so that claim is checkable by the suite
 * rather than asserted in prose.
 *
 * The central law is GPU_RECOVERY != RUNTIME_RECOVERY. When a device is lost,
 * this module rebuilds GRAPHICS RESOURCES — and only from the already-authorized
 * 29D plan bound to the session (which itself declares `rebuildsFrom:
 * "getig_frame"` and `restoresRuntimeState: false` on every descriptor). No
 * agent state, no task state, no runtime epoch, no continuity record, no
 * checkpoint, no transcript and no secret enters any function here: inputs
 * carrying such a field are REFUSED by name
 * (`refused_gpu_lifecycle_runtime_restore_forbidden`), and
 * `refuseGpuRecoveryRuntimeRestore` exists so the law is drivable as an exit
 * code rather than merely absent.
 *
 * ── WHY RESOURCE CAPS ARE IMPORTED, NOT RE-DECLARED ──────────────────────────
 *
 * Byte and count ceilings live in 29D's `GPU_PLAN_BOUNDS` and are IMPORTED
 * here. A second declaration of `maxBufferBytes` is a second opinion, and two
 * opinions drift apart the first time someone edits one. This module adds only
 * the caps that are genuinely lifecycle-shaped — live handle count, session
 * handle count, loss/recovery cycles, surface generations, viewport dimensions
 * — in `GPU_LIFECYCLE_BOUNDS`, and every one of them fails CLOSED: there is no
 * knob that shrinks a session's resources to fit, and no path that truncates a
 * handle list silently.
 *
 * ── WHY SIZES ARE CHECKED BEFORE A HANDLE EXISTS ─────────────────────────────
 *
 * An allocation request is `recordCount * strideBytes` computed through 29D's
 * imported `checkedMul`, not through `a * b`. A product that is not an exact
 * safe non-negative integer returns `null` and is REFUSED
 * (`refused_gpu_lifecycle_size_overflow`) BEFORE any handle object exists.
 * Float multiplication wraps; a wrapped size is a small allocation claimed to
 * be a large one. A handle that exists is therefore a handle whose size is
 * known, bounded by the per-usage ceiling drawn from `GPU_PLAN_BOUNDS`, and
 * counted against both the live-handle cap and the total-byte ceiling.
 *
 * Uploads are guarded the same way against the handle they name: a byte length
 * beyond the handle's own `sizeBytes` (or beyond the plan's buffer ceiling) is
 * `refused_gpu_lifecycle_cap_exceeded`, never clamped. Clamping is semantic
 * truncation wearing an operational costume (law 19).
 *
 * ── WHY DEVICE LOSS INVALIDATES EVERYTHING ───────────────────────────────────
 *
 * `markSessionDeviceLost` flips every live handle to `invalidated` with reason
 * `device_loss` in the same decision that transitions the session to `lost`.
 * There is no window in which the session reports `lost` while a handle still
 * reports `live`. A surface resize likewise invalidates `frame_scoped` handles
 * (the viewport uniform and picking table are functions of the frame), while
 * `scene_scoped` and `persistent` handles survive — because they are not
 * surface-dependent, and invalidating them would be theatre, not safety.
 *
 * An invalidated handle is STALE: any operation naming it refuses with
 * `refused_gpu_lifecycle_stale_resource` and an explanation that states the
 * old handle CONFERS NO AUTHORITY. Old GPU handle != authority is structural:
 * every handle — live, invalidated or released — carries literal
 * `authority: "none"` and `executionAuthorized: false`, and a session that has
 * just recovered still reports zero authority on its fresh handles. Recovery
 * restores drawable resources, not permission.
 *
 * ── WHY RECREATION READS ONLY THE AUTHORIZED PLAN ────────────────────────────
 *
 * After loss there is deliberately NO path that allocates arbitrary resources
 * back: `allocateSessionResources` works only from state `created`. The one
 * road out of `lost` is `recreateSessionDevice`, and its `plan` must (a) parse
 * as a well-formed 29D plan that still claims zero authority, `completeness:
 * "incomplete"` and `pixelOutputVerified: false`, and (b) MATCH THE SESSION'S
 * BINDING — same `planHash`, same `sceneHash`, same `sourceFrameId`. A
 * different plan is `refused_gpu_lifecycle_plan_mismatch`: rebuild graphics
 * only from the already-authorized GETIG frame/scene/plan. Fresh handles are
 * re-derived from that plan's buffer descriptors, so a recovered resource set
 * is byte-for-byte the planned one, never a caller-shaped one.
 *
 * ── WHY REPEATED LOSS/RECOVERY IS BOUNDED ────────────────────────────────────
 *
 * A loss/recovery loop that never ends is a resource-exhaustion machine with a
 * nice name. Every `markSessionDeviceLost` counts a loss event; every
 * successful `recreateSessionDevice` counts a recovery, and the (maxLossRecoveryCycles
 * + 1)-th recovery is `refused_gpu_lifecycle_loss_budget_exceeded`. Loss
 * itself is never refused — a dying device is not making a request — but the
 * way BACK is finite. At the budget's end the session can still be released:
 * cleanup is never behind the same limit that gates recovery.
 *
 * ── WHY SIMULATED AND REAL DEVICE EVIDENCE ARE A FIELD, NOT A SENTENCE ───────
 *
 * This workspace's test runtime has no WebGPU API, and 29C-OBS-1 stands:
 * texture readback returned all zeros on the target. Real device-loss
 * injection is therefore UNAVAILABLE here, and this module says so in three
 * explicit fields instead of burying it in prose:
 *
 *   contractEvidence        — always "simulated_contract_tests": the lifecycle
 *                             transitions are exercised as contract tests.
 *   realDeviceLossEvidence  — "unavailable" until (and unless) a caller
 *                             supplies a real observation object; then
 *                             "observed_readback_inconclusive" (29C's own
 *                             verdict name) or "observed_readback_matched".
 *   adapterDeviceRecreation — "not_yet_attempted" until a recreation runs,
 *                             then "contract_simulated" or "real_observed".
 *
 * A `real_device_observation` claim with NO observation is
 * `refused_gpu_lifecycle_evidence_unavailable` (citing 29C-OBS-1), a
 * malformed or self-contradictory observation is
 * `refused_gpu_lifecycle_evidence_invalid`, and an observation whose readback
 * did not match what was rendered can never upgrade
 * `realDeviceLossEvidence` past `observed_readback_inconclusive` — because a
 * readback that merely completed is SUBMITTED != RENDERED, as ever.
 * Supplying real evidence NEVER changes `contractEvidence`: the suite's own
 * evidence remains simulated, because that is what it is.
 *
 * ── WHY NOTHING HERE HAS A TIMESTAMP ─────────────────────────────────────────
 *
 * `sessionId` and every `handleId` are deterministic canonical hashes of their
 * bindings. No `Date.now`, no clock, no randomness: a recovery record that
 * invented chronology would be exactly the fake chronology law 10 forbids, and
 * a deterministic id makes two identical sessions indistinguishable, which is
 * the point — nothing here is an observation of WHEN, only of WHAT may follow
 * WHAT.
 */

import { canonicalHash } from "./canonical.js";
import {
  GPU_BUFFER_CONTENTS,
  GPU_BUFFER_USAGES,
  GPU_LAYOUTS,
  GPU_PASS_KINDS,
  GPU_PLAN_BOUNDS,
  GPU_PLAN_SCHEMA_VERSION,
  GPU_RESOURCE_LIFECYCLES,
  SHADER_INTERFACE,
  checkedMul,
} from "./gpuRenderPlan.js";
import type { GpuBufferUsage, GpuResourceLifecycle } from "./gpuRenderPlan.js";

// ── closed vocabularies ────────────────────────────────────────────────────────

export const GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION = "menog-gpu-resource-lifecycle/v0" as const;

/**
 * Session states, and the ONLY transitions between them.
 *
 * Note what is absent: there is no transition out of `released` (cleanup is
 * terminal), and the ONLY path back from `lost` is recreation, which requires
 * the authorized plan — a lost session can never be re-allocated directly.
 */
export const GPU_SESSION_STATES = Object.freeze([
  /** Bound to an authorized plan; no resources exist yet. */
  "created",
  /** Resources allocated (or re-derived by recreation); uploads and resize allowed. */
  "allocated",
  /** Device lost: every handle is invalidated; only recreation or release follow. */
  "lost",
  /** Terminal: every handle released. No operation restarts a released session. */
  "released",
] as const);
export type GpuSessionState = (typeof GPU_SESSION_STATES)[number];

export const GPU_SESSION_TRANSITIONS: Readonly<Record<GpuSessionState, readonly GpuSessionState[]>> = Object.freeze({
  created: Object.freeze(["allocated", "lost", "released"] as const),
  allocated: Object.freeze(["lost", "released"] as const),
  lost: Object.freeze(["allocated", "released"] as const),
  released: Object.freeze([] as const),
});

export const GPU_HANDLE_STATES = Object.freeze(["live", "invalidated", "released"] as const);
export type GpuHandleState = (typeof GPU_HANDLE_STATES)[number];

export const GPU_HANDLE_INVALIDATION_REASONS = Object.freeze([
  "none",
  "device_loss",
  "surface_resize",
  "session_release",
] as const);
export type GpuHandleInvalidationReason = (typeof GPU_HANDLE_INVALIDATION_REASONS)[number];

/**
 * Why a session believes the device was lost.
 *
 * In this workspace the honest member is `simulated_contract_event`: no
 * harness here can force real device loss. The others exist so a future real
 * observation has a name to land in, not so a simulation can borrow one.
 */
export const GPU_LOSS_REASONS = Object.freeze([
  "simulated_contract_event",
  "platform_reported_loss",
  "adapter_recreation_failed",
  "unknown",
] as const);
export type GpuLossReason = (typeof GPU_LOSS_REASONS)[number];

export const GPU_RECOVERY_EVIDENCE_MODES = Object.freeze([
  "simulated_contract_tests",
  "real_device_observation",
] as const);
export type GpuRecoveryEvidenceMode = (typeof GPU_RECOVERY_EVIDENCE_MODES)[number];

/**
 * The complete real-device observation a caller may present to
 * `recreateSessionDevice`. Every field is REQUIRED, negatives included: a
 * probe that could omit `lossObserved` would let an unknown run default to
 * "no loss happened", which is the assumption fail-closed forbids.
 */
export const GPU_REAL_LOSS_OBSERVATION_FIELDS = Object.freeze([
  "apiPresent",
  "adapterObtained",
  "deviceCreated",
  "lossObserved",
  "recreationSucceeded",
  "readbackMatchesExpectation",
  "userAgent",
] as const);

export const GPU_REAL_DEVICE_EVIDENCE_STATES = Object.freeze([
  "unavailable",
  "observed_readback_inconclusive",
  "observed_readback_matched",
] as const);
export type GpuRealDeviceEvidenceState = (typeof GPU_REAL_DEVICE_EVIDENCE_STATES)[number];

export const GPU_ADAPTER_RECREATION_STATES = Object.freeze([
  "not_yet_attempted",
  "contract_simulated",
  "real_observed",
] as const);
export type GpuAdapterRecreationState = (typeof GPU_ADAPTER_RECREATION_STATES)[number];

/**
 * Input field names that would mean a caller tried to hand runtime state to a
 * graphics-recovery function. Checked BEFORE unknown-key handling, so the
 * refusal explains the LAW rather than the schema.
 *
 * The scan is deliberately over the TOP-LEVEL keys of the offered input: this
 * module's inputs are flat control objects, and the one nested structure it
 * accepts from the outside — a 29D plan — is validated by 29H's own plan
 * parser (which already demands `restoresRuntimeState: false` on every
 * descriptor) instead of by keyword guesswork.
 */
export const GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS = Object.freeze([
  "agent",
  "agentState",
  "agentTask",
  "task",
  "taskState",
  "runtime",
  "runtimeState",
  "runtimeStateHash",
  "runtimeEpoch",
  "epoch",
  "resume",
  "resumed",
  "replay",
  "restored",
  "checkpoint",
  "continuity",
  "memory",
  "transcript",
  "prompt",
  "rawPrompt",
  "toolOutput",
  "secret",
  "credential",
  "password",
  "privateKey",
] as const);

/**
 * Every way this gate can refuse. All eleven are LIVE: suite block 29H-R
 * drives each one from a real input and compares the driven set against this
 * vocabulary, because a declared-but-unreachable refusal code advertises a
 * check that does not exist.
 */
export const GPU_LIFECYCLE_REFUSAL_CODES = Object.freeze([
  "refused_gpu_lifecycle_input_invalid",
  "refused_gpu_lifecycle_plan_invalid",
  "refused_gpu_lifecycle_plan_mismatch",
  "refused_gpu_lifecycle_runtime_restore_forbidden",
  "refused_gpu_lifecycle_cap_exceeded",
  "refused_gpu_lifecycle_size_overflow",
  "refused_gpu_lifecycle_state_invalid",
  "refused_gpu_lifecycle_stale_resource",
  "refused_gpu_lifecycle_loss_budget_exceeded",
  "refused_gpu_lifecycle_evidence_invalid",
  "refused_gpu_lifecycle_evidence_unavailable",
] as const);
export type GpuLifecycleRefusalCode = (typeof GPU_LIFECYCLE_REFUSAL_CODES)[number];

// ── explicit lifecycle bounds (law 19: fail closed, never truncate) ────────────

/**
 * The caps that belong to the LIFECYCLE rather than to the plan.
 *
 * Byte and count ceilings are NOT re-declared here; they are imported from
 * 29D's `GPU_PLAN_BOUNDS` at every point of use. This object is checked by
 * the suite to contain exactly these six keys precisely so a byte ceiling can
 * never quietly fork into a second, divergent declaration.
 */
export const GPU_LIFECYCLE_BOUNDS = Object.freeze({
  /** Live handles a single session may hold at once. */
  maxLiveHandles: 64,
  /** Total handles (live + invalidated + released) a session may ever carry. */
  maxSessionHandles: 256,
  /** Successful loss/recovery cycles before recreation refuses. */
  maxLossRecoveryCycles: 8,
  /** Surface reconfigurations before resize refuses. */
  maxSurfaceGenerations: 256,
  /** Largest single viewport dimension resize may request. */
  maxViewportDimension: 16384,
  /** Largest viewport scale resize may request. */
  maxViewportScale: 4,
});
export type GpuLifecycleBounds = typeof GPU_LIFECYCLE_BOUNDS;

/**
 * Tokens that would mean this gate had touched a real device, a real clock or
 * real randomness. Exported so the suite can assert their absence from this
 * file's CODE (comments and string literals stripped), with planted positive
 * controls proving the scanner actually fires.
 */
export const PHASE29H_FORBIDDEN_TOKENS = Object.freeze([
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
  "loseContext",
  "requestAnimationFrame",
  "getContext(",
  "device.destroy",
  "Date.now",
  "performance.now",
  "Math.random",
] as const);

// ── the produced contracts ─────────────────────────────────────────────────────

/**
 * A planned resource, as a session sees it.
 *
 * The handle is an OPAQUE, DETERMINISTIC id over its own bindings — no
 * timestamp, no counter, no randomness — and every field that could be read as
 * permission is a literal zero. `uploadedBytes` counts guarded upload volume
 * for audit; it is a byte count, not evidence of a submission.
 */
export interface GpuResourceHandle {
  readonly handleId: string;
  readonly bufferId: string;
  readonly planHash: string;
  readonly sceneHash: string;
  /** Surface generation at which this handle was created. */
  readonly allocatedAtGeneration: number;
  /** Loss-event epoch at which this handle was created (0 = first build). */
  readonly buildEpoch: number;
  readonly sizeBytes: number;
  readonly usage: readonly GpuBufferUsage[];
  readonly lifecycle: GpuResourceLifecycle;
  readonly state: GpuHandleState;
  readonly invalidationReason: GpuHandleInvalidationReason;
  readonly uploadedBytes: number;
  /** Law: recovery rebuilds graphics from the frame, never runtime state. */
  readonly rebuildsFrom: "getig_frame";
  readonly restoresRuntimeState: false;
  readonly ownerLayer: "gpu_resource";
  readonly authority: "none";
  readonly executionAuthorized: false;
}

/**
 * The lifecycle session: a pure, frozen value. Every operation RETURNS a new
 * session; nothing mutates in place, so a refused operation leaves the caller
 * holding exactly what it held before.
 *
 * Note what the session does NOT carry: no `runtimeStateHash`, no epoch, no
 * owner, no permission. It binds a plan, a scene and a frame — the three
 * things a graphics rebuild is allowed to read — and nothing else.
 */
export interface GpuResourceSession {
  readonly schemaVersion: typeof GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION;
  /** Deterministic over the binding. Two identical bindings share an id. */
  readonly sessionId: string;
  readonly state: GpuSessionState;
  readonly boundPlanHash: string;
  readonly boundSceneHash: string;
  readonly boundFrameId: string;
  readonly surfaceGeneration: number;
  readonly viewport: {
    readonly width: number;
    readonly height: number;
    readonly scale: number;
  };
  readonly handles: readonly GpuResourceHandle[];
  readonly lossEventCount: number;
  readonly recoveryCount: number;
  readonly lossReason: GpuLossReason | null;
  /** Always this: the suite's own evidence for lifecycle transitions. */
  readonly contractEvidence: "simulated_contract_tests";
  readonly realDeviceLossEvidence: GpuRealDeviceEvidenceState;
  readonly realDeviceLossEvidenceNote: string;
  readonly adapterDeviceRecreation: GpuAdapterRecreationState;
  readonly notProven: readonly string[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

export type GpuLifecycleRefused = {
  readonly ok: false;
  readonly code: "gpu_lifecycle_refused";
  readonly refusal: GpuLifecycleRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  /** A refusal emits NOTHING partial: no session, no handle, no id. */
  readonly session: null;
  readonly handle: null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type GpuLifecycleSucceeded = {
  readonly ok: true;
  readonly code: "gpu_lifecycle_applied";
  readonly session: GpuResourceSession;
  /** The handle an operation names or creates; null when none is in focus. */
  readonly handle: GpuResourceHandle | null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type GpuLifecycleDecision = GpuLifecycleSucceeded | GpuLifecycleRefused;

// ── helpers ────────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * An object with a key outside the closed vocabulary returns the offending
 * key; null means every key is declared. An ignored field reads as a read
 * field (28J-OBS-5), and an UNCOMMITTED field is even worse: 29D's planHash
 * projects a fixed field set, so an extra key would ride along hash-verified.
 */
const unknownKeyOf = (obj: Record<string, unknown>, allowed: readonly string[]): string | null => {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) return key;
  }
  return null;
};

const refuse = (
  refusal: GpuLifecycleRefusalCode,
  explanation: string,
  offendingField: string | null = null,
): GpuLifecycleRefused => ({
  ok: false,
  code: "gpu_lifecycle_refused",
  refusal,
  explanation,
  offendingField,
  session: null,
  handle: null,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const ok = (session: GpuResourceSession, handle: GpuResourceHandle | null = null): GpuLifecycleSucceeded => ({
  ok: true,
  code: "gpu_lifecycle_applied",
  session,
  handle,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const HASH_SHAPE = /^[a-f0-9]{16,128}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const PLAN_HASH_SHAPE = /^plan_[0-9a-f]{64}$/;
const isHash = (v: unknown): v is string => typeof v === "string" && HASH_SHAPE.test(v);

// Closed key vocabularies for every structure a plan is made of. 29D's
// planHash projects a FIXED field set, so a key outside these lists would be
// both unread-by-checkers and uncommitted-by-hash. Declared once, here.
const PLAN_KEYS = Object.freeze([
  "schemaVersion",
  "planHash",
  "sourceFrameId",
  "sceneHash",
  "sourceVisibleHash",
  "runtimeStateHash",
  "vertexLayoutId",
  "buffers",
  "bindGroups",
  "pipelines",
  "passes",
  "pickingResolutions",
  "framesInFlight",
  "entryCount",
  "totalBufferBytes",
  "completeness",
  "supportsHardware",
  "qualificationVerdict",
  "pixelOutputVerified",
  "notProven",
  "authority",
  "controlPlane",
  "readOnly",
  "executionAuthorized",
] as const);
const BUFFER_KEYS = Object.freeze([
  "bufferId",
  "label",
  "usage",
  "contents",
  "layout",
  "strideBytes",
  "recordCount",
  "sizeBytes",
  "sizeDerivation",
  "contentHash",
  "lifecycle",
  "rebuildsFrom",
  "restoresRuntimeState",
  "ownerLayer",
  "authority",
  "executionAuthorized",
] as const);
const BIND_GROUP_KEYS = Object.freeze([
  "bindGroupId",
  "group",
  "binding",
  "layout",
  "bufferIds",
  "authority",
  "executionAuthorized",
] as const);
const PIPELINE_KEYS = Object.freeze([
  "pipelineId",
  "shaderInterface",
  "vertexLayout",
  "instanceLayout",
  "bindGroups",
  "targetFormat",
  "depthCompare",
  "ownership",
  "authority",
  "executionAuthorized",
] as const);
const PASS_KEYS = Object.freeze([
  "passId",
  "kind",
  "pipelineIds",
  "bindGroups",
  "sceneHash",
  "authority",
  "executionAuthorized",
] as const);
const PICKING_ROW_KEYS = Object.freeze([
  "pickingIndex",
  "pickingId",
  "subjectVisibleId",
  "relationIds",
  "overlayIds",
  "markerTexts",
  "uploadedToGpu",
  "authority",
  "executionAuthorized",
] as const);
const GPU_LAYOUT_IDS: readonly string[] = Object.freeze(Object.keys(GPU_LAYOUTS));
const PIPELINE_TARGET_FORMATS: readonly string[] = Object.freeze(["presentation_only", "picking_index"]);

const inVocab = <T extends string>(v: unknown, vocab: readonly T[]): v is T =>
  typeof v === "string" && (vocab as readonly string[]).includes(v);

/**
 * The deterministic session id. No clock, no nonce: the same plan/scene/frame
 * binding always produces the same id, so the id cannot be used to claim WHEN
 * a session was created.
 */
const deriveSessionId = (planHash: string, sceneHash: string, frameId: string): string =>
  `gls_${canonicalHash({ planHash, sceneHash, frameId })}`;

/**
 * The deterministic handle id, over the handle's OWN bindings.
 *
 * `buildEpoch` is the loss-event count at creation, so handles re-derived
 * after a recovery are distinguishable from the ones the loss invalidated —
 * without any clock being consulted.
 */
const deriveHandleId = (
  planHash: string,
  bufferId: string,
  buildEpoch: number,
  allocatedAtGeneration: number,
): string =>
  `h_${canonicalHash({ planHash, bufferId, buildEpoch, allocatedAtGeneration })}`;

/** Forbidden TOP-LEVEL input fields, checked before schema handling. */
const forbiddenInputFields = (input: Record<string, unknown>): string[] =>
  Object.keys(input).filter((k) => (GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS as readonly string[]).includes(k));

/** Every declared input key refused by law before the schema complains. */
const forbidRuntimeFields = (input: Record<string, unknown>): GpuLifecycleRefused | null => {
  const hits = forbiddenInputFields(input);
  if (hits.length === 0) return null;
  return refuse(
    "refused_gpu_lifecycle_runtime_restore_forbidden",
    `input field(s) ${hits.join(", ")} would hand runtime state to a graphics-recovery operation; GPU_RECOVERY != RUNTIME_RECOVERY — agent, task and runtime state is never restored, replayed or resumed here`,
    hits[0] ?? null,
  );
};

const unknownField = (input: Record<string, unknown>, allowed: readonly string[]): string | null => {
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) return key;
  }
  return null;
};

/**
 * Per-usage byte ceiling, drawn from the IMPORTED plan bounds.
 *
 * A buffer that declares several usages gets the SMALLEST applicable ceiling —
 * the strictest constraint wins, because the loosest one is the one a future
 * edit would route around.
 */
const usageCeiling = (usage: readonly GpuBufferUsage[]): number => {
  let cap: number = GPU_PLAN_BOUNDS.maxBufferBytes;
  if (usage.includes("vertex")) cap = Math.min(cap, GPU_PLAN_BOUNDS.maxVertexBytes);
  if (usage.includes("index")) cap = Math.min(cap, GPU_PLAN_BOUNDS.maxIndexBytes);
  if (usage.includes("uniform")) cap = Math.min(cap, GPU_PLAN_BOUNDS.maxUniformBytes);
  if (usage.includes("storage")) cap = Math.min(cap, GPU_PLAN_BOUNDS.maxStorageBytes);
  return cap;
};

const liveOf = (handles: readonly GpuResourceHandle[]): GpuResourceHandle[] =>
  handles.filter((h) => h.state === "live");

// ── plan validation: the only legal rebuild source ────────────────────────────

type PlanView =
  | {
      ok: true;
      planHash: string;
      sceneHash: string;
      sourceFrameId: string;
      framesInFlight: number;
      buffers: readonly {
        readonly bufferId: string;
        readonly sizeBytes: number;
        readonly usage: readonly GpuBufferUsage[];
        readonly lifecycle: GpuResourceLifecycle;
      }[];
      totalBytes: number;
    }
  | { ok: false; refusal: GpuLifecycleRefusalCode; explanation: string; field: string | null };

const planFail = (
  refusal: GpuLifecycleRefusalCode,
  explanation: string,
  field: string | null = null,
): PlanView => ({ ok: false, refusal, explanation, field });

/**
 * Parse and judge a plan offered as the authorized rebuild source.
 *
 * Everything a recovery could exploit is checked here: schema, closed key
 * vocabulary, binding shapes, zero-authority fields, the "incomplete /
 * unverified" claim, per-buffer safe sizes, per-usage ceilings, structural
 * counts, the declared byte total, pass/scene equality, and finally a FULL
 * RECOMPUTE of 29D's planHash over the plan's own content — because a hash
 * label nobody re-derives is a claim, not a commitment. A plan that fails any
 * of these is not a smaller plan — it is no plan.
 */
const validatePlan = (plan: unknown): PlanView => {
  if (!isRecord(plan)) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan must be an object", "plan");
  }
  const planKey = unknownKeyOf(plan, PLAN_KEYS);
  if (planKey !== null) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      `plan carries undeclared field ${planKey} — an ignored field reads as a read field, and an uncommitted field rides along a verified hash`,
      planKey,
    );
  }
  if (plan["schemaVersion"] !== GPU_PLAN_SCHEMA_VERSION) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      `plan schemaVersion must be ${GPU_PLAN_SCHEMA_VERSION}`,
      "plan.schemaVersion",
    );
  }
  if (typeof plan["planHash"] !== "string" || !PLAN_HASH_SHAPE.test(plan["planHash"])) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.planHash must be plan_ + 64 hex", "plan.planHash");
  }
  if (!isHash(plan["sceneHash"])) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.sceneHash must be a hex hash", "plan.sceneHash");
  }
  if (typeof plan["sourceFrameId"] !== "string" || plan["sourceFrameId"].length === 0) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan.sourceFrameId is required — recovery binds to a frame",
      "plan.sourceFrameId",
    );
  }
  // A plan that claims completeness or verified pixels is NOT a rebuild
  // source: 29C measured no verified readback, and UNSUPPORTED != PASS.
  if (plan["completeness"] !== "incomplete") {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan.completeness must be the literal 'incomplete'; a plan claiming completeness is not an authorized rebuild source",
      "plan.completeness",
    );
  }
  if (plan["pixelOutputVerified"] !== false) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan.pixelOutputVerified must be false; ALLOCATED != SUBMITTED != RENDERED",
      "plan.pixelOutputVerified",
    );
  }
  if (
    plan["authority"] !== "none" ||
    plan["controlPlane"] !== false ||
    plan["readOnly"] !== true ||
    plan["executionAuthorized"] !== false
  ) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan must declare authority none, controlPlane false, readOnly true, executionAuthorized false",
      "plan.authority",
    );
  }
  const framesInFlight = plan["framesInFlight"];
  if (!Number.isSafeInteger(framesInFlight) || (framesInFlight as number) < 1) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.framesInFlight must be an integer >= 1", "plan.framesInFlight");
  }
  if ((framesInFlight as number) > GPU_PLAN_BOUNDS.maxFramesInFlight) {
    return planFail(
      "refused_gpu_lifecycle_cap_exceeded",
      `plan.framesInFlight ${String(framesInFlight)} exceeds GPU_PLAN_BOUNDS.maxFramesInFlight ${GPU_PLAN_BOUNDS.maxFramesInFlight}`,
      "plan.framesInFlight",
    );
  }
  const pipelines = plan["pipelines"];
  const passes = plan["passes"];
  if (!Array.isArray(pipelines) || !Array.isArray(passes)) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan requires pipelines and passes arrays", "plan.pipelines");
  }
  if (pipelines.length > GPU_PLAN_BOUNDS.maxPipelines) {
    return planFail(
      "refused_gpu_lifecycle_cap_exceeded",
      `plan declares ${pipelines.length} pipelines, over GPU_PLAN_BOUNDS.maxPipelines ${GPU_PLAN_BOUNDS.maxPipelines}`,
      "plan.pipelines",
    );
  }
  if (passes.length > GPU_PLAN_BOUNDS.maxPasses) {
    return planFail(
      "refused_gpu_lifecycle_cap_exceeded",
      `plan declares ${passes.length} passes, over GPU_PLAN_BOUNDS.maxPasses ${GPU_PLAN_BOUNDS.maxPasses}`,
      "plan.passes",
    );
  }
  const buffers = plan["buffers"];
  if (!Array.isArray(buffers) || buffers.length === 0) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan must declare at least one buffer", "plan.buffers");
  }
  let total = 0;
  for (const raw of buffers) {
    if (!isRecord(raw)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "every buffer descriptor must be an object", "plan.buffers");
    }
    const bufferKey = unknownKeyOf(raw, BUFFER_KEYS);
    if (bufferKey !== null) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `buffer carries undeclared field ${bufferKey} — an uncommitted field rides along a verified hash`,
        `plan.buffers.${bufferKey}`,
      );
    }
    const bufferId = raw["bufferId"];
    if (typeof bufferId !== "string" || bufferId.length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "buffer.bufferId is required", "plan.buffers.bufferId");
    }
    if (
      raw["rebuildsFrom"] !== "getig_frame" ||
      raw["restoresRuntimeState"] !== false ||
      raw["authority"] !== "none" ||
      raw["executionAuthorized"] !== false
    ) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `buffer ${bufferId} must declare rebuildsFrom getig_frame, restoresRuntimeState false, authority none, executionAuthorized false`,
        `plan.buffers.${bufferId}`,
      );
    }
    const sizeBytes = raw["sizeBytes"];
    if (typeof sizeBytes !== "number" || !Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
      return planFail(
        "refused_gpu_lifecycle_size_overflow",
        `buffer ${bufferId} sizeBytes ${String(sizeBytes)} is not a safe non-negative integer — a wrapped size is a small allocation claimed to be a large one`,
        `plan.buffers.${bufferId}.sizeBytes`,
      );
    }
    const usageRaw = raw["usage"];
    if (!Array.isArray(usageRaw) || usageRaw.length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `buffer ${bufferId} requires a usage array`, `plan.buffers.${bufferId}.usage`);
    }
    for (const u of usageRaw) {
      if (!inVocab(u, GPU_BUFFER_USAGES)) {
        return planFail(
          "refused_gpu_lifecycle_plan_invalid",
          `buffer ${bufferId} declares unknown usage ${String(u)}`,
          `plan.buffers.${bufferId}.usage`,
        );
      }
    }
    const usage = usageRaw as readonly GpuBufferUsage[];
    const ceiling = usageCeiling(usage);
    if (sizeBytes > ceiling) {
      return planFail(
        "refused_gpu_lifecycle_cap_exceeded",
        `buffer ${bufferId} sizeBytes ${sizeBytes} exceeds its usage ceiling ${ceiling} B (GPU_PLAN_BOUNDS)`,
        `plan.buffers.${bufferId}.sizeBytes`,
      );
    }
    if (!inVocab(raw["lifecycle"], GPU_RESOURCE_LIFECYCLES)) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `buffer ${bufferId} lifecycle ${String(raw["lifecycle"])} is not in the closed vocabulary`,
        `plan.buffers.${bufferId}.lifecycle`,
      );
    }
    if (!inVocab(raw["contents"], GPU_BUFFER_CONTENTS)) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `buffer ${bufferId} contents ${String(raw["contents"])} is not in the closed vocabulary`,
        `plan.buffers.${bufferId}.contents`,
      );
    }
    total += sizeBytes;
    if (!Number.isSafeInteger(total)) {
      return planFail("refused_gpu_lifecycle_size_overflow", "sum of buffer sizes is not a safe integer", "plan.buffers");
    }
  }
  if (total > GPU_PLAN_BOUNDS.maxBufferBytes) {
    return planFail(
      "refused_gpu_lifecycle_cap_exceeded",
      `plan buffers total ${total} B exceeds GPU_PLAN_BOUNDS.maxBufferBytes ${GPU_PLAN_BOUNDS.maxBufferBytes}`,
      "plan.buffers",
    );
  }
  const declaredTotal = plan["totalBufferBytes"];
  if (typeof declaredTotal !== "number" || !Number.isSafeInteger(declaredTotal) || declaredTotal < 0) {
    return planFail(
      "refused_gpu_lifecycle_size_overflow",
      "plan.totalBufferBytes is not a safe non-negative integer",
      "plan.totalBufferBytes",
    );
  }
    if (declaredTotal !== total) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      `plan declares totalBufferBytes ${declaredTotal} but its buffers sum to ${total} — the plan does not describe itself`,
      "plan.totalBufferBytes",
    );
  }

  // ── STRUCTURE: bind groups, pipelines, passes, picking rows ───────────────
  // These are what a renderer would ACTUALLY be driven by, and none of them
  // is covered by a length check. A depth-comparing pipeline here could
  // occlude mandatory conflict/refusal/partition markers; a pass bound to
  // another scene is a frame/scene mismatch wearing the right planHash.
  const bindGroups = plan["bindGroups"];
  if (!Array.isArray(bindGroups)) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.bindGroups must be an array", "plan.bindGroups");
  }
  const bufferIdsDeclared = new Set(
    (buffers as Record<string, unknown>[]).map((b) => String(b["bufferId"])),
  );
  for (const rawBg of bindGroups as unknown[]) {
    if (!isRecord(rawBg)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "every bind group must be an object", "plan.bindGroups");
    }
    const bgKey = unknownKeyOf(rawBg, BIND_GROUP_KEYS);
    if (bgKey !== null) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `bind group carries undeclared field ${bgKey}`, `plan.bindGroups.${bgKey}`);
    }
    if (typeof rawBg["bindGroupId"] !== "string" || rawBg["bindGroupId"].length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "bind group requires bindGroupId", "plan.bindGroups.bindGroupId");
    }
    if (
      !Number.isSafeInteger(rawBg["group"]) || (rawBg["group"] as number) < 0 ||
      !Number.isSafeInteger(rawBg["binding"]) || (rawBg["binding"] as number) < 0
    ) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "bind group group/binding must be non-negative safe integers", "plan.bindGroups.group");
    }
    if (!inVocab(rawBg["layout"], GPU_LAYOUT_IDS)) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `bind group layout ${String(rawBg["layout"])} is not a declared 29D layout`,
        "plan.bindGroups.layout",
      );
    }
    const bgBuffers = rawBg["bufferIds"];
    if (!Array.isArray(bgBuffers) || bgBuffers.length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "bind group must reference at least one buffer", "plan.bindGroups.bufferIds");
    }
    for (const b of bgBuffers as unknown[]) {
      if (typeof b !== "string" || !bufferIdsDeclared.has(b)) {
        return planFail(
          "refused_gpu_lifecycle_plan_invalid",
          `bind group references buffer ${String(b)} the plan does not declare`,
          "plan.bindGroups.bufferIds",
        );
      }
    }
    if (rawBg["authority"] !== "none" || rawBg["executionAuthorized"] !== false) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "bind group must declare authority none and executionAuthorized false", "plan.bindGroups.authority");
    }
  }

  const pipelineIdsDeclared = new Set<string>();
  for (const rawPipe of pipelines as unknown[]) {
    if (!isRecord(rawPipe)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "every pipeline must be an object", "plan.pipelines");
    }
    const pipeKey = unknownKeyOf(rawPipe, PIPELINE_KEYS);
    if (pipeKey !== null) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pipeline carries undeclared field ${pipeKey}`, `plan.pipelines.${pipeKey}`);
    }
    if (typeof rawPipe["pipelineId"] !== "string" || rawPipe["pipelineId"].length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pipeline requires pipelineId", "plan.pipelines.pipelineId");
    }
    if (rawPipe["shaderInterface"] !== SHADER_INTERFACE.schemaVersion) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `pipeline.shaderInterface must be ${SHADER_INTERFACE.schemaVersion} — a foreign interface is not the authorized shader contract`,
        "plan.pipelines.shaderInterface",
      );
    }
    if (!inVocab(rawPipe["vertexLayout"], GPU_LAYOUT_IDS)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pipeline.vertexLayout ${String(rawPipe["vertexLayout"])} is not a declared layout`, "plan.pipelines.vertexLayout");
    }
    const instanceLayout = rawPipe["instanceLayout"];
    if (instanceLayout !== null && !inVocab(instanceLayout, GPU_LAYOUT_IDS)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pipeline.instanceLayout ${String(instanceLayout)} is not a declared layout or null`, "plan.pipelines.instanceLayout");
    }
    // The depth-occlusion attack: a depth-comparing pipeline can hide a
    // mandatory conflict/refusal/partition marker behind geometry. 29E's law
    // is depthCompare "none" EVERYWHERE; it is re-asserted at recovery time.
    if (rawPipe["depthCompare"] !== "none") {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `pipeline.depthCompare ${String(rawPipe["depthCompare"])} — only "none" is permitted; a depth-comparing pipeline could occlude mandatory conflict/refusal/partition markers (markers are never occluded)`,
        "plan.pipelines.depthCompare",
      );
    }
    if (!inVocab(rawPipe["targetFormat"], PIPELINE_TARGET_FORMATS)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pipeline.targetFormat ${String(rawPipe["targetFormat"])} is not presentation_only or picking_index`, "plan.pipelines.targetFormat");
    }
    const pipeBindGroups = rawPipe["bindGroups"];
    if (!Array.isArray(pipeBindGroups)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pipeline.bindGroups must be an array", "plan.pipelines.bindGroups");
    }
    for (const g of pipeBindGroups as unknown[]) {
      if (!Number.isSafeInteger(g) || (g as number) < 0 || (g as number) >= bindGroups.length) {
        return planFail(
          "refused_gpu_lifecycle_plan_invalid",
          `pipeline references bind group ${String(g)} out of range (plan declares ${bindGroups.length})`,
          "plan.pipelines.bindGroups",
        );
      }
    }
    if (
      rawPipe["ownership"] !== "gpu_resource" ||
      rawPipe["authority"] !== "none" ||
      rawPipe["executionAuthorized"] !== false
    ) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pipeline must declare ownership gpu_resource, authority none, executionAuthorized false", "plan.pipelines.authority");
    }
    pipelineIdsDeclared.add(String(rawPipe["pipelineId"]));
  }

  for (const rawPass of passes as unknown[]) {
    if (!isRecord(rawPass)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "every pass must be an object", "plan.passes");
    }
    const passKey = unknownKeyOf(rawPass, PASS_KEYS);
    if (passKey !== null) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pass carries undeclared field ${passKey}`, `plan.passes.${passKey}`);
    }
    if (typeof rawPass["passId"] !== "string" || rawPass["passId"].length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pass requires passId", "plan.passes.passId");
    }
    if (!inVocab(rawPass["kind"], GPU_PASS_KINDS)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `pass.kind ${String(rawPass["kind"])} is not in the closed vocabulary`, "plan.passes.kind");
    }
    const passPipes = rawPass["pipelineIds"];
    if (!Array.isArray(passPipes) || passPipes.length === 0) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pass must reference at least one pipeline", "plan.passes.pipelineIds");
    }
    for (const p of passPipes as unknown[]) {
      if (typeof p !== "string" || !pipelineIdsDeclared.has(p)) {
        return planFail(
          "refused_gpu_lifecycle_plan_invalid",
          `pass references pipeline ${String(p)} the plan does not declare`,
          "plan.passes.pipelineIds",
        );
      }
    }
    const passBindGroups = rawPass["bindGroups"];
    if (!Array.isArray(passBindGroups)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pass.bindGroups must be an array", "plan.passes.bindGroups");
    }
    for (const g of passBindGroups as unknown[]) {
      if (!Number.isSafeInteger(g) || (g as number) < 0 || (g as number) >= bindGroups.length) {
        return planFail("refused_gpu_lifecycle_plan_invalid", `pass references bind group ${String(g)} out of range`, "plan.passes.bindGroups");
      }
    }
    // Frame/scene mismatch: every pass is bound to THE scene the plan claims.
    if (rawPass["sceneHash"] !== plan["sceneHash"]) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `pass ${String(rawPass["passId"])} is bound to scene ${String(rawPass["sceneHash"])} but the plan claims ${String(plan["sceneHash"])} — a pass from another scene is a frame/scene mismatch`,
        "plan.passes.sceneHash",
      );
    }
    if (rawPass["authority"] !== "none" || rawPass["executionAuthorized"] !== false) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "pass must declare authority none and executionAuthorized false", "plan.passes.authority");
    }
  }

  const pickingRows = plan["pickingResolutions"];
  if (!Array.isArray(pickingRows)) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.pickingResolutions must be an array", "plan.pickingResolutions");
  }
  if (pickingRows.length > GPU_PLAN_BOUNDS.maxPrimitives) {
    return planFail(
      "refused_gpu_lifecycle_cap_exceeded",
      `plan declares ${pickingRows.length} picking rows, over GPU_PLAN_BOUNDS.maxPrimitives ${GPU_PLAN_BOUNDS.maxPrimitives}`,
      "plan.pickingResolutions",
    );
  }
  for (const rawRow of pickingRows as unknown[]) {
    if (!isRecord(rawRow)) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "every picking row must be an object", "plan.pickingResolutions");
    }
    const rowKey = unknownKeyOf(rawRow, PICKING_ROW_KEYS);
    if (rowKey !== null) {
      return planFail("refused_gpu_lifecycle_plan_invalid", `picking row carries undeclared field ${rowKey}`, `plan.pickingResolutions.${rowKey}`);
    }
    if (
      typeof rawRow["subjectVisibleId"] !== "string" || rawRow["subjectVisibleId"].length === 0 ||
      !Number.isSafeInteger(rawRow["pickingIndex"]) || (rawRow["pickingIndex"] as number) < 0 ||
      typeof rawRow["pickingId"] !== "string"
    ) {
      return planFail("refused_gpu_lifecycle_plan_invalid", "picking row requires subjectVisibleId, a non-negative pickingIndex and a pickingId", "plan.pickingResolutions");
    }
    if (
      rawRow["uploadedToGpu"] !== false ||
      rawRow["authority"] !== "none" ||
      rawRow["executionAuthorized"] !== false
    ) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        "picking row must declare uploadedToGpu false, authority none, executionAuthorized false — identity never leaves the CPU",
        "plan.pickingResolutions",
      );
    }
  }

  // ── SELF-CONSISTENCY: sizeBytes must equal recordCount * strideBytes ──────
  for (const raw of buffers as Record<string, unknown>[]) {
    const product = checkedMul(raw["recordCount"] as number, raw["strideBytes"] as number);
    if (product === null || product !== raw["sizeBytes"]) {
      return planFail(
        "refused_gpu_lifecycle_plan_invalid",
        `buffer ${String(raw["bufferId"])} claims sizeBytes ${String(raw["sizeBytes"])} but recordCount * strideBytes is ${product === null ? "not a safe size" : String(product)} — the plan does not describe itself`,
        `plan.buffers.${String(raw["bufferId"])}.sizeBytes`,
      );
    }
  }

  // ── CONTENT INTEGRITY: re-derive 29D's planHash from the plan's content ───
  // (29I attack finding: before this check, plans with tampered buffer
  // contentHashes were accepted under the ORIGINAL planHash label. A hash
  // label nobody recomputes is a claim, not a commitment. The projection
  // below mirrors 29D's own EXACTLY — same fields, canonical key order.)
  const recomputedPlanHash = `plan_${canonicalHash({
    schemaVersion: plan["schemaVersion"],
    sceneHash: plan["sceneHash"],
    vertexLayoutId: GPU_LAYOUTS.vertex.layoutId,
    framesInFlight,
    buffers: (buffers as Record<string, unknown>[]).map((b) => ({
      bufferId: b["bufferId"],
      usage: b["usage"],
      contents: b["contents"],
      layout: b["layout"],
      strideBytes: b["strideBytes"],
      recordCount: b["recordCount"],
      sizeBytes: b["sizeBytes"],
      contentHash: b["contentHash"],
      lifecycle: b["lifecycle"],
    })),
    bindGroups: (bindGroups as Record<string, unknown>[]).map((b) => ({
      bindGroupId: b["bindGroupId"],
      bufferIds: b["bufferIds"],
    })),
    pipelines: (pipelines as Record<string, unknown>[]).map((p) => ({
      pipelineId: p["pipelineId"],
      vertexLayout: p["vertexLayout"],
      instanceLayout: p["instanceLayout"],
    })),
    passes: (passes as Record<string, unknown>[]).map((p) => ({
      passId: p["passId"],
      kind: p["kind"],
    })),
  })}`;
  if (recomputedPlanHash !== plan["planHash"]) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      `plan.planHash does not re-derive from the plan's own content (claimed ${String(plan["planHash"]).slice(0, 20)}…, recomputed ${recomputedPlanHash.slice(0, 20)}…) — a hash label nobody recomputes is a claim, not a commitment`,
      "plan.planHash",
    );
  }
  // Metadata the projection does NOT commit: shape-checked so a malformed
  // value still refuses. (Which of these fields is CONTENT vs LABEL is
  // recorded honestly in this gate's evidence — see limitations.)
  if (!isHash(plan["sourceVisibleHash"])) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.sourceVisibleHash must be a hex hash", "plan.sourceVisibleHash");
  }
  if (!isHash(plan["runtimeStateHash"]) || plan["runtimeStateHash"] === plan["sceneHash"]) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan.runtimeStateHash must be a hex hash distinct from sceneHash — SCENE_GRAPH != RUNTIME_STATE",
      "plan.runtimeStateHash",
    );
  }
  if (plan["vertexLayoutId"] !== GPU_LAYOUTS.vertex.layoutId) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      `plan.vertexLayoutId must be the canonical ${GPU_LAYOUTS.vertex.layoutId}`,
      "plan.vertexLayoutId",
    );
  }
  if (typeof plan["supportsHardware"] !== "boolean") {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.supportsHardware must be a boolean", "plan.supportsHardware");
  }
  const qv = plan["qualificationVerdict"];
  if (qv !== null && typeof qv !== "string") {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.qualificationVerdict must be a string or null", "plan.qualificationVerdict");
  }
  if (!Array.isArray(plan["notProven"]) || (plan["notProven"] as unknown[]).some((s) => typeof s !== "string")) {
    return planFail("refused_gpu_lifecycle_plan_invalid", "plan.notProven must be an array of strings — what was not proven is stated, not omitted", "plan.notProven");
  }
  const entryCount = plan["entryCount"];
  if (!Number.isSafeInteger(entryCount) || (entryCount as number) < pickingRows.length) {
    return planFail(
      "refused_gpu_lifecycle_plan_invalid",
      "plan.entryCount must be a non-negative safe integer covering at least one row per primitive",
      "plan.entryCount",
    );
  }
  return {
    ok: true,
    planHash: plan["planHash"] as string,
    sceneHash: plan["sceneHash"] as string,
    sourceFrameId: plan["sourceFrameId"] as string,
    framesInFlight: framesInFlight as number,
    buffers: buffers as unknown as readonly {
      readonly bufferId: string;
      readonly sizeBytes: number;
      readonly usage: readonly GpuBufferUsage[];
      readonly lifecycle: GpuResourceLifecycle;
    }[],
    totalBytes: total,
  };
};

// ── session validation (every operation validates what it is handed) ──────────

type SessionView = { ok: true; session: GpuResourceSession } | { ok: false };

const isHandleShaped = (raw: unknown, session: Record<string, unknown>): raw is GpuResourceHandle => {
  if (!isRecord(raw)) return false;
  const { bufferId, planHash, buildEpoch, allocatedAtGeneration, handleId } = raw;
  if (typeof bufferId !== "string" || bufferId.length === 0) return false;
  if (typeof planHash !== "string" || planHash !== session["boundPlanHash"]) return false;
  if (raw["sceneHash"] !== session["boundSceneHash"]) return false;
  if (!Number.isSafeInteger(buildEpoch) || !Number.isSafeInteger(allocatedAtGeneration)) return false;
  if (handleId !== deriveHandleId(planHash, bufferId, buildEpoch as number, allocatedAtGeneration as number)) {
    return false;
  }
  if (!inVocab(raw["state"], GPU_HANDLE_STATES)) return false;
  if (!inVocab(raw["invalidationReason"], GPU_HANDLE_INVALIDATION_REASONS)) return false;
  const sizeBytes = raw["sizeBytes"];
  if (typeof sizeBytes !== "number" || !Number.isSafeInteger(sizeBytes) || sizeBytes < 0) return false;
  if (sizeBytes > GPU_PLAN_BOUNDS.maxBufferBytes) return false;
  const uploadedBytes = raw["uploadedBytes"];
  if (typeof uploadedBytes !== "number" || !Number.isSafeInteger(uploadedBytes) || uploadedBytes < 0) return false;
  if (uploadedBytes > sizeBytes) return false;
  if (!Array.isArray(raw["usage"])) return false;
  for (const u of raw["usage"] as unknown[]) {
    if (!inVocab(u, GPU_BUFFER_USAGES)) return false;
  }
  if (!inVocab(raw["lifecycle"], GPU_RESOURCE_LIFECYCLES)) return false;
  if (
    raw["rebuildsFrom"] !== "getig_frame" ||
    raw["restoresRuntimeState"] !== false ||
    raw["ownerLayer"] !== "gpu_resource" ||
    raw["authority"] !== "none" ||
    raw["executionAuthorized"] !== false
  ) {
    return false;
  }
  return true;
};

/**
 * Structural validation of a session offered to an operation.
 *
 * Every id is RE-DERIVED, not read: a session whose `sessionId` or whose
 * handle ids do not re-derive from their own claimed bindings is a tampered
 * value and is refused as input, not repaired. The zero-authority fields are
 * checked the same way — a session claiming authority is not a session.
 */
const validateSession = (raw: unknown): SessionView => {
  if (!isRecord(raw)) return { ok: false };
  if (raw["schemaVersion"] !== GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION) return { ok: false };
  if (!inVocab(raw["state"], GPU_SESSION_STATES)) return { ok: false };
  const planHash = raw["boundPlanHash"];
  const sceneHash = raw["boundSceneHash"];
  const frameId = raw["boundFrameId"];
  if (typeof planHash !== "string" || !PLAN_HASH_SHAPE.test(planHash)) return { ok: false };
  if (!isHash(sceneHash)) return { ok: false };
  if (typeof frameId !== "string" || frameId.length === 0) return { ok: false };
  if (raw["sessionId"] !== deriveSessionId(planHash, sceneHash, frameId)) return { ok: false };
  const surfaceGeneration = raw["surfaceGeneration"];
  if (!Number.isSafeInteger(surfaceGeneration) || (surfaceGeneration as number) < 0) return { ok: false };
  if ((surfaceGeneration as number) >= GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations) return { ok: false };
  const lossEventCount = raw["lossEventCount"];
  const recoveryCount = raw["recoveryCount"];
  if (!Number.isSafeInteger(lossEventCount) || (lossEventCount as number) < 0) return { ok: false };
  if (!Number.isSafeInteger(recoveryCount) || (recoveryCount as number) < 0) return { ok: false };
  if ((recoveryCount as number) > GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles) return { ok: false };
  if ((recoveryCount as number) > (lossEventCount as number)) return { ok: false };
  if (raw["lossReason"] !== null && !inVocab(raw["lossReason"], GPU_LOSS_REASONS)) return { ok: false };
  const viewport = raw["viewport"];
  if (!isRecord(viewport)) return { ok: false };
  const { width, height, scale } = viewport as Record<string, unknown>;
  if (typeof width !== "number" || !Number.isSafeInteger(width) || width < 1) return { ok: false };
  if (typeof height !== "number" || !Number.isSafeInteger(height) || height < 1) return { ok: false };
  if (typeof scale !== "number" || !Number.isFinite(scale) || scale <= 0) return { ok: false };
  if ((width as number) > GPU_LIFECYCLE_BOUNDS.maxViewportDimension) return { ok: false };
  if ((height as number) > GPU_LIFECYCLE_BOUNDS.maxViewportDimension) return { ok: false };
  if ((scale as number) > GPU_LIFECYCLE_BOUNDS.maxViewportScale) return { ok: false };
  if (raw["contractEvidence"] !== "simulated_contract_tests") return { ok: false };
  if (!inVocab(raw["realDeviceLossEvidence"], GPU_REAL_DEVICE_EVIDENCE_STATES)) return { ok: false };
  if (typeof raw["realDeviceLossEvidenceNote"] !== "string") return { ok: false };
  if (!inVocab(raw["adapterDeviceRecreation"], GPU_ADAPTER_RECREATION_STATES)) return { ok: false };
  if (!Array.isArray(raw["notProven"])) return { ok: false };
  if (
    raw["authority"] !== "none" ||
    raw["controlPlane"] !== false ||
    raw["readOnly"] !== true ||
    raw["executionAuthorized"] !== false
  ) {
    return { ok: false };
  }
  const handles = raw["handles"];
  if (!Array.isArray(handles)) return { ok: false };
  if (handles.length > GPU_LIFECYCLE_BOUNDS.maxSessionHandles) return { ok: false };
  for (const h of handles) {
    if (!isHandleShaped(h, raw)) return { ok: false };
  }
  const liveCount = handles.filter((h) => isRecord(h) && h["state"] === "live").length;
  if (liveCount > GPU_LIFECYCLE_BOUNDS.maxLiveHandles) return { ok: false };
  return { ok: true, session: raw as unknown as GpuResourceSession };
};

const withHandles = (session: GpuResourceSession, handles: readonly GpuResourceHandle[]): GpuResourceSession =>
  Object.freeze({ ...session, handles: Object.freeze([...handles]) });

const withState = (session: GpuResourceSession, state: GpuSessionState): GpuResourceSession =>
  Object.freeze({ ...session, state });

/** Refuse unless the session is in one of the allowed states. */
const requireState = (
  session: GpuResourceSession,
  allowed: readonly GpuSessionState[],
  what: string,
): GpuLifecycleRefused | null => {
  if (allowed.includes(session.state)) return null;
  return refuse(
    "refused_gpu_lifecycle_state_invalid",
    `${what} requires session state ${allowed.join(" | ")}, but the session is '${session.state}'`,
    "session.state",
  );
};

// ── input validation for evidence ─────────────────────────────────────────────

type EvidenceView =
  | { ok: true; mode: GpuRecoveryEvidenceMode; realState: GpuRealDeviceEvidenceState; note: string; adapter: GpuAdapterRecreationState }
  | { ok: false; refusal: GpuLifecycleRefusalCode; explanation: string; field: string | null };

const EVIDENCE_RANK: Readonly<Record<GpuRealDeviceEvidenceState, number>> = Object.freeze({
  unavailable: 0,
  observed_readback_inconclusive: 1,
  observed_readback_matched: 2,
});

const ADAPTER_RANK: Readonly<Record<GpuAdapterRecreationState, number>> = Object.freeze({
  not_yet_attempted: 0,
  contract_simulated: 1,
  real_observed: 2,
});

const SIMULATED_NOTE =
  "real device-loss evidence unavailable: no device-loss injection harness exists in this workspace's test runtime (no WebGPU API here) and 29C-OBS-1 stands — texture readback returned all zeros on the target, so simulated contract tests are the honest mode";

/**
 * Judge the evidence offered alongside a recreation.
 *
 * `simulated_contract_tests` is the default and the honest mode here. A
 * `real_device_observation` claim REQUIRES a conforming observation; without
 * one it is evidence_unavailable (never silently downgraded to simulated), and
 * with a malformed or self-contradictory one it is evidence_invalid. The
 * readback field gates the outcome: a real observation whose readback did not
 * match can only reach `observed_readback_inconclusive`.
 */
const validateEvidence = (raw: unknown): EvidenceView => {
  const input = raw === undefined ? { mode: "simulated_contract_tests" as const } : raw;
  if (!isRecord(input)) {
    return { ok: false, refusal: "refused_gpu_lifecycle_input_invalid", explanation: "evidence must be an object", field: "evidence" };
  }
  const unknown = unknownField(input, ["mode", "observation"]);
  if (unknown !== null) {
    return { ok: false, refusal: "refused_gpu_lifecycle_input_invalid", explanation: `unknown evidence field: ${unknown}`, field: `evidence.${unknown}` };
  }
  const mode = input["mode"];
  if (!inVocab(mode, GPU_RECOVERY_EVIDENCE_MODES)) {
    return {
      ok: false,
      refusal: "refused_gpu_lifecycle_evidence_invalid",
      explanation: `evidence.mode ${String(mode)} is not in the closed vocabulary (${GPU_RECOVERY_EVIDENCE_MODES.join(", ")})`,
      field: "evidence.mode",
    };
  }
  if (mode === "simulated_contract_tests") {
    if (input["observation"] !== undefined) {
      return {
        ok: false,
        refusal: "refused_gpu_lifecycle_evidence_invalid",
        explanation: "a simulated_contract_tests claim must not carry a real-device observation",
        field: "evidence.observation",
      };
    }
    return { ok: true, mode, realState: "unavailable", note: SIMULATED_NOTE, adapter: "contract_simulated" };
  }
  const obs = input["observation"];
  if (obs === undefined || obs === null) {
    return {
      ok: false,
      refusal: "refused_gpu_lifecycle_evidence_unavailable",
      explanation: `real_device_observation claimed with no observation supplied; real device-loss evidence is UNAVAILABLE in this workspace (no injection harness; 29C-OBS-1 texture readback all zeros) — UNSUPPORTED != PASS`,
      field: "evidence.observation",
    };
  }
  if (!isRecord(obs)) {
    return { ok: false, refusal: "refused_gpu_lifecycle_evidence_invalid", explanation: "evidence.observation must be an object", field: "evidence.observation" };
  }
  const unknownObs = Object.keys(obs).filter(
    (k) => !(GPU_REAL_LOSS_OBSERVATION_FIELDS as readonly string[]).includes(k),
  );
  if (unknownObs.length > 0) {
    return {
      ok: false,
      refusal: "refused_gpu_lifecycle_evidence_invalid",
      explanation: `observation contains unrecognised field(s) ${unknownObs.join(", ")} — an ignored field reads as a read field`,
      field: `evidence.observation.${unknownObs[0] ?? ""}`,
    };
  }
  for (const field of GPU_REAL_LOSS_OBSERVATION_FIELDS) {
    if (obs[field] === undefined) {
      return {
        ok: false,
        refusal: "refused_gpu_lifecycle_evidence_invalid",
        explanation: `observation is missing ${field} — every field is required, negatives included`,
        field: `evidence.observation.${field}`,
      };
    }
  }
  for (const field of ["apiPresent", "adapterObtained", "deviceCreated", "lossObserved", "recreationSucceeded", "readbackMatchesExpectation"] as const) {
    if (typeof obs[field] !== "boolean") {
      return {
        ok: false,
        refusal: "refused_gpu_lifecycle_evidence_invalid",
        explanation: `observation.${field} must be a boolean`,
        field: `evidence.observation.${field}`,
      };
    }
  }
  if (typeof obs["userAgent"] !== "string" || (obs["userAgent"] as string).length === 0) {
    return {
      ok: false,
      refusal: "refused_gpu_lifecycle_evidence_invalid",
      explanation: "observation.userAgent must be a non-empty string",
      field: "evidence.observation.userAgent",
    };
  }
  const apiPresent = obs["apiPresent"] as boolean;
  const adapterObtained = obs["adapterObtained"] as boolean;
  const deviceCreated = obs["deviceCreated"] as boolean;
  const lossObserved = obs["lossObserved"] as boolean;
  const recreationSucceeded = obs["recreationSucceeded"] as boolean;
  const readbackMatches = obs["readbackMatchesExpectation"] as boolean;
  // A claim that cannot be true unless an earlier step succeeded is refused,
  // never reinterpreted: an observation may not claim more than it reached.
  const chain: readonly (readonly [boolean, boolean, string])[] = [
    [adapterObtained, apiPresent, "adapterObtained implies apiPresent"],
    [deviceCreated, adapterObtained, "deviceCreated implies adapterObtained"],
    [lossObserved, deviceCreated, "lossObserved implies deviceCreated"],
    [recreationSucceeded, lossObserved, "recreationSucceeded implies lossObserved"],
    [recreationSucceeded, apiPresent, "recreationSucceeded implies apiPresent"],
    [readbackMatches, recreationSucceeded, "readbackMatchesExpectation implies recreationSucceeded"],
  ];
  for (const [child, parent, why] of chain) {
    if (child && !parent) {
      return {
        ok: false,
        refusal: "refused_gpu_lifecycle_evidence_invalid",
        explanation: `observation inconsistent: ${why}`,
        field: "evidence.observation",
      };
    }
  }
  const realState: GpuRealDeviceEvidenceState = readbackMatches ? "observed_readback_matched" : "observed_readback_inconclusive";
  const note = readbackMatches
    ? "real device-loss observation recorded by the caller; it evidences loss-and-recreation only — power loss, thermal behaviour and hardware integrity remain unproven"
    : "real device-loss observation recorded, but its readback did not match what was rendered — SUBMITTED != RENDERED, so the evidence stops at observed_readback_inconclusive";
  return { ok: true, mode, realState, note, adapter: "real_observed" };
};

// ── the lifecycle operations ───────────────────────────────────────────────────

const NOT_PROVEN = Object.freeze([
  "no real device-loss injection was performed in this workspace: the test runtime exposes no WebGPU API, so loss is exercised only as a simulated contract event",
  "adapter/device recreation is evidenced by simulated contract tests; hardware recreation remains unobserved — 29C-OBS-1 (texture readback all zeros) still stands",
  "recovery rebuilds graphics resources only from the already-authorized 29D plan; no agent, task or runtime state was restored, replayed or resumed",
  "a GPU handle, old or new, confers zero authority: authority \"none\", executionAuthorized false",
  "ALLOCATED != SUBMITTED != RENDERED: nothing in this lifecycle draws, submits or reads back a pixel",
]);

/**
 * Bind a session to an authorized plan. No resources exist yet.
 *
 * State `created` is the only state from which arbitrary allocation is legal;
 * everything after a device loss must come back through
 * `recreateSessionDevice` and therefore through the plan.
 */
export function createGpuResourceSession(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session creation input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["plan", "viewport"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const view = validatePlan(input["plan"]);
  if (!view.ok) {
    return refuse(view.refusal, view.explanation, view.field);
  }
  const viewportRaw = input["viewport"];
  let viewport = { width: 1280, height: 720, scale: 1 };
  if (viewportRaw !== undefined) {
    if (!isRecord(viewportRaw)) {
      return refuse("refused_gpu_lifecycle_input_invalid", "viewport must be an object", "viewport");
    }
    const unknownViewport = unknownField(viewportRaw, ["width", "height", "scale"]);
    if (unknownViewport !== null) {
      return refuse("refused_gpu_lifecycle_input_invalid", `unknown viewport field: ${unknownViewport}`, `viewport.${unknownViewport}`);
    }
    const { width, height, scale } = viewportRaw as Record<string, unknown>;
    if (typeof width !== "number" || !Number.isSafeInteger(width) || width < 1 || typeof height !== "number" || !Number.isSafeInteger(height) || height < 1) {
      return refuse("refused_gpu_lifecycle_input_invalid", "viewport width and height must be positive integers", "viewport");
    }
    if (typeof scale !== "number" || !Number.isFinite(scale) || scale <= 0) {
      return refuse("refused_gpu_lifecycle_input_invalid", "viewport scale must be a finite positive number", "viewport.scale");
    }
    if ((width as number) > GPU_LIFECYCLE_BOUNDS.maxViewportDimension || (height as number) > GPU_LIFECYCLE_BOUNDS.maxViewportDimension) {
      return refuse(
        "refused_gpu_lifecycle_cap_exceeded",
        `viewport ${String(width)}x${String(height)} exceeds GPU_LIFECYCLE_BOUNDS.maxViewportDimension ${GPU_LIFECYCLE_BOUNDS.maxViewportDimension}`,
        "viewport",
      );
    }
    if ((scale as number) > GPU_LIFECYCLE_BOUNDS.maxViewportScale) {
      return refuse(
        "refused_gpu_lifecycle_cap_exceeded",
        `viewport scale ${String(scale)} exceeds GPU_LIFECYCLE_BOUNDS.maxViewportScale ${GPU_LIFECYCLE_BOUNDS.maxViewportScale}`,
        "viewport.scale",
      );
    }
    viewport = { width: width as number, height: height as number, scale: scale as number };
  }
  const session = Object.freeze({
    schemaVersion: GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION,
    sessionId: deriveSessionId(view.planHash, view.sceneHash, view.sourceFrameId),
    state: "created" as const,
    boundPlanHash: view.planHash,
    boundSceneHash: view.sceneHash,
    boundFrameId: view.sourceFrameId,
    surfaceGeneration: 0,
    viewport: Object.freeze(viewport),
    handles: Object.freeze([] as readonly GpuResourceHandle[]),
    lossEventCount: 0,
    recoveryCount: 0,
    lossReason: null,
    contractEvidence: "simulated_contract_tests" as const,
    realDeviceLossEvidence: "unavailable" as const,
    realDeviceLossEvidenceNote: SIMULATED_NOTE,
    adapterDeviceRecreation: "not_yet_attempted" as const,
    notProven: NOT_PROVEN,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  });
  return ok(session);
}

/**
 * Allocate the session's first resources — only from state `created`.
 *
 * Each request is `recordCount * strideBytes` through `checkedMul`; a null
 * product refuses before any handle exists, each result is compared against
 * its per-usage ceiling from `GPU_PLAN_BOUNDS`, and the batch is counted
 * against the live-handle cap and the total-byte ceiling. There is no clamp
 * and no truncation path: a request that does not fit is a refusal.
 */
export function allocateSessionResources(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "allocation input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "allocations"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation (ids do not re-derive, bounds violated, or a zero-authority field was non-zero)", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["created"], "allocation");
  if (stateRefusal !== null) return stateRefusal;
  const allocations = input["allocations"];
  if (!Array.isArray(allocations) || allocations.length === 0) {
    return refuse("refused_gpu_lifecycle_input_invalid", "allocations must be a non-empty array", "allocations");
  }
  if (allocations.length > GPU_LIFECYCLE_BOUNDS.maxLiveHandles) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `allocation request of ${allocations.length} handles exceeds GPU_LIFECYCLE_BOUNDS.maxLiveHandles ${GPU_LIFECYCLE_BOUNDS.maxLiveHandles}`,
      "allocations",
    );
  }
  const fresh: GpuResourceHandle[] = [];
  let totalBytes = 0;
  for (let i = 0; i < allocations.length; i += 1) {
    const raw = allocations[i];
    if (!isRecord(raw)) {
      return refuse("refused_gpu_lifecycle_input_invalid", `allocations[${i}] must be an object`, `allocations[${i}]`);
    }
    const unknownAlloc = unknownField(raw, ["bufferId", "recordCount", "strideBytes", "usage"]);
    if (unknownAlloc !== null) {
      return refuse("refused_gpu_lifecycle_input_invalid", `allocations[${i}] unknown field: ${unknownAlloc}`, `allocations[${i}].${unknownAlloc}`);
    }
    const bufferId = raw["bufferId"];
    if (typeof bufferId !== "string" || bufferId.length === 0) {
      return refuse("refused_gpu_lifecycle_input_invalid", `allocations[${i}].bufferId is required`, `allocations[${i}].bufferId`);
    }
    const usageRaw = raw["usage"];
    if (!Array.isArray(usageRaw) || usageRaw.length === 0) {
      return refuse("refused_gpu_lifecycle_input_invalid", `allocations[${i}].usage must be a non-empty array`, `allocations[${i}].usage`);
    }
    for (const u of usageRaw as unknown[]) {
      if (!inVocab(u, GPU_BUFFER_USAGES)) {
        return refuse("refused_gpu_lifecycle_input_invalid", `allocations[${i}].usage contains unknown value ${String(u)}`, `allocations[${i}].usage`);
      }
    }
    const usage = usageRaw as readonly GpuBufferUsage[];
    const sizeBytes = checkedMul(raw["recordCount"] as number, raw["strideBytes"] as number);
    if (sizeBytes === null) {
      return refuse(
        "refused_gpu_lifecycle_size_overflow",
        `allocations[${i}] recordCount ${String(raw["recordCount"])} * strideBytes ${String(raw["strideBytes"])} did not yield a safe non-negative size; a wrapped size is a small allocation claimed to be a large one`,
        `allocations[${i}]`,
      );
    }
    const ceiling = usageCeiling(usage);
    if (sizeBytes > ceiling) {
      return refuse(
        "refused_gpu_lifecycle_cap_exceeded",
        `allocations[${i}] size ${sizeBytes} B exceeds its usage ceiling ${ceiling} B (GPU_PLAN_BOUNDS) — refused, never clamped`,
        `allocations[${i}]`,
      );
    }
    if (totalBytes + sizeBytes > GPU_PLAN_BOUNDS.maxBufferBytes) {
      return refuse(
        "refused_gpu_lifecycle_cap_exceeded",
        `batch would bring the session to ${totalBytes + sizeBytes} B, over GPU_PLAN_BOUNDS.maxBufferBytes ${GPU_PLAN_BOUNDS.maxBufferBytes}`,
        `allocations[${i}]`,
      );
    }
    totalBytes += sizeBytes;
    // Mirrors 29D's own assignment: uniform and storage tables are functions
    // of the frame (a resize makes them stale); vertex and index geometry
    // changes only with the scene.
    const lifecycle: GpuResourceLifecycle = usage.includes("uniform") || usage.includes("storage")
      ? "frame_scoped"
      : "scene_scoped";
    fresh.push(
      Object.freeze({
        handleId: deriveHandleId(session.boundPlanHash, bufferId, session.lossEventCount, session.surfaceGeneration),
        bufferId,
        planHash: session.boundPlanHash,
        sceneHash: session.boundSceneHash,
        allocatedAtGeneration: session.surfaceGeneration,
        buildEpoch: session.lossEventCount,
        sizeBytes,
        usage: Object.freeze([...usage]),
        lifecycle,
        state: "live" as const,
        invalidationReason: "none" as const,
        uploadedBytes: 0,
        rebuildsFrom: "getig_frame" as const,
        restoresRuntimeState: false as const,
        ownerLayer: "gpu_resource" as const,
        authority: "none" as const,
        executionAuthorized: false as const,
      }),
    );
  }
  if (fresh.length > GPU_LIFECYCLE_BOUNDS.maxLiveHandles) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `batch of ${fresh.length} handles exceeds GPU_LIFECYCLE_BOUNDS.maxLiveHandles ${GPU_LIFECYCLE_BOUNDS.maxLiveHandles}`,
      "allocations",
    );
  }
  const next = withState(withHandles(session, fresh), "allocated");
  return ok(next, fresh[0] ?? null);
}

/**
 * Record a guarded upload volume against a LIVE handle.
 *
 * A byte length beyond the handle's own size is `cap_exceeded` — refused, not
 * clamped. Naming an invalidated, released or unknown handle is
 * `stale_resource`, and the explanation says plainly what an old handle is
 * worth: nothing.
 */
export function uploadToSessionHandle(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "upload input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "handleId", "byteLength", "contentHash"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["allocated"], "upload");
  if (stateRefusal !== null) return stateRefusal;
  const handleId = input["handleId"];
  if (typeof handleId !== "string" || handleId.length === 0) {
    return refuse("refused_gpu_lifecycle_input_invalid", "handleId is required", "handleId");
  }
  const target = session.handles.find((h) => h.handleId === handleId);
  if (target === undefined || target.state !== "live") {
    return refuse(
      "refused_gpu_lifecycle_stale_resource",
      `handle ${handleId} is ${target === undefined ? "unknown to this session" : `'${target.state}' (reason: ${target.invalidationReason})`} — an old or retired GPU handle confers no authority and accepts no upload`,
      "handleId",
    );
  }
  const byteLength = input["byteLength"];
  if (typeof byteLength !== "number" || !Number.isSafeInteger(byteLength)) {
    return refuse(
      "refused_gpu_lifecycle_size_overflow",
      `byteLength ${String(byteLength)} is not a safe integer; a wrapped byte count is a small upload claimed to be a large one`,
      "byteLength",
    );
  }
  if (byteLength < 0) {
    return refuse("refused_gpu_lifecycle_input_invalid", "byteLength must be non-negative", "byteLength");
  }
  const cap = Math.min(target.sizeBytes, GPU_PLAN_BOUNDS.maxBufferBytes);
  if (byteLength > cap) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `upload of ${byteLength} B exceeds the handle's ${target.sizeBytes} B (plan ceiling ${cap} B) — refused, never truncated`,
      "byteLength",
    );
  }
  const contentHash = input["contentHash"];
  if (contentHash !== undefined && (typeof contentHash !== "string" || !HEX64.test(contentHash))) {
    return refuse("refused_gpu_lifecycle_input_invalid", "contentHash must be 64 hex characters", "contentHash");
  }
  const nextHandles = session.handles.map((h) =>
    h.handleId === handleId ? Object.freeze({ ...h, uploadedBytes: h.uploadedBytes + byteLength }) : h,
  );
  const updated = nextHandles.find((h) => h.handleId === handleId) ?? target;
  return ok(withHandles(session, nextHandles), updated);
}

/**
 * Reconfigure the surface: bump the generation, swap the viewport, and
 * invalidate `frame_scoped` handles — because the viewport uniform and picking
 * table are functions of the frame and a new generation makes the old ones
 * stale. `scene_scoped` and `persistent` handles survive; they are not
 * surface-dependent, and invalidating them would be theatre, not safety.
 */
export function resizeSessionSurface(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "resize input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "width", "height", "scale"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["allocated"], "resize");
  if (stateRefusal !== null) return stateRefusal;
  const { width, height, scale } = input as Record<string, unknown>;
  if (typeof width !== "number" || !Number.isSafeInteger(width) || width < 1 || typeof height !== "number" || !Number.isSafeInteger(height) || height < 1) {
    return refuse("refused_gpu_lifecycle_input_invalid", "width and height must be positive integers", "width");
  }
  if (typeof scale !== "number" || !Number.isFinite(scale) || scale <= 0) {
    return refuse("refused_gpu_lifecycle_input_invalid", "scale must be a finite positive number", "scale");
  }
  if (width > GPU_LIFECYCLE_BOUNDS.maxViewportDimension || height > GPU_LIFECYCLE_BOUNDS.maxViewportDimension) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `viewport ${width}x${height} exceeds GPU_LIFECYCLE_BOUNDS.maxViewportDimension ${GPU_LIFECYCLE_BOUNDS.maxViewportDimension}`,
      "width",
    );
  }
  if (scale > GPU_LIFECYCLE_BOUNDS.maxViewportScale) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `scale ${scale} exceeds GPU_LIFECYCLE_BOUNDS.maxViewportScale ${GPU_LIFECYCLE_BOUNDS.maxViewportScale}`,
      "scale",
    );
  }
  const nextGeneration = session.surfaceGeneration + 1;
  if (nextGeneration >= GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `surface generation ${nextGeneration} would reach GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations ${GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations} — repeated reconfiguration is bounded and fails closed`,
      "session.surfaceGeneration",
    );
  }
  const nextHandles = session.handles.map((h) =>
    h.state === "live" && h.lifecycle === "frame_scoped"
      ? Object.freeze({ ...h, state: "invalidated" as const, invalidationReason: "surface_resize" as const })
      : h,
  );
  const next: GpuResourceSession = Object.freeze({
    ...session,
    surfaceGeneration: nextGeneration,
    viewport: Object.freeze({ width, height, scale }),
    handles: Object.freeze([...nextHandles]),
  });
  return ok(next);
}

/**
 * The device-loss transition.
 *
 * Loss itself is NEVER refused — a dying device is not making a request. What
 * it does, atomically with the state flip: invalidates EVERY live handle
 * (reason `device_loss`), so there is no window where the session says `lost`
 * while a handle still says `live`, and counts the loss against the bounded
 * recovery budget that `recreateSessionDevice` will spend.
 */
export function markSessionDeviceLost(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "device-loss input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "reason"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["created", "allocated"], "device loss");
  if (stateRefusal !== null) return stateRefusal;
  const reason = input["reason"];
  if (!inVocab(reason, GPU_LOSS_REASONS)) {
    return refuse(
      "refused_gpu_lifecycle_input_invalid",
      `reason ${String(reason)} is not in the closed vocabulary (${GPU_LOSS_REASONS.join(", ")})`,
      "reason",
    );
  }
  const nextHandles = session.handles.map((h) =>
    h.state === "live"
      ? Object.freeze({ ...h, state: "invalidated" as const, invalidationReason: "device_loss" as const })
      : h,
  );
  const next: GpuResourceSession = Object.freeze({
    ...session,
    state: "lost" as const,
    handles: Object.freeze([...nextHandles]),
    lossEventCount: session.lossEventCount + 1,
    lossReason: reason,
  });
  return ok(next);
}

/**
 * The ONLY road back from `lost`, and it reads one thing: the session's
 * already-authorized plan.
 *
 * Requirements, all fail-closed: the session must be `lost`; the recovery
 * budget (GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles) must not be spent; the
 * plan must parse as a well-formed zero-authority 29D plan AND match the
 * session's plan/scene/frame binding; the evidence must be a mode this
 * workspace can honestly stand behind. Fresh handles are re-derived from the
 * plan's buffer descriptors — recovery rebuilds graphics, never anything else.
 */
export function recreateSessionDevice(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "recreation input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "plan", "evidence"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["lost"], "recreation");
  if (stateRefusal !== null) return stateRefusal;
  if (session.recoveryCount + 1 > GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles) {
    return refuse(
      "refused_gpu_lifecycle_loss_budget_exceeded",
      `recovery ${session.recoveryCount + 1} would exceed GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles ${GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles}; repeated loss/recovery is bounded and fails closed`,
      "session.recoveryCount",
    );
  }
  const view = validatePlan(input["plan"]);
  if (!view.ok) {
    return refuse(view.refusal, view.explanation, view.field);
  }
  if (
    view.planHash !== session.boundPlanHash ||
    view.sceneHash !== session.boundSceneHash ||
    view.sourceFrameId !== session.boundFrameId
  ) {
    return refuse(
      "refused_gpu_lifecycle_plan_mismatch",
      "rebuild sources only from the ALREADY-AUTHORIZED GETIG frame/scene/plan bound to this session; a different plan confers nothing — GPU_RECOVERY != RUNTIME_RECOVERY",
      "plan.planHash",
    );
  }
  const evidence = validateEvidence(input["evidence"]);
  if (!evidence.ok) {
    return refuse(evidence.refusal, evidence.explanation, evidence.field);
  }
  if (session.handles.length + view.buffers.length > GPU_LIFECYCLE_BOUNDS.maxSessionHandles) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `recreation would bring the session to ${session.handles.length + view.buffers.length} handles, over GPU_LIFECYCLE_BOUNDS.maxSessionHandles ${GPU_LIFECYCLE_BOUNDS.maxSessionHandles}`,
      "session.handles",
    );
  }
  const fresh: GpuResourceHandle[] = view.buffers.map((b) =>
    Object.freeze({
      handleId: deriveHandleId(session.boundPlanHash, b.bufferId, session.lossEventCount, session.surfaceGeneration),
      bufferId: b.bufferId,
      planHash: session.boundPlanHash,
      sceneHash: session.boundSceneHash,
      allocatedAtGeneration: session.surfaceGeneration,
      buildEpoch: session.lossEventCount,
      sizeBytes: b.sizeBytes,
      usage: Object.freeze([...b.usage]),
      lifecycle: b.lifecycle,
      state: "live" as const,
      invalidationReason: "none" as const,
      uploadedBytes: 0,
      rebuildsFrom: "getig_frame" as const,
      restoresRuntimeState: false as const,
      ownerLayer: "gpu_resource" as const,
      authority: "none" as const,
      executionAuthorized: false as const,
    }),
  );
  const liveAfter = liveOf(session.handles).length + fresh.length;
  if (liveAfter > GPU_LIFECYCLE_BOUNDS.maxLiveHandles) {
    return refuse(
      "refused_gpu_lifecycle_cap_exceeded",
      `recreation would produce ${liveAfter} live handles, over GPU_LIFECYCLE_BOUNDS.maxLiveHandles ${GPU_LIFECYCLE_BOUNDS.maxLiveHandles}`,
      "plan.buffers",
    );
  }
  const next: GpuResourceSession = Object.freeze({
    ...session,
    state: "allocated" as const,
    handles: Object.freeze([...session.handles, ...fresh]),
    recoveryCount: session.recoveryCount + 1,
    // Evidence only ever UPGRADES: a later simulated recreation must not
    // erase a real observation already recorded (supersede, never erase).
    realDeviceLossEvidence:
      EVIDENCE_RANK[evidence.realState] >= EVIDENCE_RANK[session.realDeviceLossEvidence]
        ? evidence.realState
        : session.realDeviceLossEvidence,
    realDeviceLossEvidenceNote:
      EVIDENCE_RANK[evidence.realState] >= EVIDENCE_RANK[session.realDeviceLossEvidence]
        ? evidence.note
        : session.realDeviceLossEvidenceNote,
    adapterDeviceRecreation:
      ADAPTER_RANK[evidence.adapter] >= ADAPTER_RANK[session.adapterDeviceRecreation]
        ? evidence.adapter
        : session.adapterDeviceRecreation,
  });
  return ok(next, fresh[0] ?? null);
}

/**
 * Ask one question of one handle: is it live, and what is it worth?
 *
 * The answer to the second half is always nothing — `executionAuthorized`
 * false on the decision, `authority: "none"` on the handle — but the first
 * half is how stale invalidation becomes OBSERVABLE rather than merely
 * documented: an unknown, invalidated or released handle refuses with
 * `stale_resource` and the words "confers no authority".
 */
export function verifySessionHandle(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "verify input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session", "handleId"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const handleId = input["handleId"];
  if (typeof handleId !== "string" || handleId.length === 0) {
    return refuse("refused_gpu_lifecycle_input_invalid", "handleId is required", "handleId");
  }
  const target = session.handles.find((h) => h.handleId === handleId);
  if (target === undefined) {
    return refuse(
      "refused_gpu_lifecycle_stale_resource",
      `handle ${handleId} is unknown to this session — an old or foreign GPU handle confers no authority`,
      "handleId",
    );
  }
  if (target.state !== "live") {
    return refuse(
      "refused_gpu_lifecycle_stale_resource",
      `handle ${handleId} is '${target.state}' (reason: ${target.invalidationReason}) — an old or retired GPU handle confers no authority`,
      "handleId",
    );
  }
  return ok(session, target);
}

/**
 * Cleanup: release every handle and close the session, from ANY non-released
 * state — including `lost`, because cleanup must never sit behind the same
 * budget that gates recovery. A released session is terminal: no operation
 * restarts it, and double-release refuses rather than silently succeeding.
 */
export function releaseSessionResources(input: unknown): GpuLifecycleDecision {
  if (!isRecord(input)) {
    return refuse("refused_gpu_lifecycle_input_invalid", "release input must be an object");
  }
  const forbidden = forbidRuntimeFields(input);
  if (forbidden !== null) return forbidden;
  const unknown = unknownField(input, ["session"]);
  if (unknown !== null) {
    return refuse("refused_gpu_lifecycle_input_invalid", `unknown input field: ${unknown}`, unknown);
  }
  const checked = validateSession(input["session"]);
  if (!checked.ok) {
    return refuse("refused_gpu_lifecycle_input_invalid", "session failed structural validation", "session");
  }
  const session = checked.session;
  const stateRefusal = requireState(session, ["created", "allocated", "lost"], "release");
  if (stateRefusal !== null) return stateRefusal;
  const nextHandles = session.handles.map((h) =>
    h.state === "live"
      ? Object.freeze({ ...h, state: "released" as const, invalidationReason: "session_release" as const })
      : h,
  );
  const next = withState(withHandles(session, nextHandles), "released");
  return ok(next);
}

/**
 * The always-refusing guard: GPU_RECOVERY != RUNTIME_RECOVERY, as an exit
 * code the suite can drive.
 *
 * It cannot succeed under any input. It also NAMES the runtime-shaped fields
 * it found in the offered input (at the top level — this module never reaches
 * into a payload it would not accept anyway), so a test can prove the
 * vocabulary is live rather than decorative. There is no restore, replay or
 * resume function in this module at all; the guard exists so the law is
 * TESTABLE rather than merely absent.
 */
export function refuseGpuRecoveryRuntimeRestore(input: unknown): {
  readonly ok: false;
  readonly code: "recovery_refused";
  readonly refusal: "refused_gpu_lifecycle_runtime_restore_forbidden";
  readonly explanation: string;
  readonly detectedFields: readonly string[];
  readonly restoredRuntimeState: false;
  readonly replayedTaskState: false;
  readonly resumedAgentState: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
} {
  const detected = isRecord(input)
    ? Object.keys(input).filter((k) => (GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS as readonly string[]).includes(k))
    : [];
  return {
    ok: false,
    code: "recovery_refused",
    refusal: "refused_gpu_lifecycle_runtime_restore_forbidden",
    explanation:
      "GPU_RECOVERY != RUNTIME_RECOVERY: graphics resources may be rebuilt from the authorized GETIG plan, but agent, task and runtime state is never restored, replayed or resumed here — and no input, old handle or recovered device changes that",
    detectedFields: Object.freeze([...detected]),
    restoredRuntimeState: false,
    replayedTaskState: false,
    resumedAgentState: false,
    authority: "none",
    controlPlane: false,
    readOnly: true,
    executionAuthorized: false,
  };
}
