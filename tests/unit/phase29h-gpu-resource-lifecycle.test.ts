/**
 * PHASE 29H — GPU RESOURCE SAFETY & DEVICE-LOSS RECOVERY — REGRESSION SUITE
 *
 * MODE: GRAPHICS-ONLY RECOVERY / SIMULATED CONTRACT TESTS / NO GPU / NO RUNTIME / NO DEPENDENCY.
 *
 * Central laws under test:
 *   GPU_RECOVERY != RUNTIME_RECOVERY
 *   ALLOCATED    != SUBMITTED != RENDERED
 *   OLD GPU HANDLE != AUTHORITY
 *   SIMULATED CONTRACT EVIDENCE != REAL DEVICE EVIDENCE
 *
 * One describe block per pack requirement:
 *   1.  explicit resource caps
 *   2.  allocation/upload size guards
 *   3.  resize/reconfigure
 *   4.  stale resource invalidation
 *   5.  cleanup
 *   6.  device-loss transition
 *   7.  adapter/device recreation where supported
 *   8.  rebuild graphics only from already-authorized GETIG frame/scene/plan
 *   9.  never restore/replay/resume agent/task/runtime state
 *   10. old GPU handle confers no authority
 *   11. simulated contract tests vs real device evidence (honestly distinguished)
 *
 * Plus control-path scans (export surface, import surface, forbidden-token
 * CODE scan with planted positive controls) and set-equality reachability over
 * every declared refusal code (29H-R).
 *
 * The happy path runs on the REAL frozen chain (28J scenario -> 29B scene ->
 * 29D plan). Synthetic sessions/plans appear only where a case needs an input
 * the frozen chain cannot produce (a tampered plan, a second plan, an
 * oversized batch) — and each such case asserts a REFUSAL, never a successful
 * resource.
 *
 * Evidence mode is SIMULATED CONTRACT TESTS throughout: this test runtime has
 * no WebGPU API, and 29C-OBS-1 (texture readback all zeros) stands. Block
 * 29H-11 proves the module says exactly that in explicit fields instead of
 * implying real device evidence exists.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  GPU_LIFECYCLE_BOUNDS,
  GPU_LIFECYCLE_REFUSAL_CODES,
  GPU_ADAPTER_RECREATION_STATES,
  GPU_HANDLE_STATES,
  GPU_LOSS_REASONS,
  GPU_REAL_DEVICE_EVIDENCE_STATES,
  GPU_REAL_LOSS_OBSERVATION_FIELDS,
  GPU_RECOVERY_EVIDENCE_MODES,
  GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS,
  GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION,
  GPU_SESSION_STATES,
  GPU_SESSION_TRANSITIONS,
  PHASE29H_FORBIDDEN_TOKENS,
  QUALIFICATION_VERDICTS,
  allocateSessionResources,
  buildGpuRenderPlan,
  compileGetigScene,
  createGpuResourceSession,
  getigVisualSemanticRank,
  markSessionDeviceLost,
  recreateSessionDevice,
  refuseGpuRecoveryRuntimeRestore,
  releaseSessionResources,
  resizeSessionSurface,
  runGetigEndToEndScenario,
  uploadToSessionHandle,
  verifySessionHandle,
  type GpuResourceHandle,
  type GpuResourceSession,
} from "../../packages/durable-state/src/index.js";
import * as lifecycleSurface from "../../packages/durable-state/src/gpuResourceLifecycle.js";

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

/** A REAL second plan (different mapping -> different sceneHash) for mismatch tests. */
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
    frameId: "frame-29h-b",
    observerId: "observer-local-a",
    mappingHash: "abcdef0123456789",
    tokens: [token({ axis: "knowledge", semanticValue: "known", subjectVisibleId: "node-local" })],
  },
  runtimeStateHash: RUNTIME_HASH,
});
if (!compiledB.ok) throw new Error(`second scene compile refused: ${compiledB.refusal}`);
const planB = buildGpuRenderPlan({ scene: compiledB.scene });
if (!planB.ok) throw new Error(`second plan refused: ${planB.refusal}`);
const PLAN_B = planB.plan;
expect(compiledB.scene.sceneHash).not.toBe(SCENE.sceneHash);

// ── helpers ───────────────────────────────────────────────────────────────────

type Dec = ReturnType<typeof createGpuResourceSession>;

const freshSession = (): GpuResourceSession => {
  const d = createGpuResourceSession({ plan: PLAN });
  if (!d.ok) throw new Error(`create refused: ${d.refusal}: ${d.explanation}`);
  return d.session;
};

const ALLOC = [
  { bufferId: "buf.vertex.primitive", recordCount: 35, strideBytes: 32, usage: ["vertex", "copy-dst"] },
  { bufferId: "buf.uniform.viewport", recordCount: 1, strideBytes: 32, usage: ["uniform", "copy-dst"] },
  { bufferId: "buf.storage.pickingIndex", recordCount: 35, strideBytes: 4, usage: ["storage", "copy-dst"] },
];

const allocOf = (session: unknown, allocations: unknown = ALLOC): GpuResourceSession => {
  const d = allocateSessionResources({ session, allocations });
  if (!d.ok) throw new Error(`allocate refused: ${d.refusal}: ${d.explanation}`);
  return d.session;
};

const allocatedSession = (): GpuResourceSession => allocOf(freshSession());

const lostFrom = (session: GpuResourceSession, reason: unknown = "simulated_contract_event"): GpuResourceSession => {
  const d = markSessionDeviceLost({ session, reason });
  if (!d.ok) throw new Error(`loss refused: ${d.refusal}: ${d.explanation}`);
  return d.session;
};

const recoveredFrom = (session: GpuResourceSession): GpuResourceSession => {
  const d = recreateSessionDevice({ session, plan: PLAN });
  if (!d.ok) throw new Error(`recreate refused: ${d.refusal}: ${d.explanation}`);
  return d.session;
};

const lostSession = (): GpuResourceSession => lostFrom(allocatedSession());

const liveHandles = (s: GpuResourceSession): GpuResourceHandle[] => s.handles.filter((h) => h.state === "live");

const firstLive = (s: GpuResourceSession): GpuResourceHandle => {
  const h = liveHandles(s)[0];
  if (!h) throw new Error("no live handle");
  return h;
};

/** Assert a refusal: fail-closed shape, null outputs, zero authority. */
const refOf = (d: Dec, code: string): Extract<Dec, { ok: false }> => {
  expect(d.ok).toBe(false);
  if (d.ok) throw new Error(`expected refusal ${code}, got success`);
  expect(d.refusal).toBe(code);
  expect(d.session).toBeNull();
  expect(d.handle).toBeNull();
  expect(d.authority).toBe("none");
  expect(d.controlPlane).toBe(false);
  expect(d.readOnly).toBe(true);
  expect(d.executionAuthorized).toBe(false);
  expect(d.explanation.length).toBeGreaterThan(0);
  return d;
};

const tamperedPlan = (): Record<string, unknown> =>
  JSON.parse(JSON.stringify(PLAN)) as Record<string, unknown>;

const realObs = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  apiPresent: true,
  adapterObtained: true,
  deviceCreated: true,
  lossObserved: true,
  recreationSucceeded: true,
  readbackMatchesExpectation: false,
  userAgent: "menog-test-agent",
  ...over,
});

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

// ── source scanner (29E/29F/29G technique: comments and strings stripped) ─────

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
  new URL("../../packages/durable-state/src/gpuResourceLifecycle.ts", import.meta.url),
  "utf8",
);
const MODULE_CODE = stripLiterals(MODULE_SRC);

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-1 — explicit resource caps", () => {
  it("GPU_LIFECYCLE_BOUNDS declares exactly the six lifecycle caps, with the expected values", () => {
    expect(Object.keys(GPU_LIFECYCLE_BOUNDS).sort()).toEqual(
      [
        "maxLiveHandles",
        "maxSessionHandles",
        "maxLossRecoveryCycles",
        "maxSurfaceGenerations",
        "maxViewportDimension",
        "maxViewportScale",
      ].sort(),
    );
    expect(GPU_LIFECYCLE_BOUNDS.maxLiveHandles).toBe(64);
    expect(GPU_LIFECYCLE_BOUNDS.maxSessionHandles).toBe(256);
    expect(GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles).toBe(8);
    expect(GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations).toBe(256);
    expect(GPU_LIFECYCLE_BOUNDS.maxViewportDimension).toBe(16384);
    expect(GPU_LIFECYCLE_BOUNDS.maxViewportScale).toBe(4);
  });

  it("byte caps are NOT re-declared — the module references 29D's GPU_PLAN_BOUNDS instead", () => {
    for (const byteCap of ["maxBufferBytes", "maxVertexBytes", "maxIndexBytes", "maxUniformBytes", "maxStorageBytes", "maxFramesInFlight"]) {
      expect(Object.keys(GPU_LIFECYCLE_BOUNDS)).not.toContain(byteCap);
    }
    // The imported identifier really is used at points of use in CODE.
    expect(MODULE_CODE.match(/GPU_PLAN_BOUNDS\./g)?.length ?? 0).toBeGreaterThanOrEqual(6);
  });

  it("the live-handle cap refuses a batch over 64 instead of truncating it", () => {
    const d = allocateSessionResources({
      session: freshSession(),
      allocations: Array.from({ length: GPU_LIFECYCLE_BOUNDS.maxLiveHandles + 1 }, () => ({})),
    });
    const r = refOf(d, "refused_gpu_lifecycle_cap_exceeded");
    expect(r.explanation).toContain("maxLiveHandles");
    expect(r.explanation).not.toContain("truncat");
  });

  it("viewport caps refuse at create and at resize, never clamp", () => {
    const wide = refOf(
      createGpuResourceSession({
        plan: PLAN,
        viewport: { width: GPU_LIFECYCLE_BOUNDS.maxViewportDimension + 1, height: 720, scale: 1 },
      }),
      "refused_gpu_lifecycle_cap_exceeded",
    );
    expect(wide.offendingField).toBe("viewport");
    const scaled = refOf(
      createGpuResourceSession({
        plan: PLAN,
        viewport: { width: 1280, height: 720, scale: GPU_LIFECYCLE_BOUNDS.maxViewportScale + 1 },
      }),
      "refused_gpu_lifecycle_cap_exceeded",
    );
    expect(scaled.offendingField).toBe("viewport.scale");
    const resizeCap = refOf(
      resizeSessionSurface({
        session: allocatedSession(),
        width: GPU_LIFECYCLE_BOUNDS.maxViewportDimension + 1,
        height: 720,
        scale: 1,
      }),
      "refused_gpu_lifecycle_cap_exceeded",
    );
    expect(resizeCap.explanation).toContain("maxViewportDimension");
  });

  it("plan structural caps (framesInFlight, pipelines, passes) are enforced at session creation too", () => {
    const fif = tamperedPlan();
    fif["framesInFlight"] = 4; // GPU_PLAN_BOUNDS.maxFramesInFlight is 3
    refOf(createGpuResourceSession({ plan: fif }), "refused_gpu_lifecycle_cap_exceeded");

    const pipes = tamperedPlan();
    const pipeArr = pipes["pipelines"] as unknown[];
    pipes["pipelines"] = [...pipeArr, ...pipeArr, pipeArr[0]]; // 9 > maxPipelines 8
    refOf(createGpuResourceSession({ plan: pipes }), "refused_gpu_lifecycle_cap_exceeded");

    const passArr = tamperedPlan();
    const passes = passArr["passes"] as unknown[];
    passArr["passes"] = [...passes, ...passes, passes[0]]; // 5 > maxPasses 4
    refOf(createGpuResourceSession({ plan: passArr }), "refused_gpu_lifecycle_cap_exceeded");
  });

  it("the session state machine declares closed transitions: released is terminal, lost admits only recreation or release", () => {
    expect([...GPU_SESSION_STATES].sort()).toEqual(["allocated", "created", "lost", "released"].sort());
    expect([...GPU_SESSION_TRANSITIONS.released]).toEqual([]);
    expect([...GPU_SESSION_TRANSITIONS.lost].sort()).toEqual(["allocated", "released"].sort());
    expect([...GPU_SESSION_TRANSITIONS.created].sort()).toEqual(["allocated", "lost", "released"].sort());
    expect([...GPU_HANDLE_STATES].sort()).toEqual(["invalidated", "live", "released"].sort());
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-2 — allocation/upload size guards", () => {
  it("a size that cannot be represented exactly refuses before any handle exists (checkedMul)", () => {
    const d = allocateSessionResources({
      session: freshSession(),
      allocations: [{ bufferId: "buf.huge", recordCount: 2 ** 50, strideBytes: 2 ** 50, usage: ["vertex"] }],
    });
    const r = refOf(d, "refused_gpu_lifecycle_size_overflow");
    expect(r.explanation).toContain("wrapped size");
    expect(r.session).toBeNull();
  });

  it("an allocation beyond its per-usage ceiling is refused, never clamped", () => {
    const d = allocateSessionResources({
      session: freshSession(),
      allocations: [{ bufferId: "buf.bigvertex", recordCount: 3_000_000, strideBytes: 32, usage: ["vertex"] }],
    });
    const r = refOf(d, "refused_gpu_lifecycle_cap_exceeded");
    expect(r.explanation).toContain("never clamped");
  });

  it("the uniform ceiling is exact: 2048*32 = 65536 fits, one record more refuses", () => {
    const okFit = allocateSessionResources({
      session: freshSession(),
      allocations: [{ bufferId: "buf.u", recordCount: 2048, strideBytes: 32, usage: ["uniform"] }],
    });
    expect(okFit.ok).toBe(true);
    const overFit = allocateSessionResources({
      session: freshSession(),
      allocations: [{ bufferId: "buf.u", recordCount: 2049, strideBytes: 32, usage: ["uniform"] }],
    });
    refOf(overFit, "refused_gpu_lifecycle_cap_exceeded");
  });

  it("the batch total is checked against maxBufferBytes across several individually-legal allocations", () => {
    // 5 x 33554432 B storage: each within the storage ceiling, together over 134217728.
    const storageBatch = Array.from({ length: 5 }, (_, i) => ({
      bufferId: `buf.storage.${i}`,
      recordCount: 8_388_608,
      strideBytes: 4,
      usage: ["storage"],
    }));
    const d = allocateSessionResources({ session: freshSession(), allocations: storageBatch });
    const r = refOf(d, "refused_gpu_lifecycle_cap_exceeded");
    expect(r.explanation).toContain("maxBufferBytes");
  });

  it("a successful allocation yields live, correctly-sized, deterministic handles", () => {
    const s = allocatedSession();
    expect(s.state).toBe("allocated");
    expect(s.handles.length).toBe(3);
    const sizes = s.handles.map((h) => h.sizeBytes).sort((a, b) => a - b);
    expect(sizes).toEqual([32, 140, 1120].sort((a, b) => a - b));
    for (const h of s.handles) {
      expect(h.handleId).toMatch(/^h_[0-9a-f]{64}$/);
      expect(h.state).toBe("live");
      expect(h.authority).toBe("none");
      expect(h.executionAuthorized).toBe(false);
      expect(h.restoresRuntimeState).toBe(false);
      expect(h.rebuildsFrom).toBe("getig_frame");
    }
    // Determinism: no clock, no randomness — same binding, same ids.
    const again = allocatedSession();
    expect(again.sessionId).toBe(s.sessionId);
    expect(again.handles.map((h) => h.handleId)).toEqual(s.handles.map((h) => h.handleId));
  });

  it("uploads are guarded by the handle's own size and by integer safety", () => {
    const s = allocatedSession();
    const h = firstLive(s);
    refOf(
      uploadToSessionHandle({ session: s, handleId: h.handleId, byteLength: h.sizeBytes + 1 }),
      "refused_gpu_lifecycle_cap_exceeded",
    );
    refOf(
      uploadToSessionHandle({ session: s, handleId: h.handleId, byteLength: 2 ** 53 }),
      "refused_gpu_lifecycle_size_overflow",
    );
    refOf(
      uploadToSessionHandle({ session: s, handleId: h.handleId, byteLength: -1 }),
      "refused_gpu_lifecycle_input_invalid",
    );
    refOf(
      uploadToSessionHandle({ session: s, handleId: h.handleId, byteLength: 8, contentHash: "nope" }),
      "refused_gpu_lifecycle_input_invalid",
    );
    // A legal upload records exactly its bytes — not one byte more.
    const d = uploadToSessionHandle({ session: s, handleId: h.handleId, byteLength: 16 });
    if (!d.ok) throw new Error(`upload refused: ${d.refusal}`);
    expect(d.handle?.uploadedBytes).toBe(16);
    const d2 = uploadToSessionHandle({ session: d.session, handleId: h.handleId, byteLength: 16 });
    if (!d2.ok) throw new Error(`second upload refused: ${d2.refusal}`);
    expect(d2.handle?.uploadedBytes).toBe(32);
    expect(d2.handle?.sizeBytes).toBe(h.sizeBytes);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-3 — resize/reconfigure", () => {
  it("resize bumps the surface generation and swaps the viewport atomically", () => {
    const s = allocatedSession();
    const d = resizeSessionSurface({ session: s, width: 800, height: 600, scale: 2 });
    if (!d.ok) throw new Error(`resize refused: ${d.refusal}: ${d.explanation}`);
    expect(d.session.surfaceGeneration).toBe(s.surfaceGeneration + 1);
    expect(d.session.viewport).toEqual({ width: 800, height: 600, scale: 2 });
    expect(d.session.state).toBe("allocated");
    expect(d.session.sessionId).toBe(s.sessionId);
  });

  it("resize invalidates FRAME-SCOPED handles only; scene-scoped geometry survives", () => {
    const s = allocatedSession();
    const before = s.handles.map((h) => ({ id: h.bufferId, lifecycle: h.lifecycle }));
    const d = resizeSessionSurface({ session: s, width: 1920, height: 1080, scale: 1 });
    if (!d.ok) throw new Error(`resize refused: ${d.refusal}`);
    for (const h of d.session.handles) {
      if (h.lifecycle === "frame_scoped") {
        expect(h.state, h.bufferId).toBe("invalidated");
        expect(h.invalidationReason).toBe("surface_resize");
      } else {
        expect(h.state, h.bufferId).toBe("live");
      }
    }
    // uniform + storage are frame_scoped in this batch; vertex is scene_scoped
    const frameCount = before.filter((b) => b.lifecycle === "frame_scoped").length;
    expect(frameCount).toBe(2);
    expect(liveHandles(d.session).length).toBe(1);
    // ...and the invalidated one refuses upload with the stale explanation.
    const staleId = d.session.handles.find((h) => h.lifecycle === "frame_scoped")?.handleId ?? "";
    const up = refOf(
      uploadToSessionHandle({ session: d.session, handleId: staleId, byteLength: 4 }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(up.explanation).toContain("confers no authority");
  });

  it("resize requires an allocated session and legal dimensions", () => {
    refOf(
      resizeSessionSurface({ session: freshSession(), width: 800, height: 600, scale: 1 }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(
      resizeSessionSurface({ session: allocatedSession(), width: 0, height: 600, scale: 1 }),
      "refused_gpu_lifecycle_input_invalid",
    );
    refOf(
      resizeSessionSurface({ session: allocatedSession(), width: 800, height: 600, scale: 0 }),
      "refused_gpu_lifecycle_input_invalid",
    );
    refOf(
      resizeSessionSurface({ session: allocatedSession(), width: 800, height: 600, scale: 4.5 }),
      "refused_gpu_lifecycle_cap_exceeded",
    );
  });

  it("repeated reconfiguration is bounded: generation 255 refuses, never wraps", () => {
    const s = allocatedSession();
    const near = { ...s, surfaceGeneration: GPU_LIFECYCLE_BOUNDS.maxSurfaceGenerations - 1 };
    const d = resizeSessionSurface({ session: near, width: 640, height: 480, scale: 1 });
    const r = refOf(d, "refused_gpu_lifecycle_cap_exceeded");
    expect(r.explanation).toContain("maxSurfaceGenerations");
    // The refused session was NOT mutated: no partial state leaks out of a refusal.
    if (d.ok) throw new Error("expected refusal");
    expect(d.session).toBeNull();
  });

  it("a tampered session (broken id re-derivation) is refused as input, not repaired", () => {
    const s = allocatedSession();
    const tampered = { ...s, sessionId: "gls_" + "0".repeat(64) };
    const d = resizeSessionSurface({ session: tampered, width: 800, height: 600, scale: 1 });
    const r = refOf(d, "refused_gpu_lifecycle_input_invalid");
    expect(r.offendingField).toBe("session");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-4 — stale resource invalidation", () => {
  it("device loss invalidates EVERY live handle in the same decision that flips the state (atomic)", () => {
    const s = allocatedSession();
    const d = markSessionDeviceLost({ session: s, reason: "simulated_contract_event" });
    if (!d.ok) throw new Error(`loss refused: ${d.refusal}`);
    // One object, checked as a whole: no window where lost coexists with a live handle.
    expect(d.session.state).toBe("lost");
    expect(d.session.handles.length).toBe(3);
    for (const h of d.session.handles) {
      expect(h.state, h.bufferId).toBe("invalidated");
      expect(h.invalidationReason).toBe("device_loss");
    }
    expect(liveHandles(d.session).length).toBe(0);
  });

  it("an invalidated handle refuses verify and upload with 'confers no authority'", () => {
    const s = allocatedSession();
    const h = firstLive(s);
    const lost = lostFrom(s);
    const v = refOf(
      verifySessionHandle({ session: lost, handleId: h.handleId }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(v.explanation).toContain("confers no authority");
    expect(v.explanation).toContain("device_loss");
    const up = refOf(
      uploadToSessionHandle({ session: { ...lost, state: "allocated" }, handleId: h.handleId, byteLength: 4 }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(up.explanation).toContain("confers no authority");
  });

  it("an unknown handle id is stale, not silently accepted", () => {
    const s = allocatedSession();
    const v = refOf(
      verifySessionHandle({ session: s, handleId: "h_" + "0".repeat(64) }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(v.explanation).toContain("unknown");
  });

  it("a handle from a different session's plan is unknown — no cross-session handle reuse", () => {
    const otherSession = createGpuResourceSession({ plan: PLAN_B });
    if (!otherSession.ok) throw new Error("PLAN_B session refused");
    const otherAlloc = allocOf(otherSession.session);
    const foreign = firstLive(otherAlloc);
    const mine = allocatedSession();
    refOf(
      verifySessionHandle({ session: mine, handleId: foreign.handleId }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(foreign.planHash).toBe(PLAN_B.planHash);
    expect(mine.boundPlanHash).toBe(PLAN.planHash);
  });

  it("verify on a live handle succeeds but confers nothing", () => {
    const s = allocatedSession();
    const h = firstLive(s);
    const d = verifySessionHandle({ session: s, handleId: h.handleId });
    if (!d.ok) throw new Error(`verify refused: ${d.refusal}`);
    expect(d.handle?.handleId).toBe(h.handleId);
    expect(d.handle?.state).toBe("live");
    expect(d.authority).toBe("none");
    expect(d.controlPlane).toBe(false);
    expect(d.readOnly).toBe(true);
    expect(d.executionAuthorized).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-5 — cleanup", () => {
  it("release from allocated releases EVERY handle and closes the session", () => {
    const s = allocatedSession();
    const d = releaseSessionResources({ session: s });
    if (!d.ok) throw new Error(`release refused: ${d.refusal}`);
    expect(d.session.state).toBe("released");
    expect(liveHandles(d.session).length).toBe(0);
    for (const h of d.session.handles) {
      expect(h.state).toBe("released");
      expect(h.invalidationReason).toBe("session_release");
    }
  });

  it("release works from lost too — cleanup is not behind the recovery budget", () => {
    const d = releaseSessionResources({ session: lostSession() });
    if (!d.ok) throw new Error(`release refused: ${d.refusal}`);
    expect(d.session.state).toBe("released");
    expect(liveHandles(d.session).length).toBe(0);
  });

  it("a released session is terminal: double-release and every other operation refuse", () => {
    const released = (() => {
      const d = releaseSessionResources({ session: allocatedSession() });
      if (!d.ok) throw new Error("release failed");
      return d.session;
    })();
    refOf(releaseSessionResources({ session: released }), "refused_gpu_lifecycle_state_invalid");
    refOf(
      allocateSessionResources({ session: released, allocations: ALLOC }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(
      uploadToSessionHandle({ session: released, handleId: firstLive(allocatedSession()).handleId, byteLength: 1 }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(
      resizeSessionSurface({ session: released, width: 800, height: 600, scale: 1 }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(
      markSessionDeviceLost({ session: released, reason: "simulated_contract_event" }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(recreateSessionDevice({ session: released, plan: PLAN }), "refused_gpu_lifecycle_state_invalid");
  });

  it("release from created closes an empty session cleanly", () => {
    const d = releaseSessionResources({ session: freshSession() });
    if (!d.ok) throw new Error(`release refused: ${d.refusal}`);
    expect(d.session.state).toBe("released");
    expect(d.session.handles.length).toBe(0);
  });

  it("cleanup releases everything even after the recovery budget is spent", () => {
    let s = allocatedSession();
    for (let i = 1; i <= GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles; i += 1) {
      s = recoveredFrom(lostFrom(s));
    }
    const exhausted = lostFrom(s);
    refOf(recreateSessionDevice({ session: exhausted, plan: PLAN }), "refused_gpu_lifecycle_loss_budget_exceeded");
    const rel = releaseSessionResources({ session: exhausted });
    if (!rel.ok) throw new Error(`release refused after budget exhaustion: ${rel.refusal}`);
    expect(rel.session.state).toBe("released");
    expect(liveHandles(rel.session).length).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-6 — device-loss transition", () => {
  it("allocated -> lost records the reason and counts the loss event", () => {
    const s = allocatedSession();
    const d = markSessionDeviceLost({ session: s, reason: "platform_reported_loss" });
    if (!d.ok) throw new Error(`loss refused: ${d.refusal}`);
    expect(d.session.state).toBe("lost");
    expect(d.session.lossReason).toBe("platform_reported_loss");
    expect(d.session.lossEventCount).toBe(1);
    expect(d.session.recoveryCount).toBe(0);
  });

  it("created -> lost is allowed (a device can die before first allocation) and counts too", () => {
    const d = markSessionDeviceLost({ session: freshSession(), reason: "unknown" });
    if (!d.ok) throw new Error(`loss refused: ${d.refusal}`);
    expect(d.session.state).toBe("lost");
    expect(d.session.lossEventCount).toBe(1);
    expect(d.session.handles.length).toBe(0);
  });

  it("double loss refuses; a reason outside the vocabulary refuses", () => {
    const lost = lostSession();
    refOf(
      markSessionDeviceLost({ session: lost, reason: "simulated_contract_event" }),
      "refused_gpu_lifecycle_state_invalid",
    );
    refOf(
      markSessionDeviceLost({ session: allocatedSession(), reason: "made_up_reason" }),
      "refused_gpu_lifecycle_input_invalid",
    );
    refOf(
      markSessionDeviceLost({ session: allocatedSession() }),
      "refused_gpu_lifecycle_input_invalid",
    );
    expect([...GPU_LOSS_REASONS]).toContain("simulated_contract_event");
  });

  it("loss from a lost session cannot be laundered through allocate — only recreation follows", () => {
    const lost = lostSession();
    refOf(
      allocateSessionResources({ session: lost, allocations: ALLOC }),
      "refused_gpu_lifecycle_state_invalid",
    );
    // upload likewise requires allocated
    refOf(
      uploadToSessionHandle({ session: lost, handleId: firstLive(allocatedSession()).handleId, byteLength: 4 }),
      "refused_gpu_lifecycle_state_invalid",
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-7 — adapter/device recreation where supported", () => {
  it("recreation from lost with the bound plan succeeds and re-enters allocated", () => {
    const lost = lostSession();
    const d = recreateSessionDevice({ session: lost, plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}: ${d.explanation}`);
    expect(d.session.state).toBe("allocated");
    expect(d.session.recoveryCount).toBe(1);
    expect(d.session.lossEventCount).toBe(1);
    expect(d.session.adapterDeviceRecreation).toBe("contract_simulated");
    expect(liveHandles(d.session).length).toBe(PLAN.buffers.length);
    for (const h of liveHandles(d.session)) {
      expect(h.state).toBe("live");
      expect(h.authority).toBe("none");
      expect(h.executionAuthorized).toBe(false);
    }
  });

  it("recovered handles are a NEW build epoch — distinct from the ones the loss invalidated", () => {
    const lost = lostSession();
    const oldIds = new Set(lost.handles.map((h) => h.handleId));
    const d = recreateSessionDevice({ session: lost, plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}`);
    const fresh = liveHandles(d.session);
    expect(fresh.length).toBe(PLAN.buffers.length);
    for (const h of fresh) {
      expect(oldIds.has(h.handleId)).toBe(false);
      expect(h.buildEpoch).toBe(lost.lossEventCount);
    }
    // The invalidated originals are still on the record (supersede, never erase).
    expect(d.session.handles.length).toBe(lost.handles.length + fresh.length);
    expect(d.session.handles.filter((h) => h.state === "invalidated").length).toBe(lost.handles.length);
  });

  it("recreation is refused from any state other than lost", () => {
    refOf(recreateSessionDevice({ session: freshSession(), plan: PLAN }), "refused_gpu_lifecycle_state_invalid");
    refOf(
      recreateSessionDevice({ session: allocatedSession(), plan: PLAN }),
      "refused_gpu_lifecycle_state_invalid",
    );
  });

  it("repeated loss/recovery is bounded: the 9th recovery refuses, losses never do", () => {
    let s = allocatedSession();
    for (let i = 1; i <= GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles; i += 1) {
      const lost = markSessionDeviceLost({ session: s, reason: "simulated_contract_event" });
      if (!lost.ok) throw new Error(`loss ${i} refused: ${lost.refusal}`);
      const back = recreateSessionDevice({ session: lost.session, plan: PLAN });
      if (!back.ok) throw new Error(`recovery ${i} refused: ${back.refusal}: ${back.explanation}`);
      s = back.session;
      expect(s.recoveryCount).toBe(i);
    }
    expect(s.recoveryCount).toBe(GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles);
    expect(s.handles.length).toBeLessThanOrEqual(GPU_LIFECYCLE_BOUNDS.maxSessionHandles);
    // A 9th LOSS is fine (a dying device is not making a request)...
    const ninthLoss = markSessionDeviceLost({ session: s, reason: "simulated_contract_event" });
    if (!ninthLoss.ok) throw new Error(`9th loss refused: ${ninthLoss.refusal}`);
    expect(ninthLoss.session.lossEventCount).toBe(9);
    // ...but the 9th RECOVERY is beyond the budget and fails closed.
    const r = refOf(
      recreateSessionDevice({ session: ninthLoss.session, plan: PLAN }),
      "refused_gpu_lifecycle_loss_budget_exceeded",
    );
    expect(r.explanation).toContain("maxLossRecoveryCycles");
  });

  it("recreation with no prior resources (lost from created) still re-derives from the plan", () => {
    const lost = lostFrom(freshSession());
    const d = recreateSessionDevice({ session: lost, plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}: ${d.explanation}`);
    expect(d.session.state).toBe("allocated");
    expect(d.session.handles.length).toBe(PLAN.buffers.length);
    expect(d.session.recoveryCount).toBe(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-8 — rebuild graphics only from the already-authorized GETIG frame/scene/plan", () => {
  it("a plan that claims anything refuses: completeness, pixels, authority", () => {
    const completeness = tamperedPlan();
    completeness["completeness"] = "complete";
    const r1 = refOf(createGpuResourceSession({ plan: completeness }), "refused_gpu_lifecycle_plan_invalid");
    expect(r1.offendingField).toBe("plan.completeness");

    const pixels = tamperedPlan();
    pixels["pixelOutputVerified"] = true;
    const r2 = refOf(createGpuResourceSession({ plan: pixels }), "refused_gpu_lifecycle_plan_invalid");
    expect(r2.offendingField).toBe("plan.pixelOutputVerified");

    const authority = tamperedPlan();
    authority["executionAuthorized"] = true;
    const r3 = refOf(createGpuResourceSession({ plan: authority }), "refused_gpu_lifecycle_plan_invalid");
    expect(r3.offendingField).toBe("plan.authority");
  });

  it("a buffer that would restore runtime state or skip the frame source refuses", () => {
    const restores = tamperedPlan();
    (restores["buffers"] as Record<string, unknown>[])["0"]!["restoresRuntimeState"] = true;
    refOf(createGpuResourceSession({ plan: restores }), "refused_gpu_lifecycle_plan_invalid");

    const source = tamperedPlan();
    (source["buffers"] as Record<string, unknown>[])["0"]!["rebuildsFrom"] = "runtime_epoch";
    refOf(createGpuResourceSession({ plan: source }), "refused_gpu_lifecycle_plan_invalid");
  });

  it("malformed plans refuse: bad hash, empty buffers, self-inconsistent byte total, oversized size", () => {
    const hash = tamperedPlan();
    hash["planHash"] = "plan_zzz";
    refOf(createGpuResourceSession({ plan: hash }), "refused_gpu_lifecycle_plan_invalid");

    const empty = tamperedPlan();
    empty["buffers"] = [];
    refOf(createGpuResourceSession({ plan: empty }), "refused_gpu_lifecycle_plan_invalid");

    const drift = tamperedPlan();
    const driftBufs = drift["buffers"] as Record<string, unknown>[];
    driftBufs["0"]!["sizeBytes"] = (driftBufs["0"]!["sizeBytes"] as number) + 4;
    const driftR = refOf(createGpuResourceSession({ plan: drift }), "refused_gpu_lifecycle_plan_invalid");
    expect(driftR.offendingField).toBe("plan.totalBufferBytes");

    const wrapped = tamperedPlan();
    (wrapped["buffers"] as Record<string, unknown>[])["0"]!["sizeBytes"] = 2 ** 53;
    refOf(createGpuResourceSession({ plan: wrapped }), "refused_gpu_lifecycle_size_overflow");

    const overCap = tamperedPlan();
    (overCap["buffers"] as Record<string, unknown>[])["0"]!["sizeBytes"] = 67_108_865; // vertex ceiling + 1
    refOf(createGpuResourceSession({ plan: overCap }), "refused_gpu_lifecycle_cap_exceeded");
  });

  it("a well-formed plan bound to a DIFFERENT frame/scene refuses as a rebuild source", () => {
    const lost = lostSession();
    const r = refOf(
      recreateSessionDevice({ session: lost, plan: PLAN_B }),
      "refused_gpu_lifecycle_plan_mismatch",
    );
    expect(r.explanation).toContain("ALREADY-AUTHORIZED");
    expect(r.explanation).toContain("GPU_RECOVERY != RUNTIME_RECOVERY");
    // PLAN_B is itself perfectly valid — the BINDING is what refused it.
    const goodOther = createGpuResourceSession({ plan: PLAN_B });
    expect(goodOther.ok).toBe(true);
  });

  it("recovered handles carry EXACTLY the plan's buffer sizes, rebuilt from the frame", () => {
    const lost = lostSession();
    const d = recreateSessionDevice({ session: lost, plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}`);
    const recovered = liveHandles(d.session);
    const planSizes = PLAN.buffers.map((b) => b.sizeBytes).sort((a, b) => a - b);
    const handleSizes = recovered.map((h) => h.sizeBytes).sort((a, b) => a - b);
    expect(handleSizes).toEqual(planSizes);
    const planIds = PLAN.buffers.map((b) => b.bufferId).sort();
    const handleIds = recovered.map((h) => h.bufferId).sort();
    expect(handleIds).toEqual(planIds);
    for (const h of recovered) {
      expect(h.rebuildsFrom).toBe("getig_frame");
      expect(h.restoresRuntimeState).toBe(false);
      expect(h.planHash).toBe(PLAN.planHash);
      expect(h.sceneHash).toBe(PLAN.sceneHash);
    }
    expect(d.session.boundFrameId).toBe(PLAN.sourceFrameId);
  });

  it("the session itself carries no runtime-state field at all", () => {
    const keys = collectKeys(allocatedSession());
    for (const forbidden of GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS) {
      expect([...keys].includes(forbidden), forbidden).toBe(false);
    }
    expect([...keys]).not.toContain("runtimeStateHash");
    const lostKeys = collectKeys(lostSession());
    for (const forbidden of GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS) {
      expect([...lostKeys].includes(forbidden), forbidden).toBe(false);
    }
  });

  it("the binding is re-derived, not read: a tampered planHash on the session refuses", () => {
    const s = allocatedSession();
    const tampered = { ...s, boundPlanHash: "plan_" + "0".repeat(64), sessionId: s.sessionId };
    const d = verifySessionHandle({ session: tampered, handleId: firstLive(s).handleId });
    const r = refOf(d, "refused_gpu_lifecycle_input_invalid");
    expect(r.offendingField).toBe("session");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-9 — never restore/replay/resume agent/task/runtime state", () => {
  it("EVERY declared forbidden input field refuses at create, by name", () => {
    expect(GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS.length).toBeGreaterThanOrEqual(20);
    for (const field of GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS) {
      const d = createGpuResourceSession({ plan: PLAN, [field]: { anything: true } });
      expect(d.ok, field).toBe(false);
      if (d.ok) continue;
      expect(d.refusal, field).toBe("refused_gpu_lifecycle_runtime_restore_forbidden");
      expect(d.offendingField, field).toBe(field);
      expect(d.explanation, field).toContain("GPU_RECOVERY != RUNTIME_RECOVERY");
      expect(d.session, field).toBeNull();
    }
  });

  it("every operation function refuses a runtime-shaped field before anything else", () => {
    const ops: readonly ((input: unknown) => Dec)[] = [
      createGpuResourceSession,
      allocateSessionResources,
      uploadToSessionHandle,
      resizeSessionSurface,
      markSessionDeviceLost,
      recreateSessionDevice,
      verifySessionHandle,
      releaseSessionResources,
    ];
    for (const op of ops) {
      const d = op({ agent: { task: "resume" } });
      expect(d.ok, op.name).toBe(false);
      if (d.ok) continue;
      expect(d.refusal, op.name).toBe("refused_gpu_lifecycle_runtime_restore_forbidden");
      expect(d.session, op.name).toBeNull();
    }
  });

  it("the always-refusing guard can only refuse under ANY input, naming what it found", () => {
    for (const input of [null, undefined, 42, "resume", {}, { task: 1, runtime: 2 }, { plan: PLAN }]) {
      const r = refuseGpuRecoveryRuntimeRestore(input);
      expect(r.ok).toBe(false);
      expect(r.code).toBe("recovery_refused");
      expect(r.refusal).toBe("refused_gpu_lifecycle_runtime_restore_forbidden");
      expect(r.restoredRuntimeState).toBe(false);
      expect(r.replayedTaskState).toBe(false);
      expect(r.resumedAgentState).toBe(false);
      expect(r.authority).toBe("none");
      expect(r.controlPlane).toBe(false);
      expect(r.readOnly).toBe(true);
      expect(r.executionAuthorized).toBe(false);
      expect(r.explanation).toContain("GPU_RECOVERY != RUNTIME_RECOVERY");
      expect([...GPU_LIFECYCLE_REFUSAL_CODES]).toContain(r.refusal);
    }
    const named = refuseGpuRecoveryRuntimeRestore({ agent: 1, checkpoint: 2, plan: PLAN });
    expect([...named.detectedFields].sort()).toEqual(["agent", "checkpoint"]);
    expect(refuseGpuRecoveryRuntimeRestore({}).detectedFields).toEqual([]);
  });

  it("no OUTPUT key anywhere is a forbidden runtime field", () => {
    const s = allocatedSession();
    const d = verifySessionHandle({ session: s, handleId: firstLive(s).handleId });
    for (const key of collectKeys(d)) {
      expect((GPU_RECOVERY_FORBIDDEN_INPUT_FIELDS as readonly string[]).includes(key), key).toBe(false);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-10 — old GPU handle confers no authority", () => {
  it("every handle — live, invalidated, released — carries literal zero authority", () => {
    const s = allocatedSession();
    const lost = lostFrom(s);
    const released = (() => {
      const d = releaseSessionResources({ session: allocatedSession() });
      if (!d.ok) throw new Error("release failed");
      return d.session;
    })();
    for (const h of [...s.handles, ...lost.handles, ...released.handles]) {
      expect(h.authority, h.handleId).toBe("none");
      expect(h.executionAuthorized, h.handleId).toBe(false);
      expect(h.restoresRuntimeState, h.handleId).toBe(false);
      expect(h.ownerLayer, h.handleId).toBe("gpu_resource");
      expect(h.rebuildsFrom, h.handleId).toBe("getig_frame");
    }
  });

  it("presenting an old handle to any operation refuses with the authority explanation", () => {
    const s = allocatedSession();
    const old = firstLive(s);
    const lost = lostFrom(s);
    const v = refOf(
      verifySessionHandle({ session: lost, handleId: old.handleId }),
      "refused_gpu_lifecycle_stale_resource",
    );
    expect(v.explanation).toContain("old or retired GPU handle confers no authority");
    expect(v.session).toBeNull();
    expect(v.handle).toBeNull();
  });

  it("recovery grants nothing: the recovered session and its fresh handles still confers zero authority", () => {
    const d = recreateSessionDevice({ session: lostSession(), plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}`);
    expect(d.session.authority).toBe("none");
    expect(d.session.controlPlane).toBe(false);
    expect(d.session.readOnly).toBe(true);
    expect(d.session.executionAuthorized).toBe(false);
    expect(d.authority).toBe("none");
    expect(d.executionAuthorized).toBe(false);
    for (const h of liveHandles(d.session)) {
      expect(h.authority).toBe("none");
      expect(h.executionAuthorized).toBe(false);
    }
    // A successful verify of a fresh handle also confers nothing.
    const v = verifySessionHandle({ session: d.session, handleId: liveHandles(d.session)[0]!.handleId });
    if (!v.ok) throw new Error(`verify refused: ${v.refusal}`);
    expect(v.executionAuthorized).toBe(false);
    expect(v.handle?.authority).toBe("none");
  });

  it("a handle id cannot be forged into a session: ids re-derive or the input refuses", () => {
    const s = allocatedSession();
    const h = firstLive(s);
    const forged = { ...s, handles: [{ ...h, handleId: "h_" + "f".repeat(64) }, ...s.handles.slice(1)] };
    refOf(
      verifySessionHandle({ session: forged, handleId: "h_" + "f".repeat(64) }),
      "refused_gpu_lifecycle_input_invalid",
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-11 — simulated contract tests vs real device evidence, honestly distinguished", () => {
  it("a fresh session says out loud that real device-loss evidence is UNAVAILABLE, citing 29C-OBS-1", () => {
    const s = freshSession();
    expect(s.contractEvidence).toBe("simulated_contract_tests");
    expect(s.realDeviceLossEvidence).toBe("unavailable");
    expect(s.realDeviceLossEvidenceNote).toContain("29C-OBS-1");
    expect(s.realDeviceLossEvidenceNote).toContain("no WebGPU");
    expect(s.adapterDeviceRecreation).toBe("not_yet_attempted");
    expect([...GPU_ADAPTER_RECREATION_STATES]).toContain("not_yet_attempted");
  });

  it("recreation with default or explicit simulated evidence keeps real evidence 'unavailable'", () => {
    const d = recreateSessionDevice({ session: lostSession(), plan: PLAN });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}`);
    expect(d.session.contractEvidence).toBe("simulated_contract_tests");
    expect(d.session.realDeviceLossEvidence).toBe("unavailable");
    expect(d.session.realDeviceLossEvidenceNote).toContain("29C-OBS-1");
    expect(d.session.adapterDeviceRecreation).toBe("contract_simulated");

    const d2 = recreateSessionDevice({
      session: lostFrom(allocatedSession()),
      plan: PLAN,
      evidence: { mode: "simulated_contract_tests" },
    });
    if (!d2.ok) throw new Error(`recreate refused: ${d2.refusal}`);
    expect(d2.session.realDeviceLossEvidence).toBe("unavailable");
    expect(d2.session.adapterDeviceRecreation).toBe("contract_simulated");
    expect([...GPU_RECOVERY_EVIDENCE_MODES]).toContain("simulated_contract_tests");
  });

  it("claiming real evidence with NO observation refuses — UNSUPPORTED is never silently downgraded", () => {
    const r = refOf(
      recreateSessionDevice({
        session: lostSession(),
        plan: PLAN,
        evidence: { mode: "real_device_observation" },
      }),
      "refused_gpu_lifecycle_evidence_unavailable",
    );
    expect(r.explanation).toContain("29C-OBS-1");
    expect(r.explanation).toContain("UNSUPPORTED != PASS");
    expect(r.offendingField).toBe("evidence.observation");
  });

  it("a malformed or self-contradictory real observation refuses as evidence_invalid", () => {
    const base = () => ({ session: lostSession(), plan: PLAN, evidence: { mode: "real_device_observation" as const } });

    refOf(
      recreateSessionDevice({ ...base(), evidence: { mode: "not_a_mode" } }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    refOf(
      recreateSessionDevice({ ...base(), evidence: { mode: "simulated_contract_tests", observation: realObs() } }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    refOf(
      recreateSessionDevice({
        ...base(),
        evidence: { mode: "real_device_observation", observation: { ...realObs(), bogus: 1 } },
      }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    const missing = realObs();
    delete missing["lossObserved"];
    refOf(
      recreateSessionDevice({ ...base(), evidence: { mode: "real_device_observation", observation: missing } }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    refOf(
      recreateSessionDevice({
        ...base(),
        evidence: { mode: "real_device_observation", observation: realObs({ lossObserved: "yes" }) },
      }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    refOf(
      recreateSessionDevice({
        ...base(),
        evidence: { mode: "real_device_observation", observation: realObs({ userAgent: "" }) },
      }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    // chain: recreation succeeded but no loss observed — cannot be true
    const contradictory = refOf(
      recreateSessionDevice({
        ...base(),
        evidence: { mode: "real_device_observation", observation: realObs({ lossObserved: false }) },
      }),
      "refused_gpu_lifecycle_evidence_invalid",
    );
    expect(contradictory.explanation).toContain("recreationSucceeded implies lossObserved");
    // unknown evidence key refuses (not ignored)
    refOf(
      recreateSessionDevice({
        ...base(),
        evidence: { mode: "simulated_contract_tests", extra: 1 },
      }),
      "refused_gpu_lifecycle_input_invalid",
    );
  });

  it("a real observation whose readback did NOT match stops at observed_readback_inconclusive", () => {
    const d = recreateSessionDevice({
      session: lostSession(),
      plan: PLAN,
      evidence: { mode: "real_device_observation", observation: realObs({ readbackMatchesExpectation: false }) },
    });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}: ${d.explanation}`);
    expect(d.session.realDeviceLossEvidence).toBe("observed_readback_inconclusive");
    expect(d.session.adapterDeviceRecreation).toBe("real_observed");
    expect(d.session.realDeviceLossEvidenceNote).toContain("SUBMITTED != RENDERED");
    // The suite's OWN evidence label never changes: it is still simulated.
    expect(d.session.contractEvidence).toBe("simulated_contract_tests");
    // And the inconclusive name is 29C's own verdict vocabulary, not a re-declaration.
    expect([...QUALIFICATION_VERDICTS]).toContain("observed_readback_inconclusive");
    expect(
      GPU_REAL_DEVICE_EVIDENCE_STATES.filter((s) => s !== "unavailable").every(
        (s) => s === "observed_readback_inconclusive" || s === "observed_readback_matched",
      ),
    ).toBe(true);
  });

  it("a real observation with a MATCHING readback reaches observed_readback_matched — nothing stronger", () => {
    const d = recreateSessionDevice({
      session: lostSession(),
      plan: PLAN,
      evidence: { mode: "real_device_observation", observation: realObs({ readbackMatchesExpectation: true }) },
    });
    if (!d.ok) throw new Error(`recreate refused: ${d.refusal}: ${d.explanation}`);
    expect(d.session.realDeviceLossEvidence).toBe("observed_readback_matched");
    expect(d.session.realDeviceLossEvidenceNote).toContain("power loss");
    expect(d.session.realDeviceLossEvidenceNote).toContain("unproven");
    expect(d.session.contractEvidence).toBe("simulated_contract_tests");
    expect(d.session.authority).toBe("none");
  });

  it("real evidence recorded once is NEVER erased by a later simulated recreation (supersede, never erase)", () => {
    const real = recreateSessionDevice({
      session: lostSession(),
      plan: PLAN,
      evidence: { mode: "real_device_observation", observation: realObs({ readbackMatchesExpectation: true }) },
    });
    if (!real.ok) throw new Error(`recreate refused: ${real.refusal}`);
    expect(real.session.realDeviceLossEvidence).toBe("observed_readback_matched");
    const again = recreateSessionDevice({ session: lostFrom(real.session), plan: PLAN });
    if (!again.ok) throw new Error(`recreate refused: ${again.refusal}`);
    expect(again.session.realDeviceLossEvidence).toBe("observed_readback_matched");
    expect(again.session.realDeviceLossEvidenceNote).toBe(real.session.realDeviceLossEvidenceNote);
    expect(again.session.adapterDeviceRecreation).toBe("real_observed");
    expect(again.session.contractEvidence).toBe("simulated_contract_tests");
  });

  it("every observation field of the real vocabulary is required, negatives included", () => {
    expect([...GPU_REAL_LOSS_OBSERVATION_FIELDS]).toEqual([
      "apiPresent",
      "adapterObtained",
      "deviceCreated",
      "lossObserved",
      "recreationSucceeded",
      "readbackMatchesExpectation",
      "userAgent",
    ]);
    const full = realObs();
    for (const field of GPU_REAL_LOSS_OBSERVATION_FIELDS) {
      const partial = { ...full };
      delete partial[field];
      const d = recreateSessionDevice({
        session: lostFrom(allocatedSession()),
        plan: PLAN,
        evidence: { mode: "real_device_observation", observation: partial },
      });
      expect(d.ok, field).toBe(false);
      if (d.ok) continue;
      expect(d.refusal, field).toBe("refused_gpu_lifecycle_evidence_invalid");
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-S — control-path scans (export surface, import surface, forbidden tokens)", () => {
  it("the module exports EXACTLY the eight operations and one always-refusing guard", () => {
    const fnNames = Object.entries(lifecycleSurface)
      .filter(([, v]) => typeof v === "function")
      .map(([k]) => k)
      .sort();
    expect(fnNames).toEqual(
      [
        "allocateSessionResources",
        "createGpuResourceSession",
        "markSessionDeviceLost",
        "recreateSessionDevice",
        "refuseGpuRecoveryRuntimeRestore",
        "releaseSessionResources",
        "resizeSessionSurface",
        "uploadToSessionHandle",
        "verifySessionHandle",
      ].sort(),
    );
  });

  it("the module's CODE contains no GPU call, no clock and no randomness", () => {
    for (const token of PHASE29H_FORBIDDEN_TOKENS) {
      expect(MODULE_CODE, `module code must not contain "${token}"`).not.toContain(token);
    }
  });

  it("POSITIVE CONTROL: the token scan fires on tokens really present in code", () => {
    const planted = "navigator.requestDevice(); createBuffer(b); queue.submit(cmd); Date.now(); Math.random();";
    const hits = PHASE29H_FORBIDDEN_TOKENS.filter((t) => stripLiterals(planted).includes(t));
    expect(hits).toContain("navigator");
    expect(hits).toContain("requestDevice");
    expect(hits).toContain("createBuffer");
    expect(hits).toContain("queue.submit");
    expect(hits).toContain("Date.now");
    expect(hits).toContain("Math.random");
  });

  it("POSITIVE CONTROL: comments and string literals alone must NOT trip the scan", () => {
    const commentOnly = "// never Date.now or createBuffer( anything here\nconst a = 1;\n";
    expect(PHASE29H_FORBIDDEN_TOKENS.filter((t) => stripLiterals(commentOnly).includes(t))).toEqual([]);
    const literalOnly = 'const s = "navigator requestDevice queue.submit draw(";';
    expect(PHASE29H_FORBIDDEN_TOKENS.filter((t) => stripLiterals(literalOnly).includes(t))).toEqual([]);
  });

  it("the import surface is EXACTLY canonical + gpuRenderPlan — no store, no coordinator, no runtime, no WebGPU", () => {
    const imports = [...MODULE_SRC.matchAll(/from\s+"(\.[^"]+)"/g)].map((m) => m[1]);
    expect([...new Set(imports)].sort()).toEqual(["./canonical.js", "./gpuRenderPlan.js"].sort());
    for (const forbidden of [
      "./store.js",
      "./coordinator.js",
      "./statePersistence.js",
      "./continuity.js",
      "./webgpuQualification.js",
      "node:child_process",
      "node:worker_threads",
    ]) {
      expect(imports).not.toContain(forbidden);
    }
  });

  it("session and handle id derivation consults no clock: ids are pure functions of bindings", () => {
    const a = allocatedSession();
    const b = allocatedSession();
    expect(a.sessionId).toBe(b.sessionId);
    expect(a.handles.map((h) => h.handleId)).toEqual(b.handles.map((h) => h.handleId));
    expect(a.sessionId).toBe(`gls_${a.sessionId.slice(4)}`);
    expect(MODULE_CODE).not.toContain("Date");
    expect(MODULE_CODE).not.toContain("randomUUID");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29H-R — every declared refusal code is reachable from a real input (set equality)", () => {
  it("driven codes === declared codes: nothing unreachable, nothing undeclared", () => {
    const driven = new Set<string>();
    const drive = (d: Dec): void => {
      expect(d.ok).toBe(false);
      if (!d.ok) driven.add(d.refusal);
    };

    drive(createGpuResourceSession(null)); // input_invalid
    const badPlan = tamperedPlan();
    badPlan["completeness"] = "complete";
    drive(createGpuResourceSession({ plan: badPlan })); // plan_invalid
    drive(recreateSessionDevice({ session: lostSession(), plan: PLAN_B })); // plan_mismatch
    drive(createGpuResourceSession({ plan: PLAN, task: {} })); // runtime_restore_forbidden
    const capSession = allocatedSession();
    drive(
      uploadToSessionHandle({ session: capSession, handleId: firstLive(capSession).handleId, byteLength: 99_999_999 }),
    ); // cap_exceeded
    drive(
      allocateSessionResources({
        session: freshSession(),
        allocations: [{ bufferId: "b", recordCount: 2 ** 50, strideBytes: 2 ** 50, usage: ["vertex"] }],
      }),
    ); // size_overflow
    drive(allocateSessionResources({ session: allocatedSession(), allocations: ALLOC })); // state_invalid
    drive(verifySessionHandle({ session: allocatedSession(), handleId: "h_" + "0".repeat(64) })); // stale_resource
    drive(recreateSessionDevice({ session: lostSession(), plan: PLAN, evidence: { mode: "real_device_observation" } })); // evidence_unavailable
    drive(
      recreateSessionDevice({
        session: lostSession(),
        plan: PLAN,
        evidence: { mode: "real_device_observation", observation: realObs({ lossObserved: false }) },
      }),
    ); // evidence_invalid
    // loss_budget_exceeded: burn the whole budget
    let s = allocatedSession();
    for (let i = 0; i <= GPU_LIFECYCLE_BOUNDS.maxLossRecoveryCycles; i += 1) {
      const lost = markSessionDeviceLost({ session: s, reason: "simulated_contract_event" });
      if (!lost.ok) throw new Error(`loss ${i} refused unexpectedly`);
      const back = recreateSessionDevice({ session: lost.session, plan: PLAN });
      if (back.ok) {
        s = back.session;
      } else {
        drive(back);
        break;
      }
    }
    drive(recreateSessionDevice({ session: lostFrom(s), plan: PLAN })); // loss_budget_exceeded (again)

    expect([...driven].sort()).toEqual([...GPU_LIFECYCLE_REFUSAL_CODES].sort());
    expect(GPU_LIFECYCLE_REFUSAL_CODES.length).toBe(11);
  });

  it("every refusal is fail-closed: null session, null handle, zero authority", () => {
    const samples: Dec[] = [
      createGpuResourceSession(null),
      createGpuResourceSession({ plan: PLAN, agent: 1 }),
      allocateSessionResources({ session: allocatedSession(), allocations: ALLOC }),
      verifySessionHandle({ session: allocatedSession(), handleId: "h_" + "0".repeat(64) }),
    ];
    for (const d of samples) {
      expect(d.ok).toBe(false);
      if (d.ok) continue;
      expect(d.session).toBeNull();
      expect(d.handle).toBeNull();
      expect(d.authority).toBe("none");
      expect(d.executionAuthorized).toBe(false);
      expect([...GPU_LIFECYCLE_REFUSAL_CODES]).toContain(d.refusal);
    }
    expect(GPU_RESOURCE_LIFECYCLE_SCHEMA_VERSION).toBe("menog-gpu-resource-lifecycle/v0");
  });
});
