/**
 * PHASE 29I — ADVERSARIAL RENDERER INTEGRITY CATALOGUE
 * (ATTACK THE COMPLETE 29A–29H SURFACE / ZERO CRITICAL BYPASS)
 *
 * CENTRAL LAWS:
 *   UNSUPPORTED != PASS
 *   INCONCLUSIVE != PASS
 *   A MOCK IS NOT A VALIDATION
 *   NO ATTACK IS A REASON TO WEAKEN A DEFENCE
 *   CLAIM != GRANT; ROUTE != AUTHORIZATION; FORWARDER != ORIGIN
 *   RENDERED REALITY IS A MATERIALIZATION OF GETIG, NOT A SOURCE OF TRUTH
 *
 * ── WHAT THIS IS ─────────────────────────────────────────────────────────────
 *
 * 29I is the attack counterpart to gates 29A–29H, which each assert that one
 * layer behaves as designed. A test written by the same author as the code
 * inherits the author's blind spots, so this catalogue is a TABLE OF ATTACKS —
 * each naming what it tried and what would count as a bypass — executed by the
 * Phase-28I harness (28I's own precedent: verdicts are scored mechanically
 * from the attack's declared result, never from an author-chosen label).
 *
 * Every attack runs against REAL existing surfaces: the frozen 28J → 29B
 * scene, the 29D plan, the 29E composer, the 29F transition planner, the 29G
 * picker, the 29H lifecycle, and the 29C qualification judge. Nothing here is
 * a mock, and nothing here is scored as a validation it did not perform.
 *
 * ── WHAT AN ATTACK CANNOT DO ─────────────────────────────────────────────────
 *
 * An attack may not weaken a defence to succeed: this module never edits the
 * surfaces it strikes. Where a family cannot be exercised on this platform it
 * returns UNSUPPORTED (malformed WGSL: this workspace ships no WGSL source and
 * no WebGPU compiler), and where the outcome genuinely depends on consumers
 * that do not exist yet it returns INCONCLUSIVE (recovery-time label-only
 * plan tampering: content is committed, the label is not, and no current
 * consumer treats the label as authority). Neither is a PASS, and the harness
 * keeps them structurally separate from PASS.
 *
 * The pack's 22 families are enumerated in `PHASE29_ATTACK_FAMILIES`; the
 * suite asserts set-equality coverage over that table, so a family cannot be
 * silently dropped and an attack cannot dangle unreferenced. Two families
 * (alternate path, secret leakage) are proven partly by static CODE scans
 * that live in the suite itself — named in `coveredElsewhereInTests`.
 */

import type { AttackDefence, AttackInput, AttackResult } from "./getigAdversarialHarness.js";
import { runGetigEndToEndScenario } from "./getigEndToEndScenario.js";
import { compileGetigScene } from "./sceneGraphCompiler.js";
import { buildGpuRenderPlan, assertLayoutArity, assertZeroFill, GPU_LAYOUTS } from "./gpuRenderPlan.js";
import { composeRuntimeFrame } from "./renderFrameComposer.js";
import {
  planGetigTransitions,
  refuseTransitionPlaybackResume,
  refuseTransitionRuntimeMutation,
} from "./temporalTransitionPlanner.js";
import {
  GETIG_PICKING_ACTION_FIELDS,
  inspectPickedSubject,
  refusePickedSelectionExecution,
  resolvePickingSelection,
} from "./pickingResolver.js";
import {
  allocateSessionResources,
  createGpuResourceSession,
  markSessionDeviceLost,
  recreateSessionDevice,
  releaseSessionResources,
  resizeSessionSurface,
  uploadToSessionHandle,
  verifySessionHandle,
} from "./gpuResourceLifecycle.js";
import { qualifyWebGpu } from "./webgpuQualification.js";
import { getigVisualSemanticRank } from "./getigVisualMapping.js";

// ── the REAL frozen chain, built through the REAL builders ────────────────────

const scenarioRun = runGetigEndToEndScenario();
if (!scenarioRun.ok) throw new Error(`29I fixture: frozen scenario refused: ${scenarioRun.refusal}`);
const SC = scenarioRun.scenario;
const RUNTIME_HASH = "5555666677778888";

const compiledA = compileGetigScene({ mapping: SC.mapping, runtimeStateHash: RUNTIME_HASH });
if (!compiledA.ok) throw new Error(`29I fixture: frozen compile refused: ${compiledA.refusal}`);
const SCENE = compiledA.scene;

const planA = buildGpuRenderPlan({ scene: SCENE });
if (!planA.ok) throw new Error(`29I fixture: frozen plan refused: ${planA.refusal}`);
const PLAN = planA.plan;

/** A REAL second frame → second scene → second plan, for mismatch attacks. */
const tokenB = (over: Record<string, unknown>): Record<string, unknown> => ({
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
const MAPPING_B = {
  schemaVersion: "menog-getig-visual/v0",
  frameId: "frame-29i-b",
  observerId: "observer-local-a",
  mappingHash: "abcdef0123456789",
  tokens: [tokenB({ axis: "knowledge", semanticValue: "known", subjectVisibleId: "node-local" })],
};
const compiledB = compileGetigScene({ mapping: MAPPING_B, runtimeStateHash: RUNTIME_HASH });
if (!compiledB.ok) throw new Error(`29I fixture: second compile refused: ${compiledB.refusal}`);
const SCENE_B = compiledB.scene;
const planB = buildGpuRenderPlan({ scene: SCENE_B });
if (!planB.ok) throw new Error(`29I fixture: second plan refused: ${planB.refusal}`);
const PLAN_B = planB.plan;

const BINDING = {
  frameId: SC.frame.frameId,
  observerId: SC.frame.observer.observerId,
  canonicalVisibleHash: SC.frame.canonicalVisibleHash,
  viewHash: SC.viewLocal.viewHash,
};

const idxOf = (subject: string): number => {
  const i = PLAN.pickingResolutions.findIndex((r) => r.subjectVisibleId === subject);
  if (i < 0) throw new Error(`29I fixture: no picking row for ${subject}`);
  return i;
};

const tamperPlan = (): Record<string, unknown> => JSON.parse(JSON.stringify(PLAN)) as Record<string, unknown>;

const held = (observed: string, defence: AttackDefence = "refusal"): AttackResult => ({
  bypassed: false,
  defence,
  observed,
});

/** A fresh, allocated, then LOST session for recovery-surface attacks. */
const lostSessionOf = () => {
  const created = createGpuResourceSession({ plan: PLAN });
  if (!created.ok) throw new Error(`29I fixture: session create refused: ${created.refusal}`);
  const allocations = PLAN.buffers.map((b) => ({
    bufferId: b.bufferId,
    recordCount: b.recordCount,
    strideBytes: b.strideBytes,
    usage: b.usage,
  }));
  const allocated = allocateSessionResources({ session: created.session, allocations });
  if (!allocated.ok) throw new Error(`29I fixture: allocate refused: ${allocated.refusal}`);
  const lost = markSessionDeviceLost({ session: allocated.session, reason: "simulated_contract_event" });
  if (!lost.ok) throw new Error(`29I fixture: loss refused: ${lost.refusal}`);
  return { preLoss: allocated.session, lost: lost.session, handleId: allocated.session.handles[0]?.handleId ?? "" };
};

/** Every key appearing anywhere in a JSON-shaped value. */
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

// ── the catalogue ─────────────────────────────────────────────────────────────

export const PHASE29_ATTACK_CATALOGUE: readonly AttackInput[] = Object.freeze([
  // ── conflict/refusal/partition hiding ──────────────────────────────────────
  {
    attackId: "29I-01-marker-suppression-request",
    category: "conflict_suppression",
    description: "hide mandatory conflict/refusal/partition markers through a picking request",
    run: () => {
      const d = resolvePickingSelection({
        scene: SCENE,
        plan: PLAN,
        pickingIndex: idxOf("refusal:policy-gate"),
        hideMandatoryMarkers: true,
      });
      return d.ok
        ? { bypassed: true, observed: "selection produced with markers hidden" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-02-conflict-selection-keeps-inventory",
    category: "conflict_suppression",
    description: "select the conflict subject WITHOUT carrying the scene-wide marker inventory",
    run: () => {
      const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: idxOf("conflict:recon-28j-1:node-remote") });
      if (!d.ok) return held(`selection refused: ${d.refusal}`);
      const s = d.selection;
      const intact =
        s.sceneMandatoryMarkerCount === 9 &&
        s.markersPreserved === true &&
        s.hidesMandatoryMarkers === false &&
        s.mandatoryMarkerCount === 2;
      return intact
        ? held(`subject markers ${s.mandatoryMarkerCount}, scene inventory ${s.sceneMandatoryMarkerCount}, preserved=true`, "structural")
        : { bypassed: true, observed: `own=${s.mandatoryMarkerCount} scene=${s.sceneMandatoryMarkerCount} preserved=${String(s.markersPreserved)}` };
    },
  },

  // ── stale → current ────────────────────────────────────────────────────────
  {
    attackId: "29I-03-stale-scene-hash-picking",
    category: "staleness_erosion",
    description: "present a stale scene as current to the picking resolver",
    run: () => {
      const d = resolvePickingSelection({
        scene: SCENE,
        plan: PLAN,
        pickingIndex: 0,
        currentSceneHash: SCENE_B.sceneHash,
      });
      return d.ok
        ? { bypassed: true, observed: `stale scene accepted as current: ${d.selection.pickingId}` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-04-stale-plan-into-composer",
    category: "staleness_erosion",
    description: "compose a frame from a plan built for a DIFFERENT scene",
    run: () => {
      const d = composeRuntimeFrame({ scene: SCENE_B, plan: PLAN, mapping: MAPPING_B });
      return d.ok
        ? { bypassed: true, observed: "foreign plan composed into a frame" }
        : held(d.refusal);
    },
  },

  // ── unknown → trusted ──────────────────────────────────────────────────────
  {
    attackId: "29I-05-unknown-picking-id",
    category: "identity_substitution",
    description: "mint an identity from a pickingId that exists in no table",
    run: () => {
      const d = resolvePickingSelection({
        scene: SCENE,
        plan: PLAN,
        pickingId: `pick_${"0".repeat(64)}`,
      });
      return d.ok
        ? { bypassed: true, observed: `unknown id resolved to ${d.selection.subjectVisibleId}` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-06-unknown-picking-index",
    category: "identity_substitution",
    description: "resolve an index outside the plan's row space",
    run: () => {
      const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: 99_999 });
      return d.ok
        ? { bypassed: true, observed: `out-of-range index resolved to ${d.selection.subjectVisibleId}` }
        : held(d.refusal);
    },
  },

  // ── claim → grant ──────────────────────────────────────────────────────────
  {
    attackId: "29I-07-picking-action-grant",
    category: "authority_inflation",
    description: "obtain execution/permission through a picking action field",
    run: () => {
      const d = resolvePickingSelection({ execute: true });
      return d.ok
        ? { bypassed: true, observed: "action field accepted" }
        : held(`${d.refusal}: ${d.explanation.slice(0, 120)}`);
    },
  },
  {
    attackId: "29I-08-qualification-hardware-claim",
    category: "authority_inflation",
    description: "claim qualified_hardware from an observation whose readback did not match",
    run: () => {
      const d = qualifyWebGpu({
        observation: {
          apiPresent: true,
          adapterObtained: true,
          deviceCreated: true,
          isFallbackAdapter: false,
          features: [],
          limits: {
            maxBufferSize: 134217728,
            maxTextureDimension2D: 8192,
            maxBindGroups: 4,
            maxStorageBufferBindingSize: 33554432,
            maxUniformBufferBindingSize: 65536,
            maxVertexBuffers: 4,
            maxColorAttachmentBytesPerSample: 64,
          },
          wgslCompiled: true,
          wgslMessages: [],
          pipelineCreated: true,
          drawSubmitted: true,
          renderPassSucceeded: true,
          readbackSucceeded: true,
          readbackMatchesExpectation: false,
          expectedPixel: [0, 0, 0, 255],
          observedPixel: [0, 0, 0, 0],
          userAgent: "29i-attack-agent",
        },
        sourceFrameId: SC.frame.frameId,
        canonicalVisibleHash: SC.frame.canonicalVisibleHash,
        claimedQualification: "qualified_hardware",
      });
      return d.ok
        ? { bypassed: true, observed: `claim accepted with verdict ${d.qualification.verdict}` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-09-plan-completeness-claim",
    category: "completeness_lie",
    description: "declare a render plan complete without any qualifying verdict",
    run: () => {
      const d = buildGpuRenderPlan({ scene: SCENE, requestedCompleteness: "complete" });
      return d.ok
        ? { bypassed: true, observed: `completeness '${d.plan.completeness}' accepted unqualified` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-10-frame-completeness-claim",
    category: "completeness_lie",
    description: "compose a frame claiming completeness from a gate that renders nothing",
    run: () => {
      const d = composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: SC.mapping, requestedCompleteness: "complete" });
      return d.ok
        ? { bypassed: true, observed: "completeness claim accepted by the composer" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-11-real-evidence-claim-no-observation",
    category: "unsupported_as_pass",
    description: "claim real device-loss evidence with no observation supplied",
    run: () => {
      const fixture = lostSessionOf();
      const d = recreateSessionDevice({
        session: fixture.lost,
        plan: PLAN,
        evidence: { mode: "real_device_observation" },
      });
      return d.ok
        ? { bypassed: true, observed: "real evidence claimed without observation" }
        : held(`${d.refusal}: UNSUPPORTED != PASS`);
    },
  },

  // ── route → authorization ──────────────────────────────────────────────────
  {
    attackId: "29I-12-route-relations-authorize-nothing",
    category: "authority_inflation",
    description: "extract authorization from the route root's relations",
    run: () => {
      const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: idxOf("route-28j-1") });
      if (!d.ok) return held(`selection refused: ${d.refusal}`);
      const bad = d.selection.relations.filter((r) => r.authorizes !== false || r.trust !== "none");
      return bad.length === 0
        ? held(`${d.selection.relations.length} route relations, authorizes=false and trust=none on all`, "structural")
        : { bypassed: true, observed: `${bad.length} relations conferred authorization/trust` };
    },
  },
  {
    attackId: "29I-13-route-selection-executes-nothing",
    category: "authority_inflation",
    description: "turn a route-root selection into an execution",
    run: () => {
      const r = refusePickedSelectionExecution("route-28j-1");
      return r.ok
        ? { bypassed: true, observed: "route selection executed" }
        : held(`${r.refusal}; executed=${String(r.executed)} permissionGranted=${String(r.permissionGranted)}`);
    },
  },

  // ── forwarder → origin ─────────────────────────────────────────────────────
  {
    attackId: "29I-14-forwarder-relabelled-as-origin",
    category: "identity_substitution",
    description: "relabel the forwarder subject as the route origin",
    run: () => {
      const d = resolvePickingSelection({
        scene: SCENE,
        plan: PLAN,
        pickingIndex: idxOf("route-28j-1#forwarder:node-relay"),
        claimedSubjectVisibleId: "route-28j-1#origin",
      });
      if (d.ok) return { bypassed: true, observed: `forwarder accepted as origin: ${d.selection.subjectVisibleId}` };
      if (d.refusal === "refused_picking_subject_substitution") {
        return held(`${d.refusal} (explanation never names the true subject: ${!d.explanation.includes("forwarder")})`);
      }
      return held(d.refusal);
    },
  },

  // ── observer-local → global truth ──────────────────────────────────────────
  {
    attackId: "29I-15-global-truth-key-scan",
    category: "provenance_tampering",
    description: "find a global-truth / consensus claim asserted TRUE anywhere in renderer outputs",
    run: () => {
      const selection = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: idxOf("node-local") });
      const composed = composeRuntimeFrame({ scene: SCENE, plan: PLAN, mapping: SC.mapping });
      const session = createGpuResourceSession({ plan: PLAN });
      const watched = ["globalTruth", "isGlobalTruth", "global", "consensus", "globalConsensus", "worldTruth", "universalTruth"];
      const found: string[] = [];
      for (const out of [selection.ok ? selection.selection : null, composed.ok ? composed.frame : null, session.ok ? session.session : null]) {
        if (out === null) continue;
        const record = out as unknown as Record<string, unknown>;
        for (const key of watched) {
          if (key in record && record[key] !== false && record[key] !== null) {
            found.push(`${key}=${JSON.stringify(record[key])}`);
          }
        }
      }
      const observerIsLocal = SC.frame.observer.observerId === "observer-local-a" && SCENE.sourceFrameId.length > 0;
      return found.length === 0 && observerIsLocal
        ? held(`no truth/consensus claim asserted; observer stays local (${SC.frame.observer.observerId}), frame ${SCENE.sourceFrameId}`, "structural")
        : { bypassed: true, observed: found.join(", ") || "observer not local" };
    },
  },

  // ── layout/size/depth/color authority ──────────────────────────────────────
  {
    attackId: "29I-16-hostile-layout-arity",
    category: "authority_inflation",
    description: "smuggle bytes through an overlapping, out-of-stride vertex layout",
    run: () => {
      const reason = assertLayoutArity({
        layoutId: "evil.layout",
        strideBytes: 8,
        attributes: [
          { name: "a", format: "float32", offset: 0, byteLength: 8 },
          { name: "b", format: "float32", offset: 4, byteLength: 8 },
        ],
        reservedOffsets: [],
      });
      return reason === null
        ? { bypassed: true, observed: "hostile overlapping layout accepted" }
        : held(`assertLayoutArity refused: ${reason}`, "structural");
    },
  },
  {
    attackId: "29I-17-reserved-bits-not-zero",
    category: "authority_inflation",
    description: "write meaning into reserved record bytes",
    run: () => {
      const words = new Uint32Array(8);
      words[6] = 0xdeadbeef; // vertex record, reserved word at offset 24
      const reason = assertZeroFill(words, GPU_LAYOUTS.vertex, "29I probe");
      return reason === null
        ? { bypassed: true, observed: "non-zero reserved bytes accepted" }
        : held(`assertZeroFill refused: ${reason}`, "structural");
    },
  },
  {
    attackId: "29I-18-depth-occlusion-pipeline",
    category: "authority_inflation",
    description: "install a depth-comparing pipeline that could occlude mandatory markers",
    run: () => {
      const evil = tamperPlan();
      (evil["pipelines"] as Record<string, unknown>[])[0]!["depthCompare"] = "less";
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "depth-comparing pipeline accepted for recovery" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-19-colour-free-buffer-scan",
    category: "authority_inflation",
    description: "find colour/semantic fields anywhere in GPU-bound buffer descriptors",
    run: () => {
      const blob = JSON.stringify(PLAN.buffers);
      const hits = ["colour", "color", "rgb", "hsv", "semanticRank", "subjectVisibleId"].filter((t) => blob.includes(t));
      const noText = PLAN.buffers.every((b) => b.contents !== ("presentation_geometry" as never) || typeof b.contents === "string");
      return hits.length === 0 && noText
        ? held(`buffer descriptors carry no colour/semantic keys; contents classes: ${[...new Set(PLAN.buffers.map((b) => b.contents))].join(",")}`, "structural")
        : { bypassed: true, observed: hits.join(", ") };
    },
  },

  // ── animation → execution ──────────────────────────────────────────────────
  {
    attackId: "29I-20-playback-resume-guard",
    category: "replay_to_execution",
    description: "resume runtime by playing a transition plan",
    run: () => {
      const r = refuseTransitionPlaybackResume(PLAN.planHash);
      return r.ok
        ? { bypassed: true, observed: "playback resumed runtime" }
        : held(`${r.refusal}; resumed=${String(r.resumedRuntimeState)} restored=${String(r.restoredRuntimeState)}`);
    },
  },
  {
    attackId: "29I-21-animation-mutation-guard",
    category: "replay_to_execution",
    description: "mutate GETIG or the runtime through an animation plan",
    run: () => {
      const r = refuseTransitionRuntimeMutation(PLAN.planHash);
      return r.ok
        ? { bypassed: true, observed: "animation mutated GETIG/runtime" }
        : held(`${r.refusal}; mutatedGetig=${String(r.mutatedGetig)} mutatedRuntime=${String(r.mutatedRuntime)}`);
    },
  },

  // ── visual replay → runtime replay ─────────────────────────────────────────
  {
    attackId: "29I-22-visual-replay-not-executable",
    category: "replay_to_execution",
    description: "obtain an executable replay capability from a visual transition plan",
    run: () => {
      const r = refuseTransitionPlaybackResume("seq-29i");
      if (r.ok) return { bypassed: true, observed: "visual replay became executable" };
      const honest = r.explanation.includes("VISUAL_REPLAY != EXECUTABLE_REPLAY");
      return honest
        ? held(`${r.refusal}; explanation states VISUAL_REPLAY != EXECUTABLE_REPLAY`)
        : held(`${r.refusal} (explanation missing the VISUAL_REPLAY clause)`);
    },
  },
  {
    attackId: "29I-23-unknown-order-interpolation",
    category: "timeline_tampering",
    description: "interpolate frames into a chronology the sequence never established",
    run: () => {
      const d = planGetigTransitions({
        planId: "p29i",
        sequenceId: "seq29i",
        observerId: "observer-local-a",
        epochId: "e28j",
        orderingBasis: "unknown",
        frames: [],
        interpolation: { enabled: true, stepsPerTransition: 2 },
      });
      return d.ok
        ? { bypassed: true, observed: "interpolated an unestablished order" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-24-guessed-chronology-basis",
    category: "timeline_tampering",
    description: "make the planner GUESS an ordering basis",
    run: () => {
      const d = planGetigTransitions({
        planId: "p29i",
        sequenceId: "seq29i",
        observerId: "observer-local-a",
        epochId: "e28j",
        orderingBasis: "guessed_order",
        frames: [],
        interpolation: { enabled: false, stepsPerTransition: 0 },
      });
      return d.ok
        ? { bypassed: true, observed: "guessed ordering basis accepted" }
        : held(d.refusal);
    },
  },

  // ── stale GPU buffers ──────────────────────────────────────────────────────
  {
    attackId: "29I-25-stale-handle-upload",
    category: "staleness_erosion",
    description: "upload to a buffer handle from before a device loss",
    run: () => {
      const f = lostSessionOf();
      const d = uploadToSessionHandle({ session: f.lost, handleId: f.handleId, byteLength: 16 });
      return d.ok
        ? { bypassed: true, observed: "pre-loss handle accepted an upload after loss" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-26-stale-handle-after-resize",
    category: "staleness_erosion",
    description: "reuse a frame-scoped handle invalidated by a surface reconfigure",
    run: () => {
      const created = createGpuResourceSession({ plan: PLAN });
      if (!created.ok) return held(`create refused: ${created.refusal}`);
      const allocated = allocateSessionResources({
        session: created.session,
        allocations: [{ bufferId: "buf.uniform.viewport", recordCount: 1, strideBytes: 32, usage: ["uniform"] }],
      });
      if (!allocated.ok) return held(`allocate refused: ${allocated.refusal}`);
      const resized = resizeSessionSurface({ session: allocated.session, width: 800, height: 600, scale: 1 });
      if (!resized.ok) return held(`resize refused: ${resized.refusal}`);
      const d = uploadToSessionHandle({ session: resized.session, handleId: allocated.handle?.handleId ?? "missing", byteLength: 8 });
      return d.ok
        ? { bypassed: true, observed: "invalidated frame-scoped handle accepted an upload" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-27-stale-handle-verify-post-loss",
    category: "staleness_erosion",
    description: "present a pre-loss handle as still live after recovery",
    run: () => {
      const f = lostSessionOf();
      const recovered = recreateSessionDevice({ session: f.lost, plan: PLAN });
      if (!recovered.ok) return held(`recreate refused: ${recovered.refusal}`);
      const d = verifySessionHandle({ session: recovered.session, handleId: f.handleId });
      return d.ok
        ? { bypassed: true, observed: "pre-loss handle verified live after recovery" }
        : held(d.refusal);
    },
  },

  // ── frame/scene/hash mismatch ──────────────────────────────────────────────
  {
    attackId: "29I-28-content-tamper-original-label",
    category: "provenance_tampering",
    description: "forge buffer content under the plan's ORIGINAL planHash label",
    run: () => {
      const evil = tamperPlan();
      (evil["buffers"] as Record<string, unknown>[])[0]!["contentHash"] = "f".repeat(64);
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "tampered content accepted under the original hash label" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-29-size-stride-inconsistency",
    category: "provenance_tampering",
    description: "declare a buffer size that recordCount * strideBytes does not produce",
    run: () => {
      const evil = tamperPlan();
      const buffers = evil["buffers"] as Record<string, unknown>[];
      buffers[0]!["strideBytes"] = 64;
      const recordCount = buffers[0]!["recordCount"] as number;
      evil["totalBufferBytes"] = (evil["totalBufferBytes"] as number) + recordCount * 60;
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "self-inconsistent buffer size accepted" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-30-pass-scene-mismatch",
    category: "provenance_tampering",
    description: "bind a render pass to a scene other than the one the plan claims",
    run: () => {
      const evil = tamperPlan();
      (evil["passes"] as Record<string, unknown>[])[0]!["sceneHash"] = SCENE_B.sceneHash;
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "pass bound to a foreign scene accepted" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-31-scene-equals-runtime-hash",
    category: "provenance_tampering",
    description: "collapse the scene graph into runtime state (sceneHash === runtimeStateHash)",
    run: () => {
      const evilScene = JSON.parse(JSON.stringify(SCENE)) as Record<string, unknown>;
      evilScene["runtimeStateHash"] = evilScene["sceneHash"];
      const d = buildGpuRenderPlan({ scene: evilScene });
      return d.ok
        ? { bypassed: true, observed: "scene/runtime collapse accepted" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-32-false-frame-binding-composed",
    category: "provenance_tampering",
    description: "compose a frame from a plan relabelled to a frame it was never built for",
    run: () => {
      const evil = tamperPlan();
      evil["sourceFrameId"] = "frame-evil";
      const d = composeRuntimeFrame({ scene: SCENE, plan: evil, mapping: SC.mapping });
      return d.ok
        ? { bypassed: true, observed: "false frame binding composed" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-33-recovery-label-only-tamper",
    category: "provenance_tampering",
    description:
      "at RECOVERY time (no scene in hand), relabel sourceFrameId on a content-valid plan and ask whether the label alone grants anything",
    run: () => {
      const evil = tamperPlan();
      evil["sourceFrameId"] = "frame-evil";
      const d = createGpuResourceSession({ plan: evil });
      if (!d.ok) return held(d.refusal);
      // Honest outcome: the label is accepted here because 29D's planHash does
      // not commit sourceFrameId. The COMMITTED content is unchanged, authority
      // is literal-none, and the composer refuses this exact tamper when the
      // real scene accompanies the plan (29I-32). Whether a FUTURE consumer
      // would treat boundFrameId as authority cannot be tested while 29J is not
      // executed — so this is INCONCLUSIVE, never PASS.
      return {
        inconclusive: true as const,
        observed:
          "29H accepted the relabelled sourceFrameId (content committed by planHash is unchanged, authority none, composer refuses with scene present — see 29I-32); future-consumer risk untestable while 29J not executed — recorded as 29I-OBS-1",
      };
    },
  },

  // ── semantic-token/instance mismatch ───────────────────────────────────────
  {
    attackId: "29I-34-rank-value-mismatch",
    category: "provenance_tampering",
    description: "supply a semanticRank that claims a different value than semanticValue",
    run: () => {
      const d = compileGetigScene({
        mapping: {
          schemaVersion: "menog-getig-visual/v0",
          frameId: "frame-29i-x",
          observerId: "observer-local-a",
          mappingHash: "abcdef0123456789",
          tokens: [tokenB({ axis: "knowledge", semanticValue: "known", semanticRank: getigVisualSemanticRank("knowledge", "unknown") })],
        },
        runtimeStateHash: RUNTIME_HASH,
      });
      return d.ok
        ? { bypassed: true, observed: "mismatched rank/value compiled" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-35-unanchored-instance-surfaced",
    category: "provenance_tampering",
    description: "silently misanchor an overlay instance on a subject that does not exist",
    run: () => {
      const evilScene = JSON.parse(JSON.stringify(SCENE)) as Record<string, unknown>;
      const overlays = evilScene["overlays"] as Record<string, unknown>[];
      overlays[0]!["targetId"] = "ghost:subject";
      const d = buildGpuRenderPlan({ scene: evilScene });
      if (!d.ok) return held(`plan refused: ${d.refusal}`);
      const surfaced = d.plan.notProven.some((n) => n.includes("no-anchor") || n.includes("no drawable primitive"));
      return surfaced
        ? held(`misanchor surfaced, not silent: ${d.plan.notProven.find((n) => n.includes("no-anchor") || n.includes("no drawable primitive")) ?? ""}`, "structural")
        : { bypassed: true, observed: `misanchor accepted silently; notProven=${JSON.stringify(d.plan.notProven)}` };
    },
  },

  // ── picking substitution & picking → control escape ────────────────────────
  {
    attackId: "29I-36-subject-substitution-claim",
    category: "identity_substitution",
    description: "claim a different subject than the index actually resolves to",
    run: () => {
      const d = resolvePickingSelection({
        scene: SCENE,
        plan: PLAN,
        pickingIndex: idxOf("node-local"),
        claimedSubjectVisibleId: "node-remote",
      });
      return d.ok
        ? { bypassed: true, observed: `substituted subject accepted: ${d.selection.subjectVisibleId}` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-37-tampered-picking-row",
    category: "identity_substitution",
    description: "forge a pickingId inside the plan's resolution table",
    run: () => {
      const evil = JSON.parse(JSON.stringify(PLAN)) as Record<string, unknown>;
      const rows = evil["pickingResolutions"] as Record<string, unknown>[];
      rows[0]!["pickingId"] = `pick_${"1".repeat(64)}`;
      const d = resolvePickingSelection({ scene: SCENE, plan: evil, pickingIndex: 0 });
      return d.ok
        ? { bypassed: true, observed: `forged row accepted: ${d.selection.pickingId}` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-38-every-action-field-refused",
    category: "authority_inflation",
    description: "escape picking into control through ANY declared action field",
    run: () => {
      const accepted: string[] = [];
      for (const field of GETIG_PICKING_ACTION_FIELDS) {
        const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: 0, [field]: true });
        if (d.ok) accepted.push(field);
      }
      return accepted.length === 0
        ? held(`all ${GETIG_PICKING_ACTION_FIELDS.length} action fields refused with refused_picking_action_surface`)
        : { bypassed: true, observed: `action fields accepted: ${accepted.join(", ")}` };
    },
  },
  {
    attackId: "29I-39-inspection-not-control",
    category: "inspection_injection",
    description: "turn a picking inspection into a control action or a grant",
    run: () => {
      const d = inspectPickedSubject({
        scene: SCENE,
        plan: PLAN,
        view: SC.viewLocal,
        graph: SC.graph,
        binding: BINDING,
        pickingIndex: idxOf("node-local"),
      });
      if (!d.ok) return held(`inspection refused: ${d.refusal}`);
      const insp = d.inspection;
      const safe =
        d.authority === "none" &&
        d.executionAuthorized === false &&
        insp.mutatedCanonicalState === false &&
        (insp.ok ? String((insp.result as unknown as Record<string, unknown>)["confersPermission"]) === "false" : true);
      return safe
        ? held(`operation=${insp.ok ? insp.operation : "refused"} mutatedCanonicalState=false authority=none confersPermission=false`, "structural")
        : { bypassed: true, observed: `authority=${d.authority} mutated=${String(insp.mutatedCanonicalState)}` };
    },
  },

  // ── provenance/explanation misbinding ──────────────────────────────────────
  {
    attackId: "29I-40-wrong-view-binding",
    category: "provenance_tampering",
    description: "read an explanation under a binding from another view",
    run: () => {
      const d = inspectPickedSubject({
        scene: SCENE,
        plan: PLAN,
        view: SC.viewLocal,
        graph: SC.graph,
        binding: { ...BINDING, viewHash: `dead${"0".repeat(60)}` },
        pickingIndex: idxOf("node-local"),
      });
      if (!d.ok) return held(`resolver refused: ${d.refusal}`);
      return d.inspection.ok
        ? { bypassed: true, observed: "inspection succeeded under a foreign view binding" }
        : held(`inspection refused under foreign binding: ${d.inspection.refusal}`);
    },
  },
  {
    attackId: "29I-41-explanation-not-bound",
    category: "provenance_tampering",
    description: "attach an explanation trace to a subject other than the resolved one",
    run: () => {
      const d = inspectPickedSubject({
        scene: SCENE,
        plan: PLAN,
        view: SC.viewLocal,
        graph: SC.graph,
        binding: BINDING,
        pickingIndex: idxOf("node-local"),
      });
      if (!d.ok) return held(`resolver refused: ${d.refusal}`);
      if (!d.subjectExplanation) return held("no explanation claimed when none is derivable");
      if (!d.subjectExplanation.ok) return held(`explanation refused: ${d.subjectExplanation.refusal}`);
      const bound = d.subjectExplanation.trace.subjectVisibleId === d.selection.subjectVisibleId;
      return bound
        ? held(`trace.subjectVisibleId === selection.subjectVisibleId (${d.selection.subjectVisibleId})`, "structural")
        : {
            bypassed: true,
            observed: `trace bound to ${d.subjectExplanation.trace.subjectVisibleId}, selection ${d.selection.subjectVisibleId}`,
          };
    },
  },

  // ── silent truncation/overflow ─────────────────────────────────────────────
  {
    attackId: "29I-42-truncation-knob",
    category: "completeness_lie",
    description: "shrink a plan below what the scene requires without a refusal",
    run: () => {
      const d = buildGpuRenderPlan({ scene: SCENE, requestedMaxPrimitives: 1 });
      return d.ok
        ? { bypassed: true, observed: `plan truncated to ${d.plan.entryCount} entries silently` }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-43-allocation-overflow",
    category: "completeness_lie",
    description: "wrap a byte count into a small allocation claim",
    run: () => {
      const created = createGpuResourceSession({ plan: PLAN });
      if (!created.ok) return held(`create refused: ${created.refusal}`);
      const d = allocateSessionResources({
        session: created.session,
        allocations: [{ bufferId: "buf.evil", recordCount: 2 ** 50, strideBytes: 2 ** 50, usage: ["vertex"] }],
      });
      return d.ok
        ? { bypassed: true, observed: "overflowed size accepted" }
        : held(d.refusal);
    },
  },

  // ── malformed WGSL/shader input ────────────────────────────────────────────
  {
    attackId: "29I-44-wgsl-source-compilation",
    category: "unsupported_as_pass",
    description: "submit malformed WGSL and observe how the renderer pipeline judges it",
    run: () => ({
      unsupported: true as const,
      observed:
        "no WGSL source exists anywhere in this workspace (29D ships its shader INTERFACE as data; grep over packages/durable-state/src finds no @vertex/@fragment/fn main), and no WebGPU compiler is available in this runtime — a malformed-shader compile cannot be mounted honestly here; UNSUPPORTED != PASS. The adjacent real attacks on the shader INTERFACE and pipeline descriptors run as 29I-45/29I-46.",
    }),
  },
  {
    attackId: "29I-45-foreign-shader-interface",
    category: "provenance_tampering",
    description: "install a pipeline claiming a shader interface the plan never declared",
    run: () => {
      const evil = tamperPlan();
      (evil["pipelines"] as Record<string, unknown>[])[0]!["shaderInterface"] = "evil-shader/v9";
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "foreign shader interface accepted" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-46-foreign-bindgroup-layout",
    category: "provenance_tampering",
    description: "bind a group to a layout that is not one of the declared 29D layouts",
    run: () => {
      const evil = tamperPlan();
      (evil["bindGroups"] as Record<string, unknown>[])[0]!["layout"] = "evil_layout";
      const d = createGpuResourceSession({ plan: evil });
      return d.ok
        ? { bypassed: true, observed: "foreign bind-group layout accepted" }
        : held(d.refusal);
    },
  },

  // ── device-loss state resurrection ─────────────────────────────────────────
  {
    attackId: "29I-48-resurrect-by-allocate",
    category: "staleness_erosion",
    description: "reallocate arbitrary resources on a LOST session instead of recreating from the plan",
    run: () => {
      const f = lostSessionOf();
      const d = allocateSessionResources({
        session: f.lost,
        allocations: [{ bufferId: "buf.evil", recordCount: 8, strideBytes: 32, usage: ["vertex"] }],
      });
      return d.ok
        ? { bypassed: true, observed: "lost session accepted a direct allocation" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-49-resurrect-after-release",
    category: "staleness_erosion",
    description: "use any operation on a released (terminal) session",
    run: () => {
      const created = createGpuResourceSession({ plan: PLAN });
      if (!created.ok) return held(`create refused: ${created.refusal}`);
      const released = releaseSessionResources({ session: created.session });
      if (!released.ok) return held(`release refused: ${released.refusal}`);
      const d = verifySessionHandle({ session: released.session, handleId: "h_" + "0".repeat(64) });
      return d.ok
        ? { bypassed: true, observed: "released session answered a handle operation" }
        : held(d.refusal);
    },
  },
  {
    attackId: "29I-50-foreign-plan-resurrection",
    category: "staleness_erosion",
    description: "rebuild a lost session from a DIFFERENT frame's plan",
    run: () => {
      const f = lostSessionOf();
      const d = recreateSessionDevice({ session: f.lost, plan: PLAN_B });
      return d.ok
        ? { bypassed: true, observed: "recovered from a foreign plan" }
        : held(d.refusal);
    },
  },

  // ── resource leaks ─────────────────────────────────────────────────────────
  {
    attackId: "29I-51-bounded-recovery-handle-growth",
    category: "capability_union",
    description: "grow handle resources without bound across repeated loss/recovery",
    run: () => {
      const f = lostSessionOf();
      let session = f.lost;
      let recoveries = 0;
      let refusal = "";
      for (let i = 0; i < 9; i += 1) {
        const back = recreateSessionDevice({ session, plan: PLAN });
        if (!back.ok) {
          refusal = back.refusal;
          break;
        }
        recoveries += 1;
        session = back.session;
        const again = markSessionDeviceLost({ session, reason: "simulated_contract_event" });
        if (!again.ok) return { bypassed: true, observed: `loss refused mid-loop: ${again.refusal}` };
        session = again.session;
      }
      const withinHandles = session.handles.length <= 256;
      const budgetSpent = recoveries === 8 && refusal === "refused_gpu_lifecycle_loss_budget_exceeded";
      const released = releaseSessionResources({ session });
      const liveAfterRelease = released.ok ? released.session.handles.filter((h) => h.state === "live").length : -1;
      return withinHandles && budgetSpent && released.ok && liveAfterRelease === 0
        ? held(`handles stayed <=256 (final ${session.handles.length}); recovery refused at cycle ${recoveries + 1} (${refusal}); release left 0 live`, "structural")
        : { bypassed: true, observed: `handles=${session.handles.length} recoveries=${recoveries} refusal=${refusal} liveAfterRelease=${liveAfterRelease}` };
    },
  },
  {
    attackId: "29I-52-allocation-batch-cap",
    category: "capability_union",
    description: "allocate past the live-handle cap in one batch",
    run: () => {
      const created = createGpuResourceSession({ plan: PLAN });
      if (!created.ok) return held(`create refused: ${created.refusal}`);
      const d = allocateSessionResources({
        session: created.session,
        allocations: Array.from({ length: 65 }, (_, i) => ({
          bufferId: `buf.x${i}`,
          recordCount: 1,
          strideBytes: 4,
          usage: ["vertex"],
        })),
      });
      return d.ok
        ? { bypassed: true, observed: `${d.session.handles.length} handles allocated past the cap` }
        : held(d.refusal);
    },
  },

  // ── fake causality/chronology/consensus ────────────────────────────────────
  {
    attackId: "29I-53-deterministic-ids-no-clock",
    category: "timeline_tampering",
    description: "extract chronology from ids: make two identical sessions differ as if time passed",
    run: () => {
      const a = createGpuResourceSession({ plan: PLAN });
      const b = createGpuResourceSession({ plan: PLAN });
      if (!a.ok || !b.ok) return held("session create refused");
      const allocatedA = allocateSessionResources({
        session: a.session,
        allocations: [{ bufferId: "buf.v", recordCount: 4, strideBytes: 32, usage: ["vertex"] }],
      });
      const allocatedB = allocateSessionResources({
        session: b.session,
        allocations: [{ bufferId: "buf.v", recordCount: 4, strideBytes: 32, usage: ["vertex"] }],
      });
      if (!allocatedA.ok || !allocatedB.ok) return held("allocate refused");
      const same =
        a.session.sessionId === b.session.sessionId &&
        JSON.stringify(allocatedA.session.handles.map((h) => h.handleId)) ===
          JSON.stringify(allocatedB.session.handles.map((h) => h.handleId));
      return same
        ? held(`identical bindings produced identical ids (${a.session.sessionId.slice(0, 16)}…); no clock, no counter, no randomness`, "structural")
        : { bypassed: true, observed: "ids diverged between identical bindings — chronology leaked into identity" };
    },
  },

  // ── secret/raw-content leakage ─────────────────────────────────────────────
  {
    attackId: "29I-54-marker-text-never-in-gpu-bytes",
    category: "disclosure_leak",
    description: "smuggle marker text or subject identifiers into GPU-bound buffer bytes",
    run: () => {
      const d = resolvePickingSelection({ scene: SCENE, plan: PLAN, pickingIndex: idxOf("conflict:recon-28j-1:node-remote") });
      if (!d.ok) return held(`selection refused: ${d.refusal}`);
      const markerSample = d.selection.mandatoryMarkers[0]?.text ?? "";
      const blob = JSON.stringify(PLAN.buffers);
      const leaked =
        (markerSample.length > 0 && blob.includes(markerSample)) ||
        blob.includes("conflict:recon-28j-1:node-remote") ||
        blob.includes("node-remote");
      return !leaked
        ? held(`CPU selection carries ${d.selection.mandatoryMarkers.length} marker texts; buffer bytes contain none of them or any subject id`, "structural")
        : { bypassed: true, observed: "subject/marker text found in GPU-bound buffer descriptors" };
    },
  },
  {
    attackId: "29I-55-closed-buffer-contents-vocab",
    category: "disclosure_leak",
    description: "find a buffer contents class that permits text, identity or a claim",
    run: () => {
      const classes = [...new Set(PLAN.buffers.map((b) => b.contents))];
      const texty = classes.filter((c) => /text|label|id|claim|secret|prompt/i.test(c));
      const rowsUnuploaded = PLAN.pickingResolutions.every((r) => r.uploadedToGpu === false);
      return texty.length === 0 && rowsUnuploaded
        ? held(`contents classes: ${classes.join(",")} — none permits text/identity; all ${PLAN.pickingResolutions.length} picking rows uploadedToGpu=false`, "structural")
        : { bypassed: true, observed: `texty classes: ${texty.join(",")} rowsUploaded=${!rowsUnuploaded}` };
    },
  },
]);

// ── the pack's 22 families → attacks (set-equality enforced by the suite) ────

export interface Phase29AttackFamily {
  readonly family: string;
  readonly attackIds: readonly string[];
  /** Static CODE-scan blocks in the suite that co-prove this family. */
  readonly coveredElsewhereInTests?: readonly string[];
}

export const PHASE29_ATTACK_FAMILIES: readonly Phase29AttackFamily[] = Object.freeze([
  { family: "conflict/refusal/partition hiding", attackIds: ["29I-01-marker-suppression-request", "29I-02-conflict-selection-keeps-inventory"] },
  { family: "stale→current", attackIds: ["29I-03-stale-scene-hash-picking", "29I-04-stale-plan-into-composer"] },
  { family: "unknown→trusted", attackIds: ["29I-05-unknown-picking-id", "29I-06-unknown-picking-index"] },
  { family: "claim→grant", attackIds: ["29I-07-picking-action-grant", "29I-08-qualification-hardware-claim", "29I-09-plan-completeness-claim", "29I-10-frame-completeness-claim", "29I-11-real-evidence-claim-no-observation"] },
  { family: "route→authorization", attackIds: ["29I-12-route-relations-authorize-nothing", "29I-13-route-selection-executes-nothing"] },
  { family: "forwarder→origin", attackIds: ["29I-14-forwarder-relabelled-as-origin"] },
  { family: "observer-local→global truth", attackIds: ["29I-15-global-truth-key-scan"] },
  { family: "layout/size/depth/color authority", attackIds: ["29I-16-hostile-layout-arity", "29I-17-reserved-bits-not-zero", "29I-18-depth-occlusion-pipeline", "29I-19-colour-free-buffer-scan"] },
  { family: "animation→execution", attackIds: ["29I-20-playback-resume-guard", "29I-21-animation-mutation-guard"] },
  { family: "visual replay→runtime replay", attackIds: ["29I-22-visual-replay-not-executable", "29I-23-unknown-order-interpolation", "29I-24-guessed-chronology-basis"] },
  { family: "stale GPU buffers", attackIds: ["29I-25-stale-handle-upload", "29I-26-stale-handle-after-resize", "29I-27-stale-handle-verify-post-loss"] },
  { family: "frame/scene/hash mismatch", attackIds: ["29I-28-content-tamper-original-label", "29I-29-size-stride-inconsistency", "29I-30-pass-scene-mismatch", "29I-31-scene-equals-runtime-hash", "29I-32-false-frame-binding-composed", "29I-33-recovery-label-only-tamper"] },
  { family: "semantic-token/instance mismatch", attackIds: ["29I-34-rank-value-mismatch", "29I-35-unanchored-instance-surfaced"] },
  { family: "picking substitution and picking→control escape", attackIds: ["29I-36-subject-substitution-claim", "29I-37-tampered-picking-row", "29I-38-every-action-field-refused", "29I-39-inspection-not-control"] },
  { family: "provenance/explanation misbinding", attackIds: ["29I-40-wrong-view-binding", "29I-41-explanation-not-bound"] },
  { family: "silent truncation/overflow", attackIds: ["29I-42-truncation-knob", "29I-43-allocation-overflow"] },
  { family: "malformed WGSL/shader input", attackIds: ["29I-44-wgsl-source-compilation", "29I-45-foreign-shader-interface", "29I-46-foreign-bindgroup-layout"] },
  { family: "device-loss state resurrection", attackIds: ["29I-48-resurrect-by-allocate", "29I-49-resurrect-after-release", "29I-50-foreign-plan-resurrection"] },
  { family: "resource leaks", attackIds: ["29I-51-bounded-recovery-handle-growth", "29I-52-allocation-batch-cap"] },
  { family: "fake causality/chronology/consensus", attackIds: ["29I-23-unknown-order-interpolation", "29I-24-guessed-chronology-basis", "29I-53-deterministic-ids-no-clock"] },
  { family: "secret/raw-content leakage", attackIds: ["29I-54-marker-text-never-in-gpu-bytes", "29I-55-closed-buffer-contents-vocab"], coveredElsewhereInTests: ["29I-S-secret-scan"] },
  { family: "alternate network/spawn/persist/tool/control path", attackIds: ["29I-39-inspection-not-control"], coveredElsewhereInTests: ["29I-S-alternate-path-scan"] },
]);

// Re-export the harness reducers the suite and evidence builder need.
export { runAdversarialSuite, hashAdversarialRun } from "./getigAdversarialHarness.js";
export type { AttackInput, AttackOutcome, AdversarialSummary } from "./getigAdversarialHarness.js";
