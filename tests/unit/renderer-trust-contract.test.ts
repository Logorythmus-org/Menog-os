/**
 * PHASE 29A — WEBGPU RENDERER TRUST CONTRACT — SUITE
 *
 * MODE: CONTRACT-FIRST / NO DRAW CALLS.
 *
 * This suite is the mechanical half of the 29A report. Where the module argues
 * that a property must hold, this suite checks that it does — including by
 * reading the module's own SOURCE with comments and string literals stripped,
 * so the checks read CODE rather than prose.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  PHASE29A_FORBIDDEN_TOKENS,
  RENDERER_BOUNDS,
  RENDERER_REFUSAL_CODES,
  RENDERER_SCHEMA_VERSION,
  RENDERER_SEPARATION_LAWS,
  RELATION_ROLES,
  SCENE_OVERLAY_KINDS,
  SCENE_PRIMITIVE_KINDS,
  SCENE_RELATION_KINDS,
  assertFrozenSurface,
  assertRendererSeparationLaw,
  assertRoleAxisNonCollapsible,
  buildDeviceQualificationFact,
  buildGetigScene,
  buildPickingIdentities,
  buildRenderPlan,
  buildRendererFrameMetadata,
  buildRendererInput,
  buildSceneOverlay,
  buildScenePrimitive,
  buildSceneRelation,
  type RendererInput,
  type ScenePrimitive,
  type SceneRelation,
} from "../../packages/durable-state/src/index.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(HERE, "..", "..");
const MODULE_SRC = join(ROOT, "packages", "durable-state", "src", "rendererTrustContract.ts");

/**
 * Strip comments and string literals so a source scan reads CODE.
 *
 * Without this, a module that merely NAMES a forbidden token in a doc comment
 * trips the scan, and a module that uses one inside a string literal is missed.
 * Both directions are wrong, which is why the 28K suite does the same thing.
 */
const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < n && src[i] !== quote) {
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

const RAW = readFileSync(MODULE_SRC, "utf8");
const CODE = stripLiterals(RAW);

const goodInput = (): RendererInput => {
  const r = buildRendererInput({
    sourceFrameId: "frame-1",
    sourceVisibleHash: "aa11bb22cc33dd44",
    sceneHash: "1111222233334444",
    runtimeStateHash: "5555666677778888",
    observationOnly: true,
  });
  if (!r.ok) throw new Error(`fixture refused: ${r.refusal}`);
  return r.value;
};

const goodPrimitive = (over: Record<string, unknown> = {}): ScenePrimitive => {
  const r = buildScenePrimitive({ kind: "entity", primitiveId: "node-a", position: [0, 0, 0], ...over });
  if (!r.ok) throw new Error(`fixture refused: ${r.refusal}`);
  return r.value;
};

const goodRelation = (over: Record<string, unknown> = {}): SceneRelation => {
  const r = buildSceneRelation({ kind: "forwards_to", relationId: "rel-1", fromId: "a", toId: "b", role: "forwarder", ...over });
  if (!r.ok) throw new Error(`fixture refused: ${r.refusal}`);
  return r.value;
};

// ── 1. the ten separations are pinned as data, not as prose ───────────────────

describe("29A — the ten separations are pinned", () => {
  it("declares exactly the ten laws the prompt names", () => {
    expect(RENDERER_SEPARATION_LAWS).toHaveLength(10);
    const pairs = RENDERER_SEPARATION_LAWS.map((l) => `${l.left}!=${l.right}`);
    expect(pairs).toEqual([
      "pixels!=authority",
      "sceneGraph!=runtimeState",
      "selection!=permission",
      "picking!=execution",
      "animation!=liveExecution",
      "gpuRecovery!=runtimeRecovery",
      "position!=trust",
      "size!=importance",
      "depth!=privilege",
      "color!=canonicalSemantics",
    ]);
  });

  it("the prompt's ten inequalities all appear in the module source", () => {
    // Whitespace-normalised: the module aligns the != signs in a column for
    // legibility, and a formatting choice must not be able to fail this check.
    const raw = RAW.replace(/[ \t]+/g, " ");
    for (const law of [
      "PIXELS != AUTHORITY",
      "SCENE_GRAPH != RUNTIME_STATE",
      "SELECTION != PERMISSION",
      "PICKING != EXECUTION",
      "ANIMATION != LIVE_EXECUTION",
      "GPU_RECOVERY != RUNTIME_RECOVERY",
      "POSITION != TRUST",
      "SIZE != IMPORTANCE",
      "DEPTH != PRIVILEGE",
      "COLOR != CANONICAL_SEMANTICS",
    ]) {
      expect(raw, `the module never states ${law}`).toContain(law);
    }
  });

  it("reports no collapse for an honest observation", () => {
    const collapsed = assertRendererSeparationLaw({
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      authority: "none",
      permission: "none",
      executionAuthorized: false,
      liveExecution: false,
      deviceRebuilt: false,
      runtimeStateRestoredByDeviceRecovery: false,
      trust: "none",
      importance: "none",
      privilege: "none",
      canonicalKind: "entity",
    });
    expect(collapsed).toHaveLength(0);
  });

  it("names the exact law that collapsed, rather than a generic failure", () => {
    const base = {
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      authority: "none",
      permission: "none",
      executionAuthorized: false,
      liveExecution: false,
      deviceRebuilt: false,
      runtimeStateRestoredByDeviceRecovery: false,
      trust: "none",
      importance: "none",
      privilege: "none",
      canonicalKind: "entity",
    };
    expect(assertRendererSeparationLaw({ ...base, sceneHash: base.runtimeStateHash }).map((l) => l.left)).toEqual(["sceneGraph"]);
    expect(assertRendererSeparationLaw({ ...base, authority: "operator" }).map((l) => l.left)).toEqual(["pixels"]);
    expect(assertRendererSeparationLaw({ ...base, executionAuthorized: true }).map((l) => l.left)).toEqual(["picking"]);
    expect(assertRendererSeparationLaw({ ...base, liveExecution: true }).map((l) => l.left)).toEqual(["animation"]);
    expect(assertRendererSeparationLaw({ ...base, deviceRebuilt: true, runtimeStateRestoredByDeviceRecovery: true }).map((l) => l.left)).toEqual(["gpuRecovery"]);
    expect(assertRendererSeparationLaw({ ...base, trust: "high" }).map((l) => l.left)).toEqual(["position"]);
    expect(assertRendererSeparationLaw({ ...base, importance: "critical" }).map((l) => l.left)).toEqual(["size"]);
    expect(assertRendererSeparationLaw({ ...base, privilege: "admin" }).map((l) => l.left)).toEqual(["depth"]);
    expect(assertRendererSeparationLaw({ ...base, canonicalKind: "color" }).map((l) => l.left)).toEqual(["color"]);
    expect(assertRendererSeparationLaw({ ...base, permission: "granted" }).map((l) => l.left)).toEqual(["selection"]);
  });
});

// ── 2. RendererInput: allowlist, fail-closed, bound ──────────────────────────

describe("29A — RendererInput is an allowlist that fails closed", () => {
  it("accepts the five declared fields and states zero authority", () => {
    const r = buildRendererInput({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      observationOnly: true,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.authority).toBe("none");
    expect(r.controlPlane).toBe(false);
    expect(r.readOnly).toBe(true);
    expect(r.executionAuthorized).toBe(false);
    expect(r.value.observationOnly).toBe(true);
  });

  it("refuses an unknown field rather than ignoring it (28J-OBS-5 not repeated)", () => {
    const r = buildRendererInput({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      observationOnly: true,
      approvePeer: true,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_renderer_input_unknown_field");
    expect(r.offendingField).toBe("approvePeer");
  });

  it("refuses a non-object input", () => {
    for (const bad of [null, undefined, 42, "frame-1", []]) {
      const r = buildRendererInput(bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_renderer_input_invalid");
    }
  });

  it("refuses a missing or non-string frame binding", () => {
    const r = buildRendererInput({
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      observationOnly: true,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_binding_missing");
  });

  it("refuses an unbound or malformed hash", () => {
    for (const bad of ["", "zzzz", "GG11223344556677", "abc", 12345]) {
      const r = buildRendererInput({
        sourceFrameId: "frame-1",
        sourceVisibleHash: bad,
        sceneHash: "1111222233334444",
        runtimeStateHash: "5555666677778888",
        observationOnly: true,
      });
      expect(r.ok, `accepted hash ${String(bad)}`).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_renderer_hash_unbound");
    }
  });

  it("refuses sceneHash == runtimeStateHash — SCENE_GRAPH != RUNTIME_STATE, enforced not documented", () => {
    const r = buildRendererInput({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "1111222233334444",
      observationOnly: true,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_hash_unbound");
  });

  it("refuses observationOnly that is anything other than exactly true", () => {
    for (const bad of [false, "true", 1, null]) {
      const r = buildRendererInput({
        sourceFrameId: "frame-1",
        sourceVisibleHash: "aa11bb22cc33dd44",
        sceneHash: "1111222233334444",
        runtimeStateHash: "5555666677778888",
        observationOnly: bad,
      });
      expect(r.ok, `accepted observationOnly ${String(bad)}`).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_renderer_authority_claim");
    }
  });
});

// ── 3. closed vocabularies fail closed ───────────────────────────────────────

describe("29A — unknown vocabulary fails closed", () => {
  it("ScenePrimitive refuses every kind outside the frozen union", () => {
    for (const kind of ["emergent", "critical", "", "Entity", "entity ", "gpu"]) {
      const r = buildScenePrimitive({ kind, primitiveId: "n1", position: [0, 0, 0] });
      expect(r.ok, `accepted kind ${JSON.stringify(kind)}`).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_renderer_kind_unknown");
    }
  });

  it("accepts exactly the frozen primitive kinds, including an explicit 'unknown'", () => {
    for (const kind of SCENE_PRIMITIVE_KINDS) {
      const r = buildScenePrimitive({ kind, primitiveId: "n1", position: [0, 0, 0] });
      expect(r.ok, `refused declared kind ${kind}`).toBe(true);
    }
    expect(SCENE_PRIMITIVE_KINDS).toContain("unknown");
  });

  it("SceneRelation refuses unknown kinds and unknown roles", () => {
    const badKind = buildSceneRelation({ kind: "implies", relationId: "r1", fromId: "a", toId: "b", role: "origin" });
    expect(badKind.ok).toBe(false);
    if (!badKind.ok) expect(badKind.refusal).toBe("refused_renderer_relation_unknown");

    const badRole = buildSceneRelation({ kind: "forwards_to", relationId: "r1", fromId: "a", toId: "b", role: "operator" });
    expect(badRole.ok).toBe(false);
    if (!badRole.ok) expect(badRole.refusal).toBe("refused_renderer_role_unknown");
  });

  it("SceneOverlay refuses unknown kinds", () => {
    const r = buildSceneOverlay({ kind: "authority", overlayId: "o1", targetId: "n1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_overlay_unknown");
    for (const kind of SCENE_OVERLAY_KINDS) {
      expect(buildSceneOverlay({ kind, overlayId: "o1", targetId: "n1" }).ok).toBe(true);
    }
  });

  it("every frozen vocabulary array is actually frozen", () => {
    for (const v of [SCENE_PRIMITIVE_KINDS, SCENE_RELATION_KINDS, SCENE_OVERLAY_KINDS, RELATION_ROLES, RENDERER_REFUSAL_CODES, RENDERER_SEPARATION_LAWS, RENDERER_BOUNDS, PHASE29A_FORBIDDEN_TOKENS]) {
      expect(Object.isFrozen(v)).toBe(true);
    }
    expect(() => {
      (SCENE_PRIMITIVE_KINDS as unknown as string[]).push("emergent");
    }).toThrow();
  });
});

// ── 4. every constructed surface is frozen and zero-authority ────────────────

describe("29A — constructed contracts are frozen, not merely readonly", () => {
  it("freezes the input, the primitive and its position tuple", () => {
    const input = goodInput();
    expect(Object.isFrozen(input)).toBe(true);
    const p = goodPrimitive();
    expect(Object.isFrozen(p)).toBe(true);
    expect(Object.isFrozen(p.position)).toBe(true);
  });

  it("a mutation attempt on a frozen contract throws or is a no-op", () => {
    const p = goodPrimitive();
    expect(() => {
      (p as unknown as Record<string, unknown>).trust = "high";
    }).toThrow();
    expect(p.trust).toBe("none");
  });

  it("gives every primitive trust 'none' and every relation authorizes false", () => {
    expect(goodPrimitive().trust).toBe("none");
    expect(goodPrimitive({ colorHint: "#ff0000" }).colorHint).toBe("#ff0000");
    expect(goodPrimitive({ sizeHint: 99 }).sizeHint).toBe(99);
    expect(goodPrimitive({ zOrder: 99 }).zOrder).toBe(99);
    expect(goodRelation().authorizes).toBe(false);
    expect(goodRelation().trust).toBe("none");
  });

  it("freezes the assembled scene and every element inside it", () => {
    const s = buildGetigScene({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      primitives: [goodPrimitive()],
      relations: [goodRelation()],
      overlays: [],
    });
    expect(s.ok).toBe(true);
    if (!s.ok) return;
    expect(Object.isFrozen(s.value)).toBe(true);
    expect(Object.isFrozen(s.value.primitives)).toBe(true);
    expect(Object.isFrozen(s.value.primitives[0])).toBe(true);
    expect(s.value.sceneHash).not.toBe(s.value.runtimeStateHash);
  });
});

// ── 5. the role axis is non-collapsible — forwarder != origin ────────────────

describe("29A — forwarder is never origin", () => {
  it("keeps the three roles as three distinct values", () => {
    expect([...RELATION_ROLES]).toEqual(["origin", "forwarder", "destination"]);
  });

  it("refuses an axis in which distinct routes were collapsed to one role", () => {
    const r = assertRoleAxisNonCollapsible(["origin", "origin"]);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_renderer_role_axis_collapsed");
      expect(r.scene).toBeNull();
    }
  });

  it("refuses an unknown role outright", () => {
    const r = assertRoleAxisNonCollapsible(["operator" as never]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_role_unknown");
  });

  it("accepts a genuine three-role axis", () => {
    expect(assertRoleAxisNonCollapsible(["origin", "forwarder", "destination"]).ok).toBe(true);
  });
});

// ── 6. picking names WHAT WAS HIT, never an action ──────────────────────────

describe("29A — PICKING != EXECUTION", () => {
  it("refuses any attempt to attach an action to a picking identity", () => {
    for (const field of ["action", "command", "effect", "permission", "grant", "execute", "approve"]) {
      const r = buildPickingIdentities({ observerId: "obs-1", entries: [{ kind: "subject", pickingId: "p1", subjectId: "n1", [field]: "shutdown" }] });
      expect(r.ok, `accepted picking field ${field}`).toBe(false);
      if (!r.ok) {
        expect(r.refusal).toBe("refused_renderer_picking_action_claim");
        expect(r.offendingField).toBe(field);
        expect(r.pickings).toBeNull();
      }
    }
  });

  it("the PickingIdentity type has no action, permission or effect field at all", () => {
    const r = buildPickingIdentities({ observerId: "obs-1", entries: [{ kind: "subject", pickingId: "p1", subjectId: "n1" }] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const first = r.value[0];
    expect(first).toBeDefined();
    if (first === undefined) return;
    const keys = Object.keys(first).sort();
    expect(keys).toEqual(["executionAuthorized", "kind", "observerId", "pickingId", "subjectId"]);
    expect(keys).not.toContain("action");
    expect(keys).not.toContain("permission");
    expect(first.executionAuthorized).toBe(false);
  });

  it("refuses an unknown picking kind", () => {
    const r = buildPickingIdentities({ observerId: "obs-1", entries: [{ kind: "exec", pickingId: "p1" }] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_kind_unknown");
  });
});

// ── 7. UNSUPPORTED is never PASS ─────────────────────────────────────────────

describe("29A — an unsupported plan may not declare completeness", () => {
  it("refuses completeness 'complete' when hardware is unsupported", () => {
    const r = buildRenderPlan({ sceneHash: "1111222233334444", entryCount: 10, completeness: "complete", supportsHardware: false });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_renderer_completeness_unsupported_as_pass");
      expect(r.plan).toBeNull();
    }
  });

  it("accepts 'incomplete' and 'unsupported' without hardware support", () => {
    for (const completeness of ["incomplete", "unsupported"] as const) {
      const r = buildRenderPlan({ sceneHash: "1111222233334444", entryCount: 10, completeness, supportsHardware: false });
      expect(r.ok, `refused honest ${completeness}`).toBe(true);
    }
  });

  it("names no GPU resource of any kind", () => {
    const r = buildRenderPlan({ sceneHash: "1111222233334444", entryCount: 10, completeness: "incomplete", supportsHardware: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.executionAuthorized).toBe(false);
    const keys = Object.keys(r.value);
    for (const forbidden of ["buffer", "texture", "pipeline", "bindGroup", "shader", "handle"]) {
      expect(keys).not.toContain(forbidden);
    }
  });
});

// ── 8. budgets fail closed — no silent semantic truncation ───────────────────

describe("29A — over budget refuses; it never truncates", () => {
  it("refuses a primitive count above the bound instead of trimming", () => {
    const many = Array.from({ length: RENDERER_BOUNDS.maxPrimitives + 1 }, (_, i) => goodPrimitive({ primitiveId: `n${i}` }));
    const r = buildGetigScene({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      primitives: many,
      relations: [],
      overlays: [],
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_renderer_budget_exceeded");
      expect(r.scene).toBeNull();
      expect(r.partialOutputEmitted).toBe(false);
    }
  });

  it("accepts exactly the bound", () => {
    const many = Array.from({ length: RENDERER_BOUNDS.maxPrimitives }, (_, i) => goodPrimitive({ primitiveId: `n${i}` }));
    const r = buildGetigScene({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      primitives: many,
      relations: [],
      overlays: [],
    });
    expect(r.ok).toBe(true);
  });

  it("refuses an over-long label rather than shortening it", () => {
    const r = buildScenePrimitive({ kind: "entity", primitiveId: "n1", position: [0, 0, 0], label: "x".repeat(RENDERER_BOUNDS.maxLabelLength + 1) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_budget_exceeded");
  });

  it("every refusal carries zero authority and emits nothing", () => {
    const refusals = [
      buildRendererInput(null),
      buildScenePrimitive({ kind: "nope" }),
      buildSceneRelation({ kind: "nope" }),
      buildSceneOverlay({ kind: "nope" }),
      buildPickingIdentities({ observerId: "o", entries: [{ kind: "subject", action: "x" }] }),
      buildRenderPlan({ sceneHash: "1111222233334444", entryCount: 1, completeness: "complete", supportsHardware: false }),
    ];
    for (const r of refusals) {
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.code).toBe("renderer_refused");
      expect(r.authority).toBe("none");
      expect(r.controlPlane).toBe(false);
      expect(r.readOnly).toBe(true);
      expect(r.executionAuthorized).toBe(false);
      expect(r.scene).toBeNull();
      expect(r.plan).toBeNull();
      expect(r.pickings).toBeNull();
      expect(r.partialOutputEmitted).toBe(false);
      expect(RENDERER_REFUSAL_CODES).toContain(r.refusal);
    }
  });
});

// ── 9. device qualification is a FACT, and can never claim hardware validation ─

describe("29A — DeviceQualificationFact cannot assert hardware validation", () => {
  it("always reports hardwareValidated false, whatever the caller says", () => {
    const r = buildDeviceQualificationFact({
      vendor: "amd",
      isFallbackAdapter: false,
      featureCount: 9,
      maxBufferSize: 2147483648,
      maxTextureDimension2D: 16384,
      hardwareValidated: true,
    } as never);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.hardwareValidated).toBe(false);
    expect(r.value.qualification).toBe("unqualified");
    // Exactly the seven declared fields. The caller's `hardwareValidated: true`
    // did not become an eighth field, and nothing else leaked through either.
    expect(Object.keys(r.value).sort()).toEqual([
      "featureCount",
      "hardwareValidated",
      "isFallbackAdapter",
      "maxBufferSize",
      "maxTextureDimension2D",
      "qualification",
      "vendor",
    ]);
  });

  it("will not accept a qualification outside the declared union", () => {
    const r = buildDeviceQualificationFact({
      vendor: "amd",
      isFallbackAdapter: false,
      featureCount: 9,
      maxBufferSize: 1,
      maxTextureDimension2D: 1,
      qualification: "validated",
    } as never);
    expect(r.ok).toBe(false);
  });

  it("refuses a fact with no vendor — an unqualified claim is not a fact", () => {
    const r = buildDeviceQualificationFact({ vendor: "", isFallbackAdapter: false, featureCount: 0, maxBufferSize: 0, maxTextureDimension2D: 0 });
    expect(r.ok).toBe(false);
  });
});

// ── 10. frame metadata is bound and renderer-neutral ────────────────────────

describe("29A — frame metadata binds four hashes and names no backend", () => {
  it("binds frame, canonical, scene and plan identities", () => {
    const r = buildRendererFrameMetadata({
      frameId: "frame-1",
      canonicalVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      planHash: "9999888877776666",
      observerId: "obs-1",
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.graphicsBackend).toBe("none");
    expect(r.value.authority).toBe("none");
    expect(r.value.executionAuthorized).toBe(false);
    const ids = new Set([r.value.canonicalVisibleHash, r.value.sceneHash, r.value.planHash]);
    expect(ids.size).toBe(3);
  });

  it("refuses metadata whose hashes are not hashes", () => {
    const r = buildRendererFrameMetadata({ frameId: "f", canonicalVisibleHash: "nope", sceneHash: "1111222233334444", planHash: "9999888877776666", observerId: "o" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_renderer_hash_unbound");
  });
});

// ── 11. frozen is enforced, not merely promised ────────────────────────────

describe("29A — a mutable surface is refused, not merely discouraged", () => {
  it("accepts every contract this module builds", () => {
    expect(assertFrozenSurface(goodInput()).ok).toBe(true);
    expect(assertFrozenSurface(goodPrimitive()).ok).toBe(true);
    expect(assertFrozenSurface(goodRelation()).ok).toBe(true);
  });

  it("accepts a scene whose nested collections are frozen too", () => {
    const s = buildGetigScene({
      sourceFrameId: "frame-1",
      sourceVisibleHash: "aa11bb22cc33dd44",
      sceneHash: "1111222233334444",
      runtimeStateHash: "5555666677778888",
      primitives: [goodPrimitive()],
      relations: [goodRelation()],
      overlays: [],
    });
    expect(s.ok).toBe(true);
    if (!s.ok) return;
    expect(assertFrozenSurface(s.value, ["primitives", "relations", "overlays"]).ok).toBe(true);
  });

  it("refuses an unfrozen surface — a plain object literal is not a contract", () => {
    const loose = { kind: "entity", primitiveId: "n1", trust: "none" };
    expect(Object.isFrozen(loose)).toBe(false);
    const r = assertFrozenSurface(loose);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_renderer_mutable_surface");
      expect(r.scene).toBeNull();
    }
  });

  it("refuses a frozen object whose NESTED collection is mutable", () => {
    const outer = Object.freeze({ sceneHash: "1111222233334444", primitives: [goodPrimitive()] });
    expect(Object.isFrozen(outer)).toBe(true);
    expect(Object.isFrozen(outer.primitives)).toBe(false);
    const r = assertFrozenSurface(outer, ["primitives"]);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_renderer_mutable_surface");
      expect(r.offendingField).toBe("primitives");
    }
  });

  it("a readonly type annotation alone does not pass — only freezing does", () => {
    // This is the whole reason the function exists: `readonly` is erased, so a
    // hand-built object with the right shape and no Object.freeze must fail.
    const typedAsPrimitive: ScenePrimitive = {
      kind: "entity",
      primitiveId: "n1",
      label: "",
      colorHint: "none",
      sizeHint: 1,
      zOrder: 0,
      trust: "none",
      position: [0, 0, 0],
    };
    expect(typedAsPrimitive.trust).toBe("none");
    expect(assertFrozenSurface(typedAsPrimitive).ok).toBe(false);
  });
});

// ── 12. the load-bearing source claims, checked against CODE ────────────────

describe("29A — the module contains no GPU call at all", () => {
  it("no forbidden WebGPU token appears in the module's code", () => {
    for (const token of PHASE29A_FORBIDDEN_TOKENS) {
      expect(CODE.includes(token), `renderer trust contract contains ${token}`).toBe(false);
    }
  });

  it("the scan reads code, not text — a token named in a comment is invisible to it", () => {
    // If this ever fails, stripLiterals has regressed and every scan above is
    // reading prose rather than code, which would make them all vacuous.
    expect(CODE).not.toContain("GPUDevice");
    expect(readFileSync(MODULE_SRC, "utf8")).toContain("GPUDevice");
  });

  it("the module reaches no control, tool, network or process surface", () => {
    expect(CODE).not.toMatch(/\b(execute|approve|admit|grant|kill|restart|spawn|fork|exec)\s*\(/);
    expect(CODE).not.toMatch(/\b(fetch|WebSocket|net\.|dgram|http\.|https\.)\b/);
    expect(CODE).not.toMatch(/process\.env|Date\.now|Math\.random|performance\.now/);
  });

  it("declares a schema version and ten separations, and exports them", () => {
    expect(RENDERER_SCHEMA_VERSION).toBe("menog-renderer-trust-contract/v0");
    expect(RENDERER_SEPARATION_LAWS).toHaveLength(10);
    expect(RENDERER_REFUSAL_CODES.length).toBeGreaterThanOrEqual(10);
  });

  it("every refusal code the module can emit is in the frozen list", () => {
    // Scanned against the RAW source, not CODE: refusal codes ARE string
    // literals, and stripLiterals replaces every literal with "". Reading them
    // from CODE finds nothing and would make this check silently vacuous.
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(\s*"([a-z_]+)"/g)) emitted.add(m[1] as string);
    expect(emitted.size, "no refusal code was found — the scan is vacuous").toBeGreaterThan(0);
    for (const code of emitted) expect(RENDERER_REFUSAL_CODES, `${code} is emitted but not declared`).toContain(code);
  });

  it("every DECLARED refusal code is reachable — no code exists that never fires", () => {
    // The reverse direction. A declared-but-unreachable refusal code is a claim
    // the module makes about itself and does not honour; it is also the shape a
    // removed guard leaves behind, which is exactly how 29A-F0 escaped notice.
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(\s*"([a-z_]+)"/g)) emitted.add(m[1] as string);
    for (const declared of RENDERER_REFUSAL_CODES) {
      expect(emitted, `${declared} is declared but never emitted`).toContain(declared);
    }
  });
});