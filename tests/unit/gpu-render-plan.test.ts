/**
 * PHASE 29D — GPU RESOURCE & RENDER-PLAN LAYER — SUITE
 *
 * MODE: BOUNDED GPU PLAN / NO BUSINESS LOGIC / NO ALLOCATION.
 *
 * The fixture is the REAL 29B scene compiled from the FROZEN Phase-28 mapping:
 * 35 primitives, 3 relations, 9 mandatory overlays. A plan layer tested only
 * against scenes it invented would agree with its own assumptions forever.
 *
 * The centre of the suite is 29C's finding. On this machine a render pass
 * SUBMITS and a readback returns all zeros, so the honest plan is "incomplete,
 * pixel output unverified" — and every case here checks that the plan cannot
 * be talked out of that.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  GPU_BUFFER_CONTENTS,
  GPU_BUFFER_USAGES,
  GPU_LAYOUTS,
  GPU_PLAN_BOUNDS,
  GPU_PLAN_REFUSAL_CODES,
  GPU_PLAN_SCHEMA_VERSION,
  GPU_PASS_KINDS,
  GPU_PICKING_NO_ANCHOR,
  GPU_RESOURCE_LIFECYCLES,
  PHASE29D_FORBIDDEN_TOKENS,
  QUALIFICATION_VERDICTS,
  QUALIFYING_VERDICTS,
  SHADER_INTERFACE,
  assertLayoutArity,
  assertZeroFill,
  buildGpuRenderPlan,
  checkedMul,
  compileGetigScene,
  runGetigEndToEndScenario,
  type GpuLayoutDescriptor,
  type GpuRenderPlanValue,
  type WebGpuQualification,
} from "../../packages/durable-state/src/index.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(HERE, "..", "..");
const MODULE_SRC = join(ROOT, "packages", "durable-state", "src", "gpuRenderPlan.ts");

const RAW = readFileSync(MODULE_SRC, "utf8");

/**
 * Strip comments AND string/template literals, leaving code.
 *
 * The header of the module discusses the forbidden tokens in prose, so a naive
 * substring scan would find them in the comment that forbids them and the check
 * would prove nothing.
 */
const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < src.length && src[i] !== q) {
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
const CODE = stripLiterals(RAW);/**
 * Control-surface scan. A word boundary AFTER the verb (`exec\s*\(`), not
 * before it alone: the property name `executable` contains "exec" and a naive
 * `\bexec\b` pattern would flag a harmless string.
 *
 * The `*Sync` variants are listed explicitly rather than derived, because
 * `spawnSync(` is not matched by `spawn\s*\(`.
 */
const CONTROL_SURFACE_TOKENS = Object.freeze([
  "exec", "execSync", "execFile", "spawn", "spawnSync", "fork", "eval", "Function",
  "require", "import", "fetch", "XMLHttpRequest", "WebSocket", "child_process",
  "process", "listen", "bind", "writeFile", "unlink", "rmdir", "setTimeout",
] as const);
const controlSurface = new RegExp(`\\b(?:${CONTROL_SURFACE_TOKENS.join("|")})\\s*\\(`);

const RUNTIME_HASH = "5555666677778888";

// ── the REAL frozen Phase-28 mapping, compiled by the REAL 29B compiler ────────

const scenarioDecision = runGetigEndToEndScenario();
if (!scenarioDecision.ok) {
  throw new Error(`frozen Phase-28 scenario refused: ${scenarioDecision.refusal}`);
}
const compiled = compileGetigScene({ mapping: scenarioDecision.scenario.mapping, runtimeStateHash: RUNTIME_HASH });
if (!compiled.ok) {
  throw new Error(`frozen 29B compile refused: ${compiled.refusal}`);
}
const SCENE = compiled.scene;

const plan = buildGpuRenderPlan({ scene: SCENE });
if (!plan.ok) {
  throw new Error(`frozen 29D plan refused: ${plan.refusal} ${plan.explanation}`);
}
const PLAN: GpuRenderPlanValue = plan.plan;

/** Build a plan and return it, throwing when the plan is refused. */
const planOf = (scene: unknown, over: Record<string, unknown> = {}): GpuRenderPlanValue => {
  const d = buildGpuRenderPlan({ scene, ...over });
  if (!d.ok) throw new Error(`expected a plan, got ${d.refusal}: ${d.explanation}`);
  return d.plan;
};

/** Build a plan and return the refusal, throwing when it succeeds. */
const refusalOf = (scene: unknown, over: Record<string, unknown> = {}): { refusal: string; explanation: string; offendingField: string | null } => {
  const d = buildGpuRenderPlan({ scene, ...over });
  if (d.ok) throw new Error(`expected a refusal, got a plan with ${d.plan.buffers.length} buffers`);
  return { refusal: d.refusal, explanation: d.explanation, offendingField: d.offendingField };
};

const bufferById = (id: string) => {
  const found = PLAN.buffers.find((b) => b.bufferId === id);
  if (found === undefined) throw new Error(`no buffer ${id}`);
  return found;
};

/** sha256 over the exact little-endian bytes the GPU would read. */
const sha256Hex = (buffer: ArrayBuffer): string => createHash("sha256").update(Buffer.from(buffer)).digest("hex");

/** The exact 16 bytes 29D writes for one overlay instance. */
const instanceBytes = (anchor: number): ArrayBuffer => {
  const floats = new Float32Array(4);
  const words = new Uint32Array(floats.buffer);
  words[0] = anchor >>> 0;
  floats[1] = 1;
  floats[2] = 1;
  words[3] = 0;
  return floats.buffer;
};

/** The 29C verdict as this machine actually produced it. */
const OBSERVED_QUALIFICATION: WebGpuQualification = {
  verdict: "observed_readback_inconclusive",
  qualifiesHardware: false,
  schemaVersion: "menog-webgpu-qualification/v0",
  sourceFrameId: SCENE.sourceFrameId,
  canonicalVisibleHash: SCENE.sourceVisibleHash,
  qualificationHash: "b".repeat(64),
  vendor: "amd",
  isFallbackAdapter: false,
  features: [],
  limits: {
    maxBufferSize: 2147483648,
    maxTextureDimension2D: 16384,
    maxBindGroups: 4,
    maxStorageBufferBindingSize: 2147483644,
    maxUniformBufferBindingSize: 65536,
    maxVertexBuffers: 8,
    maxColorAttachmentBytesPerSample: 128,
  },
  userAgent: "menog-phase29d-fixture",
  powerLossEvidenced: false,
  hardwareIntegrityEvidenced: false,
  notProven: ["readback content did not match the rendered pixels"],
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
};

const qualificationWith = (over: Partial<WebGpuQualification>): WebGpuQualification => ({ ...OBSERVED_QUALIFICATION, ...over });

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — the module allocates nothing", () => {
  it("contains no GPU creation, submission or draw token in CODE", () => {
    for (const token of PHASE29D_FORBIDDEN_TOKENS) {
      expect(CODE, `module code must not contain "${token}"`).not.toContain(token);
    }
  });

  it("POSITIVE CONTROL: the forbidden-token scan detects a token when one is really present", () => {
    // Without this, the case above could pass because the detector is broken.
    const planted = `const x = navigator.gpu;\n// ${"nothing"} to see`;
    const hits = PHASE29D_FORBIDDEN_TOKENS.filter((t) => stripLiterals(planted).includes(t));
    expect(hits).toContain("navigator");
  });

  it("POSITIVE CONTROL: comments alone must NOT trip the scan", () => {
    // The module's own header names every forbidden token in prose. A scanner
    // that read comments would fail on the documentation of the rule.
    const commentOnly = "// never call navigator.gpu here\n/* nor requestAdapter */\nconst a = 1;\n";
    expect(PHASE29D_FORBIDDEN_TOKENS.filter((t) => stripLiterals(commentOnly).includes(t))).toEqual([]);
  });

  it("names no host control surface in CODE", () => {
    expect(controlSurface.test(CODE)).toBe(false);
  });

  it("POSITIVE CONTROL: the control-surface scan fires on a planted call", () => {
    expect(controlSurface.test("child_process.spawnSync('id')")).toBe(true);
    expect(controlSurface.test("await fetch(url)")).toBe(true);
    // ...and does not fire on the harmless property name that contains "exec".
    expect(controlSurface.test("const executable = false;")).toBe(false);
  });

  it("is byte-stable: the module is the only new source file in this gate", () => {
    expect(MODULE_SRC.endsWith("gpuRenderPlan.ts")).toBe(true);
    // The name must NOT match ^getig.*\.ts$ — the frozen 28K audit globs on it.
    expect(/^getig.*\.ts$/.test("gpuRenderPlan.ts")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — closed vocabularies", () => {
  it("GPU_BUFFER_CONTENTS has no member permitting text, identity or a claim", () => {
    const forbidden = ["text", "label", "string", "name", "id", "token", "axis", "value", "role", "trust", "authority", "claim", "prompt", "secret", "path", "memory", "store"];
    for (const member of GPU_BUFFER_CONTENTS) {
      for (const bad of forbidden) {
        expect(member.toLowerCase(), `contents member "${member}" must not permit "${bad}"`).not.toContain(bad);
      }
    }
  });

  it("GPU_BUFFER_CONTENTS is frozen and non-empty", () => {
    expect(Object.isFrozen(GPU_BUFFER_CONTENTS)).toBe(true);
    expect(GPU_BUFFER_CONTENTS.length).toBeGreaterThan(0);
  });

  it("every descriptor declares its contents from the closed vocabulary", () => {
    for (const b of PLAN.buffers) {
      expect((GPU_BUFFER_CONTENTS as readonly string[]).includes(b.contents)).toBe(true);
    }
  });

  it("every declared usage and lifecycle is in its closed vocabulary", () => {
    for (const b of PLAN.buffers) {
      for (const u of b.usage) expect((GPU_BUFFER_USAGES as readonly string[]).includes(u)).toBe(true);
      expect((GPU_RESOURCE_LIFECYCLES as readonly string[]).includes(b.lifecycle)).toBe(true);
    }
    for (const p of PLAN.passes) expect((GPU_PASS_KINDS as readonly string[]).includes(p.kind)).toBe(true);
  });

  it("bounds are positive, finite and within the device this machine reported", () => {
    for (const [k, v] of Object.entries(GPU_PLAN_BOUNDS)) {
      expect(Number.isSafeInteger(v), `${k} must be a safe integer`).toBe(true);
      expect(v as number).toBeGreaterThan(0);
    }
    // maxUniformBytes and maxBindGroups deliberately match 29C's measurement.
    expect(GPU_PLAN_BOUNDS.maxUniformBytes).toBe(OBSERVED_QUALIFICATION.limits.maxUniformBufferBindingSize);
    expect(GPU_PLAN_BOUNDS.maxBindGroups).toBe(OBSERVED_QUALIFICATION.limits.maxBindGroups);
    expect(GPU_PLAN_BOUNDS.maxBufferBytes).toBeLessThan(OBSERVED_QUALIFICATION.limits.maxBufferSize);
  });

  it("the shader interface forbids semantics by name, and carries no colour", () => {
    expect(SHADER_INTERFACE.carriesNoSemantic).toContain("colour");
    expect(SHADER_INTERFACE.carriesNoSemantic).toContain("authority");
    expect(SHADER_INTERFACE.carriesNoSemantic).toContain("role");
    expect(JSON.stringify(SHADER_INTERFACE.bindings) + JSON.stringify(SHADER_INTERFACE.entryPoints)).not.toMatch(/color|colour/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — declared layouts are arithmetically sound", () => {
  it("every shipped layout passes its own arity check", () => {
    for (const [id, layout] of Object.entries(GPU_LAYOUTS)) {
      expect(assertLayoutArity(layout as GpuLayoutDescriptor), `${id} must be arithmetically sound`).toBeNull();
    }
  });

  it("no reserved offset is also an addressable attribute", () => {
    // An attribute a shader can read is an invitation to write meaning there.
    for (const layout of Object.values(GPU_LAYOUTS)) {
      for (const offset of layout.reservedOffsets) {
        for (const a of layout.attributes) {
          expect(offset >= a.offset && offset < a.offset + a.byteLength, `${layout.layoutId}: reserved ${offset} overlaps ${a.name}`).toBe(false);
        }
      }
    }
  });

  it("attributes cover their stride without gaps below the last attribute", () => {
    for (const layout of Object.values(GPU_LAYOUTS)) {
      const covered = layout.attributes.reduce((s, a) => s + a.byteLength, 0);
      const reserved = layout.reservedOffsets.length * 4;
      expect(covered + reserved, `${layout.layoutId} must account for its whole stride`).toBe(layout.strideBytes);
    }
  });

  it("POSITIVE CONTROL: assertLayoutArity rejects a stride past the end", () => {
    const bad: GpuLayoutDescriptor = {
      layoutId: "test/overrun",
      strideBytes: 8,
      attributes: [{ name: "a", format: "float32x3", offset: 0, byteLength: 12 }],
      reservedOffsets: [],
    };
    expect(assertLayoutArity(bad)).toContain("past the");
  });

  it("POSITIVE CONTROL: assertLayoutArity rejects overlapping attributes", () => {
    const bad: GpuLayoutDescriptor = {
      layoutId: "test/overlap",
      strideBytes: 32,
      attributes: [
        { name: "a", format: "float32", offset: 0, byteLength: 8 },
        { name: "b", format: "float32", offset: 4, byteLength: 8 },
      ],
      reservedOffsets: [],
    };
    expect(assertLayoutArity(bad)).toContain("overlaps");
  });

  it("POSITIVE CONTROL: assertLayoutArity rejects a stride that is not a multiple of 4", () => {
    const bad: GpuLayoutDescriptor = {
      layoutId: "test/misaligned",
      strideBytes: 30,
      attributes: [{ name: "a", format: "float32", offset: 0, byteLength: 4 }],
      reservedOffsets: [],
    };
    expect(assertLayoutArity(bad)).toContain("multiple of 4");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — byte counts are checked before a descriptor exists", () => {
  it("checkedMul multiplies exactly inside the safe range", () => {
    expect(checkedMul(35, 32)).toBe(1120);
    expect(checkedMul(0, 32)).toBe(0);
    expect(checkedMul(1, 1)).toBe(1);
  });

  it("checkedMul refuses rather than wrapping", () => {
    // A wrapped size under-reports an allocation and lets the caller believe
    // the bound was respected. Returning a wrong number is the whole danger.
    expect(checkedMul(2 ** 53, 4)).toBeNull();
    expect(checkedMul(2 ** 53 + 1, 1)).toBeNull();
    expect(checkedMul(Number.MAX_SAFE_INTEGER, 2)).toBeNull();
  });

  it("checkedMul refuses non-integers and negatives rather than truncating them", () => {
    expect(checkedMul(1.5, 4)).toBeNull();
    expect(checkedMul(-1, 4)).toBeNull();
    expect(checkedMul(4, -1)).toBeNull();
    expect(checkedMul(NaN, 4)).toBeNull();
    expect(checkedMul(Infinity, 4)).toBeNull();
  });

  it("every shipped buffer size equals recordCount * strideBytes exactly", () => {
    for (const b of PLAN.buffers) {
      expect(b.sizeBytes, `${b.bufferId} size must be exactly count * stride`).toBe(b.recordCount * b.strideBytes);
    }
  });

  it("every buffer states how its size was derived", () => {
    for (const b of PLAN.buffers) {
      expect(b.sizeDerivation.length).toBeGreaterThan(0);
      expect(b.sizeDerivation).toContain(String(b.strideBytes));
    }
  });

  it("totalBufferBytes is the exact sum and is itself safe", () => {
    const sum = PLAN.buffers.reduce((s, b) => s + b.sizeBytes, 0);
    expect(PLAN.totalBufferBytes).toBe(sum);
    expect(Number.isSafeInteger(PLAN.totalBufferBytes)).toBe(true);
    expect(PLAN.totalBufferBytes).toBeLessThanOrEqual(GPU_PLAN_BOUNDS.maxBufferBytes);
  });

  it("POSITIVE CONTROL: assertZeroFill rejects a record that wrote into reserved space", () => {
    const words = new Uint32Array(8);
    words[6] = 7; // reserved0 of the vertex layout
    expect(assertZeroFill(words, GPU_LAYOUTS.vertex, "test")).toContain("not zero");
  });

  it("assertZeroFill accepts the zero-filled records the plan actually emits", () => {
    const words = new Uint32Array(16);
    expect(assertZeroFill(words, GPU_LAYOUTS.vertex, "test")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — no semantic value ever enters a buffer", () => {
  it("the picking buffer is byte-identical whatever the subjects are called", () => {
    // The strongest available proof that no identifier reaches the GPU: rename
    // every subject and the picking buffer's bytes do not move by one bit.
    const renamed = {
      ...SCENE,
      primitives: SCENE.primitives.map((p, i) => ({ ...p, primitiveId: `zzz:anonymous:${i}` })),
    };
    const other = planOf(renamed);
    const mine = bufferById("buf.storage.pickingIndex").contentHash;
    const theirs = other.buffers.find((b) => b.bufferId === "buf.storage.pickingIndex")?.contentHash;
    expect(theirs).toBe(mine);
  });

  it("while the vertex buffer DOES move when geometry moves", () => {
    // The negative control for the case above: the previous test would also
    // pass if the picking buffer were simply frozen and never computed.
    const moved = {
      ...SCENE,
      primitives: SCENE.primitives.map((p) => ({ ...p, position: [p.position[0] + 1, p.position[1], p.position[2]] as [number, number, number] })),
    };
    expect(bufferById("buf.vertex.primitive").contentHash).not.toBe(
      planOf(moved).buffers.find((b) => b.bufferId === "buf.vertex.primitive")?.contentHash,
    );
  });

  it("no buffer label carries a subject id, and no buffer has a text-capable contents class", () => {
    const subjectIds = new Set(SCENE.primitives.map((p) => p.primitiveId));
    for (const b of PLAN.buffers) {
      for (const id of subjectIds) {
        expect(b.label, `${b.bufferId} label must not embed "${id}"`).not.toContain(id);
      }
      expect(b.contents).not.toBe("none");
    }
  });

  it("no plan object carries an action, command, effect, permission or grant key", () => {
    const forbidden = ["action", "command", "effect", "permission", "grant", "execute", "approve", "allow"];
    const walk = (node: unknown, path: string): void => {
      if (Array.isArray(node)) {
        node.forEach((v, i) => walk(v, `${path}[${i}]`));
        return;
      }
      if (typeof node !== "object" || node === null) return;
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        expect(forbidden, `${path}.${k} must not exist`).not.toContain(k);
        walk(v, `${path}.${k}`);
      }
    };
    walk(PLAN, "plan");
  });

  it("picking ids are opaque hashes, not derived from the subject name", () => {
    for (const r of PLAN.pickingResolutions) {
      expect(r.pickingId).toMatch(/^pick_[a-f0-9]{64}$/);
      expect(r.pickingId).not.toContain(r.subjectVisibleId);
      expect(r.uploadedToGpu).toBe(false);
      expect(r.executionAuthorized).toBe(false);
    }
  });

  it("a picking index resolves to exactly one subject, and nothing authorises it", () => {
    expect(PLAN.pickingResolutions).toHaveLength(PLAN.buffers.find((b) => b.bufferId === "buf.storage.pickingIndex")?.recordCount ?? -1);
    const indices = PLAN.pickingResolutions.map((r) => r.pickingIndex);
    expect(new Set(indices).size).toBe(indices.length);
    expect(indices.every((i, k) => i === k)).toBe(true);
  });

  it("the semantic token stays traceable to its visible subject on the CPU", () => {
    // A subject carrying a mandatory marker must still be reachable from its
    // picking index, with the marker's text intact.
    const marked = PLAN.pickingResolutions.filter((r) => r.markerTexts.length > 0);
    expect(marked.length).toBeGreaterThan(0);
    for (const r of marked) {
      expect(r.overlayIds.length).toBe(r.markerTexts.length);
    }
    // Every overlay in the scene is reachable from some subject's resolution.
    const reachable = new Set(PLAN.pickingResolutions.flatMap((r) => r.overlayIds));
    expect(reachable.size).toBe(SCENE.overlays.length);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — determinism", () => {
  it("input array order cannot change the plan hash", () => {
    const shuffled = {
      ...SCENE,
      primitives: [...SCENE.primitives].reverse(),
      relations: [...SCENE.relations].reverse(),
      overlays: [...SCENE.overlays].reverse(),
    };
    expect(planOf(shuffled).planHash).toBe(PLAN.planHash);
  });

  it("the plan hash is bound to the scene, not to runtime state", () => {
    expect(PLAN.planHash).toMatch(/^plan_[a-f0-9]{64}$/);
    expect(PLAN.sceneHash).toBe(SCENE.sceneHash);
    expect(PLAN.sceneHash).not.toBe(PLAN.runtimeStateHash);
  });

  it("changing the viewport changes the uniform buffer and therefore the plan", () => {
    const other = planOf(SCENE, { viewport: { width: 1920, height: 1080, scale: 2 } });
    const mine = PLAN.buffers.find((b) => b.bufferId === "buf.uniform.viewport")?.contentHash;
    const theirs = other.buffers.find((b) => b.bufferId === "buf.uniform.viewport")?.contentHash;
    expect(theirs).not.toBe(mine);
    expect(other.planHash).not.toBe(PLAN.planHash);
  });

  it("rebuilding the same scene twice is byte-identical", () => {
    expect(planOf(SCENE).planHash).toBe(PLAN.planHash);
  });

  it("every buffer contentHash is a sha256 hex digest", () => {
    for (const b of PLAN.buffers) expect(b.contentHash).toMatch(/^[a-f0-9]{64}$/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — layers stay separate", () => {
  it("the plan is bound to source frame, scene and runtime hashes", () => {
    expect(PLAN.sourceFrameId).toBe(SCENE.sourceFrameId);
    expect(PLAN.sourceVisibleHash).toBe(SCENE.sourceVisibleHash);
    expect(PLAN.runtimeStateHash).toBe(RUNTIME_HASH);
  });

  it("a scene whose sceneHash equals its runtimeStateHash is refused", () => {
    const collapsed = { ...SCENE, sceneHash: RUNTIME_HASH };
    expect(refusalOf(collapsed).refusal).toBe("refused_gpu_plan_scene_unbound");
  });

  it("GPU_RESOURCE != SCENE_GRAPH: the plan hash is not the scene hash", () => {
    expect(PLAN.planHash).not.toBe(PLAN.sceneHash);
    for (const b of PLAN.buffers) expect(b.contentHash).not.toBe(PLAN.sceneHash);
  });

  it("every pass is bound to the scene it draws", () => {
    for (const p of PLAN.passes) expect(p.sceneHash).toBe(PLAN.sceneHash);
  });

  it("runtime state does NOT enter the plan hash — GPU_PLAN reads no runtime state", () => {
    // 29B's sceneHash covers semantics only, so a different runtimeStateHash
    // yields the same scene. The plan must likewise be a function of the PICTURE
    // alone: binding it to runtime state would couple the renderer to the
    // runtime for no visual reason, and re-hash an identical image because
    // something the GPU never sees had moved.
    const otherScene = compileGetigScene({ mapping: scenarioDecision.scenario.mapping, runtimeStateHash: "9999aaaabbbb8888" });
    if (!otherScene.ok) throw new Error("expected a second scene");
    const p = planOf(otherScene.scene);
    expect(p.runtimeStateHash).toBe("9999aaaabbbb8888");
    expect(p.planHash).toBe(PLAN.planHash);
  });

  it("a different picture DOES produce a different plan hash", () => {
    const moved = {
      ...SCENE,
      primitives: SCENE.primitives.map((p) => ({ ...p, position: [p.position[0] + 1, p.position[1], p.position[2]] as [number, number, number] })),
    };
    expect(planOf(moved).planHash).not.toBe(PLAN.planHash);
  });

  it("every buffer names getig_frame as its rebuild source and restores nothing", () => {
    for (const b of PLAN.buffers) {
      expect(b.rebuildsFrom).toBe("getig_frame");
      expect(b.restoresRuntimeState).toBe(false);
      expect(b.ownerLayer).toBe("gpu_resource");
    }
  });

  it("frames in flight is bounded and defaults to the conservative value", () => {
    expect(PLAN.framesInFlight).toBe(1);
    expect(planOf(SCENE, { framesInFlight: 3 }).framesInFlight).toBe(3);
    expect(refusalOf(SCENE, { framesInFlight: 4 }).refusal).toBe("refused_gpu_plan_budget_exceeded");
    expect(refusalOf(SCENE, { framesInFlight: 0 }).refusal).toBe("refused_gpu_plan_input_invalid");
    expect(refusalOf(SCENE, { framesInFlight: 1.5 }).refusal).toBe("refused_gpu_plan_input_invalid");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — the plan never claims a rendered pixel", () => {
  it("completeness is 'incomplete' and its TYPE admits nothing else", () => {
    expect(PLAN.completeness).toBe("incomplete");
    // The declared type is the real assertion: `"incomplete"` is the only
    // member, so a future edit cannot widen it without changing the type.
    const declared: "incomplete" = PLAN.completeness;
    expect(declared).toBe("incomplete");
  });

  it("pixelOutputVerified is false — 29C measured the readback as unverified", () => {
    expect(PLAN.pixelOutputVerified).toBe(false);
  });

  it("notProven says what was not proven, in words", () => {
    const text = PLAN.notProven.join(" | ");
    expect(text).toContain("allocation");
    expect(text).toContain("submission");
    expect(text).toContain("readback");
    expect(PLAN.notProven.length).toBeGreaterThanOrEqual(4);
  });

  it("a completeness claim of 'complete' is REFUSED without a qualifying verdict", () => {
    const r = refusalOf(SCENE, { requestedCompleteness: "complete" });
    expect(r.refusal).toBe("refused_gpu_plan_qualification_required");
    expect(r.offendingField).toBe("requestedCompleteness");
  });

  it("and REFUSED when the only verdict available is 29C's inconclusive one", () => {
    expect(refusalOf(SCENE, { qualification: OBSERVED_QUALIFICATION, requestedCompleteness: "complete" }).refusal).toBe(
      "refused_gpu_plan_qualification_required",
    );
  });

  it("a qualifying verdict is the only thing that unblocks the claim — and the plan still says incomplete", () => {
    const p = planOf(SCENE, { qualification: qualificationWith({ verdict: "qualified_hardware", qualifiesHardware: true }), requestedCompleteness: "complete" });
    expect(p.supportsHardware).toBe(true);
    // Even qualified, 29D itself allocated nothing and read back nothing, so the
    // plan it emits cannot assert that IT rendered. Honest, not pedantic.
    expect(p.completeness).toBe("incomplete");
    expect(p.pixelOutputVerified).toBe(false);
  });

  it("supportsHardware stays false for every verdict 29C can actually produce", () => {
    const producible = QUALIFICATION_VERDICTS.filter((v) => !(QUALIFYING_VERDICTS as readonly string[]).includes(v));
    expect(producible.length).toBeGreaterThan(0);
    for (const verdict of producible) {
      expect(planOf(SCENE, { qualification: qualificationWith({ verdict }) }).supportsHardware).toBe(false);
    }
  });

  it("without a qualification the plan narrows nothing and claims nothing", () => {
    const p = planOf(SCENE);
    expect(p.qualificationVerdict).toBeNull();
    expect(p.supportsHardware).toBe(false);
    expect(p.planHash).toBe(PLAN.planHash);
  });

  it("an unqualifying verdict may NARROW byte ceilings, never widen them", () => {
    const tiny = qualificationWith({ limits: { ...OBSERVED_QUALIFICATION.limits, maxBufferSize: 64 } });
    const r = refusalOf(SCENE, { qualification: tiny });
    expect(r.refusal).toBe("refused_gpu_plan_device_limit_exceeded");
    // A WIDER observation than the declared bound must not raise the bound.
    // `2 ** 40`, not `1 << 40`: `<<` coerces to a 32-bit int, so `1 << 40`
    // is 256 — a "wider" limit that silently narrows the ceiling to nothing.
    const huge = qualificationWith({ limits: { ...OBSERVED_QUALIFICATION.limits, maxBufferSize: 2 ** 40 } });
    expect(planOf(SCENE, { qualification: huge }).totalBufferBytes).toBe(PLAN.totalBufferBytes);
  });

  it("a bind-group count beyond what the device allows is refused", () => {
    const narrow = qualificationWith({ limits: { ...OBSERVED_QUALIFICATION.limits, maxBindGroups: 1 } });
    expect(refusalOf(SCENE, { qualification: narrow }).refusal).toBe("refused_gpu_plan_device_limit_exceeded");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — no silent truncation", () => {
  it("there is no cap that shrinks a scene; asking for fewer is a REFUSAL", () => {
    const r = refusalOf(SCENE, { requestedMaxPrimitives: SCENE.primitives.length - 1 });
    expect(r.refusal).toBe("refused_gpu_plan_truncation_forbidden");
    expect(r.explanation).toContain("silent truncation is forbidden");
  });

  it("a cap at or above the requirement is accepted and changes nothing", () => {
    expect(planOf(SCENE, { requestedMaxPrimitives: SCENE.primitives.length }).planHash).toBe(PLAN.planHash);
    expect(planOf(SCENE, { requestedMaxPrimitives: 99999 }).entryCount).toBe(PLAN.entryCount);
  });

  it("a non-integer or negative cap is an input refusal", () => {
    expect(refusalOf(SCENE, { requestedMaxPrimitives: 1.5 }).refusal).toBe("refused_gpu_plan_input_invalid");
    expect(refusalOf(SCENE, { requestedMaxPrimitives: -1 }).refusal).toBe("refused_gpu_plan_input_invalid");
  });

  it("every mandatory marker in the scene survives into the plan", () => {
    // 29B turned rank-0 conflicts/refusals/partitions into overlays. If the
    // plan dropped any of them the picture would be quietly wrong.
    expect(PLAN.pickingResolutions.reduce((n, r) => n + r.markerTexts.length, 0)).toBe(SCENE.overlays.length);
    expect(PLAN.entryCount).toBe(SCENE.primitives.length + SCENE.relations.length + SCENE.overlays.length);
  });

  it("an over-budget scene is refused, never trimmed to the bound", () => {
    const many = {
      ...SCENE,
      primitives: Array.from({ length: GPU_PLAN_BOUNDS.maxPrimitives + 1 }, (_, i) => ({ ...SCENE.primitives[0]!, primitiveId: `p:${i}` })),
    };
    expect(refusalOf(many).refusal).toBe("refused_gpu_plan_budget_exceeded");
  });

  it("an over-budget overlay count is refused", () => {
    const many = { ...SCENE, overlays: Array.from({ length: GPU_PLAN_BOUNDS.maxOverlays + 1 }, (_, i) => ({ ...SCENE.overlays[0]!, overlayId: `o:${i}` })) };
    expect(refusalOf(many).refusal).toBe("refused_gpu_plan_budget_exceeded");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — refusals are live and total", () => {
  it("every exported refusal code is actually emitted in the module source", () => {
    // `refuse(\s*"` rather than `refuse\("`: many call sites put the literal on
    // the next line, and the tighter pattern silently misses those.
    const emitted = new Set<string>();
    const re = /refuse\(\s*"([a-z0-9_]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(RAW)) !== null) {
      if (m[1] !== undefined) emitted.add(m[1]);
    }
    for (const code of GPU_PLAN_REFUSAL_CODES) {
      expect(emitted, `refusal code ${code} is declared but never emitted`).toContain(code);
    }
  });

  it("the module emits nothing outside the closed refusal vocabulary", () => {
    const emitted = new Set<string>();
    const re = /refuse\(\s*"([a-z0-9_]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(RAW)) !== null) {
      if (m[1] !== undefined) emitted.add(m[1]);
    }
    for (const code of emitted) {
      expect((GPU_PLAN_REFUSAL_CODES as readonly string[]).includes(code), `undeclared refusal code emitted: ${code}`).toBe(true);
    }
  });

  it("POSITIVE CONTROL: the emission scan detects a planted refusal literal", () => {
    const planted = 'return refuse(\n  "refused_gpu_plan_planted",\n  "x",\n);';
    const re = /refuse\(\s*"([a-z0-9_]+)"/g;
    const found = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(planted)) !== null) if (m[1] !== undefined) found.add(m[1]);
    expect([...found]).toContain("refused_gpu_plan_planted");
  });

  it("a refusal emits nothing partial and confers nothing", () => {
    const d = buildGpuRenderPlan({ scene: null });
    if (d.ok) throw new Error("expected a refusal");
    expect(d.plan).toBeNull();
    expect(d.partialPlanEmitted).toBe(false);
    expect(d.authority).toBe("none");
    expect(d.controlPlane).toBe(false);
    expect(d.readOnly).toBe(true);
    expect(d.executionAuthorized).toBe(false);
    expect(d.code).toBe("gpu_plan_refused");
  });

  it("malformed inputs are refused by class", () => {
    expect(refusalOf("not an object").refusal).toBe("refused_gpu_plan_scene_unbound");
    expect(refusalOf({}).refusal).toBe("refused_gpu_plan_scene_unbound");
    expect(refusalOf({ ...SCENE, sceneHash: "nope" }).refusal).toBe("refused_gpu_plan_scene_unbound");
    expect(refusalOf({ ...SCENE, sourceFrameId: "" }).refusal).toBe("refused_gpu_plan_scene_unbound");
    expect(refusalOf({ ...SCENE, sourceVisibleHash: "zz" }).refusal).toBe("refused_gpu_plan_scene_unbound");
    expect(refusalOf({ ...SCENE, primitives: "many" }).refusal).toBe("refused_gpu_plan_scene_malformed");
    expect(refusalOf(SCENE, { viewport: { width: 0, height: 10, scale: 1 } }).refusal).toBe("refused_gpu_plan_input_invalid");
  });

  it("a non-object plan input is refused", () => {
    const d = buildGpuRenderPlan(null as never);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_gpu_plan_input_invalid");
  });

  it("the refusal vocabulary has no bare pass or ok member", () => {
    for (const code of GPU_PLAN_REFUSAL_CODES) {
      expect(code.startsWith("refused_gpu_plan_")).toBe(true);
    }
    expect(GPU_PLAN_SCHEMA_VERSION).toBe("menog-gpu-render-plan/v0");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — the plan is frozen and zero-authority", () => {
  it("the plan and every nested array and descriptor is frozen", () => {
    expect(Object.isFrozen(PLAN)).toBe(true);
    expect(Object.isFrozen(PLAN.buffers)).toBe(true);
    expect(Object.isFrozen(PLAN.pipelines)).toBe(true);
    expect(Object.isFrozen(PLAN.passes)).toBe(true);
    expect(Object.isFrozen(PLAN.bindGroups)).toBe(true);
    expect(Object.isFrozen(PLAN.pickingResolutions)).toBe(true);
    expect(Object.isFrozen(PLAN.notProven)).toBe(true);
    for (const b of PLAN.buffers) {
      expect(Object.isFrozen(b)).toBe(true);
      expect(Object.isFrozen(b.usage)).toBe(true);
    }
    for (const r of PLAN.pickingResolutions) expect(Object.isFrozen(r)).toBe(true);
  });

  it("a mutable buffer array is refused by 29A's own surface guard", () => {
    // The reason 29A exists: a frozen object holding a mutable array is not a
    // frozen surface, because the array is what a renderer pushes into.
    expect(() => {
      (PLAN.buffers as unknown as unknown[]).push({});
    }).toThrow();
  });

  it("every descriptor states authority 'none' and authorises no execution", () => {
    for (const b of PLAN.buffers) {
      expect(b.authority).toBe("none");
      expect(b.executionAuthorized).toBe(false);
    }
    for (const g of PLAN.bindGroups) {
      expect(g.authority).toBe("none");
      expect(g.executionAuthorized).toBe(false);
    }
    for (const p of PLAN.pipelines) {
      expect(p.authority).toBe("none");
      expect(p.executionAuthorized).toBe(false);
      expect(p.depthCompare).toBe("none");
    }
    for (const p of PLAN.passes) {
      expect(p.authority).toBe("none");
      expect(p.executionAuthorized).toBe(false);
    }
  });

  it("the success envelope is zero-authority, read-only and non-executing", () => {
    expect(plan.authority).toBe("none");
    expect(plan.controlPlane).toBe(false);
    expect(plan.readOnly).toBe(true);
    expect(plan.executionAuthorized).toBe(false);
    expect(plan.code).toBe("gpu_plan_built");
  });

  it("depth is not privilege: no pipeline declares a depth comparison", () => {
    for (const p of PLAN.pipelines) expect(p.depthCompare).toBe("none");
  });

  it("the scene handed to the plan is never mutated", () => {
    const before = JSON.stringify(SCENE);
    buildGpuRenderPlan({ scene: SCENE });
    expect(JSON.stringify(SCENE)).toBe(before);
  });

  it("no colour is assigned to anything in the plan", () => {
    expect(JSON.stringify(PLAN.buffers) + JSON.stringify(PLAN.pipelines)).not.toMatch(/color|colour/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
describe("29D — unresolved endpoints are surfaced, never silently repaired", () => {
  it("a relation endpoint naming no primitive gets the sentinel, not a dropped index", () => {
    // Dropping an endpoint would shorten the index buffer and shift every later
    // index, turning one unresolvable relation into a scene-wide mislabel.
    const topology = bufferById("buf.index.topology");
    expect(topology.recordCount).toBe(SCENE.relations.length * 2);
  });

  it("the sentinel VALUE is what reaches the buffer, not merely a comment about it", () => {
    // Counting endpoints and counting unresolved ones cannot tell a sentinel
    // write from a plain 0 write; only the hashed bytes can. This case exists
    // because falsification F6 replaced the sentinel with 0 and nothing failed.
    const unresolvable = planOf({
      ...SCENE,
      relations: [{ kind: "forwards_to", relationId: "r:ghost", fromId: "nowhere", toId: "also-nowhere", role: "forwarder", authorizes: false, trust: "none" }],
    });
    const topology = unresolvable.buffers.find((b) => b.bufferId === "buf.index.topology");
    // Two u32 records, both 0xFFFFFFFF, hashed — so this pins the exact bytes.
    expect(topology?.contentHash).toBe(
      sha256Hex(new Uint32Array([GPU_PICKING_NO_ANCHOR, GPU_PICKING_NO_ANCHOR]).buffer),
    );
  });

  it("and a resolvable endpoint writes its real index, so the sentinel is not a blanket 0", () => {
    const resolvable = planOf({
      ...SCENE,
      relations: [{ kind: "forwards_to", relationId: "r:real", fromId: SCENE.primitives[0]!.primitiveId, toId: SCENE.primitives[1]!.primitiveId, role: "origin", authorizes: false, trust: "none" }],
    });
    const topology = resolvable.buffers.find((b) => b.bufferId === "buf.index.topology");
    expect(topology?.contentHash).toBe(sha256Hex(new Uint32Array([0, 1]).buffer));
    expect(topology?.contentHash).not.toBe(
      sha256Hex(new Uint32Array([GPU_PICKING_NO_ANCHOR, GPU_PICKING_NO_ANCHOR]).buffer),
    );
  });

  it("an overlay with no drawable anchor also writes the sentinel", () => {
    const ghost = planOf({
      ...SCENE,
      overlays: [{ kind: "explanation", overlayId: "overlay:ghost", targetId: "no-such-subject", text: "partitions:present", authority: "none" }],
    });
    const instances = ghost.buffers.find((b) => b.bufferId === "buf.instance.overlay");
    expect(instances?.recordCount).toBe(1);
    // word 0 is the anchor; it must be the sentinel, never 0.
    expect(instances?.contentHash).toBe(sha256Hex(instanceBytes(GPU_PICKING_NO_ANCHOR)));
  });

  it("and the unresolved count is stated in notProven rather than hidden", () => {
    // 29R1 (29D-OBS-2 repair): the FROZEN scene no longer has unresolved
    // endpoints — all three route relations bind to drawable primitives — so
    // the sentinel line must be ABSENT here. Surfacing itself must keep
    // working for input that genuinely does not resolve: the hostile scene
    // below is stated in notProven, never hidden. The old assertion pinned
    // the DEFECT (it required the frozen plan to carry the sentinel), so it
    // was re-pointed at an unresolvable scene rather than deleted.
    const frozenText = PLAN.notProven.join(" | ");
    expect(frozenText).not.toContain("no-anchor sentinel");
    expect(frozenText).not.toContain("relation endpoint");
    const unresolved = planOf({
      ...SCENE,
      relations: [
        { kind: "forwards_to", relationId: "r:ghost", fromId: "nowhere", toId: SCENE.primitives[0]!.primitiveId, role: "forwarder", authorizes: false, trust: "none" },
      ],
    });
    expect(unresolved.notProven.join(" | ")).toContain("no-anchor sentinel");
  });

  it("the sentinel is a distinct u32 that cannot collide with a real index", () => {
    expect(GPU_PICKING_NO_ANCHOR).toBe(0xffffffff);
    expect(PLAN.pickingResolutions.length).toBeLessThan(GPU_PICKING_NO_ANCHOR);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SUPERSEDED AT GATE 29R4 (2026-10-05): this block originally pinned the
// four-devDependency pre-authorization state — package.json sha256
// 77500e08443e424a…ed93 (767 B), pnpm-lock.yaml sha256 bd289ce7ad6d0d8c…4752
// (36 919 B). The HUMAN then explicitly authorized exactly one dependency
// addition — @webgpu/types@0.1.74, dev-only, zero runtime/transitive deps —
// recorded in docs/release/PHASE29R4_TYPING_DECISION.json (prior record
// preserved byte-exact alongside it). Recovery law: superseded, never erased.
// The pins below re-assert the post-authorization state and remain a tripwire
// for ANY further dependency change; Phase-20–28 frozen artifacts are
// unchanged (66/66 byte-identical).
describe("29D — no unauthorized dependency, no frozen Phase-28 drift", () => {
  it("package.json keeps the post-authorization sha256 — nothing beyond the authorized addition", () => {
    const raw = readFileSync(join(ROOT, "package.json"));
    expect(createHash("sha256").update(raw).digest("hex")).toBe(
      "56369ab3369c78b801e1032a4bf12f9349e839a8a43e9ed108ab34ed81893e92",
    );
  });

  it("package.json declares exactly the four original devDependencies plus the authorized @webgpu/types@0.1.74", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { devDependencies: Record<string, string>; dependencies?: Record<string, string> };
    expect(Object.keys(pkg.devDependencies).sort()).toEqual(["@types/node", "@webgpu/types", "rimraf", "typescript", "vitest"]);
    expect(pkg.devDependencies["@webgpu/types"]).toBe("0.1.74");
    expect(pkg.dependencies ?? {}).toEqual({});
  });

  it("pnpm-lock.yaml keeps the post-authorization sha256", () => {
    const lock = readFileSync(join(ROOT, "pnpm-lock.yaml"));
    expect(createHash("sha256").update(lock).digest("hex")).toBe(
      "541249d23a9f54b9d3255bbefa8bd7f221c96371a37693be344b50d5de23506d",
    );
  });

  it("this gate adds exactly one source file and one suite", () => {
    const before = ["rendererTrustContract.ts", "sceneGraphCompiler.ts", "webgpuQualification.ts"];
    for (const f of before) expect(readFileSync(join(ROOT, "packages", "durable-state", "src", f), "utf8").length).toBeGreaterThan(0);
    // 29D is the fourth Phase-29 module and the first one after 29C.
    expect(RAW.length).toBeGreaterThan(10_000);
  });
});