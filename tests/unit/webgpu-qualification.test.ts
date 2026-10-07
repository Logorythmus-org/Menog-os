/**
 * PHASE 29C — WEBGPU DEVICE & CAPABILITY QUALIFICATION — SUITE
 *
 * The fixtures are the REAL probe facts taken from this machine on 2026-10-04,
 * not invented ones. The central case is the one the machine actually produced:
 * a render pass that submits cleanly and a readback that completes but whose
 * content does NOT match what was rendered.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  OBSERVATION_FIELDS,
  QUALIFICATION_REFUSAL_CODES,
  QUALIFICATION_VERDICTS,
  QUALIFYING_VERDICTS,
  bindQualificationToFrame,
  qualifyWebGpu,
  type WebGpuObservation,
} from "../../packages/durable-state/src/index.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(HERE, "..", "..");
const MODULE_SRC = join(ROOT, "packages", "durable-state", "src", "webgpuQualification.ts");
const RAW = readFileSync(MODULE_SRC, "utf8");
const strip = (s: string): string => {
  let o = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    const d = s[i + 1];
    if (c === "/" && d === "/") {
      while (i < s.length && s[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < s.length && s[i] !== q) {
        if (s[i] === "\\") i++;
        i++;
      }
      i++;
      o += '""';
      continue;
    }
    o += c;
    i++;
  }
  return o;
};
const CODE = strip(RAW);

const FRAME = "frame-29c-t0";
const VIEW_HASH = "abcdef0123456789";

// ── THE REAL OBSERVATION from this machine ────────────────────────────────────

const REAL: WebGpuObservation = {
  apiPresent: true,
  adapterObtained: true,
  deviceCreated: true,
  isFallbackAdapter: false,
  features: [
    "bgra8unorm-storage", "depth-clip-control", "depth32float-stencil8", "dual-source-blending",
    "float32-filterable", "indirect-first-instance", "rg11b10ufloat-renderable", "texture-compression-bc",
    "timestamp-query",
  ],
  limits: {
    maxBufferSize: 2147483648,
    maxTextureDimension2D: 16384,
    maxBindGroups: 4,
    maxStorageBufferBindingSize: 2147483644,
    maxUniformBufferBindingSize: 65536,
    maxVertexBuffers: 8,
    maxColorAttachmentBytesPerSample: 128,
  },
  wgslCompiled: true,
  wgslMessages: [],
  pipelineCreated: true,
  drawSubmitted: true,
  renderPassSucceeded: true,
  readbackSucceeded: true,
  readbackMatchesExpectation: false,
  expectedPixel: [0, 128, 255, 255],
  observedPixel: [0, 0, 0, 0],
  userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.6723.191 Electron/33.4.11",
};

const obs = (over: Partial<WebGpuObservation> = {}): unknown => ({ ...REAL, ...over });

const judge = (over: Partial<WebGpuObservation> = {}, extra: Record<string, unknown> = {}) =>
  qualifyWebGpu({ observation: obs(over), sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH, vendor: "amd", ...extra });

// ── 1. the real run is judged honestly ───────────────────────────────────────

describe("29C — the real probe result is judged, not flattered", () => {
  it("records observed_readback_inconclusive for this machine", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("observed_readback_inconclusive");
    expect(r.qualification.qualifiesHardware).toBe(false);
  });

  it("says plainly that the pixels were not verified", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.notProven.length).toBeGreaterThan(0);
    expect(r.qualification.notProven.join(" ")).toContain("readback");
  });

  it("never claims power-loss or hardware-integrity evidence", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.powerLossEvidenced).toBe(false);
    expect(r.qualification.hardwareIntegrityEvidenced).toBe(false);
    // And no observation field could have supplied either: they are literal
    // false on the record, not booleans copied from the probe.
    expect(OBSERVATION_FIELDS).not.toContain("powerLossEvidenced");
    expect(OBSERVATION_FIELDS).not.toContain("hardwareIntegrityEvidenced");
  });

  it("the ONLY qualifying verdict still says power loss is unproven", () => {
    const r = judge({ readbackMatchesExpectation: true, expectedPixel: [0, 128, 255, 255], observedPixel: [0, 128, 255, 255] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("qualified_hardware");
    expect(r.qualification.notProven.join(" ")).toContain("power-loss");
    expect(r.qualification.powerLossEvidenced).toBe(false);
  });

  it("records the exact adapter facts it was given", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.vendor).toBe("amd");
    expect(r.qualification.isFallbackAdapter).toBe(false);
    expect(r.qualification.features).toHaveLength(9);
    expect(r.qualification.limits.maxBufferSize).toBe(2147483648);
    expect(r.qualification.limits.maxTextureDimension2D).toBe(16384);
    expect(r.qualification.qualificationHash).toHaveLength(64);
  });

  it("is deterministic for identical facts", () => {
    const a = judge();
    const b = judge();
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.qualification.qualificationHash).toBe(b.qualification.qualificationHash);
  });
});

// ── 2. API PRESENCE != DEVICE PASS ───────────────────────────────────────────

describe("29C — API presence is not a device pass", () => {
  it("api present but no adapter is no_adapter, not a pass", () => {
    const r = judge({ adapterObtained: false, deviceCreated: false, wgslCompiled: false, pipelineCreated: false, drawSubmitted: false, renderPassSucceeded: false, readbackSucceeded: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("no_adapter");
    expect(r.qualification.qualifiesHardware).toBe(false);
  });

  it("no WebGPU API at all is api_absent, not a pass", () => {
    const r = judge({
      apiPresent: false, adapterObtained: false, deviceCreated: false, isFallbackAdapter: false,
      wgslCompiled: false, pipelineCreated: false, drawSubmitted: false,
      renderPassSucceeded: false, readbackSucceeded: false,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("api_absent");
    expect(r.qualification.qualifiesHardware).toBe(false);
  });

  it("adapter but no device is device_refused", () => {
    const r = judge({ deviceCreated: false, wgslCompiled: false, pipelineCreated: false, drawSubmitted: false, renderPassSucceeded: false, readbackSucceeded: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("device_refused");
  });

  it("the taxonomy contains no bare pass", () => {
    expect(QUALIFICATION_VERDICTS).not.toContain("pass");
    expect(QUALIFICATION_VERDICTS).not.toContain("PASS");
    expect([...QUALIFYING_VERDICTS]).toEqual(["qualified_hardware"]);
  });

  it("only a fully verified readback reaches qualified_hardware", () => {
    const r = judge({ readbackMatchesExpectation: true, expectedPixel: [0, 128, 255, 255], observedPixel: [0, 128, 255, 255] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("qualified_hardware");
    expect(r.qualification.qualifiesHardware).toBe(true);
  });
});

// ── 3. SOFTWARE != HARDWARE ──────────────────────────────────────────────────

describe("29C — a software adapter can never be a hardware claim", () => {
  it("a fallback adapter is recorded as software_adapter_only", () => {
    const r = judge({ isFallbackAdapter: true });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("software_adapter_only");
    expect(r.qualification.qualifiesHardware).toBe(false);
  });

  it("REFUSES a fallback adapter claimed as qualified_hardware", () => {
    const r = judge({ isFallbackAdapter: true, readbackMatchesExpectation: true, expectedPixel: [1], observedPixel: [1] }, { claimedQualification: "qualified_hardware" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_qualification_unqualified_claimed_as_hardware");
      expect(r.qualification).toBeNull();
    }
  });

  it("no field can be set to turn a software path into hardware validation", () => {
    for (const field of ["isHardware", "validated", "hardwareValidated", "realGpu", "softwarePath"]) {
      const r = qualifyWebGpu({ observation: { ...REAL, ...(REAL as unknown as Record<string, unknown>), [field]: true }, sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH });
      expect(r.ok, `accepted unknown field ${field}`).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_unknown_field");
    }
  });
});

// ── 4. SUBMITTED != RENDERED, and a completed readback is not evidence ──────

describe("29C — a readback is only evidence when its CONTENT matches", () => {
  it("readbackSucceeded alone never qualifies", () => {
    const r = judge({ readbackMatchesExpectation: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.qualifiesHardware).toBe(false);
  });

  it("REFUSES a readback that claims to match while the pixels differ", () => {
    const r = judge({ readbackMatchesExpectation: true, expectedPixel: [0, 128, 255, 255], observedPixel: [0, 0, 0, 0] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
  });

  it("REFUSES a matching readback that compared nothing", () => {
    const r = judge({ readbackMatchesExpectation: true, expectedPixel: [], observedPixel: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
  });

  it("render that did not succeed is render_unverified", () => {
    const r = judge({ renderPassSucceeded: false, readbackSucceeded: false, readbackMatchesExpectation: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.verdict).toBe("render_unverified");
  });

  it("REFUSES an observation that claims a later step without the earlier one", () => {
    const cases: Partial<WebGpuObservation>[] = [
      { deviceCreated: true, adapterObtained: false },
      { adapterObtained: true, apiPresent: false },
      { pipelineCreated: true, wgslCompiled: false },
      { drawSubmitted: true, pipelineCreated: false },
      { renderPassSucceeded: true, drawSubmitted: false },
      { readbackSucceeded: true, renderPassSucceeded: false },
      { readbackMatchesExpectation: true, readbackSucceeded: false },
    ];
    for (const over of cases) {
      const r = judge(over);
      expect(r.ok, `accepted impossible chain: ${JSON.stringify(over)}`).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
    }
  });
});

// ── 5. the observation is an allowlist, and a claim is verified ──────────────

describe("29C — the observation surface is closed and claims are checked", () => {
  it("refuses an unknown observation field rather than ignoring it", () => {
    const r = qualifyWebGpu({ observation: { ...REAL, somethingElse: 1 }, sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_qualification_observation_unknown_field");
      expect(r.offendingField).toBe("somethingElse");
    }
  });

  it("requires every declared field — a missing isFallbackAdapter is a refusal", () => {
    const partial: Record<string, unknown> = { ...REAL };
    delete partial.isFallbackAdapter;
    const r = qualifyWebGpu({ observation: partial, sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
  });

  it("refuses a non-boolean where a boolean is required", () => {
    const r = judge({ deviceCreated: "yes" as never });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
  });

  it("refuses a missing or malformed limit", () => {
    const broken = { ...REAL, limits: { ...REAL.limits, maxBufferSize: -1 } };
    const r = qualifyWebGpu({ observation: broken, sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_observation_inconsistent");
  });

  it("REFUSES a qualified_hardware claim the observation does not support", () => {
    const r = judge({}, { claimedQualification: "qualified_hardware" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_qualification_unqualified_claimed_as_hardware");
  });

  it("accepts an honest 'observed' claim on this machine", () => {
    const r = judge({}, { claimedQualification: "observed" });
    expect(r.ok).toBe(true);
  });

  it("every refusal code the module can emit is declared, and every declared code is reachable", () => {
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(\s*"([a-z_]+)"/g)) emitted.add(m[1] as string);
    expect(emitted.size).toBeGreaterThan(0);
    for (const c of emitted) expect(QUALIFICATION_REFUSAL_CODES, `${c} emitted but undeclared`).toContain(c);
    for (const c of QUALIFICATION_REFUSAL_CODES) expect(emitted, `${c} declared but never emitted`).toContain(c);
  });
});

// ── 6. binding, and the record confers nothing ───────────────────────────────

describe("29C — a qualification is bound to a frame and confers nothing", () => {
  it("binds to the frame it was taken against", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.qualification.sourceFrameId).toBe(FRAME);
    expect(r.qualification.canonicalVisibleHash).toBe(VIEW_HASH);
    expect(bindQualificationToFrame(r.qualification, FRAME, VIEW_HASH).ok).toBe(true);
  });

  it("REFUSES to present a qualification against a different frame", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(bindQualificationToFrame(r.qualification, "frame-other", VIEW_HASH).ok).toBe(false);
    expect(bindQualificationToFrame(r.qualification, FRAME, "ffffffffffffffff").ok).toBe(false);
  });

  it("refuses a missing or malformed frame binding", () => {
    expect(qualifyWebGpu({ observation: REAL, sourceFrameId: "", canonicalVisibleHash: VIEW_HASH }).ok).toBe(false);
    expect(qualifyWebGpu({ observation: REAL, sourceFrameId: FRAME, canonicalVisibleHash: "nope" }).ok).toBe(false);
  });

  it("confers zero authority on both outcomes", () => {
    const ok = judge();
    const refused = qualifyWebGpu({ observation: null, sourceFrameId: FRAME, canonicalVisibleHash: VIEW_HASH });
    for (const r of [ok, refused]) {
      expect(r.authority).toBe("none");
      expect(r.controlPlane).toBe(false);
      expect(r.readOnly).toBe(true);
      expect(r.executionAuthorized).toBe(false);
    }
  });

  it("freezes the record so it cannot be edited after the fact", () => {
    const r = judge();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(Object.isFrozen(r.qualification)).toBe(true);
    expect(Object.isFrozen(r.qualification.limits)).toBe(true);
    expect(Object.isFrozen(r.qualification.features)).toBe(true);
    expect(Object.isFrozen(r.qualification.notProven)).toBe(true);
  });
});

// ── 7. no WebGPU surface, no network ─────────────────────────────────────────

describe("29C — the module makes no GPU call and needs no network", () => {
  it("contains no WebGPU, device or render call in its code", () => {
    for (const t of ["navigator.gpu", "requestAdapter", "requestDevice", "createTexture", "createCommandEncoder", "createRenderPipeline", "mapAsync", "submit("]) {
      expect(CODE.includes(t), `qualification module contains ${t}`).toBe(false);
    }
  });

  it("reaches no network, store, clock or randomness surface", () => {
    expect(CODE).not.toMatch(/\b(fetch|WebSocket|XMLHttpRequest|net\.|dgram|http\.|https\.)\b/);
    expect(CODE).not.toMatch(/Date\.now|Math\.random|performance\.now|process\.env/);
    expect(CODE).not.toMatch(/\b(spawn|fork|exec|execve)\s*\(/);
  });

  it("declares every observation field it requires", () => {
    expect(OBSERVATION_FIELDS).toContain("isFallbackAdapter");
    expect(OBSERVATION_FIELDS).toContain("readbackMatchesExpectation");
    expect(OBSERVATION_FIELDS.length).toBeGreaterThanOrEqual(16);
    expect(Object.isFrozen(OBSERVATION_FIELDS)).toBe(true);
    expect(Object.isFrozen(QUALIFICATION_VERDICTS)).toBe(true);
  });
});