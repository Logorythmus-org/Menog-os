/**
 * PHASE 29C — WEBGPU DEVICE & CAPABILITY QUALIFICATION
 * (ENVIRONMENT QUALIFICATION / MINIMAL GPU SURFACE / NO OVERCLAIM)
 *
 * CENTRAL LAWS:
 *   API_PRESENCE      != DEVICE_PASS
 *   SOFTWARE          != HARDWARE
 *   UNSUPPORTED       != PASS
 *   INCONCLUSIVE      != PASS
 *   SUBMITTED         != RENDERED
 *   QUALIFICATION     != AUTHORITY
 *
 * ── WHY THIS MODULE MAKES NO WEBGPU CALL ────────────────────────────────────
 *
 * This workspace has no WebGPU types (`lib: ES2023`, no DOM/WebGPU lib,
 * `@webgpu/types` absent) and law 33 defaults to zero new dependencies. So this
 * module does not probe anything: it defines the SHAPE of a probe observation
 * and the RULES for judging one. The probe itself runs in a real browser; its
 * raw facts are written into the evidence record and handed here.
 *
 * That separation is deliberate. A module that both probes and judges its own
 * output can quietly widen what it accepts, and the rules below are the part
 * that must be unfalsifiable.
 *
 * ── WHY THE VERDICT TAXONOMY HAS NO "PASS" MEMBER ───────────────────────────
 *
 * There is no `qualified_hardware` outcome reachable from a single probe run in
 * this environment, because hardware qualification additionally requires a
 * VERIFIED PIXEL READBACK — pixels that demonstrably match what was rendered.
 *
 * On this machine the render pass submits without error and the pipeline
 * compiles without warnings, but `copyTextureToBuffer` returns all zeros for
 * both a clear-only pass and a drawn triangle. A buffer-to-buffer round trip in
 * the same session returns correct bytes, which isolates the failure to the
 * TEXTURE readback path rather than to the GPU, the driver or the harness.
 *
 * The honest verdict for that is INCONCLUSIVE. Reporting it as a hardware pass
 * would be exactly law 31: a path that did not prove hardware rendered like
 * hardware. Reporting it as a FAILURE would be equally false — nothing failed.
 *
 * ── WHY A SOFTWARE ADAPTER CAN NEVER REACH HARDWARE QUALIFICATION ───────────
 *
 * `isFallbackAdapter: true` is refused outright by
 * `refused_qualification_software_adapter_hardware_claim`. There is no flag a
 * caller can set that turns a software adapter into a hardware claim, and no
 * path that treats "not obviously software" as "definitely hardware".
 *
 * ── WHY THE READBACK MUST MATCH THE CLEAR, NOT MERELY SUCCEED ───────────────
 *
 * `readbackSucceeded: true` on its own proves nothing: the readback completed
 * without throwing. A readback is only evidence when its CONTENT is compared
 * against what was rendered. `readbackMatchesExpectation` is therefore a
 * separate, required input, and `SUBMITTED != RENDERED` is enforced here rather
 * than trusted.
 *
 * ── WHY A QUALIFICATION IS BOUND TO A FRAME AND CONFERS NOTHING ─────────────
 *
 * A qualification record names the `sourceFrameId` and `canonicalVisibleHash` it
 * was taken against. A record whose binding does not match the frame being
 * rendered is REFUSED, because an unbound qualification could be presented as
 * covering a different frame — the same defect class as an unbound disclosure in
 * 28H.
 *
 * And it confers nothing: `authority: "none"`, `executionAuthorized: false`.
 * A faster GPU is not a stronger claim.
 */

import { canonicalHash } from "./canonical.js";

// ── verdict taxonomy ──────────────────────────────────────────────────────────

/**
 * The complete set of outcomes. Note what is absent: there is no bare `pass`,
 * and `qualified_hardware` is reachable only through the strictest branch.
 */
export const QUALIFICATION_VERDICTS = Object.freeze([
  /** Every check satisfied INCLUDING a verified pixel readback. */
  "qualified_hardware",
  /** Real adapter and device, rendering submitted, readback not verified. */
  "observed_readback_inconclusive",
  /** Everything worked except the render or readback itself. */
  "render_unverified",
  /** Adapter reports a fallback/software path. */
  "software_adapter_only",
  /** The WebGPU API is not present at all. */
  "api_absent",
  /** API present but no adapter could be obtained. */
  "no_adapter",
  /** Adapter obtained but device creation failed. */
  "device_refused",
  /** A software or mock path presented as hardware validation. */
  "refused_software_claimed_as_hardware",
] as const);
export type QualificationVerdict = (typeof QUALIFICATION_VERDICTS)[number];

/**
 * The only verdicts that may be described as a successful qualification.
 *
 * `observed_readback_inconclusive` is deliberately NOT here. A run that cannot
 * prove its own pixels proved has observed the machine, not qualified it.
 */
export const QUALIFYING_VERDICTS = Object.freeze(["qualified_hardware"] as const);
export type QualifyingVerdict = (typeof QUALIFYING_VERDICTS)[number];

export const QUALIFICATION_REFUSAL_CODES = Object.freeze([
  "refused_qualification_input_invalid",
  "refused_qualification_binding_missing",
  "refused_qualification_binding_mismatch",
  "refused_qualification_observation_unknown_field",
  "refused_qualification_observation_inconsistent",
  "refused_qualification_software_adapter_hardware_claim",
  "refused_qualification_unqualified_claimed_as_hardware",
] as const);
export type QualificationRefusalCode = (typeof QUALIFICATION_REFUSAL_CODES)[number];

export const QUALIFICATION_SCHEMA_VERSION = "menog-webgpu-qualification/v0" as const;

// ── the observation the probe must supply ─────────────────────────────────────

export interface AdapterLimitsObservation {
  readonly maxBufferSize: number;
  readonly maxTextureDimension2D: number;
  readonly maxBindGroups: number;
  readonly maxStorageBufferBindingSize: number;
  readonly maxUniformBufferBindingSize: number;
  readonly maxVertexBuffers: number;
  readonly maxColorAttachmentBytesPerSample: number;
}

/**
 * A raw probe observation.
 *
 * Every field is REQUIRED, including the negative ones. A probe that could omit
 * `isFallbackAdapter` would let an unknown adapter default to "not software",
 * which is the assumption law 31 forbids.
 */
export interface WebGpuObservation {
  readonly apiPresent: boolean;
  readonly adapterObtained: boolean;
  readonly deviceCreated: boolean;
  readonly isFallbackAdapter: boolean;
  readonly features: readonly string[];
  readonly limits: AdapterLimitsObservation;
  readonly wgslCompiled: boolean;
  readonly wgslMessages: readonly string[];
  readonly pipelineCreated: boolean;
  readonly drawSubmitted: boolean;
  readonly renderPassSucceeded: boolean;
  readonly readbackSucceeded: boolean;
  /** The decisive field: does the readback CONTENT match what was rendered? */
  readonly readbackMatchesExpectation: boolean;
  readonly expectedPixel: readonly number[];
  readonly observedPixel: readonly number[];
  readonly userAgent: string;
}

export const OBSERVATION_FIELDS = Object.freeze([
  "apiPresent",
  "adapterObtained",
  "deviceCreated",
  "isFallbackAdapter",
  "features",
  "limits",
  "wgslCompiled",
  "wgslMessages",
  "pipelineCreated",
  "drawSubmitted",
  "renderPassSucceeded",
  "readbackSucceeded",
  "readbackMatchesExpectation",
  "expectedPixel",
  "observedPixel",
  "userAgent",
] as const);

// ── the produced record ───────────────────────────────────────────────────────

export interface WebGpuQualification {
  readonly verdict: QualificationVerdict;
  readonly qualifiesHardware: boolean;
  readonly schemaVersion: typeof QUALIFICATION_SCHEMA_VERSION;
  readonly sourceFrameId: string;
  readonly canonicalVisibleHash: string;
  readonly qualificationHash: string;
  readonly vendor: string;
  readonly isFallbackAdapter: boolean;
  readonly features: readonly string[];
  readonly limits: AdapterLimitsObservation;
  readonly userAgent: string;
  /** Always false: nothing here evidences power loss or hardware integrity. */
  readonly powerLossEvidenced: false;
  /** Always false: no power-loss claim is derivable from a qualification. */
  readonly hardwareIntegrityEvidenced: false;
  /** What was NOT proven, in words. A qualification that cannot say this is not honest. */
  readonly notProven: readonly string[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

export type QualificationRefused = {
  readonly ok: false;
  readonly code: "qualification_refused";
  readonly refusal: QualificationRefusalCode;
  readonly explanation: string;
  readonly offendingField: string | null;
  readonly qualification: null;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type QualificationSucceeded = {
  readonly ok: true;
  readonly code: "qualification_recorded";
  readonly qualification: WebGpuQualification;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
};

export type QualificationDecision = QualificationSucceeded | QualificationRefused;

// ── helpers ───────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (refusal: QualificationRefusalCode, explanation: string, offendingField: string | null = null): QualificationRefused => ({
  ok: false,
  code: "qualification_refused",
  refusal,
  explanation,
  offendingField,
  qualification: null,
  authority: "none",
  controlPlane: false,
  readOnly: true,
  executionAuthorized: false,
});

const LIMITS_FIELDS = Object.freeze([
  "maxBufferSize",
  "maxTextureDimension2D",
  "maxBindGroups",
  "maxStorageBufferBindingSize",
  "maxUniformBufferBindingSize",
  "maxVertexBuffers",
  "maxColorAttachmentBytesPerSample",
] as const);

const bool = (v: unknown): v is boolean => typeof v === "boolean";
const int = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

// ── the judgement ─────────────────────────────────────────────────────────────

export interface QualifyInput {
  readonly observation: unknown;
  /** The frame the renderer intends to draw. A qualification must name it. */
  readonly sourceFrameId: string;
  readonly canonicalVisibleHash: string;
  readonly vendor?: string;
  /**
   * Optional: what the caller CLAIMS this run shows.
   *
   * A claim of hardware qualification is verified against the observation and
   * REFUSED when the observation does not support it. The claim is never taken
   * at face value.
   */
  readonly claimedQualification?: "qualified_hardware" | "observed" | "unqualified";
}

/**
 * Judge a probe observation and produce a bound, zero-authority record.
 *
 * Every rule in the header is enforced here, structurally, rather than asserted
 * in prose.
 */
export function qualifyWebGpu(input: QualifyInput): QualificationDecision {
  if (!isRecord(input)) {
    return refuse("refused_qualification_input_invalid", "qualification input must be an object");
  }
  if (typeof input.sourceFrameId !== "string" || input.sourceFrameId.length === 0) {
    return refuse("refused_qualification_binding_missing", "sourceFrameId is required", "sourceFrameId");
  }
  if (typeof input.canonicalVisibleHash !== "string" || !/^[a-f0-9]{16,128}$/.test(input.canonicalVisibleHash)) {
    return refuse("refused_qualification_binding_missing", "canonicalVisibleHash must be a hex hash", "canonicalVisibleHash");
  }

  const obs = input.observation;
  if (!isRecord(obs)) {
    return refuse("refused_qualification_input_invalid", "observation must be an object");
  }
  // Allowlist: an unrecognised observation field is refused, never ignored.
  // An ignored field reads as a read field (28J-OBS-5).
  for (const key of Object.keys(obs)) {
    if (!(OBSERVATION_FIELDS as readonly string[]).includes(key)) {
      return refuse("refused_qualification_observation_unknown_field", `unknown observation field: ${key}`, key);
    }
  }
  for (const key of OBSERVATION_FIELDS) {
    if (obs[key] === undefined) {
      return refuse("refused_qualification_observation_inconsistent", `observation is missing ${key}`, key);
    }
  }
  for (const key of ["apiPresent", "adapterObtained", "deviceCreated", "isFallbackAdapter", "wgslCompiled", "pipelineCreated", "drawSubmitted", "renderPassSucceeded", "readbackSucceeded", "readbackMatchesExpectation"] as const) {
    if (!bool(obs[key])) {
      return refuse("refused_qualification_observation_inconsistent", `${key} must be a boolean`, key);
    }
  }
  // A typed snapshot taken AFTER validation, so the truthiness checks below are
  // not re-proved at every use and the compiler can narrow them.
  const apiPresent = obs.apiPresent as boolean;
  const adapterObtained = obs.adapterObtained as boolean;
  const deviceCreated = obs.deviceCreated as boolean;
  const isFallbackAdapter = obs.isFallbackAdapter as boolean;
  const wgslCompiled = obs.wgslCompiled as boolean;
  const pipelineCreated = obs.pipelineCreated as boolean;
  const drawSubmitted = obs.drawSubmitted as boolean;
  const renderPassSucceeded = obs.renderPassSucceeded as boolean;
  const readbackSucceeded = obs.readbackSucceeded as boolean;
  const readbackMatchesExpectation = obs.readbackMatchesExpectation as boolean;
  const expectedPixel = obs.expectedPixel as readonly unknown[];
  const observedPixel = obs.observedPixel as readonly unknown[];
  if (!isRecord(obs.limits)) {
    return refuse("refused_qualification_observation_inconsistent", "limits must be an object", "limits");
  }
  for (const key of LIMITS_FIELDS) {
    if (!int((obs.limits as Record<string, unknown>)[key])) {
      return refuse("refused_qualification_observation_inconsistent", `limits.${key} must be a non-negative integer`, `limits.${key}`);
    }
  }
  for (const key of ["features", "wgslMessages", "expectedPixel", "observedPixel"] as const) {
    if (!Array.isArray(obs[key])) {
      return refuse("refused_qualification_observation_inconsistent", `${key} must be an array`, key);
    }
  }
  if (typeof obs.userAgent !== "string" || obs.userAgent.length === 0) {
    return refuse("refused_qualification_observation_inconsistent", "userAgent is required", "userAgent");
  }

  // ── CONSISTENCY: an observation may not claim more than it reached ────────
  // These are not style checks. Each one is a claim that cannot be true unless
  // every earlier step succeeded, and accepting one would let a probe that died
  // early still report a render.
  const chain: readonly (readonly [boolean, boolean, string])[] = [
    [deviceCreated, adapterObtained, "deviceCreated implies adapterObtained"],
    [adapterObtained, apiPresent, "adapterObtained implies apiPresent"],
    [pipelineCreated, wgslCompiled, "pipelineCreated implies wgslCompiled"],
    [drawSubmitted, pipelineCreated, "drawSubmitted implies pipelineCreated"],
    [renderPassSucceeded, drawSubmitted, "renderPassSucceeded implies drawSubmitted"],
    [readbackSucceeded, renderPassSucceeded, "readbackSucceeded implies renderPassSucceeded"],
    [readbackMatchesExpectation, readbackSucceeded, "readbackMatchesExpectation implies readbackSucceeded"],
  ];
  for (const [child, parent, why] of chain) {
    if (child && !parent) {
      return refuse("refused_qualification_observation_inconsistent", why, null);
    }
  }
  // If the readback claims to match, the pixels must ACTUALLY be equal.
  if (readbackMatchesExpectation) {
    const expected = expectedPixel.join(",");
    const observed = observedPixel.join(",");
    if (expected !== observed) {
      return refuse(
        "refused_qualification_observation_inconsistent",
        `readbackMatchesExpectation is true but pixels differ (expected ${expected}, observed ${observed})`,
        "readbackMatchesExpectation",
      );
    }
    if (expectedPixel.length === 0) {
      return refuse("refused_qualification_observation_inconsistent", "a matching readback must compare at least one component", "expectedPixel");
    }
  }

  // ── VERDICT ──────────────────────────────────────────────────────────────
  const notProven: string[] = [];
  let verdict: QualificationVerdict;

  if (!apiPresent) {
    verdict = "api_absent";
    notProven.push("everything: no WebGPU API is present in this runtime");
  } else if (!adapterObtained) {
    verdict = "no_adapter";
    notProven.push("adapter limits, features, device creation, render and readback");
  } else if (!deviceCreated) {
    verdict = "device_refused";
    notProven.push("render and readback");
  } else if (isFallbackAdapter) {
    // Law 31: a software path is never a hardware claim.
    verdict = "software_adapter_only";
    notProven.push("hardware qualification: the adapter reports itself as a fallback/software path");
  } else if (!renderPassSucceeded) {
    verdict = "render_unverified";
    notProven.push("that any pixel was produced; the render pass did not succeed");
  } else if (!readbackMatchesExpectation) {
    // The case this gate actually produced on this machine.
    verdict = "observed_readback_inconclusive";
    notProven.push(
      "that the GPU rendered the requested content: the readback completed but its content did not match what was rendered",
    );
    notProven.push("hardware qualification, which requires a verified pixel readback");
  } else {
    verdict = "qualified_hardware";
    notProven.push("power-loss behaviour, thermal behaviour and hardware integrity — none of which a probe evidences");
  }

  // ── A HARDWARE CLAIM IS VERIFIED, NEVER ACCEPTED ──────────────────────────
  if (input.claimedQualification === "qualified_hardware" && verdict !== "qualified_hardware") {
    return refuse(
      "refused_qualification_unqualified_claimed_as_hardware",
      `the caller claimed qualified_hardware but the observation supports '${verdict}'`,
      "claimedQualification",
    );
  }
  // A software adapter may not be reported as hardware under any wording.
  if (isFallbackAdapter && input.claimedQualification === "qualified_hardware") {
    return refuse("refused_qualification_software_adapter_hardware_claim", "a software adapter cannot be claimed as hardware", "isFallbackAdapter");
  }

  const limits = obs.limits as unknown as AdapterLimitsObservation;
  const qualificationHash = canonicalHash({
    verdict,
    vendor: input.vendor ?? "",
    adapter: { vendor: input.vendor ?? "", fallback: obs.isFallbackAdapter },
    features: [...(obs.features as readonly string[])].sort(),
    limits,
    userAgent: obs.userAgent,
    expectedPixel,
    observedPixel,
  });

  return {
    ok: true,
    code: "qualification_recorded",
    qualification: Object.freeze({
      verdict,
      qualifiesHardware: (QUALIFYING_VERDICTS as readonly string[]).includes(verdict),
      schemaVersion: QUALIFICATION_SCHEMA_VERSION,
      sourceFrameId: input.sourceFrameId,
      canonicalVisibleHash: input.canonicalVisibleHash,
      qualificationHash,
      vendor: input.vendor ?? "",
      isFallbackAdapter,
      features: Object.freeze([...(obs.features as readonly string[])].sort()),
      limits: Object.freeze({ ...limits }),
      userAgent: obs.userAgent,
      powerLossEvidenced: false as const,
      hardwareIntegrityEvidenced: false as const,
      notProven: Object.freeze(notProven),
      authority: "none" as const,
      controlPlane: false as const,
      readOnly: true as const,
      executionAuthorized: false as const,
    }),
    authority: "none",
    controlPlane: false,
    readOnly: true,
    executionAuthorized: false,
  };
}

/**
 * Bind an existing qualification to a frame.
 *
 * A qualification taken against one frame must not be presented as covering a
 * different one — the unbound-disclosure defect class from 28H.
 */
export function bindQualificationToFrame(
  qualification: WebGpuQualification,
  sourceFrameId: string,
  canonicalVisibleHash: string,
): QualificationDecision {
  if (qualification.sourceFrameId !== sourceFrameId || qualification.canonicalVisibleHash !== canonicalVisibleHash) {
    return refuse(
      "refused_qualification_binding_mismatch",
      "this qualification was taken against a different frame",
      "sourceFrameId",
    );
  }
  return {
    ok: true,
    code: "qualification_recorded",
    qualification,
    authority: "none",
    controlPlane: false,
    readOnly: true,
    executionAuthorized: false,
  };
}