/**
 * PRE-21A — Governed tool runtime logic (pure, deterministic, no I/O, no
 * execution). These functions are the ONLY sanctioned way to turn an
 * (agent-supplied) request into a decision, and they are built so that the
 * dangerous outcomes are unrepresentable:
 *
 * - validateManifest / validateEnvelope can only reject; nothing here grants.
 * - transitionLifecycle is a closed state machine: quarantined and retired
 *   are terminal (no quarantine bypass; no retirement resurrection).
 * - gateToolExecution evaluates the FULL authority intersection — task scope
 *   ∩ agent capability ∩ tool requirement ∩ Policy allow ∩ isolation
 *   enforceability — and denies BEFORE any execution when any member is
 *   missing. It structurally cannot return a plan for a policy deny, an
 *   unenforceable profile, or an empty intersection.
 * - buildToolEvidence enforces the evidence ordering: enforced ⊆ authorized
 *   ⊆ requested and observed ⊆ enforced. Any overclaim is a typed failure,
 *   never a warning. Hashing reuses the isolation module's canonical form so
 *   evidence hashes are stable across processes and platforms.
 *
 * Tool output, when it eventually exists (21C), is untrusted data — nothing
 * in this module treats it as instruction.
 */

import {
  ISOLATION_CONTRACT_SCHEMA_VERSION,
} from "../isolation/types.js";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  LIFECYCLE_STATES,
  TOOL_EXECUTION_STATUSES,
  TOOL_ID_PATTERN,
  TOOL_VERSION_PATTERN,
  type CapabilityRequirement,
  type LifecycleState,
  type ToolExecutionDecision,
  type ToolExecutionEvidence,
  type ToolExecutionPlan,
  type ToolExecutionRequest,
  type ToolFailureCode,
  type ToolId,
  type ToolInputEnvelope,
  type ToolManifest,
  type ToolVersion,
} from "./types.js";
import { canonicalIsolationJson, isolationEvidenceHash } from "../isolation/canonical.js";

// ── small helpers ────────────────────────────────────────────────────────────

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isBounded(v: unknown, min: number, max: number): v is string {
  return typeof v === "string" && v.length >= min && v.length <= max;
}

/** Shell metacharacters that have no business inside an argv vector. */
const ARGV_FORBIDDEN = /[;&|><`$\\]/;

/** Env var NAME allowlist shape: POSIX-portable, no shell meaning. */
const ENV_NAME_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

const CAPABILITY_PATTERN = /^[a-z][a-z0-9._-]*:[a-z][a-z0-9._-]{0,63}$/;

export type GateResult<T> = { ok: true; value: T } | { ok: false; code: ToolFailureCode; message: string };

// ── manifest validation (requests only; never grants) ───────────────────────

export function validateManifest(input: unknown): GateResult<ToolManifest> {
  if (!isObject(input)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "manifest must be an object" };
  }
  const toolId = input.toolId;
  if (typeof toolId !== "string" || !TOOL_ID_PATTERN.test(toolId)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "toolId must match " + String(TOOL_ID_PATTERN) };
  }
  const version = input.version;
  if (typeof version !== "string" || !TOOL_VERSION_PATTERN.test(version)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "version must be explicit semver (major.minor.patch)" };
  }
  if (!isBounded(input.displayName, 1, 120)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "displayName must be 1..120 characters" };
  }
  if (!isBounded(input.description, 1, 600)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "description must be 1..600 characters" };
  }
  if (typeof input.isolationProfileId !== "string" || input.isolationProfileId.length === 0 || input.isolationProfileId.length > 128) {
    return { ok: false, code: "MANIFEST_INVALID", message: "isolationProfileId must be a non-empty string of at most 128 characters" };
  }
  if (input.trustClass !== "human_reviewed" && input.trustClass !== "agent_supplied") {
    return { ok: false, code: "MANIFEST_INVALID", message: "trustClass must be 'human_reviewed' or 'agent_supplied'" };
  }
  if (!isBounded(input.declaredBy, 1, 120)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "declaredBy must be 1..120 characters" };
  }
  if (!Array.isArray(input.capabilities)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "capabilities must be an array" };
  }
  if (input.capabilities.length > 32) {
    return { ok: false, code: "MANIFEST_INVALID", message: "capabilities must not exceed 32 entries" };
  }
  const seen = new Set<string>();
  const capabilities: CapabilityRequirement[] = [];
  for (const c of input.capabilities) {
    if (!isObject(c)) {
      return { ok: false, code: "MANIFEST_INVALID", message: "each capability must be an object" };
    }
    if (typeof c.capability !== "string" || !CAPABILITY_PATTERN.test(c.capability)) {
      return { ok: false, code: "MANIFEST_INVALID", message: "capability names must be 'scope:name' (lowercase, bounded)" };
    }
    if (seen.has(c.capability)) {
      return { ok: false, code: "MANIFEST_INVALID", message: "duplicate capability '" + c.capability + "'" };
    }
    seen.add(c.capability);
    if (c.criticality !== "required" && c.criticality !== "optional") {
      return { ok: false, code: "MANIFEST_INVALID", message: "capability criticality must be 'required' or 'optional'" };
    }
    capabilities.push(Object.freeze({ capability: c.capability, criticality: c.criticality }));
  }
  if (input.proposedProfile !== undefined) {
    const p = input.proposedProfile;
    if (!isObject(p) || p.schemaVersion !== ISOLATION_CONTRACT_SCHEMA_VERSION) {
      return {
        ok: false,
        code: "MANIFEST_INVALID",
        message: "proposedProfile must be an isolation contract object (" + ISOLATION_CONTRACT_SCHEMA_VERSION + ")",
      };
    }
  }
  const manifest: ToolManifest = Object.freeze({
    schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
    toolId,
    version,
    displayName: input.displayName,
    description: input.description,
    capabilities,
    trustClass: input.trustClass,
    declaredBy: input.declaredBy,
    isolationProfileId: input.isolationProfileId,
    ...(input.proposedProfile !== undefined ? { proposedProfile: input.proposedProfile as ToolManifest["proposedProfile"] } : {}),
  });
  return { ok: true, value: manifest };
}

/** Deterministic manifest hash (canonical JSON, sha256) for pinning + drift detection. */
export function manifestHash(manifest: ToolManifest): string {
  return isolationEvidenceHash(canonicalManifestBody(manifest));
}

function canonicalManifestBody(manifest: ToolManifest): Record<string, unknown> {
  return {
    schemaVersion: manifest.schemaVersion,
    toolId: manifest.toolId,
    version: manifest.version,
    displayName: manifest.displayName,
    description: manifest.description,
    capabilities: manifest.capabilities,
    trustClass: manifest.trustClass,
    declaredBy: manifest.declaredBy,
    isolationProfileId: manifest.isolationProfileId,
  };
}

// ── lifecycle (closed state machine; quarantine bypass unrepresentable) ─────

const LIFECYCLE_TRANSITIONS: Readonly<Record<LifecycleState, readonly LifecycleState[]>> = Object.freeze({
  registered: ["enabled", "disabled", "quarantined", "retired"],
  enabled: ["disabled", "quarantined", "retired"],
  disabled: ["enabled", "quarantined", "retired"],
  quarantined: ["retired"],
  retired: [],
});

export function isLifecycleState(v: unknown): v is LifecycleState {
  return typeof v === "string" && (LIFECYCLE_STATES as readonly string[]).includes(v);
}

/**
 * The ONLY sanctioned lifecycle transition. Quarantined tools can go nowhere
 * but retired; retired tools cannot move at all; unknown states are refused.
 */
export function transitionLifecycle(from: LifecycleState, to: LifecycleState): GateResult<LifecycleState> {
  if (!isLifecycleState(from) || !isLifecycleState(to)) {
    return { ok: false, code: "LIFECYCLE_NOT_EXECUTABLE", message: "unknown lifecycle state" };
  }
  if (!LIFECYCLE_TRANSITIONS[from].includes(to)) {
    return {
      ok: false,
      code: "LIFECYCLE_NOT_EXECUTABLE",
      message: "illegal lifecycle transition " + from + " -> " + to + " (quarantined/retired are terminal for execution)",
    };
  }
  return { ok: true, value: to };
}

/** Only these states allow a gate evaluation to even be attempted. */
export function isExecutableLifecycle(state: LifecycleState): boolean {
  return state === "registered" || state === "enabled";
}

// ── envelope validation (untrusted agent input; can only reject) ────────────

export function validateEnvelope(input: unknown): GateResult<ToolInputEnvelope> {
  if (!isObject(input)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "envelope must be an object" };
  }
  if (input.schemaVersion !== TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "envelope schemaVersion must be " + TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION };
  }
  const toolId = input.toolId;
  if (typeof toolId !== "string" || !TOOL_ID_PATTERN.test(toolId)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "envelope.toolId must match " + String(TOOL_ID_PATTERN) };
  }
  const version = input.version;
  if (typeof version !== "string" || !TOOL_VERSION_PATTERN.test(version)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "envelope.version must be explicit semver" };
  }
  if (!isObject(input.constraints)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "envelope.constraints must be an object" };
  }
  const raw = input.constraints as Record<string, unknown>;

  if (raw.argv !== undefined) {
    if (!Array.isArray(raw.argv) || raw.argv.length > 64) {
      return { ok: false, code: "ENVELOPE_INVALID", message: "argv must be an array of at most 64 strings" };
    }
    for (const a of raw.argv) {
      if (typeof a !== "string" || a.length === 0 || a.length > 4096) {
        return { ok: false, code: "ENVELOPE_INVALID", message: "argv entries must be non-empty strings of at most 4096 characters" };
      }
      if (ARGV_FORBIDDEN.test(a)) {
        return { ok: false, code: "ARGS_FORBIDDEN", message: "argv entries must not contain shell metacharacters: " + a.slice(0, 40) };
      }
    }
  }
  if (raw.cwd !== undefined && (typeof raw.cwd !== "string" || raw.cwd.length === 0 || raw.cwd.length > 1024)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "cwd must be a non-empty string of at most 1024 characters" };
  }
  if (raw.envAllowlist !== undefined) {
    if (!Array.isArray(raw.envAllowlist) || raw.envAllowlist.length > 32) {
      return { ok: false, code: "ENVELOPE_INVALID", message: "envAllowlist must be an array of at most 32 names" };
    }
    for (const n of raw.envAllowlist) {
      if (typeof n !== "string" || !ENV_NAME_PATTERN.test(n)) {
        return { ok: false, code: "ENV_NAME_FORBIDDEN", message: "env allowlist entries must be UPPERCASE_NAMES (values never travel in envelopes): " + String(n).slice(0, 40) };
      }
    }
  }
  if (raw.timeoutMs !== undefined && (typeof raw.timeoutMs !== "number" || !Number.isInteger(raw.timeoutMs) || raw.timeoutMs < 1 || raw.timeoutMs > 600_000)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "timeoutMs must be an integer 1..600000" };
  }
  if (raw.maxOutputBytes !== undefined && (typeof raw.maxOutputBytes !== "number" || !Number.isInteger(raw.maxOutputBytes) || raw.maxOutputBytes < 1 || raw.maxOutputBytes > 4_194_304)) {
    return { ok: false, code: "ENVELOPE_INVALID", message: "maxOutputBytes must be an integer 1..4194304" };
  }
  const envelope: ToolInputEnvelope = Object.freeze({
    schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
    toolId,
    version,
    input: input.input,
    constraints: {
      ...(raw.argv !== undefined ? { argv: Object.freeze((raw.argv as string[]).slice()) } : {}),
      ...(raw.cwd !== undefined ? { cwd: raw.cwd as string } : {}),
      ...(raw.envAllowlist !== undefined ? { envAllowlist: Object.freeze((raw.envAllowlist as string[]).slice()) } : {}),
      ...(raw.timeoutMs !== undefined ? { timeoutMs: raw.timeoutMs as number } : {}),
      ...(raw.maxOutputBytes !== undefined ? { maxOutputBytes: raw.maxOutputBytes as number } : {}),
    },
  });
  return { ok: true, value: envelope };
}

/**
 * The cwd confinement check: a requested cwd is acceptable only when it stays
 * inside the authorized workspace root. Pure string/segment logic — the
 * caller supplies the authorized root it received from Policy/allocation,
 * never from the agent.
 */
export function isCwdInsideWorkspace(cwd: string, workspaceRoot: string): boolean {
  // Normalize: unify separators, drop empty/"." segments, and RESOLVE ".."
  // by popping (a leading ".." that escapes above the root is kept as a
  // segment — it will then fail the prefix comparison, denying containment).
  const norm = (p: string): string[] => {
    const out: string[] = [];
    for (const seg of p.replace(/\\/g, "/").split("/")) {
      if (seg.length === 0 || seg === ".") continue;
      if (seg === "..") {
        if (out.length > 0) out.pop();
        else out.push(seg);
      } else {
        out.push(seg);
      }
    }
    return out;
  };
  const rootSegs = norm(workspaceRoot);
  const cwdSegs = norm(cwd);
  if (rootSegs.length === 0) return false;
  if (cwdSegs.length < rootSegs.length) return false;
  for (let i = 0; i < rootSegs.length; i++) {
    if (rootSegs[i] !== cwdSegs[i]) return false;
  }
  return true;
}

// ── the authority-intersection gate (can only deny or defer) ─────────────────

/**
 * Evaluate the FULL authority intersection. Order is fixed and evidence-
 * relevant: validation → lifecycle → manifest-vs-request identity →
 * capability intersection → Policy → isolation. The first failing member
 * denies; nothing after a deny is consulted; a deny never produces a plan.
 */
export function gateToolExecution(
  request: ToolExecutionRequest,
  manifest: ToolManifest,
  lifecycle: LifecycleState
): ToolExecutionDecision {
  const deny = (status: ToolExecutionDecision["status"], reason: string): ToolExecutionDecision =>
    Object.freeze({ requestId: request.requestId, status, reason });

  // 1. Lifecycle: registration never authorizes; non-executable states deny.
  if (!isExecutableLifecycle(lifecycle)) {
    return deny("validation_denied", "tool lifecycle state '" + lifecycle + "' is not executable (registered/enabled only)");
  }

  // 2. Identity: the request must be FOR the manifest under evaluation —
  //    explicit versions; substitution across tools or versions denied.
  if (request.toolId !== manifest.toolId || request.version !== manifest.version) {
    return deny("validation_denied", "request identity does not match manifest (toolId/version mismatch)");
  }
  if (request.envelope.toolId !== manifest.toolId || request.envelope.version !== manifest.version) {
    return deny("validation_denied", "envelope identity does not match manifest (toolId/version mismatch)");
  }

  // 3. Capability intersection: requirement ∩ task scope ∩ agent capability.
  //    REQUIRED tool demands must be covered by BOTH task scope and agent
  //    capabilities; OPTIONAL demands contribute to the effective set only
  //    when both sides grant them. Empty intersection denies outright.
  const taskSet = new Set(request.taskScope);
  const agentSet = new Set(request.agentCapabilities);
  const effective: string[] = [];
  for (const cap of manifest.capabilities) {
    const granted = taskSet.has(cap.capability) && agentSet.has(cap.capability);
    if (granted) {
      effective.push(cap.capability);
    } else if (cap.criticality === "required") {
      return deny(
        "validation_denied",
        "required capability '" + cap.capability + "' is not covered by task scope and agent capability intersection"
      );
    }
  }
  if (effective.length === 0) {
    return deny("validation_denied", "authority intersection is empty — no capability is granted by task scope and agent capability");
  }

  // 4. Policy: the sole logical authorization authority. A deny never
  //    reaches isolation or a plan.
  if (request.policyOutcome !== "allow") {
    return deny("policy_denied", "policy did not allow this execution" + (request.policyRuleId ? " (" + request.policyRuleId + ")" : ""));
  }

  // 5. Isolation enforceability: measured, never assumed. An unenforceable
  //    profile denies — policy allow alone is never sufficient.
  if (!request.isolation.canEnforce) {
    return deny("isolation_denied", request.isolation.reason ?? "isolation for profile '" + request.isolation.profileId + "' is not enforceable");
  }

  const plan: ToolExecutionPlan = Object.freeze({
    requestId: request.requestId,
    toolId: request.toolId,
    version: request.version,
    effectiveCapabilities: Object.freeze(effective.slice()),
    isolationProfileId: request.isolation.profileId,
    plannedAt: new Date().toISOString(),
  });
  return Object.freeze({ requestId: request.requestId, status: "not_started", plan });
}

// ── evidence (requested ⊇ authorized ⊇ enforced ⊇ observed) ─────────────────

/**
 * Build four-layer evidence with anti-overclaim ordering: enforced ⊆
 * authorized ⊆ requested, observed ⊆ enforced. The status must be consistent
 * with the recorded layers (a not_started record may not claim enforced
 * capabilities). Hash binds the whole body except the hash itself.
 */
export function buildToolEvidence(input: {
  requestId: string;
  toolId: ToolId;
  version: ToolVersion;
  manifestHash: string;
  status: ToolExecutionDecision["status"];
  requested: readonly string[];
  authorized: readonly string[];
  enforced: readonly string[];
  observed: readonly string[];
  policyOutcome: string;
  isolationProfileId: string;
  recordedAt: string;
}): GateResult<ToolExecutionEvidence> {
  const requested = new Set(input.requested);
  const authorizedSet = new Set(input.authorized);
  const enforcedSet = new Set(input.enforced);

  for (const a of input.authorized) {
    if (!requested.has(a)) {
      return { ok: false, code: "EVIDENCE_OVERCLAIM", message: "authorized capability '" + a + "' was never requested" };
    }
  }
  for (const e of input.enforced) {
    if (!authorizedSet.has(e)) {
      return { ok: false, code: "EVIDENCE_OVERCLAIM", message: "enforced capability '" + e + "' was never authorized" };
    }
  }
  for (const o of input.observed) {
    if (!enforcedSet.has(o)) {
      return { ok: false, code: "EVIDENCE_OVERCLAIM", message: "observed capability '" + o + "' was never enforced" };
    }
  }
  if (input.status === "not_started" && input.enforced.length > 0) {
    return {
      ok: false,
      code: "EVIDENCE_OVERCLAIM",
      message: "status 'not_started' may not claim enforced capabilities",
    };
  }
  if ((input.status === "policy_denied" || input.status === "isolation_denied" || input.status === "validation_denied") && input.authorized.length > 0) {
    return {
      ok: false,
      code: "EVIDENCE_OVERCLAIM",
      message: "status '" + input.status + "' may not claim authorized capabilities",
    };
  }
  if (!TOOL_EXECUTION_STATUSES.includes(input.status)) {
    return { ok: false, code: "EVIDENCE_OVERCLAIM", message: "unknown execution status: " + String(input.status) };
  }

  const body = {
    schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
    requestId: input.requestId,
    toolId: input.toolId,
    version: input.version,
    manifestHash: input.manifestHash,
    status: input.status,
    requested: input.requested.slice().sort(),
    authorized: input.authorized.slice().sort(),
    enforced: input.enforced.slice().sort(),
    observed: input.observed.slice().sort(),
    policyOutcome: input.policyOutcome,
    isolationProfileId: input.isolationProfileId,
    recordedAt: input.recordedAt,
  };
  const evidenceHash = isolationEvidenceHash(body);
  const evidence: ToolExecutionEvidence = Object.freeze({ ...body, evidenceHash });
  return { ok: true, value: evidence };
}

// ── drift detection (explicit versions) ──────────────────────────────────────

/**
 * Version drift check: a request for toolId@version is executable only
 * against the SAME version that was hashed at registration. Any drift is a
 * typed failure — never a silent accept.
 */
export function checkVersionDrift(
  requested: { toolId: ToolId; version: ToolVersion },
  registeredHash: string,
  currentManifestHash: string
): GateResult<true> {
  if (registeredHash !== currentManifestHash) {
    return {
      ok: false,
      code: "MANIFEST_HASH_MISMATCH",
      message: "manifest hash drift for " + requested.toolId + "@" + requested.version + " — re-registration required",
    };
  }
  return { ok: true, value: true };
}

// re-export for consumers that want one import site
export { canonicalIsolationJson };
