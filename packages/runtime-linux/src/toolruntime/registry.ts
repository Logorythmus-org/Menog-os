/**
 * PRE-21B — Local tool registry (deterministic, in-memory, no authority).
 *
 * A REGISTRY IS NOT AN AUTHORITY. Membership describes availability and
 * carries the metadata that Policy/isolation consume; it never grants
 * capability. Everything this module returns is data; the only sanctioned
 * authority junction remains gateToolExecution() (21A).
 *
 * Design fixed by 21B:
 * - Deterministic: sorted maps, stable ordering for lookup/list, no wall
 *   clock, no randomness — same operations in the same order produce the
 *   same observable state.
 * - Explicit ID+version: every entry is (toolId, version) keyed; two
 *   versions of one tool coexist; identical pairs conflict.
 * - Fail-closed rejection: duplicate (toolId,version), id/version drift
 *   between manifest and metadata, and invalid manifests are REJECTED —
 *   never repaired in place, never overwritten.
 * - Guarded lifecycle: transitions go through transitionLifecycle (the 21A
 *   closed state machine); quarantined/retired are terminal; lifecycle
 *   changes append to an immutable audit trail (in-memory).
 * - No durable persistence redesign: the store is in-memory (per the
 *   standing Phase-20 freeze scope); the exported shape is the contract a
 *   future store would satisfy.
 * - FORBIDDEN by construction: no install/download, no external discovery,
 *   no implicit PATH-based executable identity, no network surface, no
 *   shell-string anything. Executable identity is EXPLICIT RECORD METADATA,
 *   validated for safety, never inferred from PATH or resolved here.
 *
 * Tool output remains untrusted data (21C scope); nothing here executes.
 */

import {
  type LifecycleState,
  type ToolId,
  type ToolManifest,
  type ToolVersion,
} from "./types.js";
import {
  isLifecycleState,
  manifestHash,
  transitionLifecycle,
  isExecutableLifecycle,
  validateManifest,
  type GateResult,
} from "./evaluate.js";

// ── metadata vocabulary (explicit record metadata — never inferred) ──────────

export const SIDE_EFFECT_CLASSES = Object.freeze([
  "read_only",
  "write_in_workspace",
  "write_outside_workspace",
  "process_spawn",
  "irreversible",
  "unknown",
] as const);
export type SideEffectClass = (typeof SIDE_EFFECT_CLASSES)[number];

/**
 * HOW the executable is identified at run time. There is deliberately NO
 * "path_lookup"/"PATH" strategy: executable identity must be explicit record
 * metadata, never resolved implicitly from the environment.
 */
export const PATH_STRATEGIES = Object.freeze([
  "explicit_absolute_path",
  "explicit_relative_path",
  "embedded",
] as const);
export type PathStrategy = (typeof PATH_STRATEGIES)[number];

export const NETWORK_REQUIREMENTS = Object.freeze([
  "none",
  "loopback_only",
  "workspace_local_service",
] as const);
export type NetworkRequirement = (typeof NETWORK_REQUIREMENTS)[number];

/** Declared resource limits (enforced again at the envelope in the gate). */
export interface ToolLimits {
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly maxArgvEntries: number;
}

/** Explicit executable identity metadata (validated; never PATH-inferred). */
export interface ExecutableIdentity {
  readonly pathStrategy: PathStrategy;
  /**
   * For explicit_absolute_path / explicit_relative_path: the exact path.
   * Absolute paths are REQUIRED to be absolute (validated); relative paths
   * must not contain ".."; both are data — confinement happens at execution.
   */
  readonly path?: string;
  /** For embedded: which in-process facility, as a closed-vocabulary key. */
  readonly embeddedKey?: string;
}

/** Registration metadata BEYOND the 21A manifest. */
export interface ToolRegistration {
  readonly manifest: ToolManifest;
  readonly sideEffectClass: SideEffectClass;
  readonly limits: ToolLimits;
  /** Isolation profile id demanded (must equal the manifest's reference). */
  readonly isolationProfileId: string;
  readonly network: NetworkRequirement;
  readonly executable: ExecutableIdentity;
  readonly registeredBy: string;
}

/** Immutable registry entry as stored. */
export interface ToolRegistryEntry {
  readonly manifest: ToolManifest;
  readonly manifestHash: string;
  readonly sideEffectClass: SideEffectClass;
  readonly limits: ToolLimits;
  readonly isolationProfileId: string;
  readonly network: NetworkRequirement;
  readonly executable: ExecutableIdentity;
  readonly registeredBy: string;
  readonly lifecycle: LifecycleState;
}

/** One immutable lifecycle audit record. */
export interface LifecycleAuditRecord {
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  readonly from: LifecycleState;
  readonly to: LifecycleState;
  readonly by: string;
}

const ABSOLUTE_PATH_RE = /^(?:[A-Za-z]:[\\/]|\/)/;
const EMBEDDED_KEY_RE = /^[a-z][a-z0-9._-]{0,63}$/;

function isBounded(v: unknown, min: number, max: number): v is string {
  return typeof v === "string" && v.length >= min && v.length <= max;
}

function isPositiveInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v > 0;
}

// ── registration validation (can only reject) ────────────────────────────────

/**
 * Validate a full registration (manifest + metadata) WITHOUT touching the
 * registry. Every field is checked; anything unknown or unsafe is rejected
 * with a typed failure. Oversized limits are rejected here, and the gate
 * re-checks them per-request at execution time.
 */
export function validateRegistration(input: unknown): GateResult<ToolRegistration> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "registration must be an object" };
  }
  const r = input as Record<string, unknown>;

  const rawManifest = r.manifest;
  if (typeof rawManifest !== "object" || rawManifest === null) {
    return { ok: false, code: "MANIFEST_INVALID", message: "registration.manifest must be an object" };
  }
  // FULL manifest re-validation (not a schemaVersion glance): this both
  // enforces every manifest invariant and yields a FROZEN manifest, so the
  // registry never stores a caller-mutable object (metadata substitution
  // after registration is unrepresentable).
  const manifestChecked = validateManifest(rawManifest);
  if (!manifestChecked.ok) return manifestChecked;
  const m = manifestChecked.value;

  if (typeof r.sideEffectClass !== "string" || !(SIDE_EFFECT_CLASSES as readonly string[]).includes(r.sideEffectClass)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "sideEffectClass must be one of the closed vocabulary values" };
  }

  if (typeof r.limits !== "object" || r.limits === null) {
    return { ok: false, code: "MANIFEST_INVALID", message: "registration.limits must be an object" };
  }
  const lim = r.limits as Record<string, unknown>;
  // Oversized limits are rejected at registration (fail closed), in addition
  // to the per-request envelope checks in the gate.
  if (!isPositiveInt(lim.timeoutMs) || lim.timeoutMs > 600_000) {
    return { ok: false, code: "MANIFEST_INVALID", message: "limits.timeoutMs must be an integer 1..600000" };
  }
  if (!isPositiveInt(lim.maxOutputBytes) || lim.maxOutputBytes > 4_194_304) {
    return { ok: false, code: "MANIFEST_INVALID", message: "limits.maxOutputBytes must be an integer 1..4194304" };
  }
  if (!isPositiveInt(lim.maxArgvEntries) || lim.maxArgvEntries > 64) {
    return { ok: false, code: "MANIFEST_INVALID", message: "limits.maxArgvEntries must be an integer 1..64" };
  }

  if (typeof r.isolationProfileId !== "string" || r.isolationProfileId.length === 0 || r.isolationProfileId.length > 128) {
    return { ok: false, code: "MANIFEST_INVALID", message: "isolationProfileId must be a non-empty string of at most 128 characters" };
  }
  if (r.isolationProfileId !== m.isolationProfileId) {
    return {
      ok: false,
      code: "ID_MISMATCH",
      message: "registration.isolationProfileId does not match the manifest's isolationProfileId",
    };
  }

  if (typeof r.network !== "string" || !(NETWORK_REQUIREMENTS as readonly string[]).includes(r.network)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "network must be one of the closed vocabulary values" };
  }

  if (typeof r.executable !== "object" || r.executable === null) {
    return { ok: false, code: "MANIFEST_INVALID", message: "registration.executable must be an object" };
  }
  const ex = r.executable as Record<string, unknown>;
  if (typeof ex.pathStrategy !== "string" || !(PATH_STRATEGIES as readonly string[]).includes(ex.pathStrategy)) {
    return {
      ok: false,
      code: "MANIFEST_INVALID",
      message: "executable.pathStrategy must be explicit_absolute_path | explicit_relative_path | embedded (no implicit PATH identity)",
    };
  }
  let identity: ExecutableIdentity;
  if (ex.pathStrategy === "embedded") {
    if (!isBounded(ex.embeddedKey, 1, 64) || !EMBEDDED_KEY_RE.test(String(ex.embeddedKey))) {
      return { ok: false, code: "MANIFEST_INVALID", message: "embedded identity requires embeddedKey matching " + String(EMBEDDED_KEY_RE) };
    }
    identity = Object.freeze({ pathStrategy: "embedded", embeddedKey: String(ex.embeddedKey) });
  } else {
    if (typeof ex.path !== "string" || ex.path.length === 0 || ex.path.length > 1024) {
      return { ok: false, code: "MANIFEST_INVALID", message: "explicit identity requires a path of 1..1024 characters" };
    }
    if (ex.pathStrategy === "explicit_absolute_path" && !ABSOLUTE_PATH_RE.test(ex.path)) {
      return { ok: false, code: "MANIFEST_INVALID", message: "explicit_absolute_path requires an absolute path" };
    }
    if (ex.path.includes("..")) {
      return { ok: false, code: "MANIFEST_INVALID", message: "executable path must not contain '..' segments" };
    }
    identity = Object.freeze({ pathStrategy: ex.pathStrategy as "explicit_absolute_path" | "explicit_relative_path", path: ex.path });
  }

  if (!isBounded(r.registeredBy, 1, 120)) {
    return { ok: false, code: "MANIFEST_INVALID", message: "registeredBy must be 1..120 characters" };
  }

  return {
    ok: true,
    value: {
      manifest: m,
      sideEffectClass: r.sideEffectClass as SideEffectClass,
      limits: Object.freeze({
        timeoutMs: lim.timeoutMs as number,
        maxOutputBytes: lim.maxOutputBytes as number,
        maxArgvEntries: lim.maxArgvEntries as number,
      }),
      isolationProfileId: r.isolationProfileId,
      network: r.network as NetworkRequirement,
      executable: identity,
      registeredBy: r.registeredBy,
    },
  };
}

// ── the registry (deterministic, in-memory) ──────────────────────────────────

export class LocalToolRegistry {
  /** (toolId → (version → entry)); insertion-ordered, exposed sorted. */
  private readonly byId = new Map<ToolId, Map<ToolVersion, ToolRegistryEntry>>();
  private readonly audit: LifecycleAuditRecord[] = [];

  /**
   * Register a validated tool. Registration is availability, NOT authority:
   * the entry lands in lifecycle "registered" and grants nothing. Duplicate
   * (toolId,version) pairs are rejected — never overwritten.
   */
  register(input: unknown): GateResult<ToolRegistryEntry> {
    const parsed = validateRegistration(input);
    if (!parsed.ok) return parsed;
    const reg = parsed.value;

    let versions = this.byId.get(reg.manifest.toolId);
    if (versions === undefined) {
      versions = new Map<ToolVersion, ToolRegistryEntry>();
      this.byId.set(reg.manifest.toolId, versions);
    }
    if (versions.has(reg.manifest.version)) {
      return {
        ok: false,
        code: "MANIFEST_INVALID",
        message: "duplicate registration for " + reg.manifest.toolId + "@" + reg.manifest.version + " (conflicts are rejected, never overwritten)",
      };
    }

    const entry: ToolRegistryEntry = Object.freeze({
      manifest: reg.manifest,
      manifestHash: manifestHash(reg.manifest),
      sideEffectClass: reg.sideEffectClass,
      limits: reg.limits,
      isolationProfileId: reg.isolationProfileId,
      network: reg.network,
      executable: reg.executable,
      registeredBy: reg.registeredBy,
      lifecycle: "registered",
    });
    versions.set(reg.manifest.version, entry);
    return { ok: true, value: entry };
  }

  /** Deterministic lookup by explicit (toolId, version). */
  lookup(toolId: ToolId, version: ToolVersion): GateResult<ToolRegistryEntry> {
    const entry = this.byId.get(toolId)?.get(version);
    if (entry === undefined) {
      return { ok: false, code: "MANIFEST_INVALID", message: "no registration for " + toolId + "@" + version };
    }
    return { ok: true, value: entry };
  }

  /**
   * All entries for a toolId, sorted by version (lexicographic on the
   * explicit semver string — deterministic, no hidden precedence rules).
   */
  listVersions(toolId: ToolId): readonly ToolRegistryEntry[] {
    const versions = this.byId.get(toolId);
    if (versions === undefined) return [];
    return [...versions.values()].sort((a, b) => (a.manifest.version < b.manifest.version ? -1 : a.manifest.version > b.manifest.version ? 1 : 0));
  }

  /** Every entry, sorted by (toolId, version) — the stable listing order. */
  listAll(): readonly ToolRegistryEntry[] {
    const out: ToolRegistryEntry[] = [];
    for (const toolId of [...this.byId.keys()].sort()) {
      out.push(...this.listVersions(toolId));
    }
    return out;
  }

  /** Executable candidates only: registered/enabled, sorted deterministically. */
  listExecutableCandidates(): readonly ToolRegistryEntry[] {
    return this.listAll().filter((e) => isExecutableLifecycle(e.lifecycle));
  }

  /**
   * The ONLY sanctioned lifecycle change. Goes through the 21A closed state
   * machine; every accepted transition appends an immutable audit record;
   * quarantined/retired are terminal (bypass unrepresentable).
   */
  transition(toolId: ToolId, version: ToolVersion, to: unknown, by: string): GateResult<ToolRegistryEntry> {
    const found = this.lookup(toolId, version);
    if (!found.ok) return found;
    const entry = found.value;
    if (!isLifecycleState(to)) {
      return { ok: false, code: "LIFECYCLE_NOT_EXECUTABLE", message: "unknown lifecycle state" };
    }
    if (!isBounded(by, 1, 120)) {
      return { ok: false, code: "LIFECYCLE_NOT_EXECUTABLE", message: "by must be 1..120 characters" };
    }
    const stepped = transitionLifecycle(entry.lifecycle, to);
    if (!stepped.ok) return stepped;

    const updated: ToolRegistryEntry = Object.freeze({ ...entry, lifecycle: stepped.value });
    this.byId.get(toolId)!.set(version, updated);
    this.audit.push(Object.freeze({ toolId, version, from: entry.lifecycle, to: stepped.value, by }));
    return { ok: true, value: updated };
  }

  /** Frozen immutable copy of the lifecycle audit trail, in append order. */
  lifecycleAudit(): readonly LifecycleAuditRecord[] {
    return Object.freeze(this.audit.slice());
  }

  size(): number {
    let n = 0;
    for (const versions of this.byId.values()) n += versions.size;
    return n;
  }
}

export { isExecutableLifecycle };
