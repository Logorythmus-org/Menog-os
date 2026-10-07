/**
 * PRE-20B — Isolation contracts (CONTRACT / TEST-FIRST; no enforcement here).
 *
 * Formalizes Policy → IsolationProfile → Linux enforcement WITHOUT implementing
 * any enforcement. 20B non-goal honored: no seccomp filter, no Landlock
 * ruleset, no namespace launcher, no cgroup manager lives in this module.
 *
 * Semantics frozen here (each enforced by tests):
 * - Policy ALLOW is NECESSARY but NOT SUFFICIENT: execution requires both a
 *   policy ALLOW and a fail-closed isolation decision.
 * - A required primitive that is missing (or merely UNVERIFIED) fails closed
 *   BEFORE target execution; fail-open is unrepresentable.
 * - Optional degradation is explicit: every downgrade is a recorded
 *   degradation entry with a consequence, never a silent fallback.
 * - Isolation can REDUCE but never EXPAND authority: profiles carry no
 *   capabilities, verbs, or policy fields; the combined gate can only deny.
 * - Agent-supplied profiles are UNTRUSTED: they may only ADD restrictions
 *   relative to a human-reviewed baseline; any relaxation is rejected.
 * - Actual enforcement is per-primitive evidence, never a boolean "sandboxed".
 *
 * Primitive vocabulary and states mirror the 20A capability matrix
 * (`docs/release/PHASE20_LINUX_CAPABILITY_MATRIX.json`).
 */

// ── schema ───────────────────────────────────────────────────────────────────

export const ISOLATION_CONTRACT_SCHEMA_VERSION = "menog-isolation-contract/v0" as const;
export type IsolationContractSchemaVersion = typeof ISOLATION_CONTRACT_SCHEMA_VERSION;

// ── primitive vocabulary (20A-probed Linux surface) ──────────────────────────

export const ISOLATION_PRIMITIVE_IDS = Object.freeze([
  "ns_user",
  "ns_mount",
  "ns_pid",
  "ns_ipc",
  "ns_uts",
  "ns_net",
  "cgroup_v2_controllers",
  "cgroup_v2_delegation",
  "landlock_fs",
  "landlock_net",
  "seccomp_filter",
  "no_new_privs",
  "rlimit_set",
  "proc_hidepid",
] as const);

export type IsolationPrimitiveId = (typeof ISOLATION_PRIMITIVE_IDS)[number];

export type IsolationPrimitive = IsolationPrimitiveId;

/** Closed state vocabulary — identical to the 20A matrix states. */
export const PRIMITIVE_STATES = Object.freeze([
  "SUPPORTED",
  "UNSUPPORTED",
  "PERMISSION_DENIED",
  "UNVERIFIED",
  "NOT_APPLICABLE",
] as const);

export type PrimitiveState = (typeof PRIMITIVE_STATES)[number];

/** True only for a state that may be relied upon (fail-closed elsewhere). */
export function isUsableState(state: PrimitiveState): boolean {
  return state === "SUPPORTED";
}

// ── requirement + profile ────────────────────────────────────────────────────

export type RequirementCriticality = "required" | "optional";

/**
 * One per-primitive demand of a profile. `onMissing` is the ONLY sanctioned
 * downgrade path and must be explicit; "proceed" is legal only for optional
 * primitives (validated in evaluate.ts).
 */
export interface IsolationRequirement {
  readonly primitive: IsolationPrimitiveId;
  readonly criticality: RequirementCriticality;
  readonly onMissing: "fail_closed" | "degrade_explicit" | "proceed";
  /** Human-readable consequence used verbatim in degradation records. */
  readonly degradationNote?: string;
  /** Minimum Landlock ABI demanded (only meaningful for Landlock primitives). */
  readonly minLandlockAbi?: number;
}

/**
 * WHAT enforcement an execution class demands. A profile deliberately carries
 * NO capabilities, verbs, actors, or policy fields: it can only restrict.
 */
export interface IsolationProfile {
  readonly schemaVersion: IsolationContractSchemaVersion;
  readonly profileId: string;
  readonly requirements: readonly IsolationRequirement[];
  /**
   * Who authored the profile. "agent_proposed" profiles are UNTRUSTED: they
   * may only add restrictions over a human-reviewed baseline (see
   * composeProfileBaseline in evaluate.ts); they never execute directly.
   */
  readonly origin: "human_reviewed" | "agent_proposed";
  /** Bounded provenance note (observability only; never executed). */
  readonly note?: string;
}

// ── capability snapshot (measured, never inferred) ───────────────────────────

export interface IsolationCapabilitySnapshot {
  readonly targetKernel: string;
  readonly targetArch: string;
  readonly isWsl: boolean;
  /** Measured Landlock ABI level, or null when unprobeable. */
  readonly landlockAbi: number | null;
  /** Per-primitive MEASURED state (20A probe output; UNVERIFIED ≠ SUPPORTED). */
  readonly primitives: Readonly<Record<IsolationPrimitiveId, PrimitiveState>>;
  readonly probedAt: string; // ISO-8601
}

// ── decision (fail-closed evaluation result) ─────────────────────────────────

export type IsolationDisposition = "enforce_full" | "degrade_explicit" | "fail_closed";

export interface IsolationDegradation {
  readonly primitive: IsolationPrimitiveId;
  readonly consequence: string;
}

export interface IsolationDecision {
  readonly disposition: IsolationDisposition;
  /** Required primitives measured SUPPORTED (and ABI-sufficient). */
  readonly satisfied: readonly IsolationPrimitiveId[];
  /** Required primitives NOT usable ⇒ execution must not begin. */
  readonly missingRequired: readonly IsolationPrimitiveId[];
  /** Explicit degradations (optional primitives not usable). */
  readonly degradations: readonly IsolationDegradation[];
  /** True only when execution may begin under this decision alone. */
  readonly canProceed: boolean;
  readonly reasons: readonly string[];
}

// ── evidence (per-primitive enforcement record — never "sandboxed: true") ────

export interface EnforcedPrimitiveRecord {
  readonly applied: boolean;
  /** Measured ABI at enforcement time when applicable (e.g. Landlock). */
  readonly abi?: number | null;
  /** Bounded detail: what was actually enforced (paths, filter summary, …). */
  readonly detail: string;
}

export interface IsolationEvidence {
  readonly schemaVersion: IsolationContractSchemaVersion;
  readonly decisionProfileId: string;
  readonly enforced: Readonly<Record<string, EnforcedPrimitiveRecord>>;
  /** SHA-256 of the canonical serialization of this evidence body. */
  readonly evidenceHash: string;
  readonly recordedAt: string; // ISO-8601
}

// ── failure (fail-closed record) ─────────────────────────────────────────────

export type IsolationFailureCode =
  | "MISSING_REQUIRED_PRIMITIVE"
  | "ABI_INSUFFICIENT"
  | "PROFILE_INVALID"
  | "PROFILE_RELAXES_BASELINE"
  | "EVIDENCE_OVERCLAIM";

export interface IsolationFailure {
  readonly code: IsolationFailureCode;
  readonly message: string;
  readonly primitives?: readonly IsolationPrimitiveId[];
}
