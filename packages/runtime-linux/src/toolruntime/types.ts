/**
 * PRE-21A — Governed tool/skill runtime contracts (CONTRACT / TEST-FIRST).
 *
 * Defines WHAT a governed tool execution IS inside the Phase-20 OS boundary.
 * This module implements NO execution: no process is spawned, no I/O is
 * performed, and no authority is granted by anything in this file. The only
 * sanctioned junction from a validated request to an executable plan is
 * gateToolExecution() in evaluate.ts — and it can only deny or defer.
 *
 * Semantics frozen here (each enforced by tests):
 * - Discovery/registration NEVER authorizes. A lifecycle record describes
 *   availability; Policy remains the sole logical authorization authority.
 * - Manifest capabilities are REQUESTS, not grants. They matter only inside
 *   the authority intersection.
 * - Agent-supplied ids, manifests, args, env, cwd, and profiles are UNTRUSTED
 *   data. Nothing an agent supplies can widen authority; validation can only
 *   reject.
 * - Execution authority exists only when ALL of these hold:
 *     task scope ∩ agent capability ∩ tool requirement ∩ Policy allow ∩
 *     isolation enforceability
 *   An invalid or empty intersection denies BEFORE any execution.
 * - Statuses distinguish not_started / started / completed / failed /
 *   timed_out / policy_denied / isolation_denied / validation_denied so a
 *   denial is never representable as a run.
 * - Evidence distinguishes requested / authorized / enforced / observed, with
 *   anti-overclaim ordering (enforced ⊆ authorized ⊆ requested; observed ⊆
 *   enforced) and a deterministic hash.
 * - Versions are explicit; lifecycle is a closed state machine whose
 *   quarantined and retired states are unreachable from and un-reachable to
 *   execution.
 *
 * Non-goals (never represented here): marketplace, remote plugins/MCP
 * federation, installs/downloads, LLM tool selection, autonomous skill
 * creation.
 */

import type { IsolationProfile } from "../isolation/types.js";

// ── schema ───────────────────────────────────────────────────────────────────

export const TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION = "menog-tool-runtime-contract/v0" as const;
export type ToolRuntimeContractSchemaVersion = typeof TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION;

// ── identity ─────────────────────────────────────────────────────────────────

/** Tool identifier: lowercase, bounded, no whitespace, no shell meaning. */
export type ToolId = string;
/** Explicit semver-ish version; two tools differing only in version differ. */
export type ToolVersion = string;

export const TOOL_ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
export const TOOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,32})?$/;

// ── trust ────────────────────────────────────────────────────────────────────

/**
 * Who vouches for a manifest. "agent_supplied" manifests are UNTRUSTED: they
 * may be registered but never elevate; every authority they claim still has
 * to survive the intersection and Policy.
 */
export type TrustClass = "human_reviewed" | "agent_supplied";

/**
 * Closed lifecycle vocabulary. registered/enabled are the only executable-
 * adjacent states; quarantined and retired are terminal for execution and can
 * never be re-enabled into execution (quarantine bypass is unrepresentable).
 */
export const LIFECYCLE_STATES = Object.freeze([
  "registered",
  "enabled",
  "disabled",
  "quarantined",
  "retired",
] as const);
export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

// ── capability demand (a REQUEST, never a grant) ─────────────────────────────

export interface CapabilityRequirement {
  /** Capability name, e.g. "workspace:read" (bounded, lowercase, colon-scoped). */
  readonly capability: string;
  readonly criticality: "required" | "optional";
}

// ── manifest (untrusted until validated; never self-authorizing) ─────────────

/**
 * A tool manifest declares what the tool BELIEVES it needs. It is a request
 * package: registration never authorizes, and the declared capabilities are
 * only ever consumed inside the authority intersection.
 */
export interface ToolManifest {
  readonly schemaVersion: ToolRuntimeContractSchemaVersion;
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  readonly displayName: string;
  readonly description: string;
  readonly capabilities: readonly CapabilityRequirement[];
  readonly trustClass: TrustClass;
  /** Bounded declared-by provenance (observability only; never executed). */
  readonly declaredBy: string;
  /**
   * Reference to the isolation demand for this tool. The referenced profile
   * must be a human-reviewed IsolationProfile known to the runtime; a
   * manifest MAY additionally carry an agent-proposed profile, which is
   * usable ONLY through the 20B restrict-only composition (composeProfileBaseline)
   * and never directly.
   */
  readonly isolationProfileId: string;
  readonly proposedProfile?: IsolationProfile;
}

/** Deterministic content hash binding a manifest's bytes of meaning. */
export interface ManifestHashRecord {
  readonly manifestHash: string; // sha256 of canonical serialization
  readonly algorithm: "sha256";
}

// ── input envelope (validated BEFORE any gate) ───────────────────────────────

/**
 * The validated input envelope. Every field inside is untrusted agent data
 * that has passed structural hygiene: argv-only (never a shell string),
 * bounded counts and lengths, allowlisted env NAMES (values are provided by
 * the execution environment, never carried in the envelope), a cwd that must
 * resolve inside the authorized workspace, and bounded timeouts/output.
 */
export interface ToolInputEnvelope {
  readonly schemaVersion: ToolRuntimeContractSchemaVersion;
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  /** Opaque tool input payload; interpreted only by the tool itself. */
  readonly input: unknown;
  readonly constraints: {
    /** Target argv vector (post `--`); shell metacharacters are rejected. */
    readonly argv?: readonly string[];
    /** Working directory request; must stay inside the authorized workspace. */
    readonly cwd?: string;
    /** Env var NAMES the tool may receive; values never travel in envelopes. */
    readonly envAllowlist?: readonly string[];
    readonly timeoutMs?: number;
    readonly maxOutputBytes?: number;
  };
}

// ── request / plan / decision / result ───────────────────────────────────────

/** Everything the gate needs, AFTER per-part validation. */
export interface ToolExecutionRequest {
  readonly requestId: string;
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  readonly envelope: ToolInputEnvelope;
  readonly requester: { readonly actorType: "agent" | "human"; readonly id: string };
  /** Capabilities the TASK has been scoped to (allocation output — not agent data). */
  readonly taskScope: readonly string[];
  /** Capabilities the AGENT has been granted (agent identity record — not self-asserted). */
  readonly agentCapabilities: readonly string[];
  /** Policy engine outcome for THIS execution ("allow" | "deny" | …). */
  readonly policyOutcome: string;
  readonly policyRuleId?: string;
  /** Isolation enforceability for the demanded profile, measured — never assumed. */
  readonly isolation: {
    readonly profileId: string;
    readonly canEnforce: boolean;
    readonly reason?: string;
  };
}

/** The executable authority plan; produced ONLY when every gate passed. */
export interface ToolExecutionPlan {
  readonly requestId: string;
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  /** Effective capabilities: requirement ∩ task scope ∩ agent capability. */
  readonly effectiveCapabilities: readonly string[];
  readonly isolationProfileId: string;
  readonly plannedAt: string; // ISO-8601
}

/** Closed status vocabulary — denials are never representable as runs. */
export const TOOL_EXECUTION_STATUSES = Object.freeze([
  "not_started",
  "started",
  "completed",
  "failed",
  "timed_out",
  "policy_denied",
  "isolation_denied",
  "validation_denied",
] as const);
export type ToolExecutionStatus = (typeof TOOL_EXECUTION_STATUSES)[number];

export interface ToolExecutionDecision {
  readonly requestId: string;
  readonly status: ToolExecutionStatus;
  /** Bounded human-readable reason for any non-run status. */
  readonly reason?: string;
  /** Present ONLY when status === "not_started" (authority fully established). */
  readonly plan?: ToolExecutionPlan;
}

/** Output is UNTRUSTED data — never a system or policy instruction. */
export interface ToolExecutionResult {
  readonly requestId: string;
  readonly status: "completed" | "failed" | "timed_out";
  readonly exitCode: number | null;
  readonly outputRef: string;
  readonly outputTrust: "untrusted_data";
  readonly truncated: boolean;
  readonly durationMs: number | null;
}

// ── evidence (requested ⊇ authorized ⊇ enforced ⊇ observed) ─────────────────

/**
 * The four distinguishable authority layers. Overclaiming in either direction
 * (claiming enforcement that was only requested; claiming observation beyond
 * enforcement) is a typed failure, never a warning.
 */
export interface ToolExecutionEvidence {
  readonly schemaVersion: ToolRuntimeContractSchemaVersion;
  readonly requestId: string;
  readonly toolId: ToolId;
  readonly version: ToolVersion;
  readonly manifestHash: string;
  readonly status: ToolExecutionStatus;
  readonly requested: readonly string[];
  readonly authorized: readonly string[];
  readonly enforced: readonly string[];
  readonly observed: readonly string[];
  readonly policyOutcome: string;
  readonly isolationProfileId: string;
  readonly evidenceHash: string; // sha256 of canonical body sans hash
  readonly recordedAt: string; // ISO-8601
}

// ── failure ──────────────────────────────────────────────────────────────────

export type ToolFailureCode =
  | "MANIFEST_INVALID"
  | "MANIFEST_HASH_MISMATCH"
  | "ENVELOPE_INVALID"
  | "ARGS_FORBIDDEN"
  | "ENV_NAME_FORBIDDEN"
  | "CWD_UNSAFE"
  | "ID_MISMATCH"
  | "LIFECYCLE_NOT_EXECUTABLE"
  | "CAPABILITY_NOT_REQUESTED"
  | "INTERSECTION_EMPTY"
  | "POLICY_DENIED"
  | "ISOLATION_UNENFORCEABLE"
  | "EVIDENCE_OVERCLAIM";
