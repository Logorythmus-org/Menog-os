/**
 * PRE-20C — deterministic preflight: (profile, snapshot) → ExecutionPlan.
 *
 * Pure and side-effect-free. Computes the required/available/enforced sets
 * and the exact launcher argv BEFORE anything is spawned. A required
 * primitive that is not measured SUPPORTED (or whose ABI is insufficient)
 * aborts here — before any process exists (fail-closed, abort-before-spawn).
 * The plan is the ONLY input the orchestrator acts on; it never decides at
 * spawn time.
 */

import type {
  IsolationCapabilitySnapshot,
  IsolationDecision,
  IsolationProfile,
  IsolationPrimitiveId,
} from "../types.js";
import { evaluateIsolation as evaluate } from "../evaluate.js";

export interface IsolationExecutionPlan {
  readonly executionId: string; // bounded, per-execution, deterministic-ish
  readonly profileId: string;
  readonly decision: IsolationDecision;
  readonly requiredSet: readonly IsolationPrimitiveId[];
  readonly availableSet: readonly IsolationPrimitiveId[];
  readonly enforcedSet: readonly IsolationPrimitiveId[];
  /** Exact launcher flags derived from the plan (argv-only contract). */
  readonly launcherFlags: readonly string[];
  /** Granted Landlock write paths (minimum-filesystem-paths rule). */
  readonly landlockWritePaths: readonly string[];
  readonly timeoutMs: number;
  readonly aborted: false;
}

export interface IsolationAbortPlan {
  readonly executionId: string;
  readonly profileId: string;
  readonly decision: IsolationDecision;
  readonly aborted: true;
  readonly reason: string;
}

export type ExecutionPlan = IsolationExecutionPlan | IsolationAbortPlan;

export interface PlanOptions {
  readonly landlockWritePaths?: readonly string[];
  readonly timeoutMs?: number;
  readonly executionId?: string;
}

const MAX_TIMEOUT_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 10_000;

function boundedExecutionId(): string {
  // Bounded per-execution identifier: monotonic counter + time, both bounded.
  const t = Date.now().toString(36);
  const c = (preflightCounter++ % 1296).toString(36).padStart(2, "0");
  return "iso-" + t + "-" + c;
}
let preflightCounter = 0;

/**
 * Build the execution plan. Deterministic: identical inputs (plus identical
 * options) yield identical launcherFlags and sets.
 */
export function planIsolatedExecution(
  profile: IsolationProfile,
  snapshot: IsolationCapabilitySnapshot,
  options: PlanOptions = {}
): ExecutionPlan {
  const decision = evaluate(profile, snapshot);
  const executionId = options.executionId ?? boundedExecutionId();

  if (!decision.canProceed) {
    return {
      executionId,
      profileId: profile.profileId,
      decision,
      aborted: true,
      reason:
        "fail-closed preflight: missing required primitives [" +
        decision.missingRequired.join(", ") +
        "] — no process will be spawned",
    };
  }

  const requiredSet = profile.requirements.filter((r) => r.criticality === "required").map((r) => r.primitive);
  const availableSet = profile.requirements.filter((r) => decision.satisfied.includes(r.primitive)).map((r) => r.primitive);

  // enforcedSet = the primitives the launcher will actually apply this run.
  const enforcedSet: IsolationPrimitiveId[] = [];
  const flags: string[] = ["--begin"];
  const ns: string[] = [];
  if (decision.satisfied.includes("ns_user")) { ns.push("user"); enforcedSet.push("ns_user"); }
  if (decision.satisfied.includes("ns_mount")) { ns.push("mount"); enforcedSet.push("ns_mount"); }
  if (decision.satisfied.includes("ns_pid")) { ns.push("pid"); enforcedSet.push("ns_pid"); }
  if (decision.satisfied.includes("ns_ipc")) { ns.push("ipc"); enforcedSet.push("ns_ipc"); }
  if (decision.satisfied.includes("ns_uts")) { ns.push("uts"); enforcedSet.push("ns_uts"); }
  if (decision.satisfied.includes("ns_net")) { ns.push("net"); enforcedSet.push("ns_net"); }
  if (ns.length > 0) flags.push("--ns", ns.join("+"));

  // rlimits: proven settable by the launcher itself; bounded defaults.
  enforcedSet.push("rlimit_set");
  flags.push("--rlimit-nofile", "256", "--rlimit-nproc", "64");

  // Landlock FS: required by profile ⇒ snapshot ABI is proven ≥ minAbi by the
  // decision; the launcher re-proves in-kernel.
  const landlockReq = profile.requirements.find((r) => r.primitive === "landlock_fs");
  if (landlockReq && decision.satisfied.includes("landlock_fs")) {
    enforcedSet.push("landlock_fs");
    flags.push("--landlock-abi", String(snapshot.landlockAbi ?? 1));
    for (const p of options.landlockWritePaths ?? []) {
      flags.push("--landlock-rw", p);
    }
  }

  // seccomp: reviewed fixed blocklist.
  if (decision.satisfied.includes("seccomp_filter")) {
    enforcedSet.push("seccomp_filter");
    flags.push("--seccomp-blocklist");
  }

  // no_new_privs is always applied by the launcher (required by Landlock and
  // seccomp anyway); include it when the profile demands it explicitly.
  if (decision.satisfied.includes("no_new_privs")) {
    enforcedSet.push("no_new_privs");
  }

  const timeoutMs = Math.min(Math.max(1, options.timeoutMs ?? DEFAULT_TIMEOUT_MS), MAX_TIMEOUT_MS);
  flags.push("--timeout-ms", String(timeoutMs));

  return {
    executionId,
    profileId: profile.profileId,
    decision,
    requiredSet,
    availableSet,
    enforcedSet,
    launcherFlags: flags,
    landlockWritePaths: options.landlockWritePaths ?? [],
    timeoutMs,
    aborted: false,
  };
}

export { evaluate as evaluateIsolation };
