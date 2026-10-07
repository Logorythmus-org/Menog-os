/**
 * PRE-21C — the frozen tool-execution isolation floor (SANCTIONED isolation
 * layer).
 *
 * The single demand-set every governed tool run makes on the Phase-20
 * boundary: every primitive REQUIRED, every miss fail-closed — a tool run
 * can never downgrade what the 20A probes and 20B contracts established.
 * This lives inside the sanctioned layer (not in the tool gate) because
 * naming the primitives is a Phase-20 concern; the tool gate consumes only
 * the TYPED profile and the preflight plan, never the primitive names.
 *
 * The wrapper here is a NEUTRAL pass-through to the 20C preflight with the
 * canonical write path (the tool's workspace-scoped cwd): it adds nothing
 * beyond what planIsolatedExecution already enforces and cannot widen any
 * authority.
 */

import {
  ISOLATION_CONTRACT_SCHEMA_VERSION,
  type IsolationCapabilitySnapshot,
  type IsolationProfile,
  type IsolationRequirement,
} from "../types.js";
import { planIsolatedExecution, type ExecutionPlan } from "./preflight.js";

export const TOOL_BASELINE_PROFILE_ID = "tool-baseline-v0";

/**
 * The frozen tool-execution floor: every primitive a governed tool run
 * demands, all required, all fail-closed. Agent-proposed overrides may only
 * ADD restrictions (restrict-only composition, 20B).
 */
const TOOL_FLOOR_REQUIREMENTS: readonly IsolationRequirement[] = Object.freeze([
  { primitive: "ns_user", criticality: "required", onMissing: "fail_closed" },
  { primitive: "ns_mount", criticality: "required", onMissing: "fail_closed" },
  { primitive: "ns_pid", criticality: "required", onMissing: "fail_closed" },
  { primitive: "ns_ipc", criticality: "required", onMissing: "fail_closed" },
  { primitive: "ns_uts", criticality: "required", onMissing: "fail_closed" },
  { primitive: "ns_net", criticality: "required", onMissing: "fail_closed" },
  { primitive: "landlock_fs", criticality: "required", onMissing: "fail_closed", minLandlockAbi: 1 },
  { primitive: "seccomp_filter", criticality: "required", onMissing: "fail_closed" },
  { primitive: "no_new_privs", criticality: "required", onMissing: "fail_closed" },
]);

function toolBaselineProfile(): IsolationProfile {
  return {
    schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
    profileId: TOOL_BASELINE_PROFILE_ID,
    origin: "human_reviewed",
    requirements: TOOL_FLOOR_REQUIREMENTS,
  };
}

/**
 * The frozen tool floor, exposed read-only so gates and live tests can
 * derive the exact launcher configuration through the real preflight
 * (never a parallel copy).
 */
export function getToolBaselineProfile(): IsolationProfile {
  return toolBaselineProfile();
}

/**
 * Neutral pass-through preflight for a governed tool run: the floor profile
 * against the measured snapshot, with the canonical workspace-scoped cwd as
 * the only granted write path. Fail-closed exactly like planIsolatedExecution.
 */
export function planToolExecution(
  snapshot: IsolationCapabilitySnapshot,
  options: { readonly timeoutMs: number; readonly writePath: string; readonly executionId?: string }
): ExecutionPlan {
  return planIsolatedExecution(toolBaselineProfile(), snapshot, {
    timeoutMs: options.timeoutMs,
    landlockWritePaths: [options.writePath],
    executionId: options.executionId,
  });
}
