/**
 * PRE-21C — the single governed tool execution junction.
 *
 * The ONLY path from a validated request to a running tool, composing
 * exclusively existing, individually frozen authorities in a fixed order:
 *
 *   envelope re-validation → registry/lifecycle → manifest identity +
 *   hash pinning → capability intersection → Policy → isolation projection
 *   (20D) → isolation preflight (20C) → launcher transport (21C) →
 *   bounded result → four-layer evidence (21A) → optional ledger append.
 *
 * Fail-closed invariants (each test-locked):
 * - every deny status maps to "the tool did not run" — the transport is
 *   never called on any deny;
 * - required isolation that cannot be enforced ⇒ not_started, never a
 *   degraded run;
 * - the launcher is the ONLY spawn surface; this module never spawns around
 *   it, no second policy path exists, and this module grants nothing;
 * - tool output is recorded as untrusted data with metadata + hash, never
 *   interpreted;
 * - the executable identity comes from the registry's explicit, frozen
 *   record — substitution is unrepresentable (21B) and no PATH inference
 *   exists.
 *
 * 19F-B2 compatibility: this file never names isolation primitives and
 * never touches the preflight directly — the floor profile and the plan
 * come from the sanctioned isolation layer as typed values only.
 */

import { createHash } from "node:crypto";
import {
  validateEnvelope,
  isExecutableLifecycle,
  gateToolExecution,
  buildToolEvidence,
} from "./evaluate.js";
import type {
  ToolExecutionRequest,
  ToolExecutionDecision,
  ToolExecutionEvidence,
  ToolExecutionResult,
} from "./types.js";
import type { ToolRegistryEntry } from "./registry.js";
import {
  type BoundExecutionEvidence,
  appendBoundEvidence,
  redactWorkspace,
} from "../isolation/binding.js";
import {
  runToolInLauncher,
  getCompiledLauncherPath,
  type LauncherToolSpec,
  type LauncherToolResult,
} from "../isolation/enforce/index.js";
import {
  TOOL_BASELINE_PROFILE_ID,
  getToolBaselineProfile,
  planToolExecution,
} from "../isolation/enforce/toolFloor.js";
import {
  ISOLATION_CONTRACT_SCHEMA_VERSION,
  type IsolationCapabilitySnapshot,
  type IsolationProfile,
} from "../isolation/types.js";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import { canonicalToolCwd } from "../isolation/enforce/toolTransport.js";
import { composeProfileBaseline } from "../isolation/evaluate.js";

// ── input shape ──────────────────────────────────────────────────────────────

export interface ToolExecutionInput {
  /** Untrusted tool request — the agent-supplied envelope is included. */
  readonly request: ToolExecutionRequest;
  /** Registry entry (from LocalToolRegistry.lookup — never agent data). */
  readonly entry: ToolRegistryEntry;
  /** Measured isolation capability snapshot (20A probe output). */
  readonly snapshot: IsolationCapabilitySnapshot;
  /** Workspace root (from allocation/Policy, never agent data). */
  readonly workspaceRoot: string;
  /** Policy outcome for THIS request — the caller ran the engine. */
  readonly policyOutcome: "allow" | "deny";
  readonly policyRuleId?: string;
  /** Trusted env value source (never agent data). */
  readonly envValueSource?: (name: string) => string | undefined;
  /** Optional ledger for bound evidence append. */
  readonly ledger?: AppendOnlyLedger;
  /** Ledger actor for the evidence append. */
  readonly ledgerActor?: { type: "runtime" | "agent" | "human"; id: string };
  /** Optional isolation profile to use instead of the frozen baseline. */
  readonly profileOverride?: IsolationProfile;
  /**
   * Runtime-infrastructure seam: an injected transport for hosts where the
   * launcher cannot be compiled in-process (e.g. Windows drivers of a remote
   * Linux target). NEVER agent-supplied — same trust tier as `snapshot`.
   * When absent, the real 21C transport drives the compiled Phase-20
   * launcher exactly as in every frozen path.
   */
  readonly transportOverride?: (spec: LauncherToolSpec) => LauncherToolResult;
}

// ── result shape ─────────────────────────────────────────────────────────────

export interface ToolExecutionOutcome {
  readonly decision: ToolExecutionDecision;
  /** Present only when the tool actually ran. */
  readonly result: ToolExecutionResult | null;
  readonly evidence: ToolExecutionEvidence;
  /** Bound evidence appended to the ledger, when a ledger was provided. */
  readonly ledgerEventId: string | null;
}

/**
 * Compose the effective profile: the frozen tool floor (owned by the
 * sanctioned isolation layer), optionally restricted by an agent-proposed
 * override. Anything else (a human-profile override, a relaxing proposal)
 * is refused. The registry entry must reference the tool baseline; an
 * unknown profile reference denies.
 */
function composeToolProfile(
  entryIsolationProfileId: string,
  override: IsolationProfile | undefined
): { ok: true; profile: IsolationProfile } | { ok: false; reason: string } {
  if (entryIsolationProfileId !== TOOL_BASELINE_PROFILE_ID) {
    return { ok: false, reason: "registry entry references isolation profile '" + entryIsolationProfileId + "' which is not the tool baseline" };
  }
  const baseline = getToolBaselineProfile();
  if (override === undefined) return { ok: true, profile: baseline };
  if (override.origin !== "agent_proposed") {
    return { ok: false, reason: "profileOverride must be agent_proposed (human baselines are frozen)" };
  }
  const composed = composeProfileBaseline(baseline, override);
  if (!composed.ok) return { ok: false, reason: composed.failure.message };
  return { ok: true, profile: composed.profile };
}

// ── helpers ──────────────────────────────────────────────────────────────────

function decisionFor(
  requestId: string,
  status: ToolExecutionDecision["status"],
  reason: string
): ToolExecutionDecision {
  return Object.freeze({ requestId, status, reason });
}

/**
 * Build the not-run outcome for any deny: the transport was never called,
 * no result exists, and the evidence claims nothing beyond the request.
 * (The evidence builder cannot fail for these inputs: every layer is a
 * subset of the request and the status is a valid denial status.)
 */
function notRun(input: ToolExecutionInput, decision: ToolExecutionDecision): ToolExecutionOutcome {
  const built = buildToolEvidence({
    requestId: input.request.requestId,
    toolId: input.entry.manifest.toolId,
    version: input.entry.manifest.version,
    manifestHash: input.entry.manifestHash,
    status: decision.status,
    requested: input.entry.manifest.capabilities.map((c) => c.capability),
    authorized: [],
    enforced: [],
    observed: [],
    policyOutcome: input.policyOutcome,
    isolationProfileId: input.entry.isolationProfileId,
    recordedAt: new Date().toISOString(),
  });
  if (!built.ok) {
    throw new Error("unreachable: deny evidence construction failed: " + built.message);
  }
  return Object.freeze({ decision, result: null, evidence: built.value, ledgerEventId: null });
}

// ── the junction ─────────────────────────────────────────────────────────────

/**
 * Execute a governed tool run. Fixed order, fail-closed at every step; the
 * launcher transport is reached ONLY after every authority has allowed.
 */
export function executeToolRun(input: ToolExecutionInput): ToolExecutionOutcome {
  const req = input.request;
  const entry = input.entry;

  // 1. Envelope re-validation (untrusted agent data; can only reject).
  const env = validateEnvelope(req.envelope);
  if (!env.ok) {
    return notRun(input, decisionFor(req.requestId, "validation_denied", env.message));
  }

  // 2. Lifecycle: registration never authorizes.
  if (!isExecutableLifecycle(entry.lifecycle)) {
    return notRun(input, decisionFor(req.requestId, "validation_denied", "tool lifecycle state '" + entry.lifecycle + "' is not executable"));
  }

  // 3. Manifest identity + capability intersection + Policy + isolation
  //    enforceability — through the 21A gate (the ONLY junction). The
  //    POLICY OUTCOME comes from the CALLER's engine (trusted), never from
  //    the untrusted request fields: an agent-supplied request cannot
  //    assert its own authorization.
  const effectiveRequest: ToolExecutionRequest = { ...req, policyOutcome: input.policyOutcome };
  const gate = gateToolExecution(effectiveRequest, entry.manifest, entry.lifecycle);
  if (gate.status !== "not_started" || gate.plan === undefined) {
    return notRun(input, gate);
  }

  // 4. Isolation profile: frozen tool floor, optionally restricted by an
  //    agent-proposed override (restrict-only).
  const composed = composeToolProfile(entry.isolationProfileId, input.profileOverride);
  if (!composed.ok) {
    return notRun(input, decisionFor(req.requestId, "validation_denied", composed.reason));
  }

  // 5. cwd: canonicalized against the authorized workspace root.
  const cwd = canonicalToolCwd(req.envelope.constraints.cwd, input.workspaceRoot);
  if (cwd === null) {
    return notRun(input, decisionFor(req.requestId, "validation_denied", "requested cwd escapes the authorized workspace"));
  }

  // 6. Bounds: registry-pinned limits bind; the envelope may only tighten.
  const timeoutMs = Math.min(req.envelope.constraints.timeoutMs ?? entry.limits.timeoutMs, entry.limits.timeoutMs);
  const maxOutputBytes = Math.min(
    req.envelope.constraints.maxOutputBytes ?? entry.limits.maxOutputBytes,
    entry.limits.maxOutputBytes
  );

  // 7. Isolation preflight through the sanctioned floor wrapper (fail-closed,
  //    abort-before-spawn; the cwd is the only granted write path).
  const plan = planToolExecution(input.snapshot, {
    timeoutMs,
    writePath: cwd,
    executionId: ("tool-" + req.requestId).slice(0, 60),
  });
  if (plan.aborted) {
    return notRun(input, decisionFor(req.requestId, "isolation_denied", plan.reason));
  }

  // 8. Executable identity: the registry's explicit absolute path only.
  //    Embedded identity resolution is out of 21C scope and refuses.
  if (entry.executable.pathStrategy !== "explicit_absolute_path" || entry.executable.path === undefined) {
    return notRun(
      input,
      decisionFor(req.requestId, "validation_denied", "executable identity must be an explicit absolute path (embedded resolution is out of 21C scope)")
    );
  }
  const executablePath: string = entry.executable.path;

  // 9. Bounded argv (registry limit binds the envelope).
  const argv = req.envelope.constraints.argv ?? [];
  if (argv.length > entry.limits.maxArgvEntries) {
    return notRun(input, decisionFor(req.requestId, "validation_denied", "argv exceeds the registry-pinned limit"));
  }

  // 10. Launcher: the ONLY spawn surface. Compile failure is fail-closed.
  //     A transport OVERRIDE (runtime infrastructure, never agent data)
  //     replaces the whole transport including launch mechanics; the host
  //     does not compile the launcher in that case.
  let launcherPath = "";
  if (input.transportOverride === undefined) {
    const launcher = getCompiledLauncherPath(input.snapshot);
    if (!launcher.ok) {
      return notRun(input, decisionFor(req.requestId, "isolation_denied", "fail-closed: " + launcher.reason));
    }
    launcherPath = launcher.path;
  }
  const spec: LauncherToolSpec = {
    launcherPath,
    launcherFlags: plan.launcherFlags,
    decision: plan.decision,
    profileId: composed.profile.profileId,
    timeoutMs: plan.timeoutMs,
    maxOutputBytes,
    cwd,
    targetArgv: [executablePath, ...argv],
    envAllowlist: req.envelope.constraints.envAllowlist ?? [],
    envValueSource: input.envValueSource ?? (() => undefined),
  };
  const run = input.transportOverride !== undefined ? input.transportOverride(spec) : runToolInLauncher(spec);

  // 11. In-kernel isolation setup failure ⇒ not_started (required isolation
  //     failure is NEVER a run).
  if (!run.targetRan) {
    const reason = run.failedPrimitive
      ? "isolation setup failed in launcher (" + run.failedPrimitive + "): " + (run.failureReason ?? "unknown")
      : "fail-closed: " + (run.failureReason ?? "transport failure");
    return notRun(input, decisionFor(req.requestId, "isolation_denied", reason));
  }

  // 12. Bounded result — output is UNTRUSTED data plus metadata, never read.
  const status: ToolExecutionResult["status"] =
    run.timedOut ? "timed_out" : run.ok ? "completed" : "failed";
  const outputHash = createHash("sha256").update(run.stdout).digest("hex");
  const result: ToolExecutionResult = Object.freeze({
    requestId: req.requestId,
    status,
    exitCode: run.exitCode,
    outputRef:
      "sha256:" + outputHash + ";bytes=" + run.stdout.length + (run.stdoutTruncated ? ";truncated=true" : ""),
    outputTrust: "untrusted_data",
    truncated: run.stdoutTruncated || run.stderrTruncated,
    durationMs: null,
  });

  // 13. Four-layer evidence (the builder enforces the ordering). The
  //     capability layers record CAPABILITIES (the run consumed every
  //     authorized capability under the enforced boundary); the per-primitive
  //     enforcement record is the ISOLATION evidence (run.isolationEvidence),
  //     bound into the ledger record — never mixed into this namespace.
  const built = buildToolEvidence({
    requestId: req.requestId,
    toolId: entry.manifest.toolId,
    version: entry.manifest.version,
    manifestHash: entry.manifestHash,
    status,
    requested: entry.manifest.capabilities.map((c) => c.capability),
    authorized: gate.plan.effectiveCapabilities,
    enforced: gate.plan.effectiveCapabilities.slice(),
    observed: gate.plan.effectiveCapabilities.slice(),
    policyOutcome: input.policyOutcome,
    isolationProfileId: composed.profile.profileId,
    recordedAt: new Date().toISOString(),
  });
  if (!built.ok) {
    // Anti-overclaim tripped on a real run: record it as a failed run with
    // no claims rather than fabricating evidence.
    return notRun(input, decisionFor(req.requestId, "validation_denied", "evidence construction refused: " + built.message));
  }

  // 14. Optional ledger append through the existing 20D bound-evidence spine.
  let ledgerEventId: string | null = null;
  if (input.ledger !== undefined && input.policyOutcome === "allow" && input.ledgerActor !== undefined) {
    const bound: BoundExecutionEvidence = {
      schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
      binding: {
        taskId: req.requestId.slice(0, 64),
        agentId: req.requester.id.slice(0, 64),
        executionId: plan.executionId.slice(0, 64),
        workspaceId: redactWorkspace(input.workspaceRoot),
      },
      policyRule: input.policyRuleId ?? null,
      outcome: status === "completed" ? ("completed" as const) : ("failed" as const),
      enforcedPrimitives: plan.enforcedSet.slice(),
      evidenceHash: built.value.evidenceHash,
      failedPrimitive: null,
      exitCode: run.exitCode,
    };
    const appended = appendBoundEvidence(input.ledger, bound, input.ledgerActor as import("@menog/core").Actor);
    if (appended.ok) ledgerEventId = appended.eventId ?? null;
  }

  return Object.freeze({ decision: gate, result, evidence: built.value, ledgerEventId });
}
