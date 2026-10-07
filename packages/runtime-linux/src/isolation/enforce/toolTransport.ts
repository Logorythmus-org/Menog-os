/**
 * PRE-21C — launcher transport for tool execution (SANCTIONED isolation
 * layer; thin — no policy, no registry, no authority of its own).
 *
 * Why this file lives inside isolation/enforce/: the 19F-B2 freeze guard
 * scans production sources outside the sanctioned layer for isolation
 * vocabulary; assembly of the LAUNCHER invocation is inherently a Phase-20
 * mechanism. It contains NO policy logic and GRANTS nothing: it receives a
 * fully-gated spec from the tool gate (execute.ts) and either drives the
 * Phase-20 launcher with it or reports a transport failure.
 *
 * Security properties (21C):
 * - argv-only end to end: launcher argv + target argv arrays; no shell
 *   string exists anywhere in the path.
 * - cwd: the requested cwd is canonicalized against the workspace root by
 *   the tool gate and applied as the spawn cwd (and target process cwd) —
 *   it can never escape the authorized workspace.
 * - env: minimal allowlist, never wholesale inheritance — the target env is
 *   { PATH, HOME, LANG, TZ } defaults + allowlisted NAMES only. Values are
 *   never carried in tool requests; secrets require an existing authorized
 *   path (unchanged by this gate).
 * - cleanup: spawnSync timeout plus the launcher supervisor's group-scoped
 *   deadline (proven in 20E A5/A13).
 * - output: capped at spec.maxOutputBytes (hard truncation with marker);
 *   oversized output is DATA loss, not a failure of containment.
 */

import { spawnSync } from "node:child_process";
import { resolve, sep } from "node:path";
import { buildIsolationEvidence, type EvidenceInputRecord } from "../evaluate.js";
import { parseLauncherJournal } from "./launcher.js";
import type { IsolationDecision, IsolationEvidence } from "../types.js";

export interface LauncherToolSpec {
  /** Absolute path of the COMPILED LAUNCHER (from the 20C orchestrator). */
  readonly launcherPath: string;
  /** Exact flags from the isolation preflight (unchanged). */
  readonly launcherFlags: readonly string[];
  /** The fail-closed isolation decision this run was planned under. */
  readonly decision: IsolationDecision;
  readonly profileId: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  /** Workspace-scoped cwd (already canonicalized by the tool gate). */
  readonly cwd: string;
  /** Exact target argv: [executablePath, ...args] — never a shell string. */
  readonly targetArgv: readonly string[];
  /** Env NAMES the tool may receive beyond the default four. */
  readonly envAllowlist: readonly string[];
  /** Trusted value source for allowlisted names; never agent data. */
  readonly envValueSource: (name: string) => string | undefined;
}

export interface LauncherToolResult {
  readonly ok: boolean;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  readonly targetRan: boolean;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  /** Contract id of the primitive whose setup failed, when known. */
  readonly failedPrimitive: string | null;
  readonly failureReason?: string;
  /** Per-primitive isolation evidence assembled from the launcher journal. */
  readonly isolationEvidence: IsolationEvidence | null;
  /** Profile id under which isolation evidence was assembled. */
  readonly isolationProfileId: string | null;
}

const TRUNCATION_MARKER = Buffer.from("\n[menog: output truncated at contract bound]\n");

/** Exported for contract tests of the truncation semantics. */
export function capOutput(buf: Buffer, maxBytes: number): { out: Buffer; truncated: boolean } {
  if (buf.length <= maxBytes) return { out: buf, truncated: false };
  const head = buf.subarray(0, Math.max(0, maxBytes - TRUNCATION_MARKER.length));
  return { out: Buffer.concat([head, TRUNCATION_MARKER]), truncated: true };
}

/**
 * Build the minimal env for the target: fixed safe defaults plus the
 * allowlisted NAMES resolved through the trusted value source. Unknown names
 * yield undefined and are simply absent — never fabricated.
 */
export function buildToolEnv(
  allowlist: readonly string[],
  valueSource: (name: string) => string | undefined
): Record<string, string> {
  const env: Record<string, string> = {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/tmp",
    LANG: "C.UTF-8",
    TZ: "UTC",
  };
  for (const name of allowlist) {
    const v = valueSource(name);
    if (v !== undefined) env[name] = v;
  }
  return env;
}

/** Canonicalize a requested cwd against the workspace root; null = unsafe. */
export function canonicalToolCwd(requested: string | undefined, workspaceRoot: string): string | null {
  const resolvedRoot = resolve(workspaceRoot);
  const resolvedCwd = resolve(resolvedRoot, requested && requested.length > 0 ? requested : ".");
  if (resolvedCwd === resolvedRoot || resolvedCwd.startsWith(resolvedRoot + sep)) {
    return resolvedCwd;
  }
  return null;
}

/**
 * Drive the Phase-20 launcher for a fully-gated tool execution. This is the
 * ONLY path a tool run may take.
 */
export function runToolInLauncher(spec: LauncherToolSpec): LauncherToolResult {
  const env = buildToolEnv(spec.envAllowlist, spec.envValueSource);

  const r = spawnSync(spec.launcherPath, [...spec.launcherFlags, "--", ...spec.targetArgv], {
    cwd: spec.cwd,
    env,
    encoding: "buffer",
    timeout: spec.timeoutMs + 5_000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });

  if (r.error) {
    return {
      ok: false,
      exitCode: null,
      signal: null,
      timedOut: false,
      targetRan: false,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false,
      stderrTruncated: false,
      failedPrimitive: null,
      failureReason: "transport failure: " + r.error.message,
      isolationEvidence: null,
      isolationProfileId: null,
    };
  }

  const stderrText = (r.stderr ?? Buffer.alloc(0)).toString("utf8");
  const { applied, failedPrimitive, failedWhy } = parseLauncherJournal(stderrText);

  const timedOut = r.signal === "SIGTERM" || r.status === 124;
  // The launcher exits 125 WITHOUT exec'ing the target on any setup failure.
  const targetRan = !timedOut && r.status !== 125 && r.status !== null;

  // Normalize to contract primitive ids; rlimit:* → rlimit_set.
  const records: EvidenceInputRecord = {};
  for (const [k, v] of Object.entries(applied)) {
    const key = k.startsWith("rlimit:") ? "rlimit_set" : k;
    records[key] = { applied: v.applied, detail: v.detail };
  }
  if (failedPrimitive) {
    records[failedPrimitive] = { applied: false, detail: "setup failed before exec: " + String(failedWhy) };
  }

  const ev = buildIsolationEvidence(
    spec.decision,
    records,
    spec.profileId,
    new Date().toISOString()
  );

  const so = capOutput((r.stdout ?? Buffer.alloc(0)) as Buffer, spec.maxOutputBytes);
  const se = capOutput((r.stderr ?? Buffer.alloc(0)) as Buffer, spec.maxOutputBytes);

  return {
    ok: !timedOut && targetRan && r.status === 0,
    exitCode: typeof r.status === "number" ? r.status : null,
    signal: r.signal ?? null,
    timedOut,
    targetRan,
    stdout: so.out,
    stderr: se.out,
    stdoutTruncated: so.truncated,
    stderrTruncated: se.truncated,
    failedPrimitive,
    failureReason: failedPrimitive
      ? "fail-closed in launcher: " + failedPrimitive + " — " + String(failedWhy)
      : undefined,
    isolationEvidence: ev.ok ? ev.evidence : null,
    isolationProfileId: spec.profileId,
  };
}
