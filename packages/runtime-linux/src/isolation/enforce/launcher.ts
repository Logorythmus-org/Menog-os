/**
 * PRE-20C — orchestrator: compile-once unprivileged launcher + planned argv
 * execution. No shell-strings anywhere: the launcher source is delivered via
 * stdin to the compiler, and the target runs from an argv array.
 *
 * Failure semantics (fail-closed, test-proven):
 * - plan.aborted ⇒ NO spawn attempt at all (target did not run).
 * - launcher compile failure ⇒ fail-closed result, target never spawns.
 * - launcher setup failure ⇒ exit 125 + failed_primitive record; the target
 *   did NOT run (exec happens only after every applied step succeeded).
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MENOG_LAUNCHER_C } from "./launcherSource.js";
import { buildIsolationEvidence, type EvidenceInputRecord } from "../evaluate.js";
import type {
  IsolationCapabilitySnapshot,
  IsolationEvidence,
  IsolationProfile,
} from "../types.js";
import type { ExecutionPlan } from "./preflight.js";

export interface IsolatedRunResult {
  readonly ok: boolean;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  readonly targetRan: boolean;
  readonly evidence: IsolationEvidence | null;
  readonly failureReason?: string;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

export interface IsolatedRunInput {
  readonly plan: ExecutionPlan;
  readonly snapshot: IsolationCapabilitySnapshot;
  readonly profile: IsolationProfile;
  readonly targetArgv: readonly string[];
}

let cachedLauncherPath: string | null = null;
let cachedHostKey: string | null = null;

/**
 * Parse the MENOG_EV journal lines (emitted by the launcher on stderr).
 * Exported so the 21C tool transport reuses the exact same parsing as the
 * 20C orchestrator — one journal grammar, one parser.
 */
export function parseLauncherJournal(stderrText: string): {
  applied: Record<string, { applied: boolean; detail: string }>;
  failedPrimitive: string | null;
  failedWhy: string | null;
} {
  const applied: Record<string, { applied: boolean; detail: string }> = {};
  let failedPrimitive: string | null = null;
  let failedWhy: string | null = null;
  for (const line of stderrText.split("\n")) {
    const idx = line.indexOf("MENOG_EV:");
    if (idx < 0) continue;
    try {
      const obj = JSON.parse(line.slice(idx + "MENOG_EV:".length).trim()) as {
        applied?: Record<string, { applied: boolean; detail?: string; abi?: number }>;
        failed_primitive?: string;
        why?: string;
      };
      if (obj.applied) {
        for (const [k, v] of Object.entries(obj.applied)) {
          applied[k] = { applied: v.applied === true, detail: String(v.detail ?? "") };
        }
      }
      if (obj.failed_primitive) {
        failedPrimitive = obj.failed_primitive;
        failedWhy = obj.why ?? null;
      }
    } catch {
      /* ignore malformed journal lines */
    }
  }
  return { applied, failedPrimitive, failedWhy };
}

/** Compile-once per target; reused across executions in this process. */
export function getCompiledLauncherPath(
  snapshot: IsolationCapabilitySnapshot
): { ok: true; path: string } | { ok: false; reason: string } {
  const hostKey = snapshot.targetKernel + "|" + snapshot.targetArch + "|v" + MENOG_LAUNCHER_C.length;
  if (cachedLauncherPath && cachedHostKey === hostKey && existsSync(cachedLauncherPath)) {
    return { ok: true, path: cachedLauncherPath };
  }
  const dir = mkdtempSync(join(tmpdir(), "menog-launcher-"));
  const srcPath = join(dir, "menog-launch.c");
  const binPath = join(dir, "menog-launch");
  writeFileSync(srcPath, MENOG_LAUNCHER_C, "utf8");
  for (const cc of ["cc", "gcc", "clang"]) {
    const r = spawnSync(cc, ["-O2", "-o", binPath, srcPath], { encoding: "utf8", timeout: 60_000 });
    if (r.status === 0 && existsSync(binPath)) {
      cachedLauncherPath = binPath;
      cachedHostKey = hostKey;
      return { ok: true, path: binPath };
    }
  }
  rmSync(dir, { recursive: true, force: true });
  return { ok: false, reason: "launcher compile failed on target (cc/gcc/clang)" };
}

/**
 * Run the planned isolated execution (argv-only). The launcher supervisor
 * enforces the timeout over the whole process group (idempotent cleanup).
 */
export function runIsolated(input: IsolatedRunInput): IsolatedRunResult {
  const { plan, snapshot, targetArgv } = input;

  if (plan.aborted) {
    // Fail-closed proof path: reached only when preflight aborted; no spawn.
    return {
      ok: false,
      exitCode: null,
      signal: null,
      timedOut: false,
      targetRan: false,
      evidence: null,
      failureReason: plan.reason,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
    };
  }
  if (targetArgv.length === 0) {
    return {
      ok: false, exitCode: null, signal: null, timedOut: false, targetRan: false,
      evidence: null, failureReason: "empty target argv",
      stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
    };
  }

  const compiled = getCompiledLauncherPath(snapshot);
  if (!compiled.ok) {
    return {
      ok: false, exitCode: null, signal: null, timedOut: false, targetRan: false,
      evidence: null, failureReason: "fail-closed: " + compiled.reason,
      stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
    };
  }

  const r = spawnSync(compiled.path, [...plan.launcherFlags, "--", ...targetArgv], {
    encoding: "buffer",
    timeout: plan.timeoutMs + 5000, // supervisor enforces its own deadline first (exit 124)
    maxBuffer: 1024 * 1024,
  });

  // Parse the MENOG_EV journal lines from stderr (emitted by the launcher only).
  const stderrText = (r.stderr ?? Buffer.alloc(0)).toString("utf8");
  const { applied, failedPrimitive, failedWhy } = parseLauncherJournal(stderrText);

  const timedOut = r.signal === "SIGTERM" || r.status === 124;
  const targetRan = !timedOut && failedPrimitive === null && r.status !== 125;

  // Normalize to contract primitive ids; rlimit:* → rlimit_set.
  const records: EvidenceInputRecord = {};
  for (const [k, v] of Object.entries(applied)) {
    const key = k.startsWith("rlimit:") ? "rlimit_set" : k;
    records[key] = { applied: v.applied, detail: v.detail };
  }
  if (failedPrimitive) {
    records[failedPrimitive] = { applied: false, detail: "setup failed before exec: " + String(failedWhy) };
  }

  const ev = buildIsolationEvidence(plan.decision, records, plan.profileId, new Date().toISOString());

  const exitCode = typeof r.status === "number" ? r.status : null;
  return {
    ok: !timedOut && failedPrimitive === null && exitCode === 0,
    exitCode,
    signal: r.signal ?? null,
    timedOut,
    targetRan,
    evidence: ev.ok ? ev.evidence : null,
    failureReason: failedPrimitive
      ? "fail-closed in launcher: " + failedPrimitive + " — " + String(failedWhy)
      : ev.ok
        ? undefined
        : ev.failure.message,
    stdout: (r.stdout ?? Buffer.alloc(0)) as Buffer,
    stderr: (r.stderr ?? Buffer.alloc(0)) as Buffer,
  };
}


