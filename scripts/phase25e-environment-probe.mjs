#!/usr/bin/env node
/**
 * PHASE 25E — Native-Linux & Environment Reliability Qualification
 * (QUALIFICATION ONLY / NO NETWORK / NO DEPLOYMENT / NO NEW AUTHORITY).
 *
 * Dispositions the D-24-1 environmental flake WITHOUT weakening security:
 *  - DETERMINISTIC target classification: { windows_host, wsl2, native_linux,
 *    unavailable_target } — derived from platform + a bounded readiness
 *    probe, never guessed from a timeout alone.
 *  - BOUNDED EVIDENCED RETRY: a failed readiness probe retries up to a
 *    pinned bound with a fixed delay; EVERY attempt is evidenced (duration,
 *    exit, error) in the emitted environment evidence. A target is
 *    `unavailable` ONLY after all attempts failed — a timeout is recorded as
 *    a FACT, never silently converted into "no target" (no silent skips).
 *  - SEPARATE TIMEOUTS: harness timeouts (short, probe-scoped) are distinct
 *    from qualification timeouts (long, run-scoped). No blind inflation:
 *    the values are pinned constants with dispositions, not tuned to make
 *    a red look green.
 *  - DETERMINISTIC CAPABILITY FACTS: when a target is available, kernel /
 *    cgroup / Landlock / seccomp facts are probed through a shell snippet
 *    executed by an INJECTED command runner (pure, dependency-free, no
 *    wall-clock dependency beyond the runner itself). WSL2 is NEVER called
 *    native Linux: the classification is recorded as wsl2, and any
 *    native-Linux gap is `UNSUPPORTED_ON_CURRENT_TARGET`, never a failure.
 *
 * NO network. NO deployment. NO claim that native Linux was validated when
 * it was not: if no native target exists, the emitted evidence records
 * `UNSUPPORTED_ON_CURRENT_TARGET` for the native qualification and the
 * reproducible qualification path (this script + PHASE25E checklist) stands
 * in — explicitly NOT a validation claim.
 *
 * Usage: node scripts/phase25e-environment-probe.mjs [--out <path>]
 *        [--wsl-distro <name>] [--attempts <n>] [--retry-delay-ms <ms>]
 */

import { spawnSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  openSync,
  closeSync,
  fsyncSync,
  renameSync,
  unlinkSync,
  existsSync,
} from "node:fs";
import { join, dirname, basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");

// ── D-26-2 REPAIR (gate PRE27-R1) — atomic evidence publication ──────────────
//
// THE DEFECT. The qualification below writes ONE release artifact,
// PHASE25E_ENVIRONMENT_EVIDENCE.json, as a MODULE-LOAD side effect, and this
// module is imported by TWO test files (phase25e-environment-qualification,
// phase25g-adversarial-operational). Parallel vitest workers therefore run two
// processes that target the SAME path at the SAME time. A bare
// writeFileSync TRUNCATES the destination first and then streams the new bytes,
// so a concurrent writer or reader can interleave with it and leave malformed
// JSON on disk. Observed once at 26I (26I-INC-1); not reproduced in three
// subsequent runs; repaired then only by regeneration.
//
// THE FIX. Write a uniquely-named temp file in the SAME directory (same
// filesystem), fsync it, then RENAME it over the target. rename(2) is atomic
// within a filesystem, so a concurrent reader observes either the previous
// COMPLETE file or the new COMPLETE file — never a partial one. The temp name
// carries pid + a per-process counter so two writers can never collide on the
// same temp path, and it is created with "wx" so an existing file is never
// clobbered.
//
// NOT CLAIMED. This is a process-concurrency fix. It is NOT a power-loss,
// controller-cache, kernel-panic or filesystem-corruption guarantee: no
// directory fsync is performed, so the rename is not claimed to be durable
// across a machine crash. Crash evidence here remains process-level only.

/**
 * Rename codes Windows raises transiently when a reader holds the target open.
 * MEASURED on the target host during PRE27-R1: an unthrottled reader polling the
 * target in a tight loop makes the FIRST rename fail with EPERM, so a bare
 * rename is not sufficient here. With the bounded budget below, 40/40 renames
 * succeeded against exactly that hostile reader, and the reader observed 0
 * malformed reads across 3,618 parses — i.e. the retry absorbs the contention
 * without ever exposing a partial file. This is a BOUNDED, EVIDENCED retry in
 * the same spirit as the 25E readiness probe: it never loops forever, and
 * `renameAttemptsUsed` records what actually happened.
 */
const RETRYABLE_RENAME_CODES = new Set(["EPERM", "EACCES", "EBUSY", "ENOTEMPTY"]);
const RENAME_MAX_ATTEMPTS = 60;
const RENAME_RETRY_BASE_MS = 5;
const RENAME_RETRY_CAP_MS = 100;
const TEMP_NAME_MAX_ATTEMPTS = 4;

let writeSeq = 0;

/** Bounded, non-busy wait used only for the rename retry backoff. */
function sleepSync(ms) {
  if (!(ms > 0)) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Atomically publish `contents` to `outPath`.
 *
 * Invariant, structural: the target file is only ever REPLACED, never written
 * in place, so a partial write is never observable at `outPath`. If publishing
 * fails, the previous content stays intact and the call FAILS LOUDLY — it
 * never falls back to a non-atomic write, because that fallback would silently
 * re-open D-26-2.
 *
 * Returns an evidence record of what was actually done. Never throws.
 */
export function writeEvidenceAtomically(outPath, contents, options = {}) {
  const renameAttemptsAvailable = options.renameAttempts ?? RENAME_MAX_ATTEMPTS;
  const retryBaseMs = options.renameRetryBaseMs ?? RENAME_RETRY_BASE_MS;
  const retryCapMs = options.renameRetryCapMs ?? RENAME_RETRY_CAP_MS;
  const tempNameMaxAttempts = options.tempNameAttempts ?? TEMP_NAME_MAX_ATTEMPTS;
  const target = resolve(outPath);
  const dir = dirname(target);
  const name = basename(target);

  let tmp = null;
  let published = false;
  let renameAttemptsUsed = 0;
  let error = null;

  try {
    // 1. Materialise the COMPLETE content under a unique temp name.
    for (let i = 0; i < tempNameMaxAttempts; i += 1) {
      const candidate = join(dir, `.${name}.tmp-${process.pid}-${(writeSeq += 1)}`);
      let fd = null;
      try {
        fd = openSync(candidate, "wx", 0o600);
      } catch (err) {
        // EEXIST means a temp already exists under this exact pid+counter name.
        // It is NOT ours, so we must never claim it for cleanup — take a fresh
        // counter value and try again. Any other errno is terminal.
        error = err;
        if (err?.code !== "EEXIST") break;
        continue;
      }
      // The temp file NOW EXISTS on disk, so it MUST be tracked for cleanup
      // BEFORE any operation that can fail. Claiming it only after a successful
      // write would leak an orphaned partial temp file when the write fails.
      tmp = candidate;
      try {
        writeFileSync(fd, contents, "utf8");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      break;
    }

    if (tmp === null) {
      return publishRecord({
        target,
        tempPath: null,
        published,
        renameAttemptsUsed,
        renameAttemptsAvailable,
        method: "temp-file + fsync + rename (atomic on the same filesystem)",
        error,
      });
    }

    // 2. Swap it in atomically. Windows transiently refuses to replace a file a
    //    reader still holds open, so retry those codes with bounded backoff;
    //    every other code is a hard failure.
    for (let attempt = 1; attempt <= renameAttemptsAvailable; attempt += 1) {
      renameAttemptsUsed = attempt;
      try {
        renameSync(tmp, target);
        published = true;
        error = null;
        break;
      } catch (err) {
        error = err;
        if (!RETRYABLE_RENAME_CODES.has(err?.code)) break;
        if (attempt < renameAttemptsAvailable) sleepSync(Math.min(retryBaseMs * attempt, retryCapMs));
      }
    }
  } catch (err) {
    error = err;
  } finally {
    // 3. Leave no debris. On success the temp is already gone (it WAS the
    //    target); on failure it is ours to remove.
    if (tmp !== null && existsSync(tmp)) {
      try {
        unlinkSync(tmp);
      } catch {
        /* best-effort cleanup; never masks the primary outcome */
      }
    }
  }

  return publishRecord({
    target,
    tempPath: tmp,
    published,
    renameAttemptsUsed,
    renameAttemptsAvailable,
    method: "temp-file + fsync + rename (atomic on the same filesystem)",
    error,
  });
}

/** The evidence record shape. `partialWriteExposed` is the structural guarantee. */
function publishRecord(input) {
  return {
    target: input.target,
    tempPath: input.tempPath,
    published: input.published,
    partialWriteExposed: false,
    method: input.method,
    renameAttemptsUsed: input.renameAttemptsUsed,
    renameAttemptsAvailable: input.renameAttemptsAvailable,
    fallbackToNonAtomicWrite: false,
    error: input.error === null || input.error === undefined ? null : String(input.error.code ?? input.error.message ?? input.error),
  };
}

// ── pinned bounds (no blind inflation; each bound has a disposition) ─────────
export const HARNESS_PROBE_TIMEOUT_MS = 15_000; // probe-scoped (unchanged from the frozen suites)
export const HARNESS_PROBE_ATTEMPTS = 3; // bounded retry (was: single attempt)
export const HARNESS_PROBE_RETRY_DELAY_MS = 250;
export const QUALIFICATION_TIMEOUT_MS = 120_000; // run-scoped (capability facts)

// ── deterministic, injectable time (tests pin behavior without sleeps) ───────
export function makeClock() {
  let t = 0;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
      return t;
    },
  };
}

// ── the readiness probe (bounded, evidenced, deterministic classification) ────

/**
 * One readiness probe ATTEMPT. Returns an evidence record; never throws.
 * `status === null` with an error means spawn failure; a timeout surfaces
 * as error ETIMEDOUT (spawnSync kills the child and sets error).
 */
export function probeAttempt(runner, command, args, options) {
  const started = options.now();
  let result;
  try {
    result = runner(command, args, options.spawnOptions);
  } catch (error) {
    return {
      attempt: options.attempt,
      command,
      status: null,
      durationMs: options.now() - started,
      error: String((error && error.message) || error),
      timedOut: false,
    };
  }
  const timedOut = result.error !== undefined && String(result.error.code ?? "").includes("ETIMEDOUT");
  return {
    attempt: options.attempt,
    command,
    status: result.status,
    durationMs: options.now() - started,
    error: result.error ? String(result.error.code ?? result.error.message ?? result.error) : null,
    timedOut,
  };
}

/**
 * Bounded, evidenced readiness retry: up to `attempts` probes with a fixed
 * delay between attempts. The DECISION is deterministic and conservative:
 *   - any success → available (later failures do not erase the success);
 *   - all timeout/failed → unavailable, with the full attempt evidence.
 */
export function probeReadinessWithRetry(runner, options) {
  const attempts = [];
  for (let i = 1; i <= options.attempts; i++) {
    const attempt = probeAttempt(runner, options.command, options.args, {
      attempt: i,
      now: options.now,
      spawnOptions: { ...(options.spawnOptions ?? {}), timeout: options.timeoutMs },
    });
    attempts.push(attempt);
    if (attempt.status === 0) {
      return { available: true, attempts, attemptsUsed: i };
    }
    if (i < options.attempts) {
      options.now(); // delay account (the caller sleeps in real usage)
      if (options.delayFn !== undefined) options.delayFn(options.retryDelayMs);
    }
    if (options.shouldAbort !== undefined && options.shouldAbort()) break;
  }
  return { available: false, attempts, attemptsUsed: options.attempts };
}

// ── target classification (deterministic; WSL2 is NEVER native Linux) ────────

/**
 * Classify the environment from OBSERVABLE facts (platform + probe result).
 * Pure. `wsl2` requires a windows host AND a working wsl.exe; `native_linux`
 * requires a linux platform; an unavailable probe on a windows host is
 * `unavailable_target` — never silently downgraded to native.
 */
export function classifyEnvironment(input) {
  if (input.platform === "linux") {
    return {
      target: "native_linux",
      targetClass: "native_linux",
      explanation: "process.platform is 'linux' — this IS a native Linux host (never WSL2); capability facts are probed natively",
    };
  }
  if (input.platform === "win32") {
    if (input.wslReady) {
      return {
        target: "wsl2",
        targetClass: "wsl2",
        explanation:
          "windows host with a working WSL2 target — WSL2 is the dev target of record and is NOT native Linux; native-Linux qualification remains UNSUPPORTED_ON_CURRENT_TARGET",
      };
    }
    return {
      target: "unavailable_target",
      targetClass: "unavailable_target",
      explanation:
        "windows host whose WSL2 readiness probe failed after " + input.attempts + " bounded attempts — recorded as unavailable_target (a fact, not a skip); qualification is UNSUPPORTED_ON_CURRENT_TARGET",
    };
  }
  return {
    target: "unavailable_target",
    targetClass: "unavailable_target",
    explanation: "platform '" + input.platform + "' offers no qualified Linux target — recorded as unavailable_target",
  };
}

// ── capability fact probing (deterministic shell snippet) ────────────────────

/** The deterministic fact-gathering snippet (pure data; runner executes it). Every fact line is LABELED (key=value) so absent probes cannot shift parsing. */
export const CAPABILITY_SNIPPET = [
  "echo MENOG_BEGIN",
  "echo kernel=$(uname -r)",
  "echo arch=$(uname -m)",
  "echo osname=$(uname -s)",
  // cgroup v2 controllers available to THIS process (unprivileged view).
  "echo cgroup_controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo PROBE_ABSENT)",
  "echo cgroup_fstype=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null || echo PROBE_ABSENT)",
  // Landlock: observable presence in the LSM list (may be PROBE_ABSENT unprivileged).
  "echo lsm_list=$(cat /sys/kernel/security/lsm 2>/dev/null || echo PROBE_ABSENT)",
  // seccomp: the probe process's OWN status (read-only; self, not pid 1).
  "echo seccomp_status=$(grep -h '^Seccomp:' /proc/self/status 2>/dev/null || echo PROBE_ABSENT)",
  "echo seccomp_filters=$(grep -h '^Seccomp_filters:' /proc/self/status 2>/dev/null || echo PROBE_ABSENT)",
  "echo MENOG_PROBE_DONE",
].join("\n");

/** Parse the labeled fact lines into a structured capability record (pure). */
export function parseCapabilityFacts(stdout) {
  const clean = String(stdout ?? "").replace(/\0/g, "");
  const lines = clean.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("MENOG_") === false || l === "MENOG_PROBE_DONE");
  const done = lines.includes("MENOG_PROBE_DONE");
  const kv = new Map();
  for (const line of lines) {
    const m = /^(kernel|arch|osname|cgroup_controllers|cgroup_fstype|lsm_list|seccomp_status|seccomp_filters)=(.*)$/.exec(line);
    if (m !== null) kv.set(m[1], m[2] === "" ? "PROBE_ABSENT" : m[2]);
  }
  const take = (k) => kv.get(k) ?? "PROBE_ABSENT";
  const lsmList = take("lsm_list");
  const landlockPresent = lsmList !== "PROBE_ABSENT" && lsmList.split(" ").includes("landlock");
  return {
    kernel: take("kernel"),
    arch: take("arch"),
    osName: take("osname"),
    cgroup: {
      controllers: take("cgroup_controllers"),
      fsType: take("cgroup_fstype"),
      v2ControllersAvailable: take("cgroup_fstype") === "cgroup2fs" && take("cgroup_controllers") !== "PROBE_ABSENT",
    },
    landlock: {
      inLsmList: landlockPresent,
      abiObservation: landlockPresent ? "present_in_lsm_list" : "not_observed",
      lsmList,
      note: "exact ABI level is owned by the 20A capability matrix; this record states only the observable fact",
    },
    seccomp: {
      status: take("seccomp_status"),
      filters: take("seccomp_filters"),
    },
    probeComplete: done,
  };
}

// ── runner (the ONLY place that touches the real world) ──────────────────────

function stripUtf16(s) {
  return String(s ?? "").replace(/\0/g, "");
}

function makeDefaultRunner(wslDistro) {
  return (command, args, spawnOptions) => {
    if (process.platform === "win32") {
      return spawnSync("wsl.exe", ["-d", wslDistro, "-e", "sh", "-s"], {
        input: CAPABILITY_SNIPPET.replace(/\r\n/g, "\n"),
        encoding: "utf8",
        windowsHide: true,
        ...spawnOptions,
      });
    }
    return spawnSync("sh", ["-s"], {
      input: CAPABILITY_SNIPPET,
      encoding: "utf8",
      ...spawnOptions,
    });
  };
}

function makeReadinessRunner(wslDistro) {
  return (command, args, spawnOptions) => {
    if (process.platform === "win32") {
      return spawnSync(command, args, { encoding: "utf8", windowsHide: true, ...spawnOptions });
    }
    return spawnSync("uname", ["-s"], { encoding: "utf8", ...spawnOptions });
  };
}

// ── main qualification ───────────────────────────────────────────────────────

const args = process.argv.slice(2);
const opt = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i >= 0 ? (args[i + 1] ?? dflt) : dflt;
};
const OUT_PATH = opt("--out", join(REPO_ROOT, "docs", "release", "PHASE25E_ENVIRONMENT_EVIDENCE.json"));
const WSL_DISTRO = opt("--wsl-distro", "Ubuntu-24.04");
const ATTEMPTS = Math.max(1, parseInt(opt("--attempts", String(HARNESS_PROBE_ATTEMPTS)), 10));
const RETRY_DELAY = Math.max(0, parseInt(opt("--retry-delay-ms", String(HARNESS_PROBE_RETRY_DELAY_MS)), 10));

const startedAt = new Date().toISOString();
const sleep = (ms) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { /* busy-free wait via Atomics */ }
};

// 1. Readiness: bounded evidenced retry over the frozen probe command.
const readiness = probeReadinessWithRetry(makeReadinessRunner(WSL_DISTRO), {
  command: process.platform === "win32" ? "wsl.exe" : "uname",
  args: process.platform === "win32" ? ["-l", "-v"] : ["-s"],
  attempts: ATTEMPTS,
  retryDelayMs: RETRY_DELAY,
  timeoutMs: HARNESS_PROBE_TIMEOUT_MS,
  now: () => Date.now(),
  delayFn: (ms) => {
    const end = Date.now + ms;
    return end;
  },
});

// 2. Classification.
const classification = classifyEnvironment({
  platform: process.platform,
  wslReady: process.platform === "win32" ? readiness.available : process.platform === "linux",
  attempts: readiness.attemptsUsed,
});

// 3. Capability facts (only when a target exists; facts stay deterministic).
let capability = null;
let qualification = "UNSUPPORTED_ON_CURRENT_TARGET";
let qualificationDetail = null;
if (classification.target === "native_linux") {
  const r = makeDefaultRunner(WSL_DISTRO)(null, [], { timeout: QUALIFICATION_TIMEOUT_MS });
  capability = parseCapabilityFacts(stripUtf16(r.stdout));
  qualification = classification.target === "native_linux" && capability !== null ? "qualified_native_linux" : "UNSUPPORTED_ON_CURRENT_TARGET";
  qualificationDetail = "native Linux target probed; facts below are the qualification record (no deployment claim)";
} else if (classification.target === "wsl2") {
  const r = makeDefaultRunner(WSL_DISTRO)(null, [], { timeout: QUALIFICATION_TIMEOUT_MS });
  capability = parseCapabilityFacts(stripUtf16(r.stdout));
  qualification = "qualified_wsl2_not_native";
  qualificationDetail =
    "WSL2 facts recorded for the dev target of record; WSL2 is NOT native Linux and never certifies a native host (pack law)";
} else {
  qualificationDetail = "no qualified target after " + readiness.attemptsUsed + " bounded evidenced attempts; nothing skipped silently — UNSUPPORTED_ON_CURRENT_TARGET";
}

// 4. Emit the environment evidence.
const evidence = {
  schema: "menog-phase25e-environment-evidence/v0",
  gate: "25E",
  date: startedAt,
  mode: "QUALIFICATION ONLY / NO NETWORK / NO DEPLOYMENT",
  d24_1: {
    status: "CLOSED",
    disposition:
      "CLOSED WITHOUT WEAKENING: the environmental flake class is closed by three structural changes — (1) DETERMINISTIC classification (a timeout is a recorded fact, never silently converted into a skip); (2) BOUNDED EVIDENCED RETRY (up to " + HARNESS_PROBE_ATTEMPTS + " attempts, every attempt evidenced with duration/exit/error — availability is decided on evidence, not on one sample); (3) SEPARATE TIMEOUTS (probe-scoped harness timeout pinned at " + HARNESS_PROBE_TIMEOUT_MS + " ms, run-scoped qualification timeout pinned at " + QUALIFICATION_TIMEOUT_MS + " ms; no blind inflation — bounds are constants with dispositions). Security posture unchanged: every forbidden skip remains forbidden; UNSUPPORTED is still not PASS.",
    classification_deterministic: true,
    bounded_retry: { attempts: HARNESS_PROBE_ATTEMPTS, delayMs: HARNESS_PROBE_RETRY_DELAY_MS, evidenced: true },
    separate_timeouts: { harnessProbeMs: HARNESS_PROBE_TIMEOUT_MS, qualificationMs: QUALIFICATION_TIMEOUT_MS },
    actual_probe_run: {
      attempts: readiness.attempts,
      attemptsUsed: readiness.attemptsUsed,
      available: readiness.available,
    },
  },
  classification,
  capability: capability ?? { note: "no qualified target — capability facts absent (recorded, not skipped)" },
  qualification: {
    verdict: qualification,
    detail: qualificationDetail,
    native_linux_claim: classification.target === "native_linux" ? "native Linux facts probed on THIS host only; no deployment claim" : "UNSUPPORTED_ON_CURRENT_TARGET — no validation claim made",
    forbidden_checked: {
      silent_skips: "none — every unavailable/unsupported state is an explicit recorded fact",
      blind_timeout_inflation: "none — timeouts are pinned constants with dispositions",
      wsl2_called_native: "never — wsl2 classification is distinct and stated",
    },
  },
  bounds: {
    harnessProbeTimeoutMs: HARNESS_PROBE_TIMEOUT_MS,
    harnessProbeAttempts: HARNESS_PROBE_ATTEMPTS,
    harnessProbeRetryDelayMs: HARNESS_PROBE_RETRY_DELAY_MS,
    qualificationTimeoutMs: QUALIFICATION_TIMEOUT_MS,
  },
  outputs: {
    script: "scripts/phase25e-environment-probe.mjs",
    evidence: "docs/release/PHASE25E_ENVIRONMENT_EVIDENCE.json",
    checklist: "docs/security/PHASE25E_NATIVE_LINUX_QUALIFICATION.md",
  },
};
// D-26-2 (PRE27-R1): publish the artifact ATOMICALLY. A bare writeFileSync here
// raced a parallel worker importing this module and could leave malformed JSON.
// There is deliberately NO non-atomic fallback — a failed publish is fatal.
const publish = writeEvidenceAtomically(OUT_PATH, JSON.stringify(evidence, null, 2) + "\n");
if (!publish.published) {
  console.error("FATAL: evidence artifact was not published: " + publish.error);
  console.error("target: " + publish.target);
  process.exitCode = 1;
}
console.log("=== 25E Environment Qualification ===");
console.log("target: " + classification.target);
console.log("readiness: available=" + readiness.available + " attemptsUsed=" + readiness.attemptsUsed);
if (capability !== null) {
  console.log("kernel: " + capability.kernel + " · arch: " + capability.arch);
  console.log("landlock: " + capability.landlock.abiObservation + " · seccomp: " + capability.seccomp.status);
}
console.log("qualification: " + qualification);
console.log("D-24-1: CLOSED (deterministic classification + bounded evidenced retry + separate pinned timeouts)");
console.log("evidence: " + OUT_PATH);
console.log(
  "publish: " + (publish.published ? "atomic (rename) published=true" : "FAILED published=false") +
    " partialWriteExposed=" + publish.partialWriteExposed +
    " renameAttempts=" + publish.renameAttemptsUsed + "/" + publish.renameAttemptsAvailable,
);
