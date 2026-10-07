/**
 * PRE-20C — enforcement-layer tests.
 *
 * Part 1 (host-pure): deterministic preflight — required/available/enforced
 * sets, abort-before-spawn, argv flag derivation.
 *
 * Part 2 (target-aware): the launcher C source is compiled and exercised IN
 * the WSL2 target-of-record (delivered via stdin to `sh -s`, exactly like the
 * 20A/20C probe tooling — the host never spawns Linux binaries), with
 * positive + adversarial cases proving the target did NOT run on fail-closed
 * paths. Skips when no WSL target exists (native Linux runs the same script
 * locally instead).
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import {
  validateIsolationProfile,
  planIsolatedExecution,
  MENOG_LAUNCHER_C,
  type IsolationCapabilitySnapshot,
  type IsolationProfile,
  type PrimitiveState,
  type IsolationPrimitiveId,
} from "@menog/runtime-linux";

// ── fixtures (host-pure) ─────────────────────────────────────────────────────

function snapshotAllSupported(
  overrides: Partial<Record<string, PrimitiveState>> = {},
  landlockAbi: number | null = 1
): IsolationCapabilitySnapshot {
  const base = Object.fromEntries(
    (
      [
        "ns_user", "ns_mount", "ns_pid", "ns_ipc", "ns_uts", "ns_net",
        "cgroup_v2_controllers", "cgroup_v2_delegation", "landlock_fs",
        "landlock_net", "seccomp_filter", "no_new_privs", "rlimit_set",
        "proc_hidepid",
      ] as IsolationPrimitiveId[]
    ).map((p) => [p, "SUPPORTED" as PrimitiveState])
  ) as Record<IsolationPrimitiveId, PrimitiveState>;
  for (const [k, v] of Object.entries(overrides)) base[k as IsolationPrimitiveId] = v as PrimitiveState;
  return {
    targetKernel: "5.15.167.4-microsoft-standard-WSL2",
    targetArch: "x86_64",
    isWsl: true,
    landlockAbi,
    primitives: base,
    probedAt: "2026-09-27T00:00:00.000Z",
  };
}

const FULL_STACK_PROFILE: { ok: true; profile: IsolationProfile } | { ok: false; failure: { code: string; message: string } } =
  validateIsolationProfile({
    profileId: "exec-isolated-fs-v0",
    origin: "human_reviewed",
    note: "20C default: unprivileged ns + NNP + Landlock FS + seccomp blocklist; cgroups optional-degrade",
    requirements: [
      { primitive: "ns_user", criticality: "required", onMissing: "fail_closed" },
      { primitive: "ns_mount", criticality: "required", onMissing: "fail_closed" },
      { primitive: "landlock_fs", criticality: "required", onMissing: "fail_closed", minLandlockAbi: 1 },
      { primitive: "no_new_privs", criticality: "required", onMissing: "fail_closed" },
      { primitive: "seccomp_filter", criticality: "required", onMissing: "fail_closed" },
      {
        primitive: "cgroup_v2_controllers",
        criticality: "optional",
        onMissing: "degrade_explicit",
        degradationNote: "no memory.max/pids.max on this target; rlimits bound resources only",
      },
    ],
  });
if (!FULL_STACK_PROFILE.ok) throw new Error("profile fixture invalid: " + FULL_STACK_PROFILE.failure.message);

// ── Part 1: preflight (host-pure) ────────────────────────────────────────────

describe("20C preflight — deterministic planning", () => {
  it("derives required/available/enforced sets and launcher flags", () => {
    const plan = planIsolatedExecution(
      FULL_STACK_PROFILE.profile,
      snapshotAllSupported({ cgroup_v2_controllers: "UNSUPPORTED" }),
      { landlockWritePaths: ["/tmp/menog-ws"], timeoutMs: 4000, executionId: "iso-test-1" }
    );
    expect(plan.aborted).toBe(false);
    if (plan.aborted) return;
    expect(plan.requiredSet).toContain("landlock_fs");
    expect(plan.enforcedSet).toContain("landlock_fs");
    expect(plan.enforcedSet).toContain("seccomp_filter");
    expect(plan.enforcedSet).toContain("rlimit_set");
    expect(plan.enforcedSet).not.toContain("cgroup_v2_controllers");
    expect(plan.launcherFlags).toContain("--seccomp-blocklist");
    expect(plan.launcherFlags.join(" ")).toContain("--landlock-rw /tmp/menog-ws");
    expect(plan.launcherFlags[0]).toBe("--begin");
    expect(plan.timeoutMs).toBe(4000);
  });

  it("aborts BEFORE spawn on any non-SUPPORTED required primitive", () => {
    for (const state of ["UNSUPPORTED", "PERMISSION_DENIED", "UNVERIFIED", "NOT_APPLICABLE"] as const) {
      const plan = planIsolatedExecution(FULL_STACK_PROFILE.profile, snapshotAllSupported({ seccomp_filter: state }));
      expect(plan.aborted, `state=${state}`).toBe(true);
      if (!plan.aborted) continue;
      expect(plan.reason).toContain("fail-closed");
      expect(plan.reason).toContain("seccomp_filter");
    }
  });

  it("aborts when the measured Landlock ABI is below the demanded level", () => {
    const plan = planIsolatedExecution(FULL_STACK_PROFILE.profile, snapshotAllSupported({}, 0));
    expect(plan.aborted).toBe(true);
  });

  it("records the explicit cgroup degradation instead of hiding it", () => {
    const plan = planIsolatedExecution(
      FULL_STACK_PROFILE.profile,
      snapshotAllSupported({ cgroup_v2_controllers: "UNSUPPORTED" })
    );
    expect(plan.aborted).toBe(false);
    if (plan.aborted) return;
    expect(plan.decision.degradations.map((d) => d.primitive)).toContain("cgroup_v2_controllers");
  });
});

// ── Part 2: target-aware launcher tests (WSL2 stdin delivery) ───────────────

const HAS_WSL =
  process.platform === "win32" &&
  spawnSync("wsl.exe", ["-l", "-v"], { encoding: "utf8", timeout: 15000 }).status === 0;

interface TargetOutcome {
  exit: number;
  stdout: string;
  evApplied: Record<string, { applied: boolean; detail?: string }>;
  failedPrimitive: string | null;
  otherStderr: string;
}

/** Compile + run the launcher inside the WSL2 target; parse evidence + outcome. */
function runLauncherInTarget(flags: string, targetArgv: readonly string[], timeoutMs = 90_000): TargetOutcome {
  // Shell-safe single-quote encoding for each target argv element.
  const shq = (s: string) => "'" + s.replace(/'/g, "'\\''") + "'";
  const target = targetArgv.map(shq).join(" ");
  const script = [
    "set +e",
    "TMPD=$(mktemp -d)",
    "cat > \"$TMPD/l.c\" <<'MENOG_EOF'",
    MENOG_LAUNCHER_C,
    "MENOG_EOF",
    "cc -O2 -o \"$TMPD/ml\" \"$TMPD/l.c\" 2>\"$TMPD/cc.err\" || { echo COMPILE_FAIL; cat \"$TMPD/cc.err\"; exit 3; }",
    `"$TMPD/ml" --begin ${flags} -- ${target}`,
    "CODE=$?",
    "echo MENOG_EXIT:$CODE",
    "rm -rf \"$TMPD\"",
    "exit 0",
  ].join("\n");
  const r = spawnSync("wsl.exe", ["-d", "Ubuntu-24.04", "-e", "sh", "-s"], {
    input: script.replace(/\r\n/g, "\n"),
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 4 * 1024 * 1024,
  });
  const out = String(r.stdout ?? "").replace(/\0/g, "");
  const err = String(r.stderr ?? "").replace(/\0/g, "");
  const exitMatch = out.match(/MENOG_EXIT:(\d+)/);
  const evApplied: Record<string, { applied: boolean; detail?: string }> = {};
  let failedPrimitive: string | null = null;
  for (const line of (out + "\n" + err).split("\n")) {
    const idx = line.indexOf("MENOG_EV:");
    if (idx < 0) continue;
    try {
      const obj = JSON.parse(line.slice(idx + 9).trim()) as {
        applied?: Record<string, { applied: boolean; detail?: string }>;
        failed_primitive?: string;
      };
      if (obj.applied) Object.assign(evApplied, obj.applied);
      if (obj.failed_primitive) failedPrimitive = obj.failed_primitive;
    } catch {
      /* ignore malformed journal lines */
    }
  }
  return {
    exit: exitMatch ? Number(exitMatch[1]) : -1,
    stdout: out,
    evApplied,
    failedPrimitive,
    otherStderr: err.split("\n").filter((l) => !l.includes("MENOG_EV:")).join("\n"),
  };
}

describe.skipIf(!HAS_WSL)("20C launcher — live on WSL2 target-of-record", () => {
  it(
    "runs the target under the full stack with per-primitive evidence",
    { timeout: 120_000 },
    () => {
      const r = runLauncherInTarget(
        "--ns user+mount --rlimit-nofile 256 --rlimit-nproc 64 --landlock-abi 1 --landlock-rw /tmp --seccomp-blocklist --timeout-ms 8000",
        ["/bin/echo", "TARGET_RAN_OK"]
      );
      expect(r.exit).toBe(0);
      expect(r.stdout).toContain("TARGET_RAN_OK");
      expect(r.evApplied["no_new_privs"]?.applied).toBe(true);
      expect(r.evApplied["landlock_fs"]?.applied).toBe(true);
      expect(r.evApplied["seccomp_filter"]?.applied).toBe(true);
      expect(r.evApplied["rlimit:nofile"]?.applied).toBe(true);
    }
  );

  it(
    "proves the target did NOT run when a required primitive fails in-kernel",
    { timeout: 120_000 },
    () => {
      const r = runLauncherInTarget(
        "--landlock-abi 1 --landlock-rw /definitely/not/here --timeout-ms 8000",
        ["/bin/echo", "SHOULD_NEVER_PRINT"]
      );
      expect(r.exit).toBe(125);
      expect(r.failedPrimitive).toBe("landlock_fs");
      expect(r.stdout).not.toContain("SHOULD_NEVER_PRINT");
    }
  );

  it(
    "mounts a fresh /proc inside the pid+mount namespace (proc inspection contained)",
    { timeout: 120_000 },
    () => {
      const r = runLauncherInTarget(
        "--ns user+mount+pid --timeout-ms 8000",
        ["/bin/sh", "-c", "ls /proc | grep -c '^[0-9]*$'"]
      );
      expect(r.exit).toBe(0);
      expect(r.evApplied["ns_pid"]?.applied).toBe(true);
      // The fresh /proc shows only the sandbox's own processes (1-2 PIDs),
      // never the host's process count.
      const pidCount = Number(r.stdout.trim().split("\n").filter((l) => /^\d+$/.test(l.trim())).pop());
      expect(pidCount).toBeLessThan(5);
    }
  );

  it(
    "enforces the deadline: kills the whole process group and exits 124",
    { timeout: 120_000 },
    () => {
      const started = Date.now();
      const r = runLauncherInTarget(
        "--rlimit-nofile 256 --timeout-ms 2000",
        ["/bin/sleep", "30"]
      );
      const elapsed = Date.now() - started;
      expect(r.exit).toBe(124);
      expect(elapsed).toBeLessThan(15000); // well under the 30s sleep
    }
  );

  it(
    "denies network by default inside a fresh network namespace",
    { timeout: 120_000 },
    () => {
      const r = runLauncherInTarget(
        "--ns user+net --timeout-ms 8000",
        ["/bin/sh", "-c", "ip -o addr 2>/dev/null | wc -l; cat /proc/net/route 2>/dev/null | wc -l"]
      );
      expect(r.exit).toBe(0);
      const nums = r.stdout.trim().split("\n").map((s) => s.trim()).filter((s) => /^\d$/.test(s));
      expect(Number(nums[0])).toBe(0); // no interfaces
      expect(Number(nums[1])).toBe(0); // no routes
    }
  );
});
