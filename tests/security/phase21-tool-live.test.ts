import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import {
  MENOG_LAUNCHER_C,
  getToolBaselineProfile,
  planIsolatedExecution,
  type IsolationCapabilitySnapshot,
} from "@menog/runtime-linux";

/**
 * PRE-21C — LIVE gated-tool-run tests on the WSL2 target-of-record.
 *
 * The REAL compiled Phase-20 launcher is driven with the exact spec shape
 * the 21C junction emits: frozen tool floor → REAL preflight → launcher
 * flags → argv-only target → minimal fixed env (the buildToolEnv defaults,
 * applied via `env -i`) → workspace cwd (the transport's spawn-cwd behavior
 * reproduced with `cd`, since the frozen launcher has no --cwd flag).
 *
 * Proven live:
 * - positive: bounded run, exit 0, MENOG_EV journal, exact argv + cwd + env;
 * - timeout: group-scoped deadline kill (exit 124), zero orphan children;
 * - containment: a target denied by Landlock write-confinement cannot place
 *   a file outside the granted path (the runtime-denial path, distinct from
 *   the 20E in-kernel setup-failure 125 already proven there).
 */

const HAS_WSL =
  process.platform === "win32" &&
  spawnSync("wsl.exe", ["-l", "-v"], { encoding: "utf8", timeout: 15_000 }).status === 0;

function runInWsl(script: string): { code: number; out: string } {
  const r = spawnSync("wsl.exe", ["-d", "Ubuntu-24.04", "-e", "sh", "-s"], {
    input: script.replace(/\r\n/g, "\n"),
    encoding: "utf8",
    timeout: 300_000,
    windowsHide: true,
  });
  const out = ((r.stdout ?? "") as string) + ((r.stderr ?? "") as string);
  return { code: r.status ?? -1, out };
}

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-09-27T00:00:00.000Z",
  primitives: {
    ns_user: "SUPPORTED",
    ns_mount: "SUPPORTED",
    ns_pid: "SUPPORTED",
    ns_ipc: "SUPPORTED",
    ns_uts: "SUPPORTED",
    ns_net: "SUPPORTED",
    cgroup_v2_controllers: "UNSUPPORTED",
    cgroup_v2_delegation: "UNSUPPORTED",
    landlock_fs: "SUPPORTED",
    landlock_net: "UNSUPPORTED",
    seccomp_filter: "SUPPORTED",
    no_new_privs: "SUPPORTED",
    rlimit_set: "SUPPORTED",
    proc_hidepid: "UNSUPPORTED",
  },
};

/** REAL preflight over the frozen tool floor → the exact launcher flags. */
function junctionFlags(landlockWritePaths: string[], timeoutMs: number): readonly string[] {
  const plan = planIsolatedExecution(getToolBaselineProfile(), SNAPSHOT, {
    timeoutMs,
    landlockWritePaths,
  });
  if (plan.aborted) throw new Error("preflight aborted on target: " + plan.reason);
  return plan.launcherFlags;
}

function makeScript(caseBody: string, flags: readonly string[]): string {
  // One single-quoted assignment: `FLAGS='--begin --ns …'`. Wrapping each
  // flag separately would make the shell execute the second word as a
  // command. No flag value contains a single quote or space.
  const flagsSh = "'" + flags.join(" ").replace(/'/g, "'\\''") + "'";
  return [
    "set -e",
    "WS=$(mktemp -d)",
    "TMPD=$(mktemp -d)",
    "cat > \"$TMPD/l.c\" <<'MENOG_EOF'",
    MENOG_LAUNCHER_C,
    "MENOG_EOF",
    "cc -O2 -o \"$TMPD/ml\" \"$TMPD/l.c\" || { echo COMPILE_FAIL; exit 3; }",
    "LAUNCHER=\"$TMPD/ml\"",
    "FLAGS=" + flagsSh,
    "CODE=0",
    caseBody,
    "echo MENOG_EXIT:$CODE",
    "rm -rf \"$WS\" \"$TMPD\"",
  ].join("\n");
}

describe("21C live — real launcher with the junction spec (WSL2)", () => {
  it.skipIf(!HAS_WSL)(
    "positive: bounded run, exit 0, journal, exact argv/cwd/env as gated",
    { timeout: 280_000 },
    () => {
      // Concrete write path (the junction passes a canonical workspace dir).
      const flags = junctionFlags(["/tmp/menog-21c-pos"], 30_000);
      const body = [
        "mkdir -p /tmp/menog-21c-pos",
        'cd /tmp/menog-21c-pos',
        // `env -i` + fixed four = the transport's buildToolEnv defaults.
        'env -i PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" HOME="/tmp" LANG="C.UTF-8" TZ="UTC" "$LAUNCHER" $FLAGS -- /bin/sh -c \'echo TOOL_RAN_OK; pwd; env | sort | tr "\\n" ";"\' >out.txt 2>err.txt || CODE=$?',
        'echo "OUT:$(cat out.txt)"',
      ].join("\n");
      const { code, out } = runInWsl(makeScript(body, flags));
      expect(code, out.slice(-2000)).toBe(0);
      expect(out).not.toContain("COMPILE_FAIL");
      expect(out).toContain("TOOL_RAN_OK");
      // cwd = the workspace dir the junction would spawn into.
      expect(out).toContain("/tmp/menog-21c-pos");
      // Minimal env: exactly the four safe defaults, nothing inherited.
      expect(out).toContain("HOME=/tmp");
      expect(out).toContain("LANG=C.UTF-8");
      expect(out).not.toContain("WSLENV");
      expect(out).toContain("MENOG_EXIT:0");
    }
  );

  it.skipIf(!HAS_WSL)(
    "timeout: deadline kill exit 124, zero orphan children (group cleanup)",
    { timeout: 280_000 },
    () => {
      const flags = junctionFlags(["/tmp/menog-21c-to"], 4_000);
      const body = [
        "mkdir -p /tmp/menog-21c-to",
        "cd /tmp/menog-21c-to",
        '"$LAUNCHER" $FLAGS -- /bin/sh -c \'sleep 6 & sleep 300 & wait\' >out.txt 2>err.txt || CODE=$?',
        'LEFT=$(pgrep -f "sleep 300" | wc -l)',
        'echo "ORPHANS:$LEFT"',
      ].join("\n");
      const { code, out } = runInWsl(makeScript(body, flags));
      expect(code, out.slice(-2000)).toBe(0);
      expect(out).toContain("MENOG_EXIT:124");
      expect(out).toContain("ORPHANS:0");
    }
  );

  it.skipIf(!HAS_WSL)(
    "containment: Landlock denies a write outside the granted path; nothing escapes",
    { timeout: 280_000 },
    () => {
      const flags = junctionFlags(["/tmp/menog-21c-ct/granted"], 30_000);
      const body = [
        "mkdir -p /tmp/menog-21c-ct/granted",
        "rm -f /tmp/escape-probe.txt",
        "cd /tmp/menog-21c-ct/granted",
        // The target tries to write outside the grant; inside works.
        '"$LAUNCHER" $FLAGS -- /bin/sh -c \'echo inside > inside-ok.txt; echo escaped > /tmp/escape-probe.txt\' >out.txt 2>err.txt || CODE=$?',
        'if [ -f /tmp/escape-probe.txt ]; then echo ESCAPED; else echo CONTAINED; fi',
        'if [ -f inside-ok.txt ]; then echo INSIDE_OK; fi',
      ].join("\n");
      const { code, out } = runInWsl(makeScript(body, flags));
      expect(code, out.slice(-2000)).toBe(0);
      expect(out).toContain("CONTAINED");
      expect(out).toContain("INSIDE_OK");
      expect(out).not.toContain("ESCAPED");
    }
  );
});
