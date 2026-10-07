#!/usr/bin/env node
/**
 * 20C live smoke driver (probe-class tooling, run manually against the target):
 * compiles the launcher in-target and exercises positive + fail-closed paths.
 * Not part of the vitest suite (tests use in-repo fixtures instead).
 *
 * Usage: node scripts/iso-smoke.mjs
 */

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// Pull the launcher source out of the built TS module via a tiny inline import.
const src = readFileSync(
  join(here, "..", "packages", "runtime-linux", "src", "isolation", "enforce", "launcherSource.ts"),
  "utf8"
);
const m = src.match(/export const MENOG_LAUNCHER_C = String\.raw`([\s\S]*)`;\s*$/);
if (!m) {
  console.error("FATAL: could not extract MENOG_LAUNCHER_C");
  process.exit(1);
}
const launcherC = m[1].replace(/\r\n/g, "\n");

const SCRIPT = `
set -e
TMPD=$(mktemp -d)
cat > "$TMPD/launch.c" <<'CEOF'
${launcherC}
CEOF
cc -O2 -o "$TMPD/menog-launch" "$TMPD/launch.c" 2>"$TMPD/cc.err" || { echo SMOKE_COMPILE_FAIL; cat "$TMPD/cc.err"; exit 1; }
echo SMOKE_COMPILE_OK

echo "--- T1: positive run (nnp+rlimits, /bin/echo) ---"
T1CODE=0
T1OUT=$("$TMPD/menog-launch" --begin --ns user+mount --rlimit-nofile 256 --rlimit-nproc 64 --landlock-abi 1 --landlock-rw /tmp --seccomp-blocklist --timeout-ms 8000 -- /bin/echo TARGET_RAN_OK 2>"$TMPD/t1.err") || T1CODE=$?
echo "stdout=$T1OUT exit=$T1CODE"
grep -a MENOG_EV "$TMPD/t1.err" || true
grep -av MENOG_EV "$TMPD/t1.err" || true

echo "--- T2: fail-closed (landlock on nonexistent path) ---"
"$TMPD/menog-launch" --begin --landlock-abi 1 --landlock-rw /definitely/not/here --timeout-ms 3000 -- /bin/echo SHOULD_NOT_PRINT 2>&1 | grep MENOG_EV || true
echo "exit=$?"

echo "--- T3: proc remount fail-closed (pid+mount ns, unwritable /proc parent) ---"
"$TMPD/menog-launch" --begin --ns user+mount+pid --timeout-ms 3000 -- /bin/echo SHOULD_NOT_PRINT 2>&1 | grep MENOG_EV || true
echo "exit=$?"

echo "--- T4: timeout kill (sleep 30, deadline 2s) ---"
START=$(date +%s%N)
CODE=0
"$TMPD/menog-launch" --begin --rlimit-nofile 256 --timeout-ms 2000 -- /bin/sleep 30 >/dev/null 2>&1 || CODE=$?
END=$(date +%s%N)
echo "exit=$CODE elapsed_ms=$(( (END-START)/1000000 ))"

echo "--- T5: netns deny-by-default (ip inside net ns) ---"
"$TMPD/menog-launch" --begin --ns user+net --timeout-ms 4000 -- /bin/sh -c 'ip -o addr 2>/dev/null | wc -l; cat /proc/net/route 2>/dev/null | wc -l' 2>&1 | grep -v MENOG_EV || true
echo "exit=$?"

echo "--- BISECT: A ns+rlimit / B +landlock / C +seccomp ---"
B=0; "$TMPD/menog-launch" --begin --ns user+mount --rlimit-nofile 256 --rlimit-nproc 64 --timeout-ms 4000 -- /bin/echo A_OK >/dev/null 2>&1 || B=$?
echo "A(ns+rlimit)=$B"
B=0; "$TMPD/menog-launch" --begin --ns user+mount --rlimit-nofile 256 --landlock-abi 1 --landlock-rw /tmp --timeout-ms 4000 -- /bin/echo B_OK >/dev/null 2>&1 || B=$?
echo "B(+landlock)=$B"
B=0; "$TMPD/menog-launch" --begin --ns user+mount --rlimit-nofile 256 --seccomp-blocklist --timeout-ms 4000 -- /bin/echo C_OK >/dev/null 2>&1 || B=$?
echo "C(+seccomp)=$B"

rm -rf "$TMPD"
`;

const r = spawnSync("wsl.exe", ["-d", "Ubuntu-24.04", "-e", "sh", "-s"], {
  input: SCRIPT,
  encoding: "utf8",
  timeout: 120_000,
  maxBuffer: 4 * 1024 * 1024,
});
const out = (r.stdout ?? "").replace(/\0/g, "");
console.log(out);
if (r.stderr) console.error("stderr:", r.stderr.replace(/\0/g, "").slice(0, 300));
process.exit(r.status ?? 0);
