#!/usr/bin/env node
/**
 * PRE-20A orchestrator — runs scripts/probe-linux.sh IN the Linux target and
 * assembles docs/release/PHASE20_LINUX_CAPABILITY_MATRIX.json.
 *
 * NON-ENFORCING / PASSIVE / LOCAL-ONLY (Prompt 20A):
 * - The probe script is copied to the target via stdin (`sh -s`) — no files
 *   are left on the target beyond its own /tmp usage (self-cleaned).
 * - Every SUPPORTED verdict is backed by an executable, non-destructive probe
 *   (20A hard rule) — never symbols, packages, docs, or versions alone.
 * - argv-array subprocesses only; zero shell-strings in this orchestrator.
 *
 * Target selection:
 *   - Windows host  → wsl.exe -d <distro> -e sh -s   (WSL2 target-of-record)
 *   - Linux host    → sh <script>                    (native target)
 *
 * Usage: node scripts/probe-linux.mjs [--out <path>] [--wsl-distro <name>]
 */

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");

const args = process.argv.slice(2);
const opt = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i >= 0 ? (args[i + 1] ?? dflt) : dflt;
};
const OUT_PATH = opt("--out", join(REPO_ROOT, "docs", "release", "PHASE20_LINUX_CAPABILITY_MATRIX.json"));
const WSL_DISTRO = opt("--wsl-distro", "Ubuntu-24.04");

const hash = (s) => createHash("sha256").update(s).digest("hex");

// Read the probe script; normalize CRLF→LF (Windows checkout) — sh requires LF.
const scriptPath = join(__dirname, "probe-linux.sh");
const script = readFileSync(scriptPath, "utf8").replace(/\r\n/g, "\n");

// ── run the probe in-target ──────────────────────────────────────────────────

function runProbeInTarget() {
  if (process.platform === "win32") {
    const r = spawnSync("wsl.exe", ["-d", WSL_DISTRO, "-e", "sh", "-s"], {
      input: script,
      encoding: "utf8",
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (r.error) throw new Error("wsl.exe failed: " + String(r.error.message ?? r.error));
    // wsl.exe may emit UTF-16 NUL padding on some channels — strip defensively.
    const clean = (s) => String(s ?? "").replace(/\0/g, "");
    return { stdout: clean(r.stdout), stderr: clean(r.stderr), exit: r.status };
  }
  const r = spawnSync("sh", ["-s"], { input: script, encoding: "utf8", timeout: 120_000 });
  if (r.error) throw new Error("sh failed: " + String(r.error.message ?? r.error));
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", exit: r.status };
}

const { stdout, stderr, exit } = runProbeInTarget();

// ── parse CONTEXT / PROBE lines ──────────────────────────────────────────────

let target = null;
const probes = [];
for (const line of stdout.split("\n")) {
  const tab = line.indexOf("\t");
  if (tab < 0) continue;
  const kind = line.slice(0, tab);
  const payload = line.slice(tab + 1).trim();
  if (!payload.startsWith("{")) continue;
  try {
    if (kind === "CONTEXT") target = JSON.parse(payload);
    else if (kind === "PROBE") probes.push(JSON.parse(payload));
  } catch (e) {
    console.error("parse warning:", kind, String(e).slice(0, 120));
  }
}

if (!target || probes.length === 0) {
  console.error("FATAL: no probe output parsed. stderr:", stderr.slice(0, 400));
  process.exit(1);
}

// ── threat mapping (primitive ids per threat) ────────────────────────────────

const threatMap = {
  filesystem_symlink_escape: ["landlock_abi", "ns_mount", "ns_user_unprivileged", "fs_mount_helpers"],
  process_escape: ["ns_pid", "no_new_privs", "euid_capabilities", "seccomp_mode"],
  resource_exhaustion: ["cgroup_v2_unified", "cgroup_v2_delegation", "rlimits"],
  network_egress: ["ns_net"],
  env_leakage: ["ns_mount", "landlock_abi", "euid_capabilities"],
  executable_abuse: ["seccomp_mode", "no_new_privs", "ns_mount", "landlock_abi"],
  proc_inspection: ["ns_pid", "proc_visibility"],
  privilege_escalation: ["no_new_privs", "euid_capabilities", "ns_user_unprivileged"],
};

// ── assemble + emit matrix ───────────────────────────────────────────────────

const matrix = {
  schema: "menog-phase20-linux-capability-matrix/v1",
  gate: "20A",
  mode: "PROBE-FIRST / NO SANDBOX IMPLEMENTATION",
  generated: new Date().toISOString(),
  target,
  hard_rule:
    "SUPPORTED is never inferred from symbols, package presence, docs, or version alone; every SUPPORTED above carries an executable non-destructive probe result",
  invariants_honored: [
    "non-enforcing: probe confines only its own short-lived children; nothing on the host is restricted",
    "fail-closed demonstrated: namespace probes self-terminate by construction; no process survives",
    "least privilege: nothing granted; argv-array subprocesses only; zero shell-strings in the orchestrator",
    "observable evidence: this matrix is the evidence record",
    "LOCAL-ONLY: no remote operation of any kind",
  ],
  probe_count: probes.length,
  state_counts: probes.reduce((acc, p) => ((acc[p.state] = (acc[p.state] ?? 0) + 1), acc), {}),
  probes,
  threat_map: threatMap,
  probe_script_sha256: hash(script),
  orchestrator_notes: {
    delivery: "probe script piped to `sh -s` via stdin; nothing persisted on the target",
    host_platform: process.platform,
    wsl_distro: process.platform === "win32" ? WSL_DISTRO : null,
  },
};

const json = JSON.stringify(matrix, null, 2) + "\n";
writeFileSync(OUT_PATH, json, "utf8");
console.log("matrix written:", OUT_PATH);
console.log(
  "states:",
  Object.entries(matrix.state_counts).map(([k, v]) => `${k}=${v}`).join(" "),
  `(${probes.length} primitives; probe exit=${exit})`
);
if (stderr.trim()) console.error("target stderr:", stderr.slice(0, 300));
