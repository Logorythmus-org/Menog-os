#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKSPACE_ROOT = path.resolve(__dirname, "..");

const EXPECTED_NODE_MIN = [22, 0, 0];
const EXPECTED_PNPM_MIN = [10, 0, 0];

const EXPECTED_WORKSPACE_PACKAGES = [
  "apps/cli",
  "packages/shared",
  "packages/verbs",
  "packages/core",
  "packages/event-ledger",
  "packages/policy",
  "packages/runtime-linux",
  "packages/commit-engine",
];

const summary = {
  schema: "menog-local-setup/v1",
  timestamp: new Date().toISOString(),
  workspaceRoot: WORKSPACE_ROOT,
  checks: {},
  actions: {},
  exitCode: 0,
};

function semGte(actual, min) {
  for (let i = 0; i < 3; i++) {
    const a = actual[i] ?? 0;
    const m = min[i] ?? 0;
    if (a > m) return true;
    if (a < m) return false;
  }
  return true;
}

function semStr(triplet) {
  return `${triplet[0]}.${triplet[1]}.${triplet[2]}`;
}

function parseVersion(raw) {
  const m = String(raw).trim().match(/v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

function run(cmd, args, opts = {}) {
  const useShell = opts.shell ?? (process.platform === "win32" && ["pnpm", "npm", "yarn", "git"].includes(cmd));
  const result = spawnSync(cmd, args, {
    cwd: WORKSPACE_ROOT,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 20 * 60 * 1000,
    shell: useShell,
    ...opts,
  });
  if (result.error) {
    result.stdout = (result.stdout || "") + `\nSPAWN_ERROR: ${result.error.message}`;
    result.status = result.status ?? 127;
  }
  return result;
}

function fail(msg, label) {
  summary.checks[label] = { status: "FAIL", detail: msg };
  summary.exitCode = Math.max(summary.exitCode, 1);
  process.stderr.write(`[FAIL] ${label}: ${msg}\n`);
}

function pass(label, detail) {
  summary.checks[label] = { status: "PASS", detail };
  process.stdout.write(`[PASS] ${label}${detail ? ` — ${detail}` : ""}\n`);
}

console.log("=== Menog OS — Local Setup ===\n");

// Check 1: Node version
(function checkNode() {
  const label = "node-version";
  const raw = process.versions.node;
  const parsed = parseVersion(raw);
  if (!parsed) {
    fail(`Could not parse Node version: ${raw}`, label);
    return;
  }
  if (!semGte(parsed, EXPECTED_NODE_MIN)) {
    fail(`Node ${raw} < required ${semStr(EXPECTED_NODE_MIN)}`, label);
    return;
  }
  pass(label, `v${raw}`);
})();

// Check 2: pnpm version
(function checkPnpm() {
  const label = "pnpm-version";
  const result = run("pnpm", ["--version"]);
  if (result.status !== 0) {
    fail(`pnpm not found or invocable (exit ${result.status}): ${result.stderr || result.stdout}`, label);
    return;
  }
  const parsed = parseVersion(result.stdout);
  if (!parsed) {
    fail(`Could not parse pnpm version: ${result.stdout.trim()}`, label);
    return;
  }
  if (!semGte(parsed, EXPECTED_PNPM_MIN)) {
    fail(`pnpm ${result.stdout.trim()} < required ${semStr(EXPECTED_PNPM_MIN)}`, label);
    return;
  }
  pass(label, `v${result.stdout.trim()}`);
})();

// Check 3: Workspace root markers
(function checkWorkspaceRoot() {
  const label = "workspace-root";
  const markers = ["package.json", "pnpm-workspace.yaml"];
  const missing = markers.filter((m) => !fs.existsSync(path.join(WORKSPACE_ROOT, m)));
  if (missing.length > 0) {
    fail(`Missing workspace markers: ${missing.join(", ")}`, label);
    return;
  }
  pass(label, `root=${WORKSPACE_ROOT}`);
})();

// Check 4: Lockfile present
(function checkLockfile() {
  const label = "lockfile-present";
  const lockfile = path.join(WORKSPACE_ROOT, "pnpm-lock.yaml");
  if (!fs.existsSync(lockfile)) {
    fail("pnpm-lock.yaml missing — cannot use --frozen-lockfile", label);
    return;
  }
  try {
    const size = fs.statSync(lockfile).size;
    if (size < 100) {
      fail(`pnpm-lock.yaml suspiciously small (${size} bytes)`, label);
      return;
    }
    pass(label, `${size} bytes`);
  } catch (e) {
    fail(`Could not stat lockfile: ${e.message}`, label);
  }
})();

// Check 5: Expected workspace package dirs
(function checkWorkspacePackages() {
  const label = "workspace-packages";
  const missing = EXPECTED_WORKSPACE_PACKAGES.filter(
    (p) => !fs.existsSync(path.join(WORKSPACE_ROOT, p, "package.json"))
  );
  if (missing.length > 0) {
    fail(`Missing expected packages: ${missing.join(", ")}`, label);
    return;
  }
  pass(label, `${EXPECTED_WORKSPACE_PACKAGES.length} packages present`);
})();

// Check 6: packageManager field present (non-blocking check)
(function checkPackageManager() {
  const label = "package-manager-field";
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(WORKSPACE_ROOT, "package.json"), "utf-8"));
    if (!pkg.packageManager) {
      summary.checks[label] = { status: "WARN", detail: "packageManager field missing in root package.json" };
      process.stdout.write(`[WARN] ${label}: packageManager field missing\n`);
      return;
    }
    const parsed = parseVersion(pkg.packageManager.replace(/^pnpm@/, ""));
    pass(label, `declared=${pkg.packageManager}${parsed ? ` (${semStr(parsed)})` : ""}`);
  } catch (e) {
    fail(`Could not read root package.json: ${e.message}`, label);
  }
})();

// Exit early for hard failures before install attempt
if (summary.exitCode !== 0) {
  process.stderr.write("\nSetup aborted — toolchain/environment checks failed.\n");
  console.log("\n=== Setup Summary (FAILED) ===");
  console.log(JSON.stringify(summary, null, 2));
  process.exit(summary.exitCode);
}

// Action A: Install dependencies with frozen lockfile
(function installDeps() {
  const label = "pnpm-install-frozen";
  const skipInstall = process.argv.includes("--no-install");
  if (skipInstall) {
    summary.actions[label] = { status: "SKIP", detail: "--no-install flag set" };
    process.stdout.write(`[SKIP] ${label}: --no-install flag\n`);
    return;
  }
  process.stdout.write(`[RUN ] ${label}: pnpm install --frozen-lockfile ...\n`);
  const result = run("pnpm", ["install", "--frozen-lockfile"], { stdio: "inherit" });
  if (result.status !== 0) {
    summary.actions[label] = { status: "FAIL", detail: `exit ${result.status}` };
    summary.exitCode = Math.max(summary.exitCode, 2);
    process.stderr.write(`[FAIL] ${label}: frozen-lockfile install failed (exit ${result.status})\n`);
    process.stderr.write("Refusing to rewrite lockfile or auto-upgrade dependencies.\n");
  } else {
    summary.actions[label] = { status: "PASS", detail: "frozen-lockfile install complete" };
    pass(label, "dependencies installed with frozen lockfile");
  }
})();

// Output summary
console.log("\n=== Setup Summary ===");
console.log(JSON.stringify(summary, null, 2));
process.exit(summary.exitCode);
