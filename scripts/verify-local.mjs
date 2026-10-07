#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import os from "node:os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKSPACE_ROOT = path.resolve(__dirname, "..");

const REQUIRED_TOP_LEVEL = [
  "package.json",
  "pnpm-workspace.yaml",
  "pnpm-lock.yaml",
  "tsconfig.json",
  "tsconfig.base.json",
  "vitest.config.ts",
  "LICENSE",
  ".gitignore",
  "apps/cli",
  "packages/core",
  "packages/event-ledger",
  "packages/policy",
  "packages/runtime-linux",
  "packages/shared",
  "packages/verbs",
  "tests",
];

const REQUIRED_SRC_FILES = [
  "apps/cli/src/runner.ts",
  "apps/cli/src/inspect.ts",
  "apps/cli/bin/menog.ts",
  "packages/event-ledger/src/ledger.ts",
  "packages/event-ledger/src/crypto.ts",
  "packages/policy/src/engine.ts",
  "packages/policy/src/capabilities.ts",
  "packages/runtime-linux/src/executor.ts",
  "packages/runtime-linux/src/validate.ts",
  "packages/runtime-linux/src/gate.ts",
  "packages/runtime-linux/src/allowlist.ts",
  "packages/verbs/src/verbs.ts",
  "packages/verbs/src/registry.ts",
];

const SECRET_PATTERNS = [
  { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "AWS Secret Assignment", re: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*[A-Za-z0-9\/+=]{40}/ },
  { name: "GitHub Token", re: /ghp_[A-Za-z0-9]{36}/ },
  { name: "GitHub Classic Token", re: /gho_[A-Za-z0-9]{36}/ },
  { name: "Generic Secret Key", re: /(?:secret|private[_-]?key|api[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i },
  { name: "Sk- OpenAI-style Key", re: /sk-[A-Za-z0-9]{32,}/ },
  { name: "RSA Private Key Block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "JWT-like Token", re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
];

const NETWORK_CALL_PATTERNS = [
  { name: "fetch()", re: /\bfetch\s*\(/ },
  { name: "http.request/http.get", re: /\b(?:http|https)\.(?:request|get)\s*\(/ },
  { name: "axios", re: /\baxios\b/ },
  { name: "XMLHttpRequest", re: /\bXMLHttpRequest\b/ },
  { name: "WebSocket", re: /\bnew\s+WebSocket\s*\(/ },
  { name: "net.connect/tls.connect", re: /\b(?:net|tls)\.(?:connect|createConnection)\s*\(/ },
  { name: "undici request", re: /\brequest\s*\(/ },
];

const GENERATED_ARTIFACT_DIRS = ["dist", "node_modules", ".pnpm-store", ".menog", "coverage", "build", "out"];

function run(cmd, args, opts = {}) {
  const useShell = opts.shell ?? (process.platform === "win32" && ["pnpm", "npm", "yarn", "git"].includes(cmd));
  const result = spawnSync(cmd, args, {
    cwd: WORKSPACE_ROOT,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 5 * 60 * 1000,
    shell: useShell,
    ...opts,
  });
  if (result.error) {
    result.stdout = (result.stdout || "") + `\nSPAWN_ERROR: ${result.error.message}`;
    result.status = result.status ?? 127;
  }
  return result;
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "menog-verify-"));
}

const report = {
  schema: "menog-local-verification/v1",
  timestamp: new Date().toISOString(),
  structure: "NOT_RUN",
  typecheck: "NOT_RUN",
  build: "NOT_RUN",
  tests: { passed: 0, failed: 0, status: "NOT_RUN" },
  securityTests: { passed: 0, failed: 0, status: "NOT_RUN" },
  cliSmoke: "NOT_RUN",
  ledgerIntegrity: "NOT_RUN",
  secretScan: "NOT_RUN",
  generatedArtifacts: "NOT_RUN",
  gitignore: "NOT_RUN",
  networkInvariant: "NOT_RUN",
  overall: "FAIL",
  _warnings: [],
  _errors: [],
};

function addWarn(msg) {
  report._warnings.push(msg);
}

function addErr(msg) {
  report._errors.push(msg);
}

console.log("=== Menog OS — Local Verification (read-only) ===\n");

// 1. Repository structure validation
(() => {
  const label = "1. structure";
  process.stdout.write(`[RUN ] ${label} ... `);
  const missing = REQUIRED_TOP_LEVEL.filter((p) => !fs.existsSync(path.join(WORKSPACE_ROOT, p)));
  const missingSrc = REQUIRED_SRC_FILES.filter((p) => !fs.existsSync(path.join(WORKSPACE_ROOT, p)));
  if (missing.length > 0 || missingSrc.length > 0) {
    process.stdout.write("FAIL\n");
    report.structure = "FAIL";
    addErr(`Missing top-level: ${missing.join(", ") || "(none)"}; Missing src: ${missingSrc.join(", ") || "(none)"}`);
  } else {
    process.stdout.write("PASS\n");
    report.structure = "PASS";
  }
})();

// 2. pnpm typecheck
(() => {
  const label = "2. typecheck";
  process.stdout.write(`[RUN ] ${label} ... `);
  const result = run("pnpm", ["typecheck"]);
  if (result.status === 0) {
    process.stdout.write("PASS\n");
    report.typecheck = "PASS";
  } else {
    process.stdout.write("FAIL\n");
    report.typecheck = "FAIL";
    addErr(`typecheck exit=${result.status}: ${(result.stderr || result.stdout || "").slice(0, 400)}`);
  }
})();

// 3. pnpm build
(() => {
  const label = "3. build";
  process.stdout.write(`[RUN ] ${label} ... `);
  const result = run("pnpm", ["build"]);
  if (result.status === 0) {
    process.stdout.write("PASS\n");
    report.build = "PASS";
  } else {
    process.stdout.write("FAIL\n");
    report.build = "FAIL";
    addErr(`build exit=${result.status}: ${(result.stderr || result.stdout || "").slice(0, 400)}`);
  }
})();

// 4. pnpm test (all) + 5. security test split
(() => {
  const label = "4. tests + 5. security";
  process.stdout.write(`[RUN ] ${label} ... `);
  function runWithJsonReport(extraArgs = []) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "menog-vitest-"));
    const reportFile = path.join(tmpDir, "report.json");
    const args = ["vitest", "run", "--color=false", `--reporter=json`, `--outputFile=${reportFile}`, ...extraArgs];
    const result = run("pnpm", args);
    let passed = 0;
    let failed = 0;
    try {
      if (fs.existsSync(reportFile)) {
        const json = JSON.parse(fs.readFileSync(reportFile, "utf-8"));
        if (json && typeof json.numPassedTestSuites === "number") {
          passed = json.numTotalTests - (json.numFailedTests || 0) - (json.numPendingTests || 0);
          failed = json.numFailedTests || 0;
        }
        if (json && json.testResults && Array.isArray(json.testResults)) {
          let p = 0, f = 0;
          for (const tr of json.testResults) {
            if (tr && Array.isArray(tr.assertionResults)) {
              for (const a of tr.assertionResults) {
                if (a.status === "passed") p++;
                else if (a.status === "failed") f++;
              }
            }
          }
          if (p > 0 || f > 0) { passed = p; failed = f; }
        }
      }
    } catch {}
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    return { result, passed, failed };
  }
  const { result: allResult, passed: totalPassed, failed: totalFailed } = runWithJsonReport();
  const { result: secResult, passed: secPassed, failed: secFailed } = runWithJsonReport(["tests/security/"]);
  if (allResult.status === 0 && secResult.status === 0) {
    const nonSecPassed = Math.max(0, totalPassed - secPassed);
    const nonSecFailed = Math.max(0, totalFailed - secFailed);
    report.tests = { passed: nonSecPassed, failed: nonSecFailed, status: "PASS" };
    report.securityTests = { passed: secPassed, failed: secFailed, status: "PASS" };
    process.stdout.write(`PASS (total=${totalPassed} non-sec=${nonSecPassed} sec=${secPassed})\n`);
  } else {
    process.stdout.write("FAIL\n");
    report.tests.status = allResult.status === 0 ? "PASS" : "FAIL";
    report.securityTests.status = secResult.status === 0 ? "PASS" : "FAIL";
    report.tests.passed = Math.max(0, totalPassed - secPassed);
    report.tests.failed = Math.max(0, totalFailed - secFailed);
    report.securityTests.passed = secPassed;
    report.securityTests.failed = secFailed;
    if (allResult.status !== 0) addErr(`all-tests exit=${allResult.status}: ${((allResult.stdout||"") + (allResult.stderr||"")).slice(0, 400)}`);
    if (secResult.status !== 0) addErr(`sec-tests exit=${secResult.status}: ${((secResult.stdout||"") + (secResult.stderr||"")).slice(0, 400)}`);
  }
})();

// 6. CLI smoke: menog inspect fixture/workspace (using built dist)
(() => {
  const label = "6. cli-smoke";
  process.stdout.write(`[RUN ] ${label} ... `);
  try {
    const cliBin = path.join(WORKSPACE_ROOT, "apps/cli/dist/bin/menog.js");
    if (!fs.existsSync(cliBin)) {
      process.stdout.write("SKIP (no dist build)\n");
      report.cliSmoke = "SKIP";
      addWarn("CLI smoke skipped — apps/cli/dist/bin/menog.js missing (build not run)");
      return;
    }
    const fixture = tmpdir();
    fs.writeFileSync(path.join(fixture, "package.json"), JSON.stringify({ name: "fixture", version: "0.0.0" }, null, 2));
    fs.writeFileSync(path.join(fixture, "README.md"), "# fixture\n");
    try {
      spawnSync("git", ["init", "-q", "-b", "main"], { cwd: fixture, timeout: 15000, stdio: "ignore" });
    } catch {}
    const result = run("node", [cliBin, "inspect", fixture]);
    fs.rmSync(fixture, { recursive: true, force: true });
    if (result.status === 0) {
      process.stdout.write("PASS\n");
      report.cliSmoke = "PASS";
    } else {
      process.stdout.write("FAIL\n");
      report.cliSmoke = "FAIL";
      addErr(`cli exit=${result.status}: ${(result.stderr || result.stdout || "").slice(0, 400)}`);
    }
  } catch (e) {
    process.stdout.write("FAIL\n");
    report.cliSmoke = "FAIL";
    addErr(`cli-smoke exception: ${e.message}`);
  }
})();

// 7. Event Ledger verify() — round-trip a temp ledger via node script
(() => {
  const label = "7. ledger-integrity";
  process.stdout.write(`[RUN ] ${label} ... `);
  const ledgerPkg = path.join(WORKSPACE_ROOT, "packages/event-ledger/dist/index.js");
  if (!fs.existsSync(path.join(WORKSPACE_ROOT, "packages/event-ledger/dist/ledger.js"))) {
    process.stdout.write("SKIP (no dist build)\n");
    report.ledgerIntegrity = "SKIP";
    addWarn("Ledger integrity skipped — build artifacts missing");
    return;
  }
  const tmp = tmpdir();
  fs.mkdirSync(path.join(tmp, "ledger"), { recursive: true });
  const ledgerFile = path.join(tmp, "ledger", "events.jsonl");
  const script = `
import { AppendOnlyLedger } from ${JSON.stringify(pathToFileURL(ledgerPkg).href)};
import path from "node:path";
const ledgerFile = ${JSON.stringify(ledgerFile)};
(() => {
  const l = AppendOnlyLedger.at(ledgerFile);
  l.append({ verb: "test.hello", subject: path.join(${JSON.stringify(tmp)}, "f"), actor: "human", resultSummary: "smoke", riskClass: "low" });
  l.append({ verb: "test.second", subject: path.join(${JSON.stringify(tmp)}, "g"), actor: "human", resultSummary: "smoke2", riskClass: "low" });
  const v = l.verify();
  if (!v.ok) { console.log("VERIFY_FAIL reason=" + (v.reason || "")); process.exit(2); }
  console.log("VERIFY_OK count=" + l.length);
})();
`;
  const scriptFile = path.join(tmp, "smoke-ledger.mjs");
  fs.writeFileSync(scriptFile, script);
  const result = run("node", [scriptFile]);
  fs.rmSync(tmp, { recursive: true, force: true });
  if (result.status === 0 && /VERIFY_OK/.test(result.stdout)) {
    process.stdout.write("PASS\n");
    report.ledgerIntegrity = "PASS";
  } else {
    process.stdout.write("FAIL\n");
    report.ledgerIntegrity = "FAIL";
    addErr(`ledger verify: exit=${result.status} out=${result.stdout.slice(0, 300)} err=${result.stderr.slice(0, 300)}`);
  }
})();

// 8. generated-artifact check (no generated artifacts interleaved within src/ dirs)
(() => {
  const label = "8. generated-artifacts";
  process.stdout.write(`[RUN ] ${label} ... `);
  const violations = [];
  for (const base of ["apps", "packages", "tests"]) {
    const basePath = path.join(WORKSPACE_ROOT, base);
    if (!fs.existsSync(basePath)) continue;
    function walk(dir, insideSrc = false) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          const isSrc = entry.name === "src" || entry.name === "bin";
          if (insideSrc && (entry.name === "dist" || entry.name === "node_modules" || entry.name === ".menog")) {
            violations.push(full);
            continue;
          }
          walk(full, insideSrc || isSrc);
        } else {
          if (insideSrc && /\.tsbuildinfo$/.test(entry.name)) violations.push(full);
        }
      }
    }
    walk(basePath, false);
  }
  if (violations.length > 0) {
    process.stdout.write("WARN\n");
    report.generatedArtifacts = "WARN";
    addWarn(`Generated artifacts interleaved in src/bin: ${violations.slice(0, 10).join(", ")}${violations.length > 10 ? ` (+${violations.length - 10} more)` : ""}`);
  } else {
    process.stdout.write("PASS\n");
    report.generatedArtifacts = "PASS";
  }
})();

// 9. secret-pattern scan
(() => {
  const label = "9. secret-scan";
  process.stdout.write(`[RUN ] ${label} ... `);
  const hits = [];
  function walk(dir, depth = 0) {
    if (depth > 6) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = full.length > WORKSPACE_ROOT.length + 1 ? full.slice(WORKSPACE_ROOT.length + 1) : entry.name;
      if (entry.isDirectory()) {
        if (["node_modules", ".git", ".pnpm", "dist", ".menog", ".trae", ".vscode", ".idea", "scripts"].includes(entry.name)) continue;
        walk(full, depth + 1);
      } else {
        if (!/\.(ts|tsx|js|mjs|cjs|json|md|yaml|yml|env|toml|cfg)$/i.test(entry.name)) continue;
        let content;
        try { content = fs.readFileSync(full, "utf-8"); } catch { continue; }
        for (const pat of SECRET_PATTERNS) {
          if (pat.re.test(content)) {
            if (/LOCAL_VERIFICATION_REPORT|FIRST_PUSH_MANIFEST|MENOG_PATENT_DISCLOSURE|TRADEMARK|password\s*=\s*""|example|PLACEHOLDER/.test(content.slice(0, 50)) && /PATENT|research|governance|docs\//.test(rel)) continue;
            hits.push(`${rel} :: ${pat.name}`);
            break;
          }
        }
      }
    }
  }
  walk(WORKSPACE_ROOT);
  if (hits.length > 0) {
    process.stdout.write("WARN\n");
    report.secretScan = "WARN";
    addWarn(`Potential secret matches: ${hits.slice(0, 10).join(" | ")}${hits.length > 10 ? ` (+${hits.length - 10} more)` : ""}`);
  } else {
    process.stdout.write("PASS\n");
    report.secretScan = "PASS";
  }
})();

// 10. .gitignore verification
(() => {
  const label = "10. gitignore";
  process.stdout.write(`[RUN ] ${label} ... `);
  const giPath = path.join(WORKSPACE_ROOT, ".gitignore");
  if (!fs.existsSync(giPath)) {
    process.stdout.write("FAIL\n");
    report.gitignore = "FAIL";
    addErr(".gitignore missing");
  } else {
    const content = fs.readFileSync(giPath, "utf-8");
    const required = [
      /node_modules\//,
      /dist\//,
      /\.tsbuildinfo/,
      /\.menog\//,
      /^\.env$/m,
      /^\.env\.\*/m,
      /!\/\.env\.example/m,
    ];
    const missing = required.filter((r) => !r.test(content));
    if (missing.length > 0) {
      process.stdout.write("WARN\n");
      report.gitignore = "WARN";
      addWarn(`.gitignore missing patterns: expected ${missing.length} regex patterns`);
    } else {
      process.stdout.write("PASS\n");
      report.gitignore = "PASS";
    }
    for (const d of GENERATED_ARTIFACT_DIRS) {
      const p = path.join(WORKSPACE_ROOT, d);
      if (fs.existsSync(p) && !new RegExp(d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(/|$)").test(content)) {
        addWarn(`Directory ${d} exists but may not be ignored by .gitignore`);
        if (report.gitignore === "PASS") report.gitignore = "WARN";
      }
    }
  }
})();

// 11. workspace escape test + 12. no-network Day-1 invariant (combined source scan)
(() => {
  const label = "11-12. workspace-escape + network-invariant";
  process.stdout.write(`[RUN ] ${label} ... `);
  const srcRoots = [
    path.join(WORKSPACE_ROOT, "apps"),
    path.join(WORKSPACE_ROOT, "packages"),
  ];
  let escapePresent = false;
  let networkHits = [];
  function walk(dir, depth = 0) {
    if (depth > 7) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (["node_modules", "dist", ".menog"].includes(entry.name)) continue;
        walk(full, depth + 1);
      } else if (/\.ts$|\.mjs$|\.js$/.test(entry.name)) {
        let content;
        try { content = fs.readFileSync(full, "utf-8"); } catch { continue; }
        if (/\.\.(\/|\\)\.\.|chroot|root\s*=|resolveRoot|absolutePathWithoutWorkspace/.test(content)) {
          escapePresent = true;
        }
        for (const np of NETWORK_CALL_PATTERNS) {
          if (np.re.test(content)) {
            const rel = full.length > WORKSPACE_ROOT.length + 1 ? full.slice(WORKSPACE_ROOT.length + 1) : entry.name;
            networkHits.push(`${rel} :: ${np.name}`);
            break;
          }
        }
      }
    }
  }
  for (const r of srcRoots) if (fs.existsSync(r)) walk(r);

  const denyTestsExist = fs.existsSync(path.join(WORKSPACE_ROOT, "tests/security/deny-tests.test.ts"));
  const securityStatusLine = report.securityTests.status;
  const workspaceEscapeOk = securityStatusLine === "PASS" && denyTestsExist;
  if (!workspaceEscapeOk) {
    addWarn(`workspace-escape-invariant: deny-tests status=${securityStatusLine}, deny-test-file=${denyTestsExist ? "present" : "MISSING"}`);
  }

  if (networkHits.length > 0) {
    process.stdout.write("FAIL\n");
    report.networkInvariant = "FAIL";
    addErr(`network-invariant FAIL — network-call-like constructs: ${networkHits.slice(0, 5).join(" | ")}${networkHits.length > 5 ? ` (+${networkHits.length - 5} more)` : ""}`);
  } else {
    process.stdout.write("PASS\n");
    report.networkInvariant = "PASS";
  }
})();

// Overall determination
report.overall =
  report._errors.length === 0 &&
  report.structure === "PASS" &&
  report.typecheck === "PASS" &&
  report.build === "PASS" &&
  report.tests.status === "PASS" &&
  report.securityTests.status === "PASS" &&
  (report.cliSmoke === "PASS" || report.cliSmoke === "SKIP") &&
  (report.ledgerIntegrity === "PASS" || report.ledgerIntegrity === "SKIP") &&
  report.gitignore !== "FAIL" &&
  report.secretScan !== "FAIL" &&
  report.networkInvariant === "PASS"
    ? "PASS"
    : "FAIL";

const OUT = path.join(WORKSPACE_ROOT, "LOCAL_VERIFICATION_REPORT.json");
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + "\n", "utf-8");
console.log(`\n=== Verification Report Written ===\n${OUT}`);
console.log(`\nOverall: ${report.overall}  (${report._errors.length} errors, ${report._warnings.length} warnings)`);
process.exit(report.overall === "PASS" ? 0 : 1);
