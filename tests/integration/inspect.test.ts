import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  runInspectWorkflow,
  parseArgs,
  normalizeWorkspaceArg,
  summarizePolicy,
  MENOG_DIRNAME,
  LEDGER_FILENAME,
  INSPECT_FORMAT_VERSION,
  type InspectReport,
} from "@menog/cli";
import { AppendOnlyLedger as Ledger } from "@menog/event-ledger";
import { mkdirSync, writeFileSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import type { Stats } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync, spawnSync } from "node:child_process";

let fixtureDir: string | null = null;
let fixtureRepo: string | null = null;
let haveGit = false;

function tmp(): string {
  const p = join(tmpdir(), "menog-integ-" + Math.random().toString(36).slice(2, 10));
  mkdirSync(p, { recursive: true });
  return p;
}

function run(cmd: string, cwd: string): void {
  execSync(cmd, { cwd, stdio: "ignore", timeout: 30000 });
}

function snapshotTree(root: string): Record<string, { readonly size: number; readonly sha: string }> {
  const out: Record<string, { size: number; sha: string }> = {};
  const walk = (dir: string): void => {
    let entries: readonly string[] = [];
    try {
      entries = readdirSync(dir, { withFileTypes: false }) as readonly string[];
    } catch {
      return;
    }
    for (const n of entries) {
      if (n === MENOG_DIRNAME) continue;
      if (n === ".git") continue;
      const full = join(dir, n);
      let st: Stats | null = null;
      try {
        st = statSync(full, { throwIfNoEntry: false }) ?? null;
      } catch {
        st = null;
      }
      if (!st) continue;
      const rel = full.length > root.length + 1 ? full.slice(root.length + 1) : n;
      if (st.isDirectory()) {
        walk(full);
      } else if (st.isFile()) {
        const content = readFileSync(full);
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
          hash = (hash * 131 + content[i]!) >>> 0;
        }
        out[rel.replace(/\\/g, "/")] = Object.freeze({ size: st.size, sha: hash.toString(16).padStart(8, "0") });
      }
    }
  };
  walk(root);
  return out;
}

beforeAll(() => {
  try {
    const v = spawnSync("git", ["--version"], { timeout: 15000 });
    haveGit = v.status === 0;
  } catch {
    haveGit = false;
  }
  fixtureDir = tmp();
  fixtureRepo = join(fixtureDir, "repo-B");
  mkdirSync(fixtureRepo, { recursive: true });
  if (haveGit) {
    run("git init -q -b main", fixtureRepo);
    try { run("git config user.email integ-test@menog.local", fixtureRepo); } catch { /* ignore */ }
    try { run("git config user.name IntegTest", fixtureRepo); } catch { /* ignore */ }
    writeFileSync(join(fixtureRepo, "README.md"), "# integration fixture\nhello world\n", "utf8");
    writeFileSync(join(fixtureRepo, "package.json"), JSON.stringify({ name: "integ-fixture", private: true }, null, 2) + "\n", "utf8");
    writeFileSync(join(fixtureRepo, "tsconfig.json"), JSON.stringify({ extends: "./tsconfig.base.json" }, null, 2) + "\n", "utf8");
    writeFileSync(
      join(fixtureRepo, "example.test.ts"),
      "import { describe, it, expect } from 'vitest';\ndescribe('unit', () => { it('x', () => { expect(1).toBe(1); }); });\n",
      "utf8"
    );
    mkdirSync(join(fixtureRepo, "src"), { recursive: true });
    writeFileSync(join(fixtureRepo, "src", "index.ts"), "export const x = 1;\n", "utf8");
    run("git add README.md package.json tsconfig.json example.test.ts src/index.ts", fixtureRepo);
    run('git commit -q -m "initial integ fixture commit"', fixtureRepo);
    writeFileSync(join(fixtureRepo, "README.md"), "# integration fixture\nhello world modified\n", "utf8");
    writeFileSync(join(fixtureRepo, "untracked.txt"), "new file\n", "utf8");
  }
});

afterAll(() => {
  if (fixtureDir && existsSync(fixtureDir)) {
    rmSync(fixtureDir, { recursive: true, force: true });
  }
});

describe("Prompt 07 — parseArgs: exactly `menog inspect <workspace>`", () => {
  it("parseArgs(['inspect','/tmp/foo']) → ok workspace=/tmp/foo", () => {
    const r = parseArgs(["inspect", "/tmp/foo"]);
    expect(r.ok).toBe(true);
    expect(r.subcommand).toBe("inspect");
    expect(r.workspaceArg).toBe("/tmp/foo");
  });

  it("parseArgs(['build']) → unknown subcommand error", () => {
    const r = parseArgs(["build"]);
    expect(r.ok).toBe(false);
    expect(r.usageError).toMatch(/unknown subcommand 'build'/);
  });

  it("parseArgs(['inspect']) → usage workspace required", () => {
    const r = parseArgs(["inspect"]);
    expect(r.ok).toBe(false);
    expect(r.usageError).toMatch(/usage:/);
  });

  it("parseArgs(['inspect','a','b']) → too many args", () => {
    const r = parseArgs(["inspect", "a", "b"]);
    expect(r.ok).toBe(false);
    expect(r.usageError).toMatch(/too many arguments/);
  });

  it("parseArgs(['--json']) → no flags accepted in day-1 v0", () => {
    const r = parseArgs(["--json"]);
    expect(r.ok).toBe(false);
    expect(r.usageError).toMatch(/accepts no flags/);
  });

  it("normalizeWorkspaceArg returns abs inside cwd", () => {
    const r = normalizeWorkspaceArg(".", fixtureRepo ?? process.cwd());
    expect(r.ok).toBe(true);
    expect(r.resolved).toBeDefined();
    expect(r.resolved!.length).toBeGreaterThan(0);
  });
});

describe("Prompt 07 — vertical integration: inspect returns deterministic structured output", () => {
  it("runInspectWorkflow on fixture repo → all required fields present, exitStatus=0, eventCount>0", async () => {
    if (!haveGit || !fixtureRepo) return;
    const workingDir = fixtureRepo;
    const res = await runInspectWorkflow({
      workspaceArg: workingDir,
      taskId: "integ-A",
      workingCwd: fixtureDir ?? undefined,
    });
    expect([0, 1]).toContain(res.exitStatus);
    expect(res.report).not.toBeNull();
    const rep = res.report as InspectReport;
    expect(rep.formatVersion).toBe(INSPECT_FORMAT_VERSION);
    expect(rep.taskId).toBe("integ-A");
    expect(rep.workspace.normalized.length).toBeGreaterThan(0);
    expect(rep.workspace.path).toBeTruthy();
    expect(typeof rep.git.isRepository).toBe("boolean");
    if (rep.git.isRepository) {
      expect(rep.git.branch).toBeTruthy();
      expect(rep.git.status).toBe("dirty");
      expect(rep.git.counts.tracked).toBeGreaterThan(0);
      expect(rep.git.counts.modified).toBeGreaterThanOrEqual(0);
      expect(rep.git.counts.untracked).toBeGreaterThanOrEqual(0);
    }
    expect(Array.isArray(rep.manifests)).toBe(true);
    if (rep.manifests.length > 0) {
      expect(rep.manifests).toContain("package.json");
    }
    expect(Number.isFinite(rep.testFiles)).toBe(true);
    expect(rep.testFiles).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(rep.warnings)).toBe(true);
    expect(typeof rep.policy.decision).toBe("string");
    expect(Number.isFinite(rep.eventCount)).toBe(true);
    expect(rep.executionDurationMs).toBeGreaterThanOrEqual(0);
    if (res.exitStatus === 0) {
      expect(rep.policy.decision).toBe("allow");
    }
    const parsed = JSON.parse(res.stdoutText) as InspectReport;
    expect(parsed.formatVersion).toBe(INSPECT_FORMAT_VERSION);
    expect(parsed.taskId).toBe(rep.taskId);
  }, { timeout: 60000 });

  it("two consecutive runs produce byte-for-byte stable report structure (fields, not timestamps)", async () => {
    if (!haveGit || !fixtureRepo) return;
    const a = await runInspectWorkflow({ workspaceArg: fixtureRepo, taskId: "det-A" });
    const b = await runInspectWorkflow({ workspaceArg: fixtureRepo, taskId: "det-B" });
    expect(a.report).not.toBeNull();
    expect(b.report).not.toBeNull();
    const ra = a.report!, rb = b.report!;
    expect(ra.formatVersion).toBe(rb.formatVersion);
    expect(ra.workspace.normalized).toBe(rb.workspace.normalized);
    expect(ra.git.isRepository).toBe(rb.git.isRepository);
    expect(ra.git.branch).toBe(rb.git.branch);
    expect(ra.git.status).toBe(rb.git.status);
    expect(ra.git.counts.tracked).toBe(rb.git.counts.tracked);
    expect(ra.git.counts.modified).toBe(rb.git.counts.modified);
    expect(ra.git.counts.untracked).toBe(rb.git.counts.untracked);
    expect(ra.manifests).toEqual(rb.manifests);
    expect(ra.testFiles).toBe(rb.testFiles);
  }, { timeout: 60000 });

  it("fixture is unchanged status-for-status after inspect runs", async () => {
    if (!haveGit || !fixtureRepo) return;
    const before = snapshotTree(fixtureRepo);
    await runInspectWorkflow({ workspaceArg: fixtureRepo, taskId: "stab-1", ledger: "memory" });
    await runInspectWorkflow({ workspaceArg: fixtureRepo, taskId: "stab-2", ledger: "memory" });
    const after = snapshotTree(fixtureRepo);
    expect(Object.keys(before).sort()).toEqual(Object.keys(after).sort());
    for (const k of Object.keys(before)) {
      expect(before[k]!.size).toBe(after[k]!.size);
      expect(before[k]!.sha).toBe(after[k]!.sha);
    }
    const postStatus = spawnSync("git", ["status", "--porcelain=v1"], { cwd: fixtureRepo, encoding: "utf8", timeout: 15000 }).stdout;
    expect(typeof postStatus).toBe("string");
    expect(postStatus!.length).toBeGreaterThan(0);
    const lines = postStatus!.split("\n").filter((l) => l.length > 0 && !l.startsWith("?? " + MENOG_DIRNAME + "/")).sort();
    const expected = [" M README.md", "?? untracked.txt"].sort();
    expect(lines).toEqual(expected);
  }, { timeout: 60000 });

  it("event ledger records workflow when using `kind:dir` ledger", async () => {
    if (!haveGit || !fixtureRepo) return;
    const ledgerWs = join(fixtureDir!, "ledger-ws");
    mkdirSync(ledgerWs, { recursive: true });
    const ledgerJsonl = join(ledgerWs, MENOG_DIRNAME, LEDGER_FILENAME);
    await runInspectWorkflow({
      workspaceArg: fixtureRepo,
      taskId: "ledger-ws-A",
      ledger: { kind: "dir", root: ledgerWs },
    });
    expect(existsSync(ledgerJsonl)).toBe(true);
    const ledger = Ledger.at(ledgerJsonl);
    expect(ledger.length).toBeGreaterThan(0);
    const verify = ledger.verify();
    expect(verify.ok).toBe(true);
    const evts = ledger.events();
    const policies = evts.filter((e: { eventType: string }) => e.eventType === "policy_decision");
    const execResults = evts.filter((e: { eventType: string }) => e.eventType === "exec_result");
    expect(policies.length).toBeGreaterThan(0);
    for (const p of policies) {
      expect(["allow", "deny"]).toContain(p.policyDecision);
      expect(p.eventType).toBe("policy_decision");
    }
    expect(execResults.length).toBeGreaterThanOrEqual(2);
  }, { timeout: 60000 });

  describe("R1 — synthetic replay summarizePolicy regression (no fake full PolicyResult)", () => {
    it("summarizePolicy accepts the narrowed PolicySummaryInput shape and preserves allow/deny", () => {
      const summary = summarizePolicy([
        {
          decision: {
            outcome: "allow" as const,
            matchedRule: "rule:inspect-default",
            reason: "verb 'inspect' in allowlist",
          },
        },
        {
          decision: {
            outcome: "deny" as const,
            matchedRule: "rule:unknown-capability",
            reason: "capability not registered",
          },
        },
        {
          decision: {
            outcome: "allow" as const,
            matchedRule: "rule:inspect-default",
          },
        },
      ]);
      expect(summary.decision).toBe("deny");
      expect(summary.eventCount).toBe(3);
      expect([...summary.matchedRules].sort()).toEqual(
        ["rule:inspect-default", "rule:unknown-capability"].sort()
      );
      expect([...summary.warnings].sort()).toEqual(
        ["verb 'inspect' in allowlist", "capability not registered"].sort()
      );
    });

    it("summarizePolicy handles empty input without perCapability fallbacks", () => {
      const summary = summarizePolicy([]);
      expect(summary.decision).toBe("allow");
      expect(summary.eventCount).toBe(0);
      expect(summary.matchedRules).toEqual([]);
      expect(summary.warnings).toEqual([]);
    });

    it("deny-only synthetic replay preserves deny outcome without matchedRule or reason", () => {
      const summary = summarizePolicy([
        { decision: { outcome: "deny" as const } },
      ]);
      expect(summary.decision).toBe("deny");
      expect(summary.eventCount).toBe(1);
      expect(summary.matchedRules).toEqual([]);
      expect(summary.warnings).toEqual([]);
    });

    it("runInspectWorkflow ledger replay produces identical policy.decision to direct policy evaluation", async () => {
      if (!haveGit || !fixtureRepo) return;
      const result = await runInspectWorkflow({
        workspaceArg: fixtureRepo,
        taskId: "r1-replay-check",
        ledger: "memory",
      });
      expect(result.exitStatus).toBe(0);
      expect(result.report).not.toBeNull();
      const report = result.report!;
      expect(report.formatVersion).toBe(INSPECT_FORMAT_VERSION);
      expect(["allow", "deny"]).toContain(report.policy.decision);
      expect(report.policy.eventCount).toBeGreaterThan(0);
      const warningsIncludePerCapability = report.warnings.some(
        (w: string) => w.toLowerCase().includes("percapability") || w.includes("as unknown")
      );
      expect(warningsIncludePerCapability).toBe(false);
    }, { timeout: 60000 });
  });
});
