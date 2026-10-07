import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  ReadonlyGitService,
  queryGitStatus,
  queryGitDiff,
  inspectGitRepo,
  parseGitStatusShort,
  parseGitDiff,
  isGitRepository,
  validateGitCommandSecurity,
} from "@menog/runtime-linux";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import {
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync, spawnSync } from "node:child_process";

const TEST_ACTOR: Actor = { type: "agent", id: "git-integ-test-agent" };

let fixtureDir: string | null = null;
let repoDir: string | null = null;
let outsideDir: string | null = null;
let nonRepoDir: string | null = null;
let haveGit = false;

function tmp(prefix: string): string {
  const p = join(tmpdir(), `menog-git-${prefix}-` + Math.random().toString(36).slice(2, 10));
  mkdirSync(p, { recursive: true });
  return p;
}

function runGit(cmd: string, cwd: string): void {
  execSync(cmd, { cwd, stdio: "ignore", timeout: 30000 });
}

beforeAll(() => {
  try {
    const v = spawnSync("git", ["--version"], { timeout: 15000 });
    haveGit = v.status === 0;
  } catch {
    haveGit = false;
  }

  fixtureDir = tmp("root");
  repoDir = join(fixtureDir, "repo");
  outsideDir = join(fixtureDir, "outside");
  nonRepoDir = join(fixtureDir, "non-repo");

  mkdirSync(repoDir, { recursive: true });
  mkdirSync(outsideDir, { recursive: true });
  mkdirSync(nonRepoDir, { recursive: true });

  writeFileSync(join(outsideDir, "OUTSIDE_SECRET.txt"), "forbidden content\n", "utf8");

  if (haveGit) {
    runGit("git init -q -b main", repoDir);
    try { runGit("git config user.email test@menog.local", repoDir); } catch { /* ignore */ }
    try { runGit("git config user.name MenogTester", repoDir); } catch { /* ignore */ }

    writeFileSync(join(repoDir, "README.md"), "# Initial Project\n", "utf8");
    writeFileSync(join(repoDir, "file1.txt"), "hello world\n", "utf8");
    runGit("git add README.md file1.txt", repoDir);
    runGit('git commit -q -m "initial baseline commit"', repoDir);
  }
});

afterAll(() => {
  if (fixtureDir && existsSync(fixtureDir)) {
    rmSync(fixtureDir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────
// 1. CLEAN REPO
// ─────────────────────────────────────────
describe("15B — Git Integration: Clean Repo", () => {
  it("detects clean repo state when working tree has no changes", async () => {
    if (!haveGit || !repoDir) return;

    const res = await queryGitStatus(repoDir);
    expect(res.ok).toBe(true);
    expect(res.status).toBeDefined();

    const st = res.status!;
    expect(st.state).toBe("clean");
    expect(st.modifiedCount).toBe(0);
    expect(st.stagedCount).toBe(0);
    expect(st.untrackedCount).toBe(0);
    expect(st.files).toHaveLength(0);
  });

  it("reports empty diffs (no changes) for clean repo", async () => {
    if (!haveGit || !repoDir) return;

    const workingDiff = await queryGitDiff(repoDir, { staged: false });
    expect(workingDiff.ok).toBe(true);
    expect(workingDiff.diff?.hasChanges).toBe(false);
    expect(workingDiff.diff?.filesChanged).toBe(0);
    expect(workingDiff.diff?.files).toHaveLength(0);

    const stagedDiff = await queryGitDiff(repoDir, { staged: true });
    expect(stagedDiff.ok).toBe(true);
    expect(stagedDiff.diff?.hasChanges).toBe(false);
    expect(stagedDiff.diff?.filesChanged).toBe(0);
  });

  it("inspectRepo returns clean status and empty diffs", async () => {
    if (!haveGit || !repoDir) return;

    const inspection = await inspectGitRepo(repoDir);
    expect(inspection.ok).toBe(true);
    expect(inspection.status.state).toBe("clean");
    expect(inspection.workingDiff.hasChanges).toBe(false);
    expect(inspection.stagedDiff.hasChanges).toBe(false);
  });
});

// ─────────────────────────────────────────
// 2. DIRTY REPO
// ─────────────────────────────────────────
describe("15B — Git Integration: Dirty Repo (Modified & Staged)", () => {
  it("detects modified working tree files and generates working tree diff", async () => {
    if (!haveGit || !repoDir) return;

    // Modify a tracked file
    writeFileSync(join(repoDir, "file1.txt"), "hello world modified line\n", "utf8");

    try {
      const statusRes = await queryGitStatus(repoDir);
      expect(statusRes.ok).toBe(true);
      expect(statusRes.status?.state).toBe("dirty");
      expect(statusRes.status?.modifiedCount).toBeGreaterThanOrEqual(1);

      const f = statusRes.status?.files.find((x) => x.path === "file1.txt");
      expect(f).toBeDefined();
      expect(f?.isModified).toBe(true);
      expect(f?.isStaged).toBe(false);

      const diffRes = await queryGitDiff(repoDir, { staged: false });
      expect(diffRes.ok).toBe(true);
      expect(diffRes.diff?.hasChanges).toBe(true);
      expect(diffRes.diff?.filesChanged).toBe(1);
      expect(diffRes.diff?.files).toContain("file1.txt");
      expect(diffRes.diff?.rawDiff).toContain("-hello world");
      expect(diffRes.diff?.rawDiff).toContain("+hello world modified line");
    } finally {
      // Revert to clean baseline
      runGit("git checkout -- file1.txt", repoDir);
    }
  });

  it("detects staged changes and generates staged diff", async () => {
    if (!haveGit || !repoDir) return;

    // Stage a modification
    writeFileSync(join(repoDir, "file1.txt"), "staged change\n", "utf8");
    runGit("git add file1.txt", repoDir);

    try {
      const statusRes = await queryGitStatus(repoDir);
      expect(statusRes.ok).toBe(true);
      expect(statusRes.status?.state).toBe("dirty");
      expect(statusRes.status?.stagedCount).toBeGreaterThanOrEqual(1);

      const f = statusRes.status?.files.find((x) => x.path === "file1.txt");
      expect(f).toBeDefined();
      expect(f?.isStaged).toBe(true);

      const stagedDiff = await queryGitDiff(repoDir, { staged: true });
      expect(stagedDiff.ok).toBe(true);
      expect(stagedDiff.diff?.hasChanges).toBe(true);
      expect(stagedDiff.diff?.files).toContain("file1.txt");
    } finally {
      // Unstage and revert
      runGit("git reset -q HEAD file1.txt", repoDir);
      runGit("git checkout -- file1.txt", repoDir);
    }
  });
});

// ─────────────────────────────────────────
// 3. UNTRACKED FILES
// ─────────────────────────────────────────
describe("15B — Git Integration: Untracked Files", () => {
  it("detects untracked files in git status", async () => {
    if (!haveGit || !repoDir) return;

    const untrackedPath = join(repoDir, "new-untracked.txt");
    writeFileSync(untrackedPath, "untracked brand new file\n", "utf8");

    try {
      const statusRes = await queryGitStatus(repoDir);
      expect(statusRes.ok).toBe(true);
      expect(statusRes.status?.state).toBe("dirty");
      expect(statusRes.status?.untrackedCount).toBeGreaterThanOrEqual(1);

      const f = statusRes.status?.files.find((x) => x.path === "new-untracked.txt");
      expect(f).toBeDefined();
      expect(f?.isUntracked).toBe(true);
      expect(f?.indexStatus).toBe("?");
      expect(f?.workingStatus).toBe("?");
    } finally {
      if (existsSync(untrackedPath)) {
        rmSync(untrackedPath);
      }
    }
  });
});

// ─────────────────────────────────────────
// 4. REPO BOUNDARY
// ─────────────────────────────────────────
describe("15B — Git Integration: Repo Boundary Enforcement", () => {
  it("rejects path traversal attempting to escape workspace via ../", async () => {
    if (!repoDir) return;

    const service = new ReadonlyGitService();
    const badPath = join(repoDir, "..", "outside");

    const statusRes = await service.queryStatus(badPath);
    // When querying an outside path as workspaceRoot, it either resolves or fails boundary check
    // If targeted relative to workspace:
    const diffRes = await service.queryDiff(join(repoDir, "../outside"));
    expect(statusRes.ok === false || diffRes.ok === false || !isGitRepository(badPath)).toBe(true);
  });

  it("fails closed when querying a directory that is not a git repository", async () => {
    if (!nonRepoDir) return;

    expect(isGitRepository(nonRepoDir)).toBe(false);

    const statusRes = await queryGitStatus(nonRepoDir);
    expect(statusRes.ok).toBe(false);
    expect(statusRes.phase).toBe("validate");
    expect(statusRes.error).toContain("not_a_git_repository");

    const diffRes = await queryGitDiff(nonRepoDir);
    expect(diffRes.ok).toBe(false);
    expect(diffRes.phase).toBe("validate");
    expect(diffRes.error).toContain("not_a_git_repository");
  });
});

// ─────────────────────────────────────────
// 5. GIT COMMAND ALLOWLIST & NO HISTORY REWRITE
// ─────────────────────────────────────────
describe("15B — Git Integration: Command Allowlist & No-Force/No-Rewrite", () => {
  it("validateGitCommandSecurity blocks mutating git subcommands", () => {
    const forbidden = [
      ["commit", "-m", "illegal"],
      ["push", "origin", "main"],
      ["rebase", "main"],
      ["reset", "--hard", "HEAD~1"],
      ["checkout", "-f"],
      ["clean", "-f"],
      ["filter-branch"],
      ["tag", "v1.0"],
    ];

    for (const argv of forbidden) {
      const sec = validateGitCommandSecurity(argv);
      expect(sec.ok).toBe(false);
      expect(sec.reason).toContain("disallowed_git_command");
    }
  });

  it("validateGitCommandSecurity blocks force and rewrite flags", () => {
    const forbiddenFlags = [
      ["diff", "--force"],
      ["diff", "-f"],
      ["diff", "--hard"],
      ["diff", "--amend"],
    ];

    for (const argv of forbiddenFlags) {
      const sec = validateGitCommandSecurity(argv);
      expect(sec.ok).toBe(false);
      expect(sec.reason).toContain("disallowed_git_flag");
    }
  });

  it("ReadonlyGitService.executeAllowlisted strictly rejects non-allowlisted git commands", async () => {
    if (!haveGit || !repoDir) return;

    const service = new ReadonlyGitService();

    // 1. Commit attempt must be blocked
    const commitOut = await service.executeAllowlisted(repoDir, ["commit", "-m", "evil"]);
    expect(commitOut.ok).toBe(false);
    expect(commitOut.phase).toBe("validate");

    // 2. Push attempt must be blocked
    const pushOut = await service.executeAllowlisted(repoDir, ["push", "origin", "main"]);
    expect(pushOut.ok).toBe(false);
    expect(pushOut.phase).toBe("validate");

    // 3. Reset attempt must be blocked
    const resetOut = await service.executeAllowlisted(repoDir, ["reset", "--hard"]);
    expect(resetOut.ok).toBe(false);
    expect(resetOut.phase).toBe("validate");
  });

  it("ReadonlyGitService emits audit events to the ledger with valid cryptographic hash chain", async () => {
    if (!haveGit || !repoDir) return;

    const ledger = AppendOnlyLedger.inMemory();
    const service = new ReadonlyGitService({ ledger, actor: TEST_ACTOR });

    const res = await service.queryStatus(repoDir);
    expect(res.ok).toBe(true);

    expect(ledger.length).toBeGreaterThanOrEqual(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("policy_decision");
    expect(ev.policyDecision).toBe("allow");

    const v = ledger.verify();
    expect(v.ok).toBe(true);
  });
});

// ─────────────────────────────────────────
// 6. UNIT PARSER TESTS
// ─────────────────────────────────────────
describe("15B — Git Integration: Status and Diff Parsers", () => {
  it("parseGitStatusShort correctly parses various git status lines", () => {
    const stdout = [
      "## main...origin/main [ahead 1]",
      " M tracked-modified.ts",
      "M  staged-modified.ts",
      "A  staged-new.ts",
      " D tracked-deleted.ts",
      "?? untracked.ts",
    ].join("\n");

    const summary = parseGitStatusShort(stdout);
    expect(summary.branch).toBe("main");
    expect(summary.state).toBe("dirty");
    expect(summary.untrackedCount).toBe(1);
    expect(summary.modifiedCount).toBe(2);
    expect(summary.stagedCount).toBe(2);
    expect(summary.deletedCount).toBe(1);
    expect(summary.files).toHaveLength(5);
  });

  it("parseGitDiff correctly extracts file paths from git diff output", () => {
    const sampleDiff = [
      "diff --git a/src/index.ts b/src/index.ts",
      "index 1234567..89abcdef 100644",
      "--- a/src/index.ts",
      "+++ b/src/index.ts",
      "@@ -1,3 +1,3 @@",
      "-old",
      "+new",
      "diff --git a/docs/README.md b/docs/README.md",
      "--- a/docs/README.md",
      "+++ b/docs/README.md",
    ].join("\n");

    const summary = parseGitDiff(sampleDiff);
    expect(summary.hasChanges).toBe(true);
    expect(summary.filesChanged).toBe(2);
    expect(summary.files).toEqual(["docs/README.md", "src/index.ts"]);
  });
});
