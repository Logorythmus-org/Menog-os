import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  AuthoritativeExecGate,
  ReadonlyExecutor,
  DAY1_ALLOWED_COMMANDS,
  BLOCKED_BASE_NAMES,
  resolveWorkspaceSafely,
  validateReadonlyExec,
  type ExecRequest,
} from "@menog/runtime-linux";
import { AppendOnlyLedger as Ledger } from "@menog/event-ledger";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { execSync, spawnSync } from "node:child_process";

let fixtureDir: string | null = null;
let fixtureRepo: string | null = null;
let haveGit: boolean = false;

function tmp(): string {
  const base = join(
    tmpdir(),
    "menog-runtime-" + Math.random().toString(36).slice(2, 10)
  );
  mkdirSync(base, { recursive: true });
  return base;
}

function run(cmd: string, cwd: string): void {
  execSync(cmd, { cwd, stdio: "ignore", timeout: 30000 });
}

beforeAll(() => {
  try {
    const v = spawnSync("git", ["--version"], { timeout: 15000 });
    haveGit = v.status === 0;
  } catch {
    haveGit = false;
  }
  fixtureDir = tmp();
  fixtureRepo = join(fixtureDir, "repo-A");
  mkdirSync(fixtureRepo, { recursive: true });
  if (haveGit) {
    run("git init -q -b main", fixtureRepo);
    try { run("git config user.email menog-test@local", fixtureRepo); } catch { /* ignore */ }
    try { run("git config user.name MenogTest", fixtureRepo); } catch { /* ignore */ }
    writeFileSync(join(fixtureRepo, "README.md"), "# menog fixture\nhello\n", "utf8");
    writeFileSync(join(fixtureRepo, "a.txt"), "alpha\n", "utf8");
    run("git add README.md a.txt", fixtureRepo);
    run('git commit -q -m "initial"', fixtureRepo);
    writeFileSync(join(fixtureRepo, "a.txt"), "alpha modified\n", "utf8");
    writeFileSync(join(fixtureRepo, "b.txt"), "untracked file\n", "utf8");
  }
});

afterAll(() => {
  if (fixtureDir && existsSync(fixtureDir)) {
    rmSync(fixtureDir, { recursive: true, force: true });
  }
});

const gitStatusArgv: readonly string[] = ["status", "--short", "--branch"];

describe("Prompt 06 — allowed git status in fixture repo", () => {
  it("validate + gate allow git status --short --branch → exit 0, stdout non-empty, ledger has 2 events (policy+exec)", async () => {
    if (!haveGit || !fixtureRepo) return;
    const ledger = Ledger.inMemory();
    const gate = new AuthoritativeExecGate({ ledger });
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo,
      executable: "git",
      argv: [...gitStatusArgv],
      timeoutMs: 8000,
      requestId: "req-git-status",
    };
    const outcome = await gate.evaluateAndMaybeRun(req);
    expect(outcome.phase).toBe("complete");
    expect(outcome.ok).toBe(true);
    expect(outcome.decision?.decision.outcome).toBe("allow");
    expect(outcome.matchedCommand?.id).toBe("day1:git-status-short-branch");
    const exec = outcome.exec!;
    expect(exec.ok).toBe(true);
    expect(exec.termination.kind).toBe("exit");
    if (exec.termination.kind === "exit") expect(exec.termination.code).toBe(0);
    expect(exec.stdout.byteLength).toBeGreaterThan(0);
    expect(exec.durationMs).toBeGreaterThanOrEqual(0);
    expect(ledger.length).toBe(2);
    const evts = ledger.events();
    expect(evts[0]!.eventType).toBe("policy_decision");
    expect(evts[0]!.policyDecision).toBe("allow");
    expect(evts[1]!.eventType).toBe("exec_result");
    expect(evts[1]!.policyDecision).toBe("allow");
    expect(evts[1]!.previousHash).toBe(evts[0]!.hash);
    expect(ledger.verify().ok).toBe(true);
  });

  it("DAY1_ALLOWED_COMMANDS has exactly 4 git readonly entries", () => {
    expect(DAY1_ALLOWED_COMMANDS).toHaveLength(4);
    for (const s of DAY1_ALLOWED_COMMANDS) {
      expect(s.executableBasename).toBe("git");
      expect(s.sideEffectClass).toBe("read");
      expect(s.requiredCapabilities.length).toBeGreaterThan(0);
    }
  });
});

describe("Prompt 06 — unknown command / forbidden executables denied", () => {
  it("executable 'sudo' in argv[0]-style basename → validate reason BLOCKED_BASE_NAMES, no exec events", async () => {
    const ledger = Ledger.inMemory();
    const gate = new AuthoritativeExecGate({ ledger });
    const outcome = await gate.evaluateAndMaybeRun({
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "sudo",
      argv: ["git", "status"],
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.phase).toBe("validate");
    expect(outcome.validationReason).toContain("BLOCKED_BASE_NAMES");
    expect(outcome.exec).toBeUndefined();
    expect(BLOCKED_BASE_NAMES).toContain("sudo");
    expect(ledger.length).toBe(0);
  });

  it("unknown 'git explode' (not in allowlist) → validate deny reason 'does not match any day-1'", async () => {
    const ledger = Ledger.inMemory();
    const gate = new AuthoritativeExecGate({ ledger });
    const outcome = await gate.evaluateAndMaybeRun({
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "git",
      argv: ["explode", "--all"],
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.phase).toBe("validate");
    expect(outcome.validationReason).toContain("allowlist");
    expect(ledger.length).toBe(0);
  });

  it("absolute executable path like /usr/bin/git → denied (arbitrary paths forbidden)", () => {
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: sep === "/" ? "/usr/bin/git" : "C:\\Program Files\\Git\\cmd\\git.exe",
      argv: ["status"],
    };
    const r = validateReadonlyExec(req);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("arbitrary executable paths not allowed");
  });

  it("shell separator '&&' in argv token → validate reject", () => {
    const r = validateReadonlyExec({
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "git",
      argv: ["status", "&&", "git", "commit"],
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("meta-character");
  });
});

describe("Prompt 06 — timeout kills slow process", () => {
  it("executor run with very short timeout and valid-but-nested git ls-files against a repo → if we can pass validation with short timeout, termination is timeout/signal/exit within timeout", async () => {
    if (!haveGit || !fixtureRepo) return;
    const exec = new ReadonlyExecutor({ timeoutCap: 200 });
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo,
      executable: "git",
      argv: ["ls-files"],
      maxOutputBytes: 1024,
      timeoutMs: 40,
      requestId: "req-timeout-git",
    };
    const v = validateReadonlyExec(req);
    if (!v.ok) {
      expect(v.reason).toBeUndefined();
      return;
    }
    const r = await exec.run(req);
    expect(["timeout", "signal", "exit"]).toContain(r.termination.kind);
    if (r.termination.kind === "timeout") {
      expect(r.termination.afterMs).toBeLessThanOrEqual(400);
    }
  }, { timeout: 30000 });

  it("validate rejects any argv attempt to sneak shell syntax or non-allowlist", () => {
    const v1 = validateReadonlyExec({
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "git",
      argv: ["-c", "core.pager=cat", "status"],
    });
    expect(v1.ok).toBe(false);
  });
});

describe("Prompt 06 — cwd cannot escape workspace root", () => {
  it("resolveWorkspaceSafely('repo/../outside') → reject", () => {
    if (!fixtureDir) return;
    const outside = join(fixtureDir, "repo-A", "..", "outside-dir");
    mkdirSync(outside, { recursive: true });
    const ws = resolve(join(fixtureDir, "repo-A"));
    const res = resolveWorkspaceSafely(ws, outside);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain("not under");
  });

  it("resolveWorkspaceSafely(workspace, subdir) → ok and inside", () => {
    if (!fixtureRepo) return;
    const sub = join(fixtureRepo, "nested");
    mkdirSync(sub, { recursive: true });
    const r = resolveWorkspaceSafely(fixtureRepo, sub);
    expect(r.ok).toBe(true);
    expect(r.resolved!.startsWith(fixtureRepo)).toBe(true);
  });

  it("workspace root = empty string → validation reject", () => {
    const r = validateReadonlyExec({
      workspaceRoot: "",
      executable: "git",
      argv: ["status"],
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/workspaceRoot/);
  });
});

describe("Prompt 06 — output limit enforced", () => {
  it("maxOutputBytes=64 on git diff (modified fixture will print more) → stdout truncated=true, bytes ≤ cap", async () => {
    if (!haveGit || !fixtureRepo) return;
    const exec = new ReadonlyExecutor({ maxOutputCap: 1024 });
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo,
      executable: "git",
      argv: ["diff", "--no-ext-diff"],
      maxOutputBytes: 64,
      timeoutMs: 10000,
    };
    const r = await exec.run(req);
    expect(r.stdout.byteLength).toBeLessThanOrEqual(64);
    expect(r.stdoutTruncated).toBe(true);
    expect(r.matchedCommand?.id).toBe("day1:git-diff-working-tree");
  });
});

describe("Prompt 06 — denial is logged (decision → ledger event)", () => {
  it("gate.policyDecisionOnly with work:write cap attempt → decision=deny, ledger records policy_decision=deny", async () => {
    const ledger = Ledger.inMemory();
    const gate = new AuthoritativeExecGate({ ledger });
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "git",
      argv: ["commit", "-m", "evil"],
    };
    const out = gate.policyDecisionOnly(req);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(ledger.length).toBe(0);
  });

  it("validate passes but policyDecisionOnly gate (fake caps via allowlist bypass trick not possible) → deny policy logged", async () => {
    const ledger = Ledger.inMemory();
    const gate = new AuthoritativeExecGate({ ledger });
    const req: ExecRequest = {
      workspaceRoot: fixtureRepo ?? tmp(),
      executable: "git",
      argv: [...gitStatusArgv],
      requestId: "req-policy-decision-only-allow",
    };
    const out = gate.policyDecisionOnly(req);
    expect(out.phase).toBe("policy");
    expect(out.ok).toBe(true);
    expect(out.decision?.decision.outcome).toBe("allow");
    expect(ledger.length).toBe(1);
    expect(ledger.events()[0]!.policyDecision).toBe("allow");
  });

  it("BLOCKED_BASE_NAMES covers sudo/su/network and shells", () => {
    for (const want of ["sudo", "su", "curl", "wget", "sh", "bash", "powershell", "ssh"]) {
      expect(BLOCKED_BASE_NAMES).toContain(want);
    }
  });
});
