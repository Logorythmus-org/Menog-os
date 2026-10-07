import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  AuthoritativeWriteGate,
  validateControlledWrite,
  resolveWritePathSafely,
  type ControlledWriteRequest,
} from "@menog/runtime-linux";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  rmSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let fixtureRoot: string | null = null;
let workspace: string | null = null;
let outsideDir: string | null = null;
let canSymlink = false;

const TEST_ACTOR: Actor = { type: "agent", id: "controlled-writer-agent" };
const HUMAN_APPROVER: Actor = { type: "human", id: "operator-0" };

function tmp(): string {
  const p = join(
    tmpdir(),
    "menog-write-sec-" + Math.random().toString(36).slice(2, 10)
  );
  mkdirSync(p, { recursive: true });
  return p;
}

beforeAll(() => {
  fixtureRoot = tmp();
  workspace = join(fixtureRoot, "workspace");
  outsideDir = join(fixtureRoot, "outside");
  mkdirSync(workspace, { recursive: true });
  mkdirSync(outsideDir, { recursive: true });

  writeFileSync(
    join(outsideDir, "CRITICAL_SYSTEM.txt"),
    "TOP_SECRET_DO_NOT_MUTATE\n",
    "utf8"
  );
  writeFileSync(
    join(workspace, "existing.txt"),
    "Initial content line 1\nInitial content line 2\n",
    "utf8"
  );

  // Try creating symlink for escape testing
  try {
    const symDir = join(workspace, "sym-outside-dir");
    symlinkSync(outsideDir, symDir, "junction");
    canSymlink = true;
  } catch {
    try {
      const symDir = join(workspace, "sym-outside-dir");
      symlinkSync(outsideDir, symDir, "dir");
      canSymlink = true;
    } catch {
      canSymlink = false;
    }
  }

  if (canSymlink) {
    try {
      const symFile = join(workspace, "sym-outside-file.txt");
      symlinkSync(join(outsideDir, "CRITICAL_SYSTEM.txt"), symFile, "file");
    } catch {
      // Junction/dir supported but maybe not file symlink
    }
  }
});

afterAll(() => {
  if (fixtureRoot && existsSync(fixtureRoot)) {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

describe("14A — Controlled Write: Path Traversal & Scope Denial", () => {
  it("rejects path traversal attempting to escape workspace via ../", () => {
    if (!workspace) return;
    const r1 = resolveWritePathSafely(workspace, "../outside.txt");
    expect(r1.ok).toBe(false);
    expect(r1.reason).toContain("path_traversal_denied");

    const r2 = resolveWritePathSafely(workspace, "sub/../../outside.txt");
    expect(r2.ok).toBe(false);
    expect(r2.reason).toContain("path_traversal_denied");
  });

  it("rejects absolute paths passed as relativePath", () => {
    if (!workspace) return;
    const absPath = process.platform === "win32" ? "C:\\Windows\\win.ini" : "/etc/shadow";
    const r = resolveWritePathSafely(workspace, absPath);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("path_traversal_denied");
  });

  it("rejects NUL byte injection in write path", () => {
    if (!workspace) return;
    const r = resolveWritePathSafely(workspace, "file.txt\u0000.evil");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("NUL");
  });

  it("rejects writes targeting protected system metadata directories (.git, .menog)", () => {
    if (!workspace) return;
    const rGit = resolveWritePathSafely(workspace, ".git/config");
    expect(rGit.ok).toBe(false);
    expect(rGit.reason).toContain("protected_path_denied");

    const rMenog = resolveWritePathSafely(workspace, ".menog/ledger.jsonl");
    expect(rMenog.ok).toBe(false);
    expect(rMenog.reason).toContain("protected_path_denied");
  });
});

describe("14A — Controlled Write: Symlink Escape Denial", () => {
  it("rejects writes attempting to write through directory symlink pointing outside workspace", () => {
    if (!workspace || !canSymlink) return;
    const r = resolveWritePathSafely(workspace, "sym-outside-dir/injected.txt");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("symlink_escape_denied");
  });

  it("rejects direct mutation of symbolic link targets", () => {
    if (!workspace || !canSymlink) return;
    const symFile = join(workspace, "sym-outside-file.txt");
    if (!existsSync(symFile)) return;

    const r = resolveWritePathSafely(workspace, "sym-outside-file.txt");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("symlink_escape_denied");
  });
});

describe("14A — Controlled Write: Capability & Policy Gate", () => {
  it("denies write request when caller lacks 'workspace:write' capability", () => {
    if (!workspace) return;
    const req: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "newfile.txt",
      operation: "create",
      content: "test",
      actor: TEST_ACTOR,
      capabilities: ["workspace:read", "workspace:list"], // missing workspace:write
      policyApproval: { approved: true },
    };

    const val = validateControlledWrite(req);
    expect(val.ok).toBe(false);
    expect(val.phase).toBe("capability");
    expect(val.reason).toContain("capability_denied");
  });

  it("denies write request when explicit policy approval is missing or false", () => {
    if (!workspace) return;
    const reqNoApproval: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "newfile.txt",
      operation: "create",
      content: "test",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
    };

    const val1 = validateControlledWrite(reqNoApproval);
    expect(val1.ok).toBe(false);
    expect(val1.phase).toBe("policy");
    expect(val1.reason).toContain("policy_approval_denied");

    const reqFalseApproval: ControlledWriteRequest = {
      ...reqNoApproval,
      policyApproval: { approved: false, reason: "Rejected by human reviewer" },
    };

    const val2 = validateControlledWrite(reqFalseApproval);
    expect(val2.ok).toBe(false);
    expect(val2.phase).toBe("policy");
    expect(val2.reason).toContain("policy_approval_denied");
  });
});

describe("14A — Controlled Write: Operation Semantics (create/patch/replace/delete-candidate)", () => {
  it("create: creates a new file, but fails if file already exists", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();

    const req: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "created-sub/hello.txt",
      operation: "create",
      content: "Hello World!\n",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true, approver: HUMAN_APPROVER, approvalId: "appr-01" },
    };

    const res1 = gate.execute(req);
    expect(res1.ok).toBe(true);
    expect(res1.phase).toBe("complete");
    expect(res1.result?.bytesWritten).toBe(13);
    expect(existsSync(join(workspace, "created-sub/hello.txt"))).toBe(true);
    expect(readFileSync(join(workspace, "created-sub/hello.txt"), "utf8")).toBe("Hello World!\n");

    // Creating again must fail (file already exists)
    const res2 = gate.execute(req);
    expect(res2.ok).toBe(false);
    expect(res2.phase).toBe("validate");
    expect(res2.reason).toContain("file_already_exists");
  });

  it("replace: replaces an existing file, but fails if file does not exist", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();

    const reqNotFound: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "does-not-exist.txt",
      operation: "replace",
      content: "replacement text",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    };
    const resNotFound = gate.execute(reqNotFound);
    expect(resNotFound.ok).toBe(false);
    expect(resNotFound.phase).toBe("validate");
    expect(resNotFound.reason).toContain("file_not_found");

    const reqReplace: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "existing.txt",
      operation: "replace",
      content: "Completely new replaced content\n",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    };
    const resReplace = gate.execute(reqReplace);
    expect(resReplace.ok).toBe(true);
    expect(resReplace.phase).toBe("complete");
    expect(readFileSync(join(workspace, "existing.txt"), "utf8")).toBe("Completely new replaced content\n");
  });

  it("patch: replaces targeted content, fails on mismatch or missing target", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    writeFileSync(join(workspace, "patchable.txt"), "const port = 3000;\nconst host = 'localhost';\n", "utf8");

    // Mismatched target
    const reqMismatch: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "patchable.txt",
      operation: "patch",
      patch: { target: "const port = 8080;", replacement: "const port = 9000;" },
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    };
    const resMismatch = gate.execute(reqMismatch);
    expect(resMismatch.ok).toBe(false);
    expect(resMismatch.phase).toBe("execute");
    expect(resMismatch.reason).toContain("patch_target_not_found");

    // Valid patch
    const reqPatch: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "patchable.txt",
      operation: "patch",
      patch: { target: "const port = 3000;", replacement: "const port = 8080;" },
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    };
    const resPatch = gate.execute(reqPatch);
    expect(resPatch.ok).toBe(true);
    expect(resPatch.phase).toBe("complete");
    expect(readFileSync(join(workspace, "patchable.txt"), "utf8")).toBe("const port = 8080;\nconst host = 'localhost';\n");
  });

  it("delete-candidate: safely unlinks candidate file, fails if not found", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    writeFileSync(join(workspace, "to-delete.txt"), "temporary file\n", "utf8");

    const reqDelete: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "to-delete.txt",
      operation: "delete-candidate",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    };

    const resDelete = gate.execute(reqDelete);
    expect(resDelete.ok).toBe(true);
    expect(resDelete.phase).toBe("complete");
    expect(existsSync(join(workspace, "to-delete.txt"))).toBe(false);

    // Deleting non-existent file fails
    const resDeleteAgain = gate.execute(reqDelete);
    expect(resDeleteAgain.ok).toBe(false);
    expect(resDeleteAgain.phase).toBe("validate");
    expect(resDeleteAgain.reason).toContain("file_not_found");
  });
});

describe("14A — Controlled Write: Audit Ledger Events", () => {
  it("records denied write attempts to the event ledger with intact hash chain", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });

    // 1. Path traversal denial
    gate.execute({
      workspaceRoot: workspace,
      relativePath: "../escape.txt",
      operation: "create",
      content: "bad",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: true },
    });

    // 2. Capability denial
    gate.execute({
      workspaceRoot: workspace,
      relativePath: "denied.txt",
      operation: "create",
      content: "bad",
      actor: TEST_ACTOR,
      capabilities: ["workspace:read"],
      policyApproval: { approved: true },
    });

    // 3. Policy approval denial
    gate.execute({
      workspaceRoot: workspace,
      relativePath: "denied.txt",
      operation: "create",
      content: "bad",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: { approved: false },
    });

    expect(ledger.length).toBe(3);
    const events = ledger.events();
    for (const ev of events) {
      expect(ev.eventType).toBe("controlled_write_denied");
      expect(ev.policyDecision).toBe("deny");
      expect(ev.actor.id).toBe(TEST_ACTOR.id);
    }

    const verify = ledger.verify();
    expect(verify.ok).toBe(true);
    expect(verify.verifiedCount).toBe(3);
  });

  it("records successful write execution to the event ledger with full provenance", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });

    const req: ControlledWriteRequest = {
      workspaceRoot: workspace,
      relativePath: "audit-recorded.txt",
      operation: "create",
      content: "audited file content\n",
      actor: TEST_ACTOR,
      capabilities: ["workspace:write"],
      policyApproval: {
        approved: true,
        approvalId: "approval-14a-test",
        approver: HUMAN_APPROVER,
      },
      taskId: "task-write-001",
    };

    const out = gate.execute(req);
    expect(out.ok).toBe(true);
    expect(ledger.length).toBe(1);

    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("controlled_write_executed");
    expect(ev.policyDecision).toBe("allow");
    expect(ev.actor.id).toBe(TEST_ACTOR.id);
    expect(ev.taskId).toBe("task-write-001");
    expect(ev.verb).toBe("modify");
    expect(ev.capability).toBe("workspace:write");

    const rs = ev.resultSummary as Record<string, unknown>;
    expect(rs.operation).toBe("create");
    expect(rs.approvalId).toBe("approval-14a-test");
    expect(typeof rs.newHash).toBe("string");
    expect(rs.bytesWritten).toBe(Buffer.byteLength("audited file content\n", "utf8"));

    expect(ledger.verify().ok).toBe(true);
  });
});
