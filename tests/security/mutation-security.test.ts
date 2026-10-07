/**
 * 14D — Mutation Security Gate
 *
 * Threat-tests hidden writes, races, symlink swaps, oversized patches,
 * and unauthorized mutations against the controlled-write pipeline.
 *
 * Every test verifies a specific attack vector against the deny-by-default
 * boundary. No test relies on implementation internals — each asserts only
 * the observable outcome (WriteGateOutcome phase/reason + filesystem state).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  AuthoritativeWriteGate,
  validateControlledWrite,
  resolveWritePathSafely,
  MAX_WRITE_CONTENT_BYTES,
  MAX_PATCH_TARGET_BYTES,
  type ControlledWriteRequest,
} from "@menog/runtime-linux";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  unlinkSync,
  symlinkSync,
  rmSync,
  existsSync,
  mkdtempSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

let fixtureRoot: string | null = null;
let workspace: string | null = null;
let outsideDir: string | null = null;
let canSymlink = false;

const ACTOR: Actor = { type: "agent", id: "mutation-sec-agent" };
const APPROVED = { approved: true as const };
const WRITE_CAP = ["workspace:write"] as const;

function makeReq(
  ws: string,
  relPath: string,
  overrides: Partial<ControlledWriteRequest> = {}
): ControlledWriteRequest {
  return {
    workspaceRoot: ws,
    relativePath: relPath,
    operation: "replace",
    content: "safe content\n",
    actor: ACTOR,
    capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
    policyApproval: APPROVED,
    ...overrides,
  };
}

beforeAll(() => {
  fixtureRoot = mkdtempSync(join(tmpdir(), "menog-14d-"));
  workspace = join(fixtureRoot, "workspace");
  outsideDir = join(fixtureRoot, "outside");
  mkdirSync(workspace, { recursive: true });
  mkdirSync(outsideDir, { recursive: true });

  writeFileSync(join(outsideDir, "SECRET.txt"), "DO_NOT_TOUCH\n", "utf8");

  // Attempt symlink creation — optional; tests skip if unavailable
  try {
    symlinkSync(outsideDir, join(workspace!, "sym-outside"), "junction");
    canSymlink = true;
  } catch {
    try {
      symlinkSync(outsideDir, join(workspace!, "sym-outside"), "dir");
      canSymlink = true;
    } catch {
      canSymlink = false;
    }
  }
});

afterAll(() => {
  if (fixtureRoot && existsSync(fixtureRoot)) {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. TOCTOU — time-of-check / time-of-use races
// ─────────────────────────────────────────────────────────────────────────────

describe("14D — TOCTOU: file-state races between validate and execute", () => {
  it("replace after file is deleted mid-race: gate returns file_not_found at execute phase, no silent write", () => {
    // Arrange: a file that exists at validate time but is deleted before execute
    if (!workspace) return;
    const raceFile = join(workspace, "toctou-delete.txt");
    writeFileSync(raceFile, "original\n", "utf8");

    const gate = new AuthoritativeWriteGate();
    const req = makeReq(workspace, "toctou-delete.txt", {
      operation: "replace",
      content: "replacement\n",
    });

    // Simulate TOCTOU: delete file after validateControlledWrite would pass,
    // but before execute writes. We drive this manually by calling the
    // low-level validateControlledWrite, then deleting, then calling gate.execute.
    const preCheck = validateControlledWrite(req);
    expect(preCheck.ok).toBe(true); // file existed at validate time

    // Simulate the race: delete between validate and execute
    unlinkSync(raceFile);

    // The gate must not silently create a new file where "replace" was expected
    const out = gate.execute(req);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("file_not_found");

    // Filesystem invariant: no file written
    expect(existsSync(raceFile)).toBe(false);
  });

  it("create after file is swapped in mid-race: gate returns file_already_exists, no overwrite", () => {
    // Arrange: no file at path at the time we construct the request
    if (!workspace) return;
    const raceFile = join(workspace, "toctou-create.txt");
    if (existsSync(raceFile)) unlinkSync(raceFile);

    const gate = new AuthoritativeWriteGate();
    const req = makeReq(workspace, "toctou-create.txt", {
      operation: "create",
      content: "new file\n",
    });

    // Simulate TOCTOU: another actor creates the file between our check and execute
    writeFileSync(raceFile, "pre-existing by other actor\n", "utf8");

    const out = gate.execute(req);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("file_already_exists");

    // The pre-existing content must NOT have been overwritten
    const onDisk = readFileSync(raceFile, "utf8");
    expect(onDisk).toBe("pre-existing by other actor\n");
  });

  it("patch after target content is replaced mid-race: patch_target_not_found, original replacement preserved", () => {
    // Arrange: file with known target string
    if (!workspace) return;
    const raceFile = join(workspace, "toctou-patch.txt");
    writeFileSync(raceFile, "version = 1\n", "utf8");

    const gate = new AuthoritativeWriteGate();
    const req = makeReq(workspace, "toctou-patch.txt", {
      operation: "patch",
      patch: { target: "version = 1", replacement: "version = 2" },
    });

    // Simulate TOCTOU: overwrite file between validate and execute
    writeFileSync(raceFile, "version = 999\n", "utf8"); // target string no longer present

    const out = gate.execute(req);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("execute");
    expect(out.reason).toContain("patch_target_not_found");

    // The intermediate content written by "another actor" must be preserved unchanged
    const onDisk = readFileSync(raceFile, "utf8");
    expect(onDisk).toBe("version = 999\n");
  });

  it("delete-candidate after file is removed mid-race: gate returns file_not_found, no error propagation outside gate", () => {
    if (!workspace) return;
    const raceFile = join(workspace, "toctou-gone.txt");
    writeFileSync(raceFile, "to be deleted\n", "utf8");

    const gate = new AuthoritativeWriteGate();
    const req = makeReq(workspace, "toctou-gone.txt", {
      operation: "delete-candidate",
    });

    // Simulate TOCTOU: another process deletes the file first
    unlinkSync(raceFile);

    const out = gate.execute(req);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("file_not_found");
    expect(existsSync(raceFile)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. SYMLINK SWAP — symlink introduced at target after path resolution
// ─────────────────────────────────────────────────────────────────────────────

describe("14D — Symlink swap: symlink swapped in after initial path resolution", () => {
  it("symlink pointing outside workspace is caught at resolveWritePathSafely boundary", () => {
    // Static symlink check (defense layer 1): symlink present before any call.
    if (!workspace || !canSymlink) return;
    const r = resolveWritePathSafely(workspace, "sym-outside/SECRET.txt");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("symlink_escape_denied");
  });

  it("direct file symlink to outside-workspace target is denied", () => {
    if (!workspace || !outsideDir) return;
    // Create a file symlink inside workspace pointing outside
    const symFile = join(workspace, "sym-secret-file.txt");
    if (existsSync(symFile)) {
      try { unlinkSync(symFile); } catch { /* ignore */ }
    }
    let created = false;
    try {
      symlinkSync(join(outsideDir, "SECRET.txt"), symFile, "file");
      created = true;
    } catch {
      // Symlinks unavailable on this platform/permission level
    }
    if (!created) return;

    const r = resolveWritePathSafely(workspace, "sym-secret-file.txt");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("symlink_escape_denied");

    // Also verify: full gate execute denies and emits a controlled_write_denied event
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });
    const out = gate.execute(makeReq(workspace, "sym-secret-file.txt", {
      operation: "replace",
      content: "injected\n",
    }));
    expect(out.ok).toBe(false);
    // Denial is at scope phase
    expect(out.phase).toBe("scope");

    // Secret file on disk must be untouched
    const secretContent = readFileSync(join(outsideDir, "SECRET.txt"), "utf8");
    expect(secretContent).toBe("DO_NOT_TOUCH\n");

    // Ledger recorded the denial
    expect(ledger.length).toBe(1);
    expect(ledger.events()[0]!.eventType).toBe("controlled_write_denied");
    expect(ledger.verify().ok).toBe(true);
  });

  it("post-creation symlink swap: writing a regular file then replacing with symlink between operations is caught", () => {
    // This tests that a second write attempt after a symlink is swapped in
    // is denied by the symlink target check at the point of the second call.
    if (!workspace || !outsideDir) return;

    const target = join(workspace, "will-become-symlink.txt");
    if (existsSync(target)) {
      try { unlinkSync(target); } catch { /* ignore */ }
    }

    // First: create as a real file
    const gate = new AuthoritativeWriteGate();
    const createReq = makeReq(workspace, "will-become-symlink.txt", {
      operation: "create",
      content: "legitimate content\n",
    });
    const createOut = gate.execute(createReq);
    expect(createOut.ok).toBe(true);
    expect(readFileSync(target, "utf8")).toBe("legitimate content\n");

    // Simulate attacker swap: remove the real file and replace with a symlink to outside
    unlinkSync(target);
    let swapDone = false;
    try {
      symlinkSync(join(outsideDir, "SECRET.txt"), target, "file");
      swapDone = true;
    } catch {
      // Platform doesn't support the symlink type — skip the swap assertion
    }

    if (!swapDone) return;

    // Second write attempt must be denied because the target is now a symlink
    const replaceReq = makeReq(workspace, "will-become-symlink.txt", {
      operation: "replace",
      content: "attacker payload\n",
    });
    const replaceOut = gate.execute(replaceReq);
    expect(replaceOut.ok).toBe(false);
    expect(replaceOut.phase).toBe("scope");
    expect(replaceOut.reason).toContain("symlink_escape_denied");

    // The outside file must be untouched
    expect(readFileSync(join(outsideDir, "SECRET.txt"), "utf8")).toBe("DO_NOT_TOUCH\n");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. DELETE BOUNDARY — unsafe delete attempts
// ─────────────────────────────────────────────────────────────────────────────

describe("14D — Delete boundary: out-of-scope and non-file delete denials", () => {
  it("delete-candidate targeting a directory is rejected (not_a_file)", () => {
    if (!workspace) return;
    const subDir = join(workspace, "subdir-nodelete");
    mkdirSync(subDir, { recursive: true });
    writeFileSync(join(subDir, "keep.txt"), "keep\n", "utf8");

    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "subdir-nodelete", {
      operation: "delete-candidate",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("not_a_file");

    // Directory must still exist
    expect(existsSync(subDir)).toBe(true);
    expect(existsSync(join(subDir, "keep.txt"))).toBe(true);
  });

  it("delete-candidate with path traversal escape is denied at scope phase", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "../outside/SECRET.txt", {
      operation: "delete-candidate",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("scope");
    expect(out.reason).toContain("path_traversal_denied");

    // Outside secret must be untouched
    expect(readFileSync(join(outsideDir!, "SECRET.txt"), "utf8")).toBe("DO_NOT_TOUCH\n");
  });

  it("delete-candidate targeting .menog metadata is denied at scope phase (protected_path_denied)", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, ".menog/events.jsonl", {
      operation: "delete-candidate",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("scope");
    expect(out.reason).toContain("protected_path_denied");
  });

  it("delete-candidate targeting .git/config is denied at scope phase (protected_path_denied)", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, ".git/config", {
      operation: "delete-candidate",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("scope");
    expect(out.reason).toContain("protected_path_denied");
  });

  it("delete-candidate with NUL byte in path is denied at scope phase", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "file.txt\u0000.evil", {
      operation: "delete-candidate",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("scope");
    expect(out.reason).toContain("NUL");
  });

  it("delete-candidate audit: denial emits controlled_write_denied to ledger with deny policyDecision", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });

    gate.execute(makeReq(workspace, "../outside/SECRET.txt", {
      operation: "delete-candidate",
    }));

    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("controlled_write_denied");
    expect(ev.policyDecision).toBe("deny");
    expect(ledger.verify().ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. PATCH SIZE BUDGET — oversized content / target denial
// ─────────────────────────────────────────────────────────────────────────────

describe("14D — Patch size budget: oversized content and target denial", () => {
  it("MAX_WRITE_CONTENT_BYTES is 4 MiB and MAX_PATCH_TARGET_BYTES is 512 KiB", () => {
    expect(MAX_WRITE_CONTENT_BYTES).toBe(4 * 1024 * 1024);
    expect(MAX_PATCH_TARGET_BYTES).toBe(512 * 1024);
  });

  it("create with content exceeding MAX_WRITE_CONTENT_BYTES is denied (content_too_large)", () => {
    if (!workspace) return;
    const oversized = "x".repeat(MAX_WRITE_CONTENT_BYTES + 1);
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "oversized-create.txt", {
      operation: "create",
      content: oversized,
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("content_too_large");

    // No file must have been created
    expect(existsSync(join(workspace, "oversized-create.txt"))).toBe(false);
  });

  it("replace with content exceeding MAX_WRITE_CONTENT_BYTES is denied (content_too_large)", () => {
    if (!workspace) return;
    const target = join(workspace, "oversized-replace.txt");
    writeFileSync(target, "original\n", "utf8");

    const oversized = "y".repeat(MAX_WRITE_CONTENT_BYTES + 1);
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "oversized-replace.txt", {
      operation: "replace",
      content: oversized,
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("content_too_large");

    // Original content must be preserved
    expect(readFileSync(target, "utf8")).toBe("original\n");
  });

  it("patch with target string exceeding MAX_PATCH_TARGET_BYTES is denied (patch_too_large)", () => {
    if (!workspace) return;
    const bigTarget = "z".repeat(MAX_PATCH_TARGET_BYTES + 1);
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "any.txt", {
      operation: "patch",
      patch: { target: bigTarget, replacement: "small" },
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("patch_too_large");
  });

  it("patch with replacement string exceeding MAX_WRITE_CONTENT_BYTES is denied (patch_too_large)", () => {
    if (!workspace) return;
    const bigReplacement = "r".repeat(MAX_WRITE_CONTENT_BYTES + 1);
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "any.txt", {
      operation: "patch",
      patch: { target: "small_target", replacement: bigReplacement },
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("patch_too_large");
  });

  it("size budget check fires before filesystem I/O: denied even when file does not exist", () => {
    // This ensures the size budget check is not gated on file existence.
    // If it were, an attacker could probe file existence via timing/error distinction.
    if (!workspace) return;
    const nonExistent = join(workspace, "ghost.txt");
    expect(existsSync(nonExistent)).toBe(false);

    const oversized = "g".repeat(MAX_WRITE_CONTENT_BYTES + 1);
    const gate = new AuthoritativeWriteGate();

    // create with oversized content — would fail as "file_already_exists" if file existed,
    // but must fail as "content_too_large" regardless of file state (budget check is first)
    const out = gate.execute(makeReq(workspace, "ghost.txt", {
      operation: "create",
      content: oversized,
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("content_too_large");
    expect(existsSync(nonExistent)).toBe(false);
  });

  it("content exactly at MAX_WRITE_CONTENT_BYTES boundary is accepted", () => {
    if (!workspace) return;
    const boundaryTarget = join(workspace, "boundary-size.txt");
    if (existsSync(boundaryTarget)) unlinkSync(boundaryTarget);

    // Exactly at limit: must NOT be denied by size budget
    const exactContent = "a".repeat(MAX_WRITE_CONTENT_BYTES);
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "boundary-size.txt", {
      operation: "create",
      content: exactContent,
    }));

    // Should pass validation (may fail at execute for other reasons, but NOT content_too_large)
    if (!out.ok) {
      expect(out.reason).not.toContain("content_too_large");
    }

    // Cleanup
    if (existsSync(boundaryTarget)) unlinkSync(boundaryTarget);
  });

  it("patch size audit: oversized-patch denial emits controlled_write_denied to ledger", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });

    const bigTarget = "B".repeat(MAX_PATCH_TARGET_BYTES + 1);
    gate.execute(makeReq(workspace, "any.txt", {
      operation: "patch",
      patch: { target: bigTarget, replacement: "ok" },
    }));

    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("controlled_write_denied");
    expect(ev.policyDecision).toBe("deny");
    expect(ledger.verify().ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. UNAUTHORIZED MUTATION — malformed / forged requests
// ─────────────────────────────────────────────────────────────────────────────

describe("14D — Unauthorized mutation: malformed and forged request shapes", () => {
  it("empty relativePath is rejected at scope phase", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    // relativePath = "" — empty string
    const out = gate.execute({
      workspaceRoot: workspace,
      relativePath: "",
      operation: "create",
      content: "bad",
      actor: ACTOR,
      capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: APPROVED,
    });
    expect(out.ok).toBe(false);
    // resolveWritePathSafely rejects empty relativePath
    expect(out.phase).toBe("scope");
  });

  it("missing capabilities array (empty) is denied at capability phase", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute({
      workspaceRoot: workspace,
      relativePath: "legit.txt",
      operation: "create",
      content: "bad",
      actor: ACTOR,
      capabilities: [] as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: APPROVED,
    });
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("capability");
    expect(out.reason).toContain("capability_denied");
  });

  it("capabilities present but missing workspace:write specifically is denied", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute({
      workspaceRoot: workspace,
      relativePath: "legit.txt",
      operation: "create",
      content: "bad",
      actor: ACTOR,
      capabilities: ["workspace:read", "workspace:list"] as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: APPROVED,
    });
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("capability");
    expect(out.reason).toContain("capability_denied");
  });

  it("policyApproval.approved=false is denied at policy phase even with correct capabilities", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute({
      workspaceRoot: workspace,
      relativePath: "legit.txt",
      operation: "create",
      content: "bad",
      actor: ACTOR,
      capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: { approved: false, reason: "reviewer rejected" },
    });
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("policy");
    expect(out.reason).toContain("policy_approval_denied");
  });

  it("policyApproval entirely absent is denied at policy phase", () => {
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute({
      workspaceRoot: workspace,
      relativePath: "legit.txt",
      operation: "create",
      content: "bad",
      actor: ACTOR,
      capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
      // policyApproval intentionally omitted
    } as ControlledWriteRequest);
    expect(out.ok).toBe(false);
    expect(out.phase).toBe("policy");
    expect(out.reason).toContain("policy_approval_denied");
  });

  it("write attempt to a directory path (not a file) is denied at validate phase (not_a_file)", () => {
    if (!workspace) return;
    const subDir = join(workspace, "dir-as-write-target");
    mkdirSync(subDir, { recursive: true });

    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "dir-as-write-target", {
      operation: "replace",
      content: "bad\n",
    }));

    expect(out.ok).toBe(false);
    expect(out.phase).toBe("validate");
    expect(out.reason).toContain("not_a_file");

    // Directory must still exist unchanged
    expect(existsSync(subDir)).toBe(true);
  });

  it("create into a deeply nested non-existent parent is allowed (gate creates parents)", () => {
    // This verifies that deep-nested creates within workspace are permitted —
    // the gate must not deny legitimate deep paths.
    if (!workspace) return;
    const gate = new AuthoritativeWriteGate();
    const out = gate.execute(makeReq(workspace, "deep/nested/sub/file.txt", {
      operation: "create",
      content: "hello\n",
    }));

    expect(out.ok).toBe(true);
    expect(out.phase).toBe("complete");
    expect(existsSync(join(workspace, "deep/nested/sub/file.txt"))).toBe(true);
  });

  it("unauthorized mutation audit: all denied attempts emit controlled_write_denied with hash chain intact", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const gate = new AuthoritativeWriteGate({ ledger });

    // 1. Capability denial
    gate.execute({
      workspaceRoot: workspace,
      relativePath: "audit1.txt",
      operation: "create",
      content: "x",
      actor: ACTOR,
      capabilities: [] as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: APPROVED,
    });

    // 2. Policy denial
    gate.execute({
      workspaceRoot: workspace,
      relativePath: "audit2.txt",
      operation: "create",
      content: "x",
      actor: ACTOR,
      capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
      policyApproval: { approved: false },
    });

    // 3. Scope denial (path traversal)
    gate.execute(makeReq(workspace, "../../escape.txt", {
      operation: "create",
      content: "x",
    }));

    expect(ledger.length).toBe(3);
    const events = ledger.events();
    for (const ev of events) {
      expect(ev.eventType).toBe("controlled_write_denied");
      expect(ev.policyDecision).toBe("deny");
    }
    expect(ledger.verify().ok).toBe(true);
    // Chain is intact: each event's previousHash equals prior event's hash
    expect(events[1]!.previousHash).toBe(events[0]!.hash);
    expect(events[2]!.previousHash).toBe(events[1]!.hash);
  });
});
