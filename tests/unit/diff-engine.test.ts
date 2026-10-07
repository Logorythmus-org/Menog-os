import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  generateDeterministicDiff,
  previewControlledWrite,
  normalizePathForDiff,
  isBinaryString,
  DEFAULT_MAX_DIFF_BYTES,
  DEFAULT_MAX_DIFF_LINES,
  DEFAULT_CONTEXT_LINES,
  type ControlledWriteRequest,
} from "@menog/runtime-linux";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_ACTOR: Actor = { type: "agent", id: "diff-test-agent" };
const APPROVED = { approved: true as const };
const WRITE_CAP = ["workspace:write"] as const;

function makeReq(
  workspaceRoot: string,
  relativePath: string,
  overrides: Partial<ControlledWriteRequest> = {}
): ControlledWriteRequest {
  return {
    workspaceRoot,
    relativePath,
    operation: "replace",
    content: "",
    actor: TEST_ACTOR,
    capabilities: WRITE_CAP as unknown as ControlledWriteRequest["capabilities"],
    policyApproval: APPROVED,
    ...overrides,
  };
}

let fixtureRoot: string | null = null;
let workspace: string | null = null;

beforeAll(() => {
  fixtureRoot = join(
    tmpdir(),
    "menog-diff-" + Math.random().toString(36).slice(2, 10)
  );
  workspace = join(fixtureRoot, "workspace");
  mkdirSync(workspace, { recursive: true });
});

afterAll(() => {
  if (fixtureRoot && existsSync(fixtureRoot)) {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────
// 1. STABLE DIFF (deterministic idempotency)
// ─────────────────────────────────────────
describe("14B — Diff Engine: stable/deterministic diff", () => {
  it("same inputs produce identical diffHash and unifiedDiff on multiple calls", () => {
    const before = "line one\nline two\nline three\n";
    const after = "line one\nline TWO\nline three\n";

    const r1 = generateDeterministicDiff(before, after, {
      pathA: "test.txt",
      pathB: "test.txt",
    });
    const r2 = generateDeterministicDiff(before, after, {
      pathA: "test.txt",
      pathB: "test.txt",
    });
    const r3 = generateDeterministicDiff(before, after, {
      pathA: "test.txt",
      pathB: "test.txt",
    });

    expect(r1.ok).toBe(true);
    expect(r1.hasChanges).toBe(true);
    expect(r1.diffHash).toBe(r2.diffHash);
    expect(r1.diffHash).toBe(r3.diffHash);
    expect(r1.unifiedDiff).toBe(r2.unifiedDiff);
    expect(r1.stats.additions).toBe(r2.stats.additions);
    expect(r1.stats.deletions).toBe(r2.stats.deletions);
  });

  it("diff accurately identifies added, removed, and context lines", () => {
    const before = "alpha\nbeta\ngamma\ndelta\n";
    const after = "alpha\nBETA_CHANGED\ngamma\ndelta\n";

    const r = generateDeterministicDiff(before, after, {
      pathA: "file.txt",
      pathB: "file.txt",
    });

    expect(r.ok).toBe(true);
    expect(r.hasChanges).toBe(true);
    expect(r.stats.deletions).toBe(1);
    expect(r.stats.additions).toBe(1);
    expect(r.stats.totalChanges).toBe(2);

    const allLines = r.hunks.flatMap((h) => h.lines);
    expect(allLines.some((l) => l.startsWith("-beta"))).toBe(true);
    expect(allLines.some((l) => l.startsWith("+BETA_CHANGED"))).toBe(true);
    expect(allLines.some((l) => l.startsWith(" alpha"))).toBe(true);

    expect(r.unifiedDiff).toContain("--- a/file.txt");
    expect(r.unifiedDiff).toContain("+++ b/file.txt");
    expect(r.unifiedDiff).toContain("@@");
    expect(r.isBinary).toBe(false);
  });

  it("multi-hunk diff: non-adjacent changes produce separate hunks", () => {
    // File with 20 lines; change line 2 and line 19
    const lines = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`);
    const before = lines.join("\n") + "\n";
    const afterLines = [...lines];
    afterLines[1] = "CHANGED line 2";
    afterLines[18] = "CHANGED line 19";
    const after = afterLines.join("\n") + "\n";

    const r = generateDeterministicDiff(before, after, {
      pathA: "multi.txt",
      pathB: "multi.txt",
    });

    expect(r.ok).toBe(true);
    expect(r.hunks.length).toBeGreaterThanOrEqual(2);
    expect(r.stats.additions).toBe(2);
    expect(r.stats.deletions).toBe(2);
  });

  it("create operation: /dev/null as before-path header, file content after", () => {
    const r = generateDeterministicDiff("", "hello world\n", {
      pathA: "new.txt",
      pathB: "new.txt",
      isCreate: true,
    });
    expect(r.ok).toBe(true);
    expect(r.hasChanges).toBe(true);
    expect(r.unifiedDiff).toContain("--- /dev/null");
    expect(r.unifiedDiff).toContain("+++ b/new.txt");
    expect(r.stats.additions).toBeGreaterThanOrEqual(1);
    expect(r.stats.deletions).toBe(0);
  });

  it("delete-candidate operation: /dev/null as after-path header", () => {
    const r = generateDeterministicDiff("goodbye\n", "", {
      pathA: "old.txt",
      pathB: "old.txt",
      isDelete: true,
    });
    expect(r.ok).toBe(true);
    expect(r.hasChanges).toBe(true);
    expect(r.unifiedDiff).toContain("--- a/old.txt");
    expect(r.unifiedDiff).toContain("+++ /dev/null");
    expect(r.stats.deletions).toBeGreaterThanOrEqual(1);
    expect(r.stats.additions).toBe(0);
  });
});

// ─────────────────────────────────────────
// 2. NO-CHANGE DIFF
// ─────────────────────────────────────────
describe("14B — Diff Engine: no-change diff", () => {
  it("identical before/after returns hasChanges=false, empty unifiedDiff, zero-hash", () => {
    const content = "unchanged\ncontent\nhere\n";
    const r = generateDeterministicDiff(content, content);

    expect(r.ok).toBe(true);
    expect(r.hasChanges).toBe(false);
    expect(r.hunks).toHaveLength(0);
    expect(r.unifiedDiff).toBe("");
    expect(r.diffHash).toBe("0".repeat(64));
    expect(r.stats.additions).toBe(0);
    expect(r.stats.deletions).toBe(0);
    expect(r.stats.totalChanges).toBe(0);
    expect(r.isBinary).toBe(false);
  });

  it("empty-to-empty returns no changes with zero-hash", () => {
    const r = generateDeterministicDiff("", "");
    expect(r.ok).toBe(true);
    expect(r.hasChanges).toBe(false);
    expect(r.diffHash).toBe("0".repeat(64));
  });
});

// ─────────────────────────────────────────
// 3. LARGE FILE LIMITS
// ─────────────────────────────────────────
describe("14B — Diff Engine: large-file limits", () => {
  it("rejects before content exceeding maxFileSizeBytes limit", () => {
    const large = "x".repeat(10_001);
    const r = generateDeterministicDiff(large, "small", {
      maxFileSizeBytes: 10_000,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("large_file_limit_exceeded");
  });

  it("rejects after content exceeding maxFileSizeBytes limit", () => {
    const large = "y".repeat(10_001);
    const r = generateDeterministicDiff("small", large, {
      maxFileSizeBytes: 10_000,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("large_file_limit_exceeded");
  });

  it("rejects line count exceeding maxLineCount limit", () => {
    const manyLines = Array.from({ length: 101 }, (_, i) => `line ${i}`).join("\n");
    const r = generateDeterministicDiff(manyLines, manyLines + "\nextra", {
      maxLineCount: 100,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("large_file_limit_exceeded");
  });

  it("DEFAULT_MAX_DIFF_BYTES is 2 MiB and DEFAULT_MAX_DIFF_LINES is 20,000", () => {
    expect(DEFAULT_MAX_DIFF_BYTES).toBe(2 * 1024 * 1024);
    expect(DEFAULT_MAX_DIFF_LINES).toBe(20_000);
    expect(DEFAULT_CONTEXT_LINES).toBe(3);
  });
});

// ─────────────────────────────────────────
// 4. PATH NORMALIZATION
// ─────────────────────────────────────────
describe("14B — Diff Engine: path normalization", () => {
  it("normalizePathForDiff converts backslashes to forward slashes", () => {
    expect(normalizePathForDiff("src\\foo\\bar.ts")).toBe("src/foo/bar.ts");
  });

  it("normalizePathForDiff strips leading ./", () => {
    expect(normalizePathForDiff("./src/index.ts")).toBe("src/index.ts");
    expect(normalizePathForDiff("././double.ts")).toBe("double.ts");
    // ../ is NOT stripped — normalizePathForDiff only strips ./ not ../
    expect(normalizePathForDiff("../../outside.txt")).toBe("../../outside.txt");
  });

  it("normalizePathForDiff handles empty/whitespace-only input", () => {
    expect(normalizePathForDiff("")).toBe("file");
    expect(normalizePathForDiff("  ")).toBe("file");
  });

  it("normalized paths appear in unified diff headers a/path and b/path", () => {
    const r = generateDeterministicDiff("old\n", "new\n", {
      pathA: "sub\\dir\\file.ts",
      pathB: "sub\\dir\\file.ts",
    });
    expect(r.unifiedDiff).toContain("a/sub/dir/file.ts");
    expect(r.unifiedDiff).toContain("b/sub/dir/file.ts");
  });
});

// ─────────────────────────────────────────
// 5. BINARY EXCLUSION
// ─────────────────────────────────────────
describe("14B — Diff Engine: binary content exclusion", () => {
  it("isBinaryString detects NUL byte as binary", () => {
    expect(isBinaryString("hello\u0000world")).toBe(true);
  });

  it("isBinaryString treats plain text as non-binary", () => {
    expect(isBinaryString("normal text with\nnewlines\ttabs")).toBe(false);
  });

  it("generateDeterministicDiff returns ok=false + isBinary=true for binary content", () => {
    const binary = "PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000".repeat(50);
    const r = generateDeterministicDiff(binary, "plain text");
    expect(r.ok).toBe(false);
    expect(r.isBinary).toBe(true);
    expect(r.error).toContain("binary_content_excluded");
  });
});

// ─────────────────────────────────────────
// 6. DIFF EVENT CAPTURE (previewControlledWrite)
// ─────────────────────────────────────────
describe("14B — Diff Engine: diff event capture via ledger", () => {
  it("previewControlledWrite emits diff_generated event for 'replace' with changes", () => {
    if (!workspace) return;
    const filePath = join(workspace, "preview-replace.txt");
    writeFileSync(filePath, "original content\nline 2\n", "utf8");

    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "preview-replace.txt", {
      operation: "replace",
      content: "updated content\nline 2\n",
    });

    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(true);
    expect(preview.diff).toBeDefined();
    expect(preview.diff!.ok).toBe(true);
    expect(preview.diff!.hasChanges).toBe(true);
    expect(preview.diff!.stats.additions).toBeGreaterThan(0);

    // Ledger event captured
    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("diff_generated");
    expect(ev.policyDecision).toBe("not_applicable");
    expect(ev.actor.id).toBe(TEST_ACTOR.id);
    expect(ev.verb).toBe("modify");
    const rs = ev.resultSummary as Record<string, unknown>;
    expect(rs.hasChanges).toBe(true);
    expect(typeof rs.diffHash).toBe("string");
    expect((rs.diffHash as string).length).toBe(64);
    expect(rs.isBinary).toBe(false);

    // Ledger hash chain intact
    expect(ledger.verify().ok).toBe(true);
  });

  it("previewControlledWrite emits diff_generated event with hasChanges=false for no-change replace", () => {
    if (!workspace) return;
    const filePath = join(workspace, "preview-nochange.txt");
    const content = "identical content\n";
    writeFileSync(filePath, content, "utf8");

    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "preview-nochange.txt", {
      operation: "replace",
      content,
    });

    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(true);
    expect(preview.diff!.hasChanges).toBe(false);
    expect(ledger.length).toBe(1);
    const rs = ledger.events()[0]!.resultSummary as Record<string, unknown>;
    expect(rs.hasChanges).toBe(false);
  });

  it("previewControlledWrite emits diff_generated event for 'create' operation", () => {
    if (!workspace) return;
    // Ensure file doesn't exist
    const filePath = join(workspace, "preview-create-new.txt");
    if (existsSync(filePath)) rmSync(filePath);

    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "preview-create-new.txt", {
      operation: "create",
      content: "brand new file\n",
    });

    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(true);
    expect(preview.diff!.ok).toBe(true);
    expect(preview.diff!.unifiedDiff).toContain("--- /dev/null");
    expect(ledger.length).toBe(1);
    expect(ledger.events()[0]!.eventType).toBe("diff_generated");
  });

  it("previewControlledWrite emits diff_generated event for 'delete-candidate' operation", () => {
    if (!workspace) return;
    const filePath = join(workspace, "preview-delete.txt");
    writeFileSync(filePath, "to be deleted\n", "utf8");

    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "preview-delete.txt", {
      operation: "delete-candidate",
    });

    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(true);
    expect(preview.diff!.unifiedDiff).toContain("+++ /dev/null");
    expect(ledger.length).toBe(1);
    expect(ledger.events()[0]!.eventType).toBe("diff_generated");
  });

  it("previewControlledWrite for 'patch' emits diff_generated event with correct change stats", () => {
    if (!workspace) return;
    const filePath = join(workspace, "preview-patch.txt");
    writeFileSync(filePath, "foo = 1\nbar = 2\nbaz = 3\n", "utf8");

    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "preview-patch.txt", {
      operation: "patch",
      patch: { target: "foo = 1", replacement: "foo = 99" },
    });

    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(true);
    expect(preview.diff!.stats.deletions).toBe(1);
    expect(preview.diff!.stats.additions).toBe(1);
    expect(ledger.length).toBe(1);
  });

  it("multiple sequential previews maintain hash chain integrity in ledger", () => {
    if (!workspace) return;
    const filePath = join(workspace, "chain-preview.txt");
    writeFileSync(filePath, "v1\n", "utf8");

    const ledger = AppendOnlyLedger.inMemory();

    for (let i = 0; i < 4; i++) {
      const req = makeReq(workspace, "chain-preview.txt", {
        operation: "replace",
        content: `v${i + 2}\n`,
      });
      previewControlledWrite(req, { ledger });
    }

    expect(ledger.length).toBe(4);
    expect(ledger.verify().ok).toBe(true);
    const events = ledger.events();
    expect(events[0]!.previousHash).toMatch(/^0{64}$/);
    expect(events[1]!.previousHash).toBe(events[0]!.hash);
    expect(events[2]!.previousHash).toBe(events[1]!.hash);
    expect(events[3]!.previousHash).toBe(events[2]!.hash);
  });

  it("previewControlledWrite returns ok=false when path traversal detected; no ledger event emitted", () => {
    if (!workspace) return;
    const ledger = AppendOnlyLedger.inMemory();
    const req = makeReq(workspace, "../escape.txt", {
      operation: "create",
      content: "bad",
    });
    const preview = previewControlledWrite(req, { ledger });

    expect(preview.ok).toBe(false);
    expect(preview.phase).toBe("scope");
    expect(preview.reason).toContain("path_traversal_denied");
    // No event should be emitted for a denied preview
    expect(ledger.length).toBe(0);
  });

  it("previewControlledWrite does NOT mutate the filesystem (zero side effects)", () => {
    if (!workspace) return;
    const filePath = join(workspace, "immutable-preview.txt");
    const originalContent = "original content must survive preview\n";
    writeFileSync(filePath, originalContent, "utf8");

    const req = makeReq(workspace, "immutable-preview.txt", {
      operation: "replace",
      content: "this must NOT be written to disk\n",
    });

    previewControlledWrite(req, {});

    // File on disk must be unchanged
    const onDisk = readFileSync(filePath, "utf8");
    expect(onDisk).toBe(originalContent);
    expect(existsSync(filePath)).toBe(true);
  });
});
