import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import {
  resolveWritePathSafely,
  type ControlledWriteRequest,
  type ControlledWriteOperation,
} from "./controlledWrite.js";

export const DEFAULT_MAX_DIFF_BYTES = 2 * 1024 * 1024; // 2 MiB
export const DEFAULT_MAX_DIFF_LINES = 20_000;
export const DEFAULT_CONTEXT_LINES = 3;

export interface DiffOptions {
  readonly contextLines?: number;
  readonly maxFileSizeBytes?: number;
  readonly maxLineCount?: number;
  readonly pathA?: string;
  readonly pathB?: string;
  readonly isCreate?: boolean;
  readonly isDelete?: boolean;
}

export interface DiffHunk {
  readonly oldStart: number;
  readonly oldCount: number;
  readonly newStart: number;
  readonly newCount: number;
  readonly header: string;
  readonly lines: readonly string[];
}

export interface DiffStats {
  readonly additions: number;
  readonly deletions: number;
  readonly totalChanges: number;
}

export interface DeterministicDiffResult {
  readonly ok: boolean;
  readonly hasChanges: boolean;
  readonly isBinary: boolean;
  readonly pathA: string;
  readonly pathB: string;
  readonly hunks: readonly DiffHunk[];
  readonly unifiedDiff: string;
  readonly stats: DiffStats;
  readonly diffHash: string;
  readonly error?: string;
}

export interface ControlledWritePreviewResult {
  readonly ok: boolean;
  readonly phase?: "scope" | "validate" | "diff";
  readonly reason?: string;
  readonly operation?: ControlledWriteOperation;
  readonly resolvedPath?: string;
  readonly diff?: DeterministicDiffResult;
  readonly eventId?: string;
}

function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Normalizes relative file paths for cross-platform unified diff headers.
 * Ensures consistent forward slashes and removes leading './'.
 */
export function normalizePathForDiff(rawPath: string): string {
  if (!rawPath || rawPath.trim().length === 0) {
    return "file";
  }
  let p = rawPath.replace(/\\/g, "/");
  while (p.startsWith("./")) {
    p = p.slice(2);
  }
  return p.replace(/^\/+/, "");
}

/**
 * Detects whether string content contains binary data (e.g. NUL byte or unprintable control characters).
 */
export function isBinaryString(content: string): boolean {
  if (content.includes("\u0000")) {
    return true;
  }
  const checkLen = Math.min(content.length, 4096);
  let nonPrintable = 0;
  for (let i = 0; i < checkLen; i++) {
    const code = content.charCodeAt(i);
    // Allow tabs, newlines, carriage returns
    if (code === 9 || code === 10 || code === 13) continue;
    if (code < 32 || code === 127) {
      nonPrintable++;
    }
  }
  return nonPrintable / checkLen > 0.3;
}

interface Edit {
  readonly type: "equal" | "insert" | "delete";
  readonly line: string;
  readonly oldIndex?: number;
  readonly newIndex?: number;
}

/**
 * Computes shortest edit sequence using Myers greedy diff algorithm with common prefix/suffix optimization.
 */
function computeEdits(a: readonly string[], b: readonly string[]): Edit[] {
  const N = a.length;
  const M = b.length;

  if (N === 0 && M === 0) return [];
  if (N === 0) {
    return b.map((line, idx) => ({ type: "insert" as const, line, newIndex: idx + 1 }));
  }
  if (M === 0) {
    return a.map((line, idx) => ({ type: "delete" as const, line, oldIndex: idx + 1 }));
  }

  // 1. Common prefix optimization
  let prefix = 0;
  while (prefix < N && prefix < M && a[prefix] === b[prefix]) {
    prefix++;
  }

  // 2. Common suffix optimization
  let suffix = 0;
  while (
    suffix < N - prefix &&
    suffix < M - prefix &&
    a[N - 1 - suffix] === b[M - 1 - suffix]
  ) {
    suffix++;
  }

  const edits: Edit[] = [];
  for (let i = 0; i < prefix; i++) {
    edits.push({ type: "equal", line: a[i]!, oldIndex: i + 1, newIndex: i + 1 });
  }

  const aMid = a.slice(prefix, N - suffix);
  const bMid = b.slice(prefix, M - suffix);
  const nMid = aMid.length;
  const mMid = bMid.length;

  if (nMid > 0 || mMid > 0) {
    if (nMid === 0) {
      for (let i = 0; i < mMid; i++) {
        edits.push({
          type: "insert",
          line: bMid[i]!,
          newIndex: prefix + i + 1,
        });
      }
    } else if (mMid === 0) {
      for (let i = 0; i < nMid; i++) {
        edits.push({
          type: "delete",
          line: aMid[i]!,
          oldIndex: prefix + i + 1,
        });
      }
    } else {
      // Myers diff algorithm on mid slice
      const MAX = nMid + mMid;
      const vOffset = MAX;
      const v = new Int32Array(2 * MAX + 1);
      const trace: Int32Array[] = [];

      v[vOffset + 1] = 0;

      let foundD = -1;
      for (let d = 0; d <= MAX; d++) {
        const vCopy = new Int32Array(v);
        trace.push(vCopy);

        for (let k = -d; k <= d; k += 2) {
          let x: number;
          const vPrev = v[vOffset + k - 1] ?? 0;
          const vNext = v[vOffset + k + 1] ?? 0;
          if (k === -d || (k !== d && vPrev < vNext)) {
            x = vNext;
          } else {
            x = vPrev + 1;
          }
          let y = x - k;

          while (x < nMid && y < mMid && aMid[x] === bMid[y]) {
            x++;
            y++;
          }

          v[vOffset + k] = x;

          if (x >= nMid && y >= mMid) {
            foundD = d;
            break;
          }
        }
        if (foundD !== -1) break;
      }

      // Backtrack to extract edit path
      let x = nMid;
      let y = mMid;
      const midEditsReversed: Edit[] = [];

      for (let d = trace.length - 1; d >= 0; d--) {
        const currentV = trace[d]!;
        const k = x - y;
        let prevK: number;

        const cvPrev = currentV[vOffset + k - 1] ?? 0;
        const cvNext = currentV[vOffset + k + 1] ?? 0;
        if (k === -d || (k !== d && cvPrev < cvNext)) {
          prevK = k + 1;
        } else {
          prevK = k - 1;
        }

        const prevX = currentV[vOffset + prevK] ?? 0;
        const prevY = prevX - prevK;

        while (x > prevX && y > prevY) {
          midEditsReversed.push({
            type: "equal",
            line: aMid[x - 1]!,
            oldIndex: prefix + x,
            newIndex: prefix + y,
          });
          x--;
          y--;
        }

        if (d > 0) {
          if (x === prevX) {
            midEditsReversed.push({
              type: "insert",
              line: bMid[y - 1]!,
              newIndex: prefix + y,
            });
            y--;
          } else if (y === prevY) {
            midEditsReversed.push({
              type: "delete",
              line: aMid[x - 1]!,
              oldIndex: prefix + x,
            });
            x--;
          }
        }
      }

      midEditsReversed.reverse();
      for (const edit of midEditsReversed) {
        edits.push(edit);
      }
    }
  }

  for (let i = 0; i < suffix; i++) {
    const oldIdx = N - suffix + i + 1;
    const newIdx = M - suffix + i + 1;
    edits.push({
      type: "equal",
      line: a[N - suffix + i]!,
      oldIndex: oldIdx,
      newIndex: newIdx,
    });
  }

  return edits;
}

/**
 * Builds unified diff hunks from edit operations with configurable context lines.
 */
function buildHunks(edits: readonly Edit[], contextLines: number): DiffHunk[] {
  const changeIndices: number[] = [];
  for (let i = 0; i < edits.length; i++) {
    if (edits[i]!.type !== "equal") {
      changeIndices.push(i);
    }
  }

  if (changeIndices.length === 0) {
    return [];
  }

  // Group changes within 2 * contextLines into clusters
  const groups: Array<{ start: number; end: number }> = [];
  let currentGroup = {
    start: Math.max(0, changeIndices[0]! - contextLines),
    end: Math.min(edits.length - 1, changeIndices[0]! + contextLines),
  };

  for (let i = 1; i < changeIndices.length; i++) {
    const idx = changeIndices[i]!;
    const nextStart = Math.max(0, idx - contextLines);
    const nextEnd = Math.min(edits.length - 1, idx + contextLines);

    if (nextStart <= currentGroup.end + 1) {
      currentGroup.end = nextEnd;
    } else {
      groups.push(currentGroup);
      currentGroup = { start: nextStart, end: nextEnd };
    }
  }
  groups.push(currentGroup);

  const hunks: DiffHunk[] = [];

  for (const group of groups) {
    const hunkEdits = edits.slice(group.start, group.end + 1);
    let oldStart = 0;
    let oldCount = 0;
    let newStart = 0;
    let newCount = 0;
    let setOldStart = false;
    let setNewStart = false;

    const lines: string[] = [];

    for (const e of hunkEdits) {
      if (e.type === "equal") {
        if (!setOldStart && e.oldIndex !== undefined) {
          oldStart = e.oldIndex;
          setOldStart = true;
        }
        if (!setNewStart && e.newIndex !== undefined) {
          newStart = e.newIndex;
          setNewStart = true;
        }
        oldCount++;
        newCount++;
        lines.push(" " + e.line);
      } else if (e.type === "delete") {
        if (!setOldStart && e.oldIndex !== undefined) {
          oldStart = e.oldIndex;
          setOldStart = true;
        }
        oldCount++;
        lines.push("-" + e.line);
      } else if (e.type === "insert") {
        if (!setNewStart && e.newIndex !== undefined) {
          newStart = e.newIndex;
          setNewStart = true;
        }
        newCount++;
        lines.push("+" + e.line);
      }
    }

    if (!setOldStart) oldStart = 1;
    if (!setNewStart) newStart = 1;

    const oldRange = oldCount === 1 ? `${oldStart}` : `${oldStart},${oldCount}`;
    const newRange = newCount === 1 ? `${newStart}` : `${newStart},${newCount}`;
    const header = `@@ -${oldRange} +${newRange} @@`;

    hunks.push({
      oldStart,
      oldCount,
      newStart,
      newCount,
      header,
      lines,
    });
  }

  return hunks;
}

/**
 * Generates deterministic unified diff between before and after text contents.
 * Text-first scope: strictly detects and excludes binary content.
 * Enforces configurable file size and line count limits.
 */
export function generateDeterministicDiff(
  before: string,
  after: string,
  options: DiffOptions = {}
): DeterministicDiffResult {
  const maxBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_DIFF_BYTES;
  const maxLines = options.maxLineCount ?? DEFAULT_MAX_DIFF_LINES;
  const context = options.contextLines ?? DEFAULT_CONTEXT_LINES;

  const rawPathA = options.isCreate ? "/dev/null" : options.pathA ?? "file";
  const rawPathB = options.isDelete ? "/dev/null" : options.pathB ?? "file";

  const pathA = options.isCreate ? "/dev/null" : `a/${normalizePathForDiff(rawPathA)}`;
  const pathB = options.isDelete ? "/dev/null" : `b/${normalizePathForDiff(rawPathB)}`;

  // 1. Binary check
  if (isBinaryString(before) || isBinaryString(after)) {
    return {
      ok: false,
      hasChanges: false,
      isBinary: true,
      pathA,
      pathB,
      hunks: [],
      unifiedDiff: "",
      stats: { additions: 0, deletions: 0, totalChanges: 0 },
      diffHash: "0".repeat(64),
      error: "binary_content_excluded: binary mutation not supported in text diff engine",
    };
  }

  // 2. Large file limits check
  const beforeBytes = Buffer.byteLength(before, "utf8");
  const afterBytes = Buffer.byteLength(after, "utf8");

  if (beforeBytes > maxBytes || afterBytes > maxBytes) {
    return {
      ok: false,
      hasChanges: false,
      isBinary: false,
      pathA,
      pathB,
      hunks: [],
      unifiedDiff: "",
      stats: { additions: 0, deletions: 0, totalChanges: 0 },
      diffHash: "0".repeat(64),
      error: `large_file_limit_exceeded: content size (${Math.max(beforeBytes, afterBytes)} bytes) exceeds maximum limit (${maxBytes} bytes)`,
    };
  }

  // 3. No-change fast path
  if (before === after) {
    return {
      ok: true,
      hasChanges: false,
      isBinary: false,
      pathA,
      pathB,
      hunks: [],
      unifiedDiff: "",
      stats: { additions: 0, deletions: 0, totalChanges: 0 },
      diffHash: "0".repeat(64),
    };
  }

  // 4. Split into lines
  const linesA = before.length === 0 ? [] : before.split("\n");
  const linesB = after.length === 0 ? [] : after.split("\n");

  if (linesA.length > maxLines || linesB.length > maxLines) {
    return {
      ok: false,
      hasChanges: false,
      isBinary: false,
      pathA,
      pathB,
      hunks: [],
      unifiedDiff: "",
      stats: { additions: 0, deletions: 0, totalChanges: 0 },
      diffHash: "0".repeat(64),
      error: `large_file_limit_exceeded: line count (${Math.max(linesA.length, linesB.length)}) exceeds maximum limit (${maxLines} lines)`,
    };
  }

  // 5. Compute edits & hunks
  const edits = computeEdits(linesA, linesB);
  const hunks = buildHunks(edits, context);

  let additions = 0;
  let deletions = 0;

  for (const e of edits) {
    if (e.type === "insert") additions++;
    else if (e.type === "delete") deletions++;
  }

  const stats: DiffStats = {
    additions,
    deletions,
    totalChanges: additions + deletions,
  };

  // 6. Format unified diff
  const headerLines = [`--- ${pathA}`, `+++ ${pathB}`];
  const hunkOutput: string[] = [];

  for (const h of hunks) {
    hunkOutput.push(h.header);
    for (const l of h.lines) {
      hunkOutput.push(l);
    }
  }

  const unifiedDiff = [...headerLines, ...hunkOutput].join("\n") + "\n";
  const diffHash = sha256Hex(unifiedDiff);

  return {
    ok: true,
    hasChanges: true,
    isBinary: false,
    pathA,
    pathB,
    hunks,
    unifiedDiff,
    stats,
    diffHash,
  };
}

export interface PreviewControlledWriteOptions extends DiffOptions {
  readonly ledger?: AppendOnlyLedger | null;
}

/**
 * Previews a controlled write request by generating the exact diff before acceptance.
 * Verifies path safety, reads current content, simulates mutation in memory,
 * and emits an audit event to the ledger if provided.
 * ZERO filesystem mutation occurs during preview.
 */
export function previewControlledWrite(
  req: ControlledWriteRequest,
  options: PreviewControlledWriteOptions = {}
): ControlledWritePreviewResult {
  const pathCheck = resolveWritePathSafely(req.workspaceRoot, req.relativePath);
  if (!pathCheck.ok || !pathCheck.resolvedPath) {
    return {
      ok: false,
      phase: "scope",
      reason: pathCheck.reason,
      operation: req.operation,
    };
  }

  const resolved = pathCheck.resolvedPath;
  const op = req.operation;
  const exists = existsSync(resolved);

  let before = "";
  let after = "";
  let isCreate = false;
  let isDelete = false;

  switch (op) {
    case "create": {
      if (exists) {
        return {
          ok: false,
          phase: "validate",
          reason: `file_already_exists: cannot 'create' existing file '${req.relativePath}'; use 'replace' or 'patch'`,
          operation: op,
          resolvedPath: resolved,
        };
      }
      before = "";
      after = req.content ?? "";
      isCreate = true;
      break;
    }

    case "replace": {
      if (!exists) {
        return {
          ok: false,
          phase: "validate",
          reason: `file_not_found: cannot 'replace' non-existent file '${req.relativePath}'`,
          operation: op,
          resolvedPath: resolved,
        };
      }
      before = readFileSync(resolved, "utf8");
      after = req.content ?? "";
      break;
    }

    case "patch": {
      if (!exists) {
        return {
          ok: false,
          phase: "validate",
          reason: `file_not_found: cannot 'patch' non-existent file '${req.relativePath}'`,
          operation: op,
          resolvedPath: resolved,
        };
      }
      if (!req.patch || typeof req.patch.target !== "string" || typeof req.patch.replacement !== "string") {
        return {
          ok: false,
          phase: "validate",
          reason: "patch must provide 'target' and 'replacement' strings",
          operation: op,
          resolvedPath: resolved,
        };
      }
      before = readFileSync(resolved, "utf8");
      const { target, replacement, expectedOccurrences = 1 } = req.patch;

      let matchCount = 0;
      let pos = 0;
      while ((pos = before.indexOf(target, pos)) !== -1) {
        matchCount++;
        pos += target.length;
      }

      if (matchCount === 0) {
        return {
          ok: false,
          phase: "validate",
          reason: `patch_target_not_found: target string not found in '${req.relativePath}'`,
          operation: op,
          resolvedPath: resolved,
        };
      }

      if (matchCount !== expectedOccurrences) {
        return {
          ok: false,
          phase: "validate",
          reason: `patch_occurrence_mismatch: target found ${matchCount} times, expected ${expectedOccurrences}`,
          operation: op,
          resolvedPath: resolved,
        };
      }

      after = before.replace(target, replacement);
      break;
    }

    case "delete-candidate": {
      if (!exists) {
        return {
          ok: false,
          phase: "validate",
          reason: `file_not_found: cannot 'delete-candidate' non-existent file '${req.relativePath}'`,
          operation: op,
          resolvedPath: resolved,
        };
      }
      before = readFileSync(resolved, "utf8");
      after = "";
      isDelete = true;
      break;
    }

    default:
      return {
        ok: false,
        phase: "validate",
        reason: `invalid_operation: '${String(op)}' is not a supported write operation`,
      };
  }

  const diff = generateDeterministicDiff(before, after, {
    ...options,
    pathA: req.relativePath,
    pathB: req.relativePath,
    isCreate,
    isDelete,
  });

  if (!diff.ok) {
    return {
      ok: false,
      phase: "diff",
      reason: diff.error,
      operation: op,
      resolvedPath: resolved,
      diff,
    };
  }

  let eventId: string | undefined;
  if (options.ledger) {
    eventId = "diff-" + randomUUID().replace(/-/g, "").slice(0, 20);
    options.ledger.append({
      eventId,
      timestamp: new Date().toISOString(),
      eventType: "diff_generated",
      actor: req.actor,
      workspaceId: req.workspaceRoot,
      taskId: req.taskId,
      verb: "modify",
      capability: "workspace:write",
      policyDecision: "not_applicable",
      inputSummary: {
        operation: req.operation,
        relativePath: req.relativePath,
        requestId: req.requestId ?? null,
      },
      resultSummary: {
        hasChanges: diff.hasChanges,
        additions: diff.stats.additions,
        deletions: diff.stats.deletions,
        diffHash: diff.diffHash,
        isBinary: diff.isBinary,
      },
    });
  }

  return {
    ok: true,
    operation: op,
    resolvedPath: resolved,
    diff,
    eventId,
  };
}
