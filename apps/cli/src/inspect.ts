import { readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  AuthoritativeExecGate,
  type ExecRequest,
  resolveWorkspaceSafely,
} from "@menog/runtime-linux";

export const MANIFEST_BASE_NAMES: readonly string[] = Object.freeze([
  "package.json",
  "pnpm-workspace.yaml",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "Cargo.toml",
  "go.mod",
  "pyproject.toml",
  "requirements.txt",
  "setup.py",
  "Pipfile",
  "Gemfile",
  "mix.exs",
  "project.clj",
  "build.gradle",
  "pom.xml",
  "Makefile",
  "CMakeLists.txt",
  "Cargo.lock",
  "composer.json",
  "tsconfig.json",
  "README.md",
]);

export const TEST_FILE_HINTS: readonly RegExp[] = Object.freeze([
  /\.test\.(ts|tsx|js|jsx|mts|cts|mjs|cjs)$/i,
  /\.spec\.(ts|tsx|js|jsx|mts|cts|mjs|cjs)$/i,
  /[._-]test\.[a-z0-9]+$/i,
  /^test_[-_a-zA-Z0-9]+\.[a-z0-9]+$/i,
  /^[-_a-zA-Z0-9]+_test\.[a-z0-9]+$/i,
  /(^|[\\/])tests?([\\/]|$)/i,
  /(^|[\\/])spec([\\/]|$)/i,
]);

export function isManifestBasename(name: string): boolean {
  if (typeof name !== "string") return false;
  const lower = name.toLowerCase();
  for (const m of MANIFEST_BASE_NAMES) {
    if (m.toLowerCase() === lower) return true;
  }
  return false;
}

export function isTestFileHint(relPath: string): boolean {
  if (typeof relPath !== "string") return false;
  const normalized = relPath.replace(/\\/g, "/");
  for (const re of TEST_FILE_HINTS) {
    if (re.test(normalized)) return true;
  }
  return false;
}

export interface NativeScan {
  readonly manifests: readonly string[];
  readonly testFiles: number;
  readonly warnings: readonly string[];
}

export function safeListTopLevel(
  workspaceRoot: string,
  options: { readonly maxEntries?: number; readonly maxDepth?: number } = {}
): NativeScan {
  const maxEntries = typeof options.maxEntries === "number" ? options.maxEntries : 20000;
  const maxDepth = typeof options.maxDepth === "number" ? options.maxDepth : 6;
  const ws = resolveWorkspaceSafely(workspaceRoot);
  const manifests: string[] = [];
  const warnings: string[] = [];
  if (!ws.ok || !ws.resolved) {
    warnings.push("workspace path rejected by safe resolver");
    return { manifests: Object.freeze(manifests), testFiles: 0, warnings: Object.freeze(warnings) };
  }
  const root = ws.resolved;
  let testFiles = 0;
  let entriesSeen = 0;
  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth) return;
    if (entriesSeen >= maxEntries) {
      if (warnings.length === 0 || warnings[warnings.length - 1] !== "workspace walk truncated: too many entries") {
        warnings.push("workspace walk truncated: too many entries");
      }
      return;
    }
    let names: readonly string[];
    try {
      names = readdirSync(dir, { withFileTypes: false }) as readonly string[];
    } catch {
      return;
    }
    for (const n of names) {
      if (entriesSeen >= maxEntries) break;
      entriesSeen++;
      const full = join(dir, n);
      const rel = full.length > root.length + 1 ? full.slice(root.length + 1) : n;
      const isHidden = n.length > 0 && n[0] === "." && n !== "." && n !== "..";
      if (isHidden) {
        if (depth === 0 && isTestFileHint(n)) {
          testFiles++;
        }
        continue;
      }
      let st: { readonly isDirectory: () => boolean; readonly isFile: () => boolean } | null = null;
      try {
        st = statSync(full, { throwIfNoEntry: false }) as unknown as
          | { readonly isDirectory: () => boolean; readonly isFile: () => boolean }
          | null;
      } catch {
        st = null;
      }
      if (!st) continue;
      const isDir = st.isDirectory();
      const isFile = st.isFile();
      if (!isDir && !isFile) continue;
      if (isDir) {
        if (n === "node_modules" || n === "dist" || n === "build" || n === "target") {
          continue;
        }
        walk(full, depth + 1);
      } else if (isFile) {
        if (isManifestBasename(n)) {
          manifests.push(rel.replace(/\\/g, "/"));
        }
        if (isTestFileHint(rel)) {
          testFiles++;
        }
      }
    }
  };
  if (existsSync(root)) {
    walk(root, 0);
  }
  return {
    manifests: Object.freeze(Array.from(new Set<string>(manifests)).sort()),
    testFiles,
    warnings: Object.freeze(warnings),
  };
}

export interface GitInspection {
  readonly isRepository: boolean;
  readonly branch: string | null;
  readonly status: "clean" | "dirty" | "unknown";
  readonly counts: {
    readonly tracked: number;
    readonly modified: number;
    readonly stagedModified: number;
    readonly untracked: number;
  };
  readonly warnings: readonly string[];
}

function decodeUtf8(bytes: Uint8Array, maxBytes: number): string {
  const b =
    bytes.length > maxBytes && maxBytes > 0 ? bytes.subarray(0, maxBytes) : bytes;
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("utf8");
  }
  return new TextDecoder("utf-8").decode(b);
}

export interface PorcelainEntry {
  readonly x: string;
  readonly y: string;
  readonly path: string;
  readonly renamed: boolean;
}

export function parseStatusPorcelainV2(stdout: string): {
  readonly branch: string | null;
  readonly entries: readonly PorcelainEntry[];
} {
  let branch: string | null = null;
  const entries: PorcelainEntry[] = [];
  const lines = stdout.split("\n");
  for (const raw of lines) {
    if (raw.length === 0) continue;
    if (raw.startsWith("# ")) {
      const payload = raw.slice(2);
      const dot = payload.indexOf(".");
      if (dot < 0) continue;
      const key = payload.slice(0, dot);
      const value = payload.slice(dot + 1);
      if (key === "branch") {
        const eq = value.indexOf(" ");
        if (eq < 0) continue;
        const subk = value.slice(0, eq);
        const subv = value.slice(eq + 1);
        if (subk === "head") {
          if (subv !== "(detached)") {
            branch = subv.length === 0 ? null : subv;
          } else {
            branch = "(detached)";
          }
        }
      }
      continue;
    }
    const first = raw[0];
    if (!first) continue;
    if (first === "1" || first === "2") {
      if (raw.length < 9) continue;
      const xy = raw.slice(2, 4);
      const rest = raw.slice(8);
      entries.push({
        x: xy[0] ?? ".",
        y: xy[1] ?? ".",
        path: rest,
        renamed: first === "2",
      });
      continue;
    }
    if (first === "?") {
      if (raw.length < 3) continue;
      entries.push({
        x: "?",
        y: "?",
        path: raw.slice(2),
        renamed: false,
      });
      continue;
    }
  }
  return { branch, entries: Object.freeze(entries) };
}

export function parseStatusShortBranch(text: string): {
  readonly branch: string | null;
  readonly entries: readonly PorcelainEntry[];
} {
  let branch: string | null = null;
  const entries: PorcelainEntry[] = [];
  const lines = text.split("\n");
  for (const raw of lines) {
    if (raw.length === 0) continue;
    if (raw.startsWith("## ")) {
      const rest = raw.slice(3).trim();
      if (rest.length === 0) continue;
      const dot3 = rest.indexOf("...");
      const trackedEnd = dot3 >= 0 ? dot3 : rest.indexOf("[");
      const onlyBranch = trackedEnd > 0 ? rest.slice(0, trackedEnd).trim() : rest;
      if (onlyBranch.length > 0 && onlyBranch !== "HEAD (no branch)") {
        branch = onlyBranch;
      } else if (onlyBranch === "HEAD (no branch)" || (onlyBranch.length === 0 && rest.startsWith("HEAD"))) {
        branch = "(detached)";
      }
      continue;
    }
    if (raw.length < 3) continue;
    const xy = raw.slice(0, 2);
    const path = raw.slice(3);
    const x = xy[0] ?? ".";
    const y = xy[1] ?? ".";
    if (path.length === 0) continue;
    entries.push({ x, y, path, renamed: x === "R" });
  }
  return { branch, entries: Object.freeze(entries) };
}

export async function runGitInspection(
  gate: AuthoritativeExecGate,
  workspaceRoot: string,
  taskId?: string
): Promise<GitInspection> {
  const warnings: string[] = [];
  let isRepository = false;
  let branch: string | null = null;
  let tracked = 0;
  let modified = 0;
  let stagedModified = 0;
  let untracked = 0;

  const req = (argv: readonly string[], extra: Partial<ExecRequest> = {}): ExecRequest => ({
    workspaceRoot,
    executable: "git",
    argv: [...argv],
    timeoutMs: 15000,
    maxOutputBytes: 1024 * 1024,
    requestId: taskId,
    ...extra,
  });

  const statusOut = await gate.evaluateAndMaybeRun(
    req(["status", "--short", "--branch"])
  );
  if (statusOut.phase === "complete" && statusOut.exec && statusOut.exec.ok) {
    isRepository = true;
    const text = decodeUtf8(statusOut.exec.stdout, 8 * 1024 * 1024);
    const parsed = parseStatusShortBranch(text);
    if (parsed.branch) branch = parsed.branch;
    for (const e of parsed.entries) {
      if (e.x === "?" && e.y === "?") {
        untracked++;
      } else {
        modified++;
      }
      if (e.x !== "." && e.x !== "?" && e.x !== "!") {
        stagedModified++;
      }
    }
  } else if (statusOut.phase === "validate" || statusOut.phase === "policy" || statusOut.phase === "cwd") {
    warnings.push(
      "git status rejected: " +
        (statusOut.validationReason ?? statusOut.decision?.decision.reason ?? "unknown")
    );
  } else {
    const err = statusOut.exec
      ? decodeUtf8(statusOut.exec.stderr, 2048)
      : "unable to run git";
    if (err.length > 0) warnings.push("git status failed: " + err.slice(0, 300));
  }

  const lsOut = await gate.evaluateAndMaybeRun(req(["ls-files"]));
  if (lsOut.phase === "complete" && lsOut.exec && lsOut.exec.ok) {
    const text = decodeUtf8(lsOut.exec.stdout, 16 * 1024 * 1024);
    let count = 0;
    let start = 0;
    while (start < text.length) {
      const end = text.indexOf("\n", start);
      const line = end < 0 ? text.slice(start) : text.slice(start, end);
      if (line.length > 0) count++;
      if (end < 0) break;
      start = end + 1;
    }
    tracked = count;
    if (count > 0) isRepository = true;
  } else if (!isRepository) {
    warnings.push("git ls-files unavailable; unable to verify git repository");
  }

  if (!isRepository) {
    warnings.push("workspace is not a git repository (or git is unavailable or denied)");
  }

  let statusClass: "clean" | "dirty" | "unknown" = "unknown";
  if (isRepository) {
    statusClass = modified === 0 && untracked === 0 && stagedModified === 0 ? "clean" : "dirty";
  }

  return {
    isRepository,
    branch,
    status: statusClass,
    counts: Object.freeze({ tracked, modified, stagedModified, untracked }),
    warnings: Object.freeze(warnings),
  };
}

export function dedupe<T extends string>(arr: readonly T[]): readonly T[] {
  return Object.freeze(Array.from(new Set(arr)).sort() as T[]);
}
