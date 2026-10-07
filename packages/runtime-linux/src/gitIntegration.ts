import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Actor } from "@menog/core";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import {
  AuthoritativeExecGate,
  type GateOutcome,
} from "./gate.js";
import {
  resolveWorkspaceSafely,
  type ExecRequest,
} from "./validate.js";

export type GitRepoState = "clean" | "dirty" | "unknown";

export interface GitFileStatus {
  readonly path: string;
  readonly indexStatus: string;
  readonly workingStatus: string;
  readonly isStaged: boolean;
  readonly isModified: boolean;
  readonly isUntracked: boolean;
  readonly isDeleted: boolean;
  readonly isRenamed: boolean;
}

export interface GitStatusSummary {
  readonly state: GitRepoState;
  readonly branch: string | null;
  readonly trackedCount: number;
  readonly modifiedCount: number;
  readonly stagedCount: number;
  readonly untrackedCount: number;
  readonly deletedCount: number;
  readonly files: readonly GitFileStatus[];
  readonly rawStdout: string;
}

export interface GitDiffSummary {
  readonly hasChanges: boolean;
  readonly filesChanged: number;
  readonly rawDiff: string;
  readonly files: readonly string[];
}

export interface GitStatusQueryResult {
  readonly ok: boolean;
  readonly status?: GitStatusSummary;
  readonly error?: string;
  readonly phase?: "cwd" | "validate" | "policy" | "execute" | "complete";
}

export interface GitDiffQueryResult {
  readonly ok: boolean;
  readonly diff?: GitDiffSummary;
  readonly error?: string;
  readonly phase?: "cwd" | "validate" | "policy" | "execute" | "complete";
}

export interface GitInspectionResult {
  readonly ok: boolean;
  readonly workspaceRoot: string;
  readonly status: GitStatusSummary;
  readonly workingDiff: GitDiffSummary;
  readonly stagedDiff: GitDiffSummary;
  readonly error?: string;
  readonly phase?: "cwd" | "validate" | "policy" | "execute" | "complete";
}

export interface ReadonlyGitServiceOptions {
  readonly gate?: AuthoritativeExecGate;
  readonly ledger?: AppendOnlyLedger | null;
  readonly actor?: Actor;
}

const FORBIDDEN_GIT_SUBCOMMANDS: readonly string[] = Object.freeze([
  "commit",
  "push",
  "pull",
  "merge",
  "rebase",
  "reset",
  "cherry-pick",
  "revert",
  "tag",
  "branch",
  "checkout",
  "switch",
  "restore",
  "clean",
  "stash",
  "apply",
  "am",
  "filter-branch",
  "replace",
  "init",
  "clone",
  "remote",
  "submodule",
  "config",
]);

const FORBIDDEN_GIT_FLAGS: readonly string[] = Object.freeze([
  "-f",
  "--force",
  "--hard",
  "--amend",
  "--delete",
  "-D",
  "-d",
]);

function decodeUtf8(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("utf8");
  }
  return new TextDecoder("utf-8").decode(bytes);
}

/**
 * Checks whether a repository directory exists and contains a .git folder or file.
 */
export function isGitRepository(workspaceRoot: string): boolean {
  if (!existsSync(workspaceRoot)) return false;
  const gitDir = join(workspaceRoot, ".git");
  return existsSync(gitDir);
}

/**
 * Parses `git status --short --branch` output into structured GitStatusSummary.
 */
export function parseGitStatusShort(rawStdout: string): GitStatusSummary {
  let branch: string | null = null;
  const files: GitFileStatus[] = [];
  const lines = rawStdout.split("\n");

  let modifiedCount = 0;
  let stagedCount = 0;
  let untrackedCount = 0;
  let deletedCount = 0;

  for (const raw of lines) {
    if (raw.length === 0) continue;

    if (raw.startsWith("## ")) {
      const rest = raw.slice(3).trim();
      if (rest.length > 0) {
        const dot3 = rest.indexOf("...");
        const bracket = rest.indexOf("[");
        const end = dot3 >= 0 ? dot3 : bracket >= 0 ? bracket : rest.length;
        const b = rest.slice(0, end).trim();
        if (b.length > 0 && b !== "HEAD (no branch)" && !b.startsWith("Initial commit on") && !b.startsWith("No commits yet on")) {
          branch = b;
        } else if (b.startsWith("No commits yet on ")) {
          branch = b.slice("No commits yet on ".length).trim();
        } else if (b.startsWith("Initial commit on ")) {
          branch = b.slice("Initial commit on ".length).trim();
        }
      }
      continue;
    }

    if (raw.startsWith("?? ")) {
      const path = raw.slice(3).trim();
      untrackedCount++;
      files.push({
        path,
        indexStatus: "?",
        workingStatus: "?",
        isStaged: false,
        isModified: false,
        isUntracked: true,
        isDeleted: false,
        isRenamed: false,
      });
      continue;
    }

    if (raw.length >= 3) {
      const idx = raw[0] ?? " ";
      const work = raw[1] ?? " ";
      let path = raw.slice(3).trim();
      const isRenamed = idx === "R" || idx === "C";

      if (path.includes(" -> ")) {
        const parts = path.split(" -> ");
        path = parts[1] ?? path;
      }

      const isStaged = idx !== " " && idx !== "?";
      const isModified = work === "M" || idx === "M";
      const isDeleted = work === "D" || idx === "D";

      if (isStaged) stagedCount++;
      if (isModified) modifiedCount++;
      if (isDeleted) deletedCount++;

      files.push({
        path,
        indexStatus: idx,
        workingStatus: work,
        isStaged,
        isModified,
        isUntracked: false,
        isDeleted,
        isRenamed,
      });
    }
  }

  const isDirty = untrackedCount > 0 || modifiedCount > 0 || stagedCount > 0 || deletedCount > 0;
  const state: GitRepoState = isDirty ? "dirty" : "clean";

  return {
    state,
    branch,
    trackedCount: files.length - untrackedCount,
    modifiedCount,
    stagedCount,
    untrackedCount,
    deletedCount,
    files: Object.freeze(files),
    rawStdout,
  };
}

/**
 * Parses `git diff` output to extract changed files and count.
 */
export function parseGitDiff(rawDiff: string): GitDiffSummary {
  const fileSet = new Set<string>();
  const lines = rawDiff.split("\n");

  for (const line of lines) {
    if (line.startsWith("diff --git a/")) {
      const parts = line.split(" b/");
      if (parts.length === 2 && parts[1]) {
        fileSet.add(parts[1].trim());
      }
    }
  }

  const files = Object.freeze([...fileSet].sort());
  const hasChanges = rawDiff.trim().length > 0;

  return {
    hasChanges,
    filesChanged: files.length,
    rawDiff,
    files,
  };
}

/**
 * Validates that git arguments strictly conform to read-only allowlist and
 * do not contain any forbidden mutating commands or flags.
 */
export function validateGitCommandSecurity(argv: readonly string[]): {
  readonly ok: boolean;
  readonly reason?: string;
} {
  if (!Array.isArray(argv) || argv.length === 0) {
    return { ok: false, reason: "argv must be a non-empty array" };
  }

  for (const token of argv) {
    const lower = token.toLowerCase();
    if (FORBIDDEN_GIT_SUBCOMMANDS.includes(lower)) {
      return {
        ok: false,
        reason: `disallowed_git_command: git '${lower}' is not permitted; read-only operations only`,
      };
    }
    if (FORBIDDEN_GIT_FLAGS.includes(lower)) {
      return {
        ok: false,
        reason: `disallowed_git_flag: flag '${lower}' is forbidden; force/rewrite operations prohibited`,
      };
    }
  }

  return { ok: true };
}

/**
 * Policy-controlled, read-only Git status and diff service.
 * Enforces repository boundaries, strict command allowlisting, no history rewriting,
 * and immutable event logging via AuthoritativeExecGate.
 */
export class ReadonlyGitService {
  readonly #gate: AuthoritativeExecGate;

  public constructor(options: ReadonlyGitServiceOptions = {}) {
    this.#gate =
      options.gate ??
      new AuthoritativeExecGate({
        ledger: options.ledger,
        actor: options.actor ?? { type: "agent", id: "git-readonly-service" },
      });
  }

  public get gate(): AuthoritativeExecGate {
    return this.#gate;
  }

  /**
   * Queries `git status --short --branch` within workspaceRoot.
   * Strictly enforces workspace boundary and presence of git repository.
   */
  public async queryStatus(workspaceRoot: string): Promise<GitStatusQueryResult> {
    const ws = resolveWorkspaceSafely(workspaceRoot);
    if (!ws.ok || !ws.resolved) {
      return {
        ok: false,
        phase: "cwd",
        error: ws.reason ?? "repo_boundary_violation: invalid workspace path",
      };
    }

    if (!isGitRepository(ws.resolved)) {
      return {
        ok: false,
        phase: "validate",
        error: `not_a_git_repository: .git missing in '${ws.resolved}'`,
      };
    }

    const req: ExecRequest = {
      workspaceRoot: ws.resolved,
      executable: "git",
      argv: ["status", "--short", "--branch"],
    };

    const outcome = await this.#gate.evaluateAndMaybeRun(req);

    if (!outcome.ok || !outcome.exec) {
      return {
        ok: false,
        phase: outcome.phase,
        error: outcome.validationReason ?? "git status execution failed",
      };
    }

    const stdout = decodeUtf8(outcome.exec.stdout);
    const summary = parseGitStatusShort(stdout);

    return {
      ok: true,
      phase: "complete",
      status: summary,
    };
  }

  /**
   * Queries `git diff` (working tree or staged) within workspaceRoot.
   */
  public async queryDiff(
    workspaceRoot: string,
    options: { readonly staged?: boolean; readonly paths?: readonly string[] } = {}
  ): Promise<GitDiffQueryResult> {
    const ws = resolveWorkspaceSafely(workspaceRoot);
    if (!ws.ok || !ws.resolved) {
      return {
        ok: false,
        phase: "cwd",
        error: ws.reason ?? "repo_boundary_violation: invalid workspace path",
      };
    }

    if (!isGitRepository(ws.resolved)) {
      return {
        ok: false,
        phase: "validate",
        error: `not_a_git_repository: .git missing in '${ws.resolved}'`,
      };
    }

    const argv: string[] = options.staged
      ? ["diff", "--cached", "--no-ext-diff"]
      : ["diff", "--no-ext-diff"];

    if (options.paths && options.paths.length > 0) {
      for (const p of options.paths) {
        argv.push(p);
      }
    }

    // Security check on argv before issuing
    const sec = validateGitCommandSecurity(argv);
    if (!sec.ok) {
      return {
        ok: false,
        phase: "validate",
        error: sec.reason,
      };
    }

    const req: ExecRequest = {
      workspaceRoot: ws.resolved,
      executable: "git",
      argv: Object.freeze(argv),
    };

    const outcome = await this.#gate.evaluateAndMaybeRun(req);

    if (!outcome.ok || !outcome.exec) {
      return {
        ok: false,
        phase: outcome.phase,
        error: outcome.validationReason ?? "git diff execution failed",
      };
    }

    const stdout = decodeUtf8(outcome.exec.stdout);
    const summary = parseGitDiff(stdout);

    return {
      ok: true,
      phase: "complete",
      diff: summary,
    };
  }

  /**
   * Complete read-only inspection of status, working tree diff, and staged diff.
   */
  public async inspectRepo(workspaceRoot: string): Promise<GitInspectionResult> {
    const ws = resolveWorkspaceSafely(workspaceRoot);
    if (!ws.ok || !ws.resolved) {
      const emptyStatus: GitStatusSummary = {
        state: "unknown",
        branch: null,
        trackedCount: 0,
        modifiedCount: 0,
        stagedCount: 0,
        untrackedCount: 0,
        deletedCount: 0,
        files: Object.freeze([]),
        rawStdout: "",
      };
      const emptyDiff: GitDiffSummary = {
        hasChanges: false,
        filesChanged: 0,
        rawDiff: "",
        files: Object.freeze([]),
      };
      return {
        ok: false,
        workspaceRoot,
        phase: "cwd",
        error: ws.reason ?? "repo_boundary_violation: invalid workspace path",
        status: emptyStatus,
        workingDiff: emptyDiff,
        stagedDiff: emptyDiff,
      };
    }

    const statusRes = await this.queryStatus(ws.resolved);
    if (!statusRes.ok || !statusRes.status) {
      const emptyStatus: GitStatusSummary = {
        state: "unknown",
        branch: null,
        trackedCount: 0,
        modifiedCount: 0,
        stagedCount: 0,
        untrackedCount: 0,
        deletedCount: 0,
        files: Object.freeze([]),
        rawStdout: "",
      };
      const emptyDiff: GitDiffSummary = {
        hasChanges: false,
        filesChanged: 0,
        rawDiff: "",
        files: Object.freeze([]),
      };
      return {
        ok: false,
        workspaceRoot: ws.resolved,
        phase: statusRes.phase ?? "validate",
        error: statusRes.error ?? "failed to query git status",
        status: emptyStatus,
        workingDiff: emptyDiff,
        stagedDiff: emptyDiff,
      };
    }

    const workingDiffRes = await this.queryDiff(ws.resolved, { staged: false });
    const stagedDiffRes = await this.queryDiff(ws.resolved, { staged: true });

    const defaultDiff: GitDiffSummary = {
      hasChanges: false,
      filesChanged: 0,
      rawDiff: "",
      files: Object.freeze([]),
    };

    return {
      ok: true,
      workspaceRoot: ws.resolved,
      phase: "complete",
      status: statusRes.status,
      workingDiff: workingDiffRes.diff ?? defaultDiff,
      stagedDiff: stagedDiffRes.diff ?? defaultDiff,
    };
  }

  /**
   * Invokes an arbitrary allowlisted git command, rejecting all mutating/history-rewriting operations.
   */
  public async executeAllowlisted(
    workspaceRoot: string,
    argv: readonly string[]
  ): Promise<GateOutcome> {
    const sec = validateGitCommandSecurity(argv);
    if (!sec.ok) {
      return {
        ok: false,
        phase: "validate",
        validationReason: sec.reason,
      };
    }

    const req: ExecRequest = {
      workspaceRoot,
      executable: "git",
      argv,
    };

    return this.#gate.evaluateAndMaybeRun(req);
  }
}

/**
 * Functional convenience wrapper for querying git status.
 */
export async function queryGitStatus(
  workspaceRoot: string,
  options?: ReadonlyGitServiceOptions
): Promise<GitStatusQueryResult> {
  const service = new ReadonlyGitService(options);
  return service.queryStatus(workspaceRoot);
}

/**
 * Functional convenience wrapper for querying git diff.
 */
export async function queryGitDiff(
  workspaceRoot: string,
  options?: ReadonlyGitServiceOptions & { readonly staged?: boolean; readonly paths?: readonly string[] }
): Promise<GitDiffQueryResult> {
  const service = new ReadonlyGitService(options);
  return service.queryDiff(workspaceRoot, options);
}

/**
 * Functional convenience wrapper for full git inspection.
 */
export async function inspectGitRepo(
  workspaceRoot: string,
  options?: ReadonlyGitServiceOptions
): Promise<GitInspectionResult> {
  const service = new ReadonlyGitService(options);
  return service.inspectRepo(workspaceRoot);
}
