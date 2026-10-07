import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  lstatSync,
  realpathSync,
} from "node:fs";
import { resolve, normalize, isAbsolute, sep, dirname } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import type { Actor } from "@menog/core";
import type { CapabilityId } from "@menog/policy";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import {
  previewControlledWrite,
  type DiffOptions,
  type ControlledWritePreviewResult,
} from "./diffEngine.js";

/**
 * Maximum byte size for the `content` field of a `create` or `replace` operation.
 * Prevents resource exhaustion from oversized write payloads.
 * Default: 4 MiB.
 */
export const MAX_WRITE_CONTENT_BYTES = 4 * 1024 * 1024; // 4 MiB

/**
 * Maximum byte size for the `patch.target` string in a `patch` operation.
 * Prevents O(n²) scan cost from oversized patch targets.
 * Default: 512 KiB.
 */
export const MAX_PATCH_TARGET_BYTES = 512 * 1024; // 512 KiB

export type ControlledWriteOperation =
  | "create"
  | "patch"
  | "replace"
  | "delete-candidate";

export interface ControlledWritePatch {
  readonly target: string;
  readonly replacement: string;
  readonly expectedOccurrences?: number;
}

export interface ControlledWritePolicyApproval {
  readonly approved: boolean;
  readonly approvalId?: string;
  readonly approver?: Actor;
  readonly reason?: string;
}

export interface ControlledWriteRequest {
  readonly workspaceRoot: string;
  readonly relativePath: string;
  readonly operation: ControlledWriteOperation;
  readonly content?: string;
  readonly patch?: ControlledWritePatch;
  readonly actor: Actor;
  readonly capabilities: readonly CapabilityId[];
  readonly policyApproval?: ControlledWritePolicyApproval;
  readonly requestId?: string;
  readonly taskId?: string;
}

export interface ControlledWritePathResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly resolvedPath?: string;
  readonly resolvedWorkspaceRoot?: string;
}

export interface ControlledWriteValidationResult {
  readonly ok: boolean;
  readonly phase?: "scope" | "capability" | "policy" | "validate";
  readonly reason?: string;
  readonly resolvedPath?: string;
  readonly resolvedWorkspaceRoot?: string;
}

export interface ControlledWriteResult {
  readonly ok: boolean;
  readonly operation: ControlledWriteOperation;
  readonly resolvedPath: string;
  readonly bytesWritten?: number;
  readonly bytesRemoved?: number;
  readonly previousHash?: string;
  readonly newHash?: string;
  readonly error?: string;
}

export interface WriteGateOutcome {
  readonly ok: boolean;
  readonly phase: "scope" | "capability" | "policy" | "validate" | "execute" | "complete";
  readonly reason?: string;
  readonly result?: ControlledWriteResult;
  readonly eventId?: string;
}

function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Resolves and strictly bounds write target path within the workspace root.
 * Enforces no path traversal, no escapes, and no symlink-based escapes.
 */
export function resolveWritePathSafely(
  workspaceRoot: string,
  relativePath: string
): ControlledWritePathResult {
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    return { ok: false, reason: "workspaceRoot must be a non-empty string" };
  }
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    return { ok: false, reason: "relativePath must be a non-empty string" };
  }
  if (relativePath.includes("\u0000")) {
    return { ok: false, reason: "relativePath contains forbidden NUL character" };
  }

  // Reject absolute paths passed as relativePath
  if (isAbsolute(relativePath) || relativePath.startsWith("/") || relativePath.startsWith("\\")) {
    return {
      ok: false,
      reason: `path_traversal_denied: relativePath '${relativePath}' must be relative, not absolute`,
    };
  }

  const rootAbs = isAbsolute(workspaceRoot)
    ? normalize(resolve(workspaceRoot))
    : normalize(resolve(process.cwd(), workspaceRoot));

  let realRoot = rootAbs;
  try {
    if (existsSync(rootAbs)) {
      realRoot = normalize(realpathSync(rootAbs));
    }
  } catch {
    realRoot = rootAbs;
  }

  const rootWithSep = rootAbs.endsWith(sep) ? rootAbs : rootAbs + sep;
  const candidate = normalize(resolve(rootAbs, relativePath));

  // 1. Strict lexical boundary check
  if (candidate !== rootAbs && !candidate.startsWith(rootWithSep)) {
    return {
      ok: false,
      reason: `path_traversal_denied: '${relativePath}' escapes workspace root '${rootAbs}'`,
    };
  }

  // 2. Protected system directory checks (.git, .menog)
  const relFromRoot = candidate.slice(rootWithSep.length);
  const segments = relFromRoot.split(sep);
  if (segments.includes(".git") || segments.includes(".menog")) {
    return {
      ok: false,
      reason: `protected_path_denied: modification of .git or .menog metadata is prohibited`,
    };
  }

  // 3. Symlink escape check along directory chain
  const realRootWithSep = realRoot.endsWith(sep) ? realRoot : realRoot + sep;
  let cur = rootAbs;
  for (const seg of segments) {
    cur = resolve(cur, seg);
    if (existsSync(cur)) {
      try {
        const st = lstatSync(cur);
        if (st.isSymbolicLink()) {
          const realCur = normalize(realpathSync(cur));
          if (realCur !== realRoot && !realCur.startsWith(realRootWithSep)) {
            return {
              ok: false,
              reason: `symlink_escape_denied: symlink component '${cur}' resolves outside workspace to '${realCur}'`,
            };
          }
        }
      } catch {
        // Continue if lstat fails
      }
    }
  }

  // 4. Target file symlink check
  if (existsSync(candidate)) {
    try {
      const st = lstatSync(candidate);
      if (st.isSymbolicLink()) {
        return {
          ok: false,
          reason: `symlink_escape_denied: direct modification of symbolic link '${candidate}' is prohibited`,
        };
      }
    } catch {
      // Continue
    }
  }

  return {
    ok: true,
    resolvedPath: candidate,
    resolvedWorkspaceRoot: rootAbs,
  };
}

/**
 * Validates a controlled write request against scope, capabilities, policy, and operations.
 */
export function validateControlledWrite(
  req: ControlledWriteRequest
): ControlledWriteValidationResult {
  if (!req || typeof req !== "object") {
    return { ok: false, phase: "validate", reason: "write request must be an object" };
  }

  // 1. Check capability
  if (!Array.isArray(req.capabilities) || !req.capabilities.includes("workspace:write")) {
    return {
      ok: false,
      phase: "capability",
      reason: "capability_denied: missing required capability 'workspace:write'",
    };
  }

  // 2. Check explicit policy approval
  if (!req.policyApproval || req.policyApproval.approved !== true) {
    return {
      ok: false,
      phase: "policy",
      reason: "policy_approval_denied: workspace write requires explicit policy approval",
    };
  }

  // 3. Check scope / path safety
  const pathCheck = resolveWritePathSafely(req.workspaceRoot, req.relativePath);
  if (!pathCheck.ok || !pathCheck.resolvedPath) {
    return {
      ok: false,
      phase: "scope",
      reason: pathCheck.reason ?? "invalid write path",
    };
  }

  const resolved = pathCheck.resolvedPath;

  // 4. Check operation semantics
  const op = req.operation;
  if (op !== "create" && op !== "patch" && op !== "replace" && op !== "delete-candidate") {
    return {
      ok: false,
      phase: "validate",
      reason: `invalid_operation: '${String(op)}' is not a supported write operation`,
    };
  }

  // 4a. Size budget enforcement (before any filesystem I/O)
  if (op === "create" || op === "replace") {
    const contentStr = req.content ?? "";
    const contentBytes = Buffer.byteLength(contentStr, "utf8");
    if (contentBytes > MAX_WRITE_CONTENT_BYTES) {
      return {
        ok: false,
        phase: "validate",
        reason: `content_too_large: content is ${contentBytes} bytes, exceeds maximum allowed ${MAX_WRITE_CONTENT_BYTES} bytes for '${op}' operation`,
      };
    }
  }

  if (op === "patch" && req.patch) {
    const targetBytes = Buffer.byteLength(req.patch.target ?? "", "utf8");
    if (targetBytes > MAX_PATCH_TARGET_BYTES) {
      return {
        ok: false,
        phase: "validate",
        reason: `patch_too_large: patch target is ${targetBytes} bytes, exceeds maximum allowed ${MAX_PATCH_TARGET_BYTES} bytes`,
      };
    }
    const replacementBytes = Buffer.byteLength(req.patch.replacement ?? "", "utf8");
    if (replacementBytes > MAX_WRITE_CONTENT_BYTES) {
      return {
        ok: false,
        phase: "validate",
        reason: `patch_too_large: patch replacement is ${replacementBytes} bytes, exceeds maximum allowed ${MAX_WRITE_CONTENT_BYTES} bytes`,
      };
    }
  }

  const exists = existsSync(resolved);

  if (op === "create") {
    if (exists) {
      return {
        ok: false,
        phase: "validate",
        reason: `file_already_exists: cannot 'create' existing file '${req.relativePath}'; use 'replace' or 'patch'`,
      };
    }
    if (typeof req.content !== "string") {
      return {
        ok: false,
        phase: "validate",
        reason: "content must be a string for 'create' operation",
      };
    }
  } else if (op === "replace") {
    if (!exists) {
      return {
        ok: false,
        phase: "validate",
        reason: `file_not_found: cannot 'replace' non-existent file '${req.relativePath}'`,
      };
    }
    if (typeof req.content !== "string") {
      return {
        ok: false,
        phase: "validate",
        reason: "content must be a string for 'replace' operation",
      };
    }
    if (!lstatSync(resolved).isFile()) {
      return {
        ok: false,
        phase: "validate",
        reason: `not_a_file: '${req.relativePath}' is not a regular file`,
      };
    }
  } else if (op === "patch") {
    if (!exists) {
      return {
        ok: false,
        phase: "validate",
        reason: `file_not_found: cannot 'patch' non-existent file '${req.relativePath}'`,
      };
    }
    if (!req.patch || typeof req.patch.target !== "string" || typeof req.patch.replacement !== "string") {
      return {
        ok: false,
        phase: "validate",
        reason: "patch must provide 'target' and 'replacement' strings",
      };
    }
    if (req.patch.target.length === 0) {
      return {
        ok: false,
        phase: "validate",
        reason: "patch 'target' string cannot be empty",
      };
    }
    if (!lstatSync(resolved).isFile()) {
      return {
        ok: false,
        phase: "validate",
        reason: `not_a_file: '${req.relativePath}' is not a regular file`,
      };
    }
  } else if (op === "delete-candidate") {
    if (!exists) {
      return {
        ok: false,
        phase: "validate",
        reason: `file_not_found: cannot 'delete-candidate' non-existent file '${req.relativePath}'`,
      };
    }
    if (!lstatSync(resolved).isFile()) {
      return {
        ok: false,
        phase: "validate",
        reason: `not_a_file: '${req.relativePath}' is not a regular file`,
      };
    }
  }

  return {
    ok: true,
    resolvedPath: resolved,
    resolvedWorkspaceRoot: pathCheck.resolvedWorkspaceRoot,
  };
}

/**
 * Pure filesystem write executor.
 * ZERO shell usage, ZERO child processes. Strictly Node.js filesystem APIs.
 */
export class ControlledWriter {
  public execute(
    req: ControlledWriteRequest,
    resolvedPath: string
  ): ControlledWriteResult {
    const op = req.operation;

    switch (op) {
      case "create": {
        const parent = dirname(resolvedPath);
        if (!existsSync(parent)) {
          mkdirSync(parent, { recursive: true });
        }
        const content = req.content ?? "";
        writeFileSync(resolvedPath, content, "utf8");
        const newHash = sha256Hex(content);
        return {
          ok: true,
          operation: "create",
          resolvedPath,
          bytesWritten: Buffer.byteLength(content, "utf8"),
          newHash,
        };
      }

      case "replace": {
        const oldContent = readFileSync(resolvedPath, "utf8");
        const prevHash = sha256Hex(oldContent);
        const content = req.content ?? "";
        writeFileSync(resolvedPath, content, "utf8");
        const newHash = sha256Hex(content);
        return {
          ok: true,
          operation: "replace",
          resolvedPath,
          previousHash: prevHash,
          newHash,
          bytesWritten: Buffer.byteLength(content, "utf8"),
        };
      }

      case "patch": {
        const oldContent = readFileSync(resolvedPath, "utf8");
        const prevHash = sha256Hex(oldContent);
        const { target, replacement, expectedOccurrences = 1 } = req.patch!;

        let matchCount = 0;
        let pos = 0;
        while ((pos = oldContent.indexOf(target, pos)) !== -1) {
          matchCount++;
          pos += target.length;
        }

        if (matchCount === 0) {
          return {
            ok: false,
            operation: "patch",
            resolvedPath,
            error: `patch_target_not_found: target string not found in '${req.relativePath}'`,
          };
        }

        if (matchCount !== expectedOccurrences) {
          return {
            ok: false,
            operation: "patch",
            resolvedPath,
            error: `patch_occurrence_mismatch: target found ${matchCount} times, expected ${expectedOccurrences}`,
          };
        }

        const newContent = oldContent.replace(target, replacement);
        writeFileSync(resolvedPath, newContent, "utf8");
        const newHash = sha256Hex(newContent);
        return {
          ok: true,
          operation: "patch",
          resolvedPath,
          previousHash: prevHash,
          newHash,
          bytesWritten: Buffer.byteLength(newContent, "utf8"),
        };
      }

      case "delete-candidate": {
        const oldContent = readFileSync(resolvedPath, "utf8");
        const prevHash = sha256Hex(oldContent);
        const removedBytes = Buffer.byteLength(oldContent, "utf8");
        unlinkSync(resolvedPath);
        return {
          ok: true,
          operation: "delete-candidate",
          resolvedPath,
          previousHash: prevHash,
          bytesRemoved: removedBytes,
        };
      }
    }
  }
}

export interface AuthoritativeWriteGateOptions {
  readonly ledger?: AppendOnlyLedger | null;
  readonly writer?: ControlledWriter;
}

/**
 * Authoritative gate for workspace mutations.
 * Enforces capability + scope + policy approval, executes via ControlledWriter,
 * and emits immutable audit events to the ledger.
 */
export class AuthoritativeWriteGate {
  readonly #ledger: AppendOnlyLedger | null;
  readonly #writer: ControlledWriter;

  public constructor(options: AuthoritativeWriteGateOptions = {}) {
    this.#ledger = options.ledger ?? null;
    this.#writer = options.writer ?? new ControlledWriter();
  }

  public preview(
    req: ControlledWriteRequest,
    options?: DiffOptions
  ): ControlledWritePreviewResult {
    return previewControlledWrite(req, { ...options, ledger: this.#ledger });
  }

  public execute(req: ControlledWriteRequest): WriteGateOutcome {
    const validation = validateControlledWrite(req);

    if (!validation.ok || !validation.resolvedPath) {
      const eventId = "write-deny-" + randomUUID().replace(/-/g, "").slice(0, 20);
      if (this.#ledger !== null) {
        this.#ledger.append({
          eventId,
          timestamp: new Date().toISOString(),
          eventType: "controlled_write_denied",
          actor: req.actor,
          workspaceId: req.workspaceRoot,
          taskId: req.taskId,
          verb: "modify",
          capability: "workspace:write",
          policyDecision: "deny",
          inputSummary: {
            operation: req.operation,
            relativePath: req.relativePath,
            requestId: req.requestId ?? null,
            requestedCapabilities: req.capabilities,
          },
          resultSummary: {
            phase: validation.phase,
            reason: validation.reason,
          },
        });
      }

      return {
        ok: false,
        phase: validation.phase ?? "validate",
        reason: validation.reason,
        eventId,
      };
    }

    const execResult = this.#writer.execute(req, validation.resolvedPath);

    if (!execResult.ok) {
      const eventId = "write-err-" + randomUUID().replace(/-/g, "").slice(0, 20);
      if (this.#ledger !== null) {
        this.#ledger.append({
          eventId,
          timestamp: new Date().toISOString(),
          eventType: "controlled_write_failed",
          actor: req.actor,
          workspaceId: validation.resolvedWorkspaceRoot,
          taskId: req.taskId,
          verb: "modify",
          capability: "workspace:write",
          policyDecision: "allow",
          inputSummary: {
            operation: req.operation,
            relativePath: req.relativePath,
            requestId: req.requestId ?? null,
          },
          resultSummary: {
            error: execResult.error,
          },
        });
      }

      return {
        ok: false,
        phase: "execute",
        reason: execResult.error,
        result: execResult,
        eventId,
      };
    }

    const eventId = "write-ok-" + randomUUID().replace(/-/g, "").slice(0, 20);
    if (this.#ledger !== null) {
      this.#ledger.append({
        eventId,
        timestamp: new Date().toISOString(),
        eventType: "controlled_write_executed",
        actor: req.actor,
        workspaceId: validation.resolvedWorkspaceRoot,
        taskId: req.taskId,
        verb: "modify",
        capability: "workspace:write",
        policyDecision: "allow",
        inputSummary: {
          operation: req.operation,
          relativePath: req.relativePath,
          requestId: req.requestId ?? null,
        },
        resultSummary: {
          operation: execResult.operation,
          resolvedPath: execResult.resolvedPath,
          bytesWritten: execResult.bytesWritten ?? null,
          bytesRemoved: execResult.bytesRemoved ?? null,
          previousHash: execResult.previousHash ?? null,
          newHash: execResult.newHash ?? null,
          approvalId: req.policyApproval?.approvalId ?? null,
          approver: req.policyApproval?.approver ?? null,
        },
      });
    }

    return {
      ok: true,
      phase: "complete",
      result: execResult,
      eventId,
    };
  }
}
