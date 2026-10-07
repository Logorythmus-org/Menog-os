import { resolve, isAbsolute, normalize, sep } from "node:path";
import {
  BLOCKED_ARGV_META_TOKENS,
  BLOCKED_BASE_NAMES,
  DAY1_ALLOWED_COMMANDS,
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_TIMEOUT_MS,
  type AllowedCommandSpec,
} from "./allowlist.js";
import type { CapabilityId } from "@menog/policy";

export interface ExecRequest {
  readonly workspaceRoot: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly requestId?: string;
}

export type ExecTermination =
  | { readonly kind: "exit"; readonly code: number }
  | { readonly kind: "signal"; readonly signal: string }
  | { readonly kind: "timeout"; readonly afterMs: number }
  | { readonly kind: "spawn-error"; readonly message: string };

export interface ExecResult {
  readonly ok: boolean;
  readonly termination: ExecTermination;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly durationMs: number;
  readonly matchedCommand?: AllowedCommandSpec;
}

export interface ValidationResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly matchedSpec?: AllowedCommandSpec;
  readonly sanitizedExecutable?: string;
  readonly sanitizedArgv?: readonly string[];
  readonly resolvedWorkspace?: string;
  readonly requiredCapabilities?: readonly CapabilityId[];
}

function basenameOf(path: string): string {
  const norm = normalize(path);
  const lastSep = norm.lastIndexOf(sep);
  const lastAlt = norm.lastIndexOf("/");
  const idx = Math.max(lastSep, lastAlt);
  return idx < 0 ? norm : norm.slice(idx + 1);
}

function stripExeExtension(name: string): string {
  const lower = name.toLowerCase();
  if (lower.endsWith(".exe")) return name.slice(0, name.length - 4);
  return name;
}

export function resolveWorkspaceSafely(
  workspaceRoot: string,
  requestedCwd?: string
): { readonly ok: boolean; readonly reason?: string; readonly resolved?: string } {
  if (typeof workspaceRoot !== "string" || workspaceRoot.length === 0) {
    return { ok: false, reason: "workspaceRoot must be a non-empty string" };
  }
  const rootAbs = isAbsolute(workspaceRoot)
    ? normalize(resolve(workspaceRoot))
    : normalize(resolve(process.cwd(), workspaceRoot));
  if (rootAbs.length === 0) {
    return { ok: false, reason: "workspaceRoot resolves to empty path" };
  }
  const rootWithSep = rootAbs.endsWith(sep) ? rootAbs : rootAbs + sep;
  if (requestedCwd === undefined || requestedCwd === null || requestedCwd === "") {
    return { ok: true, resolved: rootAbs };
  }
  const requestedAbs = isAbsolute(requestedCwd as string)
    ? normalize(resolve(requestedCwd as string))
    : normalize(resolve(rootAbs, requestedCwd as string));
  const reqWithSep = requestedAbs.endsWith(sep) ? requestedAbs : requestedAbs + sep;
  if (reqWithSep !== rootWithSep && !reqWithSep.startsWith(rootWithSep)) {
    return {
      ok: false,
      reason:
        "refusing to set cwd outside workspace root: '" +
        requestedAbs +
        "' is not under '" +
        rootAbs +
        "'",
    };
  }
  return { ok: true, resolved: requestedAbs };
}

export function validateReadonlyExec(
  req: ExecRequest
): ValidationResult {
  if (!req || typeof req !== "object") {
    return { ok: false, reason: "exec request must be an object" };
  }
  const workspaceCheck = resolveWorkspaceSafely(req.workspaceRoot);
  if (!workspaceCheck.ok) {
    return { ok: false, reason: workspaceCheck.reason };
  }
  if (typeof req.executable !== "string" || req.executable.length === 0) {
    return { ok: false, reason: "executable must be a non-empty string" };
  }
  if (!Array.isArray(req.argv)) {
    return { ok: false, reason: "argv must be an array" };
  }
  for (const a of req.argv) {
    if (typeof a !== "string") {
      return { ok: false, reason: "argv entries must be strings" };
    }
    for (const re of BLOCKED_ARGV_META_TOKENS) {
      if (re.test(a)) {
        return {
          ok: false,
          reason:
            "argv token '" + a + "' contains disallowed meta-character pattern",
        };
      }
    }
    const nullByte = a.indexOf("\u0000");
    if (nullByte !== -1) {
      return { ok: false, reason: "argv contains disallowed NUL byte" };
    }
  }
  const rawExec = req.executable;
  const execBaseWithExt = basenameOf(rawExec);
  const execBasename = stripExeExtension(execBaseWithExt).toLowerCase();
  if (BLOCKED_BASE_NAMES.some((blocked) => blocked.toLowerCase() === execBasename)) {
    return {
      ok: false,
      reason:
        "executable basename '" +
        execBasename +
        "' is in BLOCKED_BASE_NAMES (sudo/su/shell/network tools forbidden)",
    };
  }
  if (execBasename !== "git") {
    return {
      ok: false,
      reason:
        "day-1 phase-0 allowlist only accepts 'git'; got '" + execBasename + "'",
    };
  }
  if (sep !== "/" && rawExec.indexOf("/") !== -1) {
    return {
      ok: false,
      reason: "arbitrary executable paths not allowed; use PATH-resolved basename 'git' only",
    };
  }
  if (rawExec.indexOf(sep) !== -1) {
    return {
      ok: false,
      reason: "arbitrary executable paths not allowed; use PATH-resolved basename 'git' only",
    };
  }
  const argv: readonly string[] = req.argv;
  let matchedSpec: AllowedCommandSpec | undefined;
  for (const spec of DAY1_ALLOWED_COMMANDS) {
    if (spec.executableBasename.toLowerCase() !== execBasename) continue;
    if (argv.length < spec.argvPrefix.length) continue;
    let prefixOk = true;
    for (let i = 0; i < spec.argvPrefix.length; i++) {
      if (argv[i] !== spec.argvPrefix[i]) {
        prefixOk = false;
        break;
      }
    }
    if (!prefixOk) continue;
    if (spec.matchKind === "exact") {
      if (argv.length !== spec.argvPrefix.length) continue;
    } else if (spec.matchKind === "prefix") {
      if (spec.extraArgvPattern !== "any-flags" && argv.length > spec.argvPrefix.length) {
        continue;
      }
    }
    matchedSpec = spec;
    break;
  }
  if (!matchedSpec) {
    return {
      ok: false,
      reason:
        "argv 'git " +
        argv.join(" ") +
        "' does not match any day-1 readonly allowlist command",
    };
  }
  const timeoutMs =
    typeof req.timeoutMs === "number" && Number.isFinite(req.timeoutMs) && req.timeoutMs > 0
      ? Math.floor(req.timeoutMs)
      : DEFAULT_TIMEOUT_MS;
  if (timeoutMs > 120000) {
    return { ok: false, reason: "timeoutMs cannot exceed 120000 (2 min)" };
  }
  const maxOutputBytes =
    typeof req.maxOutputBytes === "number" &&
    Number.isFinite(req.maxOutputBytes) &&
    req.maxOutputBytes > 0
      ? Math.floor(req.maxOutputBytes)
      : DEFAULT_MAX_OUTPUT_BYTES;
  if (maxOutputBytes > 16 * 1024 * 1024) {
    return { ok: false, reason: "maxOutputBytes cannot exceed 16 MiB" };
  }
  return {
    ok: true,
    matchedSpec,
    sanitizedExecutable: execBasename,
    sanitizedArgv: Object.freeze(argv.slice()),
    resolvedWorkspace: workspaceCheck.resolved,
    requiredCapabilities: Object.freeze(matchedSpec.requiredCapabilities.slice()),
  };
}
