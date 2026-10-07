import { spawn, type ChildProcessWithoutNullStreams, execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { ENVIRONMENT_ALLOWLIST, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT_MS, DAY1_ALLOWED_COMMANDS } from "./allowlist.js";
import { resolveWorkspaceSafely, validateReadonlyExec, type ExecRequest, type ExecResult, type ExecTermination, type ValidationResult } from "./validate.js";

interface ProcessTracker {
  child: ChildProcessWithoutNullStreams | null;
  readonly startTime: [number, number];
  timer?: ReturnType<typeof setTimeout>;
  killed: boolean;
  done: boolean;
  stdout: Uint8Array[];
  stderr: Uint8Array[];
  stdoutTotal: number;
  stderrTotal: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
}

function filteredEnv(allowlist: readonly string[] = ENVIRONMENT_ALLOWLIST): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  const forced: Readonly<Record<string, string>> = Object.freeze({
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    PAGER: "cat",
    LESS: "",
  });
  for (const k of allowlist) {
    const v = process.env[k];
    if (v !== undefined) out[k] = v;
  }
  for (const k of Object.keys(forced)) {
    out[k] = (forced as Record<string, string>)[k];
  }
  return out;
}

function hrDurationMs(start: [number, number]): number {
  const [s, ns] = process.hrtime(start);
  return s * 1000 + ns / 1e6;
}

function concatChunks(chunks: Uint8Array[], total: number, cap: number): Uint8Array {
  const actual = Math.min(total, cap);
  const out = new Uint8Array(actual);
  let written = 0;
  for (const c of chunks) {
    if (written >= actual) break;
    const remaining = actual - written;
    if (c.length <= remaining) {
      out.set(c, written);
      written += c.length;
    } else {
      out.set(c.subarray(0, remaining), written);
      written = actual;
    }
  }
  return out.subarray(0, written);
}

function killProcessTree(child: ChildProcessWithoutNullStreams, pid: number): void {
  const isWin = process.platform === "win32";
  try {
    if (isWin) {
      try {
        execSync("taskkill /F /T /PID " + pid, { stdio: "ignore", timeout: 5000 });
        return;
      } catch {
        child.kill("SIGKILL");
        return;
      }
    }
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  } catch {
    try { child.kill("SIGKILL"); } catch { /* ignore */ }
  }
}

export class ReadonlyExecutor {
  readonly #envAllowlist: readonly string[];
  readonly #maxOutputCap: number;
  readonly #timeoutCap: number;

  public constructor(options: {
    readonly envAllowlist?: readonly string[];
    readonly maxOutputCap?: number;
    readonly timeoutCap?: number;
  } = {}) {
    this.#envAllowlist = Object.freeze(
      options.envAllowlist ? [...options.envAllowlist] : [...ENVIRONMENT_ALLOWLIST]
    );
    this.#maxOutputCap =
      typeof options.maxOutputCap === "number" ? options.maxOutputCap : DEFAULT_MAX_OUTPUT_BYTES;
    this.#timeoutCap =
      typeof options.timeoutCap === "number" ? options.timeoutCap : DEFAULT_TIMEOUT_MS;
  }

  public validate(req: ExecRequest): ValidationResult {
    return validateReadonlyExec(req);
  }

  public async run(req: ExecRequest): Promise<ExecResult> {
    const v = validateReadonlyExec(req);
    if (!v.ok) {
      return {
        ok: false,
        termination: { kind: "spawn-error", message: v.reason ?? "validation failed" },
        stdout: new Uint8Array(0),
        stderr: new Uint8Array(0),
        stdoutTruncated: false,
        stderrTruncated: false,
        durationMs: 0,
      };
    }
    const workspace = v.resolvedWorkspace!;
    if (!existsSync(workspace)) {
      return {
        ok: false,
        termination: { kind: "spawn-error", message: "workspace path does not exist: '" + workspace + "'" },
        stdout: new Uint8Array(0),
        stderr: new Uint8Array(0),
        stdoutTruncated: false,
        stderrTruncated: false,
        durationMs: 0,
      };
    }
    const cwdCheck = resolveWorkspaceSafely(req.workspaceRoot, workspace);
    if (!cwdCheck.ok) {
      return {
        ok: false,
        termination: { kind: "spawn-error", message: cwdCheck.reason ?? "cwd escape rejected" },
        stdout: new Uint8Array(0),
        stderr: new Uint8Array(0),
        stdoutTruncated: false,
        stderrTruncated: false,
        durationMs: 0,
      };
    }
    const exec = v.sanitizedExecutable!;
    const argv = [...v.sanitizedArgv!];
    const maxOut = Math.min(
      req.maxOutputBytes ?? this.#maxOutputCap,
      this.#maxOutputCap
    );
    const timeout = Math.min(
      req.timeoutMs ?? this.#timeoutCap,
      this.#timeoutCap
    );
    const env = filteredEnv(this.#envAllowlist);
    return new Promise<ExecResult>((resolvePromise) => {
      let child: ChildProcessWithoutNullStreams | null = null;
      const tracker: ProcessTracker = {
        child: null,
        startTime: process.hrtime(),
        killed: false,
        done: false,
        stdout: [],
        stderr: [],
        stdoutTotal: 0,
        stderrTotal: 0,
        stdoutTruncated: false,
        stderrTruncated: false,
      };
      try {
        child = spawn(exec, argv, {
          cwd: workspace,
          env,
          shell: false,
          windowsHide: true,
          uid: undefined,
          gid: undefined,
          detached: process.platform !== "win32",
        });
      } catch (spawnThrown) {
        resolvePromise({
          ok: false,
          termination: {
            kind: "spawn-error",
            message: String((spawnThrown as Error).message),
          },
          stdout: new Uint8Array(0),
          stderr: new Uint8Array(0),
          stdoutTruncated: false,
          stderrTruncated: false,
          durationMs: hrDurationMs(tracker.startTime),
        });
        return;
      }
      tracker.child = child;
      tracker.timer = setTimeout(() => {
        if (tracker.done) return;
        tracker.killed = true;
        const pid = child!.pid;
        if (typeof pid === "number") {
          killProcessTree(child!, pid);
        } else {
          try { child!.kill("SIGKILL"); } catch { /* ignore */ }
        }
        finish({
          ok: false,
          termination: { kind: "timeout", afterMs: timeout },
          durationMsOverride: timeout,
        });
      }, timeout);
      const finish = (override: {
        ok: boolean;
        termination: ExecTermination;
        durationMsOverride?: number;
      } | null = null) => {
        if (tracker.done) return;
        tracker.done = true;
        if (tracker.timer) {
          clearTimeout(tracker.timer);
          tracker.timer = undefined;
        }
        const durationMs =
          override && typeof override.durationMsOverride === "number"
            ? override.durationMsOverride
            : hrDurationMs(tracker.startTime);
        const stdout = concatChunks(tracker.stdout, tracker.stdoutTotal, maxOut);
        const stderr = concatChunks(tracker.stderr, tracker.stderrTotal, maxOut);
        const termination = override ? override.termination : ({ kind: "exit", code: -1 } as ExecTermination);
        const ok = override ? override.ok : termination.kind === "exit" && termination.code === 0;
        resolvePromise({
          ok,
          termination,
          stdout,
          stderr,
          stdoutTruncated: tracker.stdoutTruncated || tracker.stdoutTotal > maxOut,
          stderrTruncated: tracker.stderrTruncated || tracker.stderrTotal > maxOut,
          durationMs,
          matchedCommand: v.matchedSpec,
        });
      };
      child.stdout.on("data", (chunk: Buffer | Uint8Array | string) => {
        if (tracker.done) return;
        const b =
          typeof chunk === "string"
            ? new TextEncoder().encode(chunk)
            : chunk instanceof Uint8Array
              ? chunk
              : new Uint8Array(Buffer.from(chunk).buffer, Buffer.from(chunk).byteOffset, Buffer.from(chunk).byteLength);
        tracker.stdoutTotal += b.length;
        if (tracker.stdoutTotal <= maxOut) {
          tracker.stdout.push(b);
        } else {
          const allow = Math.max(0, maxOut - (tracker.stdoutTotal - b.length));
          if (allow > 0) tracker.stdout.push(b.subarray(0, allow));
          tracker.stdoutTruncated = true;
          try { if (child) child.stdout.destroy(); } catch { /* ignore */ }
        }
      });
      child.stderr.on("data", (chunk: Buffer | Uint8Array | string) => {
        if (tracker.done) return;
        const b =
          typeof chunk === "string"
            ? new TextEncoder().encode(chunk)
            : chunk instanceof Uint8Array
              ? chunk
              : new Uint8Array(Buffer.from(chunk).buffer, Buffer.from(chunk).byteOffset, Buffer.from(chunk).byteLength);
        tracker.stderrTotal += b.length;
        if (tracker.stderrTotal <= maxOut) {
          tracker.stderr.push(b);
        } else {
          const allow = Math.max(0, maxOut - (tracker.stderrTotal - b.length));
          if (allow > 0) tracker.stderr.push(b.subarray(0, allow));
          tracker.stderrTruncated = true;
          try { if (child) child.stderr.destroy(); } catch { /* ignore */ }
        }
      });
      child.on("error", (err) => {
        finish({
          ok: false,
          termination: { kind: "spawn-error", message: String(err.message) },
        });
      });
      child.on("close", (code, signal) => {
        if (tracker.killed && overrideTimeoutPending()) return;
        let term: ExecTermination;
        if (signal) {
          term = { kind: "signal", signal: String(signal) };
        } else if (typeof code === "number") {
          term = { kind: "exit", code };
        } else {
          term = { kind: "exit", code: -1 };
        }
        const ok = term.kind === "exit" && term.code === 0;
        finish({ ok, termination: term });
      });
      function overrideTimeoutPending(): boolean {
        return tracker.killed && !tracker.done;
      }
    });
  }
}

export function findCommandSpecById(id: string): { readonly found: boolean; readonly spec?: (typeof DAY1_ALLOWED_COMMANDS)[number] } {
  for (const s of DAY1_ALLOWED_COMMANDS) {
    if (s.id === id) return { found: true, spec: s };
  }
  return { found: false };
}
