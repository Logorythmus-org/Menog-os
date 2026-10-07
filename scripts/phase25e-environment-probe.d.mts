/**
 * Type declarations for scripts/phase25e-environment-probe.mjs (25E).
 * The script is a plain .mjs CLI (run by node directly); these declarations
 * let the qualification suite import and pin its PURE functions.
 */
export declare const HARNESS_PROBE_TIMEOUT_MS: 15000;
export declare const HARNESS_PROBE_ATTEMPTS: 3;
export declare const HARNESS_PROBE_RETRY_DELAY_MS: 250;
export declare const QUALIFICATION_TIMEOUT_MS: 120000;

export interface ProbeAttemptRecord {
  readonly attempt: number;
  readonly command: string;
  readonly status: number | null;
  readonly durationMs: number;
  readonly error: string | null;
  readonly timedOut: boolean;
}

export interface ReadinessResult {
  readonly available: boolean;
  readonly attempts: ProbeAttemptRecord[];
  readonly attemptsUsed: number;
}

export declare function makeClock(): {
  now: () => number;
  advance: (ms: number) => number;
};

export declare function probeAttempt(
  runner: (command: string, args: string[], spawnOptions: Record<string, unknown>) => { status: number | null; stdout?: string; stderr?: string; error?: unknown },
  command: string,
  args: string[],
  options: { attempt: number; now: () => number; spawnOptions: Record<string, unknown> }
): ProbeAttemptRecord;

export declare function probeReadinessWithRetry(
  runner: (command: string, args: string[], spawnOptions: Record<string, unknown>) => { status: number | null; stdout?: string; stderr?: string; error?: unknown },
  options: {
    command: string;
    args: string[];
    attempts: number;
    retryDelayMs: number;
    timeoutMs: number;
    now: () => number;
    delayFn?: (ms: number) => void;
    spawnOptions?: Record<string, unknown>;
    shouldAbort?: () => boolean;
  }
): ReadinessResult;

export type EnvironmentTarget = "windows_host" | "wsl2" | "native_linux" | "unavailable_target";

export declare function classifyEnvironment(input: {
  platform: string;
  wslReady: boolean;
  attempts: number;
}): { target: EnvironmentTarget; targetClass: EnvironmentTarget; explanation: string };

export declare const CAPABILITY_SNIPPET: string;

export interface CapabilityFacts {
  readonly kernel: string;
  readonly arch: string;
  readonly osName: string;
  readonly cgroup: { readonly controllers: string; readonly fsType: string; readonly v2ControllersAvailable: boolean };
  readonly landlock: {
    readonly inLsmList: boolean;
    readonly abiObservation: "present_in_lsm_list" | "not_observed";
    readonly lsmList: string;
    readonly note: string;
  };
  readonly seccomp: { readonly status: string; readonly filters: string };
  readonly probeComplete: boolean;
}

export declare function parseCapabilityFacts(stdout: unknown): CapabilityFacts;

/**
 * D-26-2 repair (gate PRE27-R1). Atomically publishes `contents` to `outPath`
 * by writing a uniquely-named temp file in the same directory, fsyncing it, and
 * renaming it over the target. The target is only ever REPLACED, so a partial
 * write is never observable. Never falls back to a non-atomic write.
 */
export interface AtomicPublishRecord {
  readonly target: string;
  readonly tempPath: string | null;
  readonly published: boolean;
  /** Structural guarantee: the target is only ever replaced whole. */
  readonly partialWriteExposed: false;
  readonly method: string;
  readonly renameAttemptsUsed: number;
  readonly renameAttemptsAvailable: number;
  readonly fallbackToNonAtomicWrite: false;
  readonly error: string | null;
}

export declare function writeEvidenceAtomically(
  outPath: string,
  contents: string,
  options?: {
    renameAttempts?: number;
    renameRetryBaseMs?: number;
    renameRetryCapMs?: number;
    tempNameAttempts?: number;
  },
): AtomicPublishRecord;
