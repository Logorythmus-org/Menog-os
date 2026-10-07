export interface PolicySummaryDecisionInput {
  readonly outcome: "allow" | "deny";
  readonly reason?: string;
  readonly matchedRule?: string;
}

export interface PolicySummaryInput {
  readonly decision: PolicySummaryDecisionInput;
}

export interface PolicySummary {
  readonly decision: "allow" | "deny";
  readonly matchedRules: readonly string[];
  readonly warnings: readonly string[];
  readonly eventCount: number;
}

export interface WorkspaceCounts {
  readonly tracked: number;
  readonly modified: number;
  readonly untracked: number;
  readonly stagedModified: number;
}

export interface ManifestDetection {
  readonly manifests: readonly string[];
  readonly testFiles: number;
}

export interface InspectReport {
  readonly formatVersion: "menog-inspect/v0";
  readonly generatedAt: string;
  readonly taskId: string;
  readonly workspace: {
    readonly path: string;
    readonly normalized: string;
  };
  readonly git: {
    readonly isRepository: boolean;
    readonly branch: string | null;
    readonly status: "clean" | "dirty" | "unknown";
    readonly counts: WorkspaceCounts;
  };
  readonly manifests: readonly string[];
  readonly testFiles: number;
  readonly warnings: readonly string[];
  readonly policy: PolicySummary;
  readonly eventCount: number;
  readonly executionDurationMs: number;
}

export interface InspectRunOptions {
  readonly workspaceArg: string;
  readonly taskId?: string;
  readonly workingCwd?: string;
  readonly actor?: { readonly type: "agent" | "human" | "runtime" | "tool"; readonly id: string };
  readonly ledger?: "memory" | "default" | { readonly kind: "dir"; readonly root: string } | unknown;
}

export type InspectExitStatus = 0 | 1 | 2;

export interface InspectRunResult {
  readonly exitStatus: InspectExitStatus;
  readonly report: InspectReport | null;
  readonly warnings: readonly string[];
  readonly stdoutText: string;
  readonly stderrText: string;
}

export interface ParseArgsResult {
  readonly ok: boolean;
  readonly subcommand?: "inspect";
  readonly workspaceArg?: string;
  readonly usageError?: string;
}

export const INSPECT_FORMAT_VERSION: "menog-inspect/v0" = "menog-inspect/v0";
export const INSPECT_VERB_ID: "inspect" = "inspect";
export const MENOG_DIRNAME: ".menog" = ".menog";
export const LEDGER_FILENAME: "events.jsonl" = "events.jsonl";
