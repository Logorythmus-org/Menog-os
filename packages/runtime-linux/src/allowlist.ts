import type { CapabilityId } from "@menog/policy";

export const DEFAULT_TIMEOUT_MS: 10000 = 10000;
export const DEFAULT_MAX_OUTPUT_BYTES: 65536 = 65536;

export type AllowlistMatchKind = "exact" | "prefix";

export interface AllowedCommandSpec {
  readonly id: string;
  readonly executableBasename: "git";
  readonly argvPrefix: readonly string[];
  readonly extraArgvPattern: "none" | "any-flags";
  readonly matchKind: AllowlistMatchKind;
  readonly requiredCapabilities: readonly CapabilityId[];
  readonly sideEffectClass: "read";
  readonly description: string;
}

const GIT_STATUS_CAPS: readonly CapabilityId[] = Object.freeze([
  "git:status",
  "workspace:read-metadata",
]);
const GIT_DIFF_CAPS: readonly CapabilityId[] = Object.freeze([
  "git:diff-read",
  "workspace:read-metadata",
]);
const GIT_LS_CAPS: readonly CapabilityId[] = Object.freeze([
  "workspace:list",
  "workspace:read-metadata",
]);

export const DAY1_ALLOWED_COMMANDS: readonly AllowedCommandSpec[] = Object.freeze([
  {
    id: "day1:git-status-short-branch",
    executableBasename: "git",
    argvPrefix: Object.freeze(["status", "--short", "--branch"]),
    extraArgvPattern: "none",
    matchKind: "exact",
    requiredCapabilities: GIT_STATUS_CAPS,
    sideEffectClass: "read",
    description: "git status --short --branch — read-only workspace status",
  },
  {
    id: "day1:git-diff-working-tree",
    executableBasename: "git",
    argvPrefix: Object.freeze(["diff", "--no-ext-diff"]),
    extraArgvPattern: "any-flags",
    matchKind: "prefix",
    requiredCapabilities: GIT_DIFF_CAPS,
    sideEffectClass: "read",
    description: "git diff --no-ext-diff [paths...] — read-only working tree diff",
  },
  {
    id: "day1:git-diff-cached",
    executableBasename: "git",
    argvPrefix: Object.freeze(["diff", "--cached", "--no-ext-diff"]),
    extraArgvPattern: "any-flags",
    matchKind: "prefix",
    requiredCapabilities: GIT_DIFF_CAPS,
    sideEffectClass: "read",
    description: "git diff --cached --no-ext-diff [...] — read-only staged diff",
  },
  {
    id: "day1:git-ls-files",
    executableBasename: "git",
    argvPrefix: Object.freeze(["ls-files"]),
    extraArgvPattern: "any-flags",
    matchKind: "prefix",
    requiredCapabilities: GIT_LS_CAPS,
    sideEffectClass: "read",
    description: "git ls-files [flags] — read-only tracked file enumeration",
  },
]);

export const ENVIRONMENT_ALLOWLIST: readonly string[] = Object.freeze([
  "PATH",
  "SYSTEMROOT",
  "USERPROFILE",
  "HOME",
  "LANG",
  "LC_ALL",
  "GIT_TERMINAL_PROMPT",
  "GIT_OPTIONAL_LOCKS",
  "NO_COLOR",
  "PWD",
  "TMP",
  "TEMP",
  "TMPDIR",
]);

export const BLOCKED_BASE_NAMES: readonly string[] = Object.freeze([
  "sudo",
  "su",
  "doas",
  "pkexec",
  "runas",
  "psexec",
  "ssh",
  "scp",
  "sftp",
  "curl",
  "wget",
  "netcat",
  "nc",
  "ncat",
  "bash",
  "zsh",
  "fish",
  "sh",
  "cmd.exe",
  "powershell",
  "pwsh",
  "cmd",
  "telnet",
]);

export const BLOCKED_ARGV_META_TOKENS: readonly RegExp[] = Object.freeze([
  /[|&;]/,
  /`/,
  /\$\(/,
  /\$\{/,
  /(^|[^=<>])>\s*[A-Za-z0-9_\/\\.~-]/,
  /(^|[^=<>])<\s*[A-Za-z0-9_\/\\.~-]/,
  /^>/,
  /^</,
  /\|\|/,
  /&&/,
  /--upload-pack=/,
  /--exec/,
  /-c\b/,
  /--command\b/,
  />>/,
  /<</,
]);
