import type { VerbContract } from "./types.js";

export const VERB_SCHEMA_VERSION_v0 = "0.0.1";

export const INITIAL_VERBS: readonly VerbContract[] = [
  {
    id: "observe",
    description:
      "Passively collect workspace context without producing structured analysis. Read-only environmental scan.",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze([
      "workspace:list",
      "workspace:read-metadata",
    ]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "inspect",
    description:
      "Structured read-only inspection of a workspace: list files, report git status and diffs, collect structured report. Day-1 vertical slice.",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze([
      "workspace:list",
      "workspace:read-metadata",
      "git:status",
      "git:diff-read",
    ]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    executable: true,
  },
  {
    id: "search",
    description:
      "Search workspace contents for patterns or keywords. Read-only.",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze([
      "workspace:search",
      "workspace:read-file",
      "workspace:list",
    ]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "retrieve",
    description:
      "Read and return a specific resource from the workspace by reference. Read-only.",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze([
      "workspace:read-file",
      "workspace:read-metadata",
    ]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "compare",
    description:
      "Compare two or more resources or states and produce a delta. Pure read or read-only.",
    sideEffectClass: "none",
    requiredCapabilities: Object.freeze(["workspace:read-file"]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "plan",
    description:
      "Produce a structured plan from an intent. No side effects by itself.",
    sideEffectClass: "none",
    requiredCapabilities: Object.freeze(["plan:generate"]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "execute",
    description:
      "Execute an approved local command or skill. System side-effecting; requires policy gate.",
    sideEffectClass: "system",
    requiredCapabilities: Object.freeze([
      "process:spawn",
      "workspace:read-file",
    ]),
    replayable: false,
    reversible: false,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "modify",
    description:
      "Modify workspace contents: create, edit, delete files inside the workspace write side effects.",
    sideEffectClass: "write",
    requiredCapabilities: Object.freeze([
      "workspace:write",
      "workspace:read-file",
    ]),
    replayable: false,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "validate",
    description:
      "Run validators against the workspace, possibly spawning local validation binaries. Local.",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze([
      "workspace:read-file",
      "process:spawn",
    ]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "communicate",
    description:
      "Send a message externally. Requires network authorization.",
    sideEffectClass: "network",
    requiredCapabilities: Object.freeze([
      "network:external",
      "workspace:read-file",
    ]),
    replayable: false,
    reversible: false,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "commit",
    description:
      "Create a git commit in the workspace. Write side effect; requires human review.",
    sideEffectClass: "write",
    requiredCapabilities: Object.freeze([
      "git:commit",
      "workspace:write",
      "workspace:read-file",
    ]),
    replayable: false,
    reversible: false,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
  {
    id: "recover",
    description:
      "Recover workspace or runtime state from a previous checkpoint.",
    sideEffectClass: "system",
    requiredCapabilities: Object.freeze([
      "workspace:write",
      "git:recover",
      "process:spawn",
    ]),
    replayable: false,
    reversible: true,
    inputSchemaVersion: VERB_SCHEMA_VERSION_v0,
    outputSchemaVersion: VERB_SCHEMA_VERSION_v0,
  },
] as const;
