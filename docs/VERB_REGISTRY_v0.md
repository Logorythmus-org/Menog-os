# Menog Verb Registry v0

A verb describes **what semantic action is requested**, not which agent performs it.

## Contract

```ts
export interface VerbContract<Input = unknown, Output = unknown> {
  id: string;
  description: string;
  sideEffectClass: "none" | "read" | "write" | "network" | "system";
  requiredCapabilities: string[];
  replayable: boolean;
  reversible: boolean;
  inputSchemaVersion: string;
  outputSchemaVersion: string;
}
```

## Initial registry

| Verb | Side effect | Day-1 executable |
|---|---:|---:|
| observe | read | optional |
| inspect | read | yes |
| search | read | later |
| retrieve | read | later |
| compare | none/read | later |
| plan | none | later |
| execute | system | later |
| modify | write | later |
| validate | read/system | later |
| communicate | network | later |
| commit | write | later |
| recover | write/system | later |

## `inspect`

Required capabilities:

```text
workspace:list
workspace:read-metadata
git:status
git:diff-read
```

Forbidden:

```text
workspace:write
network:external
git:commit
process:privileged
```
