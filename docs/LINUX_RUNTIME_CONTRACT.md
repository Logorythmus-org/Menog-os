# Menog Linux Runtime Contract — Phase 0

## Goal

Provide a narrow, observable, unprivileged local execution primitive.

## Phase-0 command runner

Must support:
- executable + argv array;
- no shell by default;
- cwd restricted to workspace root;
- environment allowlist;
- timeout;
- maximum output size;
- exit code;
- signal/result capture;
- process-tree cleanup;
- event emission.

## Denied by default

- `sudo`
- `su`
- package installation
- arbitrary shell strings
- writes outside workspace
- network tooling
- daemonization
- background processes
- device access
- `/proc` mutation
- `/sys` mutation
- `/dev` access except explicitly allowed runtime necessities

## Initial allowlist for `inspect`

Possible read-only commands:

```text
git status --short --branch
git diff --no-ext-diff
git diff --cached --no-ext-diff
git ls-files
```

Prefer native libraries for filesystem inspection where possible instead of spawning shell commands.

## Later hardening

Not Day-1 blockers:

```text
namespaces
cgroups v2
seccomp
Landlock
rootless containers
resource-accounting adapters
GPU device policies
```
