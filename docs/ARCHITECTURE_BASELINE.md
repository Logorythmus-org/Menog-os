# Menog OS — Architecture Baseline v0

> ### ⚠ SUPERSEDED SNAPSHOT — this is not current status
>
> This document records the **minimal Phase-0 architecture**: a 7-package workspace and an initial
> 12-verb set. Both are **historical**. The repository is now **14 projects** (13 packages + `apps/cli`)
> spanning Phases 12–29, including `@menog/planner`, `@menog/memory`, `@menog/agents`,
> `@menog/commit-engine`, `@menog/semantiq` and `@menog/durable-state`, which did not exist when
> this was written.
>
> Retained rather than rewritten, because it is a dated baseline record. For current public
> truth see [`README.md`](../README.md) and [`PROJECT_SETUP.md`](../PROJECT_SETUP.md). The detailed
> internal state/audit record is intentionally not part of the public repository.

## 1. Minimal Phase-0 architecture

```text
apps/
└── cli

packages/
├── core
├── verbs
├── algorithms
├── policy
├── runtime-linux
├── event-ledger
└── shared

tests/
├── unit
├── integration
├── security
└── fixtures
```

## 2. Intent and verbs

Phase 0 does not require a complex natural-language parser. Intent may be explicit CLI input.

Initial verb set:

```text
observe
inspect
search
retrieve
compare
plan
execute
modify
validate
communicate
commit
recover
```

Only `inspect` is required to be executable on Day 1.

## 3. Agentic algorithm registry

The ten historical agentic algorithms are preserved as the initial registry:

1. Observe–Interpret–Decide–Act
2. Goal Priority
3. Context-Aware Memory Retrieval
4. Multiagent Task Allocation
5. Runtime Risk Evaluation
6. Skill Selection
7. World-State Synchronization
8. Procedural Motion
9. Agent Communication Routing
10. Self-Monitoring & Adaptation

Phase-0 implementation requirement:
- Registry and contracts for all 10.
- Implement only what is needed for the first vertical slice:
  - OIDA-lite;
  - Runtime Risk Evaluation;
  - Skill Selection-lite;
  - Self-Monitoring-lite.

The rest stay declarative until a real workload requires them.

## 4. Security boundary

```text
Intent
→ Proposed Action
→ Capability Check
→ Policy Check
→ Argument Validation
→ Scope Validation
→ Execute
→ Record Event
→ Verify Result
```

No agent/tool may bypass the gate.

## 5. Linux boundary

Menog OS is Linux-native but does not fork the Linux kernel in Phase 0.

Initial execution uses:
- unprivileged child processes;
- explicit command allowlist;
- workspace root restriction;
- environment allowlist;
- timeout;
- process-tree cleanup;
- stdout/stderr capture;
- exit-code capture;
- no network where enforceable;
- no shell interpolation when avoidable.

Later phases may add namespaces, cgroups v2, seccomp, Landlock and rootless containers.

## 6. Event-ledger boundary

Phase 0 uses a local append-only event store.

Minimum fields:

```text
event_id
timestamp
event_type
actor
workspace_id
task_id
verb
capability
policy_decision
input_summary
result_summary
parent_event_id
hash
```

No distributed consensus is required in Phase 0.

## 7. Commit boundary

No autonomous commit on Day 1.

The runtime may produce:

```text
COMMIT_CANDIDATE.md
```

Human performs the first commit after reviewing status, diff, tests, and audit.
