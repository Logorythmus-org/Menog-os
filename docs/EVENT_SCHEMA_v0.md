# Menog Event Schema v0

## Purpose

Every important runtime transition produces an auditable local event.

## Event types

```text
runtime.started
runtime.stopped
workspace.opened
intent.received
verb.selected
policy.allowed
policy.denied
capability.checked
command.requested
command.started
command.finished
command.failed
workspace.inspected
security.violation
commit.candidate_created
audit.completed
```

## TypeScript shape

```ts
export interface MenogEvent {
  eventId: string;
  timestamp: string;
  eventType: string;
  actor: {
    type: "human" | "agent" | "runtime" | "tool";
    id: string;
  };
  workspaceId?: string;
  taskId?: string;
  verb?: string;
  capability?: string;
  policyDecision?: "allow" | "deny" | "not_applicable";
  inputSummary?: Record<string, unknown>;
  resultSummary?: Record<string, unknown>;
  parentEventId?: string;
  previousHash?: string;
  hash: string;
}
```

## Phase-0 storage

Use a simple local append-only store:

```text
.menog/
└── events.jsonl
```

or SQLite if the implementation remains simpler and well-tested.

Requirements:
- append-only semantics;
- deterministic serialization;
- hash chaining;
- no secrets;
- safe truncation/oversized payload limits;
- tests for corruption detection.
