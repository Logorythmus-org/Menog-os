# ADR-0003 — Local-First Runtime Pipeline (Intent → Verb → Algorithm → Agent/Skill → Policy → Linux → Event)

- Status: Proposed
- Date: 2026-09-05

## Context

Menog OS turns human intent into controlled, observable execution. The core
value is **visible, reversible, policy-constrained execution** inside the
user's own Linux environment. The pipeline must be explicit: no hidden stage,
no bypass of the policy gate, no silent write, and no network-by-default.

The Phase-0 vertical slice is `menog inspect <workspace>`: read-only,
auditable, bounded.

## Decision

### 1. Explicit execution pipeline (authoritative shape)

```
   [Human / System Event]
          │
          ▼
 ┌─────────────────────┐      Intent = WHY.  Untrusted free-form input.
 │    Intent Engine    │      (Phase 0: explicit CLI string — no NLP parse.)
 └─────────┬───────────┘
           │
           ▼
 ┌─────────────────────┐      Verb = WHAT.  Typed, registered, side-effect classed.
 │    Verb Registry    │      inspect / observe / search / retrieve / ...
 └─────────┬───────────┘      (see VERB_REGISTRY_v0.md)
           │
           ▼
 ┌─────────────────────┐      Algorithm = HOW TO REASON.  Recommends only.
 │ Algorithm Registry  │      OIDA-lite / Runtime Risk / Skill Selection /
 │   (Strategy family) │      Self-Monitoring + 6 contract-only.
 └─────────┬───────────┘      Never executes.  Never authorizes.
           │
           ▼
 ┌─────────────────────┐      Agent / Skill = WHO + HOW TO ACT.
 │   Agent/Skill Map   │      Maps allowed verbs → allowed local skills/tools.
 └─────────┬───────────┘      No skill bypasses the policy gate below.
           │
           ▼
 ┌─────────────────────┐      Policy = MAY IT.  AUTHORITATIVE GATE.
 │  Policy & Capability│      Checks: capability, scope, argument, workspace,
 │        Gate         │      env allowlist, timeout, budget.
 └─────────┬───────────┘      Output: allow / deny + reasons.  (writes event)
           │
    allow  │  deny ────► emit policy.denied event → return structured denial
           ▼
 ┌─────────────────────┐      Linux Runtime = WHERE.  EXECUTES ONLY.
 │  Linux Execution    │      unprivileged child + argv array + cwd locked
 │  (unprivileged)     │      + env allowlist + timeout + tree cleanup.
 └─────────┬───────────┘      Emits command.{started,finished,failed}.
           │
           ▼
 ┌─────────────────────┐      Ledger = WHAT HAPPENED.  RECORDS ONLY.
 │   Append-Only Event │      Hash-chained.  Local storage only.
 │      Ledger         │      No network sink in Phase 0.
 └─────────┬───────────┘
           │
           ▼
 ┌─────────────────────┐      Human = CRITICAL WRITE AUTHORITY.
 │  Manual Review /    │      Reviews structured result, diff, events.
 │  Manual Commit      │      First commit is ALWAYS manual (Day 1).
 └─────────────────────┘
```

### 2. Stage roles (authoritative / non-authoritative)

| Stage | Role | Authoritative? | May mutate state? |
|---|---|---:|---:|
| Intent Engine | Parse intent (text → typed) | input only | no |
| Verb Registry | Resolve + describe verb | no | no |
| Algorithm Strategy | Recommend next steps / ranking | **recommends only** | no |
| Agent/Skill Map | Select allowed tool(s) | no | no |
| **Policy & Capability Gate** | **Allow or deny proposed action** | **YES — authority** | no (but writes events) |
| **Linux Runtime** | **Execute allowed, bounded commands** | **YES — execution** | within workspace & allowlist only |
| Event Ledger | Append events | records only | append-only write (itself) |
| Human Reviewer | Sign off critical writes / commits | **YES — critical write authority** | manual commit |

### 3. Explicit clarifications (encoded in code, not convention)

- **Algorithms recommend; they never execute.** Output of any algorithm
  strategy is a structured *recommendation* record, not a command. The
  policy gate evaluates that recommendation exactly like any other input.
- **Policy authorizes or denies. It is not advisory.** A `deny` from policy
  short-circuits before reaching the Linux executor, and a `policy.denied`
  event is appended with full context.
- **Runtime executes only what policy allowed, bounded.** No fallback
  execution paths. Arguments are re-validated at the runtime boundary as a
  defense-in-depth measure.
- **Event ledger records only.** It cannot change history, cannot truncate
  its own head, and never sends events off the local machine in Phase 0.
- **Human controls critical writes / commits.** No `git commit` is ever
  invoked by the runtime. No file-write capability is granted without
  explicit scope + explicit policy decision + event record.
- **SemantIQ evaluates later, through an adapter.** SemantIQ reads events;
  it does not sit inside the execution pipeline. A future `semantiq-adapter`
  package is the sole integration surface. See ADR-0007.

## Alternatives considered

1. **Agent → MCP direct execution** — explicitly rejected; forbidden by
   SECURITY_BASELINE.md.
2. **Single monolithic `menog` binary with internalized stages** — rejected;
   the stage boundaries must remain independently testable / replacable.
3. **Policy as soft advisory** — rejected; deny-by-default is a hard
   invariant.
4. **Event ledger pushed upstream in-band** — rejected; local-only in Phase 0.

## Security impact

- The policy gate is the authoritative checkpoint. Bugs here are critical:
  tests/security/ must include bypass tests for every policy edge.
- Linux stage re-validates arguments even after policy → defense in depth
  against policy-stage bugs.
- Event ledger is append-only and hash-chained → malicious later writes
  cannot retroactively "fix" history without detection.
- Human commit gate prevents model output or compromised tooling from
  becoming write authority on the repository history.

## Reversibility

- Pipeline stages are intentionally decoupled; swapping an algorithm or
  runtime implementation is reversible (new ADR if the *boundary* changes).
- Adding network-capable stages or remote event sinks **changes the security
  boundary** and requires a new ADR that explicitly updates this one.
- Adding SemantIQ into the **direct execution path** (not as a post-hoc
  evaluator) would violate this ADR's clarifications; a superseding ADR is
  required.

## Evidence

- Core formula: [docs/PROJECT_BASELINE.md → Core formula](docs/PROJECT_BASELINE.md#L7-L22)
- Architectural layers: [docs/PROJECT_BASELINE.md → Architectural layers](docs/PROJECT_BASELINE.md#L55-L79)
- Security boundary + invariants: [docs/SECURITY_BASELINE.md → Invariants](docs/SECURITY_BASELINE.md#L18-L31)
- Security boundary flow: [docs/ARCHITECTURE_BASELINE.md → Security boundary](docs/ARCHITECTURE_BASELINE.md#L73-L87)
- Commit boundary: [docs/ARCHITECTURE_BASELINE.md → Commit boundary](docs/ARCHITECTURE_BASELINE.md#L131-L141)
- Day-1 vertical slice: [README.md → Day-1 goal](README.md#L7-L29)
