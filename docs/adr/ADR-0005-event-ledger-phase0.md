# ADR-0005 — Event Ledger Phase 0 (Local Append-Only Hash-Chained Store)

- Status: Proposed
- Date: 2026-09-05

## Context

Every important runtime transition must produce an auditable event. The
ledger is the sole source of "what happened when, by whom, with what
result." In Phase 0 the ledger is strictly local and append-only. No
distributed consensus, no remote event sink, no telemetry, no cloud.

The event schema is declared in EVENT_SCHEMA_v0.md. The storage medium is
an open choice between `.menog/events.jsonl` (JSON Lines) and SQLite
(local-file SQL). The choice must be resolved here so implementation does
not speculate.

## Decision

### 1. Storage medium

**JSON Lines (`.menog/events.jsonl`)** for Phase 0. Rationale:

- Zero additional native dependencies (no `better-sqlite3` build step, no
  libsql platform binaries).
- Directly inspectable with standard tools (`cat`, `jq`, `wc -l`).
- Append-only semantics are simple: open for append, `fsync` (where
  available) between events.
- Line-delimited format is tolerant of partial writes (one truncated line
  on crash → corrupts only that line, not the whole file).

SQLite remains a candidate for a later phase if/when queries over events
become a performance concern; migrate via a well-tested exporter that
re-hashes events into the new storage format and records a
`storage.migrated` event.

### 2. Location & layout

```
<workspace-root>/.menog/
  └── events.jsonl        # append-only lines of JSON
```

`.menog/` is committed neither to git (via `.gitignore`) nor to the event
ledger itself. Multiple workspaces each have their own `.menog/`; there is
no global ledger in Phase 0.

### 3. Event shape (re-stated here as the authoritative target; mirrors EVENT_SCHEMA_v0.md)

Each line in `events.jsonl` is a single JSON object, with keys in a stable
order (deterministic serialization) and trailing newline.

```ts
interface MenogEvent {
  eventId: string;                 // CUID2 or ULID or SHA256 of unique input
  timestamp: string;               // ISO-8601 UTC, sub-second precision
  eventType: string;               // runtime.started / policy.denied / ...
  actor: {
    type: "human" | "agent" | "runtime" | "tool";
    id: string;
  };
  workspaceId?: string;            // stable hash of workspace root path
  taskId?: string;                 // correlation id for logical tasks
  verb?: string;
  capability?: string;
  policyDecision?: "allow" | "deny" | "not_applicable";
  inputSummary?: Record<string, unknown>;   // sanitized; no secrets
  resultSummary?: Record<string, unknown>;  // sanitized; no secrets
  parentEventId?: string;          // causal chain
  previousHash?: string;           // hash of previous line (hash chain)
  hash: string;                    // SHA-256 over deterministic serialization
                                   //   of this event excluding hash field itself
}
```

### 4. Event types (initial set, directly from EVENT_SCHEMA_v0.md)

```text
runtime.started        runtime.stopped
workspace.opened       workspace.inspected
intent.received        verb.selected
policy.allowed         policy.denied
capability.checked
command.requested      command.started
command.finished       command.failed
security.violation     commit.candidate_created
audit.completed
```

### 5. Append-only & hash-chain semantics

- Writes are **append only**. Existing lines must never be modified or
  removed by the runtime. Repair / truncation is a human-only operation
  and writes its own `storage.repaired` event (manual entry).
- `previousHash` = hex-encoded SHA-256 of the **previous line's bytes**
  (before this line is appended). First event sets `previousHash` to the
  64-character string of zeroes.
- `hash` = hex-encoded SHA-256 over deterministic JSON serialization of
  this event **without its own `hash` field**.
- Oversized payload protection: serialized JSON line must not exceed a
  configurable cap (proposed default: **256 KiB per line**). Anything
  larger is truncated to a summary, and a `payload.truncated` sub-record
  is added to `resultSummary`.

### 6. Audit & verification

- A `menog audit-events` (or equivalent) command / library helper verifies
  hash chains end-to-end and reports the first line that breaks the chain.
- Events contain no secrets. `inputSummary` / `resultSummary` are run
  through a redaction step before serialization.

## Alternatives considered

1. **SQLite (local)** — rejected for Phase 0 due to native deps; deferred.
   Re-evaluate once ad-hoc query requirements emerge.
2. **Remote event sink / OTel tracing** — explicitly rejected for Phase 0
   under "no network, no telemetry."
3. **Content-addressed store (IPFS/Car files)** — rejected; adds
   complexity without Phase-0 benefit.
4. **Single JSON array file** — rejected. No streaming append; truncation
   on crash corrupts the whole file more easily than JSONL.

## Security impact

- Hash chain enables detection of out-of-band tampering.
- Append-only prevents "fixing" history after a security violation.
- Redaction before serialization prevents secret leakage through events.
- 256 KiB cap prevents unbounded log growth or JSON-parsing OOM.
- `tests/security/` includes: tamper detection, truncation-on-overflow,
  redaction correctness, secret-in-event tests.

## Reversibility

- Storage medium (JSONL → SQLite) is reversible via one-way migration
  script; new ADR required because storage format & trust boundary change.
- Adding new event types is additive and permitted within this ADR.
- Networking events off the local machine in any form requires a new ADR
  and explicit policy flag.

## Evidence

- Event schema contract: [docs/EVENT_SCHEMA_v0.md](docs/EVENT_SCHEMA_v0.md)
- Phase-0 requirements list: [docs/EVENT_SCHEMA_v0.md → Phase-0 storage requirements](docs/EVENT_SCHEMA_v0.md#L52-L69)
- Ledger layer in core formula: [docs/PROJECT_BASELINE.md → Core formula](docs/PROJECT_BASELINE.md#L7-L22)
- Day-1 ledger acceptance criteria: [docs/DAY1_ACCEPTANCE_CRITERIA.md → Ledger](docs/DAY1_ACCEPTANCE_CRITERIA.md#L35-L39)
- Security invariants & secrets rules: [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md)
