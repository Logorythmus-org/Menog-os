# PHASE 28B — Runtime Entity Projection Contract

**Gate:** `28B` — Runtime Entity Projection
**Entry:** `28A_PASS` (`PRE28_R0_READY`)
**Mother invariant:** VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A SOURCE OF TRUTH OR AUTHORITY.
**Short law:** VISIBILITY != AUTHORITY.
**Mode:** PURE DETERMINISTIC PROJECTION / READ-ONLY / NO INVENTED INFORMATION
**Verdict:** `28B_PASS`

**Source:** `packages/durable-state/src/getigEntityProjection.ts` (24,518 B)
**Tests:** `tests/unit/getig-entity-projection.test.ts` — **44 tests**

---

## 1. What this gate does

It maps a **frozen Phase-27 observability snapshot** into a 28A GETIG frame. One function:
`projectObservabilitySnapshot`. It reads, it maps, it returns. It never mutates, repairs or extends
its input, and it invents nothing — every visible field is either copied from upstream or is a
structural zero from 28A.

28A defined what a visible world may *say*. 28B decides what it actually says, from evidence that
already exists.

---

## 2. The ordering decision — the one that makes determinism real

`canonicalDurableJson` (frozen Phase-20) sorts object **keys** but preserves **array order**. So
had this module emitted collections in upstream order, a shuffled input would produce a different
`canonicalVisibleHash` — which the 28B law forbids outright.

The resolution splits two things that look alike and are not:

| | Treatment | Why |
|:--|:--|:--|
| **Collection order** | **canonicalized** — every visible collection sorted by a stable natural key | order is presentation; leaking it into the hash would make identical worlds hash differently |
| **Route hop order** | **preserved exactly** | a forwarder sequence is *meaning*; sorting it would invent a false path |

Getting either backwards is a silent correctness bug: not sorting invents instability; sorting hops
invents a topology that was never observed.

Sorting uses **code-unit string comparison**, not `localeCompare` — the latter is locale-dependent
and would make the hash machine-dependent.

### The subtlety this created, and how it is tested

Shuffled upstream input yields **byte-identical canonical visible content** ✅ — but a **different
frame hash**. That is correct, and worth being precise about: 27H legitimately hashes its own input
in order, so two orderings really are two different upstream projections, and the frame commits to
that evidence pointer.

Asserting only the content-level claim would let an unstable ordering hide behind a moving pointer.
Asserting only hash equality would hide a content-ordering bug behind a fixed pointer. So the law is
proven in **two parts**:

1. shuffled upstream input ⇒ identical canonical visible content;
2. shuffling content while **holding the evidence anchor fixed** ⇒ identical frame hash.

---

## 3. Nothing is invented

| Field | Source |
|:--|:--|
| entity ids | upstream `nodeId` / `routeId`, copied |
| epoch, as-of time | upstream `epochId` / `asOfEpochMs`, **copied or the projection refuses** |
| observer | caller's context, carried unchanged |
| `sourceProjectionHash` | upstream `projectionHash`, **verbatim, never recomputed** |
| provenance | upstream provenance, as **metadata** |
| everything else | 28A structural zeros |

A missing epoch or as-of time **refuses the projection** rather than substituting a placeholder —
inventing the one field that tells a reader *when* the view was taken would be the worst possible
place to fabricate.

---

## 4. The vocabulary mappings

**Freshness** — the critical one is the last:

| 27H | GETIG |
|:--|:--|
| `within_window` | `current` |
| `outside_window` | `stale` |
| `unknown_freshness` | **`unknown`** — never `current` |

**Lifecycle** — a retired fact stays retired:

| 27C/27H | GETIG |
|:--|:--|
| `observed` | `observed` |
| `stale` | **`observed`** (with `freshness: "stale"`) |
| `quarantined_observation` | `quarantined` |
| `retired_observation` | **`retired`** — terminal, never revived |
| `unknown_observation` | `unknown` |

`stale` is deliberately **not** a lifecycle value. A stale observation is still an observed fact that
has aged; collapsing the two dimensions would let a renderer draw a stale node as though it had
never been seen. Staleness lives in `freshness`; lifecycle stays `observed`.

---

## 5. Refusal codes are mapped through a CLOSED table, never approximated

`PROJECTION_UPSTREAM_REFUSAL_MAP` covers the eight codes a 27H snapshot can emit. **An unmapped
upstream code refuses the entire projection** — `refused_projection_unmapped_refusal_code`, naming
the offending code.

Guessing a classification would be inventing a meaning the evidence never supplied. Widening the
table is a deliberate act, not a fallback.

This is also why visible refusals carry **no free text**: upstream `ObservabilityRefusal` is only
`{subjectId, code}`, so there is no channel through which a prompt, a secret or a tool output could
ride into a visible world.

---

## 6. The separation laws survive the crossing

| Law | How the projection preserves it |
|:--|:--|
| edge ≠ trust/admission | relations carry `trust: "none"`; no other authority key appears |
| advertisement ≠ grant | every projected entity carries `grant: "none"` |
| route ≠ authorization | routes carry `admission`/`authorization` `"none"`, `executionAuthorized: false` |
| forwarder ≠ origin | origin **copied** from `originNodeId`; forwarders kept in their own field, never merged |
| reconciliation ≠ consensus | every upstream conflict is emitted **visible and `resolved: false`** |

**The consensus one deserves emphasis.** Upstream 27G classifies a conflict with a resolution such as
`terminal_retained` — it decided which observation survived. The visible world **does not adopt
that decision**: it records the disagreement with both claims and stops. A test asserts exactly
this, for `terminal_retained` as well as `no_consensus_unknown`. Adopting upstream's pick would make
the projection a consensus machine wearing a read-only hat.

---

## 7. Read-only, bounded and inert

Verified against the emitted source, not asserted:

- **Upstream is not mutated.** A test snapshots the upstream object, projects it repeatedly, and
  requires byte-identical JSON afterwards.
- **No network, store, Policy, tool, spawn or rendering API** — checked by scanning the comment-
  stripped source.
- **No exported function whose name looks like a mutation or execution API.**
- **Bounded**: the projected frame respects every 28A bound, and oversize upstream **refuses** before
  any work is done.
- A refusal exposes **no partial frame** — exactly as in 28A.

---

## 8. Non-claims

28B does **not** claim: that any runtime system was read (the input is a synthetic frozen snapshot in
tests) · that the projection is complete · that conflicts are resolved · that two observers agree ·
any renderer exists (WebGPU is Phase 29) · any two-machine LAN, power-loss, DDoS or WAN behaviour.

---

## 9. Debt

None created. D-26-1, D-26-2, D-26-3, D-26-4 carried unchanged, all **non-blocking**.

— 28B, 2026-10-03