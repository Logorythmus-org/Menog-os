# ADR-0007 — SemantIQ as Optional Post-Hoc Evaluator (Adapter Pattern, Not Pipeline Authority)

- Status: Proposed
- Date: 2026-09-05

## Context

The prompt-pack identifies **SemantIQ** as the optional evaluation
boundary: *"how well did the runtime do?"* SemantIQ is explicitly **not**
part of the Phase-0 execution path. Treating SemantIQ as part of the
direct pipeline would give it authority over execution (stop, retry,
rewrite policy), which violates the local-first zero-trust baseline and
the "model output is never authority" invariant.

## Decision

1. **SemantIQ is OPTIONAL in Phase 0.** The repository must build, test,
   typecheck, and pass Day-1 acceptance criteria **without SemantIQ
   present, configured, or reachable**. No build-time or runtime hard
   dependency. No network calls to SemantIQ. No API keys in env.

2. **SemantIQ evaluates AFTER events, never DURING execution.** The
   integration surface is a read-only adapter (`semantiq-adapter`, a
   package not required in Phase 0) that:
   - reads events from the local append-only ledger;
   - optionally reads workspace snapshots and results;
   - emits *evaluations* (scores, narratives, deltas, recommendations)
     into a separate namespace (e.g., `<workspace>/.menog/evaluations/`
     or an `evaluation.*` event type with a `source=semantiq` marker);
   - **never mutates the execution pipeline, policy, capabilities, or
     commits.**

3. **Adapter boundary (future package contract)**

   ```
   Menog Event Ledger (append-only, local)
         │ read-only
         ▼
   ┌──────────────────────────┐
   │   SemantIQ Adapter       │  ← this is the ONLY integration point
   │  (future package)        │
   └──────┬───────────────────┘
          │  evaluations (typed, signed-source)
          ▼
   Evaluations Store / UI / Manual Review
          │
          │  HUMAN reviews and optionally acts
          ▼
   (Manual policy / commit updates, reviewed)
   ```

   SemantIQ never has a direct arrow into Policy, Runtime, or Commit. The
   human is always in the loop between a SemantIQ evaluation and any
   change to authoritative state.

4. **Phase-0 packaging / code**

   - `packages/algorithms` contains the 10 algorithm strategy contracts
     but SemantIQ is **not** registered there.
   - If a SemantIQ-backed strategy family appears later, it lives in its
     own package (e.g., `packages/algorithms-semantiq-adapter`), is
     disabled by default, and is not a dependency of `apps/cli` in Phase 0.
   - No MCP route to SemantIQ. If SemantIQ is reached via network later,
     that requires a `network:` capability + explicit policy, and must be
     introduced under a new ADR.

5. **Evaluations are NOT events.** Event ledger records execution facts.
   Evaluations record opinions/judgments. They may be stored next to the
   ledger but must not rewrite or shadow events.

## Alternatives considered

1. **SemantIQ inside the direct pipeline as an "AI planner" authority** —
   explicitly rejected. Breaks "algorithms recommend, policy authorizes"
   (ADR-0003). Makes model output into a runtime authority, breaking the
   core invariant (SECURITY_BASELINE.md).
2. **SemantIQ as policy co-author** — rejected. Policy rules are code and
   edited by humans with review. SemantIQ may recommend rule changes via
   evaluations; humans decide.
3. **SemantIQ as commit gate** — rejected. Commit gate is human-only in
   Phase 0. Evaluations are evidence the human may consult.
4. **Tightly-coupled SDK import** — rejected. Adapter pattern keeps the
   core free of SemantIQ version churn and API key requirements.

## Security impact

- No SemantIQ in the execution path = no remote network = no API keys =
  no new supply-chain surface in Phase 0.
- Adapter pattern ensures that if/when SemantIQ is connected, its effects
  are scoped to evaluations only. Its output must cross the human review
  gate before mutating authoritative state.
- "No build-time dependency" means a compromised SemantIQ account,
  outage, or SDK supply-chain event cannot break Day-1 builds.

## Reversibility

- Promoting SemantIQ from optional-evaluator to a pipeline participant
  (any direct arrow into Policy/Runtime/Commit) requires a **superseding
  ADR** that:
  1. explicitly amends ADR-0003's stage roles;
  2. documents new capability/policy checks;
  3. documents network/secret handling;
  4. passes an updated security-review checklist.
- Removing SemantIQ later is trivial because the core never depends on
  it.

## Evidence

- SemantIQ in core formula: [docs/PROJECT_BASELINE.md → Core formula](docs/PROJECT_BASELINE.md#L7-L22)
- SemantIQ = optional/external: [README.md → Hard architectural rules (rule 12)](README.md#L30-L44)
- Commit boundary (human): [docs/ARCHITECTURE_BASELINE.md → Commit boundary](docs/ARCHITECTURE_BASELINE.md#L131-L141)
- Invariants (no external content as authority): [docs/SECURITY_BASELINE.md → Invariants](docs/SECURITY_BASELINE.md#L18-L31)
- MCP control plane (future, not Phase-0): [docs/SECURITY_BASELINE.md → MCP position](docs/SECURITY_BASELINE.md#L60-L78)
