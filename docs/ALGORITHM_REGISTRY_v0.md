# Menog Agentic Algorithm Registry v0

The registry preserves the ten historical agentic algorithms as **strategy families**, not ten fixed agents.

**Phase 17A status:** the ten families are formalized as machine-readable, replaceable strategy contracts in `packages/algorithms` (`@menog/algorithms`). TEN CONTRACTS — NOT TEN AGENTS. No agent is created or instantiated by the algorithm stage.

## Registry

### 1. OIDA — Observe–Interpret–Decide–Act
Purpose: core action loop.
Phase-0 implementation: lightweight deterministic control loop around `inspect`.
17A: `oida/loop-lite@0.1.0` — deterministic recommend-only OIDA phase strategy (`oidaLoopLite`).
17B: upgraded to `oida/loop-lite@0.2.0` — stateful strategy over an **explicit, caller-owned state machine** (`OidaLoopState`: `currentPhase`, `done`, `iteration`). Pure transition functions: `initialOidaState`, `validateOidaState`, `advanceOida` (single-step observe → interpret → decide → act → loop/done), `completeOidaLoop` (only from `act`). Invalid states deny with machine-readable `invalid_state`; done loops are terminal; the strategy emits `nextOidaState` as DATA (the caller owns all mutation) and a conclusion-only `reasoningSummary`. Stateless mode preserves 17A behavior.

### 2. Goal Priority
Purpose: rank competing goals.
Phase-0 status: contract only.
17A: formalized contract, `goal_priority/contract-only@0.1.0` (implemented:false; evaluation denies `strategy_not_selected`).
17B: implemented as `goal_priority/hint-budget@0.1.0` (`goalPriorityHintBudget`) — deterministic weight = 40×hint + 30×urgency + 12×recency, with `budget.maxWeight` caps and `budget.maxRanked` top-k zeroing (capped goals stay present, ranked last, flagged `budgetCapped`). Tie-breakers in order: weight → urgency → hint → insertion index. Inputs are observable data: batch-level `goalPriorityHint` (low/medium/high/critical), declarative label prefixes (`critical:`/`blocking:`/`urgent:`), optional `budget`. Malformed hints/budgets deny with `invalid_state`.

### 3. Context-Aware Memory Retrieval
Purpose: select relevant prior context.
Phase-0 status: contract only; no vector DB required.
17A: formalized contract, `context_memory_retrieval/contract-only@0.1.0` (implemented:false). Actual retrieval lives in `@menog/memory` (16C).
17C: a **port-bound strategy** is available — `buildContextMemoryStrategy(port)` builds `context_memory_retrieval/port-rank@0.1.0` over any `MemoryRetrievalPort`. The structural port is satisfied by the EXISTING policy-gated `MemoryRetrievalService` via `memoryRetrievalPortAdapter` — integration WITHOUT bypass: reads stay policy-gated, scope-isolated, ledger-observable inside `@menog/memory`. Untrusted records are prefixed `untrusted:`; the projection surface is flat (`score/snippet/origin/untrusted`, hit-capped 32, snippet-capped 96). NO PORT ⇒ evaluation denies `retrieval_unavailable`; the family stays contract-only in the default registry.

### 4. Multiagent Task Allocation
Purpose: assign tasks based on capability, load, trust and history.
Phase-0 status: contract only.
17A: formalized contract, `multiagent_task_allocation/contract-only@0.1.0` (implemented:false).

### 5. Runtime Risk Evaluation
Purpose: classify planned actions before execution.
Phase-0 implementation: required.
17A: `runtime_risk_evaluation/label-rank@0.1.0` — deterministic risk-indicator ranking; advisory only, policy remains authoritative.
17C: upgraded to `runtime_risk_evaluation/gate-rank@0.2.0` (`runtimeRiskGateRank`) — adds a machine-readable **risk verdict** (`allow | restrict | deny` + bounded reason + recommended `withholdCapabilities`). **Risk may restrict/deny execution** — advisory-ly: `applyRiskVerdict(granted, verdict)` produces the restricted capability view with a monotone-restriction invariant (result ⊆ granted; policy engine is the floor; risk can only withhold, never add). Danger-tier indicators (commit/push/rm/privileged/force) deny; medium-tier (write/modify/network/external/delete) restrict.

### 6. Skill Selection
Purpose: choose an allowed execution skill/tool for a verb.
Phase-0 implementation: minimal deterministic mapping.
17A: `skill_selection/capability-map-lite@0.1.0` — deterministic verb→capability-hint mapping; recommends labels, never grants capabilities.
17C: upgraded to `skill_selection/capability-map@0.2.0` (`skillCapabilityMapLite`) — **capability-aware**: recommended hints are intersected with caller-asserted `input.grantedCapabilities` via `filterSkillsByCapabilities` (NO TOOL WITHOUT CAPABILITY); ungranted hints are withheld and reported. The granted set is caller-asserted DATA — it can only constrain (intersection), never unlock a hint the strategy didn't recommend; the policy engine remains the sole granting authority.

### 7. World-State Synchronization
Purpose: synchronize shared runtime state across agents/nodes.
Phase-0 status: contract only.
17A: formalized contract, `world_state_synchronization/contract-only@0.1.0` (implemented:false); federation remains a non-goal.

### 8. Procedural Motion
Purpose: path planning and physical/3D runtime motion.
Phase-0 status: contract only.
17A: formalized contract, `procedural_motion/contract-only@0.1.0` (implemented:false); 3D runtime is ROADMAP ONLY.

### 9. Agent Communication Routing
Purpose: route agent-to-agent/runtime messages.
Phase-0 status: contract only.
17A: formalized contract, `agent_communication_routing/contract-only@0.1.0` (implemented:false).

### 10. Self-Monitoring & Adaptation
Purpose: observe results and propose strategy changes.
Phase-0 implementation: record outcomes only. No autonomous self-modification.
17A: `self_monitoring_adaptation/outcome-record@0.1.0` — deterministic outcome ranking; proposals are data for human review, never autonomous changes.
17D: upgraded to `self_monitoring_adaptation/observe-metrics@0.2.0` (`selfMonitoringMetricObserve`) — **bounded self-monitoring from observable metrics** with a machine-readable, at-most-one `adaptationProposal`. Adaptation targets ONLY registered tunable parameters (`AdaptiveParameterStore`): humans/policy register bounds at registration; adaptation moves values ONLY within those bounds (registered bounds govern — a proposal's claimed bounds are ignored); every applied change is audited (`ParameterChangeRecord`) and reversible (`rollback` walks an undo stack; rollback-of-rollback never re-applies). **NO SOURCE MUTATION**: the store exposes no file/code/config/exec surface; proposals never self-apply — application is an explicit, audited, caller-owned step. Metrics come from caller-supplied observable data or a structural `MetricFeedbackPort` (e.g. `executionStatsFeedbackPort` over 16B execution-memory stats); no hidden background collection. New deny states: `adaptation_out_of_bounds`, `parameter_unknown`, `rollback_target_missing`.

## Algorithm contract

The TypeScript contract below is now implemented and pinned in
`packages/algorithms/src/types.ts` (17A). The registry surface is
`StrategyRegistry` (selection, family binding, replaceable contracts,
deterministic fingerprint); the observable evaluation entry point is
`StrategySelector` (bounded input, fail-closed denials, authority re-stamping,
optional ledger observability).

```ts
export interface AlgorithmStrategy<I = unknown, O = unknown> {
  id: string;
  family: AlgorithmFamily;       // closed ten-family union
  version: string;
  implemented: boolean;
  description: string;
  evaluate(input: I, context: RuntimeContext): Promise<O>;
}
```

Selection is deny-by-default: an unregistered family+id pair denies with
`unknown_family` / `unknown_strategy`; a strategy marked `implemented:false`
denies evaluation with `strategy_not_selected` — a missing implementation is a
machine-readable denial, never a guessed result.

**17B deny-state additions:** `invalid_state` covers malformed caller-owned
state machine state (OIDA loop states), malformed goal-priority hints, and
malformed budget surfaces — precedence over size checks. The recommendation
carries two optional 17B fields: `reasoningSummary` (conclusion-only, capped
at `ALGORITHM_MAX_REASONING_SUMMARY_CHARS = 256` by the selector; explicitly
NOT private chain-of-thought) and `nextOidaState` (computed next machine
state, passed through only when well-formed; the caller owns all mutation).

**17C additions:** `AlgorithmDenyReason` += `retrieval_unavailable` (memory
port absent/denying/malformed — fail-closed, distinct from invalid_input).
`AlgorithmDecisionInput` += optional `grantedCapabilities` (bounded,
validated; malformed ⇒ `invalid_state`). `AlgorithmRecommendation` +=
optional `riskVerdict` (pinned `allow|restrict|deny` with bounded reason;
advisory data only — authority pins unaffected). Integration helpers:
`memoryRetrievalPortAdapter`, `projectHitsToLabels`, `applyRiskVerdict`,
`filterSkillsByCapabilities`.

**17D additions:** `AlgorithmDenyReason` += `adaptation_out_of_bounds` |
`parameter_unknown` | `rollback_target_missing`. `AlgorithmDecisionInput` +=
optional `metrics` (bounded, finite-only; malformed ⇒ `invalid_state`).
`AlgorithmRecommendation` += optional `adaptationProposal` (pure data,
selector-pinned, never self-applied). Contracts: `MonitorMetric`,
`MetricFeedbackPort`, `ParameterBounds`, `ParameterSensitivity`,
`TunableParameterState`, `ParameterChangeRecord`; store caps
`ALGORITHM_MAX_METRICS=32`, `ALGORITHM_MAX_TUNABLE_PARAMETERS=64`,
`ALGORITHM_MAX_PARAMETER_HISTORY=32`, `ALGORITHM_MAX_PARAMETER_MAGNITUDE=1e6`.

## Rule

Algorithms recommend/compute. Policy authorizes. Runtime executes.
