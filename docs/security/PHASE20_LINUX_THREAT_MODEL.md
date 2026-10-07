# Phase 20 — Linux Isolation Threat Model

**Gate:** 20B (CONTRACT / TEST-FIRST) · **Date:** 2026-09-27
**Scope:** the Linux enforcement surface formalized by the 20B contracts
(`packages/runtime-linux/src/isolation/`) and measured by the 20A probes
(`docs/release/PHASE20_LINUX_CAPABILITY_MATRIX.json`). Excludes by frozen scope:
executable rollback, durable persistence, 14C/14E batch mutation, 19D.
**Ground rule:** Policy is the sole logical authorization authority; Linux
isolation only enforces/reduces authority. Policy ALLOW is necessary but never
sufficient — every execution additionally requires a fail-closed isolation
decision and per-primitive enforcement evidence.

---

## 1. Contract→threat linkage

Ten threat classes × six columns. Menog controls are the **existing** frozen
authorities; Linux primitives are what 20C will apply (per-primitive, fail-closed);
residual risk is what remains **after** the combined controls, honestly stated.

| # | Threat | Menog control (existing, frozen) | Linux primitive (20C) | Residual risk | Negative test (contract-level, this gate) | Evidence (20C must emit) |
|---|---|---|---|---|---|---|
| T1 | Filesystem escape incl. symlink escape | Workspace resolver + deny-by-default policy (Day-1 deny-workspace-write); controlled-write scope validation | `landlock_fs` ruleset on the workspace (read) + deny-write outside; `ns_mount` private view | Kernel-bypass bugs in Landlock itself (historically none exploitable unprivileged); in-workspace malicious writes remain possible by design (policy-approved) | `isolation-contract.test.ts` — required `landlock_fs` missing/ABI-low ⇒ fail closed; agent profile cannot relax | `IsolationEvidence.enforced.landlock_fs = {applied, abi, detail}` in ledger event |
| T2 | TOCTOU between policy check and execution | Single authoritative gate sequence (policy decision precedes spawn/write); no parallel path | `ns_mount` + Landlock at **kernel level** closes the gap the userspace check cannot: the fs view itself is confined at execution time | Residual: paths *inside* the granted set can still race (accepted, policy-visible) | Same suite — UNVERIFIED state treated as fail-closed (no "probably fine") | per-primitive `applied` flags recorded at execution start, hashed into `IsolationEvidence` |
| T3 | Process escape (orphan/spawn outside containment) | Allowlist argv-only executor; policy `process:*` denies | `ns_pid` (target sees only itself), `no_new_privs`, `seccomp_filter` | Escape via kernel prctl/fork exploits (out of scope of unprivileged primitives; bounded by seccomp) | fail-closed on `ns_pid` ≠ SUPPORTED (test: UNVERIFIED ⇒ deny) | `ns_pid`/`no_new_privs`/`seccomp_filter` applied-records + decision hash |
| T4 | Resource exhaustion (CPU/mem/fd/process flood) | Policy budgets (maxSteps etc. are planner-level, not OS-level) | **On WSL2 dev target: none available** (hybrid cgroups, zero controllers delegated) ⇒ `rlimit_set` only, explicit degradation recorded | **Highest residual risk on dev target**: no kernel memory/pids bound; native Linux (systemd delegation) closes this; 20C must degrade explicitly, never claim cgroup enforcement | cgroup-dependent profile fails closed on the real 20A matrix (cross-gate test) | degradation entry `cgroup_v2_controllers` with consequence text; NO cgroup applied-record on WSL2 |
| T5 | Network egress | Policy Day-1 deny `network:external`; no network API in runtime | `ns_net` fresh namespace (no interfaces ⇒ deny-by-default); `landlock_net` on ABI ≥ 2 (withheld on ABI 1 per contract) | Inherited AF_UNIX fds could carry egress-adjacent channels if ever passed into the target — 20C must not pass any | agent proposal may ADD `ns_net` (restriction); removing it fails closed | `ns_net` applied-record; `landlock_net` withheld-record on ABI 1 (never approximated) |
| T6 | Env leakage | `ENVIRONMENT_ALLOWLIST` (allowlist-only env passing) | `ns_mount`/`ns_user` fresh view; env scrubbing at spawn | Env is attacker-visible inside the target by design (it's the target's env) — allowlist keeps it minimal | not contract-explicit (runtime property) — covered by existing deny-tests | applied-records for the primitives; env allowlist re-asserted by verify-local |
| T7 | Unauthorized executable | Exec-gate Day-1 allowlist (exact argv); `BLOCKED_BASE_NAMES` | `ns_mount` (no unexpected binaries visible), `seccomp_filter` (blocks execve of unusual paths is **not** its job — allowlist is), Landlock EXECUTE rules | Allowlisted binary misbehaving legitimately (git hooks etc.) — bounded by read-only side-effect class | profiles cannot mark `seccomp_filter` optional-with-proceed silently (note required) | `seccomp_filter` applied-record + allowlist match id in exec evidence |
| T8 | /proc inspection (cross-process info disclosure) | No cross-process surface in the runtime today | `ns_pid` (target's /proc shows only itself) | Host /proc stays readable to the **host-side** runtime (by design; the *target* is contained) | covered indirectly: `ns_pid` required-fail-closed test | `ns_pid` applied-record; `proc_hidepid` not relied upon (UNSUPPORTED on WSL2) |
| T9 | Privilege escalation | Policy denies `process:privileged` Day-1; no privileged helper exists | `no_new_privs` + drop-all-caps target + unprivileged userns creation path | Kernel LPE bugs (0-day class) — out of scope for any userspace contract; NNP blocks the classic setuid path | agent-proposal relaxation rejected (`PROFILE_RELAXES_BASELINE` test) | `no_new_privs` applied-record; caps-dropped detail string |
| T10 | Downgrade (silent fallback / weaker-than-claimed isolation) | Frozen no-silent-fallback invariant; observability: ledger | The 20B contracts themselves: `IsolationDecision.degradations[]` + anti-overclaim `buildIsolationEvidence` | A buggy 20C caller ignoring `canProceed` — mitigated by making the combined gate the only sanctioned junction (`assertIsolationPermits`) | `EVIDENCE_OVERCLAIM` rejection tests; UNVERIFIED ⇒ fail-closed tests | evidence hash binding decision+records; degradation entries verbatim from profile |

## 2. Fail-closed semantics (normative)

1. `evaluateIsolation(profile, snapshot)` returns `canProceed=false` iff any
   required primitive's measured state ≠ SUPPORTED or ABI < demand.
   UNVERIFIED is never treated as SUPPORTED (tests enforce all four
   non-supported states).
2. `assertIsolationPermits(policyOutcome, decision)` is the only sanctioned
   junction of the two authorities; it can only deny.
3. Optional-primitive absence produces an explicit degradation entry with the
   profile's own consequence text — or, when `onMissing='proceed'`, nothing at
   all (the profile author asserted no consequence under validation).
4. Evidence claims are bound to the decision: `applied=true` is rejected unless
   the decision satisfied that primitive (`EVIDENCE_OVERCLAIM`).

## 3. Authority separation (normative)

- `IsolationProfile` carries no capabilities, verbs, actors, or policy fields.
- `composeProfileBaseline` output always has `origin="human_reviewed"` — the
  agent proposal is consumed and discarded, its restrictions folded into the
  human-rooted result; the chain of authority is never routed through the agent.
- Isolation can reduce (deny) but never expand (grant): there is no code path
  from a profile to a capability.

## 4. Threat-driven profile guidance (informative, for 20C)

- Interactive exec class: baseline as tested (`ns_user`+`ns_mount`+`ns_pid`+
  `landlock_fs`@ABI≥1+`no_new_privs` required; cgroups optional-degrade).
- Resource-bounded class: **not achievable on the WSL2 dev target** — requires
  native Linux with systemd cgroup delegation (`cgroup_v2_controllers`
  required ⇒ fails closed on WSL2, correctly).
- Network-restricted class: add `ns_net` required; `landlock_net` minAbi 2
  (withheld on the ABI-1 dev kernel — never approximated).

## 5. Traceability

- Primitive vocabulary ⇔ `ISOLATION_PRIMITIVE_IDS` (`types.ts`)
- States ⇔ 20A matrix vocabulary; snapshot ⇔ `IsolationCapabilitySnapshot`
- Real-matrix validation: `tests/unit/isolation-contract.test.ts` (cross-gate suite)
- 20A evidence: `docs/release/PHASE20_LINUX_CAPABILITY_MATRIX.json`
- Entry invariants: `docs/release/PRE20_R1_ENTRY_FREEZE.md` §5

## 6. Governance

Unchanged and preserved verbatim:

```text
PR-01 HUMAN_DISPOSITION_PENDING
PR-02 HOLD
PR-03 HUMAN_DISPOSITION_PENDING
PR-04 HOLD
PR-05 HOLD
COMMIT AUTHORIZATION NOT GRANTED
PUSH AUTHORIZATION NOT GRANTED
PUBLICATION AUTHORIZATION NOT GRANTED
```
