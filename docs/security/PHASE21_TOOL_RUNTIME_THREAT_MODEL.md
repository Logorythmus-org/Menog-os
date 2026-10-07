# Phase 21 — Governed Tool Runtime Threat Model

**Scope:** governed tool/skill execution INSIDE the Phase-20 OS boundary, from a validated
request to the point where the Phase-20 isolation layer would take over (21C, future).
**Mode:** CONTRACT / TEST-FIRST — 21A defines threats and contracts; no execution exists yet.
**Schema:** `menog-tool-runtime-contract/v0` (`packages/runtime-linux/src/toolruntime/`).
**Date:** 2026-09-27 · **LOCAL-ONLY** · Phase 20 remains frozen.

Authority chain (invariant): Planner proposes → Allocation scopes → Policy authorizes →
Phase-20 Isolation constrains → Tool Runtime executes → Ledger observes.
**Policy remains the sole logical authorization authority.** Registry, manifests, and skills
never grant authority. An agent is never a super-agent: role-distributed least privilege holds.

---

## 1. System decomposition (as contracted in 21A)

| Element | Contract type | Trust posture |
|:--|:--|:--|
| Tool manifest (`ToolManifest`) | request package | untrusted until validated; capabilities are REQUESTS, never grants |
| Registry/lifecycle record | availability metadata | registration NEVER authorizes; `registered/enabled` only permit gate evaluation |
| Input envelope (`ToolInputEnvelope`) | validated agent input | untrusted data; can only be rejected, never widened |
| Execution request (`ToolExecutionRequest`) | gate input | task scope + agent capabilities come from allocation/identity records, never self-asserted |
| Execution plan (`ToolExecutionPlan`) | authority output | exists ONLY when the full intersection holds |
| Evidence (`ToolExecutionEvidence`) | four layers | requested ⊇ authorized ⊇ enforced ⊇ observed; overclaim = typed failure |
| Tool output (future, 21C) | untrusted data | never a system/policy instruction by default |

## 2. Threat → control → primitive → residual → negative test → evidence

| ID | Threat | Menog control (21A contract) | Enforcement primitive (present/future) | Residual risk | Negative test | Evidence |
|:--|:--|:--|:--|:--|:--|:--|
| T21-01 | Spoofing/substitution (request claims another tool or version) | request/envelope identity must equal manifest identity (toolId+version) | gate order 2 denies before any authority is consulted | none within contract layer; runtime-level misbinding handled at 21C | `toolruntime-contract.test.ts` "spoofed identity…" | gate decision records + evidence manifestHash |
| T21-02 | Capability inflation (manifest claims more than it may use) | capabilities are requests; only the task∩agent∩requirement intersection counts | gate order 3; empty/uncoved required demand denies | a tool whose task AND agent both over-grant — controlled by allocation/Policy, out of 21A scope | "capability inflation is inert" | evidence `authorized` layer |
| T21-03 | argv injection (shell metacharacters, option smuggling) | argv-only envelope; metacharacters rejected at validation | envelope validation (`ARGS_FORBIDDEN`); 20C launcher is argv-only by construction | argument VALUES still reach the tool — bounded, not interpreted | "rejects shell metacharacters in argv" | evidence requested/enforced layers |
| T21-04 | cwd escape (outside authorized workspace, `..` traversal) | `isCwdInsideWorkspace` prefix containment with `..` resolution | gate + 20C Landlock write-class confinement at execution | symlinked paths inside the workspace are a 20C/21C runtime concern (Landlock binds real paths) | "cwd confinement: escape … refused" | evidence enforced layer |
| T21-05 | env/secret leakage (values smuggled through requests) | env allowlist carries NAMES only; values never travel in envelopes | envelope validation (`ENV_NAME_FORBIDDEN`) | env VALUES sourced at execution time; supplied by runtime, never agent | "env allowlist accepts NAMES only" | evidence requested layer (names only) |
| T21-06 | Output prompt injection (tool output read as instruction) | `outputTrust: "untrusted_data"` is a REQUIRED, fixed field | type system + future 21C output validation; Ledger records output as data | an agent may still treat data as instruction — agent-side hardening remains standing debt | type-level pin (fixture asserts `outputTrust`) | evidence status/observed layers |
| T21-07 | Network egress via tool execution | Policy deny first (sole authority); profile must also support egress | Day-1 deny + 20B/20C netns deny-by-default (0 routes/0 addrs, proven in 20E A10) | egress authorization flows are a future Policy extension; today deny-only | "policy deny never reaches a plan" + 20E A10 | evidence policyOutcome + isolationProfileId |
| T21-08 | Child/grandchild escape (target spawning beyond boundary) | profile demands PID-namespace isolation; 20C group-scoped cleanup | 20C launcher (deadline kill, whole process group) + 20E A5/A13 | none measured on target; native-Linux deferred (unchanged) | 20E A5/A13 (existing) | isolation evidence per-primitive |
| T21-09 | Resource abuse (runaway time/output) | envelope bounds: timeoutMs ≤ 600000, maxOutputBytes ≤ 4 MiB, argv ≤ 64×4096 | envelope validation + 20C deadline supervision (exit 124) | CPU/memory bounding remains rlimits-only on target (cgroups unsupported — carried debt) | "constrains argv count/size, timeout, output" | evidence enforced layer + launcher journal |
| T21-10 | Version drift / rollback to stale manifest | explicit semver; `checkVersionDrift` pins request to registration hash | registry hash pinning; drift = `MANIFEST_HASH_MISMATCH`, re-registration required | none in contract; registry storage is 21B scope | "same hash passes; any drift fails closed" | evidence manifestHash |
| T21-11 | Confused deputy (permissive tool used for another authority's intent) | full five-way intersection: task scope ∩ agent capability ∩ tool requirement ∩ Policy ∩ isolation; order is fixed, first deny wins | gate order 1–5; deny statuses distinct from run statuses | none in contract layer | "empty intersection denies before policy is consulted" | evidence authorized layer + status |
| T21-12 | Evidence spoofing (claiming authority never exercised) | four-layer ordering enforced: enforced ⊆ authorized ⊆ requested, observed ⊆ enforced; denial statuses may claim nothing | `buildToolEvidence` typed failures | ledger binding is 21E scope; until then evidence is in-process | "rejects overclaims in every direction" | evidenceHash (canonical, deterministic) |
| T21-13 | Quarantine bypass (re-enabling a quarantined/retired tool) | closed lifecycle machine: quarantined → retired ONLY; retired terminal | `transitionLifecycle` + gate order 1 refuses non-executable states | none in contract | "quarantined cannot return to any executable state" | lifecycle transition records (21B) |

## 3. Explicit non-goals (never represented in this layer)

Marketplace · remote plugins / MCP federation · installs/downloads · LLM tool selection ·
autonomous skill creation. Any of these would require a new human gate; their absence is a
design property, not an omission.

## 4. Residual-risk register (honest, carried forward)

1. **CPU/memory bounding is rlimits-only** on the WSL2 dev target (cgroup-v2 controllers
   unsupported) — unchanged from the Phase-20 freeze; explicit degradation per contract.
2. **Kernel-side read confinement** remains a Phase-20 residual (20E A4): reads are
   Menog-allowlist-scoped, not Landlock-enforced, at ABI 1.
3. **Native-Linux validation** remains deferred; WSL2 results never certify native hosts.
4. **Output-instruction separation** (T21-06) is type-level today; behavioral validation of
   tool output is 21C/21E scope.
5. **Registry storage integrity** (persistence of lifecycle state and hashes) is 21B scope;
   21A defines the transition law but not the store.
