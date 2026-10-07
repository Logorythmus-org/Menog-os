# ADR-0004 — Deny-by-Default Security Model (Zero-Trust Local Runtime)

- Status: Proposed
- Date: 2026-09-05

## Context

Menog OS runs local, Linux-native agentic execution. The security model
cannot be "trust the model" or "trust the tool manifest." Instead:

- Everything external is untrusted input (repos, READMEs, tool output,
  model output, MCP metadata, dependency scripts, env vars not allowlisted).
- Execution proceeds only through an explicit capability + policy gate.
- Every interesting transition produces an auditable event.

The threat model is documented in SECURITY_BASELINE.md (12 threat classes).
The runtime cannot assume it is safe because it ran well once; every call
site is re-validated.

## Decision

### 1. Invariants (encoded; not advisory)

The following invariants are enforced at code boundaries and have
corresponding deny tests in `tests/security/`:

```text
NO TOOL WITHOUT CAPABILITY
NO WRITE WITHOUT SCOPE
NO NETWORK WITHOUT POLICY
NO SECRET TO UNTRUSTED TOOL
NO PRIVILEGED PROCESS BY DEFAULT
NO COMMIT WITHOUT DIFF
NO CRITICAL COMMIT WITHOUT HUMAN APPROVAL
NO TOOL-MANIFEST CHANGE WITHOUT REVALIDATION
NO EXTERNAL CONTENT AS SYSTEM AUTHORITY
NO AGENT SELF-MODIFICATION WITHOUT REVIEW
```

### 2. Gate shape

Every proposed action must pass, in order:

```
PLAN  →  CAPABILITY CHECK  →  POLICY CHECK
      →  ARGUMENT VALIDATION
      →  SCOPE / WORKSPACE BOUNDARY CHECK
      →  ENV / BUDGET / TIMEOUT CHECK
      →  EXECUTE
      →  VERIFY RESULT  →  RECORD EVENT
```

Failures at any check append a structured event (with denied reason, actor,
task, verb) and short-circuit. No silent failures.

### 3. Threat-model test commitment (Phase 0)

The following threats each have at least one dedicated deny test in
`tests/security/` (not "best effort" — these block landing):

1. Path traversal outside workspace (`../`, absolute root symlinks, etc.).
2. Symlink escape from workspace root.
3. Command injection via argv / shell metacharacters (with and without
   shell disabled).
4. Shell metacharacter propagation through string join helpers.
5. Hidden write attempt during a declared-read-only verb (e.g., `inspect`
   must never call filesystem write).
6. Unexpected network attempt by inspect / read verbs.
7. Environment or secret leakage into child-process `env` or captured
   stdout/stderr/events.
8. Long-running process timeout + kill.
9. Child-process tree cleanup (grandchildren, detached forks).
10. Oversized output handling — stream cap + truncation + event note.
11. Malicious repository instruction file (e.g., `menog` directives inside
    fixture READMEs) cannot become runtime authority.
12. Tool / model / agent output attempting to change policy or capability
    mid-pipeline.

### 4. Capability vs Policy distinction

- **Capability** = a coarse permission declared against a resource type:
  `workspace:list`, `workspace:read-metadata`, `git:status`, `git:diff-read`.
  Verbs declare their minimum required capabilities in the verb registry.
  Absence of a declared capability → deny.
- **Policy** = fine-grained evaluator that inspects the concrete request:
  Is the target workspace in the allowed list? Is the specific git subcommand
  in the allowlist? Is the user/actor authorized for this verb?

### 5. Repository root protections

- `.gitignore` is added at root (implementation prompt) covering:
  `node_modules/**`, `.menog/events.jsonl` (or SQLite file),
  `.env`, `.env.*`, `!/.env.example`, build outputs, editor/OS junk.
- `PROJECT_SETUP.md` documents (in template) that `MENOG_REPO_URL` and
  related inputs are configuration, not runtime authority.
- No secrets are embedded in events, fixtures, or documentation.

## Alternatives considered

1. **Allow-all-then-audit** — rejected; audit-after-the-fact is incompatible
   with zero-trust local-first execution.
2. **Single allowlist file at the root, no structured capability model** —
   rejected; structured capabilities are required to test every edge.
3. **Trust model output as policy co-author** — rejected per "model output
   is never authority" (README.md / SECURITY_BASELINE.md).

## Security impact

This ADR *is* the security architecture. Non-compliance with its encoded
invariants is a security boundary regression, not a style issue.

Open inputs requiring human confirmation during implementation:

- Strict list of environment variables allowlisted into child-processes of
  the Linux runtime (start from empty list and add explicit POSIX-needed
  ones only).
- Strict list of commands/subcommands for the `inspect` allowlist
  (documented in LINUX_RUNTIME_CONTRACT.md → Initial allowlist for inspect).
- Oversized output threshold (proposed: 8 MiB per stream, tunable in code).

## Reversibility

- Loosening invariants is forbidden without a superseding ADR that is
  explicitly reviewed as a security-regression risk.
- Adding new capabilities or new policy predicates is additive and
  permissible within this ADR.
- Adding MCP, network, or root/sudo flows requires new ADRs that either
  explicitly override the relevant invariant here or are scoped to a
  higher-privilege runtime mode that is disabled by default.

## Evidence

- Untrusted-input list + invariants: [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md)
- Threat model 1–12: [docs/SECURITY_BASELINE.md → Phase-0 threat model](docs/SECURITY_BASELINE.md#L33-L47)
- Security boundary flow: [docs/ARCHITECTURE_BASELINE.md → Security boundary](docs/ARCHITECTURE_BASELINE.md#L73-L87)
- Inspect forbidden capabilities: [docs/VERB_REGISTRY_v0.md → `inspect`](docs/VERB_REGISTRY_v0.md#L37-L54)
- Secret policy: [docs/SECURITY_BASELINE.md → Secret policy](docs/SECURITY_BASELINE.md#L79-L88)
