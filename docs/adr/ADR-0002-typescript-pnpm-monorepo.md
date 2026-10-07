# ADR-0002 — TypeScript + pnpm Monorepo (Toolchain & Package Layout)

- Status: Proposed
- Date: 2026-09-05

## Context

The language/runtime/package-manager choice constrains every downstream
decision: type system, execution model, dependency resolution, supply-chain
surface, test ecosystem, and Linux runtime interop. The prompt-pack specifies
TypeScript + Node.js + pnpm workspaces as the default, with strict TypeScript
and pinned versions.

The repository currently contains **zero manifests, zero lockfiles, and zero
tsconfigs** (see CURRENT_STATE.md → Toolchain / Package Structure).

## Decision

1. **Language**: TypeScript. All first-party code is authored in `.ts` (or
   `.mts`/`.cts` when module boundaries require it). Transpilation target and
   module format will be settled in the implementation prompt.
2. **Strictness**: `strict: true` in every `tsconfig.json`. No sub-package may
   opt out of `strict`.
3. **Runtime**: Node.js LTS/Current as declared in `PROJECT_SETUP.md`
   (currently pinned to discovered `v22.15.0` — pending human ratification,
   CURRENT_STATE.md D5).
4. **Package manager**: pnpm. Version pinned to discovered `10.11.1` or a
   minor-range `.npmrc`/`packageManager` field to be set at implementation
   time.
5. **Workspace layout (pnpm workspaces)**:

   ```
   apps/
     cli/                  # menog CLI entrypoint: bin entry, command parser
   packages/
     core/                 # types, intent model, task model, pipeline glue
     verbs/                # verb contracts + verb registry (see VERB_REGISTRY_v0)
     algorithms/           # algorithm strategy contracts + registry
     policy/               # capability model + policy evaluator (gate)
     runtime-linux/        # unprivileged local command runner + allowlist
     event-ledger/         # append-only event store + hash chain
     shared/               # shared primitives (paths, hashing, validation)
   tests/
     unit/                 # per-package unit tests
     integration/          # pipeline/integration tests
     security/             # threat-model/deny tests (SECURITY_BASELINE.md)
     fixtures/             # fixture repositories and canned data
   docs/adr/               # this ADR + future decisions
   security/               # (deferred placeholder for) policies/threat models
   ```

   Only directories that contain a valid manifest or non-placeholder content
   are actually created at bootstrap. No empty directories are committed.

6. **Version pinning**: First-party packages use caret-free `0.0.x` or
   workspace protocol where appropriate. Third-party deps are pinned to
   exact patch versions or tilded to patch per package.
7. **Lockfile**: `pnpm-lock.yaml` is committed and treated as a security
   boundary input; `pnpm install --frozen-lockfile` in CI after Day 1.
8. **Formatter / linter**: added only if deterministic and fast. Decision is
   deferred to Prompt 0x (CURRENT_STATE.md D11); the code style in Phase 0 is
   whatever `tsc` accepts.

## Alternatives considered

1. **Go / Rust single binary** — rejected for Phase 0 because the baseline
   prompt-pack specifies TypeScript and the agentic algorithm contracts are
   expressed in TypeScript shapes in the docs. Re-evaluate at end of Phase 0
   via a new ADR.
2. **npm workspaces / yarn (berry) / bun** — rejected. pnpm is declared the
   default by the prompt-pack.
3. **Turborepo / Nx** — deferred. No orchestration layer in Phase 0.
4. **Deno / Bun runtime** — deferred. Node.js is the Phase-0 target.

## Security impact

- `strict: true` eliminates a class of runtime-null / any-typed escape.
- pnpm hoisting rules are stricter than npm/yarn classic by default →
  shallower supply-chain surface for phantom-dep attacks. Frozen lockfile in
  CI prevents un-reviewed dep drift.
- No monorepo task runner in Phase 0 = less build-time code that could
   execute untrusted pre/post scripts. `preinstall`/`postinstall` scripts of
   third-party deps are an open risk; review them explicitly before first
   `pnpm install`.
- Exact package layout constrains where untrusted code can land:
   `tests/fixtures/` are deliberately treated as untrusted inputs by the
   policy layer.

## Reversibility

- Package layout (split into packages) is mostly reversible at the monorepo
  boundary via workspaces config; internal import paths must be updated, but
  persisted formats (events) are unaffected.
- Switching language/runtime/PM **after** code exists is moderately costly;
  hence this ADR at the architecture baseline before any code is written.
- Any change of runtime or PM after the first commit requires a superseding
  ADR because it modifies the trust and execution boundaries.

## Evidence

- Prompt-pack default: [README.md → Repository variables](README.md#L65-L76)
- Baseline toolchain spec: [docs/PROJECT_BASELINE.md → Phase-0 scope](docs/PROJECT_BASELINE.md#L24-L38)
- Expected layout (mirrored here): [docs/ARCHITECTURE_BASELINE.md → Minimal Phase-0 architecture](docs/ARCHITECTURE_BASELINE.md#L1-L23)
- Current toolchain facts: `CURRENT_STATE.md` → Toolchain
