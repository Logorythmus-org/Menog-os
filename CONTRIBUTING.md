# Contributing to Menog OS

Thank you for contributing to Menog OS.

The project is experimental, but contributions are open. The goal is to make participation easy
without weakening the runtime's security, authority, evidence, or reproducibility boundaries.

## Start here

Before opening a pull request:

1. Read the project [README](README.md).
2. Check existing [Issues](https://github.com/Logorythmus-org/Menog-os/issues).
3. For a first contribution, prefer an issue labelled `good first issue` or `help wanted`.
4. For security-sensitive findings, stop and read [SECURITY.md](SECURITY.md). Do not disclose
   exploit details publicly.

## Contribution paths

### Fast contribution path

Use this path for changes that do not alter security or authority semantics:

- documentation;
- examples;
- tests;
- CLI help and usability;
- reproducibility improvements;
- non-semantic refactors;
- typo and error-message improvements;
- contributor tooling.

A well-scoped PR can usually proceed directly if the issue and expected behavior are clear.

### Core change path

Open or discuss an issue before implementation when a change affects:

- `@menog/policy`;
- runtime execution or isolation;
- capabilities or authority;
- cryptography, identity, trust, federation, or mesh admission;
- ledger/evidence semantics;
- secret handling;
- network boundaries;
- persistence/recovery guarantees;
- security-sensitive CI or supply-chain behavior.

Core changes need explicit design rationale and stronger review evidence.

## Development setup

```sh
git clone https://github.com/Logorythmus-org/Menog-os.git
cd Menog-os

node scripts/setup-local.mjs
pnpm typecheck
pnpm build
pnpm test
```

Use the committed lockfile. Do not casually rewrite dependency versions or generated lockfile state.

## Branch naming

Use names that describe the work, not the tool or model used:

- `feat/<topic>`
- `fix/<topic>`
- `docs/<topic>`
- `test/<topic>`
- `security/<topic>`
- `governance/<topic>`
- `research/<topic>`

Avoid branch names based on agent names, model names, prompt IDs, or internal phase numbers.

## Pull requests

Keep PRs small enough to review.

A PR should explain:

- what problem it solves;
- why the change belongs in Menog OS;
- what files or boundaries it touches;
- how it was tested;
- whether behavior or authority semantics changed;
- any known limitations.

Before requesting review:

```sh
pnpm typecheck
pnpm build
pnpm test
```

CI and Security checks must remain green unless the PR explicitly demonstrates and resolves a
pre-existing failure.

## AI-assisted contributions

AI assistance is allowed.

If AI materially generated or transformed code, tests, documentation, or analysis, disclose it in
the PR template:

- what tool/model assistance was used;
- which parts were materially AI-assisted;
- what the human contributor verified.

The contributor remains responsible for correctness, licensing, provenance, security, and test results.

## Coding expectations

- TypeScript remains strict.
- Prefer explicit types at authority/trust boundaries.
- Do not bypass policy checks to make a test pass.
- Do not convert an unsupported/inconclusive result into a pass by changing assertions.
- Avoid hidden network calls, telemetry, or secret access.
- Preserve deterministic behavior where practical.
- Keep dependencies minimal; new runtime dependencies require explicit justification.

## Commit style

Clear imperative commit messages are preferred. Conventional Commit prefixes are welcome but not mandatory:

- `feat:`
- `fix:`
- `docs:`
- `test:`
- `ci:`
- `security:`
- `governance:`

## Licensing and provenance

Code contributions are accepted under the repository's applicable source licence, currently MPL-2.0
for core source paths. Documentation/configuration paths may use the licence metadata already assigned
to those paths.

By submitting a contribution, you represent that you have the right to submit it under the applicable
repository licence.

Do not submit:

- employer-confidential material;
- copied code without compatible licence/provenance;
- secrets or credentials;
- private datasets or personal data;
- generated material whose rights or provenance you cannot explain.

## Review and merge

A positive review is technical feedback; merge authority remains with repository maintainers.

Maintainers may ask for:

- smaller scope;
- additional tests;
- architecture notes;
- security review;
- provenance clarification;
- a separate issue or RFC for high-impact changes.

See [GOVERNANCE.md](GOVERNANCE.md) and [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md).
