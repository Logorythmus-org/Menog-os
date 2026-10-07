# Menog OS — Third-Party Notices

Classification: PUBLIC
Generated: 2026-09-05 (PROMPT 11A §8)
Reconciled: 2026-10-07 (public-state reconciliation after PR #1 merge)
Audit baseline: committed pnpm-lock.yaml (lockfileVersion 9.0) and the PR #1 public verification surface.

IMPORTANT — this table is populated ONLY with locally-determinable facts.
No claims of legal compatibility are made. Licenses classified per
THIRD_PARTY_POLICY.md §License Classification Scheme.
UNKNOWN rows MUST NOT be pushed to a public remote without HUMAN override.

CURRENT PUBLIC TREE NOTE — 2026-10-07

  The live root devDependency set is:
    @types/node 22.10.2
    @webgpu/types 0.1.74
    rimraf 6.1.3
    typescript 5.7.2
    vitest 2.1.9

  The committed lockfile also carries the explicit security overrides:
    brace-expansion 5.0.12
    source-map-js 1.2.2

  The FPR-R6D / PR #1 licence verification reported 57 third-party package
  entries with 0 denied licences:
    MIT 44, BSD-3-Clause 2, Apache-2.0 2, BlueOak-1.0.0 7, ISC 2.

  Table B below is retained as the earlier GP-R5 provenance snapshot. It is
  NOT the authoritative current transitive closure after the dependency
  remediation that preceded PR #1. For the current closure, run the manual
  License workflow / `pnpm licenses list --json` against the committed
  frozen lockfile. The historical table is intentionally not rewritten from
  inference.

GP-R5 RECONCILIATION NOTE — READ BEFORE ACTING ON THIS FILE

  The transitive closure below is now COMPLETE AS A FACTUAL INVENTORY.
  It was generated from `pnpm licenses list --json` run against this
  working tree, and every value in Table B is a fact read from local
  package metadata.

  Completing an inventory is NOT an acceptance decision. GP-R5 does NOT
  decide compatibility, does NOT ratify the licence choice, does NOT
  resolve the copyright holder, and does NOT accept any dependency.
  Every row in this file still reads:

      Status   = PENDING → HUMAN MUST RATIFY
      Approver = HUMAN_REVIEW_REQUIRED

  THIRD_PARTY_POLICY.md §Dependency Acceptance Pipeline stage 3 states
  that compatibility "is NOT automated. A human must sign off on the
  combination". That human sign-off has not happened. This file remains
  an input to that decision, not the decision.

See also: pnpm-lock.yaml, root package.json `devDependencies`,
THIRD_PARTY_POLICY.md for full acceptance pipeline.

============================================================
Row Legend
============================================================
  D  = Direct dependency (root package.json lists it)
  T  = Transitive (brought in by a direct dep; not listed in root package.json)
  Class = PERMISSIVE | WEAK COPYLEFT | STRONG COPYLEFT | NETWORK COPYLEFT | PROPRIETARY | UNKNOWN
  Status = ACCEPTED (class OK + provenance verified) | REVIEW (needs human) | PENDING (automated only) | REJECTED
  "—"  = the package's LOCAL metadata declares no repository/homepage field.
          No value was inferred or substituted.

============================================================
Table A — Direct dependencies and non-package material
============================================================

| Name | Version | D/T | Upstream URL (from package.json / npm) | SPDX (proposed) | Class | Provenance | Menog Mods? | Status | Approver | Notes
|---|---|---|---|---|---|---|---|---|---|---|
| typescript | 5.7.2 | D | https://github.com/microsoft/TypeScript | Apache-2.0 | PERMISSIVE | pnpm-lock integrity sha512; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only build tool; Apache-2.0 widespread. Only .tsbuildinfo is a build artefact; the tsc binary is not redistributed by Menog. |
| vitest | 2.1.9 | D | https://github.com/vitest-dev/vitest | MIT | PERMISSIVE | pnpm-lock integrity; npm | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only test runner. Its transitive closure is now COMPLETE — see Table B (rows 1–68). Flagged in the recorded pnpm audit. |
| @types/node | 22.10.2 | D | https://github.com/DefinitelyTyped/DefinitelyTyped | MIT | PERMISSIVE | pnpm-lock integrity; npm | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | TypeScript type stubs only. No runtime bits shipped. |
| rimraf | 6.1.3 | D | https://github.com/isaacs/rimraf | ISC | PERMISSIVE | pnpm-lock integrity; npm | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only clean-script helper. Root of the audit-flagged brace-expansion chain (rimraf>glob>minimatch>brace-expansion). |
| @webgpu/types | 0.1.74 | D | https://github.com/gpuweb/types | BSD-3-Clause | PERMISSIVE | pnpm-lock integrity; npm | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | ADDED BY GP-R5. Declared in root package.json devDependencies and present on disk, but absent from the Day-1 table — a factual omission, now recorded. TypeScript type declarations for the WebGPU API only; no runtime bits shipped. BSD-3-Clause is read from the package's own manifest, not asserted as compatible. |
| node:* stdlib (child_process, fs, crypto, path, os, net, …) | engines >=22.0.0 | implicit | https://github.com/nodejs/node | MIT (Node.js stdlib wrapper license headers) | PERMISSIVE | bundled with Node.js runtime, NOT vendored in repo | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Used via ESM `import from "node:*"`. Package.json declares `engines.node = ">=22.0.0"` (there is no single pinned runtime version; the Day-1 figure "22.15.0" was a point-in-time observation). Node.js runtime itself is not redistributed in the Menog repo. Exactly one governed `node:net` import site exists in production source (`packages/durable-state/src/endpointListenerBoundary.ts`). |
| MPL-2.0 license text (LICENSE + LICENSES/MPL-2.0.txt) | 2.0 | imported | https://opensource.org/license/mpl-2-0/ + https://mozilla.org/en-US/MPL/2.0/ | MPL-2.0 | WEAK COPYLEFT | Verbatim reproduction of steward text; authority opensource.org; retrieved 2026-09-05 | no | ACCEPTED (license text only; not a code dep) | RATIFIED (IP-001, 2026-10-06) | Canonical steward text is not modified. MPL-2.0 is the ratified Menog OS core licence. |

============================================================
Table B — Transitive closure (COMPLETE — 68 package-version rows)
============================================================

Generated 2026-10-06 by GP-R5 from `pnpm licenses list --json`.
67 distinct packages resolve, across 68 package-version instances
(`@vitest/pretty-format` resolves at both 2.1.8 and 2.1.9).

Distribution by declared SPDX identifier, counted by DISTINCT PACKAGE
(the two figures differ by one only because @vitest/pretty-format
resolves at both 2.1.8 and 2.1.9; it is one package, two instances):

  MIT            48   (49 version instances)
  BlueOak-1.0.0   8   ( 8 version instances)
  ISC             7   ( 7 version instances)
  Apache-2.0      2   ( 2 version instances)
  BSD-3-Clause    2   ( 2 version instances)
  --------------------------------------------
  total          67   (68 version instances)

  UNKNOWN: 0   WEAK COPYLEFT: 0   STRONG COPYLEFT: 0
  NETWORK COPYLEFT: 0   PROPRIETARY: 0

Every identifier above appears in THIRD_PARTY_POLICY.md §License
Classification Scheme as PERMISSIVE. The Class column below therefore
reads PERMISSIVE for all rows. This is a classification of the declared
identifier, NOT a compatibility conclusion, and NOT an acceptance.

| Name | Version | D/T | Upstream URL | SPDX (declared) | Class | Provenance | Menog Mods? | Status | Approver | Notes
|---|---|---|---|---|---|---|---|---|---|---|
| expect-type | 1.4.0 | T | https://github.com/mmkal/expect-type | Apache-2.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| typescript | 5.7.2 | D | https://github.com/microsoft/TypeScript | Apache-2.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Direct devDependency — see Table A; listed here because pnpm licenses list enumerates it in the closure. |
| @isaacs/cliui | 9.0.0 | T | — | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| glob | 11.1.0 | T | https://github.com/isaacs/node-glob | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| jackspeak | 4.2.3 | T | https://github.com/isaacs/jackspeak | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| lru-cache | 11.5.2 | T | https://github.com/isaacs/node-lru-cache | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| minimatch | 10.2.6 | T | https://github.com/isaacs/minimatch | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| minipass | 7.1.3 | T | https://github.com/isaacs/minipass | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| package-json-from-dist | 1.0.1 | T | https://github.com/isaacs/package-json-from-dist | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| path-scurry | 2.0.2 | T | https://github.com/isaacs/path-scurry | BlueOak-1.0.0 | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @webgpu/types | 0.1.74 | D | https://github.com/gpuweb/types | BSD-3-Clause | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Direct devDependency — see Table A; listed here because pnpm licenses list enumerates it in the closure. |
| source-map-js | 1.2.1 | T | 7rulnik/source-map-js | BSD-3-Clause | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| foreground-child | 3.3.1 | T | https://github.com/tapjs/foreground-child | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| isexe | 2.0.0 | T | https://github.com/isaacs/isexe | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| picocolors | 1.1.1 | T | alexeyraspopov/picocolors | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| rimraf | 6.1.3 | D | https://github.com/isaacs/rimraf | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Direct devDependency — see Table A; listed here because pnpm licenses list enumerates it in the closure. |
| siginfo | 2.0.0 | T | https://github.com/emilbayes/siginfo | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| signal-exit | 4.1.0 | T | https://github.com/tapjs/signal-exit | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| which | 2.0.2 | T | https://github.com/isaacs/node-which | ISC | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @esbuild/win32-x64 | 0.21.5 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Platform-specific native binary shipped as an optionalDependency; dev-only, not redistributed by Menog. |
| @jridgewell/sourcemap-codec | 1.6.0 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @rollup/rollup-win32-x64-gnu | 4.63.1 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Platform-specific native binary shipped as an optionalDependency; dev-only, not redistributed by Menog. |
| @rollup/rollup-win32-x64-msvc | 4.63.1 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Platform-specific native binary shipped as an optionalDependency; dev-only, not redistributed by Menog. |
| @types/estree | 1.0.9 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @types/node | 22.10.2 | D | https://github.com/DefinitelyTyped/DefinitelyTyped | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Direct devDependency — see Table A; listed here because pnpm licenses list enumerates it in the closure. |
| @vitest/expect | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @vitest/mocker | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| @vitest/pretty-format | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Two versions resolve in the lockfile (2.1.8 and 2.1.9). Dev-only. |
| @vitest/pretty-format | 2.1.9 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Two versions resolve in the lockfile (2.1.8 and 2.1.9). Dev-only. |
| @vitest/runner | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @vitest/snapshot | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @vitest/spy | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| @vitest/utils | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| assertion-error | 2.0.1 | T | https://github.com/chaijs/assertion-error | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| balanced-match | 4.0.4 | T | https://github.com/juliangruber/balanced-match | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| brace-expansion | 5.0.9 | T | https://github.com/juliangruber/brace-expansion | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| cac | 6.7.14 | T | egoist/cac | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| chai | 5.3.3 | T | https://github.com/chaijs/chai | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| check-error | 2.1.3 | T | https://github.com/chaijs/check-error | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| cross-spawn | 7.0.6 | T | https://github.com/moxystudio/node-cross-spawn | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| debug | 4.4.3 | T | https://github.com/debug-js/debug | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| deep-eql | 5.0.2 | T | https://github.com/chaijs/deep-eql | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| es-module-lexer | 1.7.0 | T | https://github.com/guybedford/es-module-lexer | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| esbuild | 0.21.5 | T | https://github.com/evanw/esbuild | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| estree-walker | 3.0.3 | T | https://github.com/Rich-Harris/estree-walker | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| loupe | 3.2.1 | T | https://github.com/chaijs/loupe | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| magic-string | 0.30.21 | T | https://github.com/Rich-Harris/magic-string | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| ms | 2.1.3 | T | vercel/ms | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| nanoid | 3.3.18 | T | ai/nanoid | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| path-key | 3.1.1 | T | sindresorhus/path-key | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| pathe | 1.1.2 | T | unjs/pathe | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| pathval | 2.0.1 | T | https://github.com/chaijs/pathval | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| postcss | 8.5.28 | T | postcss/postcss | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| rollup | 4.63.1 | T | https://github.com/rollup/rollup | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| shebang-command | 2.0.0 | T | kevva/shebang-command | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| shebang-regex | 3.0.0 | T | sindresorhus/shebang-regex | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| stackback | 0.0.2 | T | https://github.com/shtylman/node-stackback | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| std-env | 3.10.0 | T | unjs/std-env | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| tinybench | 2.9.0 | T | tinylibs/tinybench | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| tinyexec | 0.3.2 | T | https://github.com/tinylibs/tinyexec | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| tinypool | 1.1.1 | T | https://github.com/tinylibs/tinypool | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| tinyrainbow | 1.2.0 | T | https://github.com/tinylibs/tinyrainbow | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| tinyspy | 3.0.2 | T | https://github.com/tinylibs/tinyspy | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| undici-types | 6.20.0 | T | https://github.com/nodejs/undici | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| vite | 5.4.21 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Flagged in the recorded pnpm audit (see §pnpm audit). Dev-only; not a shipped runtime dependency. |
| vite-node | 2.1.8 | T | — | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |
| vitest | 2.1.9 | D | https://github.com/vitest-dev/vitest | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Direct devDependency — see Table A; listed here because pnpm licenses list enumerates it in the closure. |
| why-is-node-running | 2.3.0 | T | https://github.com/mafintosh/why-is-node-running | MIT | PERMISSIVE | pnpm-lock integrity; npm registry | no | PENDING → HUMAN MUST RATIFY | HUMAN_REVIEW_REQUIRED | Dev-only transitive dependency of the test/build toolchain. |

============================================================
§pnpm audit — recorded result (GP-R5, 2026-10-06)
============================================================

  Command:  pnpm audit
  Exit:     1  (non-zero)
  Found:    14 advisories — 4 critical, 4 high, 6 moderate

  Every affected package is a DEV-ONLY toolchain package. All advisory
  paths are rooted at `.` (the root package's devDependencies); none
  resolves through a shipped runtime dependency, because Menog ships
  zero third-party runtime dependencies.

  Affected modules and the dev-only paths that reach them:

    CRITICAL  vitest 2.1.8         .>vitest
    CRITICAL  tinypool 1.1.1       .>vitest>tinypool
    HIGH      vite 5.4.21          .>vitest>vite
    HIGH      brace-expansion 5.0.9  .>rimraf>glob>minimatch>brace-expansion
    HIGH      source-map-js 1.2.1   .>vitest>vite>postcss>source-map-js
    MODERATE  esbuild 0.21.5        .>vitest>vite>esbuild
    MODERATE  @vitest/mocker 2.1.8  .>vitest>@vitest/mocker

  PUBLICATION_GATE.md row 4 requires `pnpm audit` to exit 0. It does
  not. This is recorded as a FACTUAL failing condition, not resolved
  here: GP-R5 is a licence-metadata gate and its prompt does not
  authorize a dependency upgrade, and the runtime law forbids changing
  behaviour that is not a strictly-required publication/build repair.

  Remediation is a dependency-upgrade decision (vitest 2.1.8 → 3.2.6+
  and/or vite → 6.4.3+, esbuild → 0.25.0+, plus a lockfile change).
  It is recorded as a human decision item in
  docs/github-prep/GP_R5_LICENSE_REPORT.md, not performed here.

============================================================
§REUSE / SPDX metadata status (GP-R5)
============================================================

  Root LICENSE                          present — verbatim MPL-2.0 steward text
  LICENSES/MPL-2.0.txt                  present — REUSE canonical mirror
  .reuse/REUSE.toml                     present — PROPOSED safe defaults
  LICENSES/CC-BY-4.0.txt                NOT PRESENT
  LICENSES/CC0-1.0.txt                  NOT PRESENT
  SPDX headers in Menog source          NOT APPLIED (0 files)
  .license sidecar files                NOT PRESENT (0 files)

  REUSE.toml assigns SPDX-License-Identifier values per path pattern:
  MPL-2.0 to code, CC-BY-4.0 to Markdown docs, CC0-1.0 to JSON/YAML/
  templates. The MPL-2.0 text is present. The CC-BY-4.0 and CC0-1.0
  texts are NOT present, so a REUSE-compliant tree is not yet
  achievable for the docs/JSON subsets.

  Per docs/governance/SPDX_REUSE_POLICY.md §Repository Layout, those two
  texts are deliberately deferred: they may be placed "only after human
  chooses those license IDs for docs/configs". GP-R5 does not place them
  and does not change any policy in REUSE.toml — doing so would convert a
  PROPOSED licensing policy into an applied one, which is a human
  decision (IP-001).

  REUSE.toml correctly carries NO SPDX-FileCopyrightText for Menog-
  authored files, because the copyright holder is unresolved (IP-002).
  That omission is intentional and is preserved.

  `reuse lint` was NOT run: the `reuse` tool is not installed in this
  environment. This file does not claim REUSE compliance.

============================================================
Runtime Executables Used But Not Vendored / Not Shipped
============================================================

These are external tools invoked by Menog via allowlist (packages/runtime-linux/
allowlist.ts DAY1_ALLOWED_COMMANDS). They are shipped by the user's operating
system distribution, NOT by Menog. Their classification here is for
transparency only — Menog does NOT convey them.

  git (git status, git diff --no-index --stat, git diff --no-index --name-status)
    → OS package; covered by the upstream Git project's own licensing
      (the Git project states GPL-2.0-only, with a Linux-syscall-note
      exception in its COPYING). Invoked as a separate process.
      Menog does not modify git or statically link it.

============================================================
Totals (GP-R5 reconciliation, 2026-10-06)
============================================================

  PERMISSIVE:          67 packages / 68 version instances
  WEAK COPYLEFT:        1 (MPL-2.0 license text; not a code dep)
  STRONG COPYLEFT:      0
  NETWORK COPYLEFT:     0
  PROPRIETARY:          0
  UNKNOWN:              0

  Status = ACCEPTED:    1 (MPL-2.0 license text only — not a code dep)
  Status = PENDING:     5 direct code deps + 67 closure packages
                        (the 5 direct deps are themselves inside the
                        closure enumeration; no row is ACCEPTED yet)
  Status = REVIEW:      0
  Status = REJECTED:    0

  Human sign-off required:  ALL rows.  Nothing in this file is accepted.
