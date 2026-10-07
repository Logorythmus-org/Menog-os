# Phase 25D — Federation Egress Disclosure (NO NETWORK)

**Gate:** 25D · **Date:** 2026-10-01 · **Status:** the ONE sanctioned PRE-TRANSPORT egress
gate — a pure classification/decision layer. No transport, no sockets, no discovery; the
transport remains the caller's bounded in-process fixture (24D discipline).

Module: `packages/durable-state/src/federationEgress.ts` (exported from
`@menog/durable-state`). Suite: `tests/unit/federation-egress.test.ts` (19 tests).

## 1. The question this gate answers

**What is allowed to leave a Menog node?** Everything else denies by default.

## 2. Closed content classes

Allowed OUT (`EGRESS_ALLOWED_CLASSES`):

| Class | Meaning |
|:--|:--|
| `public_identity` | fingerprint/NodeId/instance id/protocol version (24B PUBLIC facts) |
| `protocol_metadata` | schema/protocol versions, message ids, timestamps, lineage refs |
| `content_hashes` | sha256 hex hashes (payload/evidence/subject/anchor/receipt/commit) |
| `bounded_intent` | the closed inert intent/status/response vocabulary |
| `provenance_refs` | proposal/receipt/anchor record references |
| `evidence_refs` | durable evidence record ids/hashes, commit sequence, observation ids |
| `disclosure_manifest` | the manifest itself (self-describing) |

Forbidden FOREVER (`EGRESS_FORBIDDEN_CLASSES`), each with a pinned detection family:
`secret_material` (24B denylist keys at ANY depth + PKCS#8/PEM tripwires) ·
`raw_hidden_policy` (policy-named raw/hidden fields, policy-source text) ·
`raw_tool_output` (stdout/stderr/traceback/exit-code material, unbounded dumps) ·
`local_environment` (drive/UNC/POSIX paths, `VAR=value`, ALL-CAPS env names) ·
`process_handles` (pid/fd/handle/socket/pointer material) · `executable_material`
(shell tokens, `$(...)`, backticks, pipes, chains, interpreters) · `unknown` (anything
not in the closed allowed vocabulary).

## 3. The gate decision

`decideEgress` (pure, deterministic, fail closed):

1. **Shape + default deny**: the candidate carries exactly `{schemaVersion, payloadHash,
   fields}`; each field entry exactly `{key, egressClass, value}`; unknown top-level
   fields, unknown per-field keys, and non-sanctioned key↔class pairs refuse
   (`unknown_field`). Field-name allowlists are closed PER CLASS.
2. **Independent re-classification**: the gate NEVER trusts the caller's claimed class —
   it re-derives findings from (key, value), including JSON-encoded string smuggling
   (a structural string is parsed and scanned at depth).
3. **Redact-or-refuse (never widen)**: `local_environment` and `process_handles` are
   REDACTABLE — the field is dropped and recorded in `manifest.redacted`;
   `secret_material`, `raw_hidden_policy`, `raw_tool_output`, `executable_material`
   REFUSE the whole candidate — secrets and executable material never ride, even
   redacted.
4. **Bounds** (`oversize_manifest`): ≤64 fields, ≤4,096 B per field value, ≤16,384 B
   serialized manifest.
5. **Hash binding** (`hash_mismatch`): the candidate's `payloadHash` must equal the
   outgoing payload's hash.
6. **Determinism**: identical inputs → byte-identical manifests; the decision time is a
   CALLER-supplied input (`nowEpochMs`) — the gate never reads the wall clock.

## 4. Stale disclosure

`verifyEgressManifest` re-checks an existing manifest's binding against the outgoing
payload hash: a mismatch is a **STALE DISCLOSURE** and refuses with a re-run instruction —
a disclosure earned for one payload is void for any other.

## 5. Disclosure grants no authority

A disclosure manifest is a FACT about what left. It carries no
`executionAuthorized`/`policyAuthorized`/authority field (structurally pinned), grants
nothing locally or remotely, and performs no transport. The federation→tool direct path
remains forbidden; nothing here can execute.

## 6. Explicitly unchanged

No network primitive in the module (suite-pinned token scan). No new 22A record kind, no
unfreeze event, no store schema change, no dependency. Private keys never enter any
record, manifest, or report (a secret-shaped finding refuses, never logs the value).
