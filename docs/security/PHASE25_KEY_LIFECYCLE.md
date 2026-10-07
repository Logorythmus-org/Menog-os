# Phase 25B — Identity / Key Lifecycle Operations (LOCAL ONLY, NO NETWORK)

**Gate:** 25B · **Date:** 2026-10-01 · **Status:** OPERATIONAL LAYER over the frozen 24B
crypto identity — no network, no key persistence, no key-export API, no HSM/TPM/secure-
enclave/production-PKI claim of any kind. Platform crypto means `node:crypto` Ed25519
(24B), reused unchanged; **no new dependency**.

Module: `packages/durable-state/src/federationKeyLifecycle.ts` (exported from
`@menog/durable-state`). Suite: `tests/unit/federation-key-lifecycle.test.ts` (39 tests).

## 1. The lifecycle machine

Closed states, in canonical order (`KEY_LIFECYCLE_STATES`):

```
uninitialized → active → rotation_requested → rotated → revoked → retired
```

with the evidenced compromise/retirement shortcuts `active → revoked`,
`rotation_requested → revoked`, `active → retired`, an evidenced abort
`rotation_requested → active`, and the formal post-rotation revocation
`rotated → revoked`. `retired` is the ONLY terminal state;
`retired → anything` is unrepresentable. Every edge requires non-empty
evidence (`decideLifecycleTransition` refuses otherwise) and appends to an
IMMUTABLE trail — records are frozen values, history is never rewritten.

## 2. Records are PUBLIC FACTS ONLY

A `KeyLifecycleRecord` carries exactly: `schemaVersion`, canonical `keyId`
(`kid-` + 16 hex of SHA-256 over the raw public key HEX — deliberately a
different derivation than the fingerprint, so a mismatch is detectable),
`publicKeyHex`, `fingerprint`, `nodeId`, `state`, creation/update
timestamps, the append-only evidenced `trail`, and `peerTrustLink: null`.

- The private key NEVER appears: 25B never receives, holds, exports,
  serializes, or observes private key material (it stays inside 24B's
  module-private memory-only closure). There is no key-export API.
- Every record validates against the 24B secret-key denylist — a
  secret-key-shaped key at ANY depth refuses the record outright
  (ledger/provenance/reports can therefore never receive one through this
  layer).
- Public facts must re-derive (24B `verifyRestartIdentity` + `deriveKeyId`);
  timestamps must bind to the trail (creation = initialize entry, update =
  newest entry, monotone) — a tampered or stale record fails validation.

## 3. Rotation = re-identity (never mutation, never inheritance)

Rotation requires a prior evidenced request (`rotation_requested`), the
FRESH identity's public facts (from 24B `rotateLocalIdentity`), and genuine
freshness (new key → new fingerprint → new NodeId; a no-op/self-
referential rotation refuses as `rotation_not_fresh`). Duplicate requests
while one is pending refuse (`rotation_already_requested`); a direct
`active → rotated` jump refuses (`rotation_not_requested`).

**Trust non-inheritance (25A P7 operationalized):** the fresh identity
starts with NO record and NO trust; `decideTrustInheritance` refuses
ALWAYS — re-admission is a NEW local evidenced 24C decision, never
automatic, never a silent re-pin of an admitted peer. The lifecycle record
structurally carries no trust link (`peerTrustLink: null`).

## 4. Key-USE gate (the operational layer 25B adds)

`decideKeyUse` gates USE independently of cryptographic verifiability: the
24B verifier may still validate an old key's signature while the lifecycle
refuses its use. Refusals: unknown record; invalid record; key-id claim
mismatch; fingerprint claim mismatch; state `rotated` (stale key —
`stale_rotated_key`); `revoked`; `retired`. Permitted only in `active` /
`rotation_requested`, and even then as AUTHENTICATION capability only —
never authority.

## 5. Restart / reload — revocation survives

`reloadLifecycleRecord` re-validates the record's public facts and reloads
it in EXACTLY its prior state: a record revoked/rotated/retired before the
restart is still revoked/rotated/retired after it. The private key is not
part of the reload (it never persisted — the documented 24B limitation);
signing capability is re-established out-of-band by the operator and
remains subject to the key-use gate. Nothing is invented, nothing resumes.

## 6. State rollback cannot resurrect keys

`decideRollbackRestore`: lifecycle facts are MONOTONE. A snapshot older
than a rotated/revoked/retired current state would resurrect a dead key
and refuses (`rollback_would_resurrect_key`); divergence without
resurrection refuses as `rollback_conflict` for investigation; only an
equal-state snapshot restores, as an idempotent no-op. Unknown states
refuse the judgment itself.

## 7. Scanner discipline

The module source contains no network/execution/persistence token (suite-
pinned list, including `request(` after the verify-local network-invariant
scanner flagged — and the fix removed — one prose occurrence). No new 22A
record kind, no unfreeze event, no store schema change, no dependency.

## 8. Explicitly NOT claimed

No HSM, TPM, secure enclave, keyfile, OS keyring, or production PKI is
used or claimed. Private-key memory exposure (dump/swap/debugger) remains
the documented 24B limitation, unchanged. No revocation-list distribution,
no expiry metadata, no certificate chains — revocation is a LOCAL
lifecycle fact, not a network protocol.
