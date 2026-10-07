import { describe, it, expect } from "vitest";
import {
  DURABLE_RECORD_SCHEMA_VERSION,
  DURABLE_STORE_SCHEMA_VERSION,
  RECORD_KINDS,
  DURABILITY_CLASSES,
  INTEGRITY_STATUSES,
  PERSIST_FAILURE_CODES,
  RECOVERY_DECISION_CODES,
  MIGRATION_DECISION_CODES,
  QUARANTINE_CAUSES,
  RECORD_KIND_CLASSIFICATION,
  AUTHORITATIVE_RECORD_KINDS,
  DERIVED_RECORD_KINDS,
  APPEND_ONLY_RECORD_KINDS,
  TERMINAL_QUARANTINE_KINDS,
  MAX_RECORD_PAYLOAD_BYTES,
  durableContentHash,
  verifyEnvelopeIntegrity,
  envelopeBodyOf,
  hasKnownRecordSchema,
  canonicalDurableJson,
  validateEnvelope,
  decidePersist,
  findSecretPayloadKeyPaths,
  payloadSerializabilityError,
  isRecordKind,
  isDurabilityClass,
  isPersistFailureCode,
  isAppendOnlyKind,
  isVersionedMutableKind,
  isRebuildableKind,
  isAuthoritativeKind,
  isDerivedKind,
  classificationCoversAllKinds,
  type DurableRecordEnvelope,
  type DurableRecordSchemaVersion,
} from "@menog/durable-state";

/**
 * PHASE 22A — durable-state CONTRACT tests (no storage, no I/O anywhere).
 *
 * Each test pins one frozen semantic or one threat class from
 * docs/security/PHASE22_STORAGE_THREAT_MODEL.md:
 *   TS22-01 torn/partial write        TS22-09 ledger/store divergence
 *   TS22-02 corruption                TS22-10 index poisoning
 *   TS22-03 stale rollback            TS22-11 evidence substitution
 *   TS22-04 concurrent writers        TS22-12 path/symlink escape (n/a at contract layer — typed out)
 *   TS22-05 lost/duplicate update     TS22-13 malicious DB content
 *   TS22-06 replayed transaction      TS22-14 secret leakage
 *   TS22-07 schema confusion          TS22-15 unauthorized recovery
 *   TS22-08 migration failure         TS22-16 authority resurrection
 *
 * Central invariant under test: durable state ≠ executable replay ≠ authorization.
 */

// ── fixtures ─────────────────────────────────────────────────────────────────

function sealEnvelope(
  over: Partial<DurableRecordEnvelope> = {}
): DurableRecordEnvelope {
  const body = {
    schemaVersion: DURABLE_RECORD_SCHEMA_VERSION,
    recordId: over.recordId ?? "evt-aaaaaaaaaaaaaaaaaaaaaaaa",
    recordKind: over.recordKind ?? "event_ledger_entry",
    durabilityClass: over.durabilityClass ?? "append_only",
    secretPolicy: over.secretPolicy ?? "secret_free",
    authority: over.authority ?? "durable_evidence",
    revision: over.revision ?? 1,
    supersedesRevision: over.supersedesRevision ?? null,
    createdAtEpochMs: over.createdAtEpochMs ?? 1_760_000_000_000,
    transactionId: over.transactionId ?? "tx-seal-0001",
    payload: over.payload ?? { eventType: "test.event", note: "sealed" },
  };
  return Object.freeze({
    ...body,
    contentHash: durableContentHash(body),
  }) as DurableRecordEnvelope;
}

function mutableEnvelope(
  over: Partial<DurableRecordEnvelope> = {}
): DurableRecordEnvelope {
  return sealEnvelope({
    recordId: "mem-bbbbbbbbbbbbbbbbbbbbbbbb",
    recordKind: "memory_record",
    durabilityClass: "versioned_mutable",
    authority: "durable_state",
    revision: over.revision ?? 1,
    ...over,
  });
}

// ── vocabulary: closed unions ────────────────────────────────────────────────

describe("22A closed vocabularies", () => {
  it("exposes exactly the frozen record kinds (new kinds need an unfreeze event)", () => {
    // UNFREEZE EVENTS 2026-10-01: `peer_trust_registry` added by 24C and
    // `federation_receipt` added by 24D, per the 22A unfreeze protocol —
    // the pack requires peer facts AND cross-node evidence to persist
    // through the sanctioned durable path. peer_trust_registry mirrors
    // skill_tool_registry (authoritative, versioned_mutable, terminal-
    // quarantine); federation_receipt mirrors event_ledger_entry
    // (authoritative, append_only, permanent evidence). `federation_proposal`
    // added by 24E: durable inert evidence of cross-node task PROPOSALS —
    // also mirrors event_ledger_entry (append_only, permanent); the kind
    // exists so the PROPOSAL DECISION is tamper-evident and the duplicate-
    // proposal guard is durable across restarts. A proposal record never
    // grants capabilities, never chooses Policy, and never executes.
    // `federation_provenance` added by 24F: durable tamper-evident BINDINGS
    // of cross-node happenings (proposal/receipt/candidate/allocation/policy
    // /execution linkage) — also mirrors event_ledger_entry; a binding is
    // evidence of linkage, never a grant of authority; foreign evidence
    // stays DATA. No other kind was added or changed.
    expect(RECORD_KINDS).toEqual([
      "event_ledger_entry",
      "tool_run_evidence",
      "memory_record",
      "agent_metadata",
      "goal_lifecycle",
      "skill_tool_registry",
      "peer_trust_registry",
      "federation_receipt",
      "federation_proposal",
      "federation_provenance",
      "derived_index",
      "store_checkpoint",
    ]);
    expect(Object.isFrozen(RECORD_KINDS)).toBe(true);
  });

  it("exposes exactly three durability classes", () => {
    expect(DURABILITY_CLASSES).toEqual(["append_only", "versioned_mutable", "rebuildable"]);
  });

  it("exposes exactly one secret policy (secret_free) — no modeled secret persistence", () => {
    expect(Object.isFrozen(RECORD_KINDS)).toBe(true);
    expect(isRecordKind("event_ledger_entry")).toBe(true);
    expect(isRecordKind("snapshot_store")).toBe(false);
    expect(isDurabilityClass("append_only")).toBe(true);
    expect(isDurabilityClass("best_effort")).toBe(false);
  });

  it("exposes the closed integrity/failure/recovery/migration/quarantine vocabularies", () => {
    expect(INTEGRITY_STATUSES).toEqual(["integrity_verified", "integrity_failed", "integrity_unknown"]);
    expect(PERSIST_FAILURE_CODES.length).toBeGreaterThanOrEqual(21);
    expect(isPersistFailureCode("secret_key_denied")).toBe(true);
    expect(isPersistFailureCode("made_up_code")).toBe(false);
    expect(RECOVERY_DECISION_CODES).toEqual([
      "accept_full_state",
      "accept_without_quarantined",
      "rebuild_derived_required",
      "rejected_schema_mismatch",
      "rejected_unverifiable",
      "rejected_scan_bound",
    ]);
    expect(MIGRATION_DECISION_CODES).toEqual([
      "migration_unnecessary",
      "migration_planned",
      "migration_rejected_unsupported",
      "migration_rejected_evidence",
    ]);
    expect(QUARANTINE_CAUSES).toEqual([
      "content_hash_mismatch",
      "unknown_schema_version",
      "unknown_record_kind",
      "chain_broken",
      "parent_missing",
      "truncated_record",
      "oversized_record",
      "malformed_envelope",
    ]);
  });

  it("pins the store/record schema version strings", () => {
    expect(DURABLE_STORE_SCHEMA_VERSION).toBe("menog-durable-store/v0");
    expect(DURABLE_RECORD_SCHEMA_VERSION).toBe("menog-durable-record/v0");
    expect(hasKnownRecordSchema({ schemaVersion: DURABLE_RECORD_SCHEMA_VERSION })).toBe(true);
    expect(hasKnownRecordSchema({ schemaVersion: "menog-durable-record/v1" as DurableRecordSchemaVersion })).toBe(false);
  });
});

// ── classification table ─────────────────────────────────────────────────────

describe("22A classification table (frozen per kind)", () => {
  it("classifies every kind — no orphan rows, no extra rows", () => {
    expect(classificationCoversAllKinds()).toBe(true);
    for (const kind of RECORD_KINDS) {
      expect(RECORD_KIND_CLASSIFICATION[kind]).toBeDefined();
      expect(RECORD_KIND_CLASSIFICATION[kind].recordKind).toBe(kind);
    }
    expect(Object.keys(RECORD_KIND_CLASSIFICATION).length).toBe(RECORD_KINDS.length);
  });

  it("ledger + tool evidence are authoritative, append-only, hash-bound, replay-free", () => {
    for (const kind of ["event_ledger_entry", "tool_run_evidence"] as const) {
      const row = RECORD_KIND_CLASSIFICATION[kind];
      expect(row.authorityPosture).toBe("authoritative");
      expect(row.mutationPosture).toBe("append_only");
      expect(row.integrityBinding).toBe("content_hash_required");
      expect(row.secretPolicy).toBe("secret_free");
    }
    expect(RECORD_KIND_CLASSIFICATION.event_ledger_entry.recoverySemantics).toBe("replay_free");
    expect(RECORD_KIND_CLASSIFICATION.tool_run_evidence.recoverySemantics).toBe("verify_then_accept");
    expect(RECORD_KIND_CLASSIFICATION.event_ledger_entry.retentionClass).toBe("permanent");
  });

  it("indexes and checkpoints are derived, rebuildable, never authoritative", () => {
    for (const kind of ["derived_index", "store_checkpoint"] as const) {
      const row = RECORD_KIND_CLASSIFICATION[kind];
      expect(row.authorityPosture).toBe("derived");
      expect(row.mutationPosture).toBe("rebuildable");
      expect(row.recoverySemantics).toBe("rebuild_from_authoritative");
    }
    expect(DERIVED_RECORD_KINDS).toEqual(["derived_index", "store_checkpoint"]);
    expect(AUTHORITATIVE_RECORD_KINDS).toEqual([
      "event_ledger_entry",
      "tool_run_evidence",
      "memory_record",
      "agent_metadata",
      "goal_lifecycle",
      "skill_tool_registry",
      "peer_trust_registry",
      "federation_receipt",
      "federation_proposal",
      "federation_provenance",
    ]);
  });

  it("memory/agent/goal/registry state is authoritative + versioned_mutable (restore as data)", () => {
    for (const kind of ["memory_record", "agent_metadata", "goal_lifecycle", "skill_tool_registry"] as const) {
      const row = RECORD_KIND_CLASSIFICATION[kind];
      expect(row.authorityPosture).toBe("authoritative");
      expect(row.mutationPosture).toBe("versioned_mutable");
      expect(row.secretPolicy).toBe("secret_free");
      expect(row.integrityBinding).toBe("content_hash_required");
    }
  });

  it("partitions kinds exactly (append-only ∩ mutable = ∅; authoritative ∪ derived = all)", () => {
    const appendOnly = new Set(APPEND_ONLY_RECORD_KINDS);
    for (const kind of RECORD_KINDS) {
      const mut = RECORD_KIND_CLASSIFICATION[kind].mutationPosture;
      if (mut === "append_only") expect(appendOnly.has(kind)).toBe(true);
      else expect(appendOnly.has(kind)).toBe(false);
    }
    const union = new Set([...AUTHORITATIVE_RECORD_KINDS, ...DERIVED_RECORD_KINDS]);
    expect(union.size).toBe(RECORD_KINDS.length);
  });

  it("predicates agree with the table", () => {
    expect(isAppendOnlyKind("event_ledger_entry")).toBe(true);
    expect(isAppendOnlyKind("memory_record")).toBe(false);
    expect(isVersionedMutableKind("memory_record")).toBe(true);
    expect(isRebuildableKind("derived_index")).toBe(true);
    expect(isAuthoritativeKind("goal_lifecycle")).toBe(true);
    expect(isDerivedKind("store_checkpoint")).toBe(true);
  });

  it("names the anti-resurrection surface (registry + run evidence)", () => {
    expect(TERMINAL_QUARANTINE_KINDS).toEqual(["skill_tool_registry", "tool_run_evidence", "peer_trust_registry"]);
  });
});

// ── canonical hashing + integrity ────────────────────────────────────────────

describe("22A canonical serialization + integrity binding", () => {
  it("produces stable hashes across key order (sorted canonical form)", () => {
    const a = canonicalDurableJson({ b: 1, a: 2 });
    const b = canonicalDurableJson({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(durableContentHash({ ...envelopeBodyOf(sealEnvelope()) })).toBe(
      durableContentHash({ ...envelopeBodyOf(sealEnvelope()) })
    );
  });

  it("verifies a sealed envelope; any field mutation breaks integrity", () => {
    const env = sealEnvelope();
    expect(verifyEnvelopeIntegrity(env)).toBe("integrity_verified");

    const tamperedPayload = { ...env, payload: { ...env.payload, note: "rewritten" } } as DurableRecordEnvelope;
    expect(verifyEnvelopeIntegrity(tamperedPayload)).toBe("integrity_failed");

    const tamperedKind = { ...env, recordKind: "memory_record" } as unknown as DurableRecordEnvelope;
    expect(verifyEnvelopeIntegrity(tamperedKind)).toBe("integrity_failed");
  });

  it("reports integrity_unknown for a missing/garbage hash rather than guessing", () => {
    const noHash = { ...sealEnvelope(), contentHash: "" } as DurableRecordEnvelope;
    expect(verifyEnvelopeIntegrity(noHash)).toBe("integrity_unknown");
    const shortHash = { ...sealEnvelope(), contentHash: "deadbeef" } as DurableRecordEnvelope;
    expect(verifyEnvelopeIntegrity(shortHash)).toBe("integrity_unknown");
  });
});

// ── envelope validation (fail closed) ────────────────────────────────────────

describe("22A envelope validation — unknown anything fails closed", () => {
  it("rejects an unknown schemaVersion (TS22-07 schema confusion)", () => {
    const env = { ...sealEnvelope(), schemaVersion: "menog-durable-record/v999" };
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("unknown_schema_version");
      expect(r.reason).toContain("failing closed");
    }
  });

  it("rejects an unknown recordKind", () => {
    const env = { ...sealEnvelope(), recordKind: "session_transcript" };
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("unknown_record_kind");
  });

  it("rejects an unknown durabilityClass and kind/class mismatch", () => {
    const wrongClass = { ...sealEnvelope(), durabilityClass: "versioned_mutable" };
    expect(validateEnvelope(wrongClass).ok).toBe(false);
    const kindMismatch = { ...sealEnvelope(), recordKind: "memory_record" } as DurableRecordEnvelope;
    expect(validateEnvelope(kindMismatch).ok).toBe(false);
    if (!validateEnvelope(kindMismatch).ok) {
      expect((validateEnvelope(kindMismatch) as { ok: false; failureCode: string }).failureCode).toBe("unknown_durability_class");
    }
  });

  it("rejects any secretPolicy other than secret_free (TS22-14 secret denial by default)", () => {
    const env = { ...sealEnvelope(), secretPolicy: "encrypted_at_rest" };
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("unknown_secret_policy");
      expect(r.reason).toContain("secret persistence is not modeled");
    }
  });

  it("rejects recovered_data as a persist-time authority (only recovery stamps it)", () => {
    const env = { ...sealEnvelope(), authority: "recovered_data" };
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("unknown_authority_class");
  });

  it("rejects authority/durability mismatch (derived index claiming durable_evidence)", () => {
    const env = sealEnvelope({
      recordId: "idx-cccccccccccccccccccccccc",
      recordKind: "derived_index",
      durabilityClass: "rebuildable",
      authority: "durable_evidence",
    });
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("unknown_authority_class");
  });

  it("rejects malformed record ids and id/kind prefix mismatches", () => {
    expect(validateEnvelope(sealEnvelope({ recordId: "not-a-valid-id" })).ok).toBe(false);
    expect(validateEnvelope(sealEnvelope({ recordId: "mem-wrongprefixforledger" })).ok).toBe(false);
    const r = validateEnvelope(sealEnvelope({ recordId: "mem-bbbbbbbbbbbbbbbbbbbbbbbb" }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("id_kind_mismatch");
  });

  it("rejects bad revisions: zero, negative, non-integer, append-only revision > 1 (TS22-02 mutation law)", () => {
    expect(validateEnvelope(sealEnvelope({ revision: 0 })).ok).toBe(false);
    expect(validateEnvelope(sealEnvelope({ revision: -1 })).ok).toBe(false);
    expect(validateEnvelope(sealEnvelope({ revision: 1.5 })).ok).toBe(false);
    const appended = sealEnvelope({ revision: 2 });
    const r = validateEnvelope(appended);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("append_only_mutation");
      expect(r.reason).toContain("mutation is not representable");
    }
  });

  it("requires supersedesRevision = revision - 1 for mutable revisions > 1 (lost-update detection)", () => {
    const wrong = mutableEnvelope({ revision: 3, supersedesRevision: 1 });
    const r = validateEnvelope(wrong);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("invalid_revision");
    const right = mutableEnvelope({ revision: 2, supersedesRevision: 1 });
    expect(validateEnvelope(right).ok).toBe(true);
  });

  it("rejects invalid transaction ids and implausible timestamps", () => {
    expect(validateEnvelope(sealEnvelope({ transactionId: "TX UPPER" })).ok).toBe(false);
    expect(validateEnvelope(sealEnvelope({ createdAtEpochMs: -5 })).ok).toBe(false);
    expect(validateEnvelope(sealEnvelope({ createdAtEpochMs: Number.NaN })).ok).toBe(false);
  });
});

// ── payload hygiene ──────────────────────────────────────────────────────────

describe("22A payload hygiene — no secrets, bounded, serializable", () => {
  it("finds secret-shaped keys at any depth", () => {
    const hits = findSecretPayloadKeyPaths({
      summary: "ok",
      nested: { apiKey: "should-not-persist", deeper: { access_token: "x" } },
    });
    expect(hits).toContain("nested.apiKey");
    expect(hits).toContain("nested.deeper.access_token");
  });

  it("denies records carrying secret-shaped keys (TS22-14)", () => {
    const env = sealEnvelope({ payload: { userPassword: "hunter2" } });
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("secret_key_denied");
      expect(r.reason).toContain("denied by default");
    }
  });

  it("rejects non-serializable payloads (functions, symbols, BigInt, class instances, non-finite numbers)", () => {
    expect(payloadSerializabilityError({ fn: () => 1 })).not.toBeNull();
    expect(payloadSerializabilityError({ s: Symbol("x") })).not.toBeNull();
    expect(payloadSerializabilityError({ b: 10n })).not.toBeNull();
    expect(payloadSerializabilityError({ n: Number.NaN })).not.toBeNull();
    expect(payloadSerializabilityError(new Map())).not.toBeNull();
    expect(payloadSerializabilityError({ ok: 1, nested: { fine: "x" } })).toBeNull();
  });

  it("rejects oversized payloads (bounded records)", () => {
    const big = "x".repeat(MAX_RECORD_PAYLOAD_BYTES + 1);
    const env = sealEnvelope({ payload: { blob: big } });
    const r = validateEnvelope(env);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("payload_oversized");
  });

  it("rejects envelopes whose contentHash does not re-derive (TS22-11 evidence substitution)", () => {
    const env = sealEnvelope();
    const tampered = { ...env, contentHash: "0".repeat(64) } as DurableRecordEnvelope;
    const r = validateEnvelope(tampered);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("content_hash_mismatch");
      expect(r.reason).toContain("modified after sealing or never sealed");
    }
  });
});

// ── persist decisions ────────────────────────────────────────────────────────

describe("22A persist decisions — all-or-nothing, fail closed", () => {
  it("accepts a valid append-only persist", () => {
    const env = sealEnvelope();
    const r = decidePersist({
      envelope: env,
      transactionId: env.transactionId,
      idExists: false,
      existingRevision: null,
      storeWritable: true,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.committed).toBe(true);
      expect(r.recordId).toBe(env.recordId);
      expect(r.commitSequence).toBe(-1); // assigned by the 22B store at commit
    }
  });

  it("denies everything on a read-only store", () => {
    const r = decidePersist({
      envelope: sealEnvelope(),
      transactionId: "tx-seal-0001",
      idExists: false,
      existingRevision: null,
      storeWritable: false,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("store_readonly");
  });

  it("denies a re-append of an existing append-only id (TS22-06 replayed transaction)", () => {
    const env = sealEnvelope();
    const r = decidePersist({
      envelope: env,
      transactionId: env.transactionId,
      idExists: true,
      existingRevision: 1,
      storeWritable: true,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("duplicate_revision");
      expect(r.reason).toContain("immutable");
    }
  });

  it("denies stale and lost updates on mutable records (TS22-05)", () => {
    const env = mutableEnvelope({ revision: 2, supersedesRevision: 1 });
    const stale = decidePersist({
      envelope: env,
      transactionId: env.transactionId,
      idExists: true,
      existingRevision: 5,
      storeWritable: true,
    });
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.failureCode).toBe("revision_conflict");

    const skipped = mutableEnvelope({ revision: 7, supersedesRevision: 6 });
    const r2 = decidePersist({
      envelope: skipped,
      transactionId: skipped.transactionId,
      idExists: true,
      existingRevision: 5,
      storeWritable: true,
    });
    expect(r2.ok).toBe(false);
    if (!r2.ok) {
      expect(r2.failureCode).toBe("revision_conflict");
      expect(r2.reason).toContain("exactly stored + 1");
    }
  });

  it("denies an envelope whose transactionId disagrees with the intent (TS22-01 torn intent)", () => {
    const env = sealEnvelope();
    const r = decidePersist({
      envelope: env,
      transactionId: "tx-other-intent",
      idExists: false,
      existingRevision: null,
      storeWritable: true,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failureCode).toBe("invalid_transaction_id");
  });

  it("failures are never partial commits (committed:false is structural)", () => {
    const r = decidePersist({
      envelope: sealEnvelope({ payload: { password: "x" } }),
      transactionId: "tx-seal-0001",
      idExists: false,
      existingRevision: null,
      storeWritable: true,
    });
    expect(r.ok).toBe(false);
    expect(r.committed).toBe(false);
  });
});
