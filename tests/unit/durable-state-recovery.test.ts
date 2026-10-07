import { describe, it, expect } from "vitest";
import {
  RECOVERY_MODES,
  decideRecovery,
  decideMigration,
  type RecoveryRequest,
  type RecoverySnapshot,
  type RecoveredRecordFinding,
} from "@menog/durable-state";

/**
 * PHASE 22A — recovery/migration/quarantine CONTRACT tests.
 *
 * Pins the recovery trust boundary: recovered evidence never authorizes;
 * corruption quarantined, never healed; unknown schema fails closed;
 * migrations are explicit/versioned/non-executing; checkpoints never
 * override the ledger.
 */

function request(over: Partial<RecoveryRequest> = {}): RecoveryRequest {
  return {
    mode: "load_committed_state",
    expectedStoreSchemaVersion: "menog-durable-store/v0",
    maxRecords: 1000,
    semantics: "no_execution",
    ...over,
  };
}

function finding(over: Partial<RecoveredRecordFinding> = {}): RecoveredRecordFinding {
  return {
    recordId: over.recordId ?? "evt-aaaaaaaaaaaaaaaaaaaaaaaa",
    recordKind: over.recordKind ?? "event_ledger_entry",
    integrityStatus: over.integrityStatus ?? "integrity_verified",
    cause: over.cause ?? null,
    alreadyQuarantined: over.alreadyQuarantined ?? false,
  };
}

function snapshot(over: Partial<RecoverySnapshot> = {}): RecoverySnapshot {
  return {
    expectedStoreSchemaVersion: "menog-durable-store/v0",
    actualStoreSchemaVersion: "menog-durable-store/v0",
    committedThrough: 7,
    observedThrough: 7,
    totalRecordsScanned: 2,
    findings: [finding(), finding({ recordId: "mem-bbbbbbbbbbbbbbbbbbbbbbbb", recordKind: "memory_record" })],
    scanTruncated: false,
    ...over,
  };
}

// ── recovery vocabulary ──────────────────────────────────────────────────────

describe("22A recovery vocabulary", () => {
  it("offers only no-execution recovery modes", () => {
    expect(RECOVERY_MODES).toEqual([
      "load_committed_state",
      "verify_full_ledger",
      "rebuild_derived_only",
    ]);
  });

  it("cannot express an execution-bearing recovery request (type-level)", () => {
    const req = request();
    // The `semantics` field is a literal type — only "no_execution" exists.
    expect(req.semantics).toBe("no_execution");
  });
});

// ── the recovery authority boundary ──────────────────────────────────────────

describe("22A recovery decisions never authorize (central invariant)", () => {
  it("every accept decision stamps recovered_data + executionAuthorized:false + policyAuthorized:false", () => {
    const d = decideRecovery(snapshot(), request());
    expect(d.code).toBe("accept_full_state");
    expect(d.authority).toBe("recovered_data");
    expect(d.executionAuthorized).toBe(false);
    expect(d.policyAuthorized).toBe(false);
    expect(d.denyReason).toBeNull();
  });

  it("the same holds for the quarantine path and the rebuild path", () => {
    const q = decideRecovery(
      snapshot({
        findings: [
          finding(),
          finding({ recordId: "run-cccccccccccccccccccc", recordKind: "tool_run_evidence", integrityStatus: "integrity_failed", cause: "content_hash_mismatch" }),
        ],
      }),
      request()
    );
    expect(q.code).toBe("accept_without_quarantined");
    expect(q.authority).toBe("recovered_data");
    expect(q.executionAuthorized).toBe(false);
    expect(q.policyAuthorized).toBe(false);

    const rb = decideRecovery(snapshot({ observedThrough: 9, committedThrough: 7 }), request());
    expect(rb.code).toBe("rebuild_derived_required");
    expect(rb.authority).toBe("recovered_data");
    expect(rb.executionAuthorized).toBe(false);
    expect(rb.policyAuthorized).toBe(false);
  });
});

// ── fail-closed recovery ─────────────────────────────────────────────────────

describe("22A recovery fails closed", () => {
  it("rejects an unknown store schema (TS22-13 malicious DB content)", () => {
    const d = decideRecovery(snapshot({ actualStoreSchemaVersion: "menog-durable-store/v999" }), request());
    expect(d.code).toBe("rejected_schema_mismatch");
    expect(d.denyReason).toBe("schema_version_mismatch");
    expect(d.admittedRecordIds).toEqual([]);
  });

  it("rejects a store with no readable schema at all", () => {
    const d = decideRecovery(snapshot({ actualStoreSchemaVersion: null }), request());
    expect(d.code).toBe("rejected_schema_mismatch");
    expect(d.denyReason).toBe("unknown_schema_version");
  });

  it("rejects schema drift between request and store (TS22-03 stale DB rollback)", () => {
    const d = decideRecovery(
      snapshot({ actualStoreSchemaVersion: "menog-durable-store/v0" }),
      request({ expectedStoreSchemaVersion: "menog-durable-store/v1" })
    );
    expect(d.code).toBe("rejected_schema_mismatch");
  });

  it("rejects a scan that hit its bound — partial recovery is not recovery", () => {
    const d = decideRecovery(snapshot({ scanTruncated: true, totalRecordsScanned: 1000 }), request({ maxRecords: 1000 }));
    expect(d.code).toBe("rejected_scan_bound");
    expect(d.denyReason).toBe("scan_bound_exceeded");
    expect(d.admittedRecordIds).toEqual([]);
  });

  it("quarantines corrupt records instead of healing them (TS22-02 corruption)", () => {
    const corruptedId = "evt-dddddddddddddddddddddddd";
    const d = decideRecovery(
      snapshot({
        findings: [
          finding(),
          finding({ recordId: corruptedId, integrityStatus: "integrity_failed", cause: "content_hash_mismatch" }),
          finding({ recordId: "evt-eeeeeeeeeeeeeeeeeeeeeeee", integrityStatus: "integrity_unknown", cause: "truncated_record" }),
        ],
      }),
      request()
    );
    expect(d.code).toBe("accept_without_quarantined");
    expect(d.quarantinedRecordIds).toContain(corruptedId);
    expect(d.quarantinedRecordIds).toContain("evt-eeeeeeeeeeeeeeeeeeeeeeee");
    expect(d.admittedRecordIds).toEqual(["evt-aaaaaaaaaaaaaaaaaaaaaaaa"]);
    expect(d.explanation).toContain("QUARANTINED");
    expect(d.explanation).toContain("never repaired, never healed");
  });

  it("already-quarantined records stay quarantined and do not fail the load", () => {
    const d = decideRecovery(
      snapshot({
        findings: [
          finding(),
          finding({ recordId: "evt-ffffffffffffffffffffffff", integrityStatus: "integrity_failed", alreadyQuarantined: true }),
        ],
      }),
      request()
    );
    expect(d.code).toBe("accept_full_state");
    expect(d.admittedRecordIds).toEqual(["evt-aaaaaaaaaaaaaaaaaaaaaaaa"]);
  });

  it("detects checkpoint/ledger divergence and demands a derived rebuild, never a silent heal (TS22-09)", () => {
    const d = decideRecovery(snapshot({ observedThrough: 12, committedThrough: 7 }), request());
    expect(d.code).toBe("rebuild_derived_required");
    expect(d.denyReason).toBe("checkpoint_ledger_divergence");
    expect(d.explanation).toContain("diverges");
    expect(d.explanation).toContain("rebuilt");
  });
});

// ── migration ────────────────────────────────────────────────────────────────

describe("22A migration decisions — explicit, versioned, non-executing", () => {
  it("reports unnecessary for a fresh store or matching version", () => {
    expect(decideMigration({
      currentStoreSchemaVersion: null,
      knownStoreSchemaVersions: ["menog-durable-store/v0"],
      codeStoreSchemaVersion: "menog-durable-store/v0",
    }).code).toBe("migration_unnecessary");
    expect(decideMigration({
      currentStoreSchemaVersion: "menog-durable-store/v0",
      knownStoreSchemaVersions: ["menog-durable-store/v0"],
      codeStoreSchemaVersion: "menog-durable-store/v0",
    }).code).toBe("migration_unnecessary");
  });

  it("refuses to migrate an unknown store schema (fail closed, TS22-08)", () => {
    const d = decideMigration({
      currentStoreSchemaVersion: "menog-durable-store/vX",
      knownStoreSchemaVersions: ["menog-durable-store/v0"],
      codeStoreSchemaVersion: "menog-durable-store/v0",
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.code).toBe("migration_rejected_unsupported");
      expect(d.plan).toBeNull();
      expect(d.explanation).toContain("fail");
    }
  });

  it("refuses version-skipping migrations", () => {
    const d = decideMigration({
      currentStoreSchemaVersion: "menog-durable-store/v0",
      knownStoreSchemaVersions: ["menog-durable-store/v0", "menog-durable-store/v1", "menog-durable-store/v2"],
      codeStoreSchemaVersion: "menog-durable-store/v2",
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("migration_rejected_unsupported");
  });

  it("plans only single-step migrations and marks them non-executing", () => {
    const d = decideMigration({
      currentStoreSchemaVersion: "menog-durable-store/v0",
      knownStoreSchemaVersions: ["menog-durable-store/v0", "menog-durable-store/v1"],
      codeStoreSchemaVersion: "menog-durable-store/v1",
    });
    expect(d.ok).toBe(true);
    if (d.ok && d.code === "migration_planned") {
      expect(d.plan).not.toBeNull();
      expect(d.plan?.stepCount).toBe(1);
      expect(d.plan?.semantics).toBe("non_executing");
      expect(d.plan?.sourceStoreSchemaVersion).toBe("menog-durable-store/v0");
      expect(d.plan?.targetStoreSchemaVersion).toBe("menog-durable-store/v1");
      expect(d.plan?.requiredEvidence.length).toBeGreaterThanOrEqual(3);
    }
  });
});
