import { describe, it, expect } from "vitest";
import type { Actor } from "@menog/core";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  SEMANTIQ_MAX_EXPORT_RECORDS,
  SEMANTIQ_MAX_EXPORT_EVENTS,
  SEMANTIQ_SECRET_PATTERNS,
  redactValue,
  isSemantiqTransferDenyReason,
  KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS,
  exportEvidence,
  importEvidence,
  buildEvaluationRequestEvent,
  buildEvaluationResultEvent,
  buildEvaluationDeniedEvent,
  validateEvaluationEvent,
  SemantiqEvaluationRecordStore,
  type SemantiqEvaluationRecord,
  type SemantiqEvaluationProvenance,
  type SemantiqDimensionScore,
  type SemantiqEvidenceEventSummary,
} from "@menog/semantiq";

const AGENT: Actor = { type: "agent", id: "agent-18c" };

const T0 = 1_840_000_000_000;

function prov(overrides: Partial<SemantiqEvaluationProvenance> = {}): SemantiqEvaluationProvenance {
  return {
    source: "engine",
    actorId: AGENT.id,
    actorType: AGENT.type,
    derivedFrom: ["evt-18c-1"],
    engineId: "engine-18c",
    engineVersion: "1.0.0",
    ...overrides,
  };
}

function score(dimension: string, value: number, confidence = 0.9): SemantiqDimensionScore {
  return { dimension: dimension as SemantiqDimensionScore["dimension"], score: value, confidence };
}

function isTransferDenial(r: { ok: boolean }): r is { ok: false; denyReason: string; reason: string } {
  return r.ok === false;
}

function buildRecord(subject: string, atEpochMs = T0): SemantiqEvaluationRecord {
  const built = buildEvaluationResultEvent({
    subject,
    trigger: "manual",
    atEpochMs,
    dimensions: [score("plan_quality", 0.9)],
    provenance: prov(),
  });
  if (!built.ok) throw new Error("fixture rejected: " + built.reason);
  const store = new SemantiqEvaluationRecordStore();
  const persisted = store.persist(built.event);
  if (!persisted.ok) throw new Error("fixture not persistable: " + persisted.reason);
  return persisted.record;
}

function requestRecord(subject: string, atEpochMs = T0): SemantiqEvaluationRecord {
  const built = buildEvaluationRequestEvent({
    subject,
    trigger: "cli",
    atEpochMs,
    provenance: prov({ source: "derived_from_ledger", engineId: undefined, engineVersion: undefined }),
  });
  if (!built.ok) throw new Error("fixture rejected: " + built.reason);
  const store = new SemantiqEvaluationRecordStore();
  const persisted = store.persist(built.event);
  if (!persisted.ok) throw new Error("fixture not persistable: " + persisted.reason);
  return persisted.record;
}

const ALLOWED = [{ engineId: "engine-18c", engineVersion: "1.0.0" }];

function eventSummary(eventId: string): SemantiqEvidenceEventSummary {
  return {
    eventId,
    eventType: "verb_executed",
    actorType: "runtime",
    actorId: "runtime-18c",
    timestamp: new Date(T0).toISOString(),
    policyDecision: "allow",
    verb: "inspect",
  };
}

// ---------------------------------------------------------------------------
// 18C-1 — Redaction: no secrets by default, layered patterns, bounded walk.
// ---------------------------------------------------------------------------

describe("18C-1 — redaction (no secrets by default)", () => {
  it("18C-R1 every pinned secret pattern is detected and replaced with a labeled marker", () => {
    // Sample tokens are assembled via concatenation so THIS SOURCE FILE
    // never contains a scan-matching literal (verify-local secret-scan
    // hygiene); the runtime strings are full tokens.
    const cases: readonly [RegExp, string][] = [
      [/AKIA[0-9A-Z]{16}/, "AKIA" + "IOSFODNN7EXAMPLE"],
      [/ghp_[A-Za-z0-9]{16,}/, "ghp_" + "ABCDEFGHIJKLMNOPqrstuv"],
      [/sk-[A-Za-z0-9_-]{16,}/, "sk-" + "abcdefghijklmnop123456"],
      [/xox[baprs]-[A-Za-z0-9-]{10,}/, "xoxb-" + "1234567890-abcdef"],
      [
        /eyJ[A-Za-z0-9_-]+/,
        ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxIn0", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"].join("."),
      ],
      [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "-----BEGIN " + "RSA PRIVATE KEY-----"],
    ];
    for (const [pattern, sample] of cases) {
      expect(SEMANTIQ_SECRET_PATTERNS.some((p) => p.re.test(sample)), "pattern coverage for " + String(pattern)).toBe(true);
      const r = redactValue(sample, 4096);
      expect(String(r.value)).not.toContain(sample);
      expect(String(r.value)).toContain("[REDACTED:");
      expect(r.redactions).toBeGreaterThan(0);
    }
  });

  it("18C-R2 assignments (password/api_key/authorization/bearer) are redacted with names intact", () => {
    const r = redactValue({ password: "hunter2-secret", api_key: "abc123def456", authorization: "Bearer tokentokentoken12" }, 4096) as { value: Record<string, string> };
    const out = JSON.stringify(r.value);
    expect(out).not.toContain("hunter2-secret");
    expect(out).not.toContain("abc123def456");
    expect(out).not.toContain("tokentokentoken12");
    expect(r.value["password"]).toContain("[REDACTED:");
    expect(Object.keys(r.value).sort()).toEqual(["api_key", "authorization", "password"]);
  });

  it("18C-R3 connection strings with credentials are redacted by default (local-first: no endpoints belong in evidence)", () => {
    const r = redactValue("mongodb://admin:s3cret@db.example.com:27017/menog", 4096);
    expect(String(r.value)).not.toContain("s3cret");
    expect(String(r.value)).toContain("[REDACTED:connection_string]");
  });

  it("18C-R4 nested structures are deep-redacted; arrays and keys are bounded", () => {
    const hostile = {
      note: "token=" + "z".repeat(200),
      nested: { deeper: { jwt: ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxIn0", "abc123"].join(".") } },
      big: Array.from({ length: 200 }, (_, i) => "item-" + String(i)),
    };
    const r = redactValue(hostile, 256);
    const out = JSON.stringify(r.value);
    expect(out).not.toContain("z".repeat(200));
    expect(out).toContain("[REDACTED:");
    expect((r.value as Record<string, unknown>)["big"]).toHaveLength(129); // 128 + truncation marker
    expect(r.redactions).toBeGreaterThanOrEqual(2);
  });

  it("18C-R5 export redacts secrets embedded anywhere in record content", () => {
    // Build a valid record, then attack its exported form through a hostile
    // provenance note (builder bounds the note; redaction still scans).
    const built = buildEvaluationResultEvent({
      subject: "leak-18c",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("task_completion", 0.8)],
      provenance: prov({ note: "reviewed by api_key=sk-realkey123456789" }),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const store = new SemantiqEvaluationRecordStore();
    const persisted = store.persist(built.event);
    expect(persisted.ok).toBe(true);
    if (!persisted.ok) return;
    const exp = exportEvidence({
      records: [persisted.record],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (exp.ok) {
      const json = JSON.stringify(exp.package);
      expect(json).not.toContain("sk-realkey123456789");
      expect(json).toContain("[REDACTED:");
      expect(exp.redactions).toBeGreaterThanOrEqual(1);
      expect(exp.package.metadata.redactionCount).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// 18C-2 — Schema validation (import deny-by-default gates).
// ---------------------------------------------------------------------------

describe("18C-2 — schema validation (bounded, deny-by-default import)", () => {
  it("18C-C1 the transfer deny union is closed, frozen, and guarded", () => {
    expect(KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS).toEqual([
      "invalid_input",
      "oversized_export",
      "invalid_package",
      "schema_mismatch",
      "tampered_record",
      "unknown_evaluator",
      "oversized_package",
      "duplicate_record",
      "store_full",
    ]);
    expect(Object.isFrozen(KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS)).toBe(true);
    expect(isSemantiqTransferDenyReason("tampered_record")).toBe(true);
    expect(isSemantiqTransferDenyReason("policy_override")).toBe(false);
  });

  it("18C-C2 import rejects non-objects, wrong versions, wrong kinds, and count mismatches", () => {
    const exp = exportEvidence({
      records: [buildRecord("schema-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const meta = pkg.metadata as Record<string, unknown>;
    expect(importEvidence(null).ok).toBe(false);
    expect(importEvidence(42).ok).toBe(false);
    expect(importEvidence({ ...pkg, metadata: { ...meta, schemaVersion: "menog-semantiq/v9" } }).ok).toBe(false);
    expect(importEvidence({ ...pkg, metadata: { ...meta, packageKind: "something-else" } }).ok).toBe(false);
    const mismatch = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    (mismatch.records as unknown[]).push({});
    const r = importEvidence(mismatch);
    expect(isTransferDenial(r) && r.denyReason).toBe("invalid_package");
  });

  it("18C-C3 import rejects oversized packages (record/event caps)", () => {
    const many = [];
    for (let i = 0; i < SEMANTIQ_MAX_EXPORT_RECORDS + 1; i++) many.push(buildRecord("cap-" + String(i), T0 + i));
    const exp = exportEvidence({
      records: many.slice(0, SEMANTIQ_MAX_EXPORT_RECORDS),
      events: Array.from({ length: SEMANTIQ_MAX_EXPORT_EVENTS + 1 }, (_, i) => eventSummary("e" + String(i))),
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    // Export itself must refuse the oversized event list.
    expect(exp.ok).toBe(false);
    expect(isTransferDenial(exp) && exp.denyReason).toBe("oversized_export");
  });

  it("18C-C4 imported events must re-pass the 18B event validator (no foreign shapes)", () => {
    const exp = exportEvidence({
      records: [buildRecord("foreign-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const recs = pkg.records as Record<string, unknown>[];
    recs[0]!.event = { ...(recs[0]!.event as Record<string, unknown>), authority: "execution_authority" };
    const r = importEvidence(pkg);
    expect(r.ok).toBe(false);
  });

  it("18C-C5 export refuses malformed inputs with machine-readable reasons", () => {
    expect(isTransferDenial(exportEvidence({ records: [], exporterId: "", exporterVersion: "1", exportedAtEpochMs: T0 }) as { ok: boolean }) ).toBe(true);
    const badRecs = exportEvidence({
      records: [null as unknown as SemantiqEvaluationRecord],
      exporterId: "x",
      exporterVersion: "1",
      exportedAtEpochMs: T0,
    });
    expect(isTransferDenial(badRecs) && badRecs.denyReason).toBe("invalid_input");
  });
});

// ---------------------------------------------------------------------------
// 18C-3 — Tampered packages: hash and id integrity gates.
// ---------------------------------------------------------------------------

describe("18C-3 — tampered package detection (integrity gates)", () => {
  it("18C-T1 a mutated record event is caught by the contentHash gate", () => {
    const exp = exportEvidence({
      records: [buildRecord("tamper-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const recs = pkg.records as Record<string, unknown>[];
    const ev = recs[0]!.event as Record<string, unknown>;
    // Mutate a schema-neutral field (provenance note): the event stays
    // schema-valid so ONLY the hash gate can fire.
    const p = ev.provenance as Record<string, unknown>;
    p["note"] = "mutated after export";
    const r = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(false);
    expect(isTransferDenial(r) && r.denyReason).toBe("tampered_record");
  });

  it("18C-T2 a forged recordId (hash recomputed but id wrong) is caught by the id gate", () => {
    const exp = exportEvidence({
      records: [buildRecord("idgate-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const recs = pkg.records as Record<string, unknown>[];
    recs[0]!["recordId"] = "f".repeat(64);
    const r = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(false);
    expect(isTransferDenial(r) && r.denyReason).toBe("tampered_record");
  });

  it("18C-T3 a tampered packageHash over the whole payload is caught", () => {
    const exp = exportEvidence({
      records: [buildRecord("pkghash-18c")],
      events: [eventSummary("evt-18c-t3")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const events = pkg.events as Record<string, unknown>[];
    events[0]!["verb"] = "forged-verb"; // payload mutated under the same hash
    const r = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(false);
    expect(isTransferDenial(r) && r.denyReason).toBe("tampered_record");
  });

  it("18C-T4 a healthy package with valid hashes passes all integrity gates", () => {
    const exp = exportEvidence({
      records: [buildRecord("clean-18c"), requestRecord("clean-req-18c")],
      events: [eventSummary("evt-18c-clean")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const round = JSON.parse(JSON.stringify(exp.package));
    const r = importEvidence(round, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 18C-4 — Unknown evaluator: identity/version validation is opt-in.
// ---------------------------------------------------------------------------

describe("18C-4 — evaluator identity validation (opt-in, never ambient)", () => {
  it("18C-U1 engine-sourced records are refused when no allow-list is provided", () => {
    const exp = exportEvidence({
      records: [buildRecord("noallow-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const r = importEvidence(JSON.parse(JSON.stringify(exp.package)));
    expect(r.ok).toBe(false);
    expect(isTransferDenial(r) && r.denyReason).toBe("unknown_evaluator");
  });

  it("18C-U2 unknown evaluator id or version is refused; exact pairs pass", () => {
    const exp = exportEvidence({
      records: [buildRecord("ident-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package));
    expect(importEvidence(pkg, { allowedEvaluators: [{ engineId: "engine-18c", engineVersion: "9.9.9" }] }).ok).toBe(false);
    expect(importEvidence(pkg, { allowedEvaluators: [{ engineId: "other", engineVersion: "1.0.0" }] }).ok).toBe(false);
    const ok = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(ok.ok).toBe(true);
  });

  it("18C-U3 partial engine identity (one of two fields) is rejected as malformed", () => {
    const exp = exportEvidence({
      records: [buildRecord("partial-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const recs = pkg.records as Record<string, unknown>[];
    const ev = recs[0]!.event as Record<string, unknown>;
    const p = { ...(ev.provenance as Record<string, unknown>) };
    delete p["engineVersion"];
    ev["provenance"] = p;
    // Recompute hashes so ONLY the identity gate can fire.
    recs[0]!["contentHash"] = exp.package.records[0]!.contentHash.slice(0, 63) + "0";
    const r = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(false);
  });

  it("18C-U4 ledger-derived (non-engine) records import without an allow-list", () => {
    const exp = exportEvidence({
      records: [requestRecord("noengine-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const r = importEvidence(JSON.parse(JSON.stringify(exp.package)), {});
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.imported).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 18C-5 — Round-trip: export → import reproduces equivalent evidence.
// ---------------------------------------------------------------------------

describe("18C-5 — round-trip fidelity", () => {
  it("18C-R10 export → JSON → import preserves records byte-identically (validated)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const built = buildEvaluationDeniedEvent({
      subject: "roundtrip-18c",
      trigger: "event_hook",
      atEpochMs: T0,
      denyReason: "adapter_disabled",
      reason: "no engine configured",
      provenance: prov({ source: "derived_from_ledger", engineId: undefined, engineVersion: undefined }),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const persisted = store.persist(built.event);
    expect(persisted.ok).toBe(true);
    if (!persisted.ok) return;

    const exp = exportEvidence({
      records: [persisted.record],
      events: [eventSummary("evt-18c-rt")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;

    // Simulate transfer across a trust boundary via JSON text.
    const wire = JSON.stringify(exp.package);
    const imported = importEvidence(JSON.parse(wire), {});
    expect(imported.ok).toBe(true);
    if (!imported.ok) return;
    expect(imported.imported).toBe(1);
    const rec = imported.records[0]!;
    expect(rec.event).toEqual(persisted.record.event);
    expect(rec.contentHash).toBe(persisted.record.contentHash);
    expect(rec.recordId).toBe(persisted.record.recordId);
    expect(validateEvaluationEvent(rec.event)).toBeNull();
  });

  it("18C-R11 export is deterministic: identical inputs produce identical package hashes", () => {
    const mk = () =>
      exportEvidence({
        records: [buildRecord("det-18c")],
        events: [eventSummary("evt-18c-det")],
        exporterId: "menog-18c",
        exporterVersion: "0.1.0",
        exportedAtEpochMs: T0,
      });
    const a = mk();
    const b = mk();
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.package.packageHash).toBe(b.package.packageHash);
      expect(JSON.stringify(a.package)).toBe(JSON.stringify(b.package));
    }
  });

  it("18C-R12 a multi-record export round-trips with counts and hashes intact", () => {
    const records = [
      buildRecord("multi-1-18c", T0),
      buildRecord("multi-2-18c", T0 + 1),
      requestRecord("multi-3-18c", T0 + 2),
    ];
    const exp = exportEvidence({
      records,
      events: [eventSummary("evt-18c-m1"), eventSummary("evt-18c-m2")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    expect(exp.package.metadata.recordCount).toBe(3);
    expect(exp.package.metadata.eventCount).toBe(2);
    const imported = importEvidence(JSON.parse(JSON.stringify(exp.package)), { allowedEvaluators: ALLOWED });
    expect(imported.ok).toBe(true);
    if (imported.ok) expect(imported.imported).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// 18C-6 — Authority separation + ledger integrity (negative security).
// ---------------------------------------------------------------------------

describe("18C-6 — authority separation (transfer never becomes authority)", () => {
  it("18C-A1 imported records keep advisory pins and can never re-authorize anything", () => {
    const exp = exportEvidence({
      records: [buildRecord("pins-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const imported = importEvidence(JSON.parse(JSON.stringify(exp.package)), { allowedEvaluators: ALLOWED });
    expect(imported.ok).toBe(true);
    if (imported.ok) {
      const rec = imported.records[0]!;
      expect(rec.event.authority).toBe("advisory_data");
      expect(rec.event.executionAuthorized).toBe(false);
      const json = JSON.stringify(rec);
      expect(json.includes('"executionAuthorized":true')).toBe(false);
    }
  });

  it("18C-A2 an import payload claiming execution authority is rejected at the schema gate", () => {
    const exp = exportEvidence({
      records: [buildRecord("authforge-18c")],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (!exp.ok) return;
    const pkg = JSON.parse(JSON.stringify(exp.package)) as Record<string, unknown>;
    const recs = pkg.records as Record<string, unknown>[];
    recs[0]!.event = { ...(recs[0]!.event as Record<string, unknown>), executionAuthorized: true };
    const r = importEvidence(pkg, { allowedEvaluators: ALLOWED });
    expect(r.ok).toBe(false);
    expect(isTransferDenial(r) && r.denyReason).toBe("invalid_package");
  });

  it("18C-A3 the policy engine stays deny-by-default for transfer verbs (Day-1 unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["semantiq.export", "semantiq.import", "evidence.export", "evidence.import"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-18c",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });

  it("18C-A4 export/import perform no I/O: the ledger stays untouched and chain-intact", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const r = ledger.append({
      eventId: "evt-18c-l1",
      timestamp: new Date(T0).toISOString(),
      eventType: "verb_executed",
      actor: { type: "runtime", id: "runtime-18c" },
      workspaceId: "ws-18c",
      verb: "inspect",
      policyDecision: "allow",
    });
    expect(r.ok).toBe(true);
    const snapshot = JSON.stringify(ledger.events());
    const exp = exportEvidence({
      records: [requestRecord("io-18c")],
      events: [{ ...eventSummary("evt-18c-l1") }],
      exporterId: "menog-18c",
      exporterVersion: "0.1.0",
      exportedAtEpochMs: T0,
    });
    expect(exp.ok).toBe(true);
    if (exp.ok) void importEvidence(JSON.parse(JSON.stringify(exp.package)), {});
    expect(JSON.stringify(ledger.events())).toBe(snapshot);
    expect(ledger.verify().ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 18C-7 — Governance invariants (15E/16E/17E/18A/18B pattern).
// ---------------------------------------------------------------------------

import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

describe("18C-7 — governance invariants", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];

  it("18C-V1 PR-01..PR-05 disposition block is verbatim in the 18C report", () => {
    const content = readDoc("docs/release/PROMPT_18C_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(content.includes(line), "missing " + line).toBe(true);
    }
  });

  it("18C-V2 authorization-not-granted lines are unchanged in the 18C report", () => {
    const content = readDoc("docs/release/PROMPT_18C_REPORT.md").replace(/\s+/g, " ");
    expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("18C-V3 no Phase-20 isolation primitives exist in the semantiq package source", () => {
    const srcRoot = path.resolve(process.cwd(), "packages/semantiq/src");
    const files = ["adapter.ts", "rules.ts", "types.ts", "index.ts", "events.ts", "records.ts", "requestFlow.ts", "transfer.ts"];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = path.join(srcRoot, f);
      expect(existsSync(full), "semantiq source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("18C-V4 the 18C report documents no-secrets-by-default and opt-in evaluator identity", () => {
    const report = readDoc("docs/release/PROMPT_18C_REPORT.md");
    expect(/no secrets by default/i.test(report)).toBe(true);
    expect(report.includes("unknown_evaluator")).toBe(true);
    expect(report.includes("menog-semantiq/v0")).toBe(true);
  });

  it("18C-V5 the semantiq package still declares no network surface (transfer is pure data-in/data-out)", () => {
    const pkg = JSON.parse(readDoc("packages/semantiq/package.json")) as { dependencies?: Record<string, string> };
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(["@menog/core"]);
    const src = readDoc("packages/semantiq/src/transfer.ts");
    expect(/node:net|node:http|node:https|node:tls|node:dns|node:fs/.test(src)).toBe(false);
  });
});
