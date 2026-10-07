import { describe, it, expect } from "vitest";
import {
  AppendOnlyLedger,
  GENESIS_PREVIOUS_HASH,
  computeEventHash,
  serializeEventForHash,
  sha256Hex,
  MAX_LINE_BYTES,
  DEFAULT_REDACTION_MARKER,
  type MenogEventInput,
  type MenogEvent,
} from "@menog/event-ledger";
import { writeFileSync, mkdirSync, readFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function tmpdirForTest(): string {
  const base = join(tmpdir(), "menog-event-ledger-" + Math.random().toString(36).slice(2, 10));
  mkdirSync(base, { recursive: true });
  return base;
}

function cleanupDir(dir: string): void {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

function baseInput(overrides: Partial<MenogEventInput> = {}): MenogEventInput {
  return {
    eventId: "evt-" + Math.random().toString(36).slice(2, 10),
    timestamp: "2026-09-05T00:00:00.000Z",
    eventType: "verb_invoke",
    actor: { type: "agent", id: "agent-0" },
    workspaceId: "ws-0",
    taskId: "task-0",
    verb: "inspect",
    capability: "workspace:list",
    policyDecision: "allow",
    inputSummary: { path: "/workspace" },
    resultSummary: { fileCount: 42 },
    ...overrides,
  };
}

describe("AppendOnlyLedger — append + verify baseline", () => {
  it("appends two events and chain links previousHash correctly", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const a = ledger.append(baseInput({ eventId: "evt-1" }));
    const b = ledger.append(baseInput({ eventId: "evt-2" }));
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    expect(a.event?.previousHash).toBe(GENESIS_PREVIOUS_HASH);
    expect(b.event?.previousHash).toBe(a.event!.hash);
    expect(b.event?.eventId).toBe("evt-2");
    expect(ledger.length).toBe(2);
  });

  it("verify() passes on clean chain and reports 2/2", () => {
    const ledger = AppendOnlyLedger.inMemory();
    ledger.append(baseInput({ eventId: "evt-1" }));
    ledger.append(baseInput({ eventId: "evt-2" }));
    const result = ledger.verify();
    expect(result.ok).toBe(true);
    expect(result.verifiedCount).toBe(2);
    expect(result.totalCount).toBe(2);
    expect(result.reasons).toHaveLength(0);
  });
});

describe("AppendOnlyLedger — corruption detection", () => {
  it("detects modified historical event via verify()", () => {
    const dir = tmpdirForTest();
    try {
      const filePath = join(dir, ".menog", "events.jsonl");
      const ledger = AppendOnlyLedger.at(filePath);
      ledger.append(baseInput({ eventId: "evt-1", resultSummary: { ok: true } }));
      ledger.append(baseInput({ eventId: "evt-2", resultSummary: { ok: true, n: 2 } }));
      expect(ledger.verify().ok).toBe(true);
      const raw = readFileSync(filePath, "utf8");
      const corrupted = raw.replace(
        '"resultSummary":{"ok":true}',
        '"resultSummary":{"ok":false}'
      );
      expect(corrupted).not.toBe(raw);
      writeFileSync(filePath, corrupted, "utf8");
      expect(() => AppendOnlyLedger.at(filePath)).toThrow(/integrity verification failed/);
      let caught: Error | null = null;
      try {
        AppendOnlyLedger.at(filePath);
      } catch (e) {
        caught = e as Error;
      }
      expect(caught).not.toBeNull();
      const msg = caught!.message;
      expect(msg.includes("hash mismatch") || msg.includes("previousHash mismatch")).toBe(true);
      expect(msg.includes("1/2 events verified") || msg.includes(" events verified")).toBe(true);
    } finally {
      cleanupDir(dir);
    }
  });

  it("rejects manual wrong previousHash override at append time", () => {
    const ledger = AppendOnlyLedger.inMemory();
    ledger.append(baseInput({ eventId: "evt-1" }));
    const bad = ledger.append(
      baseInput({
        eventId: "evt-2",
        previousHash:
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      })
    );
    expect(bad.ok).toBe(false);
    expect(bad.reason).toContain("previousHash mismatch");
    expect(ledger.length).toBe(1);
  });
});

describe("AppendOnlyLedger — denied-action recording", () => {
  it("records a policy=deny action and verify() still passes", () => {
    const ledger = AppendOnlyLedger.inMemory();
    ledger.append(baseInput({ eventId: "evt-allow", policyDecision: "allow" }));
    const denyResult = ledger.append(
      baseInput({
        eventId: "evt-deny",
        eventType: "policy_denied",
        policyDecision: "deny",
        verb: "execute",
        capability: "process:privileged",
        resultSummary: {
          reason: "capability process:privileged not granted to agent-0",
        },
      })
    );
    expect(denyResult.ok).toBe(true);
    expect(denyResult.event?.policyDecision).toBe("deny");
    expect(denyResult.event?.eventType).toBe("policy_denied");
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(2);
    const evts = ledger.events();
    expect(evts[1]!.policyDecision).toBe("deny");
  });

  it("redacts any secret-sounding fields from inputSummary/resultSummary", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const result = ledger.append(
      baseInput({
        eventId: "evt-secret-check",
        inputSummary: {
          path: "/x",
          password: "supersecret",
          apiKey: "sk_12345",
          nested: { bearerToken: "tok-deadbeef" },
        },
        resultSummary: {
          exitCode: 1,
          sessionId: "should-be-redacted",
        },
      })
    );
    expect(result.ok).toBe(true);
    const input = result.event!.inputSummary! as Record<string, unknown>;
    expect(input.path).toBe("/x");
    expect(input.password).toBe(DEFAULT_REDACTION_MARKER);
    expect(input.apiKey).toBe(DEFAULT_REDACTION_MARKER);
    expect((input.nested as Record<string, unknown>).bearerToken).toBe(
      DEFAULT_REDACTION_MARKER
    );
    const r = result.event!.resultSummary! as Record<string, unknown>;
    expect(r.exitCode).toBe(1);
    expect(r.sessionId).toBe(DEFAULT_REDACTION_MARKER);
    const recomputed = computeEventHash(
      result.event! as Omit<MenogEvent, "hash">
    );
    expect(recomputed).toBe(result.event!.hash);
  });
});

describe("AppendOnlyLedger — ordering & determinism", () => {
  it("preserves append order in events() array and in serialized JSONL", () => {
    const dir = tmpdirForTest();
    try {
      const filePath = join(dir, ".menog", "events.jsonl");
      const l1 = AppendOnlyLedger.at(filePath);
      const ids = ["a", "b", "c", "d", "e"];
      for (const id of ids) l1.append(baseInput({ eventId: "evt-" + id }));
      expect(l1.events().map((e) => e.eventId)).toEqual(ids.map((i) => "evt-" + i));
      const l2 = AppendOnlyLedger.at(filePath);
      expect(l2.events().map((e) => e.eventId)).toEqual(ids.map((i) => "evt-" + i));
      expect(l2.verify().ok).toBe(true);
      expect(sha256Hex(serializeEventForHash(l1.events()[0]! as Omit<MenogEvent, "hash">))).toBe(
        l1.events()[0]!.hash
      );
    } finally {
      cleanupDir(dir);
    }
  });

  it("rejects duplicate eventIds at append time", () => {
    const ledger = AppendOnlyLedger.inMemory();
    expect(ledger.append(baseInput({ eventId: "dup" })).ok).toBe(true);
    const r = ledger.append(baseInput({ eventId: "dup" }));
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("duplicate eventId");
    expect(ledger.length).toBe(1);
  });

  it("enforces per-event payload byte limit (rejects oversized events)", () => {
    const ledger = AppendOnlyLedger.inMemory({ maxLineBytes: 512 });
    const huge = "x".repeat(4096);
    const r = ledger.append(
      baseInput({
        eventId: "evt-huge",
        resultSummary: { payload: huge },
      })
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("exceeds max line size limit");
  });
});

describe("AppendOnlyLedger — hash determinism + genesis", () => {
  it("uses GENESIS_PREVIOUS_HASH for first event and SHA-256 hex length 64", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const r = ledger.append(baseInput({ eventId: "evt-genesis" }));
    expect(r.event?.previousHash).toBe(GENESIS_PREVIOUS_HASH);
    expect(r.event?.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(GENESIS_PREVIOUS_HASH).toMatch(/^0{64}$/);
  });

  it("maxLineBytes default is 256 KiB", () => {
    expect(MAX_LINE_BYTES).toBe(256 * 1024);
  });
});
