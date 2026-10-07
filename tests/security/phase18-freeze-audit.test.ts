import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import type { Actor } from "@menog/core";
import {
  SEMANTIQ_SCHEMA_VERSION,
  SEMANTIQ_STAGES,
  KNOWN_SEMANTIQ_TRIGGERS,
  KNOWN_SEMANTIQ_CLAIM_KINDS,
  KNOWN_SEMANTIQ_DENY_REASONS,
  KNOWN_SEMANTIQ_EVENT_TYPES,
  SEMANTIQ_EVALUATION_DIMENSIONS,
  SEMANTIQ_EVALUATION_VERDICTS,
  SEMANTIQ_PROVENANCE_SOURCES,
  SEMANTIQ_MAX_CLAIMS,
  SEMANTIQ_MAX_EVENTS_PER_EVALUATION,
  SEMANTIQ_MAX_RECORDS,
  SEMANTIQ_MAX_EVENT_DIMENSIONS,
  SEMANTIQ_MAX_EXPORT_RECORDS,
  SEMANTIQ_MAX_EXPORT_EVENTS,
  SEMANTIQ_MAX_TOTAL_BYTES,
  SEMANTIQ_MAX_REJECTIONS,
  SEMANTIQ_SCORE_STEP,
  SEMANTIQ_VERDICT_PASS_THRESHOLD,
  SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD,
  KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS,
  KNOWN_SEMANTIQ_HOSTILE_PATTERNS,
  KNOWN_SEMANTIQ_BOUNDARY_DENY_REASONS,
  validateEvaluationEvent,
  deriveVerdict,
  buildSemantiqAdapter,
  buildDisabledAdapterState,
  SemantiqEvaluationRecordStore,
  SemantiqRejectionLog,
  exportEvidence,
  importEvidence,
  requestEvaluation,
  type SemantiqLedgerPort,
} from "@menog/semantiq";

const AGENT: Actor = { type: "agent", id: "agent-18e-audit" };
const T0 = 1_860_000_000_000;

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

function emptyPort(): SemantiqLedgerPort {
  return { readEvents: () => ({ ok: true, events: [] }) };
}

function isDenial(r: { ok: boolean }): r is { ok: false; denyReason: string; reason: string } {
  return r.ok === false;
}

// ---------------------------------------------------------------------------
// 18E-P — Contract pins. Any change is an unfreeze-protocol event
// (PHASE_18_FREEZE.md §5) requiring explicit human approval.
// ---------------------------------------------------------------------------

describe("18E-P — SemantIQ V1 contract pins (schema, unions, caps)", () => {
  it("18E-P1 schema version is pinned at menog-semantiq/v0 (SemantIQ V1)", () => {
    expect(SEMANTIQ_SCHEMA_VERSION).toBe("menog-semantiq/v0");
  });

  it("18E-P2 lifecycle stages, triggers, and claim kinds are exactly the frozen unions", () => {
    expect(SEMANTIQ_STAGES).toEqual(["requested", "computed", "delivered"]);
    expect(KNOWN_SEMANTIQ_TRIGGERS).toEqual(["manual", "scheduled", "cli", "event_hook", "unknown"]);
    expect(KNOWN_SEMANTIQ_CLAIM_KINDS).toEqual([
      "goal_achievement",
      "metric_delta",
      "narrative_summary",
      "regression_indicator",
      "recommendation_proposal",
    ]);
    for (const u of [SEMANTIQ_STAGES, KNOWN_SEMANTIQ_TRIGGERS, KNOWN_SEMANTIQ_CLAIM_KINDS]) {
      expect(Object.isFrozen(u)).toBe(true);
    }
  });

  it("18E-P3 deny-reason unions are exactly the frozen V1 set (18A/18B/18C/18D deltas pinned)", () => {
    expect(KNOWN_SEMANTIQ_DENY_REASONS).toEqual([
      "adapter_disabled",
      "adapter_unconfigured",
      "adapter_degraded",
      "invalid_request",
      "ledger_unavailable",
      "oversized_request",
      "conflict_unresolved",
    ]);
    expect(KNOWN_SEMANTIQ_EVENT_TYPES).toEqual([
      "algorithm_recommended",
      "algorithm_denied",
      "verb_executed",
      "evaluation_requested",
      "evaluation_result",
    ]);
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
    expect(KNOWN_SEMANTIQ_BOUNDARY_DENY_REASONS).toEqual([
      "authority_confusion",
      "instruction_smuggling",
      "score_manipulation",
      "schema_abuse",
      "invalid_input",
    ]);
    expect(KNOWN_SEMANTIQ_HOSTILE_PATTERNS).toEqual([
      "system_instruction_override",
      "role_redirection",
      "policy_override_directive",
      "tool_authorization_demand",
      "capability_grant_demand",
      "write_demand",
      "commit_demand",
      "authority_claim",
      "execution_claim",
      "instruction_boundary_probe",
    ]);
  });

  it("18E-P4 the four evaluation dimensions and verdicts are exactly the closed unions", () => {
    expect(SEMANTIQ_EVALUATION_DIMENSIONS).toEqual([
      "plan_quality",
      "task_completion",
      "policy_compliance",
      "reproducibility",
    ]);
    expect(SEMANTIQ_EVALUATION_VERDICTS).toEqual(["pass", "borderline", "fail", "indeterminate"]);
    expect(SEMANTIQ_PROVENANCE_SOURCES).toEqual(["human", "engine", "derived_from_ledger", "mixed"]);
    expect(SEMANTIQ_MAX_EVENT_DIMENSIONS).toBe(4);
  });

  it("18E-P5 all 18A–18D caps are pinned (bounded surface)", () => {
    expect(SEMANTIQ_MAX_CLAIMS).toBe(16);
    expect(SEMANTIQ_MAX_EVENTS_PER_EVALUATION).toBe(256);
    expect(SEMANTIQ_MAX_RECORDS).toBe(1024);
    expect(SEMANTIQ_MAX_EXPORT_RECORDS).toBe(256);
    expect(SEMANTIQ_MAX_EXPORT_EVENTS).toBe(256);
    expect(SEMANTIQ_MAX_TOTAL_BYTES).toBe(262_144);
    expect(SEMANTIQ_MAX_REJECTIONS).toBe(512);
    expect(SEMANTIQ_SCORE_STEP).toBe(0.1);
    expect(SEMANTIQ_VERDICT_PASS_THRESHOLD).toBe(0.8);
    expect(SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD).toBe(0.5);
  });

  it("18E-P6 verdict derivation thresholds are pinned behavioral semantics", () => {
    const s = (d: string, v: number) => ({ dimension: d as "plan_quality", score: v, confidence: 1 });
    expect(deriveVerdict([])).toBe("indeterminate");
    expect(deriveVerdict([s("plan_quality", 0.9)])).toBe("pass");
    expect(deriveVerdict([s("plan_quality", 0.6)])).toBe("borderline");
    expect(deriveVerdict([s("plan_quality", 0.4)])).toBe("fail");
    expect(deriveVerdict([s("plan_quality", 0.79)])).toBe("borderline");
  });
});

// ---------------------------------------------------------------------------
// 18E-T — Implemented-vs-contract truth: what 18A–18D really shipped.
// ---------------------------------------------------------------------------

describe("18E-T — implemented-vs-contract truth audit", () => {
  it("18E-T1 exactly nine semantiq source modules exist (no hidden surface)", () => {
    const srcDir = path.resolve(process.cwd(), "packages/semantiq/src");
    expect(existsSync(srcDir)).toBe(true);
    const files = readdirSync(srcDir).filter((f) => f.endsWith(".ts")).sort();
    expect(files).toEqual([
      "adapter.ts",
      "boundary.ts",
      "events.ts",
      "index.ts",
      "records.ts",
      "requestFlow.ts",
      "rules.ts",
      "transfer.ts",
      "types.ts",
    ]);
  });

  it("18E-T2 @menog/semantiq depends only on @menog/core; devDependencies empty (18A guarantee intact)", () => {
    const pkg = JSON.parse(readDoc("packages/semantiq/package.json")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(["@menog/core"]);
    expect(pkg.devDependencies ?? {}).toEqual({});
  });

  it("18E-T3 no workspace package imports @menog/semantiq (optionality is structural)", () => {
    for (const dir of ["packages", "apps"]) {
      const base = path.resolve(process.cwd(), dir);
      if (!existsSync(base)) continue;
      for (const entry of readdirDirs(base)) {
        const pkgPath = path.join(base, entry, "package.json");
        if (!existsSync(pkgPath)) continue;
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
          name?: string;
          dependencies?: Record<string, string>;
        };
        if (pkg.name === "@menog/semantiq") continue;
        for (const dep of Object.keys(pkg.dependencies ?? {})) {
          expect(dep.includes("semantiq"), pkg.name + " → " + dep).toBe(false);
        }
      }
    }
  });

  it("18E-T4 the store/log/emitter surfaces are exactly what the docs claim (no exec/write capability)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const log = new SemantiqRejectionLog();
    const a = buildSemantiqAdapter({ ledgerPort: emptyPort(), engine: null });
    for (const [obj, name] of [
      [store, "store"],
      [log, "log"],
      [a, "adapter"],
    ] as [object, string][]) {
      const names = new Set<string>();
      let proto: object | null = Object.getPrototypeOf(obj);
      while (proto && proto !== Object.prototype) {
        for (const n of Object.getOwnPropertyNames(proto)) names.add(n);
        proto = Object.getPrototypeOf(proto);
      }
      for (const f of ["exec", "spawn", "commit", "authorize", "grant", "writeFile", "fetch", "connect"]) {
        expect(names.has(f), name + " exposes " + f).toBe(false);
      }
    }
    // The store exposes persist/read/length/getById/summary — nothing else
    // beyond Object prototype methods.
    const own = new Set(Object.getOwnPropertyNames(SemantiqEvaluationRecordStore.prototype));
    own.delete("constructor");
    expect([...own].sort()).toEqual(["getById", "length", "persist", "read", "summary"]);
  });

  it("18E-T5 every 18A–18D gate artifact exists and pins its verdict", () => {
    const expected: readonly [string, string][] = [
      ["docs/release/PROMPT_18A_REPORT.md", "18A_PASS_WITH_MINOR_DEBT"],
      ["docs/release/PROMPT_18B_REPORT.md", "18B_PASS_WITH_MINOR_DEBT"],
      ["docs/release/PROMPT_18C_REPORT.md", "18C_PASS_WITH_MINOR_DEBT"],
      ["docs/release/PROMPT_18D_REPORT.md", "18D_PASS_WITH_MINOR_DEBT"],
      ["docs/release/PROMPT_18E_REPORT.md", "18E_"],
    ];
    for (const [doc, verdict] of expected) {
      const content = readDoc(doc);
      expect(content.includes(verdict), doc + " must pin " + verdict).toBe(true);
    }
  });

  it("18E-T6 the freeze artifact declares the transition and keeps SemantIQ external", () => {
    const freeze = readDoc("docs/release/PHASE_18_FREEZE.md");
    expect(freeze.includes("Phase-18: OPEN → FROZEN")).toBe(true);
    expect(freeze.includes("OPTIONAL_EXTERNAL")).toBe(true);
    expect(freeze.includes("PENDING HUMAN SIGNATURE")).toBe(true);
    expect(freeze.includes("menog-semantiq/v0")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 18E-A — Authority / fail-closed / isolation / determinism audits.
// ---------------------------------------------------------------------------

describe("18E-A — authority, fail-closed, isolation, determinism", () => {
  it("18E-A1 adapter-off verification: disabled/unconfigured deny honestly, deterministically, with zero engine/port work", async () => {
    let portTouched = false;
    const off = buildSemantiqAdapter({
      ledgerPort: {
        readEvents: () => {
          portTouched = true;
          return { ok: true, events: [] };
        },
      },
      engine: null,
    });
    expect(off.state).toBe("disabled");
    const r1 = await off.evaluate({ subject: "off-18e", trigger: "manual" } as never, { actor: AGENT });
    const r2 = await off.evaluate({ subject: "off-18e", trigger: "manual" } as never, { actor: AGENT });
    expect(r1.ok).toBe(false);
    expect(isDenial(r1) && r1.denyReason).toBe("adapter_disabled");
    expect(isDenial(r1) && isDenial(r2) && r1.denyReason === r2.denyReason).toBe(true);
    expect(portTouched).toBe(false);
    const un = await buildSemantiqAdapter({}).evaluate({ subject: "x", trigger: "manual" } as never, { actor: AGENT });
    expect(isDenial(un) && un.denyReason).toBe("adapter_unconfigured");
    const dg = await buildDisabledAdapterState("degraded").evaluate({ subject: "x", trigger: "manual" } as never, { actor: AGENT });
    expect(isDenial(dg) && dg.denyReason).toBe("adapter_degraded");
  });

  it("18E-A2 authority pins hold across every result family (evaluation, events, rejections)", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: emptyPort(), engine: () => ({ ok: true, claims: [{ kind: "narrative_summary", value: "ok", confidence: 1 }] as never, summary: "s" }) });
    const ev = await a.evaluate({ subject: "pins-18e", trigger: "manual" } as never, { actor: AGENT });
    expect(ev.ok && ev.authority).toBe("advisory_data");
    expect(ev.ok && ev.executionAuthorized).toBe(false);
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "pins-event-18e", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      []
    );
    if (out.ok) {
      expect(out.event.authority).toBe("advisory_data");
      expect(out.event.executionAuthorized).toBe(false);
      expect(validateEvaluationEvent(out.event)).toBeNull();
    }
    const rej = new SemantiqRejectionLog().record({
      rejectedAtEpochMs: T0,
      rejectedBy: "adapter",
      denyReason: "instruction_smuggling",
      patterns: [],
      findings: [],
      payload: { x: 1 },
    });
    expect(rej.ok && rej.record.authority).toBe("advisory_data");
    expect(rej.ok && rej.record.executionAuthorized).toBe(false);
  });

  it("18E-A3 the full 12-deny surface of the adapter domain is behaviorally reachable (6 semantiq deny reasons)", async () => {
    const mk = (o: Parameters<typeof buildSemantiqAdapter>[0]) => buildSemantiqAdapter(o);
    const seen = new Set<string>();
    // adapter_disabled
    const d1 = await mk({ ledgerPort: emptyPort(), engine: null }).evaluate({ subject: "a", trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d1)) seen.add(d1.denyReason);
    // adapter_unconfigured
    const d2 = await mk({}).evaluate({ subject: "a", trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d2)) seen.add(d2.denyReason);
    // adapter_degraded (throwing engine)
    const d3 = await mk({ ledgerPort: emptyPort(), engine: () => { throw new Error("x"); } }).evaluate({ subject: "a", trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d3)) seen.add(d3.denyReason);
    // invalid_request
    const d4 = await mk({ ledgerPort: emptyPort(), engine: () => ({ ok: true, claims: [], summary: "s" }) }).evaluate({ subject: "", trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d4)) seen.add(d4.denyReason);
    // oversized_request
    const d5 = await mk({ ledgerPort: emptyPort(), engine: () => ({ ok: true, claims: [], summary: "s" }) }).evaluate({ subject: "x".repeat(257), trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d5)) seen.add(d5.denyReason);
    // ledger_unavailable (denying port)
    const d6 = await mk({ ledgerPort: { readEvents: () => ({ ok: false, denyReason: "ledger_unavailable", reason: "no ledger" }) }, engine: () => ({ ok: true, claims: [], summary: "s" }) }).evaluate({ subject: "a", trigger: "manual" } as never, { actor: AGENT });
    if (isDenial(d6)) seen.add(d6.denyReason);
    expect(
      [...seen].sort(),
    ).toEqual(["adapter_degraded", "adapter_disabled", "adapter_unconfigured", "invalid_request", "ledger_unavailable", "oversized_request"]);
  });

  it("18E-A4 evaluation output cannot flip a policy decision (Day-1 deny re-proven post-freeze)", async () => {
    const { DenyByDefaultPolicyEngine } = await import("@menog/policy");
    const engine = new DenyByDefaultPolicyEngine();
    // An honest advisory proposal (no grant-demand phrasing) IS deliverable;
    // the boundary only refuses instruction-bearing payloads (18D-I3). The
    // policy engine must still deny regardless of what was delivered.
    const a = buildSemantiqAdapter({ ledgerPort: emptyPort(), engine: () => ({ ok: true, claims: [{ kind: "recommendation_proposal", value: "propose raising the retry threshold", confidence: 0.99 }] as never, summary: "proposal for human review" }) });
    const r = await a.evaluate({ subject: "flip-attempt-18e", trigger: "manual" } as never, { actor: AGENT });
    expect(r.ok).toBe(true); // advisory data delivered
    for (const verb of ["workspace.write", "semantiq.evaluate", "evaluation.record"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-18e",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("18E-A5 the record store stays insert-once and fail-closed (provenance immutable post-freeze)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "once-18e", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      []
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      const second = store.persist(out.event);
      expect(second.ok).toBe(false);
      if (!second.ok) expect(second.denyReason).toBe("duplicate_record");
      expect(store.length).toBe(2); // request + denied (missing evaluator)
    }
  });

  it("18E-A6 deterministic behavior: identical inputs produce identical artifacts across stores/exports", () => {
    const build = () => {
      const store = new SemantiqEvaluationRecordStore();
      const out = requestEvaluation(
        { subject: "det-18e", trigger: "cli", atEpochMs: T0, context: { actor: AGENT } },
        store,
        []
      );
      const exp = exportEvidence({ records: store.read().records, exporterId: "menog-18e", exporterVersion: "0.0.1", exportedAtEpochMs: T0 });
      return { kind: out.ok ? out.kind : "?", hash: exp.ok ? exp.package.packageHash : "?" };
    };
    expect(build()).toEqual(build());
    // Import side is deterministic too (same package ⇒ same verdict).
    const exp = exportEvidence({ records: [], events: [], exporterId: "menog-18e", exporterVersion: "0.0.1", exportedAtEpochMs: T0 });
    expect(exp.ok).toBe(true);
    if (exp.ok) {
      const i1 = importEvidence(JSON.parse(JSON.stringify(exp.package)), {});
      const i2 = importEvidence(JSON.parse(JSON.stringify(exp.package)), {});
      expect(i1.ok).toBe(i2.ok);
    }
  });
});

// ---------------------------------------------------------------------------
// 18E-V — Governance invariants frozen in Phase-18 artifacts (15E/16E/17E
// pattern), including the adapter-off verification requirement.
// ---------------------------------------------------------------------------

describe("18E-V — governance invariants frozen in Phase-18 artifacts", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];
  const DOCS_CARRYING_PR_BLOCK = [
    "docs/release/PROMPT_18A_REPORT.md",
    "docs/release/PROMPT_18B_REPORT.md",
    "docs/release/PROMPT_18C_REPORT.md",
    "docs/release/PROMPT_18D_REPORT.md",
    "docs/release/PROMPT_18E_REPORT.md",
    "docs/release/PHASE_18_FREEZE.md",
  ];

  it("18E-V1 PR-01..PR-05 disposition block is verbatim in all six Phase-18 artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      for (const line of PR_BLOCK_LINES) {
        expect(content.includes(line), doc + " missing " + line).toBe(true);
      }
    }
  });

  it("18E-V2 authorization-not-granted lines are unchanged in all Phase-18 artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUSH AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED"), doc).toBe(true);
    }
  });

  it("18E-V3 no Phase-20 isolation primitives exist in any semantiq source file", () => {
    const srcDir = path.resolve(process.cwd(), "packages/semantiq/src");
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of readdirDirs(srcDir)) {
      if (!f.endsWith(".ts")) continue;
      expect(forbidden.test(readFileSync(path.join(srcDir, f), "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("18E-V4 dependency/lockfile discipline: zero external deps, lockfile byte-count documented in the freeze", () => {
    const pkg = JSON.parse(readDoc("packages/semantiq/package.json")) as { dependencies?: Record<string, string> };
    for (const d of Object.keys(pkg.dependencies ?? {})) {
      expect(d.startsWith("@menog/"), "non-workspace dependency: " + d).toBe(true);
    }
    const freeze = readDoc("docs/release/PHASE_18_FREEZE.md");
    expect(freeze.includes("36,672")).toBe(true);
  });

  it("18E-V5 ADR-0007 remains the governing decision (optional post-hoc evaluator, not pipeline authority)", () => {
    const adr = readDoc("docs/adr/ADR-0007-semantIQ-optional-adapter.md");
    expect(adr.includes("OPTIONAL")).toBe(true);
    expect(adr.includes("Adapter Pattern")).toBe(true);
    const freeze = readDoc("docs/release/PHASE_18_FREEZE.md");
    expect(freeze.includes("never has a direct arrow into Policy, Runtime, or Commit")).toBe(true);
  });

  it("18E-V6 multi-agent preparation is documented as entry requirements, not implemented capability", () => {
    const freeze = readDoc("docs/release/PHASE_18_FREEZE.md");
    expect(freeze.includes("multi-agent")).toBe(true);
    expect(freeze.toLowerCase().includes("roadmap only")).toBe(true);
    expect(freeze.includes("Phase-19 entry requirements")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Helpers (dir listing without importing node:fs types beyond basics).
// ---------------------------------------------------------------------------

function readdirDirs(dir: string): string[] {
  return readdirSync(dir);
}
