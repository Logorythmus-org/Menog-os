import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import type { MenogEventInput } from "@menog/core";
import type { Actor } from "@menog/core";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  SEMANTIQ_SCHEMA_VERSION,
  SEMANTIQ_STAGES,
  KNOWN_SEMANTIQ_TRIGGERS,
  KNOWN_SEMANTIQ_CLAIM_KINDS,
  KNOWN_SEMANTIQ_DENY_REASONS,
  isSemantiqDenyReason,
  validateEvaluationRequest,
  normalizeClaim,
  SEMANTIQ_MAX_SUBJECT_CHARS,
  SEMANTIQ_MAX_CLAIMS,
  SEMANTIQ_MAX_CLAIM_VALUE_CHARS,
  SEMANTIQ_MAX_EVENTS_PER_EVALUATION,
  buildDisabledAdapterState,
  buildSemantiqAdapter,
  denyByDefaultSemantiqEmitter,
  type SemantiqEngine,
  type SemantiqEventView,
  type SemantiqLedgerPort,
} from "@menog/semantiq";

const AGENT: Actor = { type: "agent", id: "agent-18a" };

interface TestRequest {
  readonly subject: string;
  readonly trigger: "manual" | "scheduled" | "cli" | "event_hook" | "unknown";
  readonly eventTypes?: readonly ("algorithm_recommended" | "algorithm_denied" | "verb_executed" | "evaluation_requested")[];
  readonly note?: string;
}

function req(overrides: Partial<TestRequest> = {}): TestRequest {
  return { subject: "eval-18a", trigger: "manual", ...overrides };
}

function port(events: readonly unknown[] = []): SemantiqLedgerPort {
  return {
    readEvents: ({ limit }: { readonly limit: number }) => ({
      ok: true as const,
      events: events.slice(0, limit) as readonly SemantiqEventView[],
    }),
  };
}

function denyingPort(): SemantiqLedgerPort {
  return {
    readEvents: () => ({ ok: false, denyReason: "ledger_unavailable", reason: "no ledger attached" }),
  };
}

interface OkEngineOptions {
  claims?: readonly { kind: string; value: string; confidence: number }[];
  summary?: string;
}

function okEngine(opts: OkEngineOptions = {}): SemantiqEngine {
  return () => ({
    ok: true,
    claims: (opts.claims ?? [{ kind: "narrative_summary", value: "ran fine", confidence: 0.9 }]) as never,
    summary: opts.summary ?? "one claim derived from recent events",
  });
}

function view(eventId: string): SemantiqEventView {
  return {
    eventId,
    eventType: "verb_executed",
    actor: { type: "runtime", id: "runtime-18a" },
    timestamp: "2026-09-26T00:00:00.000Z",
    verb: "inspect",
  };
}

function isDenial(
  r: { ok: boolean }
): r is { ok: false; denyReason: string; reason: string; stage: string; schemaVersion: string } {
  return r.ok === false;
}

// ---------------------------------------------------------------------------
// 18A-1 — Adapter-off behavior: disabled/unconfigured/degraded are complete,
// honest, machine-readable states. Menog works fully without the adapter.
// ---------------------------------------------------------------------------

describe("18A-1 — adapter-off behavior (machine-readable off states)", () => {
  it("18A-O1 disabled adapter (no engine) denies with adapter_disabled; state matches the explicit off-state constructor", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: null });
    expect(a.state).toBe("disabled");
    const r = await a.evaluate(req(), { actor: AGENT });
    const r2 = await buildDisabledAdapterState("disabled").evaluate(req(), { actor: AGENT });
    expect(r.ok).toBe(false);
    expect(isDenial(r) && r.denyReason).toBe("adapter_disabled");
    expect(isDenial(r2) && r2.denyReason).toBe(isDenial(r) ? r.denyReason : "");
  });

  it("18A-O2 unconfigured adapter (no ledger port) denies with adapter_unconfigured", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: null, engine: okEngine() });
    expect(a.state).toBe("unconfigured");
    const r = await a.evaluate(req(), { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("adapter_unconfigured");
  });

  it("18A-O3 the disabled-state surface is itself a valid contract (explicit constructor)", async () => {
    for (const state of ["disabled", "unconfigured", "degraded"] as const) {
      const a = buildDisabledAdapterState(state);
      expect(a.state).toBe(state);
      const r = await a.evaluate(req(), { actor: AGENT });
      expect(r.ok).toBe(false);
      expect(isDenial(r) && r.denyReason).toBe(
        state === "unconfigured"
          ? "adapter_unconfigured"
          : state === "degraded"
            ? "adapter_degraded"
            : "adapter_disabled"
      );
    }
  });

  it("18A-O4 off-state denials stay honest for oversized requests (validate first, deny second)", async () => {
    const a = buildDisabledAdapterState("disabled");
    const r = await a.evaluate(req({ subject: "x".repeat(SEMANTIQ_MAX_SUBJECT_CHARS + 1) }), { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("oversized_request");
  });

  it("18A-O5 adapter identities: ids/versions/descriptions are observable metadata", () => {
    const off = buildDisabledAdapterState("disabled");
    expect(off.id).toBe("semantiq.disabled");
    expect(off.version).toBe(SEMANTIQ_SCHEMA_VERSION);
    expect(typeof off.description).toBe("string");
    const wrapped = buildSemantiqAdapter({ id: "semantiq.custom", version: "1.2.3", ledgerPort: null });
    expect(wrapped.id).toBe("semantiq.custom");
    expect(wrapped.version).toBe("1.2.3");
  });

  it("18A-O6 disabled adapter performs no ledger work (no port touched when off)", async () => {
    let portTouched = false;
    const a = buildSemantiqAdapter({
      ledgerPort: {
        readEvents: () => {
          portTouched = true;
          return { ok: true, events: [] };
        },
      },
      engine: null,
    });
    await a.evaluate(req(), { actor: AGENT });
    expect(portTouched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 18A-2 — Schema conversion + version metadata: bounded normalization,
// closed unions, pinned version.
// ---------------------------------------------------------------------------

describe("18A-2 — schema conversion & version metadata", () => {
  it("18A-C1 schema version is pinned at menog-semantiq/v0", () => {
    expect(SEMANTIQ_SCHEMA_VERSION).toBe("menog-semantiq/v0");
  });

  it("18A-C2 lifecycle stages, triggers, claim kinds, and deny reasons are closed frozen unions", () => {
    expect(SEMANTIQ_STAGES).toEqual(["requested", "computed", "delivered"]);
    expect(KNOWN_SEMANTIQ_TRIGGERS).toEqual(["manual", "scheduled", "cli", "event_hook", "unknown"]);
    expect(KNOWN_SEMANTIQ_CLAIM_KINDS).toEqual([
      "goal_achievement",
      "metric_delta",
      "narrative_summary",
      "regression_indicator",
      "recommendation_proposal",
    ]);
    // 18B delta (documented in PROMPT_18B_REPORT.md §3): the deny-reason
    // union gained `conflict_unresolved` for the evaluation event model.
    expect(KNOWN_SEMANTIQ_DENY_REASONS).toEqual([
      "adapter_disabled",
      "adapter_unconfigured",
      "adapter_degraded",
      "invalid_request",
      "ledger_unavailable",
      "oversized_request",
      "conflict_unresolved",
    ]);
    for (const union of [SEMANTIQ_STAGES, KNOWN_SEMANTIQ_TRIGGERS, KNOWN_SEMANTIQ_CLAIM_KINDS, KNOWN_SEMANTIQ_DENY_REASONS]) {
      expect(Object.isFrozen(union)).toBe(true);
    }
  });

  it("18A-C3 request validation: shape, trigger membership, eventTypes membership, note type", () => {
    expect(validateEvaluationRequest(req())).toBeNull();
    expect(validateEvaluationRequest(null as never)).not.toBeNull();
    expect(validateEvaluationRequest(req({ subject: "" }))).not.toBeNull();
    expect(validateEvaluationRequest(req({ trigger: "cron" as never }))).not.toBeNull();
    expect(validateEvaluationRequest(req({ eventTypes: ["verb_executed"] }))).toBeNull();
    expect(validateEvaluationRequest(req({ eventTypes: ["policy.override"] as never }))).not.toBeNull();
    expect(validateEvaluationRequest(req({ note: 42 as never }))).not.toBeNull();
    expect(isSemantiqDenyReason("adapter_disabled")).toBe(true);
    expect(isSemantiqDenyReason("policy_override")).toBe(false);
  });

  it("18A-C4 oversized requests deny with oversized_request (distinct machine-readable state)", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: okEngine() });
    const big = req({ subject: "x".repeat(SEMANTIQ_MAX_SUBJECT_CHARS + 1) });
    const r = await a.evaluate(big as never, { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("oversized_request");
  });

  it("18A-C5 event views are normalized: malformed events dropped, verbs/policies bounded", async () => {
    const seen: SemantiqEventView[] = [];
    const a = buildSemantiqAdapter({
      ledgerPort: port([
        view("ok-1"),
        null,
        42,
        { eventId: "x", eventType: "", timestamp: "t", actor: { type: "runtime", id: "r" } },
        { eventId: "ok-2", eventType: "algorithm_recommended", timestamp: "t", actor: { type: "tool", id: "t" }, verb: "v".repeat(99), policyDecision: "deny" },
      ]),
      engine: (v) => {
        seen.push(...v.events);
        return { ok: true, claims: [{ kind: "narrative_summary", value: "c", confidence: 0.5 }] as never, summary: "s" };
      },
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    expect(seen).toHaveLength(2);
    expect(seen[0]!.eventId).toBe("ok-1");
    expect(seen[1]!.verb).toHaveLength(64);
    expect(seen[1]!.policyDecision).toBe("deny");
  });

  it("18A-C6 the event-read bound is enforced (adapter cannot be forced past SEMANTIQ_MAX_EVENTS_PER_EVALUATION)", async () => {
    const many: unknown[] = [];
    for (let i = 0; i < SEMANTIQ_MAX_EVENTS_PER_EVALUATION + 50; i++) many.push(view("e" + String(i)));
    const a = buildSemantiqAdapter({ ledgerPort: port(many), engine: okEngine() });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.derivedFrom.length).toBeLessThanOrEqual(SEMANTIQ_MAX_EVENTS_PER_EVALUATION);
  });

  it("18A-C7 claim normalization: over-limit claims bounded, bad ones dropped", async () => {
    const claims = [
      { kind: "narrative_summary", value: "v".repeat(SEMANTIQ_MAX_CLAIM_VALUE_CHARS + 5), confidence: 0.5 },
      { kind: "unknown_kind", value: "v", confidence: 0.5 },
      { kind: "metric_delta", value: "", confidence: 0.5 },
      { kind: "metric_delta", value: "v", confidence: Number.NaN },
      null,
      "not-an-object",
    ];
    const a = buildSemantiqAdapter({
      ledgerPort: port([]),
      engine: () => ({ ok: true, claims: claims as never, summary: "s" }),
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.claims).toHaveLength(1);
      expect(r.claims[0]!.value).toHaveLength(SEMANTIQ_MAX_CLAIM_VALUE_CHARS);
    }
    expect(normalizeClaim({ kind: "narrative_summary", value: "x", confidence: 2 })).toEqual({
      kind: "narrative_summary",
      value: "x",
      confidence: 1,
    });
  });

  it("18A-C8 version metadata flows through every result (schema, adapter id/version)", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: okEngine(), id: "semantiq.v", version: "9.9.9" });
    const ok = await a.evaluate(req() as never, { actor: AGENT });
    expect(ok.ok && ok.schemaVersion).toBe(SEMANTIQ_SCHEMA_VERSION);
    expect(ok.ok && ok.adapterId).toBe("semantiq.v");
    expect(ok.ok && ok.adapterVersion).toBe("9.9.9");
    const off = await buildSemantiqAdapter({ ledgerPort: null }).evaluate(req() as never, { actor: AGENT });
    expect(isDenial(off) && off.schemaVersion).toBe(SEMANTIQ_SCHEMA_VERSION);
  });
});

// ---------------------------------------------------------------------------
// 18A-3 — Failure isolation & integrity: engine throws, port throws, port
// denies, in-flight mutation, deterministic ids.
// ---------------------------------------------------------------------------

describe("18A-3 — failure isolation & integrity gate", () => {
  it("18A-I1 a throwing engine degrades to adapter_degraded; the error never propagates", async () => {
    const a = buildSemantiqAdapter({
      ledgerPort: port([]),
      engine: () => {
        throw new Error("boom");
      },
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(false);
    expect(isDenial(r) && r.denyReason).toBe("adapter_degraded");
  });

  it("18A-I2 a hostile error object carrying an authority field stays inert (isolation)", async () => {
    class PolicyLikeError extends Error {
      readonly policyDecision = "allow";
      readonly executionAuthorized = true;
      readonly grants = ["workspace:write"];
      constructor() {
        super("hostile error payload");
      }
    }
    const a = buildSemantiqAdapter({
      ledgerPort: port([]),
      engine: () => {
        throw new PolicyLikeError();
      },
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("adapter_degraded");
    const raw = JSON.stringify(r);
    expect(raw).not.toContain("workspace:write");
    expect(raw).not.toContain("hostile error payload");
  });

  it("18A-I3 a throwing ledger port degrades to ledger_unavailable (machine-readable)", async () => {
    const a = buildSemantiqAdapter({
      ledgerPort: {
        readEvents: () => {
          throw new Error("disk on fire");
        },
      },
      engine: okEngine(),
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("ledger_unavailable");
  });

  it("18A-I4 a denying ledger port propagates its machine-readable denial", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: denyingPort(), engine: okEngine() });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("ledger_unavailable");
  });

  it("18A-I5 an engine payload mutated between compute and delivery refuses delivery (integrity gate)", async () => {
    let reads = 0;
    const mutatingClaims = {
      get length() {
        reads++;
        return reads === 1 ? 1 : 2;
      },
      0: { kind: "narrative_summary", value: "one", confidence: 0.5 },
      1: { kind: "metric_delta", value: "two", confidence: 0.5 },
    };
    const engine = (): { ok: true; claims: typeof mutatingClaims; summary: string } => ({
      ok: true,
      claims: mutatingClaims,
      summary: "s",
    });
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: engine as unknown as SemantiqEngine });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r) && r.denyReason).toBe("adapter_degraded");
  });

  it("18A-I6 the deny stage is machine-readable across every failure path (no silent guesses)", async () => {
    const cases: SemantiqEngine[] = [
      () => {
        throw new Error("a");
      },
      () => ({ ok: false, denyReason: "bogus" as never, reason: "b" }),
      () => ({ ok: true, claims: [{ kind: "bogus", value: "v", confidence: 0.5 }] as never, summary: "c" }),
      () => ({ ok: true, claims: [] as never, summary: 42 as never }),
    ];
    let idx = 0;
    for (const engine of cases) {
      const a = buildSemantiqAdapter({ ledgerPort: port([]), engine });
      const r = await a.evaluate(req() as never, { actor: AGENT });
      expect(r.ok, "case " + String(idx)).toBe(false);
      expect(isDenial(r) && isSemantiqDenyReason(r.denyReason), "case " + String(idx)).toBe(true);
      idx++;
    }
  });

  it("18A-I7 over-limit output is bounded, not denied (bounding ≠ tampering)", async () => {
    const many: object[] = [];
    for (let i = 0; i < SEMANTIQ_MAX_CLAIMS + 10; i++) {
      many.push({ kind: "narrative_summary", value: "c" + String(i), confidence: 0.5 });
    }
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: () => ({ ok: true, claims: many as never, summary: "s" }) });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.claims).toHaveLength(SEMANTIQ_MAX_CLAIMS);
  });

  it("18A-I8 the adapter surface exposes no execution/commit/policy methods", () => {
    const surfaces = [
      buildDisabledAdapterState("disabled"),
      buildSemantiqAdapter({ ledgerPort: port([]), engine: okEngine() }),
    ];
    const forbidden = ["exec", "spawn", "commit", "authorize", "grant", "writeFile", "fetch", "evaluatePolicy"];
    for (const s of surfaces) {
      const names = new Set<string>();
      let proto: object | null = Object.getPrototypeOf(s);
      while (proto && proto !== Object.prototype) {
        for (const n of Object.getOwnPropertyNames(proto)) names.add(n);
        proto = Object.getPrototypeOf(proto);
      }
      for (const f of forbidden) expect(names.has(f)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 18A-4 — Authority separation: evaluation output can never authorize,
// never flip policy, and never shadow ledger events.
// ---------------------------------------------------------------------------

describe("18A-4 — authority separation (evaluator is never authority)", () => {
  it("18A-A1 authority pins are re-stamped on every delivered evaluation", async () => {
    const a = buildSemantiqAdapter({ ledgerPort: port([]), engine: okEngine() });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.authority).toBe("advisory_data");
      expect(r.executionAuthorized).toBe(false);
      expect(r.stage).toBe("computed");
      expect(Object.isFrozen(r)).toBe(true);
      expect(Object.isFrozen(r.claims)).toBe(true);
    }
  });

  it("18A-A2 engine output attempting to carry authority fields is dropped claim-by-claim", async () => {
    const a = buildSemantiqAdapter({
      ledgerPort: port([]),
      engine: () =>
        ({
          ok: true,
          claims: [
            { kind: "narrative_summary", value: "honest", confidence: 0.5 },
            { kind: "narrative_summary", value: "smuggled", confidence: 0.5, executionAuthorized: true },
            { kind: "narrative_summary", value: "smuggled2", confidence: 0.5, grants: ["workspace:write"] },
            { kind: "narrative_summary", value: "smuggled3", confidence: 0.5, policyDecision: "allow" },
          ],
          summary: "s",
        }) as never,
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.claims).toHaveLength(1);
      expect(r.claims[0]!.value).toBe("honest");
    }
  });

  it("18A-A3 engine-reported deny reasons are honored only within the closed union", async () => {
    const denyEngine = (reason: string): SemantiqEngine =>
      (() => ({ ok: false, denyReason: reason, reason: "engine says no" })) as unknown as SemantiqEngine;
    const a1 = buildSemantiqAdapter({ ledgerPort: port([]), engine: denyEngine("ledger_unavailable") });
    const r1 = await a1.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r1) && r1.denyReason).toBe("ledger_unavailable");
    const a2 = buildSemantiqAdapter({ ledgerPort: port([]), engine: denyEngine("policy_override") });
    const r2 = await a2.evaluate(req() as never, { actor: AGENT });
    expect(isDenial(r2) && r2.denyReason).toBe("adapter_degraded");
  });

  it("18A-A4 a delivered evaluation serializes with authority pins intact (no smuggled authority keys)", async () => {
    const a = buildSemantiqAdapter({
      ledgerPort: port([]),
      engine: () =>
        ({
          ok: true,
          claims: [{ kind: "recommendation_proposal", value: "switch strategy", confidence: 0.99 }],
          summary: "proposes changes",
        }) as never,
    });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const json = JSON.stringify(r);
      expect(json.includes("executionAuthorized\":true")).toBe(false);
      expect(json.includes("workspace:write")).toBe(false);
      expect(r.authority).toBe("advisory_data");
    }
  });

  it("18A-A5 the deny-by-default emitter refuses non-evaluation event types even under engine influence", async () => {
    const appended: string[] = [];
    const emitter = denyByDefaultSemantiqEmitter((input) => {
      appended.push(input.eventType);
      return { ok: true, eventId: "evt-18a-1" };
    });
    expect(emitter.append({ eventType: "verb_executed", policyDecision: "allow", actor: AGENT, inputSummary: {}, resultSummary: {} }).ok).toBe(false);
    expect(emitter.append({ eventType: "policy.updated", policyDecision: "allow", actor: AGENT, inputSummary: {}, resultSummary: {} }).ok).toBe(false);
    expect(emitter.append({ eventType: "evaluation_delivered", policyDecision: "not_applicable", actor: AGENT, inputSummary: {}, resultSummary: {} }).ok).toBe(true);
    expect(appended).toEqual(["evaluation_delivered"]);
    expect(denyByDefaultSemantiqEmitter(() => ({ ok: true })).append({ eventType: "evaluation_requested", policyDecision: "not_applicable", actor: AGENT, inputSummary: {}, resultSummary: {} }).ok).toBe(true);
  });

  it("18A-A6 DenyByDefaultPolicyEngine Day-1 deny is unchanged for SemantIQ-ish verbs", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["semantiq.evaluate", "evaluation.record", "evaluation.read"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-18a",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });
});

// ---------------------------------------------------------------------------
// 18A-5 — No-runtime-dependency: the adapter is optional end-to-end.
// ---------------------------------------------------------------------------

describe("18A-5 — no-runtime-dependency (optional by construction)", () => {
  it("18A-D1 every workspace package except @menog/semantiq has zero semantiq dependency", () => {
    const root = process.cwd();
    const checked: string[] = [];
    for (const dir of [path.join(root, "packages"), path.join(root, "apps")]) {
      if (!existsSync(dir)) continue;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const pkgPath = path.join(dir, entry.name, "package.json");
        if (!existsSync(pkgPath)) continue;
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
          name?: string;
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
          peerDependencies?: Record<string, string>;
        };
        const all = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
        if (pkg.name === "@menog/semantiq") continue;
        for (const dep of Object.keys(all)) {
          expect(dep.includes("semantiq"), (pkg.name ?? entry.name) + " depends on " + dep).toBe(false);
        }
        checked.push(pkg.name ?? entry.name);
      }
    }
    expect(checked).toContain("@menog/algorithms");
    expect(checked).toContain("@menog/cli");
    expect(checked.length).toBeGreaterThanOrEqual(10);
  });

  it("18A-D2 @menog/semantiq depends only on @menog/core (workspace links only)", () => {
    const pkg = JSON.parse(
      readFileSync(path.join(process.cwd(), "packages", "semantiq", "package.json"), "utf8")
    ) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps).toEqual(["@menog/core"]);
    expect(pkg.devDependencies ?? {}).toEqual({});
  });

  it("18A-D3 the CLI runner does not import or reference the semantiq adapter (adapter-off Day-1 path)", () => {
    const runnerPath = path.join(process.cwd(), "apps", "cli", "src", "runner.ts");
    expect(existsSync(runnerPath)).toBe(true);
    const src = readFileSync(runnerPath, "utf8");
    expect(/semantiq/i.test(src)).toBe(false);
  });

  it("18A-D4 the full evaluation path works with no ledger port, no engine, and no emitter (pure off state)", async () => {
    const a = buildSemantiqAdapter({});
    expect(a.state).toBe("unconfigured");
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(false);
    expect(isDenial(r) && r.schemaVersion).toBe(SEMANTIQ_SCHEMA_VERSION);
  });
});

// ---------------------------------------------------------------------------
// 18A-6 — Integration: the real AppendOnlyLedger satisfies the port
// unchanged; deny-by-default writes; no event shadowing.
// ---------------------------------------------------------------------------

describe("18A-6 — ledger integration (read-only, deny-by-default, no shadowing)", () => {
  function ledgerPortOf(ledger: AppendOnlyLedger): SemantiqLedgerPort {
    return {
      readEvents: ({ limit }) => {
        const evs = ledger.events();
        const tail = evs.slice(Math.max(0, evs.length - limit));
        return { ok: true, events: tail as unknown as SemantiqEventView[] };
      },
    };
  }

  function appendEval(ledger: AppendOnlyLedger, id: string, type: string): void {
    const r = ledger.append({
      eventId: id,
      timestamp: new Date(1_820_000_000_000).toISOString(),
      eventType: type,
      actor: { type: "runtime", id: "runtime-18a" },
      workspaceId: "ws-18a",
      verb: "inspect",
      policyDecision: "allow",
    } satisfies MenogEventInput);
    expect(r.ok).toBe(true);
  }

  it("18A-L1 the real AppendOnlyLedger satisfies the port unchanged; evaluation derives from real events", async () => {
    const ledger = AppendOnlyLedger.inMemory();
    appendEval(ledger, "evt-18a-l1", "verb_executed");
    appendEval(ledger, "evt-18a-l2", "algorithm_recommended");
    const a = buildSemantiqAdapter({ ledgerPort: ledgerPortOf(ledger), engine: okEngine() });
    const r = await a.evaluate(req() as never, { actor: AGENT, workspaceId: "ws-18a" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.derivedFrom).toEqual(["evt-18a-l1", "evt-18a-l2"]);
  });

  it("18A-L2 an evaluation via the deny-by-default emitter appends ONLY an evaluation_delivered record", async () => {
    const ledger = AppendOnlyLedger.inMemory();
    appendEval(ledger, "evt-18a-l3", "verb_executed");
    const before = ledger.length;
    let emitted = 0;
    const emitter = denyByDefaultSemantiqEmitter((input) => {
      emitted++;
      const r = ledger.append({
        eventId: "evt-18a-eval-" + String(emitted),
        timestamp: new Date(1_820_000_000_001).toISOString(),
        eventType: input.eventType,
        actor: { type: "runtime", id: "runtime-18a" },
        workspaceId: "ws-18a",
        policyDecision: input.policyDecision,
      } satisfies MenogEventInput);
      return r.ok ? { ok: true, eventId: "evt-18a-eval-" + String(emitted) } : { ok: false };
    });
    const a = buildSemantiqAdapter({ ledgerPort: ledgerPortOf(ledger), engine: okEngine(), ledger: emitter });
    const r = await a.evaluate(req() as never, { actor: AGENT, workspaceId: "ws-18a" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.evaluationEventId).toBe("evt-18a-eval-1");
    expect(ledger.length).toBe(before + 1);
    const evs = ledger.events();
    expect(evs[evs.length - 1]!.eventType).toBe("evaluation_delivered");
  });

  it("18A-L3 evaluations never rewrite or shadow ledger events (append-only preserved, chain intact)", async () => {
    const ledger = AppendOnlyLedger.inMemory();
    appendEval(ledger, "evt-18a-l4", "verb_executed");
    const snapshot = JSON.stringify(ledger.events());
    const a = buildSemantiqAdapter({ ledgerPort: ledgerPortOf(ledger), engine: okEngine() });
    await a.evaluate(req() as never, { actor: AGENT });
    expect(JSON.stringify(ledger.events())).toBe(snapshot);
    expect(ledger.length).toBe(1);
    const v = ledger.verify();
    expect(v.ok).toBe(true);
  });

  it("18A-L4 an empty ledger view is a valid, non-denial observation", async () => {
    const ledger = AppendOnlyLedger.inMemory();
    const a = buildSemantiqAdapter({ ledgerPort: ledgerPortOf(ledger), engine: okEngine() });
    const r = await a.evaluate(req() as never, { actor: AGENT });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.derivedFrom).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 18A-7 — Governance invariants (15E/16E/17E pattern).
// ---------------------------------------------------------------------------

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

describe("18A-7 — governance invariants", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];

  it("18A-V1 PR-01..PR-05 disposition block is verbatim in the 18A report", () => {
    const content = readDoc("docs/release/PROMPT_18A_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(content.includes(line), "missing " + line).toBe(true);
    }
  });

  it("18A-V2 authorization-not-granted lines are unchanged in the 18A report", () => {
    const content = readDoc("docs/release/PROMPT_18A_REPORT.md").replace(/\s+/g, " ");
    expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("18A-V3 no Phase-20 isolation primitives exist in the semantiq package source", () => {
    const srcRoot = path.resolve(process.cwd(), "packages/semantiq/src");
    const files = ["adapter.ts", "rules.ts", "types.ts", "index.ts"];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = path.join(srcRoot, f);
      expect(existsSync(full), "semantiq source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("18A-V4 SemantIQ stays documented as the optional external evaluator (ADR-0007 unchanged)", () => {
    const adr = readDoc("docs/adr/ADR-0007-semantIQ-optional-adapter.md");
    expect(adr.includes("OPTIONAL")).toBe(true);
    expect(adr.includes("Adapter Pattern")).toBe(true);
    const report = readDoc("docs/release/PROMPT_18A_REPORT.md");
    expect(report.includes("OPTIONAL_EXTERNAL")).toBe(true);
  });

  it("18A-V5 the 18A report records the adapter as optional/disabled-by-default with no network (no overclaim)", () => {
    const report = readDoc("docs/release/PROMPT_18A_REPORT.md");
    expect(report.includes("disabled by default")).toBe(true);
    expect(report.includes("no network")).toBe(true);
  });
});
