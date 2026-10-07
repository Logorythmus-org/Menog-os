import { createHash } from "node:crypto";
import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type {
  SemantiqAdapterContract,
  SemantiqAdapterState,
  SemantiqClaim,
  SemantiqDenial,
  SemantiqDenyReason,
  SemantiqEngine,
  SemantiqEvaluation,
  SemantiqEvaluationRequest,
  SemantiqLedgerEmitter,
  SemantiqLedgerPort,
  SemantiqLifecycleRecord,
  SemantiqEventView,
  SemantiqResult,
  SemantiqRuntimeContext,
} from "./types.js";
import {
  SEMANTIQ_MAX_CLAIMS,
  SEMANTIQ_MAX_DERIVED_FROM,
  SEMANTIQ_MAX_EVENTS_PER_EVALUATION,
  SEMANTIQ_MAX_SUMMARY_CHARS,
  isSemantiqDenyReason,
  normalizeClaim,
  normalizeEventView,
  semantiqDeny,
  validateEvaluationRequest,
} from "./rules.js";
import {
  scanHostileText,
  screenEvaluationRequest,
  type SemantiqFinding,
} from "./boundary.js";

/**
 * Phase 18A — the contract layer that turns any (untrusted) evaluation
 * engine into a `SemantiqAdapterContract`.
 *
 * Design (ADR-0007 + 18A):
 *  - DISABLED BY DEFAULT: the disabled adapter is a complete, honest,
 *    machine-readable surface — every evaluation denies
 *    `adapter_disabled`/`adapter_unconfigured`/`adapter_degraded`. Menog
 *    works fully without any engine; nothing else in the workspace imports
 *    this package.
 *  - FAILURE ISOLATION: every engine invocation runs inside try/catch. Any
 *    throw (including Error subclasses carrying policy-like fields) becomes
 *    the machine-readable `adapter_degraded` denial — the error never
 *    propagates as an execution failure and never fails open.
 *  - INTEGRITY GATE: the engine's returned claims/summary are snapshotted
 *    once, and the raw output is re-read after normalization. Any
 *    difference between the two reads (a hostile engine mutating its
 *    payload between compute and delivery, e.g. via getters) denies with
 *    `adapter_degraded` and delivers nothing. Legitimate over-limit output
 *    is BOUNDED (dropped), not denied — bounding and tampering are distinct.
 *  - AUTHORITY SEPARATION: `authority: "advisory_data"` and
 *    `executionAuthorized: false` are re-stamped by this layer regardless
 *    of what the engine claims; an engine payload carrying an authority
 *    field is dropped claim-by-claim, and an engine-reported deny reason is
 *    honored only when it is a known machine-readable reason.
 *  - OBSERVABLE, WRITABLE-BY-NOBODY: the ONLY ledger write available to the
 *    adapter path is a deny-by-default emitter: the caller wraps their
 *    ledger, and `append` returns { ok:false } unless the event type is
 *    explicitly allowed. Even a hostile engine cannot cause the adapter
 *    layer to append an unauthorized event.
 */

const ALLOWED_EVALUATION_EVENT_TYPES: readonly string[] = Object.freeze([
  "evaluation_requested",
  "evaluation_delivered",
  "evaluation_denied",
  // 18B: typed evaluation RESULT records joined the observable surface.
  "evaluation_result",
  // 18D: rejected-evaluator-instruction evidence (deny-by-default emitter).
  "evaluation_rejected",
]);

/**
 * Deny-by-default ledger emitter factory: the CALLER wraps their own ledger
 * append; the returned emitter refuses every event type except the three
 * explicit SemantIQ observability types. This keeps NO WRITE WITHOUT SCOPE
 * true for the evaluation stage.
 */
export function denyByDefaultSemantiqEmitter(
  append: (input: {
    readonly eventType: string;
    readonly policyDecision: "allow" | "deny" | "not_applicable";
    readonly actor: { readonly type: string; readonly id: string };
    readonly workspaceId?: string;
    readonly taskId?: string;
    readonly inputSummary: Readonly<Record<string, unknown>>;
    readonly resultSummary: Readonly<Record<string, unknown>>;
  }) => { readonly ok: boolean; readonly eventId?: string }
): SemantiqLedgerEmitter {
  return Object.freeze({
    append: (input: {
      readonly eventType: string;
      readonly policyDecision: "allow" | "deny" | "not_applicable";
      readonly actor: { readonly type: string; readonly id: string };
      readonly workspaceId?: string;
      readonly taskId?: string;
      readonly inputSummary: Readonly<Record<string, unknown>>;
      readonly resultSummary: Readonly<Record<string, unknown>>;
    }) => {
      if (!(ALLOWED_EVALUATION_EVENT_TYPES as readonly string[]).includes(input.eventType)) {
        return { ok: false };
      }
      return append(input);
    },
  });
}

export interface SemantiqContractOptions {
  /** Optional ledger port; absence = machine-readable unconfigured state. */
  readonly ledgerPort?: SemantiqLedgerPort | null;
  /** Optional evaluation engine; absence = machine-readable disabled state. */
  readonly engine?: SemantiqEngine | null;
  /** Optional deny-by-default emitter (see denyByDefaultSemantiqEmitter). */
  readonly ledger?: SemantiqLedgerEmitter | null;
  /**
   * 18D: optional rejection log; when provided, refused hostile payloads
   * (instruction smuggling / authority confusion) are RECORDED here.
   */
  readonly rejectionLog?: import("./boundary.js").SemantiqRejectionLog | null;
  readonly id?: string;
  readonly version?: string;
  readonly description?: string;
}

type EngineOutput =
  | {
      readonly ok: true;
      readonly claims: readonly SemantiqClaim[];
      readonly summary: string;
    }
  | { readonly ok: false; readonly denyReason: SemantiqDenyReason; readonly reason: string };

/** Deterministic evaluation id: sha256(requestFingerprint + eventFingerprint). */
function evaluationId(
  request: SemantiqEvaluationRequest,
  events: readonly { readonly eventId: string }[]
): string {
  const requestFingerprint = JSON.stringify([
    request.subject,
    request.trigger,
    request.eventTypes ?? null,
    request.note ?? null,
  ]);
  const eventFingerprint = JSON.stringify(events.map((e) => e.eventId));
  return createHash("sha256")
    .update(requestFingerprint + "|" + eventFingerprint, "utf8")
    .digest("hex");
}

/** Safe canonical serialization (unserializable content is a sentinel). */
function safeSerialize(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "undefined";
  } catch {
    return "<unserializable>";
  }
}

/** Digest of the RAW engine output (used for the mutation-integrity gate). */
function rawOutputDigest(claims: unknown, summary: unknown): string {
  return createHash("sha256")
    .update(safeSerialize(claims) + "|" + safeSerialize(summary), "utf8")
    .digest("hex");
}

/** Shared denial shorthand. */
function deny(
  denyReason: SemantiqDenyReason,
  reason: string,
  stage: "requested" | "computed" = "requested"
): SemantiqDenial {
  return semantiqDeny(denyReason, reason, stage) as SemantiqDenial;
}

/**
 * Build the disabled/unconfigured/degraded adapter surface. Every evaluation
 * denies with an explicit machine-readable reason; this is NOT an error
 * state — it is the honest "SemantIQ is not part of this runtime" contract
 * (Menog works fully with the adapter in this state).
 */
export function buildDisabledAdapterState(
  state: SemantiqAdapterState
): SemantiqAdapterContract {
  const denyReason: SemantiqDenyReason =
    state === "unconfigured"
      ? "adapter_unconfigured"
      : state === "degraded"
        ? "adapter_degraded"
        : "adapter_disabled";
  return Object.freeze({
    id: "semantiq.disabled",
    version: SEMANTIQ_SCHEMA_VERSION,
    description:
      "disabled SemantIQ adapter: evaluations deny with adapter_" +
      state +
      "; Menog works fully without an evaluation engine",
    state,
    async evaluate(
      request: SemantiqEvaluationRequest,
      _context: SemantiqRuntimeContext
    ): Promise<SemantiqResult> {
      void _context;
      const invalid = validateEvaluationRequest(request);
      if (invalid !== null) {
        const isOversized = invalid.includes("exceeds SEMANTIQ_MAX");
        return deny(isOversized ? "oversized_request" : "invalid_request", invalid);
      }
      return deny(
        denyReason,
        "SemantIQ adapter is " +
          state +
          "; evaluation denied — Menog works fully without an external evaluator (ADR-0007)"
      );
    },
  });
}

/**
 * Wrap an engine into the full contract-layer adapter. The engine is NEVER
 * trusted: its output is validated, bounded, normalized, integrity-checked,
 * and re-stamped as advisory data.
 */
export function buildSemantiqAdapter(
  options: SemantiqContractOptions
): SemantiqAdapterContract {
  const id = options.id ?? "semantiq.default";
  const version = options.version ?? "0.1.0";
  const description =
    options.description ??
    "contract-layer SemantIQ adapter over an injected evaluation engine";
  const port = options.ledgerPort ?? null;
  const engine = options.engine ?? null;
  const ledger = options.ledger ?? null;
  const rejections = options.rejectionLog ?? null;

  // Explicit lifecycle state: no ledger port ⇒ unconfigured; no engine ⇒
  // disabled. There is no ambient reconfiguration — build a new adapter to
  // change state.
  const state: SemantiqAdapterState =
    port === null ? "unconfigured" : engine === null ? "disabled" : "ready";

  if (state !== "ready") {
    const base = buildDisabledAdapterState(state);
    const offContract: SemantiqAdapterContract = Object.freeze({
      id,
      version,
      description,
      state,
      evaluate: (request: SemantiqEvaluationRequest, context: SemantiqRuntimeContext): Promise<SemantiqResult> =>
        base.evaluate(request, context),
    });
    return offContract;
  }

  return Object.freeze({
    id,
    version,
    description,
    state,
    async evaluate(
      request: SemantiqEvaluationRequest,
      context: SemantiqRuntimeContext
    ): Promise<SemantiqResult> {
      // Stage 1 — REQUESTED: validate + bound the request before any engine
      // or ledger work happens.
      const invalid = validateEvaluationRequest(request);
      if (invalid !== null) {
        const isOversized = invalid.includes("exceeds SEMANTIQ_MAX");
        return deny(isOversized ? "oversized_request" : "invalid_request", invalid);
      }

      // Stage 1b — 18D BOUNDARY SCREEN: evaluator-injection / instruction-
      // smuggling defense BEFORE the engine sees anything. Hostile text in
      // subject/note and authority fields anywhere in the request refuse
      // the evaluation and are RECORDED when a rejection log is attached.
      const screen = screenEvaluationRequest(request);
      if (!screen.ok) {
        if (rejections !== null) {
          rejections.record({
            rejectedAtEpochMs: 0,
            rejectedBy: "adapter",
            denyReason: screen.denyReason ?? "instruction_smuggling",
            patterns: screen.findings.map((f) => f.pattern),
            request,
            findings: screen.findings,
            payload: request,
            context,
          });
        }
        return deny(
          "invalid_request",
          screen.reason ?? "request refused at the evaluation boundary"
        );
      }

      // Read the bounded event view through the read-only port. Port failure
      // is machine-readable (ledger_unavailable), never a guessed success.
      if (port === null || engine === null) {
        // Unreachable in this branch (state === "ready"); narrows for TS.
        return deny("adapter_unconfigured", "adapter state invariant violated");
      }
      let rawEvents: readonly unknown[];
      try {
        const read = port.readEvents({ limit: SEMANTIQ_MAX_EVENTS_PER_EVALUATION });
        if (!read.ok) {
          return deny("ledger_unavailable", "ledger port denied: " + read.reason);
        }
        rawEvents = read.events;
      } catch {
        // Port error content is withheld from the denial reason — a hostile
        // port payload must not flow into machine-readable output.
        return deny(
          "ledger_unavailable",
          "ledger port threw (error content withheld)"
        );
      }

      // Normalize/drop malformed events before any engine sees them. The
      // port surface is arrays-of-objects: a non-array port payload is a
      // port-contract violation and degrades the adapter (fail closed).
      const events: SemantiqEventView[] = [];
      if (!Array.isArray(rawEvents)) {
        return deny(
          "adapter_degraded",
          "ledger port returned a non-array event payload; adapter degraded",
          "computed"
        );
      }
      for (const raw of rawEvents) {
        if (events.length >= SEMANTIQ_MAX_EVENTS_PER_EVALUATION) break;
        const view = normalizeEventView(raw);
        if (view !== null) events.push(view);
      }

      // Stage 2 — COMPUTED: run the engine inside failure isolation.
      let engineOut: EngineOutput;
      try {
        engineOut = engine({ events, request });
      } catch {
        // Failure isolation: engine exceptions become machine-readable
        // degradations. The error object NEVER propagates as an execution
        // failure, is never serialized into the denial (hostile error
        // payloads stay inert), and never fails open into a success path.
        return deny(
          "adapter_degraded",
          "evaluation engine threw (error content withheld); adapter degraded",
          "computed"
        );
      }
      if (!engineOut.ok) {
        // Engine-requested denials are honored ONLY for known machine-
        // readable reasons; anything else is a degradation.
        if (isSemantiqDenyReason(engineOut.denyReason)) {
          return deny(engineOut.denyReason, "engine denied: " + engineOut.reason, "computed");
        }
        return deny(
          "adapter_degraded",
          "engine returned unknown deny reason; treated as degradation",
          "computed"
        );
      }

      // Shape gate: claims must be array-shaped BEFORE any normalization or
      // integrity work runs (a non-array claims payload violates the engine
      // contract and degrades the adapter — fail closed).
      if (!Array.isArray(engineOut.claims)) {
        return deny(
          "adapter_degraded",
          "engine claims payload must be array-shaped",
          "computed"
        );
      }

      // Snapshot the raw output ONCE, then re-read it after normalization:
      // a mismatch proves the engine mutated its payload between compute
      // and delivery (e.g. getter-based tampering) ⇒ deliver nothing.
      const rawClaimsSnapshot: unknown = engineOut.claims;
      const rawSummarySnapshot: unknown = engineOut.summary;
      const digestBefore = rawOutputDigest(rawClaimsSnapshot, rawSummarySnapshot);

      // Bound the summary (conclusion-only, never a derivation trace).
      if (typeof rawSummarySnapshot !== "string") {
        return deny("adapter_degraded", "engine summary must be a string", "computed");
      }
      // 18D: the summary is the one free-text field that always surfaces —
      // it must carry NO smuggled instructions.
      const summaryScan = scanHostileText(rawSummarySnapshot, "engine.summary");
      if (summaryScan.length > 0) {
        if (rejections !== null) {
          rejections.record({
            rejectedAtEpochMs: 0,
            rejectedBy: "contract_layer",
            denyReason: "instruction_smuggling",
            patterns: [...new Set(summaryScan.map((f) => f.pattern))],
            request,
            findings: summaryScan,
            payload: { summary: rawSummarySnapshot },
            context,
          });
        }
        return deny(
          "adapter_degraded",
          "engine summary carried smuggled instructions; evaluation refused at the boundary",
          "computed"
        );
      }

      // Normalize claims: unknown kinds / authority-carrying shapes dropped;
      // over-limit output is bounded (distinct from tampering).
      const claims: SemantiqClaim[] = [];
      let claimFindings: SemantiqFinding[] = [];
      for (const raw of rawClaimsSnapshot as readonly unknown[]) {
        if (claims.length >= SEMANTIQ_MAX_CLAIMS) break;
        const c = normalizeClaim(raw);
        if (c !== null) {
          // 18D: an otherwise-valid claim carrying smuggled INSTRUCTIONS in
          // its value text is refused outright (not merely dropped) — the
          // whole evaluation degrades; hostile content must never surface
          // as even a normalized advisory claim.
          const scan = scanHostileText(c.value, "claim.value");
          if (scan.length > 0) {
            claimFindings = claimFindings.concat(scan);
            continue;
          }
          claims.push(c);
        }
      }
      if (claims.length === 0 && claimFindings.length > 0) {
        if (rejections !== null) {
          rejections.record({
            rejectedAtEpochMs: 0,
            rejectedBy: "contract_layer",
            denyReason: "instruction_smuggling",
            patterns: [...new Set(claimFindings.map((f) => f.pattern))],
            request,
            findings: claimFindings,
            payload: { claims: rawClaimsSnapshot },
            context,
          });
        }
        return deny(
          "adapter_degraded",
          "engine claims carried smuggled instructions; evaluation refused at the boundary",
          "computed"
        );
      }

      const digestAfter = rawOutputDigest(engineOut.claims, engineOut.summary);
      if (digestBefore !== digestAfter) {
        return deny(
          "adapter_degraded",
          "evaluation content changed between compute and delivery (integrity gate); delivery refused",
          "computed"
        );
      }

      // An engine whose ENTIRE claim set fails contract normalization is
      // degraded (fail closed) — distinct from an engine that legitimately
      // returned zero claims, which delivers an honest empty evaluation.
      const rawClaimCount = (rawClaimsSnapshot as readonly unknown[]).length;
      if (rawClaimCount > 0 && claims.length === 0) {
        return deny(
          "adapter_degraded",
          "all engine claims failed contract normalization; adapter degraded",
          "computed"
        );
      }
      const summary =
        rawSummarySnapshot.length > SEMANTIQ_MAX_SUMMARY_CHARS
          ? rawSummarySnapshot.slice(0, SEMANTIQ_MAX_SUMMARY_CHARS)
          : rawSummarySnapshot;

      // Stage 3 — DELIVERED: re-stamp authority pins and emit observability.
      const evalId = evaluationId(request, events);
      const evaluation: SemantiqEvaluation = Object.freeze({
        ok: true,
        schemaVersion: SEMANTIQ_SCHEMA_VERSION,
        stage: "computed",
        trigger: request.trigger,
        adapterId: id,
        adapterVersion: version,
        derivedFrom: Object.freeze(
          events.slice(0, SEMANTIQ_MAX_DERIVED_FROM).map((e) => e.eventId)
        ),
        claims: Object.freeze(claims),
        summary,
        // Authority pins are RE-STAMPED here; engine values are ignored.
        authority: "advisory_data",
        executionAuthorized: false,
      });

      // Observable lifecycle record (stage transition delivered).
      const record: SemantiqLifecycleRecord = Object.freeze({
        evaluationId: evalId,
        stage: "delivered",
        trigger: request.trigger,
        atEpochMs: 0,
        outcome: "delivered",
      });

      let evaluationEventId: string | undefined;
      if (ledger !== null) {
        try {
          const res = ledger.append({
            eventType: "evaluation_delivered",
            policyDecision: "not_applicable",
            actor: { type: context.actor.type, id: context.actor.id },
            workspaceId: context.workspaceId,
            taskId: context.taskId,
            inputSummary: {
              subject: request.subject.slice(0, 256),
              trigger: request.trigger,
              adapterId: id,
              adapterVersion: version,
            },
            resultSummary: {
              outcome: record.outcome,
              evaluationId: record.evaluationId,
              claimCount: claims.length,
              derivedFromCount: evaluation.derivedFrom.length,
              authority: "advisory_data",
              executionAuthorized: false,
            },
          });
          if (res.ok && res.eventId !== undefined) {
            evaluationEventId = res.eventId;
          }
        } catch {
          // Emitter failure is observability-only: the evaluation itself is
          // unaffected (logging must never become an authority path).
        }
      }

      return evaluationEventId !== undefined
        ? Object.freeze({ ...evaluation, evaluationEventId })
        : evaluation;
    },
  });
}
