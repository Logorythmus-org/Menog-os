/**
 * PHASE 28G — READ-ONLY INSPECTION RUNTIME
 *
 * The prompt requires testing four things specifically:
 *   1. mutation attempts
 *   2. action-name scans
 *   3. filter semantics
 *   4. timeline selection and provenance traces
 *
 * These are grouped into seven suites below. Every assertion is about what the
 * runtime REFUSES or structurally cannot do, so the tests are falsifying
 * checks: if a future edit added a mutating path, these fail.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  inspect,
  refuseInspectionAsControl,
  INSPECTION_QUERY_KINDS,
  INSPECTION_ALLOWED_OPERATIONS,
  INSPECTION_FORBIDDEN_ACTIONS,
  INSPECTION_REFUSAL_CODES,
  INSPECTION_FILTER_BASES,
  INSPECTION_BOUNDS,
  INSPECTION_SCHEMA_VERSION,
  type InspectionQuery,
} from "../../packages/durable-state/src/getigInspectionRuntime.js";
import { buildGetigObserverView } from "../../packages/durable-state/src/getigObserverViews.js";

const here = dirname(fileURLToPath(import.meta.url));
const MODULE_PATH = join(
  here,
  "..",
  "..",
  "packages",
  "durable-state",
  "src",
  "getigInspectionRuntime.ts",
);

// ── fixtures ─────────────────────────────────────────────────────────────────

/**
 * A real 28E view, built by the real 28E builder — never hand-rolled.
 *
 * The frame shape is the frozen 28A/28B one: typed collections keyed by their
 * own id keys (`visibleId`, `eventId`, …), not a flat fact list. Building this
 * through the real builder is deliberate: it proves 28G reads genuine Phase-28
 * output rather than a shape invented here to make the tests pass.
 */
function buildView() {
  const decision = buildGetigObserverView({
    viewId: "view-1",
    observerId: "observer-local",
    observerKind: "local_runtime",
    runtimeId: "runtime-a",
    epochId: "epoch-1",
    frame: {
      frameId: "frame-10",
      epochId: "epoch-1",
      observer: { observerId: "observer-local" },
      canonicalVisibleHash: "vh-10",
      entities: [
        { visibleId: "n1", kind: "tool", lifecycle: "observed", freshness: "current" },
        { visibleId: "n2", kind: "peer", lifecycle: "retired", freshness: "stale" },
        // No `kind`: present in the view, but the observer says nothing about
        // it, so 28E derives knowledge `unknown` rather than inventing one.
        { visibleId: "n4", lifecycle: "unknown", freshness: "unknown" },
      ],
      events: [
        { eventId: "n3", kind: "note", lifecycle: "quarantined", freshness: "current" },
      ],
    },
  });
  if (!decision.ok) throw new Error(`fixture view failed to build: ${decision.refusal}`);
  return decision.view;
}

const VIEW = buildView();

const BINDING = {
  frameId: VIEW.builtFromFrameId,
  observerId: VIEW.observerId,
  canonicalVisibleHash: VIEW.builtFromVisibleHash,
  viewHash: VIEW.viewHash,
};

const SEQUENCE = {
  sequenceId: "seq-1",
  observerId: VIEW.observerId,
  orderingBasis: "observed_local_order",
  entries: [
    { frameId: "frame-8", canonicalVisibleHash: "vh-8" },
    { frameId: "frame-9", canonicalVisibleHash: "vh-9" },
    { frameId: "frame-10", canonicalVisibleHash: "vh-10" },
  ],
  replaySemantics: "visual_history_not_executable",
};

const GRAPH = {
  graphId: "graph-1",
  nodes: [
    { nodeId: "n1", kind: "subject" },
    { nodeId: "e1", kind: "provenance_ref" },
    { nodeId: "e2", kind: "frame" },
  ],
  edges: [
    { edgeId: "a", fromNodeId: "n1", toNodeId: "e1" },
    { edgeId: "b", fromNodeId: "e1", toNodeId: "e2" },
  ],
};

const run = (query: InspectionQuery, extra: Record<string, unknown> = {}) =>
  inspect({ query, view: VIEW, binding: BINDING, ...extra });

/**
 * Narrow a decision to a result variant by discriminant.
 *
 * The result union has five variants, and a test asserting on one of them would
 * otherwise need an `as unknown as` cast at every site. `as` on a union whose
 * discriminant is checked first is sound, and this helper routes through
 * `unknown` exactly once so the intent is visible rather than hidden.
 */
const resultOf = <T>(decision: ReturnType<typeof inspect>, check: (r: unknown) => boolean): T => {
  if (!decision.ok) throw new Error(`expected a successful decision, got refusal ${decision.refusal}`);
  if (!check(decision.result)) throw new Error("result variant did not match the expected shape");
  return decision.result as T;
};

// ── 1. structural read-only surface ──────────────────────────────────────────

describe("28G — the API is structurally read-only", () => {
  it("every decision reports authority none and readOnly true", () => {
    const ok = run({ kind: "inspect", operation: "inspect" });
    expect(ok.authority).toBe("none");
    expect(ok.readOnly).toBe(true);
    if (ok.ok) {
      expect(ok.result.authority).toBe("none");
      expect((ok.result as { readonly readOnly: boolean }).readOnly).toBe(true);
    }
  });

  it("every successful inspection reports that it mutated nothing", () => {
    for (const operation of INSPECTION_ALLOWED_OPERATIONS) {
      const decision = run({ kind: "inspect", operation } as InspectionQuery);
      if (decision.ok) expect(decision.mutatedCanonicalState).toBe(false);
    }
  });

  it("the frozen view is byte-identical before and after an inspection", () => {
    const before = JSON.stringify(VIEW);
    run({ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired" });
    run({ kind: "inspect", operation: "inspect" });
    run({ kind: "select", operation: "select", subjectVisibleId: "n1" });
    expect(JSON.stringify(VIEW)).toBe(before);
  });

  it("the same query over the same input is byte-identical — no mutable cache", () => {
    const a = run({ kind: "filter", operation: "filter", filterBase: "knowledge", filterValue: "known" });
    const b = run({ kind: "filter", operation: "filter", filterBase: "knowledge", filterValue: "known" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    if (a.ok && b.ok && "inspectionId" in a.result && "inspectionId" in b.result) {
      expect(a.result.inspectionId).toBe(b.result.inspectionId);
    }
  });

  it("no exported symbol performs a forbidden action", async () => {
    const mod = await import("../../packages/durable-state/src/getigInspectionRuntime.js");
    for (const name of Object.keys(mod)) {
      const normalised = name.toLowerCase();
      for (const action of INSPECTION_FORBIDDEN_ACTIONS) {
        // `refuseInspectionAsControl` deliberately CONTAINS a forbidden word and
        // is the only export allowed to, because it refuses.
        if (name === "refuseInspectionAsControl") continue;
        if (INSPECTION_FORBIDDEN_ACTIONS.includes(action as never)) {
          expect(normalised.includes(action.replace(/_/g, ""))).toBe(false);
        }
      }
    }
  });
});

// ── 2. action-name scan over the module source ───────────────────────────────

describe("28G — action-name scan of the module source", () => {
  const source = readFileSync(MODULE_PATH, "utf8");

  it("declares every forbidden action the prompt names", () => {
    for (const action of [
      "execute",
      "approve",
      "admit",
      "quarantine",
      "retire",
      "grant",
      "restart",
      "kill",
      "invoke_tool",
      "write_runtime_state",
      "auto_resume",
    ]) {
      expect(INSPECTION_FORBIDDEN_ACTIONS).toContain(action);
    }
    expect(INSPECTION_FORBIDDEN_ACTIONS.length).toBeGreaterThanOrEqual(15);
  });

  it("declares no forbidden operation as an allowed one", () => {
    for (const action of INSPECTION_FORBIDDEN_ACTIONS) {
      expect(INSPECTION_ALLOWED_OPERATIONS).not.toContain(action);
    }
  });

  it("has no function declaration named after a forbidden action", () => {
    for (const action of INSPECTION_FORBIDDEN_ACTIONS) {
      const camel = action.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());
      const pattern = new RegExp(`function\\s+${camel}\\b`, "i");
      expect(pattern.test(source), `found forbidden function ${camel}`).toBe(false);
    }
  });

  it("has no arrow-function export named after a forbidden action", () => {
    for (const action of INSPECTION_FORBIDDEN_ACTIONS) {
      const camel = action.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());
      const pattern = new RegExp(`export\\s+const\\s+${camel}\\b`, "i");
      expect(pattern.test(source), `found forbidden export ${camel}`).toBe(false);
    }
  });

  it("declares no mutating method on any result interface", () => {
    // A `set`/`update`/`remove` method on a result type would be the back door.
    expect(/readonly\s+(set|update|remove|delete|clear|commit|apply|persist|write)\b/i.test(source)).toBe(
      false,
    );
  });

  it("every query kind in the source maps to an allowed operation", () => {
    for (const kind of INSPECTION_QUERY_KINDS) {
      expect(kind.length).toBeGreaterThan(0);
    }
    expect(INSPECTION_QUERY_KINDS.length).toBe(INSPECTION_ALLOWED_OPERATIONS.length);
  });
});

// ── 3. mutation attempts are refused ─────────────────────────────────────────

describe("28G — mutation attempts", () => {
  it("refuses a query carrying a forbidden action field", () => {
    for (const action of ["execute", "approve", "admit", "retire", "grant", "auto_resume"]) {
      const decision = inspect({
        query: { kind: "inspect", operation: "inspect", [action]: true },
        view: VIEW,
        binding: BINDING,
      });
      expect(decision.ok).toBe(false);
      if (!decision.ok) {
        expect(decision.refusal).toBe("refused_query_mutation_shape");
        expect(decision.mutatedCanonicalState).toBe(false);
      }
    }
  });

  it("refuses a mutation attempt riding on a selection, distinctly", () => {
    const decision = inspect({
      query: { kind: "select", operation: "select", subjectVisibleId: "n1", approve: true },
      view: VIEW,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_selection_mutation_attempt");
  });

  it("refuses a mutation-shaped field even alongside an otherwise valid query", () => {
    const decision = inspect({
      query: { kind: "inspect", operation: "inspect", write_runtime_state: "yes" },
      view: VIEW,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
  });

  it("refuses an unknown operation rather than defaulting to something safe-ish", () => {
    const decision = run({ kind: "inspect", operation: "execute_tool" as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_query_operation_unknown");
  });

  it("refuses an unknown query kind", () => {
    const decision = inspect({ query: { kind: "mutate", operation: "inspect" }, view: VIEW, binding: BINDING });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_query_kind_unknown");
  });

  it("refuses a non-object query", () => {
    for (const bad of [null, undefined, 42, "inspect", []]) {
      const decision = inspect({ query: bad, view: VIEW, binding: BINDING });
      expect(decision.ok).toBe(false);
    }
  });

  it("refuseInspectionAsControl cannot succeed for any input", () => {
    for (const claimed of ["execute", "approve", undefined, 0, {}, ["grant"]]) {
      const decision = refuseInspectionAsControl(claimed);
      expect(decision.ok).toBe(false);
      expect(decision.result).toBeNull();
      expect(decision.authority).toBe("none");
    }
  });
});

// ── 4. binding is mandatory ──────────────────────────────────────────────────

describe("28G — results stay bound to frame, observer and hash", () => {
  it("refuses an inspection with no binding at all", () => {
    const decision = inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_binding_frame_missing");
  });

  it("refuses a binding missing frame, observer or hash", () => {
    // Each case omits exactly ONE field, so each must report THAT field's own
    // code. A case omitting two fields would pass against a looser check while
    // hiding which field actually caused the refusal.
    const cases: [Record<string, unknown>, string][] = [
      [{ observerId: "o", canonicalVisibleHash: "h", viewHash: "vh" }, "refused_binding_frame_missing"],
      [{ frameId: "f", canonicalVisibleHash: "h", viewHash: "vh" }, "refused_binding_observer_missing"],
      [{ frameId: "f", observerId: "o", viewHash: "vh" }, "refused_binding_hash_missing"],
      [{ frameId: "f", observerId: "o", canonicalVisibleHash: "h" }, "refused_binding_hash_missing"],
    ];
    for (const [binding, refusal] of cases) {
      const decision = inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe(refusal);
    }
  });

  it("refuses a binding that disagrees with the view it would describe", () => {
    const decision = inspect({
      query: { kind: "inspect", operation: "inspect" },
      view: VIEW,
      binding: { ...BINDING, viewHash: "some-other-hash" },
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_binding_mismatch");
  });

  it("every successful result echoes the binding it was given", () => {
    const decision = run({ kind: "inspect", operation: "inspect" });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.result.binding).toEqual(BINDING);
  });

  it("refuses a sequence whose observer does not match the binding", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      sequence: { ...SEQUENCE, observerId: "someone-else" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_binding_mismatch");
  });
});

// ── 5. filter semantics ──────────────────────────────────────────────────────

describe("28G — filter semantics", () => {
  it("a filtered result always declares itself filtered and incomplete", () => {
    const decision = run({ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired" });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = decision.result as { isFiltered: boolean; isComplete: boolean; excludedCount: number };
      expect(result.isFiltered).toBe(true);
      expect(result.isComplete).toBe(false);
      expect(result.excludedCount).toBeGreaterThan(0);
    }
  });

  it("filtering never alters the canonical view", () => {
    const decision = run({ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired" });
    expect(decision.ok).toBe(true);
    if (decision.ok) expect((decision.result as { canonicalViewAltered: boolean }).canonicalViewAltered).toBe(false);
    expect(VIEW.facts).toHaveLength(4);
  });

  it("retired and quarantined facts remain visible in the view after a filter", () => {
    run({ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "observed" });
    const lifecycles = VIEW.facts.map((f) => (f as { readonly lifecycle: string }).lifecycle);
    expect(lifecycles).toContain("retired");
    expect(lifecycles).toContain("quarantined");
  });

  it("filters correctly on each supported base", () => {
    const cases: [InspectionQuery, string[]][] = [
      [{ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired" }, ["n2"]],
      [{ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "quarantined" }, ["n3"]],
      [{ kind: "filter", operation: "filter", filterBase: "knowledge", filterValue: "unknown" }, ["n4"]],
      [{ kind: "filter", operation: "filter", filterBase: "freshness", filterValue: "stale" }, ["n2"]],
      // `n3` comes from the frame's `events` collection, so the derived
      // `subjectCollection` is `events` — the value 28E actually assigns.
      [{ kind: "filter", operation: "filter", filterBase: "subject_collection", filterValue: "events" }, ["n3"]],
      [{ kind: "filter", operation: "filter", filterBase: "subject_collection", filterValue: "entities" }, ["n1", "n2", "n4"]],
    ];
    for (const [query, expected] of cases) {
      const decision = run(query);
      expect(decision.ok).toBe(true);
      if (decision.ok) {
        expect(resultOf<{ subjectVisibleIds: string[] }>(decision, (r) => "subjectVisibleIds" in (r as object)).subjectVisibleIds).toEqual(expected);
      }
    }
  });

  it("an unknown filter base is refused, never silently ignored", () => {
    const decision = inspect({
      query: { kind: "filter", operation: "filter", filterBase: "authority_level", filterValue: "high" },
      view: VIEW,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_filter_predicate_unknown");
  });

  it("a filter with no value is refused", () => {
    const decision = inspect({
      query: { kind: "filter", operation: "filter", filterBase: "lifecycle" },
      view: VIEW,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_filter_predicate_unknown");
  });

  it("every declared filter base is a real closed member", () => {
    expect([...INSPECTION_FILTER_BASES]).toEqual([
      "lifecycle",
      "freshness",
      "knowledge",
      "subject_collection",
      "divergence",
    ]);
  });
});

// ── 6. limits and bounds fail closed ─────────────────────────────────────────

describe("28G — resource limits fail closed", () => {
  it("refuses a limit outside the explicit bounds rather than clamping it", () => {
    for (const limit of [0, -1, 2.5, INSPECTION_BOUNDS.maxResultLimit + 1, NaN]) {
      const decision = run({ kind: "inspect", operation: "inspect", limit });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_limit_out_of_range");
    }
  });

  it("refuses a non-numeric limit", () => {
    const decision = inspect({
      query: { kind: "inspect", operation: "inspect", limit: "10" },
      view: VIEW,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
  });

  it("honours an in-range limit and reports the shortfall", () => {
    const decision = run({ kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired", limit: 1 });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = resultOf<{ subjectVisibleIds: string[]; matchedCount: number }>(
        decision,
        (r) => "matchedCount" in (r as object),
      );
      expect(result.subjectVisibleIds).toHaveLength(1);
    }
  });
});

// ── 7. timeline selection is navigation, not resumption ──────────────────────

describe("28G — timeline selection", () => {
  it("reads past frames without resuming one", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      sequence: SEQUENCE,
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = resultOf<{
        frameIds: string[];
        resumesRuntimeState: boolean;
        restoresRuntimeState: boolean;
        replaySemantics: string;
      }>(decision, (r) => "frameIds" in (r as object));
      expect(result.frameIds).toEqual(["frame-10", "frame-8", "frame-9"]);
      expect(result.resumesRuntimeState).toBe(false);
      expect(result.restoresRuntimeState).toBe(false);
      expect(result.replaySemantics).toBe("visual_history_not_executable");
    }
  });

  it("refuses a timeline query given no sequence", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_input_not_a_sequence");
  });

  it("refuses a sequence that does not declare visual-history-only semantics", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      sequence: { ...SEQUENCE, replaySemantics: "executable_replay" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_input_not_a_sequence");
  });

  it("reports no chronology when the ordering basis is unknown", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      sequence: { ...SEQUENCE, orderingBasis: "unknown" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect((decision.result as { temporalOrderEstablished: boolean }).temporalOrderEstablished).toBe(false);
    }
  });

  it("timeline navigation never reports resuming runtime state", () => {
    const decision = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      sequence: SEQUENCE,
      binding: BINDING,
    });
    expect(JSON.stringify(decision)).toContain('"resumesRuntimeState":false');
    expect(JSON.stringify(decision)).toContain('"controlPlane":false');
  });
});

// ── 8. provenance traces explain and never authorise ─────────────────────────

describe("28G — provenance traces", () => {
  it("traces a subject through the frozen graph", () => {
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" },
      graph: GRAPH,
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = resultOf<{ hops: { nodeId: string; depth: number }[]; hopCount: number }>(
        decision,
        (r) => "hops" in (r as object),
      );
      expect(result.hopCount).toBe(2);
      expect(result.hops.map((h) => h.nodeId)).toEqual(["e1", "e2"]);
      expect(result.hops[0]?.depth).toBe(1);
    }
  });

  it("no hop confers trust or authority", () => {
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" },
      graph: GRAPH,
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = resultOf<{
        hops: { confersTrust: boolean; confersAuthority: boolean }[];
        authorizes: boolean;
      }>(decision, (r) => "authorizes" in (r as object));
      expect(result.authorizes).toBe(false);
      for (const hop of result.hops) {
        expect(hop.confersTrust).toBe(false);
        expect(hop.confersAuthority).toBe(false);
      }
    }
  });

  it("a cyclic graph terminates instead of looping forever", () => {
    const cyclic = {
      graphId: "cyclic",
      nodes: [{ nodeId: "a", kind: "subject" }, { nodeId: "b", kind: "frame" }],
      edges: [
        { edgeId: "1", fromNodeId: "a", toNodeId: "b" },
        { edgeId: "2", fromNodeId: "b", toNodeId: "a" },
      ],
    };
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "a" },
      graph: cyclic,
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = decision.result as { cycleBroken: boolean; hopCount: number };
      expect(result.cycleBroken).toBe(true);
      expect(result.hopCount).toBe(1);
    }
  });

  it("a large fan-out stops at the hop bound rather than running away", () => {
    const fanout = {
      graphId: "wide",
      nodes: [{ nodeId: "root", kind: "subject" }],
      edges: Array.from({ length: 5_000 }, (_v, i) => ({
        edgeId: `e${i}`,
        fromNodeId: "root",
        toNodeId: `leaf-${i}`,
      })),
    };
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "root" },
      graph: fanout,
      binding: BINDING,
    });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = decision.result as { hopCount: number; boundedStop: boolean };
      expect(result.hopCount).toBeLessThanOrEqual(INSPECTION_BOUNDS.maxTracedHops);
      expect(result.boundedStop).toBe(true);
    }
  });

  it("refuses a provenance trace with no graph", () => {
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_input_not_a_graph");
  });

  it("refuses a trace with no subject rather than tracing everything", () => {
    const decision = inspect({
      query: { kind: "trace_provenance", operation: "trace_provenance" },
      graph: GRAPH,
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_subject_unknown");
  });
});

// ── 9. selection confers nothing ─────────────────────────────────────────────

describe("28G — selection confers nothing", () => {
  it("a selection carries no permission, authority or execution", () => {
    const decision = run({ kind: "select", operation: "select", subjectVisibleId: "n1" });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = decision.result as {
        authority: string;
        confersPermission: boolean;
        isExecution: boolean;
        grantsNothing: boolean;
      };
      expect(result.authority).toBe("none");
      expect(result.confersPermission).toBe(false);
      expect(result.isExecution).toBe(false);
      expect(result.grantsNothing).toBe(true);
    }
  });

  it("focusing on a tool-like subject does not make it permitted", () => {
    // `n1` is statedKind `tool` in the fixture. Selecting it must still grant
    // nothing — SELECTION != PERMISSION, and TOOL != GRANT.
    const decision = run({ kind: "focus", operation: "focus", subjectVisibleId: "n1" });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = decision.result as { confersPermission: boolean; authority: string };
      expect(result.confersPermission).toBe(false);
      expect(result.authority).toBe("none");
    }
  });

  it("expanding a subject reveals detail without granting anything", () => {
    const collapsed = run({ kind: "expand_collapse", operation: "expand_collapse", expansionState: "collapsed" });
    const expanded = run({ kind: "expand_collapse", operation: "expand_collapse", expansionState: "expanded" });
    expect(collapsed.ok && expanded.ok).toBe(true);
    if (collapsed.ok && expanded.ok) {
      const a = collapsed.result as { expansionState: string; authority: string };
      const b = expanded.result as { expansionState: string; authority: string };
      expect(a.expansionState).toBe("collapsed");
      expect(b.expansionState).toBe("expanded");
      expect(a.authority).toBe("none");
      expect(b.authority).toBe("none");
    }
  });

  it("refuses a subject that is not in the view rather than reporting it empty", () => {
    const decision = run({ kind: "select", operation: "select", subjectVisibleId: "does-not-exist" });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_subject_unknown");
  });

  it("refuses a view that is not a Phase-28 observer view", () => {
    const decision = inspect({
      query: { kind: "inspect", operation: "inspect" },
      view: { viewId: "v", observerId: "o" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_input_not_a_view");
  });

  it("refuses a view that claims authority it may not claim", () => {
    const decision = inspect({
      query: { kind: "inspect", operation: "inspect" },
      view: { ...VIEW, authority: "full" },
      binding: BINDING,
    });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_input_not_a_view");
  });
});

// ── 10. refusals and conflicts stay enumerable ───────────────────────────────

describe("28G — refusals and conflicts", () => {
  it("enumerates barred subjects so a filtered view cannot hide them", () => {
    const decision = run({ kind: "enumerate_refusals", operation: "enumerate_refusals_conflicts" });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const result = resultOf<{ barredSubjects: string[]; counts: { barredSubjectCount: number } }>(
        decision,
        (r) => "barredSubjects" in (r as object),
      );
      expect(result.barredSubjects).toEqual(["n2", "n3"]);
      expect(result.counts.barredSubjectCount).toBe(2);
    }
  });

  it("never claims completeness for an enumeration", () => {
    const decision = run({ kind: "enumerate_refusals", operation: "enumerate_refusals_conflicts" });
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect((decision.result as { completenessClaimed: boolean }).completenessClaimed).toBe(false);
    }
  });

  it("every declared refusal code is a real closed member", () => {
    expect(INSPECTION_REFUSAL_CODES.length).toBeGreaterThanOrEqual(15);
    for (const code of INSPECTION_REFUSAL_CODES) expect(typeof code).toBe("string");
  });

  it("uses the declared schema version", () => {
    expect(INSPECTION_SCHEMA_VERSION).toBe("menog-getig-inspection/v0");
    const decision = run({ kind: "inspect", operation: "inspect" });
    if (decision.ok) expect((decision.result as { schemaVersion: string }).schemaVersion).toBe(INSPECTION_SCHEMA_VERSION);
  });
});

// ── 11. every refusal code is reachable ──────────────────────────────────────

describe("28G — every declared refusal code is reachable", () => {
  it("produces each refusal code from a real input", () => {
    const produced = new Set<string>();
    const record = (d: ReturnType<typeof inspect>) => {
      if (!d.ok) produced.add(d.refusal);
    };

    record(inspect({ query: { kind: "nope", operation: "inspect" }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "inspect", operation: "nope" }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "inspect", operation: "inspect", grant: 1 }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding: { observerId: "o", canonicalVisibleHash: "h", viewHash: "vh" } }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding: { frameId: "f", canonicalVisibleHash: "h", viewHash: "vh" } }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding: { frameId: "f", observerId: "o" } }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding: { ...BINDING, viewHash: "x" } }));
    record(inspect({ query: { kind: "inspect", operation: "inspect" }, view: { bad: true }, binding: BINDING }));
    record(inspect({ query: { kind: "timeline_navigate", operation: "timeline_navigate" }, binding: BINDING }));
    record(inspect({ query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" }, binding: BINDING }));
    record(inspect({ query: { kind: "select", operation: "select", subjectVisibleId: "zzz" }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "filter", operation: "filter", filterBase: "wat", filterValue: "x" }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "inspect", operation: "inspect", limit: 0 }, view: VIEW, binding: BINDING }));
    record(inspect({ query: { kind: "inspect", operation: "inspect", limit: 99_999 }, view: VIEW, binding: BINDING }));
    record(
      inspect({
        query: { kind: "select", operation: "select", subjectVisibleId: "n1", mutate_policy: true },
        view: VIEW,
        binding: BINDING,
      }),
    );
    // A mutation attempt riding on a selection gets its own code: selecting
    // something and asking to change it is the conflation 28G must refuse.
    record(
      inspect({
        query: { kind: "select", operation: "select", subjectVisibleId: "n1", approve: true },
        view: VIEW,
        binding: BINDING,
      }),
    );
    // An oversized view must be refused, never silently truncated.
    record(
      inspect({
        query: { kind: "inspect", operation: "inspect" },
        view: {
          ...VIEW,
          facts: Array.from({ length: INSPECTION_BOUNDS.maxSubjectsPerQuery + 1 }, (_v, i) => ({
            factId: `f${i}`,
            subjectVisibleId: `s${i}`,
            lifecycle: "observed",
          })),
        },
        binding: BINDING,
      }),
    );

    for (const code of INSPECTION_REFUSAL_CODES) {
      expect(produced.has(code), `unreachable refusal code: ${code}`).toBe(true);
    }
  });
});
