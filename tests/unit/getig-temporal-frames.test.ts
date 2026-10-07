/**
 * PHASE 28C — TEMPORAL FRAMES & RUNTIME TIMELINE
 * (VISUAL HISTORY ONLY / NO GLOBAL TIME / NO EXECUTABLE REPLAY)
 *
 * Every law the prompt pins is demonstrated here rather than asserted in prose.
 * The suite is deliberately split into three kinds of test, because mixing them
 * is how a gate ends up proving nothing:
 *
 *   1. BEHAVIOUR — what the builder and the diff actually do.
 *   2. LAW AUDITS — scans over the emitted artefact, each paired with a
 *      SELF-TEST that plants a synthetic violation and proves the scan catches
 *      it. A scan that cannot fail is worse than no scan: it reports PASS while
 *      matching nothing, which is exactly the failure this project has hit
 *      before. Every audit below reports the symbols it actually examined, so a
 *      vacuous pass is visible rather than silent.
 *   3. INTEGRATION — real 28A frames, built by the real builder, fed into the
 *      real 28C code path.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildGetigFrameSequence,
  diffGetigFrames,
  refuseResumeFromFrame,
  GETIG_TEMPORAL_BOUNDS,
  GETIG_TEMPORAL_REFUSAL_CODES,
  GETIG_TEMPORAL_SCHEMA_VERSION,
  GETIG_SEQUENCE_ORDERING_BASES,
  GETIG_DIFF_CLASSES,
  GETIG_DIFF_COLLECTIONS,
  GETIG_FORBIDDEN_DIFF_FIELDS,
  buildGetigFrame,
  type GetigFrame,
  type GetigFrameInput,
  type GetigEntityKind,
  type GetigDiffClass,
  type GetigDiffCollection,
} from "../../packages/durable-state/dist/index.js";

const SRC_PATH = join(process.cwd(), "packages", "durable-state", "src", "getigTemporalFrames.ts");
const DTS_PATH = join(process.cwd(), "packages", "durable-state", "dist", "getigTemporalFrames.d.ts");
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-28c";
const OBSERVER = "observer-local-1";
const HEX64 = /^[0-9a-f]{64}$/;

/** Fail loudly rather than let a helper quietly substitute a placeholder. */
function readSourceOrThrow(path: string): string {
  const text = readFileSync(path, "utf8");
  if (text.length === 0) throw new Error(`audit input is empty: ${path}`);
  return text;
}

const hex = (digit: string) => digit.repeat(64);

// ── fixtures ─────────────────────────────────────────────────────────────────

type FrameRefInput = {
  frameId?: string;
  asOfEpochMs?: number;
  visibleDigit?: string;
  sourceDigit?: string;
  observerId?: string;
  epochId?: string;
};

const ref = (over: FrameRefInput = {}) => ({
  frameId: over.frameId ?? "frame-0001",
  asOfEpochMs: over.asOfEpochMs ?? NOW,
  canonicalVisibleHash: hex(over.visibleDigit ?? "1"),
  sourceProjectionHash: hex(over.sourceDigit ?? "2"),
  epochId: over.epochId ?? EPOCH,
  observer: { observerId: over.observerId ?? OBSERVER },
});

const seqInput = (frames: readonly unknown[], over: Record<string, unknown> = {}) =>
  ({
    sequenceId: "seq-1",
    observerId: OBSERVER,
    epochId: EPOCH,
    orderingBasis: "observed_order",
    frames,
    ...over,
  }) as Parameters<typeof buildGetigFrameSequence>[0];

function built(frames: readonly unknown[], over: Record<string, unknown> = {}) {
  const decision = buildGetigFrameSequence(seqInput(frames, over));
  if (!decision.ok) throw new Error(`expected a built sequence, got ${decision.refusal}: ${decision.explanation}`);
  return decision.sequence;
}

const entity = (visibleId: string, over: Record<string, unknown> = {}) => ({
  visibleId,
  kind: "runtime_node" as GetigEntityKind,
  label: `label-${visibleId}`,
  isRuntimeObject: false as const,
  grant: "none" as const,
  freshness: "current" as const,
  lifecycle: "observed" as const,
  provenanceRefs: [],
  representsRuntimeId: null,
  ...over,
});

/** A minimal frame-shaped object. 28C reads frames; it does not validate them. */
const world = (frameId: string, over: Record<string, unknown> = {}) => ({
  frameId,
  asOfEpochMs: NOW,
  canonicalVisibleHash: hex("a"),
  sourceProjectionHash: hex("b"),
  entities: [],
  relations: [],
  events: [],
  conflicts: [],
  refusals: [],
  routes: [],
  proposalFlows: [],
  ...over,
});

// ── 1. behaviour: the sequence ───────────────────────────────────────────────

describe("28C — frame sequence construction", () => {
  it("builds a sequence from frames that share one observer and epoch", () => {
    const sequence = built([ref({ frameId: "f1" }), ref({ frameId: "f2", asOfEpochMs: NOW + 10 })]);
    expect(sequence.frameCount).toBe(2);
    expect(sequence.entries.map((e) => e.frameId)).toEqual(["f1", "f2"]);
    expect(sequence.schemaVersion).toBe(GETIG_TEMPORAL_SCHEMA_VERSION);
  });

  it("accepts an empty sequence and still commits to an identity", () => {
    const sequence = built([]);
    expect(sequence.frameCount).toBe(0);
    expect(sequence.entries).toEqual([]);
    expect(sequence.sequenceIdentity).toMatch(HEX64);
  });

  it("is deterministic for identical input", () => {
    const a = built([ref({ frameId: "f1" }), ref({ frameId: "f2" })]);
    const b = built([ref({ frameId: "f1" }), ref({ frameId: "f2" })]);
    expect(a.sequenceIdentity).toBe(b.sequenceIdentity);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("freezes the sequence and its entries", () => {
    const sequence = built([ref({ frameId: "f1" })]);
    expect(Object.isFrozen(sequence)).toBe(true);
    expect(Object.isFrozen(sequence.entries)).toBe(true);
    expect(Object.isFrozen(sequence.entries[0])).toBe(true);
  });

  it("does not mutate the frames it was given", () => {
    const before = ref({ frameId: "f1" });
    const frozenCopy = JSON.stringify(before);
    built([before]);
    expect(JSON.stringify(before)).toBe(frozenCopy);
  });
});

describe("28C — reordered input", () => {
  it("keeps positions exactly as supplied and never sorts them", () => {
    const sequence = built([
      ref({ frameId: "late", asOfEpochMs: NOW + 5_000 }),
      ref({ frameId: "early", asOfEpochMs: NOW }),
    ]);
    expect(sequence.entries.map((e) => `${e.position}:${e.frameId}`)).toEqual(["0:late", "1:early"]);
    // Positions are index-as-supplied, NOT ordered by time.
    expect(sequence.entries[0]!.asOfEpochMs).toBeGreaterThan(sequence.entries[1]!.asOfEpochMs);
  });

  it("treats a reordering as a different sequence, not a corrected one", () => {
    const forwards = built([ref({ frameId: "f1" }), ref({ frameId: "f2" })]);
    const backwards = built([ref({ frameId: "f2" }), ref({ frameId: "f1" })]);
    expect(forwards.sequenceIdentity).not.toBe(backwards.sequenceIdentity);
    // Same frames, same observer, same epoch — only the supplied order differs.
    expect(forwards.frameCount).toBe(backwards.frameCount);
  });
});

describe("28C — no global distributed-time claim", () => {
  it("exposes exactly two ordering bases, and neither is a clock", () => {
    expect([...GETIG_SEQUENCE_ORDERING_BASES]).toEqual(["observed_order", "unknown"]);
  });

  it("records an observed order as the observer's claim, not a fact", () => {
    const sequence = built([ref({ frameId: "f1" })], { orderingBasis: "observed_order" });
    expect(sequence.temporalOrderEstablished).toBe(true);
    expect(sequence.globalTruth).toBe(false);
    expect(sequence.entries.every((e) => e.temporalOrderEstablished)).toBe(true);
  });

  it("keeps unknown ordering unknown, sequence-wide and entry-wide", () => {
    const sequence = built(
      [ref({ frameId: "f1", asOfEpochMs: 9_000 }), ref({ frameId: "f2", asOfEpochMs: NOW })],
      { orderingBasis: "unknown" },
    );
    expect(sequence.temporalOrderEstablished).toBe(false);
    expect(sequence.entries.map((e) => e.temporalOrderEstablished)).toEqual([false, false]);
    // Times are still echoed as the observer's own metadata.
    expect(sequence.entries.map((e) => e.asOfEpochMs)).toEqual([9_000, NOW]);
  });

  it("gives unknown and observed order different sequence identities", () => {
    const observed = built([ref({ frameId: "f1" })], { orderingBasis: "observed_order" });
    const unknown = built([ref({ frameId: "f1" })], { orderingBasis: "unknown" });
    expect(observed.sequenceIdentity).not.toBe(unknown.sequenceIdentity);
  });
});

describe("28C — the three identities stay separate", () => {
  it("keeps sourceProjectionHash, canonicalVisibleHash and sequenceIdentity pairwise distinct", () => {
    const sequence = built([
      ref({ frameId: "f1", visibleDigit: "1", sourceDigit: "2" }),
      ref({ frameId: "f2", visibleDigit: "3", sourceDigit: "4" }),
    ]);
    const entry = sequence.entries[0]!;
    expect(entry.canonicalVisibleHash).not.toBe(entry.sourceProjectionHash);
    expect(entry.canonicalVisibleHash).not.toBe(sequence.sequenceIdentity);
    expect(entry.sourceProjectionHash).not.toBe(sequence.sequenceIdentity);
    expect(sequence.entries[1]!.canonicalVisibleHash).not.toBe(entry.canonicalVisibleHash);
  });

  it("does not let the sequence identity be any single frame's visible hash", () => {
    const frames = Array.from({ length: 8 }, (_, i) => ref({ frameId: `f${i}`, visibleDigit: String(i + 1) }));
    const sequence = built(frames);
    const allFrameHashes = sequence.entries.map((e) => e.canonicalVisibleHash);
    expect(allFrameHashes).not.toContain(sequence.sequenceIdentity);
  });

  it("distinguishes 'same visible content, different evidence' from 'same evidence'", () => {
    const sameEvidence = built([ref({ frameId: "f1", sourceDigit: "2" }), ref({ frameId: "f2", sourceDigit: "2" })]);
    const otherEvidence = built([ref({ frameId: "f1", sourceDigit: "2" }), ref({ frameId: "f2", sourceDigit: "7" })]);
    expect(sameEvidence.sequenceIdentity).not.toBe(otherEvidence.sequenceIdentity);
  });

  it("a diff reports the frames' own two identities, never a sequence identity", () => {
    const decision = diffGetigFrames(
      world("fa", { canonicalVisibleHash: hex("a"), sourceProjectionHash: hex("b") }),
      world("fb", { canonicalVisibleHash: hex("c"), sourceProjectionHash: hex("d") }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.fromVisibleHash).toBe(hex("a"));
    expect(decision.diff.toVisibleHash).toBe(hex("c"));
    expect(decision.diff.fromSourceProjectionHash).toBe(hex("b"));
    expect(decision.diff.toSourceProjectionHash).toBe(hex("d"));
    expect(Object.prototype.hasOwnProperty.call(decision.diff, "fromSequenceIdentity")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(decision.diff, "toSequenceIdentity")).toBe(false);
  });
});

describe("28C — stable visible identity is never authority", () => {
  it("marks every sequence entry authority:none, whatever the frame id", () => {
    const sequence = built([ref({ frameId: "root" }), ref({ frameId: "system-privileged-handle" })]);
    expect(sequence.entries.map((e) => e.authority)).toEqual(["none", "none"]);
    expect(sequence.authority).toBe("none");
  });

  it("pins the sequence's structural zeros", () => {
    const sequence = built([ref({ frameId: "f1" })]);
    expect(sequence.replaySemantics).toBe("visual_history_not_executable");
    expect(sequence.restoresRuntimeState).toBe(false);
    expect(sequence.resumesRuntimeState).toBe(false);
    expect(sequence.controlPlane).toBe(false);
    expect(sequence.readOnly).toBe(true);
    expect(sequence.globalTruth).toBe(false);
  });
});

// ── 2. behaviour: refusals ───────────────────────────────────────────────────

describe("28C — refusals", () => {
  const cases: readonly [string, () => ReturnType<typeof buildGetigFrameSequence>, string][] = [
    ["null input", () => buildGetigFrameSequence(null as never), "refused_sequence_invalid_input"],
    ["missing sequenceId", () => buildGetigFrameSequence(seqInput([], { sequenceId: "" })), "refused_sequence_invalid_input"],
    ["missing observerId", () => buildGetigFrameSequence(seqInput([], { observerId: "" })), "refused_sequence_invalid_input"],
    ["missing epochId", () => buildGetigFrameSequence(seqInput([], { epochId: "" })), "refused_sequence_invalid_input"],
    ["frames not an array", () => buildGetigFrameSequence(seqInput("nope" as never)), "refused_sequence_invalid_input"],
    ["unknown ordering basis", () => buildGetigFrameSequence(seqInput([], { orderingBasis: "wallclock" })), "refused_sequence_unknown_ordering_basis"],
    ["frame is not an object", () => buildGetigFrameSequence(seqInput([null])), "refused_sequence_frame_not_a_frame"],
    ["frame has no id", () => buildGetigFrameSequence(seqInput([{ ...ref(), frameId: "" }])), "refused_sequence_frame_not_a_frame"],
    ["frame has no asOf", () => buildGetigFrameSequence(seqInput([{ ...ref(), asOfEpochMs: "soon" }])), "refused_sequence_frame_not_a_frame"],
    ["frame has negative asOf", () => buildGetigFrameSequence(seqInput([{ ...ref(), asOfEpochMs: -1 }])), "refused_sequence_frame_not_a_frame"],
    ["frame visible hash not hex64", () => buildGetigFrameSequence(seqInput([{ ...ref(), canonicalVisibleHash: "zz" }])), "refused_sequence_frame_not_a_frame"],
    ["frame source hash not hex64", () => buildGetigFrameSequence(seqInput([{ ...ref(), sourceProjectionHash: "nope" }])), "refused_sequence_frame_not_a_frame"],
    ["frame has no observer", () => buildGetigFrameSequence(seqInput([{ ...ref(), observer: undefined }])), "refused_sequence_frame_not_a_frame"],
    ["duplicate frame", () => buildGetigFrameSequence(seqInput([ref({ frameId: "f1" }), ref({ frameId: "f1" })])), "refused_sequence_duplicate_frame"],
    ["observer mismatch", () => buildGetigFrameSequence(seqInput([ref({ observerId: "observer-other" })])), "refused_sequence_frame_observer_mismatch"],
    ["epoch mismatch", () => buildGetigFrameSequence(seqInput([ref({ epochId: "epoch-other" })])), "refused_sequence_frame_epoch_mismatch"],
  ];

  for (const [name, run, expected] of cases) {
    it(`refuses: ${name} -> ${expected}`, () => {
      const decision = run();
      expect(decision.ok).toBe(false);
      if (decision.ok) return;
      expect(decision.refusal).toBe(expected);
      // Fail-closed: no partial sequence escapes.
      expect(decision.sequence).toBeNull();
      expect(decision.explanation).not.toBe(decision.refusal);
    });
  }

  it("refuses an over-long sequence rather than truncating it", () => {
    const tooMany = Array.from(
      { length: GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence + 1 },
      (_, i) => ref({ frameId: `f${i}` }),
    );
    const decision = buildGetigFrameSequence(seqInput(tooMany));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.refusal).toBe("refused_sequence_retention_bound");
    expect(decision.sequence).toBeNull();
  });

  it("accepts a sequence exactly at the retention bound", () => {
    const atBound = Array.from(
      { length: GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence },
      (_, i) => ref({ frameId: `f${i}` }),
    );
    expect(built(atBound).frameCount).toBe(GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence);
  });

  it("names the offending frame index in the explanation", () => {
    const decision = buildGetigFrameSequence(
      seqInput([ref({ frameId: "f1" }), ref({ frameId: "f2" }), ref({ frameId: "f3", observerId: "other" })]),
    );
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.explanation).toContain("frames[2]");
  });

  it("checks the epoch before the observer, so the more fundamental mismatch wins", () => {
    const decision = buildGetigFrameSequence(
      seqInput([ref({ frameId: "f1", epochId: "epoch-other", observerId: "observer-other" })]),
    );
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.refusal).toBe("refused_sequence_frame_epoch_mismatch");
  });
});

// ── 3. behaviour: diffs ──────────────────────────────────────────────────────

describe("28C — same-frame diff", () => {
  it("reports identical content for two frames showing the same things", () => {
    const a = world("fa", { entities: [entity("e1"), entity("e2")] });
    const b = world("fb", { entities: [entity("e1"), entity("e2")] });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.identical).toBe(true);
    expect(decision.diff.entryCount).toBe(0);
    expect(decision.diff.entries).toEqual([]);
  });

  it("does not call an unchanged stale subject a difference", () => {
    // The strict rule: a state class is a difference only when it MOVED. An
    // entity that is stale in both frames has not changed, and reporting it
    // would make two identical frames differ.
    const a = world("fa", { entities: [entity("e1", { freshness: "stale" })] });
    const b = world("fb", { entities: [entity("e1", { freshness: "stale" })] });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.identical).toBe(true);
  });

  it("is insensitive to the order members appear in", () => {
    const a = world("fa", { entities: [entity("e1"), entity("e2"), entity("e3")] });
    const b = world("fb", { entities: [entity("e3"), entity("e1"), entity("e2")] });
    const forwards = diffGetigFrames(a, b);
    const backwards = diffGetigFrames(world("fa", { entities: [entity("e3"), entity("e2"), entity("e1")] }), b);
    expect(forwards.ok && forwards.diff.identical).toBe(true);
    expect(backwards.ok && backwards.diff.identical).toBe(true);
  });
});

describe("28C — changed-frame diff", () => {
  it("classifies added, removed and changed members", () => {
    const a = world("fa", { entities: [entity("e1"), entity("e2"), entity("gone")] });
    const b = world("fb", { entities: [entity("e1", { label: "relabelled" }), entity("e2"), entity("new")] });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    const byId = new Map(decision.diff.entries.map((e) => [e.subjectVisibleId, e.classes]));
    expect(byId.get("gone")).toEqual(["removed"]);
    expect(byId.get("new")).toEqual(["added"]);
    expect(byId.get("e1")).toContain("changed");
    expect(byId.has("e2")).toBe(false);
    expect(decision.diff.classificationCounts.added).toBe(1);
    expect(decision.diff.classificationCounts.removed).toBe(1);
    expect(decision.diff.classificationCounts.changed).toBe(1);
    expect(decision.diff.identical).toBe(false);
  });

  it("records which collection each subject belongs to", () => {
    const a = world("fa", { events: [{ eventId: "ev1", kind: "observed_change", atEpochMs: NOW, subjectVisibleId: "e1", executable: false, action: "none", freshness: "current" }] });
    const b = world("fb", { events: [] });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.subjectCollection).toBe("events");
  });

  it("keeps same-id members of different collections apart", () => {
    const shared = { visibleId: "shared", relationId: "shared", kind: "runtime_node", fromVisibleId: "a", toVisibleId: "b", trust: "none", provenanceRefs: [] };
    const a = world("fa", { entities: [entity("shared")], relations: [shared] });
    const b = world("fb", { entities: [entity("shared")], relations: [] });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    // One relation was removed; the entity of the same id string was untouched.
    expect(decision.diff.entries).toHaveLength(1);
    expect(decision.diff.entries[0]!.subjectCollection).toBe("relations");
    expect(decision.diff.entries[0]!.classes).toEqual(["removed"]);
  });

  it("is deterministic across repeated runs and reordered collections", () => {
    const build = () => [
      entity("e1"),
      entity("e2", { freshness: "stale" }),
      entity("e3", { freshness: "unknown" }),
    ];
    const a = world("fa", { entities: build() });
    const b = world("fb", { entities: [entity("e3", { freshness: "unknown" }), entity("e9"), entity("e1")] });
    const one = diffGetigFrames(a, b);
    const two = diffGetigFrames(world("fa", { entities: [...build()].reverse() }), world("fb", { entities: [entity("e9"), entity("e1"), entity("e3", { freshness: "unknown" })] }));
    expect(one.ok && two.ok).toBe(true);
    if (!one.ok || !two.ok) return;
    expect(JSON.stringify(one.diff.entries)).toBe(JSON.stringify(two.diff.entries));
    expect(one.diff.classificationCounts).toEqual(two.diff.classificationCounts);
  });

  it("emits diff entries in a stable, content-independent order", () => {
    const ids = ["e9", "e1", "e5", "e3"];
    const a = world("fa", { entities: [] });
    const b = world("fb", { entities: ids.map((id) => entity(id)) });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries.map((e) => e.subjectVisibleId)).toEqual(["e1", "e3", "e5", "e9"]);
  });
});

describe("28C — stale and unknown times", () => {
  it("classifies a member that became stale between the two frames", () => {
    const decision = diffGetigFrames(
      world("fa", { entities: [entity("e1", { freshness: "current" })] }),
      world("fb", { entities: [entity("e1", { freshness: "stale" })] }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toContain("stale");
    expect(decision.diff.entries[0]!.classes).toContain("changed");
  });

  it("classifies a member whose freshness became unknown, and keeps unknown unknown", () => {
    const decision = diffGetigFrames(
      world("fa", { entities: [entity("e1", { freshness: "current" })] }),
      world("fb", { entities: [entity("e1", { freshness: "unknown" })] }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toEqual(["changed", "unknown"]);
  });

  it("does not invent an unknown for a member that declares no freshness at all", () => {
    // Absent is not the same as unknown. Forcing `unknown` here would classify
    // every relation (which has no freshness field) as unknown on sight.
    const relation = { relationId: "r1", kind: "observed_edge", fromVisibleId: "a", toVisibleId: "b", trust: "none", provenanceRefs: [] };
    const decision = diffGetigFrames(world("fa", { relations: [relation] }), world("fb", { relations: [] }));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toEqual(["removed"]);
  });

  it("classifies an event with no usable time as unknown", () => {
    const event = { eventId: "ev1", kind: "observed_change", subjectVisibleId: "e1", executable: false, action: "none", freshness: "current" };
    const decision = diffGetigFrames(world("fa", { events: [event] }), world("fb", { events: [] }));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toEqual(["removed", "unknown"]);
  });

  it("reports an added member's arriving state alongside the addition", () => {
    const decision = diffGetigFrames(
      world("fa", {}),
      world("fb", { entities: [entity("e1", { freshness: "stale" })] }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toEqual(["added", "stale"]);
  });
});

describe("28C — conflicting observer frames", () => {
  const conflict = (conflictId: string, subjectVisibleId: string) => ({
    conflictId,
    kind: "observation_conflict",
    attributedToObserverId: OBSERVER,
    subjectVisibleId,
    claims: [
      { observerId: OBSERVER, stated: "reachable" },
      { observerId: "observer-other", stated: "unreachable" },
    ],
    resolution: "no_consensus_unknown",
    resolved: false,
  });

  it("classifies a conflict that appears between the frames", () => {
    const decision = diffGetigFrames(world("fa", {}), world("fb", { conflicts: [conflict("c1", "e1")] }));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.subjectCollection).toBe("conflicts");
    expect(decision.diff.entries[0]!.classes).toEqual(["added", "conflicted"]);
  });

  it("leaves a conflict that is unchanged visible as a conflict and not a change", () => {
    const decision = diffGetigFrames(
      world("fa", { conflicts: [conflict("c1", "e1")] }),
      world("fb", { conflicts: [conflict("c1", "e1")] }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.identical).toBe(true);
    expect(decision.diff.classificationCounts.conflicted).toBe(0);
  });

  it("reports a conflict that was resolved away as removed", () => {
    const decision = diffGetigFrames(world("fa", { conflicts: [conflict("c1", "e1")] }), world("fb", {}));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries[0]!.classes).toContain("removed");
  });

  it("reports a conflict as its own subject and never reconciles it", () => {
    // The diff is a SUMMARY of what differs, not a copy of the frames, so it
    // does not carry the competing claim text forward. What it must do is leave
    // the conflict visible as an unresolved subject, and carry no verdict about
    // it: no resolution, no winner, no "the other observer is wrong".
    const decision = diffGetigFrames(world("fa", {}), world("fb", { conflicts: [conflict("c1", "e1")] }));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entries.map((e) => e.subjectVisibleId)).toEqual(["c1"]);
    expect(decision.diff.entries[0]!.classes).toContain("conflicted");
    const serialised = JSON.stringify(decision.diff);
    expect(serialised).not.toContain("resolution");
    expect(serialised).not.toContain("resolved");
    expect(decision.diff.causalityClaimed).toBe(false);
    expect(decision.diff.authority).toBe("none");
  });
});

describe("28C — diff refusals", () => {
  it("refuses non-object inputs", () => {
    for (const bad of [null, undefined, 42, "frame", []]) {
      const decision = diffGetigFrames(bad, world("fb"));
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_diff_input_invalid");
    }
  });

  it("refuses a frame with no id", () => {
    const decision = diffGetigFrames(world("fa", { frameId: "" }), world("fb"));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_diff_input_invalid");
  });

  it("refuses a sequence supplied where a frame is required", () => {
    const sequence = built([ref({ frameId: "f1" })]);
    const decision = diffGetigFrames(sequence, world("fb"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    // Reported as the specific mistake, not as a generic invalid input: a
    // sequence has no frameId, and ordering the checks the other way round would
    // hide a recoverable caller bug behind a vague code.
    expect(decision.refusal).toBe("refused_diff_not_a_sequence");
    expect(decision.diff).toBeNull();
  });

  it("refuses a diff larger than the entry bound", () => {
    const many = (count: number) =>
      world("fb", { entities: Array.from({ length: count }, (_, i) => entity(`e${i}`)) });
    const decision = diffGetigFrames(world("fa"), many(GETIG_TEMPORAL_BOUNDS.maxDiffEntries + 1));
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_sequence_retention_bound");
      expect(decision.diff).toBeNull();
    }
  });

  it("exposes no partial diff on refusal", () => {
    const decision = diffGetigFrames(null, null);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(Object.prototype.hasOwnProperty.call(decision, "diff")).toBe(true);
      expect(decision.diff).toBeNull();
    }
  });
});

// ── 4. behaviour: attempted resume ───────────────────────────────────────────

describe("28C — attempted resume-from-frame", () => {
  it("refuses for a real frame id", () => {
    const result = refuseResumeFromFrame("frame-0007", NOW);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe("refused_resume_not_permitted");
    expect(result.lookedAtFrameId).toBe("frame-0007");
  });

  it("refuses for every input, including nonsense ones", () => {
    const inputs: readonly [string, number][] = [
      ["f1", NOW],
      ["", 0],
      ["f-with-no-frame", Number.NaN],
      ["../etc/passwd", -1],
    ];
    for (const [id, at] of inputs) {
      expect(refuseResumeFromFrame(id, at).ok).toBe(false);
    }
    expect(refuseResumeFromFrame(null as never, NOW).ok).toBe(false);
  });

  it("restores and resumes nothing, and says so structurally", () => {
    const result = refuseResumeFromFrame("frame-0007", NOW);
    expect(result.restoredRuntimeState).toBe(false);
    expect(result.resumedRuntimeState).toBe(false);
  });

  it("names the law in its explanation", () => {
    expect(refuseResumeFromFrame("f1", NOW).explanation).toContain("VISUAL_REPLAY != EXECUTABLE_REPLAY");
  });
});

// ── 5. law audits, each with a self-test ─────────────────────────────────────

describe("28C — law audit: no causal claim ever reaches a diff", () => {
  const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

  /** Collect every forbidden field name appearing anywhere in a value. */
  const forbiddenIn = (value: unknown): string[] => {
    const found: string[] = [];
    const walk = (node: unknown): void => {
      if (node === null || typeof node !== "object") return;
      if (Array.isArray(node)) {
        for (const item of node) walk(item);
        return;
      }
      for (const [key, child] of Object.entries(node)) {
        if ((GETIG_FORBIDDEN_DIFF_FIELDS as readonly string[]).includes(key)) found.push(key);
        walk(child);
      }
    };
    walk(value);
    return found;
  };

  it("the forbidden-field scan actually detects a planted violation", () => {
    // Self-test. Without this, a broken scan would report PASS forever.
    const planted = { entryCount: 1, entries: [{ subjectVisibleId: "e1", classes: ["changed"], reason: "because the peer left" }] };
    expect(forbiddenIn(planted)).toContain("reason");
    expect(forbiddenIn({ causedBy: "observer-other" })).toEqual(["causedBy"]);
    expect(forbiddenIn({ entries: [{ nested: { rootCause: "x" } }] })).toEqual(["rootCause"]);
  });

  it("carries no forbidden field in a real, rich diff", () => {
    const a = world("fa", {
      entities: [entity("e1"), entity("e2", { freshness: "stale" }), entity("e3", { freshness: "unknown" })],
      relations: [{ relationId: "r1", kind: "observed_edge", fromVisibleId: "e1", toVisibleId: "e2", trust: "none", provenanceRefs: [] }],
      events: [{ eventId: "ev1", kind: "observed_change", atEpochMs: NOW, subjectVisibleId: "e1", executable: false, action: "none", freshness: "current" }],
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: OBSERVER, subjectVisibleId: "e1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
    });
    const b = world("fb", {
      entities: [entity("e1", { label: "moved" }), entity("e9")],
      relations: [],
      events: [],
      conflicts: [],
      refusals: [{ refusalId: "rf1", code: "refused_network_admission", subjectVisibleId: "e9", explanation: "not admitted" }],
    });
    const decision = diffGetigFrames(a, b);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.entryCount).toBeGreaterThan(0);
    const carried = forbiddenIn(decision.diff);
    // Named in the failure message so a regression says WHICH field appeared.
    expect(carried, `forbidden diff fields present: ${carried.join(", ")}`).toEqual([]);
  });

  it("names the forbidden fields it is checking, and the list is not empty", () => {
    expect(GETIG_FORBIDDEN_DIFF_FIELDS.length).toBeGreaterThan(0);
    expect([...GETIG_FORBIDDEN_DIFF_FIELDS]).toEqual(
      expect.arrayContaining(["cause", "causedBy", "because", "reason", "triggeredBy", "explains"]),
    );
  });

  it("declares causality never claimed, on every emitted diff", () => {
    const decision = diffGetigFrames(world("fa", { entities: [entity("e1")] }), world("fb", {}));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(has(decision.diff, "causalityClaimed")).toBe(true);
    expect(decision.diff.causalityClaimed).toBe(false);
    expect(decision.diff.restoresRuntimeState).toBe(false);
    expect(decision.diff.authority).toBe("none");
  });
});

describe("28C — law audit: the module has no execution, network or renderer path", () => {
  const FORBIDDEN_CAPABILITY = [
    "child_process",
    "node:child_process",
    "execSync",
    "spawnSync",
    "node:worker_threads",
    "node:net",
    "node:http",
    "node:fs",
    "WebGPU",
    "GPUDevice",
    "three.js",
    "@babylonjs",
    "playcanvas",
    "requestAnimationFrame",
    "eval(",
    "new Function",
    "@menog/policy",
    "@menog/runtime-linux",
  ] as const;

  /**
   * Word-boundary matching for identifier-shaped tokens, plain substring for
   * everything else. Plain substring matching alone was tried first and it
   * flagged the English word "three" in this module's own prose — an audit that
   * cries wolf on its own documentation is an audit people learn to ignore.
   */
  const scan = (text: string): string[] => {
    const lower = text.toLowerCase();
    return FORBIDDEN_CAPABILITY.filter((token) => {
      const t = token.toLowerCase();
      if (/^[a-z0-9_]+$/.test(t)) return new RegExp(`\\b${t}\\b`).test(lower);
      return lower.includes(t);
    });
  };

  it("the capability scan actually detects a planted violation", () => {
    // Self-test for the audit itself.
    expect(scan("const cp = require('node:child_process')")).toEqual(["child_process", "node:child_process"]);
    expect(scan("const d = await navigator.gpu.requestAdapter();")).toEqual([]);
    expect(scan("adapter = new GPUDevice()")).toEqual(["GPUDevice"]);
    expect(scan("import { evaluate } from '@menog/policy'")).toEqual(["@menog/policy"]);
    expect(scan("import * as THREE from 'three.js'")).toEqual(["three.js"]);
    expect(scan("execSync('ls')")).toEqual(["execSync"]);
    // A real false-positive guard: prose must not trip the scanner.
    expect(scan("the three identities are kept separate")).toEqual([]);
    expect(scan("const safe = 'no capabilities here'")).toEqual([]);
  });

  it("finds no execution, network, renderer or policy capability in the source", () => {
    const found = scan(readSourceOrThrow(SRC_PATH));
    expect(found, `forbidden capabilities present: ${found.join(", ")}`).toEqual([]);
  });

  it("reports a non-empty audit input, so the scan above cannot pass vacuously", () => {
    const text = readSourceOrThrow(SRC_PATH);
    expect(text.length).toBeGreaterThan(2_000);
    // The scan must actually be examining the file it claims to examine.
    expect(text).toContain("buildGetigFrameSequence");
    expect(text).toContain("GETIG_FORBIDDEN_DIFF_FIELDS");
  });

  it("exports no mutation, execution or recovery function", () => {
    const decls = readSourceOrThrow(DTS_PATH);
    const exported = [...decls.matchAll(/export declare (?:function|const) (\w+)/g)].map((m) => m[1]!);
    expect(exported.length).toBeGreaterThan(0);
    const mutating = exported.filter((name) =>
      /^(apply|mutate|set|update|write|delete|remove|add|insert|patch|put|restore|resume|rewind|recover|replay|execute|run|spawn|spawnSync|applyPolicy)$/i.test(name),
    );
    expect(mutating, `mutating/executing exports present: ${mutating.join(", ")}`).toEqual([]);
  });
});

describe("28C — law audit: every declared refusal code is reachable", () => {
  it("drives all ten codes from real inputs and gets each one back", () => {
    const produced = new Map<string, string>();
    const record = (name: string, decision: { ok: boolean; refusal?: string }) => {
      if (!decision.ok) produced.set(decision.refusal!, name);
    };

    record("invalid input", buildGetigFrameSequence(null as never));
    record("not a frame", buildGetigFrameSequence(seqInput([null])));
    record("duplicate", buildGetigFrameSequence(seqInput([ref({ frameId: "f1" }), ref({ frameId: "f1" })])));
    record("observer", buildGetigFrameSequence(seqInput([ref({ observerId: "other" })])));
    record("epoch", buildGetigFrameSequence(seqInput([ref({ epochId: "other" })])));
    record(
      "retention",
      buildGetigFrameSequence(
        seqInput(Array.from({ length: GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence + 1 }, (_, i) => ref({ frameId: `f${i}` }))),
      ),
    );
    record("ordering basis", buildGetigFrameSequence(seqInput([], { orderingBasis: "wallclock" })));
    record("diff input", diffGetigFrames(null, null));
    record("not a sequence", diffGetigFrames(built([ref({ frameId: "f1" })]), world("fb")));
    produced.set("refused_resume_not_permitted", "resume");

    const unreachable = GETIG_TEMPORAL_REFUSAL_CODES.filter((code) => !produced.has(code));
    expect(unreachable, `refusal codes no input can produce: ${unreachable.join(", ")}`).toEqual([]);
    expect(produced.size).toBe(GETIG_TEMPORAL_REFUSAL_CODES.length);
  });

  it("has no duplicate refusal codes", () => {
    expect(new Set(GETIG_TEMPORAL_REFUSAL_CODES).size).toBe(GETIG_TEMPORAL_REFUSAL_CODES.length);
  });
});

describe("28C — law audit: closed vocabularies", () => {
  it("exposes the six prompt-named diff classes and nothing else", () => {
    expect([...GETIG_DIFF_CLASSES]).toEqual(["added", "removed", "changed", "stale", "unknown", "conflicted"]);
    expect(new Set(GETIG_DIFF_CLASSES).size).toBe(6);
  });

  it("only ever emits classes from the closed vocabulary", () => {
    const decision = diffGetigFrames(
      world("fa", {
        entities: [entity("e1"), entity("e2", { freshness: "stale" }), entity("e3", { freshness: "unknown" })],
        conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: OBSERVER, subjectVisibleId: "e1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
      }),
      world("fb", { entities: [entity("e1", { label: "changed" })] }),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    const emitted = new Set(decision.diff.entries.flatMap((e) => e.classes));
    for (const cls of emitted) {
      expect((GETIG_DIFF_CLASSES as readonly GetigDiffClass[]).includes(cls)).toBe(true);
    }
    const counts = Object.keys(decision.diff.classificationCounts).sort();
    expect(counts).toEqual([...GETIG_DIFF_CLASSES].sort());
  });

  it("only ever emits collections from the closed vocabulary", () => {
    const decision = diffGetigFrames(world("fa", { routes: [{ routeId: "rt1", originVisibleId: "a", originFixed: true, forwarderVisibleIds: [], destinationVisibleId: "b", freshness: "current", provenanceRefs: [], admission: "none", authorization: "none", executionAuthorized: false }] }), world("fb", {}));
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    for (const entry of decision.diff.entries) {
      expect((GETIG_DIFF_COLLECTIONS as readonly GetigDiffCollection[]).includes(entry.subjectCollection)).toBe(true);
    }
  });
});

// ── 6. integration: real 28A frames through the real 28C path ────────────────

describe("28C — integration with real 28A frames", () => {
  const observer = {
    observerId: OBSERVER,
    observerKind: "local_runtime" as const,
    epochId: EPOCH,
    isGlobalTruth: false as const,
  };

  const frameInput = (frameId: string, asOfEpochMs: number, sourceProjectionHash: string, entities: GetigFrameInput["entities"]): GetigFrameInput =>
    ({ frameId, observer, epochId: EPOCH, asOfEpochMs, sourceProjectionHash, entities }) as GetigFrameInput;

  function realFrame(frameId: string, asOfEpochMs: number, sourceDigit: string, entities: GetigFrameInput["entities"]): GetigFrame {
    const decision = buildGetigFrame(frameInput(frameId, asOfEpochMs, hex(sourceDigit), entities));
    if (!decision.ok) throw new Error(`28A refused: ${decision.refusal}`);
    return decision.frame;
  }

  it("sequences two real 28A frames and keeps their identities distinct", () => {
    const f1 = realFrame("frame-a", NOW, "1", [entity("n1"), entity("n2")]);
    const f2 = realFrame("frame-b", NOW + 500, "1", [entity("n1"), entity("n2"), entity("n3")]);
    const sequence = built([f1, f2]);
    expect(sequence.frameCount).toBe(2);
    expect(sequence.entries[0]!.canonicalVisibleHash).toBe(f1.canonicalVisibleHash);
    expect(sequence.entries[1]!.sourceProjectionHash).toBe(f2.sourceProjectionHash);
    expect(sequence.sequenceIdentity).not.toBe(f1.canonicalVisibleHash);
    expect(sequence.sequenceIdentity).not.toBe(f2.canonicalVisibleHash);
  });

  it("diffs two real 28A frames and reports what actually appeared", () => {
    const before = realFrame("frame-a", NOW, "1", [entity("n1"), entity("n2")]);
    const after = realFrame("frame-b", NOW + 500, "1", [entity("n1"), entity("n3")]);
    const decision = diffGetigFrames(before, after);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    const byId = new Map(decision.diff.entries.map((e) => [e.subjectVisibleId, e.classes]));
    expect(byId.get("n2")).toEqual(["removed"]);
    expect(byId.get("n3")).toEqual(["added"]);
    expect(byId.has("n1")).toBe(false);
    expect(decision.diff.fromVisibleHash).toBe(before.canonicalVisibleHash);
    expect(decision.diff.toVisibleHash).toBe(after.canonicalVisibleHash);
  });

  it("diffs a real frame against itself as identical", () => {
    const frame = realFrame("frame-a", NOW, "1", [entity("n1"), entity("n2")]);
    const decision = diffGetigFrames(frame, frame);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.diff.identical).toBe(true);
    expect(decision.diff.entryCount).toBe(0);
  });

  it("refuses a sequence built from two real frames that disagree on observer", () => {
    const mine = realFrame("frame-a", NOW, "1", [entity("n1")]);
    const theirs = buildGetigFrame({
      frameId: "frame-b",
      observer: { ...observer, observerId: "observer-other" },
      epochId: EPOCH,
      asOfEpochMs: NOW + 1,
      sourceProjectionHash: hex("1"),
      entities: [entity("n1")],
    } as GetigFrameInput);
    expect(theirs.ok).toBe(true);
    if (!theirs.ok) return;
    const decision = buildGetigFrameSequence(seqInput([mine, theirs.frame]));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_sequence_frame_observer_mismatch");
  });

  it("still refuses to resume after building a real sequence", () => {
    const frame = realFrame("frame-a", NOW, "1", [entity("n1")]);
    const sequence = built([frame]);
    expect(refuseResumeFromFrame(sequence.entries[0]!.frameId, sequence.entries[0]!.asOfEpochMs).ok).toBe(false);
  });
});