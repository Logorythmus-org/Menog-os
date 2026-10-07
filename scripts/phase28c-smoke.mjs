/**
 * PHASE 28C — out-of-suite smoke check.
 *
 * This file exists so the 28C behaviours can be demonstrated against the BUILT
 * artefact (`dist/`) rather than only inside a suite that could be masking a
 * stale build. It is a development probe, not a gate test.
 *
 * It also demonstrates the failure mode this project has hit before: a check
 * that silently matches nothing reports success. Every probe below prints its
 * own name and observed value, and the script exits non-zero if any of them
 * disagrees with what is printed.
 */
import {
  buildGetigFrameSequence,
  diffGetigFrames,
  refuseResumeFromFrame,
  GETIG_TEMPORAL_REFUSAL_CODES,
  GETIG_FORBIDDEN_DIFF_FIELDS,
  GETIG_TEMPORAL_BOUNDS,
} from "../packages/durable-state/dist/index.js";

let failures = 0;
const check = (name, ok, observed) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${observed}`);
};

const H = (c) => String(c).repeat(64);
const frame = (id, visibleDigit, sourceDigit, observerId = "obs-a", epochId = "ep-1", asOfEpochMs = 1000) => ({
  frameId: id,
  asOfEpochMs,
  canonicalVisibleHash: H(visibleDigit),
  sourceProjectionHash: H(sourceDigit),
  epochId,
  observer: { observerId },
});

const seqOf = (frames, orderingBasis = "observed_order", extra = {}) =>
  buildGetigFrameSequence({
    sequenceId: "seq-1",
    observerId: "obs-a",
    epochId: "ep-1",
    orderingBasis,
    frames,
    ...extra,
  });

// determinism
const a = seqOf([frame("f1", 1, 7), frame("f2", 2, 7)]);
const b = seqOf([frame("f1", 1, 7), frame("f2", 2, 7)]);
check("sequence identity is deterministic", a.ok && b.ok && a.sequence.sequenceIdentity === b.sequence.sequenceIdentity,
  a.ok ? a.sequence.sequenceIdentity : a.explanation);

// the three identities are pairwise distinct
if (a.ok) {
  const distinct = new Set([
    a.sequence.entries[0].canonicalVisibleHash,
    a.sequence.entries[0].sourceProjectionHash,
    a.sequence.sequenceIdentity,
  ]);
  check("three identities are distinct", distinct.size === 3, `${distinct.size} distinct values`);
}

// reordered input keeps supplied positions and changes the sequence identity
const r = seqOf([frame("f2", 2, 7), frame("f1", 1, 7)]);
check("reordered input keeps positions", r.ok && r.sequence.entries.map((e) => e.frameId).join(",") === "f2,f1",
  r.ok ? r.sequence.entries.map((e) => `${e.position}:${e.frameId}`).join(" ") : r.explanation);
check("reordered input is a different sequence", r.ok && a.ok && r.sequence.sequenceIdentity !== a.sequence.sequenceIdentity,
  r.ok ? r.sequence.sequenceIdentity.slice(0, 16) : r.explanation);

// unknown ordering stays unknown, sequence-wide
const u = seqOf([frame("f1", 1, 7), frame("f2", 2, 7)], "unknown");
check("unknown basis -> no temporal order anywhere",
  u.ok && u.sequence.temporalOrderEstablished === false && u.sequence.entries.every((e) => !e.temporalOrderEstablished),
  u.ok ? `seq=${u.sequence.temporalOrderEstablished} entries=${u.sequence.entries.map((e) => e.temporalOrderEstablished).join(",")}` : u.explanation);

// every per-frame refusal mode
const malformed = [
  ["not a frame", [null], "observed_order", "refused_sequence_frame_not_a_frame"],
  ["bad frameId", [{ ...frame("f1", 1, 7), frameId: "" }], "observed_order", "refused_sequence_frame_not_a_frame"],
  ["duplicate frame", [frame("f1", 1, 7), frame("f1", 1, 7)], "observed_order", "refused_sequence_duplicate_frame"],
  ["observer mismatch", [frame("f1", 1, 7, "obs-b")], "observed_order", "refused_sequence_frame_observer_mismatch"],
  ["epoch mismatch", [frame("f1", 1, 7, "obs-a", "ep-9")], "observed_order", "refused_sequence_frame_epoch_mismatch"],
  ["non-hex hash", [{ ...frame("f1", 1, 7), canonicalVisibleHash: "zz" }], "observed_order", "refused_sequence_frame_not_a_frame"],
  ["unknown ordering basis", [frame("f1", 1, 7)], "wallclock", "refused_sequence_unknown_ordering_basis"],
  ["retention bound",
    Array.from({ length: GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence + 1 }, (_, i) => frame(`f${i}`, 1, 7)),
    "observed_order", "refused_sequence_retention_bound"],
];
for (const [name, frames, basis, expected] of malformed) {
  const res = seqOf(frames, basis);
  const got = res.ok ? "OK" : res.refusal;
  check(`refusal: ${name}`, !res.ok && got === expected && res.sequence === null, got);
}

// diff classification
const entity = (id, freshness) => ({ visibleId: id, kind: "node", label: id, freshness });
const worldFrame = (id, entities, extra = {}) => ({
  frameId: id,
  asOfEpochMs: 1000,
  canonicalVisibleHash: H(id.length),
  sourceProjectionHash: H(9),
  entities,
  relations: [],
  events: [],
  conflicts: [],
  refusals: [],
  routes: [],
  proposalFlows: [],
  ...extra,
});

const changed = diffGetigFrames(
  worldFrame("fa", [
    entity("e1", "current"),
    entity("e2", "stale"),
    entity("e3", "unknown"),
    entity("e4", "current"),
    entity("e5", "current"),
  ]),
  worldFrame("fb", [
    // e5 is the same subject with different content: that is a `changed`.
    { ...entity("e5", "current"), label: "renamed" },
    entity("e1", "current"),
    entity("e9", "current"),
  ]),
);
if (changed.ok) {
  const c = changed.diff.classificationCounts;
  check("diff classifies removed/changed/stale/unknown/added",
    c.removed === 3 && c.changed === 1 && c.added === 1 && c.stale === 1 && c.unknown === 1,
    JSON.stringify(c));
  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const carried = [
    ...GETIG_FORBIDDEN_DIFF_FIELDS.filter((f) => has(changed.diff, f)),
    ...changed.diff.entries.flatMap((e) =>
      GETIG_FORBIDDEN_DIFF_FIELDS.filter((f) => has(e, f)).map((f) => `entry.${f}`)),
  ];
  check("diff never carries a causal field", carried.length === 0, carried.join(",") || "none present");
  check("diff asserts no causality and restores nothing",
    changed.diff.causalityClaimed === false && changed.diff.restoresRuntimeState === false,
    `causalityClaimed=${changed.diff.causalityClaimed}`);
} else {
  check("diff built", false, changed.explanation);
}

const same = diffGetigFrames(worldFrame("fa", [entity("e1", "current")]), worldFrame("fb", [entity("e1", "current")]));
check("same frame content -> identical", same.ok && same.diff.identical, same.ok ? String(same.diff.identical) : same.explanation);

const shuffledA = worldFrame("fa", [entity("e1", "current"), entity("e2", "stale")]);
const shuffledB = worldFrame("fb", [entity("e2", "stale"), entity("e1", "current")]);
// both frames carry a stale entity; identical content must still diff as identical.
const deterministic = diffGetigFrames(shuffledA, shuffledB);
const deterministic2 = diffGetigFrames(shuffledA, shuffledB);
check("diff is deterministic and order-insensitive",
  deterministic.ok && deterministic2.ok && JSON.stringify(deterministic.diff) === JSON.stringify(deterministic2.diff)
  && deterministic.diff.identical,
  deterministic.ok ? JSON.stringify(deterministic.diff.entries) : deterministic.explanation);

// a sequence is not a frame
const asSeq = diffGetigFrames(a.ok ? a.sequence : {}, worldFrame("fb", []));
check("a sequence is refused as diff input", !asSeq.ok && asSeq.refusal === "refused_diff_not_a_sequence" && asSeq.diff === null,
  asSeq.ok ? "built" : asSeq.refusal);

// resume never resumes
const resume = refuseResumeFromFrame("f1", 1000);
check("resume always refuses", resume.ok === false && resume.refusal === "refused_resume_not_permitted"
  && resume.restoredRuntimeState === false && resume.resumedRuntimeState === false,
  resume.refusal);

// the remaining two refusal codes
const noSequenceId = buildGetigFrameSequence({ observerId: "obs-a", epochId: "ep-1", orderingBasis: "observed_order", frames: [] });
const badDiffInput = diffGetigFrames(null, worldFrame("fb", []));

// every declared refusal code was actually produced by something above
const produced = new Set([
  ...malformed.map(([, frames, basis]) => {
    const res = seqOf(frames, basis);
    return res.ok ? "OK" : res.refusal;
  }),
  ...(changed.ok ? [] : [changed.refusal]),
  ...(noSequenceId.ok ? [] : [noSequenceId.refusal]),
  ...(badDiffInput.ok ? [] : [badDiffInput.refusal]),
  asSeq.ok ? "OK" : asSeq.refusal,
  resume.refusal,
]);
const unreachable = GETIG_TEMPORAL_REFUSAL_CODES.filter((c) => !produced.has(c));
check("every declared refusal code is reachable", unreachable.length === 0,
  unreachable.length === 0 ? `all ${GETIG_TEMPORAL_REFUSAL_CODES.length} produced` : `unreachable: ${unreachable.join(", ")}`);

console.log(`\n28C smoke: ${failures === 0 ? "ALL PASS" : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);