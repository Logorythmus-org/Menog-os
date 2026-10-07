/**
 * PHASE 28C — TEMPORAL FRAMES & RUNTIME TIMELINE
 * (VISUAL HISTORY ONLY / IMMUTABLE / NO GLOBAL TIME / NO EXECUTABLE REPLAY)
 *
 * CENTRAL LAW: VISUAL_REPLAY != EXECUTABLE_REPLAY.
 *
 * This module builds immutable frame SEQUENCES and deterministic semantic DIFFS
 * between frames. It is visible history and nothing more.
 *
 * THE THREE IDENTITIES ARE KEPT SEPARATE, on purpose:
 *
 *   1. `sourceProjectionHash`   — the upstream evidence a frame was derived from
 *   2. `canonicalVisibleHash`   — what that one frame shows
 *   3. `sequenceIdentity`       — what the ORDERED SET of frame references is
 *
 * Collapsing any two of them would destroy a capability a later gate needs. Two
 * different sets of frames can hash alike while pointing at different evidence;
 * two different evidence projections can yield the same visible content; and a
 * sequence is a THIRD thing that is neither of its parts. A timeline that cannot
 * tell them apart cannot say which one changed — so a diff reports the first two
 * by their own names and never dresses a visible hash up as a sequence identity.
 *
 * NO GLOBAL DISTRIBUTED-TIME CLAIM:
 *
 * There is no clock here. Frames are not sorted into a pretended chronology. A
 * sequence carries an EXPLICIT ordering basis:
 *   · `"observed_order"` — the observer declares this is the order it saw, and
 *     the sequence records that claim as the observer's, not as a fact;
 *   · `"unknown"` — no ordering could be established, so NONE is asserted. Frame
 *     positions are kept as supplied and the sequence says so.
 *
 * "Unknown ordering stays unknown" is load-bearing: inventing a sort key for
 * frames whose times are not comparable would manufacture a history that never
 * happened. Positions are therefore written exactly as supplied, and a test
 * feeds shuffled frames to prove this module does not quietly repair them.
 *
 * CAUSALITY IS NEVER INVENTED:
 *
 * A diff records WHAT differs between two frames and nothing about WHY. There is
 * deliberately no `cause`, `reason`, `because`, `triggeredBy` or `explains` field
 * anywhere in the diff shape, and `GETIG_FORBIDDEN_DIFF_FIELDS` names them so a
 * later gate can prove they never appear — by scanning real diff output rather
 * than by trusting this comment.
 *
 * HISTORY NEVER RESTORES STATE:
 *
 * `refuseResumeFromFrame()` is the ONLY navigation-ish export, and it can only
 * ever refuse. Navigating to a past frame selects which visible frame is being
 * LOOKED AT. It does not restore, rewind, resume, recover or re-enter any runtime
 * state — and this module contains no mechanism by which it could.
 *
 * STABLE VISIBLE IDENTITY IS NEVER AUTHORITY:
 *
 * A frame id that persists across the sequence is a stable label for a visible
 * object. It confers nothing. Every sequence entry carries `authority: "none"`.
 *
 * FAIL-CLOSED, AND EVERY DECLARED REFUSAL IS REACHABLE:
 *
 * Each rejection has its own code and its own explanation. A declared code that
 * no input could ever produce is worse than no code at all, so the suite drives
 * every one of `GETIG_TEMPORAL_REFUSAL_CODES` from a real input and asserts that
 * it is the code that came back.
 */

import { canonicalHash } from "./canonical.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

/** How (or whether) the sequence's frame positions were established. */
export const GETIG_SEQUENCE_ORDERING_BASES = Object.freeze([
  "observed_order",
  "unknown",
] as const);
export type GetigSequenceOrderingBasis = (typeof GETIG_SEQUENCE_ORDERING_BASES)[number];

/** The closed set of semantic classifications a diff may report. */
export const GETIG_DIFF_CLASSES = Object.freeze([
  "added",
  "removed",
  "changed",
  "stale",
  "unknown",
  "conflicted",
] as const);
export type GetigDiffClass = (typeof GETIG_DIFF_CLASSES)[number];

/** The visible collections a diff can classify over. Mirrors the 28A frame. */
export const GETIG_DIFF_COLLECTIONS = Object.freeze([
  "entities",
  "relations",
  "events",
  "conflicts",
  "refusals",
  "routes",
  "proposalFlows",
] as const);
export type GetigDiffCollection = (typeof GETIG_DIFF_COLLECTIONS)[number];

/** 28C's own refusals. Every code here is driven by at least one real input. */
export const GETIG_TEMPORAL_REFUSAL_CODES = Object.freeze([
  "refused_sequence_invalid_input",
  "refused_sequence_frame_not_a_frame",
  "refused_sequence_duplicate_frame",
  "refused_sequence_frame_observer_mismatch",
  "refused_sequence_frame_epoch_mismatch",
  "refused_sequence_retention_bound",
  "refused_sequence_unknown_ordering_basis",
  "refused_diff_input_invalid",
  "refused_diff_not_a_sequence",
  "refused_resume_not_permitted",
] as const);
export type GetigTemporalRefusalCode = (typeof GETIG_TEMPORAL_REFUSAL_CODES)[number];

/**
 * Fields that would turn an observation into a causal claim. Their ABSENCE from
 * every diff is asserted against real emitted diffs by test; naming them here
 * makes the law auditable.
 */
export const GETIG_FORBIDDEN_DIFF_FIELDS = Object.freeze([
  "cause",
  "causedBy",
  "because",
  "reason",
  "triggeredBy",
  "explains",
  "causalChain",
  "rootCause",
  "blame",
  "responsibleFor",
] as const);
export type GetigForbiddenDiffField = (typeof GETIG_FORBIDDEN_DIFF_FIELDS)[number];

/** Bounded retention. A visible history is finite by construction. */
export const GETIG_TEMPORAL_BOUNDS = Object.freeze({
  maxFramesPerSequence: 128,
  maxDiffEntries: 512,
  maxIdChars: 128,
});

export const GETIG_TEMPORAL_SCHEMA_VERSION = "menog-getig-temporal/v0" as const;

// ── the shapes ───────────────────────────────────────────────────────────────

/**
 * A structural echo of what a frame must carry to be placeable in a sequence.
 * Declared here so 28C depends on the SHAPE, not on importing a builder — the
 * module reads frames, it never constructs or mutates one.
 */
export interface TemporalFrameRef {
  readonly frameId: string;
  readonly asOfEpochMs: number;
  readonly canonicalVisibleHash: string;
  readonly sourceProjectionHash: string;
  readonly epochId: string;
  readonly observer: { readonly observerId: string };
}

/** One immutable position in a sequence. */
export interface FrameSequenceEntry {
  /** Position as SUPPLIED, never re-sorted by this module. */
  readonly position: number;
  readonly frameId: string;
  /** The observer's own instant for this frame, echoed as metadata. */
  readonly asOfEpochMs: number;
  readonly canonicalVisibleHash: string;
  readonly sourceProjectionHash: string;
  readonly observerId: string;
  /**
   * Whether this entry's position means anything as TIME. When the sequence
   * basis is `unknown`, every entry says `false` — an unknown order is unknown
   * for the whole sequence, not per-entry.
   */
  readonly temporalOrderEstablished: boolean;
  /** Structural: a stable visible id confers nothing. */
  readonly authority: "none";
}

export interface GetigFrameSequence {
  readonly schemaVersion: typeof GETIG_TEMPORAL_SCHEMA_VERSION;
  readonly sequenceId: string;
  readonly observerId: string;
  readonly epochId: string;
  readonly orderingBasis: GetigSequenceOrderingBasis;
  /**
   * False when the basis is `unknown`. This is the honest answer to "does this
   * sequence claim a chronology?" — and the answer is allowed to be no.
   */
  readonly temporalOrderEstablished: boolean;
  /** The THIRD identity: the hash of the ordered set of frame references. */
  readonly sequenceIdentity: string;
  readonly frameCount: number;
  readonly entries: readonly FrameSequenceEntry[];
  /** VISUAL HISTORY ONLY. */
  readonly replaySemantics: "visual_history_not_executable";
  readonly restoresRuntimeState: false;
  readonly resumesRuntimeState: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly globalTruth: false;
}

/** One classified difference. Observation only — no cause, ever. */
export interface SemanticDiffEntry {
  readonly subjectVisibleId: string;
  /** Which visible collection the subject belongs to. */
  readonly subjectCollection: GetigDiffCollection;
  readonly classes: readonly GetigDiffClass[];
}

export interface SemanticDiff {
  /** Identity #1 of the left side: the frame's own visible content hash. */
  readonly fromFrameId: string;
  readonly fromVisibleHash: string;
  readonly fromSourceProjectionHash: string;
  /** Identity #1 of the right side. */
  readonly toFrameId: string;
  readonly toVisibleHash: string;
  readonly toSourceProjectionHash: string;
  /** True when both frames describe the SAME classified content. */
  readonly identical: boolean;
  readonly entries: readonly SemanticDiffEntry[];
  readonly entryCount: number;
  readonly classificationCounts: Readonly<Record<GetigDiffClass, number>>;
  /** Structural: a diff is an observation and never a causal claim. */
  readonly causalityClaimed: false;
  /** Structural: looking at a diff confers nothing and restores nothing. */
  readonly restoresRuntimeState: false;
  readonly authority: "none";
  readonly readOnly: true;
}

// ── decisions ────────────────────────────────────────────────────────────────

export type SequenceBuilt = {
  readonly ok: true;
  readonly code: "sequence_built";
  readonly sequence: GetigFrameSequence;
};
export type SequenceRefused = {
  readonly ok: false;
  readonly code: "sequence_refused";
  readonly refusal: GetigTemporalRefusalCode;
  readonly explanation: string;
  readonly sequenceId: string;
  /** Fail-closed: a refusal exposes no partial sequence. */
  readonly sequence: null;
};
export type SequenceDecision = SequenceBuilt | SequenceRefused;

export type DiffBuilt = {
  readonly ok: true;
  readonly code: "diff_computed";
  readonly diff: SemanticDiff;
};
export type DiffRefused = {
  readonly ok: false;
  readonly code: "diff_refused";
  readonly refusal: GetigTemporalRefusalCode;
  readonly explanation: string;
  /** Fail-closed: a refusal exposes no partial diff. */
  readonly diff: null;
};
export type DiffDecision = DiffBuilt | DiffRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= GETIG_TEMPORAL_BOUNDS.maxIdChars;
}

/** Code-unit comparison. Never `localeCompare`: a locale-dependent ordering
 *  would make the sequence identity machine-dependent. */
function byKey<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

/**
 * A subject key that cannot be confused with its parts. JSON encoding keeps it
 * unambiguous even for ids that contain punctuation.
 */
function diffKey(collection: GetigDiffCollection, id: string): string {
  return JSON.stringify([collection, id]);
}

/** The 28A visible collections, each with the id field that names a member. */
const DIFF_COLLECTION_ID_KEYS: Readonly<Record<GetigDiffCollection, string>> = Object.freeze({
  entities: "visibleId",
  relations: "relationId",
  events: "eventId",
  conflicts: "conflictId",
  refusals: "refusalId",
  routes: "routeId",
  proposalFlows: "proposalId",
});

// ── the ONE sequence builder ─────────────────────────────────────────────────

export function buildGetigFrameSequence(input: {
  readonly sequenceId: string;
  readonly observerId: string;
  readonly epochId: string;
  readonly orderingBasis: GetigSequenceOrderingBasis;
  readonly frames: readonly unknown[];
}): SequenceDecision {
  const refuse = (refusal: GetigTemporalRefusalCode, detail: string): SequenceRefused => ({
    ok: false,
    code: "sequence_refused",
    refusal,
    explanation: `the sequence was refused and no partial sequence was produced: ${detail}`,
    sequenceId: isRecord(input) && isId(input.sequenceId) ? input.sequenceId : "",
    sequence: null,
  });

  if (!isRecord(input)) {
    return {
      ok: false,
      code: "sequence_refused",
      refusal: "refused_sequence_invalid_input",
      explanation: "the sequence was refused and no partial sequence was produced: the builder input must be an object",
      sequenceId: "",
      sequence: null,
    };
  }
  if (!isId(input.sequenceId)) return refuse("refused_sequence_invalid_input", "sequenceId is missing or over-long");
  if (!isId(input.observerId)) return refuse("refused_sequence_invalid_input", "observerId is missing or over-long");
  if (!isId(input.epochId)) return refuse("refused_sequence_invalid_input", "epochId is missing or over-long");
  if (!(GETIG_SEQUENCE_ORDERING_BASES as readonly string[]).includes(String(input.orderingBasis))) {
    return refuse(
      "refused_sequence_unknown_ordering_basis",
      `"${String(input.orderingBasis)}" is not an ordering basis; refusing rather than guessing an order`,
    );
  }
  if (!Array.isArray(input.frames)) return refuse("refused_sequence_invalid_input", "frames must be an array");
  if (input.frames.length > GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence) {
    return refuse(
      "refused_sequence_retention_bound",
      `${input.frames.length} frames exceeds the retention bound of ${GETIG_TEMPORAL_BOUNDS.maxFramesPerSequence}`,
    );
  }

  const temporalOrderEstablished = input.orderingBasis === "observed_order";
  const seen = new Set<string>();
  const entries: FrameSequenceEntry[] = [];

  // One failure mode, one code, one frame index. The whole sequence is refused
  // because a partially-valid timeline is itself a claim about order.
  const reject = (index: number, refusal: GetigTemporalRefusalCode, detail: string): SequenceRefused =>
    refuse(refusal, `frames[${index}] ${detail}`);

  for (let index = 0; index < input.frames.length; index += 1) {
    const frame: unknown = input.frames[index];
    if (!isRecord(frame)) return reject(index, "refused_sequence_frame_not_a_frame", "is not an object");
    if (!isId(frame.frameId)) return reject(index, "refused_sequence_frame_not_a_frame", "has no usable frameId");
    if (typeof frame.asOfEpochMs !== "number" || !Number.isFinite(frame.asOfEpochMs) || frame.asOfEpochMs < 0) {
      return reject(index, "refused_sequence_frame_not_a_frame", "has no usable asOfEpochMs");
    }
    if (!isHex64(frame.canonicalVisibleHash)) {
      return reject(index, "refused_sequence_frame_not_a_frame", "has no usable canonicalVisibleHash");
    }
    if (!isHex64(frame.sourceProjectionHash)) {
      return reject(index, "refused_sequence_frame_not_a_frame", "has no usable sourceProjectionHash");
    }
    if (!isRecord(frame.observer) || !isId(frame.observer.observerId)) {
      return reject(index, "refused_sequence_frame_not_a_frame", "has no usable observer.observerId");
    }
    // Epoch first: a frame from another epoch is not this sequence's frame at
    // all, before any observer question is even asked.
    if (frame.epochId !== input.epochId) {
      return reject(index, "refused_sequence_frame_epoch_mismatch", `belongs to epoch "${String(frame.epochId)}"`);
    }
    // A sequence belongs to ONE observer. Mixing vantage points would
    // manufacture a global view — the exact law this phase forbids.
    if (frame.observer.observerId !== input.observerId) {
      return reject(index, "refused_sequence_frame_observer_mismatch", `was observed by "${frame.observer.observerId}"`);
    }
    if (seen.has(frame.frameId)) {
      return reject(index, "refused_sequence_duplicate_frame", `appears more than once`);
    }
    seen.add(frame.frameId);

    entries.push({
      // Position is AS SUPPLIED. This module never re-sorts frames, because a
      // sort would manufacture a chronology it has no evidence for.
      position: index,
      frameId: frame.frameId,
      asOfEpochMs: frame.asOfEpochMs,
      canonicalVisibleHash: frame.canonicalVisibleHash,
      sourceProjectionHash: frame.sourceProjectionHash,
      observerId: frame.observer.observerId,
      temporalOrderEstablished,
      authority: "none",
    });
    // Freeze each entry, not just the array that holds them: a frozen array of
    // mutable objects is not an immutable history.
    Object.freeze(entries[entries.length - 1]);
  }

  // The THIRD identity: a hash over the ordered REFERENCES. It is deliberately
  // NOT the hash of any frame, and not a hash of frame contents.
  const sequenceIdentity = canonicalHash({
    schemaVersion: GETIG_TEMPORAL_SCHEMA_VERSION,
    sequenceId: input.sequenceId,
    observerId: input.observerId,
    epochId: input.epochId,
    orderingBasis: input.orderingBasis,
    frames: entries.map((e) => ({
      frameId: e.frameId,
      asOfEpochMs: e.asOfEpochMs,
      canonicalVisibleHash: e.canonicalVisibleHash,
      sourceProjectionHash: e.sourceProjectionHash,
    })),
  });

  return {
    ok: true,
    code: "sequence_built",
    sequence: Object.freeze({
      schemaVersion: GETIG_TEMPORAL_SCHEMA_VERSION,
      sequenceId: input.sequenceId,
      observerId: input.observerId,
      epochId: input.epochId,
      orderingBasis: input.orderingBasis,
      temporalOrderEstablished,
      sequenceIdentity,
      frameCount: entries.length,
      entries: Object.freeze(entries),
      replaySemantics: "visual_history_not_executable",
      restoresRuntimeState: false,
      resumesRuntimeState: false,
      authority: "none",
      controlPlane: false,
      readOnly: true,
      globalTruth: false,
    }),
  };
}

// ── the ONE diff function ────────────────────────────────────────────────────

/** A single visible member, reduced to what a diff is allowed to observe. */
interface DiffSubject {
  readonly collection: GetigDiffCollection;
  readonly id: string;
  readonly hash: string;
  /** `null` when the subject simply does not declare freshness — NOT unknown. */
  readonly freshness: string | null;
  /** False when the subject's own time is absent or unusable. */
  readonly timeKnown: boolean;
  readonly conflicted: boolean;
}

/**
 * Compute a semantic diff between two frames.
 *
 * The diff says WHAT differs. It never says WHY, and it never asserts that one
 * frame caused the other — the two are two observations, not a story.
 *
 * A subject is keyed by (collection, id) rather than by id alone, so a relation
 * and an entity that happen to share an id string are two subjects and not one
 * conflated one.
 */
export function diffGetigFrames(from: unknown, to: unknown): DiffDecision {
  const refuse = (refusal: GetigTemporalRefusalCode, detail: string): DiffRefused => ({
    ok: false,
    code: "diff_refused",
    refusal,
    explanation: `the diff was refused and no partial diff was produced: ${detail}`,
    diff: null,
  });

  if (!isRecord(from) || !isRecord(to)) {
    return refuse("refused_diff_input_invalid", "both inputs must be frame-shaped objects");
  }
  // A SEQUENCE is not a frame, and this check comes FIRST on purpose: a sequence
  // has no `frameId`, so testing for `frameId` ahead of this would report a
  // generic "invalid input" for a specific, recoverable mistake. Diffing a
  // sequence would otherwise yield a silent "everything was removed" result,
  // which reads like an observation and is not one. Refuse, and say which it was.
  if (isId(from.sequenceIdentity) || isId(to.sequenceIdentity)
    || Array.isArray(from.entries) || Array.isArray(to.entries)) {
    return refuse("refused_diff_not_a_sequence", "a frame sequence was supplied where a single frame is required");
  }
  if (!isId(from.frameId) || !isId(to.frameId)) {
    return refuse("refused_diff_input_invalid", "frameId is required on both");
  }

  const collect = (frame: Record<string, unknown>): Map<string, DiffSubject> => {
    const subjects = new Map<string, DiffSubject>();
    for (const collection of GETIG_DIFF_COLLECTIONS) {
      const items = frame[collection];
      if (!Array.isArray(items)) continue;
      const idKey = DIFF_COLLECTION_ID_KEYS[collection];
      for (const item of items) {
        if (!isRecord(item)) continue;
        const id = item[idKey];
        if (!isId(id)) continue;
        const freshness = typeof item.freshness === "string" ? item.freshness : null;
        // An event is the one collection that names its own instant; a missing or
        // unusable one is an unknown time and is classified as such.
        const atMs = collection === "events" ? item.atEpochMs : undefined;
        const timeKnown = collection !== "events" || (typeof atMs === "number" && Number.isFinite(atMs));
        subjects.set(diffKey(collection, id), {
          collection,
          id,
          hash: canonicalHash(item),
          freshness,
          timeKnown,
          conflicted: collection === "conflicts",
        });
      }
    }
    return subjects;
  };

  const before = collect(from);
  const after = collect(to);

  const subjectKeys = byKey([...new Set([...before.keys(), ...after.keys()])], (k) => k);
  if (subjectKeys.length > GETIG_TEMPORAL_BOUNDS.maxDiffEntries) {
    return refuse(
      "refused_sequence_retention_bound",
      `${subjectKeys.length} diff entries exceeds the bound of ${GETIG_TEMPORAL_BOUNDS.maxDiffEntries}`,
    );
  }

  const counts: Record<GetigDiffClass, number> = {
    added: 0,
    removed: 0,
    changed: 0,
    stale: 0,
    unknown: 0,
    conflicted: 0,
  };

  const entries: SemanticDiffEntry[] = [];
  for (const key of subjectKeys) {
    const b = before.get(key);
    const a = after.get(key);
    const live0 = a ?? b;
    if (!live0) continue;
    const collection = live0.collection;
    const id = live0.id;
    const classes: GetigDiffClass[] = [];

    if (!b && a) classes.push("added");
    else if (b && !a) classes.push("removed");
    else if (b && a && b.hash !== a.hash) classes.push("changed");

    // Freshness, conflict and time are observations about the SAME subject, and
    // they are NEVER presented as the reason for a structural difference.
    //
    // They are reported on a strict rule, because the loose version is a lie:
    // an entity that is stale in BOTH frames has not changed, and calling that a
    // difference would make two identical frames differ. So a state class is
    // reported when the subject appeared or disappeared (its arriving/leaving
    // state is worth recording), or when that state actually MOVED between the
    // two frames. Anything else is not a difference and is not reported.
    const live = live0;
    const freshnessMoved = !b || !a || b.freshness !== a.freshness;
    const timeMoved = !b || !a || b.timeKnown !== a.timeKnown;
    const conflictMoved = !b || !a || b.conflicted !== a.conflicted;
    if (freshnessMoved) {
      if (live.freshness === "stale") classes.push("stale");
      if (live.freshness === "unknown") classes.push("unknown");
    }
    if (timeMoved && !live.timeKnown) classes.push("unknown");
    if (conflictMoved && live.conflicted) classes.push("conflicted");

    if (classes.length === 0) continue;
    for (const c of classes) counts[c] += 1;
    entries.push({ subjectVisibleId: id, subjectCollection: collection, classes: Object.freeze(classes) });
  }

  const hex = (value: unknown): string => (typeof value === "string" ? value : "");

  return {
    ok: true,
    code: "diff_computed",
    diff: Object.freeze({
      fromFrameId: from.frameId,
      fromVisibleHash: hex(from.canonicalVisibleHash),
      fromSourceProjectionHash: hex(from.sourceProjectionHash),
      toFrameId: to.frameId,
      toVisibleHash: hex(to.canonicalVisibleHash),
      toSourceProjectionHash: hex(to.sourceProjectionHash),
      identical: entries.length === 0,
      entries: Object.freeze(entries),
      entryCount: entries.length,
      classificationCounts: Object.freeze(counts),
      // Structural: this gate never asserts that one frame caused another.
      causalityClaimed: false,
      restoresRuntimeState: false,
      authority: "none",
      readOnly: true,
    }),
  };
}

// ── the resume guard ─────────────────────────────────────────────────────────

/**
 * Historical navigation NEVER restores runtime state.
 *
 * This is the ONLY navigation-adjacent export in the module, and it cannot
 * succeed under any input. It exists so the law is TESTABLE rather than merely
 * absent: a reader can require that it is the sole such export and that it
 * always refuses.
 *
 * Looking at a past frame selects which visible frame is displayed. That is a
 * read. Restoring the runtime to a past state is not a read, and there is no
 * code path here that could attempt it.
 */
export function refuseResumeFromFrame(
  frameId: string,
  _asOfEpochMs: number,
): {
  readonly ok: false;
  readonly code: "resume_refused";
  readonly refusal: "refused_resume_not_permitted";
  readonly explanation: string;
  readonly lookedAtFrameId: string;
  readonly restoredRuntimeState: false;
  readonly resumedRuntimeState: false;
} {
  return {
    ok: false,
    code: "resume_refused",
    refusal: "refused_resume_not_permitted",
    explanation:
      "navigating to a historical frame selects which visible frame is being LOOKED AT; it never restores, resumes or recovers runtime state. VISUAL_REPLAY != EXECUTABLE_REPLAY.",
    lookedAtFrameId: typeof frameId === "string" ? frameId : "",
    restoredRuntimeState: false,
    resumedRuntimeState: false,
  };
}