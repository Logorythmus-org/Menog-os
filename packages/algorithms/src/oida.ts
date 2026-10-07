import type {
  OidaAdvanceResult,
  OidaLoopState,
  OidaPhase,
  OidaStateValidation,
} from "./types.js";
import { ALGORITHM_MAX_OIDATA_ITERATIONS, OIDATA_PHASES } from "./types.js";

/**
 * Phase 17B — OIDA state machine (pure, caller-owned state).
 *
 * The OIDA loop (Observe → Interpret → Decide → Act) becomes an EXPLICIT
 * observable state machine with machine-readable invalid states:
 *
 *   observe → interpret → decide → act → observe (loop) | done
 *
 * State transitions are computed by these PURE functions; the strategy and
 * the caller own all state. Nothing here mutates, no hidden counters, no
 * timers, no I/O — equal states advance deterministically.
 *
 * Invalid states (all fail-closed with a reason string):
 *  - non-object / missing fields;
 *  - unknown phase;
 *  - done=true with phase !== "act";
 *  - non-integer, negative, or over-budget iteration
 *    (ALGORITHM_MAX_OIDATA_ITERATIONS);
 *  - advancing a done loop;
 *  - attempting to skip a phase or move backwards.
 */

const PHASE_ORDER: Readonly<Record<OidaPhase, number>> = Object.freeze({
  observe: 0,
  interpret: 1,
  decide: 2,
  act: 3,
});

/** The canonical initial OIDA loop state. */
export function initialOidaState(): OidaLoopState {
  return Object.freeze({ currentPhase: "observe", done: false, iteration: 0 });
}

/** Validate any value as a well-formed, in-budget OIDA loop state. */
export function validateOidaState(state: unknown): OidaStateValidation {
  if (state === null || typeof state !== "object" || Array.isArray(state)) {
    return { ok: false, reason: "oidaState must be an object" };
  }
  const s = state as Partial<OidaLoopState>;
  if (!isOidaPhaseField(s.currentPhase)) {
    return {
      ok: false,
      reason:
        "oidaState.currentPhase must be one of observe | interpret | decide | act; got '" +
        String(s.currentPhase) +
        "'",
    };
  }
  if (typeof s.done !== "boolean") {
    return { ok: false, reason: "oidaState.done must be boolean" };
  }
  if (s.done && s.currentPhase !== "act") {
    return {
      ok: false,
      reason:
        "oidaState.done=true is only legal with currentPhase='act'; got '" +
        s.currentPhase +
        "'",
    };
  }
  if (typeof s.iteration !== "number" || !Number.isInteger(s.iteration)) {
    return { ok: false, reason: "oidaState.iteration must be an integer" };
  }
  if (s.iteration < 0) {
    return { ok: false, reason: "oidaState.iteration must be >= 0" };
  }
  if (s.iteration > ALGORITHM_MAX_OIDATA_ITERATIONS) {
    return {
      ok: false,
      reason:
        "oidaState.iteration " +
        String(s.iteration) +
        " exceeds ALGORITHM_MAX_OIDATA_ITERATIONS (" +
        String(ALGORITHM_MAX_OIDATA_ITERATIONS) +
        ")",
    };
  }
  return { ok: true };
}

function isOidaPhaseField(value: unknown): value is OidaPhase {
  return value === "observe" || value === "interpret" || value === "decide" || value === "act";
}

/**
 * Compute the NEXT loop state from a validated current state.
 * Returns the new state and the phase the loop is now in. Fails closed on
 * invalid states, advancing a done loop, or attempts to skip/backtrack.
 *
 * Semantics (deterministic):
 *  - act  → observe, iteration + 1 (loop continues);
 *  - observe → interpret → decide are sequential single-step advances;
 *  - at decide, callers choose: advance once more to `act` (step), or mark
 *    the loop `done` via `completeOidaLoop`.
 */
export function advanceOida(state: OidaLoopState): OidaAdvanceResult {
  const valid = validateOidaState(state);
  if (!valid.ok) return valid;

  if (state.done) {
    return { ok: false, reason: "cannot advance a done OIDA loop" };
  }

  const idx = PHASE_ORDER[state.currentPhase];
  if (idx >= PHASE_ORDER.act) {
    // currentPhase === "act" (and not done): loop around.
    return {
      ok: true,
      state: Object.freeze({
        currentPhase: "observe",
        done: false,
        iteration: state.iteration + 1,
      }),
      phase: "observe",
    };
  }

  const nextPhase = OIDATA_PHASES[idx + 1]!;
  return {
    ok: true,
    state: Object.freeze({
      currentPhase: nextPhase,
      done: false,
      iteration: state.iteration,
    }),
    phase: nextPhase,
  };
}

/**
 * Mark a validated, non-done loop as done. Only legal from `act` (the
 * terminal phase): observing/interpreting/deciding loops are not complete.
 */
export function completeOidaLoop(state: OidaLoopState): OidaAdvanceResult {
  const valid = validateOidaState(state);
  if (!valid.ok) return valid;
  if (state.done) {
    return { ok: false, reason: "OIDA loop is already done" };
  }
  if (state.currentPhase !== "act") {
    return {
      ok: false,
      reason:
        "OIDA loop can only complete from phase 'act'; current phase is '" +
        state.currentPhase +
        "'",
    };
  }
  return {
    ok: true,
    state: Object.freeze({
      currentPhase: "act",
      done: true,
      iteration: state.iteration,
    }),
    phase: "act",
  };
}
