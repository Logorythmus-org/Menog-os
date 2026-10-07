import type {
  AlgorithmDecisionInput,
  AlgorithmRecommendation,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import { OIDATA_PHASES } from "./types.js";
import { validateOidaState, advanceOida } from "./oida.js";

/**
 * Phase 17B — OIDA strategy (family 1 upgrade): `oida/loop-lite@0.2.0`.
 *
 * Upgrade over 17A's `loop-lite@0.1.0`:
 *  - accepts an explicit caller-owned `oidaState`;
 *  - recommends the next phase as a ranked candidate list;
 *  - computes `nextOidaState` (data for the caller — the caller owns state
 *    mutation; strategies never mutate);
 *  - emits a conclusion-only `reasoningSummary` (no chain-of-thought);
 *  - remains fully deterministic for deterministic inputs;
 *  - stays 17A-compatible: without `oidaState` it reproduces the 17A
 *    stateless behavior (sensitivity-ranked static phase list).
 *
 * Invalid `oidaState` (or an illegal transition) throws `OidaStateError`,
 * which the selector maps to the machine-readable `invalid_state` denial —
 * a malformed loop can never masquerade as a successful recommendation.
 *
 * Still recommend-only: the OIDA "act" recommendation never executes —
 * policy remains the sole authority and the runtime the sole executor.
 */

/** 17B semantic mapping: recommended phase → recommendation confidence. */
const PHASE_CONFIDENCE: Readonly<Record<string, number>> = Object.freeze({
  observe: 0.8,
  interpret: 0.85,
  decide: 0.9,
  act: 0.7,
});

function boundedSummary(s: string): string {
  return s.length > 256 ? s.slice(0, 256) : s;
}

export const oidaLoopLite: StrategyContract = Object.freeze({
  id: "loop-lite",
  family: "oida",
  version: "0.2.0",
  implemented: true,
  description:
    "stateful OIDA loop strategy: validates caller-owned oidaState, recommends the next phase (and state) deterministically; stateless mode preserves 17A behavior",
  async evaluate(
    input: AlgorithmDecisionInput,
    _context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    void _context;

    // Stateless mode (17A-compatible): no oidaState supplied.
    if (input.oidaState === undefined) {
      const phases: readonly string[] = OIDATA_PHASES;
      if (input.sensitivity === "untrusted_external") {
        return {
          family: "oida",
          strategyId: "loop-lite",
          rankedCandidates: ["interpret", ...phases.filter((p) => p !== "interpret")],
          confidence: 0.9,
          rationale:
            "untrusted external content must be classified before any decision or action is recommended",
          isRecommendation: true,
          executionAuthorized: false,
          reasoningSummary: "stateless ordering: interpret-first for untrusted_external input",
        };
      }
      return {
        family: "oida",
        strategyId: "loop-lite",
        rankedCandidates: [...phases],
        confidence: 0.8,
        rationale:
          "trusted decision input follows the canonical observe-first OIDA ordering",
        isRecommendation: true,
        executionAuthorized: false,
        reasoningSummary: "stateless ordering: canonical observe-first OIDA phases",
      };
    }

    // Stateful mode (17B): validate then compute next phase + state.
    const valid = validateOidaState(input.oidaState);
    if (!valid.ok) {
      throw new OidaStateError(valid.reason);
    }

    const adv = advanceOida(input.oidaState);
    if (!adv.ok) {
      throw new OidaStateError(adv.reason);
    }

    const next = adv.state;
    const phase = adv.phase;
    const looped = next.iteration !== input.oidaState.iteration;
    const summary = boundedSummary(
      "loop at " +
        input.oidaState.currentPhase +
        " (iteration " +
        String(input.oidaState.iteration) +
        ") recommends " +
        phase +
        " next" +
        (looped ? "; iteration advanced to " + String(next.iteration) : "")
    );

    return {
      family: "oida",
      strategyId: "loop-lite",
      rankedCandidates: [phase],
      confidence: PHASE_CONFIDENCE[phase] ?? 0.7,
      rationale: "deterministic OIDA advance: " + input.oidaState.currentPhase + " → " + phase,
      isRecommendation: true,
      executionAuthorized: false,
      reasoningSummary: summary,
      nextOidaState: next,
    };
  },
});

/** Sentinel error type the selector maps to the `invalid_state` denial. */
export class OidaStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidaStateError";
  }
}
