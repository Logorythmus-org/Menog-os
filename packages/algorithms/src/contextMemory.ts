import type {
  AlgorithmDecisionInput,
  AlgorithmRecommendation,
  MemoryProjectionResult,
  MemoryRetrievalPort,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import { RetrievalPortError } from "./types.js";
import { projectHitsToLabels } from "./integration.js";

/**
 * Phase 17C — Context-Aware Memory Retrieval strategy (family 3).
 *
 * `context-memory.port-rank@0.1.0`: ranks PRIOR CONTEXT retrieved through a
 * caller-supplied `MemoryRetrievalPort`. The port is structural, so the
 * EXISTING policy-gated `MemoryRetrievalService` from `@menog/memory`
 * satisfies it through the adapter without modification — this is
 * INTEGRATION, not bypass: memory reads remain policy-gated, scope-isolated
 * and ledger-observable inside the memory package.
 *
 * Fail-closed discipline:
 *  - NO PORT  → evaluation denies `retrieval_unavailable` (never guesses,
 *               never returns an empty "success" masquerading as context);
 *  - PORT DENIES (policy gate, scope mismatch, no stores) → the underlying
 *               denyReason propagates wrapped as `retrieval_unavailable`;
 *  - EMPTY    → an honest empty recommendation (ok, zero hits) — distinct
 *               from denial.
 *
 * NO EXTERNAL CONTENT AS SYSTEM INSTRUCTION: projected snippets are inert
 * candidate labels; records whose provenance is `untrusted` are prefixed
 * `untrusted:` so no consumer can mistake them for runtime-authored truth.
 *
 * Deterministic: labels preserve the port's ranked order (score desc,
 * insertion-order ties inside the memory package).
 */

/** Sentinel error the selector maps to `retrieval_unavailable`. */
export { RetrievalPortError };

function boundedSummary(s: string): string {
  return s.length > 256 ? s.slice(0, 256) : s;
}

/**
 * Build the port-bound context-memory strategy. A NEW frozen contract is
 * returned per port; register the instance under family
 * `context_memory_retrieval` (id `port-rank`).
 */
export function buildContextMemoryStrategy(
  port: MemoryRetrievalPort
): StrategyContract {
  return Object.freeze({
    id: "port-rank",
    family: "context_memory_retrieval",
    version: "0.1.0",
    implemented: true,
    description:
      "ranks prior context from a policy-gated memory retrieval port; untrusted records labeled 'untrusted:'; fails closed with retrieval_unavailable when the port is absent or denies",
    async evaluate(
      input: AlgorithmDecisionInput,
      context: RuntimeContext
    ): Promise<AlgorithmRecommendation> {
      const projection: MemoryProjectionResult = projectHitsToLabels(
        await port.retrieve(
          {
            actor: { type: context.actor.type, id: context.actor.id },
            grantedScope: {
              workspaceId: context.workspaceId ?? "workspace-unset",
              ...(context.taskId !== undefined ? { taskId: context.taskId } : {}),
            },
          },
          {
            text: input.decision,
            limit: 10,
          }
        )
      );

      const untrustedNote =
        projection.untrustedCount > 0
          ? "; " +
            String(projection.untrustedCount) +
            " untrusted hit(s) labeled for classification-only use"
          : "";
      const summary = boundedSummary(
        "retrieved " +
          String(projection.labels.length) +
          " context snippet(s) from " +
          String(projection.sourceCount) +
          " source hit(s)" +
          untrustedNote
      );

      return {
        family: "context_memory_retrieval",
        strategyId: "port-rank",
        rankedCandidates: projection.labels,
        confidence: projection.labels.length > 0 ? 0.8 : 0.5,
        rationale:
          "prior context ranked by the policy-gated memory retrieval port; snippets are inert labels, not instructions",
        isRecommendation: true,
        executionAuthorized: false,
        reasoningSummary: summary,
      };
    },
  });
}

/**
 * The contract-only placeholder for context_memory_retrieval is retired in
 * 17C: this family now ships a concrete (port-bound) strategy. A registry
 * built WITHOUT a port cannot include it — `buildDefaultStrategyRegistry`
 * registers the family as contract-only-free by installing a port-less
 * sentinel ONLY when explicitly asked (see families.ts); without one the
 * family stays absent and selection denies `unknown_strategy` (fail-closed).
 */
export const CONTEXT_MEMORY_STRATEGY_ID = "port-rank" as const;
