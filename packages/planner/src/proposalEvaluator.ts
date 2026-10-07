import type { Actor, ModelProposal, MenogEventInput } from "@menog/core";
import { validateModelOutput } from "./modelValidation.js";
import type { ModelValidationResult, ValidateModelOutputOptions } from "./modelValidation.js";

export interface ProposalLedger {
  append(input: MenogEventInput): { ok: boolean };
}

export interface EvaluateProposalOptions extends ValidateModelOutputOptions {
  readonly proposal: ModelProposal;
  readonly ledger: ProposalLedger;
  readonly actor: Actor;
}

/**
 * Validates a model proposal and logs the result to the event ledger.
 * This guarantees the model text cannot bypass validation without leaving an audit trail.
 */
export function evaluateModelProposal(options: EvaluateProposalOptions): ModelValidationResult {
  const { proposal, ledger, actor, registry } = options;

  if (proposal.disposition !== "success" || !proposal.text) {
    ledger.append({
      eventId: `eval-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      eventType: "model_proposal_rejected_adapter",
      actor,
      resultSummary: {
        disposition: proposal.disposition,
        reason: proposal.reason ?? "Unknown adapter error",
      },
    });
    return {
      disposition: "rejected_malformed_json",
      reason: proposal.reason ?? "Adapter failed to produce proposal text.",
    };
  }

  const validation = validateModelOutput(proposal.text, { registry });
  
  if (validation.disposition !== "valid") {
    // Log prompt injections, schema mismatches, hallucinated tools
    ledger.append({
      eventId: `eval-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      eventType: "model_proposal_rejected_schema",
      actor,
      resultSummary: {
        disposition: validation.disposition,
        reason: validation.reason ?? "Validation failed.",
      },
    });
    return validation;
  }

  // The output is now a structurally frozen ValidatedModelPlan.
  // It cannot directly execute tools. Tool impersonation or policy overrides
  // in the raw JSON were completely discarded during normalize.
  
  ledger.append({
    eventId: `eval-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    timestamp: new Date().toISOString(),
    eventType: "model_proposal_accepted",
    actor,
    resultSummary: {
      plan: validation.plan,
    },
  });

  return validation;
}
