import { VerbRegistry, defaultVerbRegistry } from "@menog/verbs";

export type ModelValidationDisposition = 
  | "valid"
  | "rejected_oversized"
  | "rejected_malformed_json"
  | "rejected_schema_mismatch"
  | "rejected_hallucinated_verb"
  | "rejected_hallucinated_capability";

export interface ValidatedModelVerb {
  readonly verbId: string;
  readonly capabilities: readonly string[];
  readonly description: string;
}

export interface ValidatedModelPlan {
  readonly verbs: readonly ValidatedModelVerb[];
  readonly explanation: string;
}

export interface ModelValidationResult {
  readonly disposition: ModelValidationDisposition;
  readonly plan?: ValidatedModelPlan;
  readonly reason?: string;
}

const MAX_PAYLOAD_SIZE = 50 * 1024; // 50KB

export interface ValidateModelOutputOptions {
  readonly registry?: VerbRegistry;
}

export function validateModelOutput(
  rawJsonString: string,
  options?: ValidateModelOutputOptions
): ModelValidationResult {
  if (rawJsonString.length > MAX_PAYLOAD_SIZE) {
    return {
      disposition: "rejected_oversized",
      reason: `Payload size ${rawJsonString.length} exceeds limit of ${MAX_PAYLOAD_SIZE}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJsonString);
  } catch (err) {
    return {
      disposition: "rejected_malformed_json",
      reason: "Failed to parse JSON string.",
    };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      disposition: "rejected_schema_mismatch",
      reason: "Output must be a JSON object.",
    };
  }

  const obj = parsed as Record<string, unknown>;

  if (!Array.isArray(obj.verbs)) {
    return {
      disposition: "rejected_schema_mismatch",
      reason: "Missing or invalid 'verbs' array.",
    };
  }

  const registry = options?.registry ?? defaultVerbRegistry;
  const normalizedVerbs: ValidatedModelVerb[] = [];

  for (const item of obj.verbs) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return {
        disposition: "rejected_schema_mismatch",
        reason: "Each verb entry must be an object.",
      };
    }

    const verbObj = item as Record<string, unknown>;
    const verbId = verbObj.verbId;

    if (typeof verbId !== "string") {
      return {
        disposition: "rejected_schema_mismatch",
        reason: "Verb entry missing string 'verbId'.",
      };
    }

    const lookup = registry.get(verbId);
    if (!lookup.found) {
      return {
        disposition: "rejected_hallucinated_verb",
        reason: `Hallucinated verb: ${verbId}`,
      };
    }

    let description = "";
    if (typeof verbObj.description === "string") {
      description = verbObj.description;
    }

    const capabilities: string[] = [];
    if (verbObj.capabilities !== undefined) {
      if (!Array.isArray(verbObj.capabilities)) {
        return {
          disposition: "rejected_schema_mismatch",
          reason: "Capabilities must be an array of strings if present.",
        };
      }
      for (const cap of verbObj.capabilities) {
        if (typeof cap !== "string") {
          return {
            disposition: "rejected_schema_mismatch",
            reason: "Capability must be a string.",
          };
        }
        
        // Ensure the capability is known/required by this verb.
        // If the model asks for a capability this verb doesn't actually use/support, reject it.
        if (!lookup.verb.requiredCapabilities.includes(cap)) {
          return {
            disposition: "rejected_hallucinated_capability",
            reason: `Verb ${verbId} does not support capability: ${cap}`,
          };
        }
        
        capabilities.push(cap);
      }
    }

    // Normalize safe fields only. Ignore extra injected properties.
    normalizedVerbs.push(
      Object.freeze({
        verbId,
        capabilities: Object.freeze(capabilities),
        description,
      })
    );
  }

  let explanation = "";
  if (typeof obj.explanation === "string") {
    explanation = obj.explanation;
  }

  const validatedPlan: ValidatedModelPlan = Object.freeze({
    verbs: Object.freeze(normalizedVerbs),
    explanation,
  });

  return {
    disposition: "valid",
    plan: validatedPlan,
  };
}
