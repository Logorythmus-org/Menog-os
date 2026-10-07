import type {
  ModelInput,
  ModelProposal,
  ModelMetadata,
  ModelAdapter,
} from "./types.js";

/**
 * Deterministically serializes model metadata for cryptographic event linking
 * and consistency checks.
 */
export function serializeModelMetadata(metadata: ModelMetadata): string {
  return JSON.stringify({
    contextWindow: metadata.contextWindow,
    id: metadata.id,
    provider: metadata.provider,
    requireNetwork: metadata.requireNetwork,
  });
}

/**
 * A dummy local model adapter used primarily for tests to ensure invariant enforcement.
 */
export function createDummyLocalAdapter(options?: {
  id?: string;
  provider?: ModelMetadata["provider"];
  requireNetwork?: boolean;
}): ModelAdapter {
  const metadata: ModelMetadata = {
    id: options?.id ?? "dummy-local-v1",
    provider: options?.provider ?? "test_dummy",
    requireNetwork: options?.requireNetwork ?? false,
    contextWindow: 4096,
  };

  return {
    metadata,
    async propose(input: ModelInput): Promise<ModelProposal> {
      // 1. Invariant: No Network
      if (metadata.requireNetwork) {
        return {
          disposition: "rejected_network_required",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Network access is prohibited by invariant.",
        };
      }

      // 2. Reject Invalid Input
      if (!input.messages || input.messages.length === 0) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be empty.",
        };
      }
      
      const hasEmptyMessages = input.messages.some(m => !m.content || m.content.trim() === "");
      if (hasEmptyMessages) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be blank.",
        };
      }

      // 3. Return untrusted proposal
      // The system should never use this as an authority, only as proposal data
      // that goes through a planner/verifier.
      return {
        disposition: "success",
        text: `Dummy response to: ${input.messages?.[input.messages.length - 1]?.content ?? ""}`,
        metadata,
        serializedMetadata: serializeModelMetadata(metadata),
      };
    },
  };
}
