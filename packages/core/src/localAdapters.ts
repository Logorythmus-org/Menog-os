import type {
  ModelInput,
  ModelProposal,
  ModelMetadata,
  ModelAdapter,
} from "./types.js";
import { serializeModelMetadata } from "./modelAdapter.js";

export interface LocalAdapterOptions {
  readonly endpointUrl: string;
  readonly modelName?: string;
  readonly contextWindow?: number;
  readonly fetchFn?: typeof fetch;
  readonly timeoutMs?: number;
}

export function createOllamaAdapter(options: LocalAdapterOptions): ModelAdapter {
  const metadata: ModelMetadata = {
    id: `ollama-${options.modelName ?? "default"}`,
    provider: "ollama",
    requireNetwork: false, // Local endpoint invariant
    contextWindow: options.contextWindow ?? 4096,
  };
  
  const fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? 10000;

  return {
    metadata,
    async propose(input: ModelInput): Promise<ModelProposal> {
      if (!input.messages || input.messages.length === 0) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be empty.",
        };
      }
      
      if (input.messages.some(m => !m.content || m.content.trim() === "")) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be blank.",
        };
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchFn(options.endpointUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: options.modelName ?? "llama2",
            messages: input.messages,
            stream: false,
            options: {
              num_ctx: metadata.contextWindow,
              temperature: input.temperature,
              stop: input.stopSequences,
            },
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          return {
            disposition: "rejected_endpoint_error",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: `Endpoint returned status: ${response.status}`,
          };
        }

        const data = (await response.json().catch(() => null)) as any;
        if (!data || typeof data.message?.content !== "string") {
          return {
            disposition: "rejected_endpoint_error",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: "Malformed endpoint response.",
          };
        }

        return {
          disposition: "success",
          text: data.message.content,
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
        };
      } catch (err: unknown) {
        clearTimeout(timeoutId);
        
        if (err instanceof Error && err.name === "AbortError") {
          return {
            disposition: "rejected_timeout",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: "Request timed out.",
          };
        }

        return {
          disposition: "rejected_endpoint_error",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: `Offline or network failure: ${err instanceof Error ? err.message : "Unknown error"}`,
        };
      }
    },
  };
}

export function createLlamaCppAdapter(options: LocalAdapterOptions): ModelAdapter {
  const metadata: ModelMetadata = {
    id: `llamacpp-${options.modelName ?? "default"}`,
    provider: "llamacpp",
    requireNetwork: false, // Local endpoint invariant
    contextWindow: options.contextWindow ?? 4096,
  };
  
  const fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? 10000;

  return {
    metadata,
    async propose(input: ModelInput): Promise<ModelProposal> {
      if (!input.messages || input.messages.length === 0) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be empty.",
        };
      }
      
      if (input.messages.some(m => !m.content || m.content.trim() === "")) {
        return {
          disposition: "rejected_invalid_input",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: "Input messages cannot be blank.",
        };
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchFn(options.endpointUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer local", // Sometimes required by OpenAI compat layers
          },
          body: JSON.stringify({
            model: options.modelName ?? "default",
            messages: input.messages.map(m => ({
              role: m.role,
              content: m.content,
            })),
            stream: false,
            max_tokens: input.maxTokens,
            temperature: input.temperature,
            stop: input.stopSequences,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          return {
            disposition: "rejected_endpoint_error",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: `Endpoint returned status: ${response.status}`,
          };
        }

        const data = (await response.json().catch(() => null)) as any;
        if (!data || !Array.isArray(data.choices) || typeof data.choices[0]?.message?.content !== "string") {
          return {
            disposition: "rejected_endpoint_error",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: "Malformed endpoint response.",
          };
        }

        return {
          disposition: "success",
          text: data.choices[0].message.content,
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
        };
      } catch (err: unknown) {
        clearTimeout(timeoutId);
        
        if (err instanceof Error && err.name === "AbortError") {
          return {
            disposition: "rejected_timeout",
            metadata,
            serializedMetadata: serializeModelMetadata(metadata),
            reason: "Request timed out.",
          };
        }

        return {
          disposition: "rejected_endpoint_error",
          metadata,
          serializedMetadata: serializeModelMetadata(metadata),
          reason: `Offline or network failure: ${err instanceof Error ? err.message : "Unknown error"}`,
        };
      }
    },
  };
}
