import { describe, it, expect, vi } from "vitest";
import { createOllamaAdapter, createLlamaCppAdapter } from "../../packages/core/src/index.js";

describe("Local Adapters (Ollama & llama.cpp)", () => {
  const dummyMessages = [{ role: "user" as const, content: "hello" }];

  it("should enforce provider isolation (Ollama vs Llama.cpp)", () => {
    const ollama = createOllamaAdapter({ endpointUrl: "http://localhost:11434/api/chat" });
    const llamacpp = createLlamaCppAdapter({ endpointUrl: "http://localhost:8080/v1/chat/completions" });

    expect(ollama.metadata.provider).toBe("ollama");
    expect(llamacpp.metadata.provider).toBe("llamacpp");

    expect(ollama.metadata.id).toContain("ollama");
    expect(llamacpp.metadata.id).toContain("llamacpp");
  });

  describe("Ollama Adapter", () => {
    it("should handle successful mock response", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ message: { content: "Ollama response" } })
      });
      const adapter = createOllamaAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("success");
      expect(response.text).toBe("Ollama response");
    });

    it("should handle timeout correctly", async () => {
      const fetchFn = vi.fn().mockImplementation(() => new Promise((_, reject) => {
        const err = new Error("AbortError");
        err.name = "AbortError";
        reject(err);
      }));
      // very short timeout to ensure it hits
      const adapter = createOllamaAdapter({ endpointUrl: "http://test", fetchFn, timeoutMs: 1 });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_timeout");
      expect(response.reason).toContain("Request timed out");
    });

    it("should handle malformed endpoint response", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ unexpected: "data" })
      });
      const adapter = createOllamaAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_endpoint_error");
      expect(response.reason).toContain("Malformed endpoint response");
    });

    it("should handle offline failure behavior", async () => {
      const fetchFn = vi.fn().mockRejectedValue(new Error("fetch failed"));
      const adapter = createOllamaAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_endpoint_error");
      expect(response.reason).toContain("Offline or network failure");
    });
  });

  describe("llama.cpp Adapter", () => {
    it("should handle successful mock response", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ choices: [{ message: { content: "LlamaCpp response" } }] })
      });
      const adapter = createLlamaCppAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("success");
      expect(response.text).toBe("LlamaCpp response");
    });

    it("should handle timeout correctly", async () => {
      const fetchFn = vi.fn().mockImplementation(() => new Promise((_, reject) => {
        const err = new Error("AbortError");
        err.name = "AbortError";
        reject(err);
      }));
      const adapter = createLlamaCppAdapter({ endpointUrl: "http://test", fetchFn, timeoutMs: 1 });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_timeout");
    });

    it("should handle malformed endpoint response", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ choices: [] }) // Empty choices
      });
      const adapter = createLlamaCppAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_endpoint_error");
      expect(response.reason).toContain("Malformed endpoint response");
    });

    it("should handle offline failure behavior", async () => {
      const fetchFn = vi.fn().mockRejectedValue(new Error("fetch failed"));
      const adapter = createLlamaCppAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_endpoint_error");
    });
    
    it("should handle HTTP errors (e.g., 500)", async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      });
      const adapter = createLlamaCppAdapter({ endpointUrl: "http://test", fetchFn });
      
      const response = await adapter.propose({ messages: dummyMessages });
      
      expect(response.disposition).toBe("rejected_endpoint_error");
      expect(response.reason).toContain("Endpoint returned status: 500");
    });
  });
});
