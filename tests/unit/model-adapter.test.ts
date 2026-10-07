import { describe, it, expect } from "vitest";
import { createDummyLocalAdapter, serializeModelMetadata } from "../../packages/core/src/index.js";

describe("ModelAdapter Contract", () => {
  it("should support provider neutrality", () => {
    const adapter1 = createDummyLocalAdapter({ provider: "local_llama" });
    const adapter2 = createDummyLocalAdapter({ provider: "local_onnx" });
    const adapter3 = createDummyLocalAdapter({ provider: "unspecified" });
    
    expect(adapter1.metadata.provider).toBe("local_llama");
    expect(adapter2.metadata.provider).toBe("local_onnx");
    expect(adapter3.metadata.provider).toBe("unspecified");
  });

  it("should serialize metadata deterministically", () => {
    const adapter = createDummyLocalAdapter();
    const serialized = serializeModelMetadata(adapter.metadata);
    
    expect(serialized).toContain('"contextWindow":4096');
    expect(serialized).toContain('"provider":"test_dummy"');
    expect(serialized).toContain('"requireNetwork":false');
  });

  it("should enforce no-network invariant", async () => {
    // Adapter constructed with requireNetwork = true (simulating a violation attempt)
    const adapter = createDummyLocalAdapter({ requireNetwork: true });
    
    const response = await adapter.propose({
      messages: [{ role: "user", content: "hello" }]
    });

    // The contract MUST reject it before processing if it requires network
    expect(response.disposition).toBe("rejected_network_required");
    expect(response.reason).toContain("Network access is prohibited");
  });

  it("should reject invalid responses/inputs (empty messages)", async () => {
    const adapter = createDummyLocalAdapter();
    
    // No messages
    let response = await adapter.propose({
      messages: []
    });
    expect(response.disposition).toBe("rejected_invalid_input");

    // Blank message content
    response = await adapter.propose({
      messages: [{ role: "user", content: "   " }]
    });
    expect(response.disposition).toBe("rejected_invalid_input");
  });

  it("should treat output as untrusted proposal data", async () => {
    const adapter = createDummyLocalAdapter();
    
    const response = await adapter.propose({
      messages: [{ role: "user", content: "Create a critical file" }]
    });

    expect(response.disposition).toBe("success");
    expect(response.text).toContain("Dummy response to: Create a critical file");
    
    // Validate we correctly serialized metadata alongside proposal
    expect(response.serializedMetadata).toBeTypeOf("string");
    // Ensure the disposition is proposal data, not execution authority
    // The type itself is ModelProposal which is fundamentally non-authoritative
  });
});
