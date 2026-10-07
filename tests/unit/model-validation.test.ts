import { describe, it, expect } from "vitest";
import { validateModelOutput } from "../../packages/planner/src/index.js";
import { VerbRegistry } from "../../packages/verbs/src/index.js";

const dummyRegistry = new VerbRegistry([
  {
    id: "fs.read",
    description: "Read a file",
    sideEffectClass: "read",
    requiredCapabilities: ["read_workspace"],
    replayable: true,
    reversible: false,
    inputSchemaVersion: "v0",
    outputSchemaVersion: "v0",
    executable: true,
  },
  {
    id: "fs.write",
    description: "Write a file",
    sideEffectClass: "write",
    requiredCapabilities: ["write_workspace"],
    replayable: false,
    reversible: true,
    inputSchemaVersion: "v0",
    outputSchemaVersion: "v0",
    executable: true,
  },
]);

describe("Model Output Validation", () => {
  it("should accept valid JSON and normalize safe fields", () => {
    const rawJson = JSON.stringify({
      verbs: [
        {
          verbId: "fs.read",
          capabilities: ["read_workspace"],
          description: "Reading some file",
          maliciousPayload: "exec rm -rf /" // Should be ignored
        }
      ],
      explanation: "Plan explanation",
      extraUnsafeField: { nested: "data" } // Should be ignored
    });

    const result = validateModelOutput(rawJson, { registry: dummyRegistry });
    
    expect(result.disposition).toBe("valid");
    expect(result.plan).toBeDefined();
    
    // Explicitly check normalization
    const planKeys = Object.keys(result.plan!);
    expect(planKeys).toEqual(["verbs", "explanation"]);
    const verb = result.plan!.verbs[0];
    expect(verb).toBeDefined();
    
    const verbKeys = Object.keys(verb!);
    expect(verbKeys).toEqual(["verbId", "capabilities", "description"]);
    
    expect(verb!.verbId).toBe("fs.read");
    expect((verb as any).maliciousPayload).toBeUndefined();
  });

  it("should reject hallucinated verbs", () => {
    const rawJson = JSON.stringify({
      verbs: [
        { verbId: "fs.read" },
        { verbId: "fs.hack" } // Hallucinated
      ]
    });

    const result = validateModelOutput(rawJson, { registry: dummyRegistry });
    expect(result.disposition).toBe("rejected_hallucinated_verb");
    expect(result.reason).toContain("fs.hack");
  });

  it("should reject hallucinated/unknown capabilities", () => {
    const rawJson = JSON.stringify({
      verbs: [
        { 
          verbId: "fs.read",
          capabilities: ["read_workspace", "read_passwords"] // read_passwords is not in VerbContract
        }
      ]
    });

    const result = validateModelOutput(rawJson, { registry: dummyRegistry });
    expect(result.disposition).toBe("rejected_hallucinated_capability");
    expect(result.reason).toContain("read_passwords");
  });

  it("should reject oversized output", () => {
    // 50KB limit
    const hugeDescription = "a".repeat(60000);
    const rawJson = JSON.stringify({
      verbs: [{ verbId: "fs.read", description: hugeDescription }]
    });

    const result = validateModelOutput(rawJson, { registry: dummyRegistry });
    expect(result.disposition).toBe("rejected_oversized");
  });

  it("should reject malformed JSON", () => {
    const rawJson = "{ verbs: [ 'fs.read' ] "; // syntax error
    const result = validateModelOutput(rawJson, { registry: dummyRegistry });
    expect(result.disposition).toBe("rejected_malformed_json");
  });

  it("should perform schema fuzz tests (schema mismatch)", () => {
    const tests = [
      "[]",
      '""',
      "null",
      JSON.stringify({ verbs: {} }), // verbs not array
      JSON.stringify({ verbs: [null] }),
      JSON.stringify({ verbs: ["fs.read"] }), // string instead of object
      JSON.stringify({ verbs: [{ verbId: 123 }] }), // verbId not string
      JSON.stringify({ verbs: [{ verbId: "fs.read", capabilities: "read" }] }), // caps not array
      JSON.stringify({ verbs: [{ verbId: "fs.read", capabilities: [123] }] }) // caps element not string
    ];

    for (const raw of tests) {
      const result = validateModelOutput(raw, { registry: dummyRegistry });
      expect(result.disposition).toBe("rejected_schema_mismatch");
    }
  });
});
