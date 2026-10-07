import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["tests/unit/**/*.test.ts", "tests/integration/**/*.test.ts", "tests/security/**/*.test.ts"],
    exclude: [
      "node_modules",
      "dist",
      "build",
      // FPR-R1 Bucket B: internal evidence audit tests — excluded from public candidate
      "tests/security/phase16-freeze-audit.test.ts",
      "tests/security/phase17-freeze-audit.test.ts",
      "tests/security/phase18-freeze-audit.test.ts",
      "tests/security/phase19-freeze-audit.test.ts",
      "tests/security/phase28k-freeze-audit.test.ts",
      "tests/unit/phase29k-r1-freeze-reconciliation.test.ts",
      "tests/unit/phase29k-reaudit-freeze.test.ts",
      // FPR-R1 Bucket B: governance-invariant reads of docs/release/PROMPT_*_REPORT.md
      "tests/security/agents-allocation-security.test.ts",
      "tests/security/agents-channels-security.test.ts",
      "tests/security/agents-recovery-security.test.ts",
      "tests/security/agents-security.test.ts",
      "tests/security/algorithms-integration-security.test.ts",
      "tests/security/algorithms-oida-goal-priority-security.test.ts",
      "tests/security/algorithms-security.test.ts",
      "tests/security/algorithms-self-monitoring-security.test.ts",
      "tests/security/semantiq-adapter-security.test.ts",
      "tests/security/semantiq-boundary-security.test.ts",
      "tests/security/semantiq-evaluation-events-security.test.ts",
      "tests/security/semantiq-evidence-transfer-security.test.ts",
      "tests/unit/gpu-render-plan.test.ts",
      "tests/unit/render-frame-composer.test.ts",
    ],
    typecheck: {
      enabled: false,
    },
  },
  resolve: {
    alias: {
      "@menog/algorithms": path.resolve(__dirname, "packages/algorithms/src/index.ts"),
      "@menog/semantiq": path.resolve(__dirname, "packages/semantiq/src/index.ts"),
      "@menog/verbs": path.resolve(__dirname, "packages/verbs/src/index.ts"),
      "@menog/shared": path.resolve(__dirname, "packages/shared/src/index.ts"),
      "@menog/core": path.resolve(__dirname, "packages/core/src/index.ts"),
      "@menog/agents": path.resolve(__dirname, "packages/agents/src/index.ts"),
      "@menog/event-ledger": path.resolve(__dirname, "packages/event-ledger/src/index.ts"),
      "@menog/policy": path.resolve(__dirname, "packages/policy/src/index.ts"),
      "@menog/runtime-linux": path.resolve(__dirname, "packages/runtime-linux/src/index.ts"),
      "@menog/planner": path.resolve(__dirname, "packages/planner/src/index.ts"),
      "@menog/commit-engine": path.resolve(__dirname, "packages/commit-engine/src/index.ts"),
      "@menog/memory": path.resolve(__dirname, "packages/memory/src/index.ts"),
      "@menog/durable-state": path.resolve(__dirname, "packages/durable-state/src/index.ts"),
      "@menog/cli": path.resolve(__dirname, "apps/cli/src/index.ts"),
    },
  },
});
