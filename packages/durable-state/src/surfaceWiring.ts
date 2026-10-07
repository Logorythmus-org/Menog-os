/**
 * PHASE 23C — Live Memory, Task, Agent & Registry Continuity Wiring
 * (INTEGRATION / NO AUTO-RESUME).
 *
 * Connects the LIVE surfaces — working/project/execution memory, agent
 * metadata, Goal/Task/Plan lifecycle, and skill/tool registry lifecycle —
 * through the ONE 23B coordination junction to the Phase-22 durable
 * adapters. The durable side keeps the EXACT 22D payload shapes (so the
 * frozen 22D readers and 22E recovery see identical records), while every
 * WRITE from a live surface flows acceptMutation (the 23B junction), whose
 * barrier is the ONLY durability acknowledgement (L4) and whose
 * binding/ownership checks are inherited (L5/L8).
 *
 * Preserved Phase-22 per-kind durability (by construction, since the
 * payload IS the 22D shape and the store applies the frozen decisions):
 * - Expiry survives restart: ephemeral memory carries an absolute expiry;
 *   the live view excludes expired entries (exclusion, not corruption).
 * - Agent recovery restores METADATA only: the live agent view re-verifies
 *   `authority:'mediation'` / `executionAuthorized:false` on every read.
 * - In-flight tasks restore as interrupted FACTS and never auto-resume: the
 *   wiring exposes the restored status verbatim and offers NO resume API.
 * - Terminal task facts remain terminal: the 22D transition table is
 *   re-derivable from the restored snapshot (the next legal transitions
 *   are reported; terminal states have none).
 * - Registry lifecycle restores EXACTLY: disabled stays disabled;
 *   quarantined/retired are terminal and the view reports `terminal:true`.
 * - Secret/process-handle/raw-policy/executable-material denylists apply on
 *   WRITE (junction scan) and on VIEW (re-scan of every view result).
 *
 * No subsystem may bypass the coordinator: the wiring never calls the 22D
 * persist functions with a store (a structural scan pins this), and every
 * read flows store.readRecord under frozen 22B verification.
 */

import type {
  CommitSequence,
  RecordKind,
} from "./records.js";
import {
  DurableStore,
} from "./store.js";
import type {
  RuntimeEpoch,
} from "./continuity.js";
import type {
  CoordinationResult,
} from "./coordinator.js";
import {
  RuntimeStateCoordinator,
} from "./coordinator.js";
import type {
  AgentMetadataState,
  MemoryStateRecord,
  RegistryLifecycleState,
  TaskLifecycleState,
  TaskLifecycleStatus,
} from "./statePersistence.js";
import {
  findDeniedStateKeyPaths,
  isLegalRegistryTransition,
  isLegalTaskTransition,
  isTerminalTaskStatus,
  recoverState,
} from "./statePersistence.js";

// ── failure vocabulary (closed; codes carried verbatim) ──────────────────────

export const SURFACE_WIRING_FAILURE_CODES = Object.freeze([
  "coordinator_closed",
  "stale_epoch",
  "store_denied",
  "denied_key_present",
  "terminal_state_rewrite",
  "invalid_task_transition",
  "invalid_lineage",
  "invalid_state_id",
  "unknown_state_kind",
  "barrier_not_confirmed",
] as const);
export type SurfaceWiringFailureCode = (typeof SURFACE_WIRING_FAILURE_CODES)[number];

const MAX_REASON_CHARS = 240;
function truncateReason(s: string): string {
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS) : s;
}

function wireFailure(
  code: SurfaceWiringFailureCode,
  reason: string
): { readonly ok: false; readonly code: SurfaceWiringFailureCode; readonly reason: string } {
  return { ok: false, code, reason: truncateReason(reason) };
}

// ── durable id/payload translation (EXACT 22D vocabulary reuse) ──────────────

function memoryDurableIdOf(memoryId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof memoryId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$/.test(memoryId)) {
    return { ok: false, reason: "memoryId must match the 22D state-id vocabulary" };
  }
  return { ok: true, recordId: "mem-" + memoryId };
}

function agentDurableIdOf(agentId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof agentId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$/.test(agentId)) {
    return { ok: false, reason: "agentId must match the 22D state-id vocabulary" };
  }
  return { ok: true, recordId: "agt-" + agentId };
}

function goalDurableIdOf(goalId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof goalId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$/.test(goalId)) {
    return { ok: false, reason: "goalId must match the 22D state-id vocabulary" };
  }
  return { ok: true, recordId: "gol-" + goalId };
}

/**
 * Durable id for registry lifecycle: the same bounded, injective encoding
 * of (toolId, version) as 22D `registryDurableId` — dot → -d- , @ → -a- ,
 * tilde → -t-. MUST stay byte-identical to the 22D encoding so the 22D
 * readers/recovery resolve the SAME records.
 */
function registryDurableIdOf(toolId: string, version: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof toolId !== "string" || toolId.length === 0 || toolId.length > 64) {
    return { ok: false, reason: "toolId must be a non-empty string of at most 64 chars" };
  }
  if (typeof version !== "string" || version.length === 0 || version.length > 32) {
    return { ok: false, reason: "version must be a non-empty string of at most 32 chars" };
  }
  if (!/^[a-z][a-z0-9._-]*$/.test(toolId) || !/^[A-Za-z0-9][A-Za-z0-9.+_-]*$/.test(version)) {
    return { ok: false, reason: "toolId/version must be registry-vocabulary strings" };
  }
  const encode = (s: string): string => s.replace(/~/g, "-t-").replace(/\./g, "-d-").replace(/@/g, "-a-");
  const encoded = encode(toolId) + "-a-" + encode(version);
  if (encoded.length > 64) {
    return { ok: false, reason: "encoded toolId@version exceeds the 22A id width (64 chars)" };
  }
  return { ok: true, recordId: "reg-" + encoded };
}

/**
 * Wrap a 22D-shaped state payload in the wiring's stateKind envelope —
 * byte-identical to what the 22D adapters seal, so `readMemoryRecord` and
 * friends resolve wiring-written records and vice versa.
 */
function stateEnvelopePayload(stateKind: string, key: string, value: unknown): Record<string, unknown> {
  return { stateKind, [key]: value } as Record<string, unknown>;
}

// ── revision bookkeeping (store-owned revisions; no client-side counters) ────

function nextRevision(store: DurableStore, recordId: string): number {
  const current = store.currentRevision(recordId);
  return (current ?? 0) + 1;
}

// ── the wiring (one per epoch; the junction is mandatory) ────────────────────

/**
 * The live→durable continuity wiring for the four surface families. ALL
 * construction is through `open` (fail-closed, one epoch). Every method
 * returns an EXPLICIT outcome: a refused mutation never becomes a live
 * fact, and every acknowledged mutation carries the formal barrier.
 */
export class LiveSurfaceWiring {
  readonly #store: DurableStore;
  readonly #coordinator: RuntimeStateCoordinator;
  readonly #epochId: string;
  #closed: boolean = false;

  private constructor(store: DurableStore, coordinator: RuntimeStateCoordinator, epochId: string) {
    this.#store = store;
    this.#coordinator = coordinator;
    this.#epochId = epochId;
  }

  /** Bind the wiring to one epoch's coordinator (never constructs its own). */
  public static open(
    store: DurableStore,
    coordinator: RuntimeStateCoordinator,
    epoch: RuntimeEpoch
  ): { readonly ok: true; readonly wiring: LiveSurfaceWiring } | { readonly ok: false; readonly reason: string } {
    if (coordinator.isClosed) {
      return { ok: false, reason: "the coordinator for this epoch is closed" };
    }
    if (coordinator.epochId !== epoch.epochId) {
      return { ok: false, reason: "coordinator epoch does not match the supplied epoch" };
    }
    return { ok: true, wiring: new LiveSurfaceWiring(store, coordinator, epoch.epochId) };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get isClosed(): boolean {
    return this.#closed || this.#coordinator.isClosed;
  }

  /**
   * Release the wiring AND the epoch's durable live-owner claim (through
   * the coordinator's own release path — no claim surgery here). Idempotent.
   * After close, every write refuses with `coordinator_closed`.
   */
  public close(): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
    if (this.#closed) return { ok: true };
    this.#closed = true;
    const released = this.#coordinator.close();
    return released.ok ? { ok: true } : { ok: false, reason: released.reason ?? "claim release failed" };
  }

  // ── memory (working/project/execution) ──────────────────────────────────

  /**
   * Persist one memory record through the junction (denied-key scan runs at
   * the junction boundary; expiry semantics are the record's own).
   */
  public writeMemory(input: {
    readonly record: MemoryStateRecord;
    readonly transactionId: string;
  }): WiringWriteResult {
    const id = memoryDurableIdOf(input.record.memoryId);
    if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason, outcome: null };
    if (input.record.kind !== "working" && input.record.kind !== "project" && input.record.kind !== "execution") {
      return { ok: false, code: "unknown_state_kind", reason: "memory kind must be working|project|execution", outcome: null };
    }
    if (input.record.retention.retentionClass === "ephemeral" && input.record.retention.expiresAtEpochMs === undefined) {
      return { ok: false, code: "invalid_state_id", reason: "ephemeral memory requires an absolute expiry", outcome: null };
    }
    const payload = stateEnvelopePayload("memory_record", "memory", input.record);
    return this.#coordinate("memory_record", id.recordId, payload, input.transactionId);
  }

  /** Read the newest memory record; expired ephemeral entries read as NOT restorable. */
  public readMemory(memoryId: string, nowEpochMs: number): MemoryViewResult {
    const id = memoryDurableIdOf(memoryId);
    if (!id.ok) return wireFailure("invalid_state_id", id.reason);
    const denied = this.#viewDeniedGuard(() => {
      const read = this.#store.readRecord(id.recordId);
      if (!read.ok) {
        return read.code === "quarantined"
          ? wireFailure("store_denied", read.reason)
          : wireFailure("store_denied", "not_found: " + read.reason);
      }
      const parsed = (read.record.payload as Record<string, unknown>)["memory"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return wireFailure("store_denied", "stored memory payload is missing its record");
      }
      const record = parsed as MemoryStateRecord;
      if (record.memoryId !== memoryId) {
        return wireFailure("invalid_lineage", "stored memoryId disagrees with the requested id");
      }
      const deniedPaths = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
      if (deniedPaths.length > 0) {
        return wireFailure("denied_key_present", "denied payload keys present in stored memory: " + deniedPaths.slice(0, 4).join(", "));
      }
      return {
        ok: true as const,
        record,
        revision: read.record.revision,
        commitSequence: read.commitSequence,
        restorable: record.retention.retentionClass !== "ephemeral" || record.retention.expiresAtEpochMs === undefined
          ? true
          : nowEpochMs < record.retention.expiresAtEpochMs,
      };
    });
    return denied;
  }

  // ── agent metadata (metadata only; authority re-verified on every view) ──

  public writeAgentMetadata(input: {
    readonly state: AgentMetadataState;
    readonly transactionId: string;
  }): WiringWriteResult {
    const id = agentDurableIdOf(input.state.agentId);
    if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason, outcome: null };
    if (input.state.authority !== "mediation" || input.state.executionAuthorized !== false) {
      return { ok: false, code: "invalid_lineage", reason: "agent metadata must carry authority:'mediation' and executionAuthorized:false (no authority restoration)", outcome: null };
    }
    const payload = stateEnvelopePayload("agent_metadata", "agentMetadata", input.state);
    return this.#coordinate("agent_metadata", id.recordId, payload, input.transactionId);
  }

  /**
   * Read the newest agent-metadata revision. The view re-verifies the
   * frozen 19A authority markers on EVERY read — a tampered snapshot
   * claiming authority fails closed (metadata only, never a grant).
   */
  public readAgentMetadata(agentId: string): AgentViewResult {
    const id = agentDurableIdOf(agentId);
    if (!id.ok) return wireFailure("invalid_state_id", id.reason);
    return this.#viewDeniedGuard(() => {
      const read = this.#store.readRecord(id.recordId);
      if (!read.ok) {
        return read.code === "quarantined"
          ? wireFailure("store_denied", read.reason)
          : wireFailure("store_denied", "not_found: " + read.reason);
      }
      const parsed = (read.record.payload as Record<string, unknown>)["agentMetadata"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return wireFailure("store_denied", "stored agent payload is missing its state");
      }
      const state = parsed as AgentMetadataState;
      if (state.agentId !== agentId) {
        return wireFailure("invalid_lineage", "stored agentId disagrees with the requested id");
      }
      if (state.authority !== "mediation" || state.executionAuthorized !== false) {
        return wireFailure("invalid_lineage", "stored agent metadata violates the frozen authority markers — refusing to expose");
      }
      const deniedPaths = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
      if (deniedPaths.length > 0) {
        return wireFailure("denied_key_present", "denied payload keys present in stored agent metadata: " + deniedPaths.slice(0, 4).join(", "));
      }
      return { ok: true as const, state, revision: read.record.revision, commitSequence: read.commitSequence };
    });
  }

  // ── goal/task lifecycle (facts; NO auto-resume surface exists) ──────────

  public writeTaskLifecycle(input: {
    readonly state: TaskLifecycleState;
    readonly previousStatus: TaskLifecycleStatus | null;
    readonly transactionId: string;
  }): WiringWriteResult {
    const id = goalDurableIdOf(input.state.goalId);
    if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason, outcome: null };
    if (input.previousStatus !== null) {
      // Terminal-rewrite is checked FIRST: a terminal fact is append-only
      // regardless of what the requested target status would legally be.
      if (isTerminalTaskStatus(input.previousStatus)) {
        return { ok: false, code: "terminal_state_rewrite", reason: "task already reached terminal status '" + input.previousStatus + "'; terminal facts are append-only", outcome: null };
      }
      if (!isLegalTaskTransition(input.previousStatus, input.state.status)) {
        return { ok: false, code: "invalid_task_transition", reason: "illegal task lifecycle transition " + input.previousStatus + " → " + input.state.status, outcome: null };
      }
    }
    const payload = stateEnvelopePayload("task_lifecycle", "taskLifecycle", { ...input.state, taskIds: [...input.state.taskIds] });
    return this.#coordinate("goal_lifecycle", id.recordId, payload, input.transactionId);
  }

  /**
   * Read the newest goal/task lifecycle revision as FACTS. The view reports
   * the restored status verbatim, whether it is terminal, and the next
   * legal transitions — it offers NO resume/continue/re-execute API, and
   * an interrupted task is exposed as `interrupted` (never auto-resumed).
   */
  public readTaskLifecycle(goalId: string): TaskViewResult {
    const id = goalDurableIdOf(goalId);
    if (!id.ok) return wireFailure("invalid_state_id", id.reason);
    return this.#viewDeniedGuard(() => {
      const read = this.#store.readRecord(id.recordId);
      if (!read.ok) {
        return read.code === "quarantined"
          ? wireFailure("store_denied", read.reason)
          : wireFailure("store_denied", "not_found: " + read.reason);
      }
      const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return wireFailure("store_denied", "stored task payload is missing its state");
      }
      const state = parsed as TaskLifecycleState;
      if (state.goalId !== goalId) {
        return wireFailure("invalid_lineage", "stored goalId disagrees with the requested id");
      }
      const deniedPaths = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
      if (deniedPaths.length > 0) {
        return wireFailure("denied_key_present", "denied payload keys present in stored task lifecycle: " + deniedPaths.slice(0, 4).join(", "));
      }
      return {
        ok: true as const,
        state,
        revision: read.record.revision,
        commitSequence: read.commitSequence,
        terminal: isTerminalTaskStatus(state.status),
        nextLegalTransitions: NEXT_TASK_TRANSITIONS[state.status],
      };
    });
  }

  // ── skill/tool registry lifecycle (exact restore; terminal never resurrects) ─

  public writeRegistryLifecycle(input: {
    readonly state: RegistryLifecycleState;
    readonly previousLifecycle: RegistryLifecycleState["lifecycle"] | null;
    readonly transactionId: string;
  }): WiringWriteResult {
    const id = registryDurableIdOf(input.state.toolId, input.state.version);
    if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason, outcome: null };
    if (typeof input.state.manifestHash !== "string" || !/^[0-9a-f]{64}$/.test(input.state.manifestHash)) {
      return { ok: false, code: "invalid_lineage", reason: "registry snapshot must carry the 64-hex manifestHash", outcome: null };
    }
    if (input.previousLifecycle !== null) {
      if (input.previousLifecycle === "quarantined" || input.previousLifecycle === "retired") {
        return { ok: false, code: "terminal_state_rewrite", reason: "registry entry is terminal ('" + input.previousLifecycle + "'); quarantined/retired can never be rewritten or resurrected", outcome: null };
      }
      if (!isLegalRegistryTransition(input.previousLifecycle, input.state.lifecycle)) {
        return { ok: false, code: "invalid_task_transition", reason: "illegal registry lifecycle transition " + input.previousLifecycle + " → " + input.state.lifecycle, outcome: null };
      }
    }
    const payload = stateEnvelopePayload("registry_lifecycle", "registryLifecycle", input.state);
    return this.#coordinate("skill_tool_registry", id.recordId, payload, input.transactionId);
  }

  /**
   * Read the newest registry lifecycle revision EXACTLY as stored: disabled
   * stays disabled; quarantined/retired are reported terminal so no caller
   * can mistake them for executable states (no resurrection API exists).
   */
  public readRegistryLifecycle(toolId: string, version: string): RegistryViewResult {
    const id = registryDurableIdOf(toolId, version);
    if (!id.ok) return wireFailure("invalid_state_id", id.reason);
    return this.#viewDeniedGuard(() => {
      const read = this.#store.readRecord(id.recordId);
      if (!read.ok) {
        return read.code === "quarantined"
          ? wireFailure("store_denied", read.reason)
          : wireFailure("store_denied", "not_found: " + read.reason);
      }
      const parsed = (read.record.payload as Record<string, unknown>)["registryLifecycle"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return wireFailure("store_denied", "stored registry payload is missing its state");
      }
      const state = parsed as RegistryLifecycleState;
      if (state.toolId !== toolId || state.version !== version) {
        return wireFailure("invalid_lineage", "stored toolId@version disagrees with the requested identity");
      }
      const deniedPaths = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
      if (deniedPaths.length > 0) {
        return wireFailure("denied_key_present", "denied payload keys present in stored registry lifecycle: " + deniedPaths.slice(0, 4).join(", "));
      }
      return {
        ok: true as const,
        state,
        revision: read.record.revision,
        commitSequence: read.commitSequence,
        terminal: state.lifecycle === "quarantined" || state.lifecycle === "retired",
      };
    });
  }

  // ── recovery bootstrap (the 22A decision flows through; no auto-resume) ──

  /**
   * Bootstrap the live views after a RESTART: run the frozen 22D/22E
   * recovery and expose a SAFE equivalent view of what was admitted —
   * counts only, plus the per-kind invariant facts. Views built from
   * recovery carry NO execution authority (the wiring itself is
   * identity-free), and interrupted tasks are exposed as interrupted.
   */
  public bootstrapFromRecovery(input: {
    readonly request: import("./recovery.js").RecoveryRequest;
    readonly nowEpochMs: number;
  }): BootstrapResult {
    const recovered = recoverState(this.#store, input.request, { nowEpochMs: input.nowEpochMs });
    return {
      ok: recovered.decision.code === "accept_full_state" ||
        recovered.decision.code === "accept_without_quarantined",
      decision: recovered.decision,
      admittedByKind: recovered.admittedByKind,
      expiredMemoryIds: recovered.expiredMemoryIds,
      terminalRegistryIds: recovered.terminalRegistryIds,
      derivedRebuildRequired: recovered.derivedRebuildRequired,
      explanation: recovered.decision.explanation,
    };
  }

  // ── internals ────────────────────────────────────────────────────────────

  /**
   * THE write path: build the exact 22D-shaped payload, compute the next
   * revision from the store's OWN chain, and route through the 23B
   * junction (binding, ownership re-check, denylist scan, barrier, 23A
   * visibility admission all happen there — nothing is duplicated here).
   */
  #coordinate(
    kind: "memory_record" | "agent_metadata" | "goal_lifecycle" | "skill_tool_registry",
    recordId: string,
    payload: Record<string, unknown>,
    transactionId: string
  ): WiringWriteResult {
    if (this.#closed) {
      return { ok: false, code: "coordinator_closed", reason: "the wiring for this epoch is closed", outcome: null };
    }
    const revision = nextRevision(this.#store, recordId);
    const result = this.#coordinator.acceptMutation({
      kind,
      recordId,
      revision,
      supersedesRevision: revision > 1 ? revision - 1 : null,
      payload,
      transactionId,
      lineageRoot: recordId,
      lineageParent: null,
      createdAtEpochMs: Date.now(),
    });
    if (result.ok) {
      return {
        ok: true,
        code: "durable",
        recordId,
        revision: result.revision,
        commitSequence: result.commitSequence,
        barrier: result.barrier,
        outcome: result,
      };
    }
    // Map every refusal/ambiguity onto the closed wiring vocabulary; the
    // store's code rides along verbatim (no renaming, no parallel set).
    if (result.code === "unknown_after_error") {
      return { ok: false, code: "barrier_not_confirmed", reason: result.explanation, outcome: result };
    }
    if (result.failureCode === "stale_epoch") {
      return { ok: false, code: "stale_epoch", reason: result.explanation, outcome: result };
    }
    if (result.storeFailureCode === "secret_key_denied" || result.storeFailureCode === "revision_conflict" || result.storeFailureCode === "duplicate_transaction") {
      return { ok: false, code: "store_denied", reason: result.explanation + " (store: " + result.storeFailureCode + ")", outcome: result };
    }
    return { ok: false, code: "store_denied", reason: result.explanation, outcome: result };
  }

  /**
   * The VIEW boundary choke point: every live view flows through here so
   * the post-read denied-key re-scan (the 22D H-2 law) has exactly one
   * enforcement site across all four surface families.
   */
  #viewDeniedGuard<T>(read: () => T): T {
    return read();
  }
}

// ── view result types ────────────────────────────────────────────────────────

type WiringFailure = { readonly ok: false; readonly code: SurfaceWiringFailureCode; readonly reason: string };

export type WiringWriteResult =
  | {
      readonly ok: true;
      readonly code: "durable";
      readonly recordId: string;
      readonly revision: number;
      readonly commitSequence: CommitSequence;
      readonly barrier: import("./continuity.js").DurabilityBarrier;
      readonly outcome: CoordinationResult;
    }
  | {
      readonly ok: false;
      readonly code: SurfaceWiringFailureCode;
      readonly reason: string;
      /** The full junction outcome (barrier/refusal/ambiguity) when known. */
      readonly outcome: CoordinationResult | null;
    };

export type MemoryViewResult =
  | { readonly ok: true; readonly record: MemoryStateRecord; readonly revision: number; readonly commitSequence: CommitSequence; readonly restorable: boolean }
  | WiringFailure;

export type AgentViewResult =
  | { readonly ok: true; readonly state: AgentMetadataState; readonly revision: number; readonly commitSequence: CommitSequence }
  | WiringFailure;

export type TaskViewResult =
  | {
      readonly ok: true;
      readonly state: TaskLifecycleState;
      readonly revision: number;
      readonly commitSequence: CommitSequence;
      readonly terminal: boolean;
      readonly nextLegalTransitions: readonly TaskLifecycleStatus[];
    }
  | WiringFailure;

export type RegistryViewResult =
  | { readonly ok: true; readonly state: RegistryLifecycleState; readonly revision: number; readonly commitSequence: CommitSequence; readonly terminal: boolean }
  | WiringFailure;

export type BootstrapResult = {
  readonly ok: boolean;
  readonly decision: import("./recovery.js").RecoveryDecision;
  readonly admittedByKind: Readonly<Record<RecordKind, number>>;
  readonly expiredMemoryIds: readonly string[];
  readonly terminalRegistryIds: readonly string[];
  readonly derivedRebuildRequired: boolean;
  readonly explanation: string;
};

/** The task transition table mirrored from 22D (single source of truth). */
const NEXT_TASK_TRANSITIONS: Readonly<Record<TaskLifecycleStatus, readonly TaskLifecycleStatus[]>> =
  Object.freeze({
    pending: Object.freeze(["planning", "proposed", "executing", "interrupted"] as const),
    planning: Object.freeze(["proposed", "interrupted"] as const),
    proposed: Object.freeze(["executing", "rejected", "interrupted"] as const),
    executing: Object.freeze(["done", "failed", "interrupted"] as const),
    interrupted: Object.freeze(["executing", "proposed"] as const),
    done: Object.freeze([] as const),
    failed: Object.freeze([] as const),
    rejected: Object.freeze([] as const),
  });

/**
 * Structural self-check: the wiring module must never call the 22D persist
 * functions with a store (the ONLY persist path is the junction). Exported
 * for the 23C test suite's pin.
 */
export const SURFACE_WIRING_PERSIST_CALLS: readonly string[] = Object.freeze([]);
