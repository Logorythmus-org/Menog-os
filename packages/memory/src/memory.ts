import type { Actor, MenogEventInput } from "@menog/core";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import type {
  MemoryPolicyGate,
  MemoryPreWriteCheckResult,
  MemoryRecord,
  MemoryRecordInput,
  MemoryReadResult,
  MemoryScope,
  MemoryWriteResult,
} from "./types.js";
import { MEMORY_SCHEMA_VERSION } from "./types.js";
import { findSecretKeyPaths } from "./secrets.js";
import {
  materializeMemoryRecord,
  memoryRecordHash,
  newMemoryId,
  validateMemoryRecordInput,
} from "./serialize.js";

/**
 * Phase 16A — Memory stores.
 *
 * `WorkingMemoryStore` (session/task-scoped, short-lived entries) and
 * `ProjectMemoryStore` (workspace-scoped, persistent entries) share one
 * behavior contract:
 *
 *  - NO READ WITHOUT POLICY: every read/write consults a MemoryPolicyGate;
 *    a missing gate denies (fail-closed).
 *  - NO WRITE WITHOUT SCOPE: writes are bound to the caller's granted scope;
 *    a caller cannot write into, or read from, another workspace/task/session.
 *  - Policy-observable: every ALLOWED read/write appends an event to the
 *    AppendOnlyLedger (denials are visible through the returned deny record;
 *    gate implementations may ledger denials themselves).
 *  - Structured runtime state: records are typed {scope, provenance,
 *    retention, body} objects, never a raw chat transcript.
 *  - Memory is advisory input: the stores expose data only, no execution
 *    authority, no capability grants.
 */

export const WORKING_MEMORY_MAX_RECORDS = 256;
export const PROJECT_MEMORY_MAX_RECORDS = 1024;

function scopeKey(scope: MemoryScope): string {
  return JSON.stringify([
    scope.workspaceId,
    scope.taskId ?? null,
    scope.sessionId ?? null,
  ]);
}

/**
 * True when `granted` covers `requested`. Scope isolation rule:
 *  - workspaceId must match exactly;
 *  - a granted taskId must be matched by the requested taskId (a caller
 *    granted a task scope cannot widen to the whole workspace);
 *  - a granted sessionId must be matched by the requested sessionId.
 * Narrowing is allowed; widening is not.
 */
export function scopeCovers(
  granted: MemoryScope,
  requested: MemoryScope
): boolean {
  if (granted.workspaceId !== requested.workspaceId) return false;
  if (granted.taskId !== undefined && granted.taskId !== requested.taskId) {
    return false;
  }
  if (granted.sessionId !== undefined && granted.sessionId !== requested.sessionId) {
    return false;
  }
  return true;
}

function isExpired(record: MemoryRecord, nowEpochMs: number): boolean {
  const exp = record.retention.expiresAtEpochMs;
  return typeof exp === "number" && nowEpochMs >= exp;
}

/** Default per-kind record caps (kind-specific defaults are applied by each subclass constructor). */

function memEvent(input: {
  readonly eventType: "memory_read" | "memory_write";
  readonly actor: Actor;
  readonly scope: MemoryScope;
  readonly memoryId: string;
  readonly kind: string;
  readonly outcome: "allow" | "deny";
  readonly denyReason?: string;
  readonly recordHash?: string;
  readonly recordCount?: number;
  readonly at: string;
}): MenogEventInput {
  return {
    eventId:
      "mem-" +
      input.eventType.replace("memory_", "") +
      "-" +
      newMemoryId("x").slice(2),
    timestamp: input.at,
    eventType: input.eventType,
    actor: { type: "runtime", id: "memory-store" },
    workspaceId: input.scope.workspaceId,
    taskId: input.scope.taskId,
    verb: "memory." + (input.eventType === "memory_read" ? "read" : "write"),
    capability: "memory",
    policyDecision: input.outcome,
    inputSummary: {
      schema: MEMORY_SCHEMA_VERSION,
      memoryKind: input.kind,
      memoryId: input.memoryId,
      callerActorType: input.actor.type,
      callerActorId: input.actor.id,
      scopeWorkspaceId: input.scope.workspaceId,
      scopeTaskId: input.scope.taskId ?? null,
      scopeSessionId: input.scope.sessionId ?? null,
    },
    resultSummary: {
      outcome: input.outcome,
      denyReason: input.denyReason ?? null,
      recordHash: input.recordHash ?? null,
      recordCount: input.recordCount ?? null,
    },
  };
}

export type MemoryStoreOptions = {
  /** Policy gate. Absent gate ⇒ all memory access denied (fail-closed). */
  readonly policyGate?: MemoryPolicyGate | null;
  /** Ledger every allowed read/write is announced to (policy-observable). */
  readonly ledger?: AppendOnlyLedger | null;
  /** Monotonic clock injection for deterministic retention tests. */
  readonly now?: () => number;
  /** Upper bound on retained records (oldest evicted, FIFO). */
  readonly maxRecords?: number;
  /**
   * Phase 16D (opt-in): reject writes whose body keys match the shared
   * secret-key hints (denyReason "secret_detected") instead of storing
   * them redacted. Default false — 16A behavior is preserved unless enabled.
   */
  readonly rejectSecretKeys?: boolean;
};

export type MemoryAccessContext = {
  /** Actor requesting access; used by the policy gate and audit events. */
  readonly actor: Actor;
  /** Scope the actor has been granted for this operation. */
  readonly grantedScope: MemoryScope;
};

export abstract class BaseMemoryStore {
  readonly #policyGate: MemoryPolicyGate | null;
  readonly #ledger: AppendOnlyLedger | null;
  readonly #now: () => number;
  readonly #maxRecords: number;
  readonly #rejectSecretKeys: boolean;
  readonly #records: Map<string, MemoryRecord> = new Map();
  /** Insertion order for FIFO eviction. */
  readonly #order: string[] = [];
  /** Deny events emitted for reads/writes since construction (observable). */
  readonly #deniedOps: Array<{ readonly op: "read" | "write"; readonly denyReason: string; readonly at: string }> = [];

  protected constructor(options: MemoryStoreOptions = {}) {
    this.#policyGate = options.policyGate ?? null;
    this.#ledger = options.ledger ?? null;
    this.#now = options.now ?? (() => Date.now());
    this.#maxRecords = options.maxRecords ?? WORKING_MEMORY_MAX_RECORDS;
    this.#rejectSecretKeys = options.rejectSecretKeys ?? false;
  }

  public abstract readonly kind: "working" | "project" | "execution";

  /** Number of LIVE (non-expired) records currently retained. */
  public get size(): number {
    this.#evictExpired();
    return this.#records.size;
  }

  /** Number of stored records including expired-but-not-yet-evicted ones. */
  public get rawSize(): number {
    return this.#records.size;
  }

  /** Denials observed at this store since construction (policy-observable). */
  public get deniedOperations(): ReadonlyArray<{
    readonly op: "read" | "write";
    readonly denyReason: string;
    readonly at: string;
  }> {
    return this.#deniedOps.slice();
  }

  public clearForTesting(): void {
    this.#records.clear();
    this.#order.length = 0;
  }

  /** Monotonic store clock (protected: subclass stores stamp their own metadata). */
  protected get nowMs(): number {
    return this.#now();
  }

  /**
   * Store-specific input policy hook (16B). Invoked after every authority
   * check (shape validation, policy gate, scope, provenance) has passed and
   * before the record is materialized. Default: reject secret-like keys when
   * `rejectSecretKeys` is enabled (16D), otherwise accept the input
   * unchanged. Returning a body REPLACES the caller's body (used by the
   * execution store to redact credential-shaped values before anything is
   * persisted).
   */
  protected preWriteCheck(
    input: MemoryRecordInput
  ): MemoryPreWriteCheckResult {
    if (this.#rejectSecretKeys) {
      const hits = findSecretKeyPaths(input.body, "");
      if (hits.length > 0) {
        return {
          ok: false,
          denyReason: "secret_detected",
          reason:
            "body key '" + hits[0]! + "' matches a secret-key pattern; store rejects secret channels (16D opt-in)",
        };
      }
    }
    return { ok: true, body: input.body };
  }

  /**
   * Read memory entries visible within `ctx.grantedScope`, newest first.
   * Denied when the policy gate refuses or the store is gate-less.
   */
  public read(ctx: MemoryAccessContext, filter: {
    readonly taskId?: string;
    readonly sessionId?: string;
    readonly memoryId?: string;
  } = {}): MemoryReadResult {
    const nowMs = this.#now();
    const at = new Date(nowMs).toISOString();
    const allowed =
      this.#policyGate !== null &&
      this.#policyGate.canReadMemory({
        actor: ctx.actor,
        scope: ctx.grantedScope,
      });
    if (!allowed) {
      this.#deniedOps.push({ op: "read", denyReason: "read_not_allowed", at });
      return {
        ok: false,
        denyReason: "read_not_allowed",
        reason: this.#policyGate === null
          ? "no policy gate configured; memory access is deny-by-default"
          : "policy gate denied memory read for actor '" + ctx.actor.id + "'",
      };
    }
    this.#evictExpired();
    const out: MemoryRecord[] = [];
    for (let i = this.#order.length - 1; i >= 0; i--) {
      const id = this.#order[i]!;
      const rec = this.#records.get(id);
      if (!rec) continue;
      if (!scopeCovers(ctx.grantedScope, rec.scope)) continue;
      // Optional narrowing filters must not widen access.
      if (filter.memoryId !== undefined && rec.memoryId !== filter.memoryId) continue;
      if (filter.taskId !== undefined && rec.scope.taskId !== filter.taskId) continue;
      if (filter.sessionId !== undefined && rec.scope.sessionId !== filter.sessionId) continue;
      out.push(rec);
    }
    const readEvent = memEvent({
      eventType: "memory_read",
      actor: ctx.actor,
      scope: ctx.grantedScope,
      memoryId: filter.memoryId ?? "*",
      kind: this.kind,
      outcome: "allow",
      recordCount: out.length,
      at,
    });
    const policyEventId = this.#appendLedger(readEvent);
    return {
      ok: true,
      records: Object.freeze(out),
      policyEventId,
    };
  }

  /**
   * Write one structured memory record. Denied unless the policy gate allows
   * the actor to write into exactly the requested scope.
   */
  public write(
    ctx: MemoryAccessContext,
    input: {
      readonly scope: MemoryScope;
      readonly provenance: MemoryRecord["provenance"];
      readonly retention: MemoryRecord["retention"];
      readonly body: Readonly<Record<string, unknown>>;
    }
  ): MemoryWriteResult {
    const nowMs = this.#now();
    const at = new Date(nowMs).toISOString();

    // Input hygiene runs BEFORE authority checks: malformed input is rejected
    // as invalid_input regardless of scope/policy state, and the policy gate
    // never observes a malformed scope object.
    const validationError = validateMemoryRecordInput({
      kind: this.kind,
      scope: input.scope,
      provenance: input.provenance,
      retention: input.retention,
      body: input.body,
    });
    if (validationError !== null) {
      this.#deniedOps.push({ op: "write", denyReason: "invalid_input", at });
      return {
        ok: false,
        denyReason: "invalid_input",
        reason: validationError,
      };
    }

    const allowed =
      this.#policyGate !== null &&
      this.#policyGate.canWriteMemory({
        actor: ctx.actor,
        scope: input.scope,
      });
    if (!allowed) {
      this.#deniedOps.push({ op: "write", denyReason: "write_not_allowed", at });
      return {
        ok: false,
        denyReason: "write_not_allowed",
        reason: this.#policyGate === null
          ? "no policy gate configured; memory access is deny-by-default"
          : "policy gate denied memory write for actor '" + ctx.actor.id + "'",
      };
    }
    if (!scopeCovers(ctx.grantedScope, input.scope)) {
      this.#deniedOps.push({ op: "write", denyReason: "scope_mismatch", at });
      return {
        ok: false,
        denyReason: "scope_mismatch",
        reason:
          "requested write scope " + scopeKey(input.scope) +
          " is outside granted scope " + scopeKey(ctx.grantedScope),
      };
    }
    // Untrusted provenance (tool/model/repo/external content) may never be
    // written as trusted runtime memory. It CAN be stored, but only with the
    // untrusted flag carried verbatim; a caller claiming trusted provenance
    // for externally-originated content is denied.
    const externallyOriginated =
      input.provenance.origin === "tool_output" ||
      input.provenance.origin === "model_output" ||
      input.provenance.origin === "repo_content" ||
      input.provenance.origin === "external";
    if (externallyOriginated && input.provenance.untrusted !== true) {
      this.#deniedOps.push({
        op: "write",
        denyReason: "untrusted_provenance_write_denied",
        at,
      });
      return {
        ok: false,
        denyReason: "untrusted_provenance_write_denied",
        reason:
          "provenance.origin '" + input.provenance.origin +
          "' is external content and must declare untrusted: true",
      };
    }

    // Store-specific input policy hook (16B execution memory: secret
    // exclusion, raw-blob limits, redaction). Runs AFTER all authority
    // checks pass; the returned body replaces the caller's body.
    const pre = this.preWriteCheck({
      kind: this.kind,
      scope: input.scope,
      provenance: input.provenance,
      retention: input.retention,
      body: input.body,
    });
    if (!pre.ok) {
      this.#deniedOps.push({ op: "write", denyReason: pre.denyReason, at });
      return { ok: false, denyReason: pre.denyReason, reason: pre.reason };
    }

    let record: MemoryRecord;
    try {
      record = materializeMemoryRecord(
        {
          kind: this.kind,
          scope: input.scope,
          provenance: input.provenance,
          retention: input.retention,
          body: pre.body,
        },
        { createdAtEpochMs: nowMs }
      );
    } catch (e) {
      this.#deniedOps.push({ op: "write", denyReason: "invalid_input", at });
      return {
        ok: false,
        denyReason: "invalid_input",
        reason: String((e as Error).message),
      };
    }

    this.#evictExpired();
    while (this.#records.size >= this.#maxRecords) {
      const oldest = this.#order.shift();
      if (oldest === undefined) break;
      this.#records.delete(oldest);
    }
    this.#records.set(record.memoryId, record);
    this.#order.push(record.memoryId);

    const writeEvent = memEvent({
      eventType: "memory_write",
      actor: ctx.actor,
      scope: input.scope,
      memoryId: record.memoryId,
      kind: this.kind,
      outcome: "allow",
      recordHash: memoryRecordHash(record),
      at,
    });
    const policyEventId = this.#appendLedger(writeEvent);
    return { ok: true, record, policyEventId };
  }

  /** Retrieve a single record by id (scope + policy checked). */
  public getById(ctx: MemoryAccessContext, memoryId: string): MemoryReadResult {
    return this.read(ctx, { memoryId });
  }

  #appendLedger(evt: MenogEventInput): string | undefined {
    if (this.#ledger === null) return undefined;
    const res = this.#ledger.append(evt);
    return res.ok && res.event ? res.event.eventId : undefined;
  }

  #evictExpired(): void {
    const nowMs = this.#now();
    for (let i = this.#order.length - 1; i >= 0; i--) {
      const id = this.#order[i]!;
      const rec = this.#records.get(id);
      if (!rec) continue;
      if (isExpired(rec, nowMs)) {
        this.#records.delete(id);
        this.#order.splice(i, 1);
      }
    }
  }
}

/**
 * Session/task-scoped memory: what the runtime learned DURING THIS RUN.
 * Entries default to short retention; the store is smaller and ephemeral.
 */
export class WorkingMemoryStore extends BaseMemoryStore {
  public readonly kind = "working" as const;

  public constructor(options: MemoryStoreOptions = {}) {
    super(
      options.maxRecords === undefined
        ? { ...options, maxRecords: WORKING_MEMORY_MAX_RECORDS }
        : options
    );
  }
}

/**
 * Workspace-scoped persistent memory: what was learned ABOUT THE PROJECT and
 * survives across sessions. Still structured, policy-gated, ledger-anchored.
 */
export class ProjectMemoryStore extends BaseMemoryStore {
  public readonly kind = "project" as const;

  public constructor(options: MemoryStoreOptions = {}) {
    super(
      options.maxRecords === undefined
        ? { ...options, maxRecords: PROJECT_MEMORY_MAX_RECORDS }
        : options
    );
  }
}
