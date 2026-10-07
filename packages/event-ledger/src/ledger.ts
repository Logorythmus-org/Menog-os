import { existsSync, mkdirSync, readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { MenogEvent, MenogEventInput } from "@menog/core";
import {
  MAX_LINE_BYTES,
  GENESIS_PREVIOUS_HASH,
  computeEventHash,
  serializeEventForHash,
  sha256Hex,
  redactSummary,
} from "./crypto.js";

export interface AppendResult {
  readonly ok: boolean;
  readonly event?: Readonly<MenogEvent>;
  readonly reason?: string;
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly reasons: readonly string[];
  readonly verifiedCount: number;
  readonly totalCount: number;
}

export interface LedgerConstructorOptions {
  readonly maxLineBytes?: number;
}

function nonEmptyString(value: unknown, fieldName: string): string | null {
  if (typeof value !== "string" || value.length === 0) {
    return "missing field '" + fieldName + "'";
  }
  return null;
}

function validateEventInput(
  input: MenogEventInput
): string | null {
  const errEventId = nonEmptyString(input.eventId, "eventId");
  if (errEventId) return errEventId;
  const errTs = nonEmptyString(input.timestamp, "timestamp");
  if (errTs) return errTs;
  const errEventType = nonEmptyString(input.eventType, "eventType");
  if (errEventType) return errEventType;
  if (!input.actor) return "missing field 'actor'";
  if (typeof input.actor.type !== "string" || input.actor.type.length === 0) {
    return "invalid actor.type";
  }
  if (typeof input.actor.id !== "string" || input.actor.id.length === 0) {
    return "invalid actor.id";
  }
  if (typeof input.previousHash === "string" && input.previousHash.length === 0) {
    return "invalid previousHash: empty string not allowed (use undefined for genesis)";
  }
  if (input.workspaceId !== undefined && (typeof input.workspaceId !== "string" || input.workspaceId.length === 0)) {
    return "invalid workspaceId: if present must be non-empty string";
  }
  if (input.taskId !== undefined && (typeof input.taskId !== "string" || input.taskId.length === 0)) {
    return "invalid taskId: if present must be non-empty string";
  }
  if (input.verb !== undefined && (typeof input.verb !== "string" || input.verb.length === 0)) {
    return "invalid verb: if present must be non-empty string";
  }
  if (input.capability !== undefined && (typeof input.capability !== "string" || input.capability.length === 0)) {
    return "invalid capability: if present must be non-empty string";
  }
  if (
    input.policyDecision !== undefined &&
    input.policyDecision !== "allow" &&
    input.policyDecision !== "deny" &&
    input.policyDecision !== "not_applicable"
  ) {
    return "invalid policyDecision: must be allow|deny|not_applicable if present";
  }
  if (input.inputSummary !== undefined && typeof input.inputSummary !== "object") {
    return "invalid inputSummary: must be object if present";
  }
  if (input.resultSummary !== undefined && typeof input.resultSummary !== "object") {
    return "invalid resultSummary: must be object if present";
  }
  if (input.parentEventId !== undefined && (typeof input.parentEventId !== "string" || input.parentEventId.length === 0)) {
    return "invalid parentEventId: if present must be non-empty string";
  }
  return null;
}

function formatLine(event: MenogEvent): string {
  return JSON.stringify(event, undefined, 0) + "\n";
}

export class AppendOnlyLedger {
  readonly #events: MenogEvent[] = [];
  readonly #eventIds: Set<string> = new Set();
  readonly #filePath: string | null;
  readonly #maxLineBytes: number;

  public constructor(
    filePath: string | null = null,
    options: LedgerConstructorOptions = {}
  ) {
    this.#filePath = filePath;
    this.#maxLineBytes = options.maxLineBytes ?? MAX_LINE_BYTES;
    if (filePath !== null) {
      this.#loadFromDisk();
    }
  }

  public static at(filePath: string, options?: LedgerConstructorOptions): AppendOnlyLedger {
    return new AppendOnlyLedger(filePath, options);
  }

  public static inMemory(options?: LedgerConstructorOptions): AppendOnlyLedger {
    return new AppendOnlyLedger(null, options);
  }

  public get filePath(): string | null {
    return this.#filePath;
  }

  public get length(): number {
    return this.#events.length;
  }

  public events(): readonly MenogEvent[] {
    return this.#events.slice();
  }

  public lastHash(): string {
    const tail = this.#events[this.#events.length - 1];
    return tail ? tail.hash : GENESIS_PREVIOUS_HASH;
  }

  public append(input: MenogEventInput): AppendResult {
    const err = validateEventInput(input);
    if (err) return { ok: false, reason: err };
    if (this.#eventIds.has(input.eventId)) {
      return { ok: false, reason: "duplicate eventId: '" + input.eventId + "'" };
    }
    const expectedPrevious = this.lastHash();
    const providedPrevious =
      typeof input.previousHash === "string" ? input.previousHash : undefined;
    if (providedPrevious !== undefined && providedPrevious !== expectedPrevious) {
      return {
        ok: false,
        reason:
          "previousHash mismatch: expected '" +
          expectedPrevious +
          "' but got '" +
          providedPrevious +
          "'",
      };
    }
    const sanitizedInput: MenogEventInput = {
      ...input,
      inputSummary: redactSummary(input.inputSummary),
      resultSummary: redactSummary(input.resultSummary),
      previousHash: expectedPrevious,
    };
    const hash = computeEventHash(sanitizedInput as Omit<MenogEvent, "hash">);
    const event: MenogEvent = Object.freeze({
      ...sanitizedInput,
      previousHash: expectedPrevious,
      hash,
    } as MenogEvent);
    const line = formatLine(event);
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (lineBytes > this.#maxLineBytes) {
      return {
        ok: false,
        reason:
          "event exceeds max line size limit: " +
          String(lineBytes) +
          " > " +
          String(this.#maxLineBytes) +
          " bytes",
      };
    }
    if (this.#filePath !== null) {
      const dir = dirname(this.#filePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      appendFileSync(this.#filePath, line, "utf8");
    }
    this.#events.push(event);
    this.#eventIds.add(event.eventId);
    return { ok: true, event };
  }

  public verify(): VerifyResult {
    const reasons: string[] = [];
    let verified = 0;
    const total = this.#events.length;
    for (let i = 0; i < total; i++) {
      const current = this.#events[i];
      if (!current) continue;
      const prev = i === 0 ? null : this.#events[i - 1];
      const expectedPrevious =
        i === 0 ? GENESIS_PREVIOUS_HASH : prev ? prev.hash : GENESIS_PREVIOUS_HASH;
      if (current.previousHash !== expectedPrevious) {
        reasons.push(
          "event " +
            String(i) +
            " (" +
            current.eventId +
            "): previousHash mismatch"
        );
        continue;
      }
      const recomputed = sha256Hex(
        serializeEventForHash(current as Omit<MenogEvent, "hash">)
      );
      if (recomputed !== current.hash) {
        reasons.push(
          "event " +
            String(i) +
            " (" +
            current.eventId +
            "): hash mismatch"
        );
        continue;
      }
      verified++;
    }
    return {
      ok: reasons.length === 0,
      reasons: Object.freeze(reasons),
      verifiedCount: verified,
      totalCount: total,
    };
  }

  #loadFromDisk(): void {
    if (this.#filePath === null) return;
    if (!existsSync(this.#filePath)) return;
    const raw = readFileSync(this.#filePath, "utf8");
    if (raw.length === 0) return;
    const lines = raw.split("\n");
    let lineNo = 0;
    const parsed: MenogEvent[] = [];
    for (const rawLine of lines) {
      lineNo++;
      const line = rawLine.trim();
      if (line.length === 0) continue;
      const lineBytes = Buffer.byteLength(rawLine, "utf8");
      if (lineBytes > this.#maxLineBytes) {
        throw new Error(
          "AppendOnlyLedger.load: line " +
            String(lineNo) +
            " exceeds " +
            String(this.#maxLineBytes) +
            " bytes"
        );
      }
      let parsedEvent: unknown;
      try {
        parsedEvent = JSON.parse(line);
      } catch (e) {
        throw new Error(
          "AppendOnlyLedger.load: line " +
            String(lineNo) +
            " is not valid JSON: " +
            String((e as Error).message)
        );
      }
      if (!parsedEvent || typeof parsedEvent !== "object") {
        throw new Error(
          "AppendOnlyLedger.load: line " +
            String(lineNo) +
            " is not a JSON object"
        );
      }
      parsed.push(parsedEvent as MenogEvent);
    }
    for (const ev of parsed) {
      if (this.#eventIds.has(ev.eventId)) {
        throw new Error(
          "AppendOnlyLedger.load: duplicate eventId '" + ev.eventId + "'"
        );
      }
      this.#events.push(ev);
      this.#eventIds.add(ev.eventId);
    }
    const verification = this.verify();
    if (!verification.ok) {
      const msg = verification.reasons.length === 1
        ? verification.reasons[0]!
        : verification.reasons.length + " integrity failures:\n  - " + verification.reasons.join("\n  - ");
      throw new Error(
        "AppendOnlyLedger.load: ledger integrity verification failed (" +
          String(verification.verifiedCount) +
          "/" +
          String(verification.totalCount) +
          " events verified): " +
          msg
      );
    }
  }

  public dumpToDir(directoryPath: string): { ok: boolean; reason?: string } {
    try {
      if (!existsSync(directoryPath)) {
        mkdirSync(directoryPath, { recursive: true });
      }
      const target = resolve(directoryPath, "events.jsonl");
      let out = "";
      for (const ev of this.#events) out += formatLine(ev);
      writeFileSync(target, out, "utf8");
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String((e as Error).message) };
    }
  }
}
