import type { VerbContract, VerbId, VerbLookupResult } from "./types.js";
import { INITIAL_VERBS } from "./verbs.js";
import { isSideEffectClass } from "@menog/shared";

export class VerbRegistry {
  readonly #verbs = new Map<VerbId, VerbContract>();
  readonly #order: VerbId[] = [];

  constructor(initial: readonly VerbContract[] = INITIAL_VERBS) {
    for (const verb of initial) {
      this.register(verb);
    }
  }

  register(verb: VerbContract): { ok: true } | { ok: false; reason: string } {
    if (!verb || typeof verb !== "object") {
      return { ok: false, reason: "verb must be an object" };
    }
    if (typeof verb.id !== "string" || verb.id.length === 0) {
      return { ok: false, reason: "verb.id must be a non-empty string" };
    }
    if (this.#verbs.has(verb.id)) {
      return {
        ok: false,
        reason: "duplicate verb id: '" + verb.id + "'",
      };
    }
    if (typeof verb.description !== "string" || verb.description.length === 0) {
      return { ok: false, reason: "verb '" + verb.id + "': description must be a non-empty string" };
    }
    if (!isSideEffectClass(verb.sideEffectClass)) {
      return {
        ok: false,
        reason:
          "verb '" + verb.id + "': invalid sideEffectClass '" + String(verb.sideEffectClass) + "'",
      };
    }
    if (!Array.isArray(verb.requiredCapabilities)) {
      return {
        ok: false,
        reason: "verb '" + verb.id + "': requiredCapabilities must be an array",
      };
    }
    for (const cap of verb.requiredCapabilities) {
      if (typeof cap !== "string" || cap.length === 0) {
        return {
          ok: false,
          reason:
            "verb '" +
            verb.id +
            "': requiredCapabilities entries must be non-empty strings",
        };
      }
    }
    if (typeof verb.replayable !== "boolean") {
      return { ok: false, reason: "verb '" + verb.id + "': replayable must be boolean" };
    }
    if (typeof verb.reversible !== "boolean") {
      return { ok: false, reason: "verb '" + verb.id + "': reversible must be boolean" };
    }
    if (typeof verb.inputSchemaVersion !== "string" || verb.inputSchemaVersion.length === 0) {
      return {
        ok: false,
        reason: "verb '" + verb.id + "': inputSchemaVersion must be non-empty string",
      };
    }
    if (typeof verb.outputSchemaVersion !== "string" || verb.outputSchemaVersion.length === 0) {
      return {
        ok: false,
        reason: "verb '" + verb.id + "': outputSchemaVersion must be non-empty string",
      };
    }

    const frozen: VerbContract = Object.freeze({
      id: verb.id,
      description: verb.description,
      sideEffectClass: verb.sideEffectClass,
      requiredCapabilities: Object.freeze([...verb.requiredCapabilities]),
      replayable: verb.replayable,
      reversible: verb.reversible,
      inputSchemaVersion: verb.inputSchemaVersion,
      outputSchemaVersion: verb.outputSchemaVersion,
      executable: verb.executable,
    });

    this.#verbs.set(verb.id, Object.freeze(frozen));
    this.#order.push(verb.id);
    return { ok: true };
  }

  get<T = unknown>(verbId: VerbId): VerbLookupResult<T> {
    if (typeof verbId !== "string" || verbId.length === 0) {
      return { found: false, verbId: String(verbId), reason: "verb id must be a non-empty string" };
    }
    const verb = this.#verbs.get(verbId);
    if (!verb) {
      return { found: false, verbId, reason: "unknown verb: '" + verbId + "'" };
    }
    return { found: true, verb: verb as VerbContract<T> };
  }

  has(verbId: VerbId): boolean {
    return this.#verbs.has(verbId);
  }

  list(): readonly VerbContract[] {
    const out: VerbContract[] = [];
    for (const id of this.#order) {
      const v = this.#verbs.get(id);
      if (v) out.push(v);
    }
    return Object.freeze(out);
  }

  ids(): readonly VerbId[] {
    return Object.freeze([...this.#order]);
  }

  size(): number {
    return this.#verbs.size;
  }

  deterministicFingerprint(): string {
    const NL = "\n";
    const parts: string[] = [];
    for (const id of this.#order) {
      const v = this.#verbs.get(id);
      if (!v) continue;
      const line =
        v.id +
        NL +
        v.description +
        NL +
        v.sideEffectClass +
        NL +
        v.requiredCapabilities.join(",") +
        NL +
        String(v.replayable) +
        NL +
        String(v.reversible) +
        NL +
        v.inputSchemaVersion +
        NL +
        v.outputSchemaVersion +
        NL +
        String(v.executable ?? false);
      parts.push(line);
    }
    return parts.join("||");
  }
}

export const defaultVerbRegistry: VerbRegistry = new VerbRegistry(INITIAL_VERBS);
