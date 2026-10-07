import type { SideEffectClass } from "@menog/shared";

export interface VerbContract<Input = unknown, Output = unknown> {
  readonly id: string;
  readonly description: string;
  readonly sideEffectClass: SideEffectClass;
  readonly requiredCapabilities: readonly string[];
  readonly replayable: boolean;
  readonly reversible: boolean;
  readonly inputSchemaVersion: string;
  readonly outputSchemaVersion: string;
  readonly executable?: boolean;
  readonly __input?: Input;
  readonly __output?: Output;
}

export type VerbId = string;

export type VerbLookupResult<T> =
  | { found: true; verb: VerbContract<T> }
  | { found: false; verbId: string; reason: string };
