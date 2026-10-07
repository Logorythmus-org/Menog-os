export type SideEffectClass = "none" | "read" | "write" | "network" | "system";

export const SIDE_EFFECT_CLASSES: readonly SideEffectClass[] = Object.freeze([
  "none",
  "read",
  "write",
  "network",
  "system",
]);

export function isSideEffectClass(value: unknown): value is SideEffectClass {
  return typeof value === "string" && (SIDE_EFFECT_CLASSES as readonly string[]).includes(value);
}
