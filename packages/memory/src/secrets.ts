/**
 * Phase 16B — secret exclusion + credential-value redaction for memory.
 *
 * The key patterns mirror `SECRET_KEY_HINTS` in `@menog/event-ledger`
 * (packages/event-ledger/src/crypto.ts) so that memory bodies and ledger
 * summaries share ONE definition of "looks like a secret". The two lists are
 * textually identical; a comment on the ledger side points back here.
 */

export const MEMORY_SECRET_KEY_HINTS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(pass(word|phrase)?)([-_ ]|$)/i,
  /(^|[-_ ])secret([-_ ]|$)/i,
  /(^|[-_ ])((api[-_]?)?key|apikey)([-_ ]|$)/i,
  /(^|[-_ ])(token)([-_ ]|$)/i,
  /(^|[-_ ])(credential|credentials|cred)([-_ ]|$)/i,
  /(^|[-_ ])(private[-_ ]?key|privkey)([-_ ]|$)/i,
  /(^|[-_ ])(auth|authentication)([-_ ]|$)/i,
  /(^|[-_ ])(cookie)([-_ ]|$)/i,
  /(^|[-_ ])(session)([-_ ]|$)/i,
  /(^|[-_ ])(bearer)([-_ ]|$)/i,
  /(^|[-_ ])(signing[-_ ]?secret)([-_ ]|$)/i,
  /(^|[-_ ])(access[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])(refresh[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])((aws|gcp|azure)[-_ ]?(secret|key))([-_ ]|$)/i,
  /(^|[-_ ])(signing|signature|sign)[-_ ]?key([-_ ]|$)/i,
  /(^|[-_ ])(jwt|jwks)([-_ ]|$)/i,
  /(^|[-_ ])(secret[-_ ]?key|key[-_ ]?secret)([-_ ]|$)/i,
]);

/**
 * Collect the paths of every secret-like KEY at any depth of a body (plain
 * objects are descended into; values are never read). Depth is bounded to
 * keep hostile deep-nesting payloads from exhausting the scan.
 */
export function findSecretKeyPaths(
  value: unknown,
  prefix: string = "",
  maxDepth: number = 8
): string[] {
  if (maxDepth <= 0 || value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const hits: string[] = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const p = prefix.length === 0 ? k : prefix + "." + k;
    if (secretKeyMatches(k)) hits.push(p);
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      hits.push(...findSecretKeyPaths(v, p, maxDepth - 1));
    }
  }
  return hits;
}

/** True when a key hint looks like a secret channel. */
export function secretKeyMatches(keyHint: string): boolean {
  if (typeof keyHint !== "string" || keyHint.length === 0) return false;
  const normalized = keyHint.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
  return (
    MEMORY_SECRET_KEY_HINTS.some((re) => re.test(keyHint.toLowerCase())) ||
    MEMORY_SECRET_KEY_HINTS.some((re) => re.test(normalized))
  );
}

/**
 * Content patterns for credential-shaped string VALUES. These redact the
 * matched credential itself, leaving surrounding text intact. Content-based
 * redaction is defense in depth: key-based rejection (secret_detected) is
 * the primary control.
 */
const CREDENTIAL_VALUE_PATTERNS: readonly RegExp[] = Object.freeze([
  /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, // JWT (three segments)
  /gh[oprs]_[A-Za-z0-9]{20,}/g, // GitHub-style tokens
  /sk-[A-Za-z0-9]{20,}/g, // OpenAI-style keys
  /AKIA[0-9A-Z]{16}/g, // AWS access key ids
  /(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)\s*[:=]\s*[^\s"',;}]+/gi,
]);

export const MEMORY_REDACTION_MARKER = "[REDACTED]";

function redactInString(value: string): string {
  let out = value;
  for (const re of CREDENTIAL_VALUE_PATTERNS) {
    out = out.replace(re, MEMORY_REDACTION_MARKER);
  }
  return out;
}

/**
 * Deeply redact credential-shaped string VALUES inside arbitrary body
 * content. Keys are NOT transformed here (key-level secrets are REJECTED by
 * the execution store before this runs); only values are sanitized.
 */
export function redactCredentialValues<T>(value: T): T {
  return redactDeep(value) as T;
}

function redactDeep(value: unknown): unknown {
  if (typeof value === "string") return redactInString(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return value.map((v) => redactDeep(v));
  }
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>)) {
    out[k] = redactDeep((value as Record<string, unknown>)[k]);
  }
  return out;
}
