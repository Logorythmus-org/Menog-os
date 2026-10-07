/**
 * PHASE 22B — Runtime binding for `node:sqlite`.
 *
 * `node:sqlite` is a prefix-only built-in on current Node (bare `sqlite` is
 * NOT in `builtinModules`), and some module-resolution layers (vite-node /
 * Vitest 2.1.8) strip the `node:` prefix and check it against the bare-name
 * list — so a static import falls through to file resolution and fails.
 *
 * This module loads the built-in through Node's OWN `createRequire` at
 * runtime, bypassing every resolver in the chain. `createRequire` itself is
 * imported from `node:module`, which every resolution layer externalizes
 * natively. The `node:sqlite` types come from @types/node as a TYPE-ONLY
 * import — erased at runtime, so nothing static references the module.
 */

import { createRequire } from "node:module";
import type { DatabaseSync as DatabaseSyncClass } from "node:sqlite";

type SqliteModule = {
  readonly DatabaseSync: new (
    location: string,
    options?: { readonly open?: boolean; readonly allowExtension?: boolean }
  ) => DatabaseSyncClass;
};

const nodeRequire = createRequire(import.meta.url);

// The prefixed form is the only valid spelling of this built-in; require of
// a built-in never touches the filesystem.
const sqlite = nodeRequire("node:sqlite") as SqliteModule;

/** The real SQLite DatabaseSync constructor from the Node runtime. */
export const DatabaseSync: SqliteModule["DatabaseSync"] = sqlite.DatabaseSync;
