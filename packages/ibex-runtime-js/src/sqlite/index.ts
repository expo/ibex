/**
 * exact:sqlite module
 *
 * SQLite database module for the Ibex runtime.
 * API compatible with bun:sqlite, with built-in cr-sqlite CRDT support.
 *
 * @example
 * ```typescript
 * import { Database } from "exact:sqlite";
 *
 * const db = new Database(":memory:");
 * db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
 * db.run("INSERT INTO users (name) VALUES (?)", "Alice");
 *
 * const users = db.query("SELECT * FROM users").all();
 * console.log(users); // [{ id: 1, name: "Alice" }]
 *
 * // cr-sqlite support
 * db.enableCrSqlite();
 * db.markAsCrr("users");
 * const changes = db.getChanges();
 * ```
 *
 * @see https://bun.sh/docs/api/sqlite
 * @see https://vlcn.io/docs/cr-sqlite/intro
 */

export { Database, type DatabaseOptions } from './Database';
export { Statement, type Changes } from './Statement';
export { constants } from './constants';
export { SQLiteError } from './errors';

// Default export matches bun:sqlite
export { Database as default } from './Database';
