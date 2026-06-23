/**
 * SQLite Statement for the Ibex runtime.
 *
 * Prepared statement wrapping native SQLite3 operations.
 * API matches bun:sqlite's Statement class.
 *
 * @see https://bun.sh/docs/api/sqlite#statement
 */

const g = globalThis as any;

export interface Changes {
  changes: number;
  lastInsertRowid: number | bigint;
}

type SQLBindings = string | number | bigint | boolean | null | Uint8Array;
type SQLParams = SQLBindings | Record<string, SQLBindings>;

export class Statement<ReturnType = unknown, ParamsType extends any[] = any[]> {
  /** @internal */
  _handle: any;
  /** @internal */
  _db: any;
  /** @internal */
  _sql: string;
  /** @internal */
  _finalized = false;
  /** @internal */
  _columnTypes: (string | null)[] = [];
  /** @internal */
  _declaredTypes: (string | null)[] = [];
  /** @internal */
  _readOnly = true;
  /** @internal */
  _executed = false;

  /** Column names of the result set. */
  columnNames: string[] = [];

  /** Number of parameters expected by the statement. */
  paramsCount = 0;

  /** The native handle. */
  get native(): any {
    return {
      columns: [...this.columnNames],
      columnsCount: this.columnNames.length,
    };
  }

  /** Column types based on actual values. */
  get columnTypes(): (string | null)[] {
    if (!this._readOnly) {
      throw new Error('columnTypes is not available for non-read-only statements');
    }
    return this._columnTypes;
  }

  /** Types from CREATE TABLE schema. */
  get declaredTypes(): (string | null)[] {
    if (this._readOnly && !this._executed) {
      throw new Error('Statement must be executed before accessing declaredTypes');
    }
    return this._declaredTypes;
  }

  /** @internal */
  constructor(dbHandle: any, sql: string) {
    this._db = dbHandle;
    this._sql = sql;

    if (!g.__exactSqlitePrepare) {
      throw new Error(
        'exact:sqlite native bridge not available. ' +
        'The exact:sqlite module requires the Ibex runtime with SQLite support.'
      );
    }

    const result = g.__exactSqlitePrepare(dbHandle, sql);
    this._handle = result.handle;
    this.columnNames = result.columnNames || [];
    this._declaredTypes = result.declaredTypes || [];
    this.paramsCount = result.paramsCount || 0;
    this._readOnly = result.readOnly !== false;
  }

  /**
   * Execute the statement and return all matching rows as objects.
   */
  all(...params: ParamsType): ReturnType[] {
    this._checkFinalized();
    const bindings = this._normalizeParams(params);
    const result = g.__exactSqliteAll(this._handle, bindings);
    this._recordExecution(result);
    return result.rows;
  }

  /**
   * Execute the statement and return the first matching row as an object.
   * Returns null if no rows match.
   */
  get(...params: ParamsType): ReturnType | null {
    this._checkFinalized();
    const bindings = this._normalizeParams(params);
    const result = g.__exactSqliteGet(this._handle, bindings);
    this._recordExecution(result);
    return result.row ?? null;
  }

  /**
   * Execute the statement. Returns changes info.
   */
  run(...params: ParamsType): Changes {
    this._checkFinalized();
    const bindings = this._normalizeParams(params);
    const result = g.__exactSqliteRun(this._handle, bindings);
    this._executed = true;
    return result;
  }

  /**
   * Execute the statement and return all rows as arrays of values (no keys).
   */
  values(...params: ParamsType): unknown[][] {
    this._checkFinalized();
    const bindings = this._normalizeParams(params);
    const result = g.__exactSqliteValues(this._handle, bindings);
    this._recordExecution(result);
    return result.rows;
  }

  /**
   * Destroy the statement and free resources.
   * Once finalized, the statement cannot be used again.
   */
  finalize(): void {
    if (this._finalized) return;
    this._finalized = true;
    if (g.__exactSqliteFinalize) {
      g.__exactSqliteFinalize(this._handle);
    }
  }

  /**
   * Return the expanded SQL with most recent bound values.
   */
  toString(): string {
    this._checkFinalized();
    if (g.__exactSqliteExpandedSql) {
      return g.__exactSqliteExpandedSql(this._handle);
    }
    return this._sql;
  }

  /**
   * Map results to class instances.
   * Uses Object.create (NOT new) - constructor is NOT called.
   */
  as<T>(Class: new (...args: any[]) => T): Statement<T, ParamsType> {
    const wrapped = Object.create(this);
    const origAll = this.all.bind(this);
    const origGet = this.get.bind(this);

    wrapped.all = function (...params: any[]) {
      const rows = origAll(...params);
      return rows.map((row: any) => Object.assign(Object.create(Class.prototype), row));
    };

    wrapped.get = function (...params: any[]) {
      const row = origGet(...params);
      if (row === null) return null;
      return Object.assign(Object.create(Class.prototype), row);
    };

    return wrapped;
  }

  [Symbol.dispose](): void {
    this.finalize();
  }

  /** @internal */
  private _checkFinalized(): void {
    if (this._finalized) {
      throw new Error('Statement has been finalized and cannot be used');
    }
  }

  /** @internal */
  private _normalizeParams(params: any[]): any {
    if (params.length === 0) return undefined;
    if (params.length === 1 && typeof params[0] === 'object' && params[0] !== null && !(params[0] instanceof Uint8Array)) {
      return params[0]; // Named parameters
    }
    return params; // Positional parameters
  }

  /** @internal */
  private _recordExecution(result: any): void {
    this._executed = true;
    this._columnTypes = Array.isArray(result?.columnTypes) ? result.columnTypes : [];
  }
}

export default Statement;
