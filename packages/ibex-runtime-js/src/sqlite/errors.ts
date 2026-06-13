/**
 * SQLite error class for the Exact runtime.
 * Matches bun:sqlite's SQLiteError.
 */

export class SQLiteError implements Error {
  readonly name = 'SQLiteError';
  readonly message: string;
  stack?: string;
  readonly errno: number;
  readonly code?: string;
  readonly byteOffset: number;

  constructor(message: string, errno: number = 0, code?: string, byteOffset: number = 0) {
    this.message = message;
    this.stack = new Error(this.message).stack;
    this.errno = errno;
    this.code = code;
    this.byteOffset = byteOffset;
  }
}
Object.setPrototypeOf(SQLiteError.prototype, Error.prototype);
Object.setPrototypeOf(SQLiteError, Error);

export default SQLiteError;
