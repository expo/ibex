/**
 * exact:sqlite - CommonJS module entry point
 *
 * This file is included by the Rust module loader via include_str!().
 * It provides the bun:sqlite-compatible API with cr-sqlite extension support.
 */

var g = globalThis;
var CRSQLITE_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function validateCrSqliteIdentifier(tableName) {
  if (typeof tableName !== 'string' || !CRSQLITE_IDENTIFIER_RE.test(tableName)) {
    throw new TypeError(
      'markAsCrr tableName must be a simple SQLite identifier matching ' +
      '[A-Za-z_][A-Za-z0-9_]*'
    );
  }
  return tableName;
}

// ============================================================================
// SQLiteError
// ============================================================================

function SQLiteError(message, errno, code, byteOffset) {
  var err = new Error(message);
  err.name = 'SQLiteError';
  err.errno = errno || 0;
  err.code = code;
  err.byteOffset = byteOffset || 0;
  Object.setPrototypeOf(err, SQLiteError.prototype);
  return err;
}
SQLiteError.prototype = Object.create(Error.prototype);
SQLiteError.prototype.constructor = SQLiteError;

// ============================================================================
// Constants
// ============================================================================

var constants = {
  SQLITE_OPEN_READONLY: 0x00000001,
  SQLITE_OPEN_READWRITE: 0x00000002,
  SQLITE_OPEN_CREATE: 0x00000004,
  SQLITE_OPEN_DELETEONCLOSE: 0x00000008,
  SQLITE_OPEN_EXCLUSIVE: 0x00000010,
  SQLITE_OPEN_URI: 0x00000040,
  SQLITE_OPEN_MEMORY: 0x00000080,
  SQLITE_OPEN_NOMUTEX: 0x00008000,
  SQLITE_OPEN_FULLMUTEX: 0x00010000,
  SQLITE_OPEN_SHAREDCACHE: 0x00020000,
  SQLITE_OPEN_PRIVATECACHE: 0x00040000,
  SQLITE_OPEN_WAL: 0x00080000,
  SQLITE_PREPARE_PERSISTENT: 0x01,
  SQLITE_PREPARE_NORMALIZE: 0x02,
  SQLITE_PREPARE_NO_VTAB: 0x04,
  SQLITE_FCNTL_LOCKSTATE: 1,
  SQLITE_FCNTL_SIZE_HINT: 5,
  SQLITE_FCNTL_CHUNK_SIZE: 6,
  SQLITE_FCNTL_PERSIST_WAL: 10,
  SQLITE_FCNTL_OVERWRITE: 11,
  SQLITE_FCNTL_POWERSAFE_OVERWRITE: 13,
  SQLITE_FCNTL_MMAP_SIZE: 18,
  SQLITE_FCNTL_DATA_VERSION: 35,
};

// ============================================================================
// Statement
// ============================================================================

function Statement(dbHandle, sql) {
  if (!g.__exactSqlitePrepare) {
    throw new Error('exact:sqlite native bridge not available');
  }
  this._db = dbHandle;
  this._sql = sql;
  this._finalized = false;
  this._columnTypes = [];
  this._declaredTypes = [];
  this._readOnly = true;
  this._executed = false;

  var result = g.__exactSqlitePrepare(dbHandle, sql);
  this._handle = result.handle;
  this.columnNames = result.columnNames || [];
  this._declaredTypes = result.declaredTypes || [];
  this.paramsCount = result.paramsCount || 0;
  this._readOnly = result.readOnly !== false;
}

Statement.prototype._checkFinalized = function() {
  if (this._finalized) throw new Error('Statement has been finalized and cannot be used');
};

Statement.prototype._normalizeParams = function(params) {
  if (params.length === 0) return undefined;
  if (params.length === 1 && typeof params[0] === 'object' && params[0] !== null && !(params[0] instanceof Uint8Array)) {
    return params[0];
  }
  return params;
};

Object.defineProperty(Statement.prototype, 'native', {
  get: function() {
    return {
      columns: this.columnNames.slice(),
      columnsCount: this.columnNames.length,
    };
  },
  configurable: true, enumerable: true,
});

Object.defineProperty(Statement.prototype, 'columnTypes', {
  get: function() {
    if (!this._readOnly) {
      throw new Error('columnTypes is not available for non-read-only statements');
    }
    return this._columnTypes;
  },
  configurable: true, enumerable: true,
});

Object.defineProperty(Statement.prototype, 'declaredTypes', {
  get: function() {
    if (this._readOnly && !this._executed) {
      throw new Error('Statement must be executed before accessing declaredTypes');
    }
    return this._declaredTypes;
  },
  configurable: true, enumerable: true,
});

Statement.prototype._recordExecution = function(result) {
  this._executed = true;
  this._columnTypes = Array.isArray(result && result.columnTypes) ? result.columnTypes : [];
};

Statement.prototype.all = function() {
  this._checkFinalized();
  var bindings = this._normalizeParams(Array.prototype.slice.call(arguments));
  var result = g.__exactSqliteAll(this._handle, bindings);
  this._recordExecution(result);
  return result.rows;
};

Statement.prototype.get = function() {
  this._checkFinalized();
  var bindings = this._normalizeParams(Array.prototype.slice.call(arguments));
  var result = g.__exactSqliteGet(this._handle, bindings);
  this._recordExecution(result);
  return result.row != null ? result.row : null;
};

Statement.prototype.run = function() {
  this._checkFinalized();
  var bindings = this._normalizeParams(Array.prototype.slice.call(arguments));
  var result = g.__exactSqliteRun(this._handle, bindings);
  this._executed = true;
  return result;
};

Statement.prototype.values = function() {
  this._checkFinalized();
  var bindings = this._normalizeParams(Array.prototype.slice.call(arguments));
  var result = g.__exactSqliteValues(this._handle, bindings);
  this._recordExecution(result);
  return result.rows;
};

Statement.prototype.finalize = function() {
  if (this._finalized) return;
  this._finalized = true;
  if (g.__exactSqliteFinalize) g.__exactSqliteFinalize(this._handle);
};

Statement.prototype.toString = function() {
  this._checkFinalized();
  if (g.__exactSqliteExpandedSql) return g.__exactSqliteExpandedSql(this._handle);
  return this._sql;
};

Statement.prototype.as = function(Class) {
  var self = this;
  var wrapped = Object.create(this);

  wrapped.all = function() {
    var rows = self.all.apply(self, arguments);
    return rows.map(function(row) {
      return Object.assign(Object.create(Class.prototype), row);
    });
  };

  wrapped.get = function() {
    var row = self.get.apply(self, arguments);
    if (row === null) return null;
    return Object.assign(Object.create(Class.prototype), row);
  };

  return wrapped;
};

// ============================================================================
// Database
// ============================================================================

function Database(filename, options) {
  if (!(this instanceof Database)) return new Database(filename, options);

  this.filename = filename || ':memory:';
  this._closed = false;
  this._queryCache = {};
  this._crSqliteLoaded = false;

  if (typeof options === 'number') {
    this._options = {};
  } else {
    this._options = options || {};
  }

  if (!g.__exactSqliteOpen) {
    throw new Error('exact:sqlite native bridge not available. The exact:sqlite module requires the Ibex runtime with SQLite support.');
  }

  var flags = typeof options === 'number' ? options : undefined;
  this._handle = g.__exactSqliteOpen(this.filename, {
    readonly: this._options.readonly || false,
    create: this._options.create !== false,
    readwrite: this._options.readwrite !== false,
    safeIntegers: this._options.safeIntegers || false,
    flags: flags,
  });

  // Enable WAL mode and foreign keys by default
  this.run('PRAGMA journal_mode = WAL');
  this.run('PRAGMA foreign_keys = ON');
}

Object.defineProperty(Database.prototype, 'handle', {
  get: function() { return this._handle; },
  configurable: true, enumerable: true,
});

Object.defineProperty(Database.prototype, 'inTransaction', {
  get: function() {
    this._checkClosed();
    return g.__exactSqliteInTransaction ? g.__exactSqliteInTransaction(this._handle) : false;
  },
  configurable: true, enumerable: true,
});

Database.prototype._checkClosed = function() {
  if (this._closed) throw new Error('Database is closed');
};

Database.prototype.query = function(sql) {
  this._checkClosed();
  if (!this._queryCache[sql]) {
    this._queryCache[sql] = new Statement(this._handle, sql);
  }
  return this._queryCache[sql];
};

Database.prototype.prepare = function(sql) {
  this._checkClosed();
  return new Statement(this._handle, sql);
};

Database.prototype.run = function(sql) {
  this._checkClosed();
  var bindings = Array.prototype.slice.call(arguments, 1);
  if (g.__exactSqliteExec) {
    var params;
    if (bindings.length === 1 && typeof bindings[0] === 'object' && bindings[0] !== null && !(bindings[0] instanceof Uint8Array)) {
      params = bindings[0];
    } else if (bindings.length > 0) {
      params = bindings;
    }
    return g.__exactSqliteExec(this._handle, sql, params);
  }
  var stmt = this.prepare(sql);
  try { return stmt.run.apply(stmt, bindings); }
  finally { stmt.finalize(); }
};

Database.prototype.exec = Database.prototype.run;

Database.prototype.transaction = function(fn) {
  var db = this;
  db._checkClosed();

  function wrapTransaction(beginStatement) {
    return function() {
      if (db.inTransaction) {
        var sp = '_sp_' + Date.now() + '_' + Math.random().toString(36).slice(2);
        db.run('SAVEPOINT "' + sp + '"');
        try {
          var result = fn.apply(this, arguments);
          db.run('RELEASE "' + sp + '"');
          return result;
        } catch (e) {
          db.run('ROLLBACK TO "' + sp + '"');
          db.run('RELEASE "' + sp + '"');
          throw e;
        }
      }
      db.run(beginStatement);
      try {
        var result = fn.apply(this, arguments);
        db.run('COMMIT');
        return result;
      } catch (e) {
        db.run('ROLLBACK');
        throw e;
      }
    };
  }

  var txnFn = wrapTransaction('BEGIN');
  txnFn.deferred = wrapTransaction('BEGIN DEFERRED');
  txnFn.immediate = wrapTransaction('BEGIN IMMEDIATE');
  txnFn.exclusive = wrapTransaction('BEGIN EXCLUSIVE');
  return txnFn;
};

Database.prototype.close = function(throwOnError) {
  if (this._closed) return;
  if (this._crSqliteLoaded) {
    try { this.run('SELECT crsql_finalize()'); } catch (e) {}
  }
  this._closed = true;
  for (var key in this._queryCache) {
    this._queryCache[key].finalize();
  }
  this._queryCache = {};
  if (g.__exactSqliteClose) {
    try { g.__exactSqliteClose(this._handle); }
    catch (e) { if (throwOnError) throw e; }
  }
};

Database.prototype.serialize = function(name) {
  this._checkClosed();
  if (!g.__exactSqliteSerialize) throw new Error('Database serialization not supported');
  return g.__exactSqliteSerialize(this._handle, name || 'main');
};

Database.prototype.loadExtension = function(path, entryPoint) {
  this._checkClosed();
  if (!g.__exactSqliteLoadExtension) throw new Error('Extension loading not supported');
  g.__exactSqliteLoadExtension(this._handle, path, entryPoint);
};

Database.prototype.fileControl = function() {
  this._checkClosed();
  if (!g.__exactSqliteFileControl) throw new Error('fileControl not supported');
  return g.__exactSqliteFileControl.apply(null, [this._handle].concat(Array.prototype.slice.call(arguments)));
};

// cr-sqlite methods
Database.prototype.enableCrSqlite = function() {
  this._checkClosed();
  if (this._crSqliteLoaded) return;
  if (g.__exactCrSqlitePath) {
    this.loadExtension(g.__exactCrSqlitePath());
  } else if (g.__exactSqliteLoadCrSqlite) {
    g.__exactSqliteLoadCrSqlite(this._handle);
  } else {
    throw new Error('cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support.');
  }
  this._crSqliteLoaded = true;
};

Database.prototype.getSiteId = function() {
  this._checkClosed();
  if (!this._crSqliteLoaded) throw new Error('cr-sqlite is not loaded. Call db.enableCrSqlite() first.');
  return this.query('SELECT crsql_site_id() as id').get().id;
};

Database.prototype.getDbVersion = function() {
  this._checkClosed();
  if (!this._crSqliteLoaded) throw new Error('cr-sqlite is not loaded. Call db.enableCrSqlite() first.');
  return this.query('SELECT crsql_db_version() as version').get().version;
};

Database.prototype.markAsCrr = function(tableName) {
  this._checkClosed();
  if (!this._crSqliteLoaded) throw new Error('cr-sqlite is not loaded. Call db.enableCrSqlite() first.');
  var validatedTableName = validateCrSqliteIdentifier(tableName);
  this.run("SELECT crsql_as_crr('" + validatedTableName + "')");
};

Database.prototype.getChanges = function(sinceVersion, excludeSiteId) {
  this._checkClosed();
  if (!this._crSqliteLoaded) throw new Error('cr-sqlite is not loaded. Call db.enableCrSqlite() first.');
  sinceVersion = sinceVersion || 0;
  if (excludeSiteId) {
    return this.query(
      'SELECT "table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq" FROM crsql_changes WHERE db_version > ? AND site_id IS NOT ?'
    ).all(sinceVersion, excludeSiteId);
  }
  return this.query(
    'SELECT "table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq" FROM crsql_changes WHERE db_version > ?'
  ).all(sinceVersion);
};

Database.prototype.applyChanges = function(changes) {
  this._checkClosed();
  if (!this._crSqliteLoaded) throw new Error('cr-sqlite is not loaded. Call db.enableCrSqlite() first.');
  var insert = this.prepare(
    'INSERT INTO crsql_changes ("table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );
  var applyAll = this.transaction(function(changes) {
    for (var i = 0; i < changes.length; i++) {
      var c = changes[i];
      insert.run(c.table, c.pk, c.cid, c.val, c.col_version, c.db_version, c.site_id, c.cl, c.seq);
    }
  });
  try { applyAll(changes); }
  finally { insert.finalize(); }
};

// Static methods
Database.open = function(filename, options) {
  return new Database(filename, options);
};

Database.deserialize = function(data, options) {
  if (!g.__exactSqliteDeserialize) throw new Error('Database deserialization not supported');
  var isReadOnly = typeof options === 'boolean' ? options : (options && options.readonly) || false;
  var handle = g.__exactSqliteDeserialize(data, isReadOnly);
  var db = Object.create(Database.prototype);
  db._handle = handle;
  db._closed = false;
  db._queryCache = {};
  db._options = typeof options === 'object' ? options : { readonly: isReadOnly };
  db.filename = ':memory:';
  db._crSqliteLoaded = false;
  return db;
};

// ============================================================================
// Exports
// ============================================================================

module.exports = Database;
module.exports.Database = Database;
module.exports.Statement = Statement;
module.exports.constants = constants;
module.exports.SQLiteError = SQLiteError;
module.exports.default = Database;
