#include "hermes_runtime_internal.h"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <unordered_map>

extern "C" void ex_host_free_string(char* value);
extern "C" uint64_t ex_host_sqlite_open(const char* path, const char* options_json);
extern "C" int32_t ex_host_sqlite_close(uint64_t handle);
extern "C" char* ex_host_sqlite_prepare(uint64_t db_handle, const char* sql);
extern "C" int32_t ex_host_sqlite_finalize(uint64_t statement_handle);
extern "C" char* ex_host_sqlite_expanded_sql(uint64_t statement_handle);
extern "C" int32_t ex_host_sqlite_in_transaction(uint64_t handle);
extern "C" char* ex_host_sqlite_all(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_get(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_run(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_values(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_exec(uint64_t handle, const char* sql, const char* bindings_json);

namespace {

constexpr uint64_t SQLITE_OPEN_READONLY = 0x00000001;
constexpr uint64_t SQLITE_OPEN_READWRITE = 0x00000002;
constexpr uint64_t SQLITE_OPEN_CREATE = 0x00000004;

struct SqliteHandleEntry {
  uint64_t owner;
  std::vector<std::string> capabilities;
};

struct SqliteStatementEntry {
  uint64_t owner;
  uint64_t dbHandle;
  std::vector<std::string> capabilities;
};

static std::mutex g_sqlite_handle_mutex;
static std::unordered_map<uint64_t, SqliteHandleEntry> g_sqlite_dbs;
static std::unordered_map<uint64_t, SqliteStatementEntry> g_sqlite_statements;

bool sqliteMemoryPath(const std::string& path) {
  return path == ":memory:" || path.rfind("file::memory:", 0) == 0;
}

bool objectBoolProperty(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Object& object,
    const char* name,
    bool defaultValue) {
  auto value = object.getProperty(runtime, name);
  return value.isBool() ? value.getBool() : defaultValue;
}

bool sqliteFlagsNeedWrite(uint64_t flags) {
  if ((flags & (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)) != 0) {
    return true;
  }
  if ((flags & SQLITE_OPEN_READONLY) != 0) {
    return false;
  }
  return true;
}

bool sqliteOpenNeedsWrite(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count) {
  if (count <= 1 || args[1].isUndefined() || args[1].isNull()) {
    return true;
  }
  if (args[1].isNumber()) {
    return sqliteFlagsNeedWrite(static_cast<uint64_t>(args[1].asNumber()));
  }
  if (!args[1].isObject()) {
    return true;
  }

  auto object = args[1].asObject(runtime);
  auto flags = object.getProperty(runtime, "flags");
  if (flags.isNumber()) {
    return sqliteFlagsNeedWrite(static_cast<uint64_t>(flags.asNumber()));
  }

  bool readonly = objectBoolProperty(runtime, object, "readonly", false);
  if (readonly) {
    return false;
  }
  bool create = objectBoolProperty(runtime, object, "create", true);
  bool readwrite = objectBoolProperty(runtime, object, "readwrite", true);
  return create || readwrite;
}

std::vector<std::string> sqliteOpenCapabilities(
    const std::string& path,
    bool needsWrite) {
  std::vector<std::string> capabilities;
  capabilities.push_back(needsWrite ? "sqlite:write" : "sqlite:read");
  if (!sqliteMemoryPath(path)) {
    capabilities.push_back("fs:read:" + path);
    if (needsWrite) {
      capabilities.push_back("fs:write:" + path);
    }
  }
  return capabilities;
}

void requireSqliteCapabilities(
    facebook::jsi::Runtime& runtime,
    const std::vector<std::string>& capabilities,
    const char* syscall) {
  for (const auto& capability : capabilities) {
    if (!checkCapability(capability)) {
      throw facebook::jsi::JSError(
          runtime,
          std::string("Permission denied: ") + syscall + " requires " + capability);
    }
  }
}

void registerSqliteDb(uint64_t dbHandle, std::vector<std::string> capabilities) {
  if (dbHandle == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  g_sqlite_dbs[dbHandle] = SqliteHandleEntry{currentPrincipalId(), std::move(capabilities)};
}

void unregisterSqliteDb(uint64_t dbHandle) {
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  g_sqlite_dbs.erase(dbHandle);
  for (auto it = g_sqlite_statements.begin(); it != g_sqlite_statements.end();) {
    if (it->second.dbHandle == dbHandle) {
      it = g_sqlite_statements.erase(it);
    } else {
      ++it;
    }
  }
}

void registerSqliteStatement(uint64_t statementHandle, uint64_t dbHandle) {
  if (statementHandle == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  auto db = g_sqlite_dbs.find(dbHandle);
  if (db == g_sqlite_dbs.end()) {
    return;
  }
  g_sqlite_statements[statementHandle] = SqliteStatementEntry{
      db->second.owner,
      dbHandle,
      db->second.capabilities,
  };
}

void unregisterSqliteStatement(uint64_t statementHandle) {
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  g_sqlite_statements.erase(statementHandle);
}

SqliteHandleEntry requireSqliteDb(
    facebook::jsi::Runtime& runtime,
    uint64_t dbHandle,
    const char* syscall) {
  if (isAllowAll()) {
    return SqliteHandleEntry{currentPrincipalId(), {}};
  }
  SqliteHandleEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
    auto it = g_sqlite_dbs.find(dbHandle);
    if (it == g_sqlite_dbs.end()) {
      throw facebook::jsi::JSError(
          runtime, std::string(syscall) + ": invalid sqlite handle");
    }
    entry = it->second;
  }
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": sqlite handle belongs to a different principal");
  }
  requireSqliteCapabilities(runtime, entry.capabilities, syscall);
  return entry;
}

SqliteStatementEntry requireSqliteStatement(
    facebook::jsi::Runtime& runtime,
    uint64_t statementHandle,
    const char* syscall) {
  if (isAllowAll()) {
    return SqliteStatementEntry{currentPrincipalId(), 0, {}};
  }
  SqliteStatementEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
    auto it = g_sqlite_statements.find(statementHandle);
    if (it == g_sqlite_statements.end()) {
      throw facebook::jsi::JSError(
          runtime, std::string(syscall) + ": invalid sqlite statement handle");
    }
    entry = it->second;
  }
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime,
        std::string(syscall) + ": sqlite statement belongs to a different principal");
  }
  requireSqliteCapabilities(runtime, entry.capabilities, syscall);
  return entry;
}

uint64_t extractJsonHandle(const char* json) {
  if (!json) {
    return 0;
  }
  std::string text(json);
  auto handleKey = text.find("\"handle\"");
  if (handleKey == std::string::npos) {
    return 0;
  }
  auto colon = text.find(':', handleKey);
  if (colon == std::string::npos) {
    return 0;
  }
  size_t pos = colon + 1;
  while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  uint64_t handle = 0;
  bool sawDigit = false;
  while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
    sawDigit = true;
    handle = handle * 10 + static_cast<uint64_t>(text[pos] - '0');
    ++pos;
  }
  return sawDigit ? handle : 0;
}

} // namespace

static bool sqliteColumnTypeIsBlob(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Array& columnTypes,
    size_t index) {
  auto type = columnTypes.getValueAtIndex(runtime, index);
  return type.isString() && type.asString(runtime).utf8(runtime) == "BLOB";
}

static facebook::jsi::Value convertSqliteBlobValue(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Value value) {
  if (!value.isObject()) {
    return value;
  }

  auto object = value.asObject(runtime);
  if (!object.isArray(runtime)) {
    return value;
  }

  auto array = object.asArray(runtime);
  auto length = array.size(runtime);
  std::vector<uint8_t> bytes;
  bytes.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    auto entry = array.getValueAtIndex(runtime, i);
    if (!entry.isNumber()) {
      return value;
    }
    auto number = entry.asNumber();
    if (number < 0 || number > 255) {
      return value;
    }
    bytes.push_back(static_cast<uint8_t>(number));
  }

  return makeUint8Array(runtime, std::move(bytes));
}

static void convertSqliteBlobColumnsInRowObject(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Object& row,
    const std::unordered_map<std::string, std::string>& columnTypesByName) {
  auto keys = row.getPropertyNames(runtime);
  auto count = keys.size(runtime);
  for (size_t i = 0; i < count; ++i) {
    auto key = keys.getValueAtIndex(runtime, i);
    if (!key.isString()) {
      continue;
    }
    auto property = key.asString(runtime).utf8(runtime);
    auto type = columnTypesByName.find(property);
    if (type == columnTypesByName.end() || type->second != "BLOB") {
      continue;
    }
    row.setProperty(
        runtime,
        property.c_str(),
        convertSqliteBlobValue(runtime, row.getProperty(runtime, property.c_str())));
  }
}

static void convertSqliteBlobColumnsInRowArray(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Array& row,
    const facebook::jsi::Array& columnTypes) {
  auto limit = std::min(row.size(runtime), columnTypes.size(runtime));
  for (size_t i = 0; i < limit; ++i) {
    if (!sqliteColumnTypeIsBlob(runtime, columnTypes, i)) {
      continue;
    }
    row.setValueAtIndex(
        runtime,
        i,
        convertSqliteBlobValue(runtime, row.getValueAtIndex(runtime, i)));
  }
}

static void convertSqliteBlobColumns(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Object& result) {
  auto columnTypesValue = result.getProperty(runtime, "columnTypes");
  if (!columnTypesValue.isObject()) {
    return;
  }

  auto columnTypesObject = columnTypesValue.asObject(runtime);
  if (!columnTypesObject.isArray(runtime)) {
    return;
  }

  auto columnTypes = columnTypesObject.asArray(runtime);
  std::unordered_map<std::string, std::string> columnTypesByName;
  auto columnNamesValue = result.getProperty(runtime, "columnNames");
  if (columnNamesValue.isObject()) {
    auto columnNamesObject = columnNamesValue.asObject(runtime);
    if (columnNamesObject.isArray(runtime)) {
      auto columnNames = columnNamesObject.asArray(runtime);
      auto limit = std::min(columnNames.size(runtime), columnTypes.size(runtime));
      for (size_t i = 0; i < limit; ++i) {
        auto nameValue = columnNames.getValueAtIndex(runtime, i);
        auto typeValue = columnTypes.getValueAtIndex(runtime, i);
        if (nameValue.isString() && typeValue.isString()) {
          columnTypesByName[nameValue.asString(runtime).utf8(runtime)] =
              typeValue.asString(runtime).utf8(runtime);
        }
      }
    }
  }

  auto rowValue = result.getProperty(runtime, "row");
  if (rowValue.isObject()) {
    auto rowObject = rowValue.asObject(runtime);
    if (rowObject.isArray(runtime)) {
      auto rowArray = rowObject.asArray(runtime);
      convertSqliteBlobColumnsInRowArray(runtime, rowArray, columnTypes);
      result.setProperty(runtime, "row", rowArray);
    } else {
      convertSqliteBlobColumnsInRowObject(runtime, rowObject, columnTypesByName);
      result.setProperty(runtime, "row", rowObject);
    }
  }

  auto rowsValue = result.getProperty(runtime, "rows");
  if (!rowsValue.isObject()) {
    return;
  }

  auto rowsObject = rowsValue.asObject(runtime);
  if (!rowsObject.isArray(runtime)) {
    return;
  }

  auto rows = rowsObject.asArray(runtime);
  auto rowCount = rows.size(runtime);
  for (size_t i = 0; i < rowCount; ++i) {
    auto rowValue = rows.getValueAtIndex(runtime, i);
    if (!rowValue.isObject()) {
      continue;
    }

    auto rowObject = rowValue.asObject(runtime);
    if (rowObject.isArray(runtime)) {
      auto rowArray = rowObject.asArray(runtime);
      convertSqliteBlobColumnsInRowArray(runtime, rowArray, columnTypes);
      rows.setValueAtIndex(runtime, i, rowArray);
    } else {
      convertSqliteBlobColumnsInRowObject(runtime, rowObject, columnTypesByName);
      rows.setValueAtIndex(runtime, i, rowObject);
    }
  }

  result.setProperty(runtime, "rows", rows);
}

void installSqliteHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  // __exactSqliteOpen(path, options) -> numeric sqlite handle
  auto sqliteOpenFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteOpen"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteOpen: path required");
        }
        std::string path = args[0].toString(runtime).utf8(runtime);
        bool needsWrite = sqliteOpenNeedsWrite(runtime, args, count);
        auto capabilities = sqliteOpenCapabilities(path, needsWrite);
        // @ref LLP 0013#policy — SQLite is a native host boundary: opening a
        // database needs both sqlite:* authority and path-scoped fs:* grants.
        requireSqliteCapabilities(runtime, capabilities, "__exactSqliteOpen");
        std::string optionsJson;
        const char* options = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          optionsJson = stringifyValue(runtime, args[1]);
          options = optionsJson.c_str();
        }
        uint64_t handle = ex_host_sqlite_open(path.c_str(), options);
        if (handle == 0) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteOpen failed");
        }
        registerSqliteDb(handle, std::move(capabilities));
        return facebook::jsi::Value(static_cast<double>(handle));
      });
  rt.global().setProperty(rt, "__exactSqliteOpen", std::move(sqliteOpenFn));

  // __exactSqliteClose(handle) -> 0/-1
  auto sqliteCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteClose: handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteDb(runtime, handle, "__exactSqliteClose");
        if (ex_host_sqlite_close(handle) == 0) {
          unregisterSqliteDb(handle);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSqliteClose", std::move(sqliteCloseFn));

  // __exactSqlitePrepare(handle, sql) -> object {handle, ...}
  auto sqlitePrepareFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqlitePrepare"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactSqlitePrepare: db handle and sql required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteDb(runtime, handle, "__exactSqlitePrepare");
        auto sql = args[1].toString(runtime).utf8(runtime);
        char* json = ex_host_sqlite_prepare(handle, sql.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, "__exactSqlitePrepare failed");
        }
        uint64_t statementHandle = extractJsonHandle(json);
        if (statementHandle != 0) {
          registerSqliteStatement(statementHandle, handle);
        }
        auto value = parseJsonValue(runtime, json);
        ex_host_free_string(json);
        return value;
      });
  rt.global().setProperty(rt, "__exactSqlitePrepare", std::move(sqlitePrepareFn));

  // __exactSqliteFinalize(statementHandle) -> 0/-1
  auto sqliteFinalizeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteFinalize"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteFinalize: statement handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, handle, "__exactSqliteFinalize");
        if (ex_host_sqlite_finalize(handle) == 0) {
          unregisterSqliteStatement(handle);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSqliteFinalize", std::move(sqliteFinalizeFn));

  // __exactSqliteExpandedSql(statementHandle) -> string
  auto sqliteExpandedSqlFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteExpandedSql"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteExpandedSql: statement handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, handle, "__exactSqliteExpandedSql");
        char* expanded = ex_host_sqlite_expanded_sql(handle);
        if (!expanded) {
          return facebook::jsi::Value::null();
        }
        auto value = facebook::jsi::String::createFromUtf8(runtime, expanded);
        ex_host_free_string(expanded);
        return value;
      });
  rt.global().setProperty(rt, "__exactSqliteExpandedSql", std::move(sqliteExpandedSqlFn));

  // __exactSqliteInTransaction(handle) -> boolean
  auto sqliteInTransactionFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteInTransaction"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteInTransaction: handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteDb(runtime, handle, "__exactSqliteInTransaction");
        auto in_tx = ex_host_sqlite_in_transaction(handle);
        return facebook::jsi::Value(in_tx != 0);
      });
  rt.global().setProperty(rt, "__exactSqliteInTransaction", std::move(sqliteInTransactionFn));

  auto sqliteResultToValue = [](facebook::jsi::Runtime& runtime,
                               char* json,
                               const char* error_message) -> facebook::jsi::Value {
    if (!json) {
      throw facebook::jsi::JSError(runtime, error_message);
    }
    auto value = parseJsonValue(runtime, json);
    ex_host_free_string(json);
    if (value.isObject()) {
      auto object = value.asObject(runtime);
      convertSqliteBlobColumns(runtime, object);
      return object;
    }
    return value;
  };

  // __exactSqliteAll(statementHandle, bindings) -> object {rows, columnTypes}
  auto sqliteAllFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteAll"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteAll: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, statementHandle, "__exactSqliteAll");
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_all(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteAll failed");
      });
  rt.global().setProperty(rt, "__exactSqliteAll", std::move(sqliteAllFn));

  // __exactSqliteGet(statementHandle, bindings) -> object {row, columnTypes}
  auto sqliteGetFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteGet"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteGet: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, statementHandle, "__exactSqliteGet");
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_get(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteGet failed");
      });
  rt.global().setProperty(rt, "__exactSqliteGet", std::move(sqliteGetFn));

  // __exactSqliteRun(statementHandle, bindings) -> object {changes, lastInsertRowid}
  auto sqliteRunFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteRun"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteRun: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, statementHandle, "__exactSqliteRun");
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_run(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteRun failed");
      });
  rt.global().setProperty(rt, "__exactSqliteRun", std::move(sqliteRunFn));

  // __exactSqliteValues(statementHandle, bindings) -> object {rows, columnTypes}
  auto sqliteValuesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteValues"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteValues: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteStatement(runtime, statementHandle, "__exactSqliteValues");
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_values(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteValues failed");
      });
  rt.global().setProperty(rt, "__exactSqliteValues", std::move(sqliteValuesFn));

  // __exactSqliteExec(handle, sql, bindings) -> object {changes, lastInsertRowid}
  auto sqliteExecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteExec"),
      3,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteExec: db handle and sql required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        requireSqliteDb(runtime, handle, "__exactSqliteExec");
        auto sql = args[1].toString(runtime).utf8(runtime);
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
          bindingsJson = stringifyValue(runtime, args[2]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_exec(handle, sql.c_str(), bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteExec failed");
      });
  rt.global().setProperty(rt, "__exactSqliteExec", std::move(sqliteExecFn));

}
