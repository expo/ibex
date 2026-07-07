#include "hermes_runtime_internal.h"

#include <algorithm>
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
        ex_host_sqlite_close(handle);
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
        auto sql = args[1].toString(runtime).utf8(runtime);
        char* json = ex_host_sqlite_prepare(handle, sql.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, "__exactSqlitePrepare failed");
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
        ex_host_sqlite_finalize(handle);
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
