#include "hermes_runtime_internal.h"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <sstream>
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
extern "C" uint64_t ex_host_legacy_authorization_generation(void);
extern "C" int32_t ex_host_legacy_authorization_cacheable(void);

namespace {

constexpr uint64_t SQLITE_OPEN_READONLY = 0x00000001;
constexpr uint64_t SQLITE_OPEN_READWRITE = 0x00000002;
constexpr uint64_t SQLITE_OPEN_CREATE = 0x00000004;

struct SqliteHandleEntry {
  uint64_t runtimeNonce;
  uint64_t owner;
  std::vector<std::string> capabilities;
  uint64_t authorizationGeneration = 0;
  std::vector<uint64_t> authorizedPrincipalStack;
};

struct SqliteStatementEntry {
  uint64_t runtimeNonce;
  uint64_t owner;
  uint64_t dbHandle;
  std::vector<std::string> capabilities;
  uint64_t authorizationGeneration = 0;
  std::vector<uint64_t> authorizedPrincipalStack;
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

template <typename Entry>
void requireSqliteAuthorization(
    facebook::jsi::Runtime& runtime,
    Entry& entry,
    const char* syscall) {
  auto principals = exactCollectTypedPrincipalStack();
  if (principals.empty() || principals.front() != entry.owner) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": sqlite handle belongs to a different principal");
  }

  if (ex_host_legacy_authorization_cacheable() != 1) {
    requireSqliteCapabilities(runtime, entry.capabilities, syscall);
    entry.authorizationGeneration = 0;
    entry.authorizedPrincipalStack.clear();
    return;
  }

  auto generation = ex_host_legacy_authorization_generation();
  if (generation != 0 && generation == entry.authorizationGeneration &&
      principals == entry.authorizedPrincipalStack) {
    return;
  }

  // A retained SQLite handle fixes its path, capabilities, owner, and deputy
  // stack. Re-run the full legacy checks only when one of those identities or
  // the policy generation changed. A concurrent publication during the check
  // cannot seed a lease: retry against a stable generation, then fail closed.
  // @ref LLP 0021#handles-dynamic-authority-and-generations
  for (size_t attempt = 0; attempt < 3; ++attempt) {
    auto before = ex_host_legacy_authorization_generation();
    if (before == 0) break;
    requireSqliteCapabilities(runtime, entry.capabilities, syscall);
    auto after = ex_host_legacy_authorization_generation();
    if (before == after) {
      entry.authorizationGeneration = after;
      entry.authorizedPrincipalStack = std::move(principals);
      return;
    }
  }
  throw facebook::jsi::JSError(
      runtime, std::string(syscall) + ": capability authority changed during authorization");
}

void registerSqliteDb(uint64_t dbHandle, SqliteHandleEntry entry) {
  if (dbHandle == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  g_sqlite_dbs[dbHandle] = std::move(entry);
}

void unregisterSqliteDb(uint64_t dbHandle) {
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  auto db = g_sqlite_dbs.find(dbHandle);
  if (db == g_sqlite_dbs.end() ||
      db->second.runtimeNonce != exactCurrentRuntimeNonce()) {
    return;
  }
  auto runtimeNonce = db->second.runtimeNonce;
  g_sqlite_dbs.erase(db);
  for (auto it = g_sqlite_statements.begin(); it != g_sqlite_statements.end();) {
    if (it->second.runtimeNonce == runtimeNonce &&
        it->second.dbHandle == dbHandle) {
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
  if (db == g_sqlite_dbs.end() ||
      db->second.runtimeNonce != exactCurrentRuntimeNonce()) {
    return;
  }
  g_sqlite_statements[statementHandle] = SqliteStatementEntry{
      db->second.runtimeNonce,
      db->second.owner,
      dbHandle,
      db->second.capabilities,
      db->second.authorizationGeneration,
      db->second.authorizedPrincipalStack,
  };
}

void unregisterSqliteStatement(uint64_t statementHandle) {
  std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
  auto statement = g_sqlite_statements.find(statementHandle);
  if (statement != g_sqlite_statements.end() &&
      statement->second.runtimeNonce == exactCurrentRuntimeNonce()) {
    g_sqlite_statements.erase(statement);
  }
}

SqliteHandleEntry requireSqliteDb(
    facebook::jsi::Runtime& runtime,
    uint64_t dbHandle,
    const char* syscall) {
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
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": sqlite handle belongs to a different runtime");
  }
  if (!isAllowAll() && entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": sqlite handle belongs to a different principal");
  }
  if (!isAllowAll()) {
    requireSqliteAuthorization(runtime, entry, syscall);
    std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
    auto current = g_sqlite_dbs.find(dbHandle);
    if (current != g_sqlite_dbs.end() &&
        current->second.runtimeNonce == entry.runtimeNonce &&
        current->second.owner == entry.owner) {
      current->second.authorizationGeneration = entry.authorizationGeneration;
      current->second.authorizedPrincipalStack = entry.authorizedPrincipalStack;
    }
  }
  return entry;
}

SqliteStatementEntry requireSqliteStatement(
    facebook::jsi::Runtime& runtime,
    uint64_t statementHandle,
    const char* syscall) {
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
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(
        runtime,
        std::string(syscall) + ": sqlite statement belongs to a different runtime");
  }
  if (!isAllowAll() && entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime,
        std::string(syscall) + ": sqlite statement belongs to a different principal");
  }
  if (!isAllowAll()) {
    requireSqliteAuthorization(runtime, entry, syscall);
    std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
    auto current = g_sqlite_statements.find(statementHandle);
    if (current != g_sqlite_statements.end() &&
        current->second.runtimeNonce == entry.runtimeNonce &&
        current->second.owner == entry.owner) {
      current->second.authorizationGeneration = entry.authorizationGeneration;
      current->second.authorizedPrincipalStack = entry.authorizedPrincipalStack;
    }
  }
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

std::string sqliteBase64Encode(const uint8_t* data, size_t length) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((length + 2) / 3) * 4);
  for (size_t i = 0; i < length; i += 3) {
    uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
    if (i + 1 < length) {
      chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
    }
    if (i + 2 < length) {
      chunk |= static_cast<uint32_t>(data[i + 2]);
    }
    out.push_back(alphabet[(chunk >> 18) & 0x3f]);
    out.push_back(alphabet[(chunk >> 12) & 0x3f]);
    out.push_back(i + 1 < length ? alphabet[(chunk >> 6) & 0x3f] : '=');
    out.push_back(i + 2 < length ? alphabet[chunk & 0x3f] : '=');
  }
  return out;
}

bool sqliteBase64Decode(const std::string& input, std::vector<uint8_t>& output) {
  auto decode = [](unsigned char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
  };
  if (input.size() % 4 != 0) return false;
  output.clear();
  output.reserve((input.size() / 4) * 3);
  for (size_t i = 0; i < input.size(); i += 4) {
    int a = decode(static_cast<unsigned char>(input[i]));
    int b = decode(static_cast<unsigned char>(input[i + 1]));
    int c = input[i + 2] == '=' ? -2 : decode(static_cast<unsigned char>(input[i + 2]));
    int d = input[i + 3] == '=' ? -2 : decode(static_cast<unsigned char>(input[i + 3]));
    if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2) ||
        ((c == -2 || d == -2) && i + 4 != input.size())) {
      return false;
    }
    uint32_t chunk = (static_cast<uint32_t>(a) << 18) |
        (static_cast<uint32_t>(b) << 12) |
        (static_cast<uint32_t>(c < 0 ? 0 : c) << 6) |
        static_cast<uint32_t>(d < 0 ? 0 : d);
    output.push_back(static_cast<uint8_t>((chunk >> 16) & 0xff));
    if (c >= 0) output.push_back(static_cast<uint8_t>((chunk >> 8) & 0xff));
    if (d >= 0) output.push_back(static_cast<uint8_t>(chunk & 0xff));
  }
  return true;
}

std::string stringifySqliteBindingValue(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (value.isObject()) {
    auto object = value.asObject(runtime);
    const uint8_t* data = nullptr;
    size_t length = 0;
    if (extractArrayBufferView(runtime, object, data, length)) {
      // JSON.stringify turns Uint8Array into an object with numeric keys. That
      // silently stored IndexedDB's binary envelope as TEXT. Carry typed bytes
      // over the C ABI in an unambiguous tagged scalar; Rust decodes the tag to
      // a real SQLite BLOB before executing the statement.
      return std::string("{\"$ibexSqliteBindingV1\":{\"kind\":\"blob\",\"base64\":") +
          jsonString(sqliteBase64Encode(data, length)) + "}}";
    }
  }
  // Wrap every ordinary value too. Otherwise a user object shaped like the
  // private blob tag could forge the transport discriminant and silently
  // change from the legacy object binding semantics to BLOB.
  return std::string("{\"$ibexSqliteBindingV1\":{\"kind\":\"value\",\"value\":") +
      stringifyValue(runtime, value) + "}}";
}

std::string stringifySqliteBindings(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (!value.isObject()) {
    return stringifySqliteBindingValue(runtime, value);
  }

  auto object = value.asObject(runtime);
  const uint8_t* directData = nullptr;
  size_t directLength = 0;
  if (extractArrayBufferView(runtime, object, directData, directLength)) {
    return stringifySqliteBindingValue(runtime, value);
  }

  std::ostringstream out;
  if (object.isArray(runtime)) {
    auto array = object.asArray(runtime);
    out << '[';
    for (size_t i = 0; i < array.size(runtime); ++i) {
      if (i != 0) {
        out << ',';
      }
      out << stringifySqliteBindingValue(runtime, array.getValueAtIndex(runtime, i));
    }
    out << ']';
    return out.str();
  }

  auto names = object.getPropertyNames(runtime);
  out << '{';
  for (size_t i = 0; i < names.size(runtime); ++i) {
    auto nameValue = names.getValueAtIndex(runtime, i);
    if (!nameValue.isString()) {
      continue;
    }
    if (out.tellp() > 1) {
      out << ',';
    }
    auto name = nameValue.asString(runtime).utf8(runtime);
    out << jsonString(name) << ':'
        << stringifySqliteBindingValue(runtime, object.getProperty(runtime, name.c_str()));
  }
  out << '}';
  return out.str();
}

} // namespace

void exactCleanupRuntimeSqlite(uint64_t runtimeNonce) {
  std::vector<uint64_t> dbHandles;
  {
    std::lock_guard<std::mutex> lock(g_sqlite_handle_mutex);
    for (auto it = g_sqlite_statements.begin(); it != g_sqlite_statements.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        it = g_sqlite_statements.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = g_sqlite_dbs.begin(); it != g_sqlite_dbs.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        dbHandles.push_back(it->first);
        it = g_sqlite_dbs.erase(it);
      } else {
        ++it;
      }
    }
  }
  // Closing can drop the final Arc and run SQLite teardown. Never do that
  // while holding the registry mutex used by Host calls in other runtimes.
  for (auto handle : dbHandles) {
    ex_host_sqlite_close(handle);
  }
}

static bool sqliteColumnTypeIsBlob(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Array& columnTypes,
    size_t index) {
  auto type = columnTypes.getValueAtIndex(runtime, index);
  return type.isString() && type.asString(runtime).utf8(runtime) == "BLOB";
}

static facebook::jsi::Value convertSqliteBlobValue(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Value value,
    bool allowLegacyNumberArray) {
  if (!value.isObject()) {
    return value;
  }

  auto object = value.asObject(runtime);
  if (!object.isArray(runtime)) {
    auto encoded = object.getProperty(runtime, "$ibexSqliteBlobResultBase64");
    if (!encoded.isString()) return value;
    std::vector<uint8_t> bytes;
    if (!sqliteBase64Decode(encoded.asString(runtime).utf8(runtime), bytes)) return value;
    return makeUint8Array(runtime, std::move(bytes));
  }

  // Current Rust results use the private base64 envelope above. Number arrays
  // are accepted only for legacy results whose SQLite column type is BLOB;
  // treating every user array as bytes would corrupt ordinary JSON values.
  if (!allowLegacyNumberArray) return value;

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
    bool legacyBlob = type != columnTypesByName.end() && type->second == "BLOB";
    row.setProperty(
        runtime,
        property.c_str(),
        convertSqliteBlobValue(
            runtime, row.getProperty(runtime, property.c_str()), legacyBlob));
  }
}

static void convertSqliteBlobColumnsInRowArray(
    facebook::jsi::Runtime& runtime,
    facebook::jsi::Array& row,
    const facebook::jsi::Array& columnTypes) {
  auto limit = row.size(runtime);
  for (size_t i = 0; i < limit; ++i) {
    bool legacyBlob = i < columnTypes.size(runtime) &&
        sqliteColumnTypeIsBlob(runtime, columnTypes, i);
    row.setValueAtIndex(
        runtime,
        i,
        convertSqliteBlobValue(
            runtime, row.getValueAtIndex(runtime, i), legacyBlob));
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
        SqliteHandleEntry authorization{
            exactCurrentRuntimeNonce(), currentPrincipalId(),
            std::move(capabilities), 0, {}};
        requireSqliteAuthorization(runtime, authorization, "__exactSqliteOpen");
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
        registerSqliteDb(handle, std::move(authorization));
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
          bindingsJson = stringifySqliteBindings(runtime, args[1]);
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
          bindingsJson = stringifySqliteBindings(runtime, args[1]);
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
          bindingsJson = stringifySqliteBindings(runtime, args[1]);
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
          bindingsJson = stringifySqliteBindings(runtime, args[1]);
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
          bindingsJson = stringifySqliteBindings(runtime, args[2]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_exec(handle, sql.c_str(), bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteExec failed");
      });
  rt.global().setProperty(rt, "__exactSqliteExec", std::move(sqliteExecFn));

}
