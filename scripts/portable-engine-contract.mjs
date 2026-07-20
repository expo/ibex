// Production primitives for the diagnostic portable-Hermes publisher.
// This module intentionally depends only on Node built-ins: its exact bytes are
// part of the reviewed build-authority closure.
//
// @ref LLP 0035#portable-package-contract — identity inputs use strict I-JSON,
// RFC 8785 canonicalization, byte-level binary parsing, and exact membership.

import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";

const fatalUtf8 = new TextDecoder("utf-8", { fatal: true });
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MACHO_CPU = Object.freeze({ arm64: 0x0100000c, x86_64: 0x01000007 });
const MACHO_GENERIC_CPU_SUBTYPE = Object.freeze({ arm64: 0, x86_64: 3 });
const MACHO_ARCHITECTURE_BY_CPU = new Map(
  Object.entries(MACHO_CPU).map(([architecture, cpu]) => [cpu, architecture]),
);
const MACHO_LOAD_DYLIB_COMMANDS = new Map([
  [0x0c, "LC_LOAD_DYLIB"],
  [0x80000018, "LC_LOAD_WEAK_DYLIB"],
  [0x8000001f, "LC_REEXPORT_DYLIB"],
  [0x20, "LC_LAZY_LOAD_DYLIB"],
  [0x80000023, "LC_LOAD_UPWARD_DYLIB"],
]);
const MACHO_ID_DYLIB = 0x0d;
const MACHO_LOAD_DYLINKER = 0x0e;
const MACHO_RPATH = 0x8000001c;
const HERMES_HBC_MAGIC = 0x1f1903c103bc1fc6n;

export function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertUnicodeScalarString(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error(`${label}: lone high surrogate at UTF-16 offset ${index}`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error(`${label}: lone low surrogate at UTF-16 offset ${index}`);
    }
  }
}

function assertIJsonValue(value, label, seen) {
  if (typeof value === "string") {
    assertUnicodeScalarString(value, label);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label}: non-finite JSON number`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error(`${label}: integer is outside the I-JSON safe range`);
    }
    return;
  }
  if (typeof value === "boolean" || value === null) return;
  if (
    value === undefined ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    typeof value === "bigint"
  ) {
    throw new Error(`${label}: value is not representable in I-JSON`);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error(`${label}: cyclic JSON value`);
    const keys = Object.keys(value);
    if (
      keys.length !== value.length ||
      keys.some((key, index) => key !== String(index)) ||
      Reflect.ownKeys(value).some(
        (key) => key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key)),
      )
    ) {
      throw new Error(`${label}: sparse arrays and extra array fields are forbidden in I-JSON`);
    }
    seen.add(value);
    value.forEach((item, index) => assertIJsonValue(item, `${label}[${index}]`, seen));
    seen.delete(value);
    return;
  }
  if (typeof value !== "object") throw new Error(`${label}: value is not representable in I-JSON`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label}: non-plain object is not representable in I-JSON`);
  }
  if (seen.has(value)) throw new Error(`${label}: cyclic JSON value`);
  seen.add(value);
  const enumerableKeys = Object.keys(value);
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== enumerableKeys.length ||
    ownKeys.some((key) => typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key))
  ) {
    throw new Error(`${label}: JSON object has symbol or non-enumerable own fields`);
  }
  for (const key of enumerableKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw new Error(`${label}.${key}: JSON accessors are forbidden`);
    assertUnicodeScalarString(key, `${label} object key`);
    assertIJsonValue(descriptor.value, `${label}.${key}`, seen);
  }
  seen.delete(value);
}

export function assertIJson(value, label = "$") {
  assertIJsonValue(value, label, new Set());
}

// RFC 8785 orders object keys by UTF-16 code units and uses ECMAScript's
// primitive serialization. assertIJson excludes values JCS cannot represent.
function serializeCanonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeCanonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${serializeCanonicalJson(value[key])}`)
    .join(",")}}`;
}

export function canonicalJson(value) {
  assertIJson(value);
  return serializeCanonicalJson(value);
}

function skipJsonWhitespace(state) {
  while (
    state.text[state.index] === " " ||
    state.text[state.index] === "\t" ||
    state.text[state.index] === "\r" ||
    state.text[state.index] === "\n"
  ) {
    state.index += 1;
  }
}

function parseJsonStringToken(state) {
  const start = state.index;
  if (state.text[state.index] !== '"') throw new Error("expected JSON string");
  state.index += 1;
  while (state.index < state.text.length) {
    const character = state.text[state.index];
    if (character === '"') {
      state.index += 1;
      return JSON.parse(state.text.slice(start, state.index));
    }
    if (character === "\\") {
      state.index += 1;
      if (state.index >= state.text.length) throw new Error("truncated JSON escape");
      if (state.text[state.index] === "u") {
        const escape = state.text.slice(state.index + 1, state.index + 5);
        if (!/^[0-9A-Fa-f]{4}$/u.test(escape)) throw new Error("invalid JSON Unicode escape");
        state.index += 5;
      } else {
        if (!/["\\/bfnrt]/u.test(state.text[state.index])) {
          throw new Error("invalid JSON escape");
        }
        state.index += 1;
      }
      continue;
    }
    if (character.charCodeAt(0) < 0x20) {
      throw new Error("control character in JSON string");
    }
    state.index += 1;
  }
  throw new Error("unterminated JSON string");
}

function parseJsonValueForDuplicateKeys(state) {
  skipJsonWhitespace(state);
  const character = state.text[state.index];
  if (character === "{") return parseJsonObjectForDuplicateKeys(state);
  if (character === "[") return parseJsonArrayForDuplicateKeys(state);
  if (character === '"') {
    parseJsonStringToken(state);
    return;
  }
  const token = state.text
    .slice(state.index)
    .match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u);
  if (!token) throw new Error(`invalid JSON token at character ${state.index}`);
  state.index += token[0].length;
}

function parseJsonObjectForDuplicateKeys(state) {
  state.index += 1;
  skipJsonWhitespace(state);
  const keys = new Set();
  if (state.text[state.index] === "}") {
    state.index += 1;
    return;
  }
  while (state.index < state.text.length) {
    skipJsonWhitespace(state);
    const key = parseJsonStringToken(state);
    if (keys.has(key)) throw new Error(`duplicate JSON object key ${JSON.stringify(key)}`);
    keys.add(key);
    skipJsonWhitespace(state);
    if (state.text[state.index] !== ":") throw new Error("expected colon after JSON key");
    state.index += 1;
    parseJsonValueForDuplicateKeys(state);
    skipJsonWhitespace(state);
    if (state.text[state.index] === "}") {
      state.index += 1;
      return;
    }
    if (state.text[state.index] !== ",") throw new Error("expected comma in JSON object");
    state.index += 1;
  }
  throw new Error("unterminated JSON object");
}

function parseJsonArrayForDuplicateKeys(state) {
  state.index += 1;
  skipJsonWhitespace(state);
  if (state.text[state.index] === "]") {
    state.index += 1;
    return;
  }
  while (state.index < state.text.length) {
    parseJsonValueForDuplicateKeys(state);
    skipJsonWhitespace(state);
    if (state.text[state.index] === "]") {
      state.index += 1;
      return;
    }
    if (state.text[state.index] !== ",") throw new Error("expected comma in JSON array");
    state.index += 1;
  }
  throw new Error("unterminated JSON array");
}

export function parseJsonStrict(bytes, label = "<json>") {
  let text;
  try {
    text = fatalUtf8.decode(bytes);
  } catch (error) {
    throw new Error(`${label}: invalid UTF-8: ${error.message}`);
  }
  const state = { text, index: 0 };
  try {
    parseJsonValueForDuplicateKeys(state);
    skipJsonWhitespace(state);
    if (state.index !== text.length) {
      throw new Error(`unexpected trailing content at character ${state.index}`);
    }
  } catch (error) {
    throw new Error(`${label}: ${error.message}`);
  }
  const value = JSON.parse(text);
  assertIJson(value, label);
  return value;
}

export function assertCanonicalJsonBytes(bytes, value, label = "<json>") {
  const expected = Buffer.from(canonicalJson(value), "utf8");
  if (!Buffer.from(bytes).equals(expected)) {
    throw new Error(`${label}: bytes are not the RFC 8785 canonical encoding`);
  }
}

export function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}: expected an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label}: expected exact fields ${wanted.join(", ")}; got ${actual.join(", ")}`);
  }
}

export function rawDigest(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("hex")}`;
}

export function semanticDigest(domain, value, omitFields = []) {
  const projection = structuredClone(value);
  for (const field of omitFields) delete projection[field];
  const hash = createHash("sha256");
  hash.update(Buffer.from(domain, "utf8"));
  hash.update(Buffer.from([0]));
  hash.update(Buffer.from(canonicalJson(projection), "utf8"));
  return `sha256-${hash.digest("base64url")}`;
}

export function gitObjectId(format, type, bytes) {
  if (format !== "sha1" && format !== "sha256") throw new Error(`unsupported Git object format: ${format}`);
  if (type !== "commit" && type !== "tree") throw new Error(`unsupported Git object type: ${type}`);
  return createHash(format)
    .update(Buffer.from(`${type} ${bytes.length}\0`, "ascii"))
    .update(bytes)
    .digest("hex");
}

export function assertNormalizedPayloadPath(value, label = "payload path") {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label}: empty path`);
  // The v1 producer is deliberately stricter than the schema: all physical
  // Hermes package names are printable ASCII, making Apple/Windows collision
  // equivalence deterministic without a locale or Unicode database.
  if (!/^[\x21-\x7e]+$/u.test(value)) throw new Error(`${label}: only printable ASCII is admitted`);
  if (value.startsWith("/") || value.includes("\\") || value.includes(":")) {
    throw new Error(`${label}: absolute, backslash, and colon syntax is forbidden`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`${label}: path is not normalized`);
  }
  return value;
}

export function assertSafeRelativeSymlink(pathname, target) {
  assertNormalizedPayloadPath(pathname, "symlink path");
  if (typeof target !== "string" || target.length === 0 || !/^[\x21-\x7e]+$/u.test(target)) {
    throw new Error(`${pathname}: symlink target must be non-empty printable ASCII`);
  }
  if (target.startsWith("/") || target.includes("\\") || target.includes(":")) {
    throw new Error(`${pathname}: escaping symlink syntax is forbidden`);
  }
  const base = pathname.split("/").slice(0, -1);
  for (const segment of target.split("/")) {
    if (segment === "" || segment === ".") throw new Error(`${pathname}: symlink target is not normalized`);
    if (segment === "..") {
      if (base.length === 0) throw new Error(`${pathname}: symlink target escapes payload`);
      base.pop();
    } else {
      base.push(segment);
    }
  }
  if (base.length === 0) throw new Error(`${pathname}: symlink target cannot name the payload root`);
  return base.join("/");
}

export function assertUniquePortablePaths(paths, { caseFolded = true } = {}) {
  const raw = new Set();
  const equivalent = new Map();
  for (const pathname of paths) {
    assertNormalizedPayloadPath(pathname);
    if (raw.has(pathname)) throw new Error(`duplicate payload path: ${pathname}`);
    raw.add(pathname);
    const key = caseFolded ? pathname.toLowerCase() : pathname;
    const prior = equivalent.get(key);
    if (prior) throw new Error(`target-filesystem path collision: ${prior} and ${pathname}`);
    equivalent.set(key, pathname);
  }
}

function checkedRange(buffer, offset, size, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset + size > buffer.length) {
    throw new Error(`${label}: byte range ${offset}..${offset + size} is outside ${buffer.length} bytes`);
  }
}

function decodeCString(buffer, start, end, label) {
  checkedRange(buffer, start, end - start, label);
  const nul = buffer.indexOf(0, start);
  if (nul < start || nul >= end) throw new Error(`${label}: missing NUL terminator`);
  const bytes = buffer.subarray(start, nul);
  if (bytes.length === 0) throw new Error(`${label}: empty string`);
  let text;
  try {
    text = fatalUtf8.decode(bytes);
  } catch (error) {
    throw new Error(`${label}: invalid UTF-8: ${error.message}`);
  }
  if (text.includes("\0")) throw new Error(`${label}: embedded NUL`);
  return { bytes: Buffer.from(bytes), text, end: nul + 1 };
}

function selectMachOSlice(buffer, architecture) {
  if (!(architecture in MACHO_CPU)) throw new Error(`unsupported Mach-O architecture: ${architecture}`);
  checkedRange(buffer, 0, 4, "Mach-O header");
  const magicBe = buffer.readUInt32BE(0);
  if (magicBe === 0xcafebabe || magicBe === 0xcafebabf) {
    const is64 = magicBe === 0xcafebabf;
    checkedRange(buffer, 4, 4, "fat Mach-O architecture count");
    const count = buffer.readUInt32BE(4);
    if (count === 0 || count > 64) throw new Error(`fat Mach-O has invalid architecture count ${count}`);
    const rowSize = is64 ? 32 : 20;
    const tableEnd = 8 + count * rowSize;
    checkedRange(buffer, 8, count * rowSize, "fat Mach-O architecture table");
    const matches = [];
    const slices = [];
    const cpuTypes = new Set();
    for (let index = 0; index < count; index += 1) {
      const row = 8 + index * rowSize;
      const cpu = buffer.readUInt32BE(row);
      const cpuSubtype = buffer.readUInt32BE(row + 4);
      const offsetValue = is64 ? buffer.readBigUInt64BE(row + 8) : BigInt(buffer.readUInt32BE(row + 8));
      const sizeValue = is64 ? buffer.readBigUInt64BE(row + 16) : BigInt(buffer.readUInt32BE(row + 12));
      const alignmentExponent = buffer.readUInt32BE(row + (is64 ? 24 : 16));
      if (offsetValue > BigInt(MAX_SAFE_INTEGER) || sizeValue > BigInt(MAX_SAFE_INTEGER)) {
        throw new Error("fat Mach-O slice range exceeds the I-JSON safe integer range");
      }
      const offset = Number(offsetValue);
      const size = Number(sizeValue);
      if (alignmentExponent > 30) {
        throw new Error(`fat Mach-O slice ${index} has unsupported alignment exponent ${alignmentExponent}`);
      }
      const alignment = 2 ** alignmentExponent;
      if (offset % alignment !== 0) {
        throw new Error(`fat Mach-O slice ${index} offset ${offset} is not aligned to ${alignment}`);
      }
      if (size === 0 || offset < tableEnd) throw new Error(`fat Mach-O slice ${index} overlaps its architecture table`);
      checkedRange(buffer, offset, size, `fat Mach-O slice ${index}`);
      if (cpuTypes.has(cpu)) throw new Error(`fat Mach-O contains duplicate CPU type 0x${cpu.toString(16)}`);
      cpuTypes.add(cpu);
      slices.push({ offset, size, index });
      if (cpu === MACHO_CPU[architecture]) matches.push({ offset, size, fatCpuSubtype: cpuSubtype });
    }
    slices.sort((left, right) => left.offset - right.offset);
    for (let index = 1; index < slices.length; index += 1) {
      if (slices[index - 1].offset + slices[index - 1].size > slices[index].offset) {
        throw new Error(`fat Mach-O slices ${slices[index - 1].index} and ${slices[index].index} overlap`);
      }
    }
    if (matches.length !== 1) throw new Error(`fat Mach-O must contain exactly one ${architecture} slice; found ${matches.length}`);
    return {
      ...matches[0],
      container: "fat",
      containerArchitectures: [...cpuTypes]
        .map((cpu) => MACHO_ARCHITECTURE_BY_CPU.get(cpu) ?? `unknown-0x${cpu.toString(16)}`)
        .sort(compareUtf8),
    };
  }
  return {
    offset: 0,
    size: buffer.length,
    container: "thin",
    containerArchitectures: [architecture],
    fatCpuSubtype: null,
  };
}

// @ref LLP 0035#build-consumption-and-post-link-contracts — final-executable
// evidence retains exact load-command kinds, RPATHs, and whole-file identity.
export function parseMachO(
  bytes,
  { architecture = "arm64", requireExternalDefinedSymbols = true } = {},
) {
  const buffer = Buffer.from(bytes);
  const slice = selectMachOSlice(buffer, architecture);
  const base = slice.offset;
  checkedRange(buffer, base, 32, "64-bit Mach-O header");
  if (buffer.readUInt32LE(base) !== 0xfeedfacf) throw new Error("selected image is not a little-endian 64-bit Mach-O");
  if (buffer.readUInt32LE(base + 4) !== MACHO_CPU[architecture]) {
    throw new Error(`selected Mach-O machine is not ${architecture}`);
  }
  const cpuSubtype = buffer.readUInt32LE(base + 8);
  if (slice.fatCpuSubtype !== null && slice.fatCpuSubtype !== cpuSubtype) {
    throw new Error(
      `fat Mach-O ${architecture} CPU subtype ${slice.fatCpuSubtype} does not match slice subtype ${cpuSubtype}`,
    );
  }
  if (cpuSubtype !== MACHO_GENERIC_CPU_SUBTYPE[architecture]) {
    throw new Error(
      `selected Mach-O ${architecture} slice has unsupported CPU subtype ${cpuSubtype}; ` +
        `expected ${MACHO_GENERIC_CPU_SUBTYPE[architecture]}`,
    );
  }
  const fileType = buffer.readUInt32LE(base + 12);
  const commandCount = buffer.readUInt32LE(base + 16);
  const commandBytes = buffer.readUInt32LE(base + 20);
  if (commandCount > 65535) throw new Error("Mach-O load-command count exceeds producer limit");
  if (32 + commandBytes > slice.size) throw new Error("Mach-O load commands escape the selected slice");
  checkedRange(buffer, base + 32, commandBytes, "Mach-O load commands");
  let cursor = base + 32;
  const commandsEnd = cursor + commandBytes;
  const dependencyCommands = [];
  const rpaths = [];
  let dylibId = null;
  let dylinker = null;
  let symbolTable = null;
  for (let index = 0; index < commandCount; index += 1) {
    checkedRange(buffer, cursor, 8, `Mach-O load command ${index}`);
    const command = buffer.readUInt32LE(cursor);
    const commandSize = buffer.readUInt32LE(cursor + 4);
    if (commandSize < 8 || commandSize % 4 !== 0 || cursor + commandSize > commandsEnd) {
      throw new Error(`Mach-O load command ${index} has invalid size ${commandSize}`);
    }
    if (MACHO_LOAD_DYLIB_COMMANDS.has(command)) {
      if (commandSize < 24) throw new Error(`Mach-O dylib command ${index} is truncated`);
      const nameOffset = buffer.readUInt32LE(cursor + 8);
      if (nameOffset < 24 || nameOffset >= commandSize) throw new Error(`Mach-O dylib command ${index} has invalid name offset`);
      const decoded = decodeCString(
        buffer,
        cursor + nameOffset,
        cursor + commandSize,
        `Mach-O dependency ${index}`,
      );
      if (!buffer.subarray(decoded.end, cursor + commandSize).every((byte) => byte === 0)) {
        throw new Error(`Mach-O dependency ${index} has non-zero string padding`);
      }
      dependencyCommands.push({
        command: MACHO_LOAD_DYLIB_COMMANDS.get(command),
        installName: decoded.text,
      });
    }
    if (command === MACHO_ID_DYLIB) {
      if (dylibId !== null || commandSize < 24) {
        throw new Error("Mach-O must contain at most one complete LC_ID_DYLIB command");
      }
      const nameOffset = buffer.readUInt32LE(cursor + 8);
      if (nameOffset < 24 || nameOffset >= commandSize) throw new Error("Mach-O LC_ID_DYLIB has invalid name offset");
      const decoded = decodeCString(buffer, cursor + nameOffset, cursor + commandSize, "Mach-O dylib ID");
      if (!buffer.subarray(decoded.end, cursor + commandSize).every((byte) => byte === 0)) {
        throw new Error("Mach-O dylib ID has non-zero string padding");
      }
      dylibId = decoded.text;
    }
    if (command === MACHO_LOAD_DYLINKER) {
      if (dylinker !== null || commandSize < 12) {
        throw new Error("Mach-O must contain at most one complete LC_LOAD_DYLINKER command");
      }
      const nameOffset = buffer.readUInt32LE(cursor + 8);
      if (nameOffset < 12 || nameOffset >= commandSize) throw new Error("Mach-O LC_LOAD_DYLINKER has invalid name offset");
      const decoded = decodeCString(buffer, cursor + nameOffset, cursor + commandSize, "Mach-O dynamic linker");
      if (!buffer.subarray(decoded.end, cursor + commandSize).every((byte) => byte === 0)) {
        throw new Error("Mach-O dynamic linker has non-zero string padding");
      }
      dylinker = decoded.text;
    }
    if (command === MACHO_RPATH) {
      if (commandSize < 12) throw new Error(`Mach-O LC_RPATH command ${index} is truncated`);
      const pathOffset = buffer.readUInt32LE(cursor + 8);
      if (pathOffset < 12 || pathOffset >= commandSize) {
        throw new Error(`Mach-O LC_RPATH command ${index} has invalid path offset`);
      }
      const decoded = decodeCString(
        buffer,
        cursor + pathOffset,
        cursor + commandSize,
        `Mach-O LC_RPATH ${index}`,
      );
      if (!buffer.subarray(decoded.end, cursor + commandSize).every((byte) => byte === 0)) {
        throw new Error(`Mach-O LC_RPATH command ${index} has non-zero string padding`);
      }
      rpaths.push(decoded.text);
    }
    if (command === 0x02) {
      if (commandSize !== 24 || symbolTable) throw new Error("Mach-O must contain at most one canonical LC_SYMTAB command");
      symbolTable = {
        symbolOffset: buffer.readUInt32LE(cursor + 8),
        symbolCount: buffer.readUInt32LE(cursor + 12),
        stringOffset: buffer.readUInt32LE(cursor + 16),
        stringSize: buffer.readUInt32LE(cursor + 20),
      };
    }
    cursor += commandSize;
  }
  if (cursor !== commandsEnd) throw new Error("Mach-O load-command bytes do not match declared count");
  const names = new Map();
  if (symbolTable) {
    if (symbolTable.symbolCount > 10_000_000) throw new Error("Mach-O symbol count exceeds producer limit");
    const symbolsStart = base + symbolTable.symbolOffset;
    const stringsStart = base + symbolTable.stringOffset;
    const symbolsSize = symbolTable.symbolCount * 16;
    if (symbolTable.symbolOffset + symbolsSize > slice.size || symbolTable.stringOffset + symbolTable.stringSize > slice.size) {
      throw new Error("Mach-O symbol or string table escapes the selected slice");
    }
    const loadRange = [base, base + 32 + commandBytes];
    const symbolRange = [symbolsStart, symbolsStart + symbolsSize];
    const stringRange = [stringsStart, stringsStart + symbolTable.stringSize];
    const overlaps = ([leftStart, leftEnd], [rightStart, rightEnd]) => leftStart < rightEnd && rightStart < leftEnd;
    if (overlaps(loadRange, symbolRange) || overlaps(loadRange, stringRange) || overlaps(symbolRange, stringRange)) {
      throw new Error("Mach-O header/load commands, symbol table, and string table must not overlap");
    }
    checkedRange(buffer, symbolsStart, symbolsSize, "Mach-O nlist_64 table");
    checkedRange(buffer, stringsStart, symbolTable.stringSize, "Mach-O string table");
    const stringsEnd = stringsStart + symbolTable.stringSize;
    for (let index = 0; index < symbolTable.symbolCount; index += 1) {
      const row = symbolsStart + index * 16;
      const stringIndex = buffer.readUInt32LE(row);
      const type = buffer[row + 4];
      const isExternal = (type & 0x01) !== 0;
      const isDebug = (type & 0xe0) !== 0;
      const kind = type & 0x0e;
      const isDefined = kind === 0x02 || kind === 0x0a || kind === 0x0e;
      if (!isExternal || isDebug || !isDefined) continue;
      if (stringIndex === 0 || stringIndex >= symbolTable.stringSize) throw new Error(`Mach-O symbol ${index} has invalid string index`);
      const decoded = decodeCString(buffer, stringsStart + stringIndex, stringsEnd, `Mach-O symbol ${index}`);
      names.set(decoded.bytes.toString("base64"), decoded.bytes);
    }
  }
  if (requireExternalDefinedSymbols && !symbolTable) {
    throw new Error("Mach-O has no LC_SYMTAB for external-defined symbol extraction");
  }
  if (requireExternalDefinedSymbols && names.size === 0) {
    throw new Error("Mach-O has no external-defined symbols");
  }
  const dependencies = dependencyCommands.map(({ installName }) => installName);
  const dependencySet = [...new Set(dependencies)].sort(compareUtf8);
  if (dependencySet.length !== dependencies.length) throw new Error("Mach-O contains duplicate load-dylib dependency commands");
  const sortedDependencyCommands = dependencyCommands.sort((left, right) =>
    compareUtf8(`${left.command}\0${left.installName}`, `${right.command}\0${right.installName}`),
  );
  const rpathSet = [...new Set(rpaths)].sort(compareUtf8);
  if (rpathSet.length !== rpaths.length) throw new Error("Mach-O contains duplicate LC_RPATH commands");
  return {
    format: "mach-o",
    architecture,
    cpuSubtype,
    fileType,
    dylibId,
    dylinker,
    dependencies: dependencySet,
    dependencyCommands: sortedDependencyCommands,
    rpaths: rpathSet,
    executableDigest: rawDigest(buffer),
    executableSize: buffer.length,
    externalDefinedSymbolNames: [...names.values()].sort(Buffer.compare),
    container: slice.container,
    containerArchitectures: slice.containerArchitectures,
    sliceOffset: slice.offset,
    sliceSize: slice.size,
  };
}

export function parseHermesBytecode(bytes) {
  const buffer = Buffer.from(bytes);
  checkedRange(buffer, 0, 36, "Hermes bytecode header");
  if (buffer.readBigUInt64LE(0) !== HERMES_HBC_MAGIC) throw new Error("Hermes bytecode has the wrong magic header");
  const version = buffer.readUInt32LE(8);
  const fileLength = buffer.readUInt32LE(32);
  if (fileLength !== buffer.length) {
    throw new Error(`Hermes bytecode header length ${fileLength} does not equal output length ${buffer.length}`);
  }
  return { version, fileLength };
}

function writeTarText(header, offset, length, value, label) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error(`${label}: value is too long for ustar`);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label}: invalid ustar integer`);
  const octal = value.toString(8);
  if (octal.length > length - 1) throw new Error(`${label}: value does not fit ustar field`);
  header.write(`${octal.padStart(length - 1, "0")}\0`, offset, length, "ascii");
}

function splitUstarPath(pathname) {
  const direct = Buffer.byteLength(pathname, "utf8");
  if (direct <= 100) return { name: pathname, prefix: "" };
  const segments = pathname.split("/");
  for (let split = segments.length - 1; split > 0; split -= 1) {
    const prefix = segments.slice(0, split).join("/");
    const name = segments.slice(split).join("/");
    if (Buffer.byteLength(prefix, "utf8") <= 155 && Buffer.byteLength(name, "utf8") <= 100) {
      return { name, prefix };
    }
  }
  throw new Error(`${pathname}: path does not fit deterministic ustar fields`);
}

function tarHeader(member) {
  const header = Buffer.alloc(512);
  const tarPath = member.kind === "directory" ? `${member.path}/` : member.path;
  const { name, prefix } = splitUstarPath(tarPath);
  writeTarText(header, 0, 100, name, member.path);
  const mode = member.kind === "symlink" ? 0o777 : member.kind === "directory" || member.executable ? 0o755 : 0o644;
  writeTarOctal(header, 100, 8, mode, `${member.path} mode`);
  writeTarOctal(header, 108, 8, 0, `${member.path} uid`);
  writeTarOctal(header, 116, 8, 0, `${member.path} gid`);
  writeTarOctal(header, 124, 12, member.kind === "regular" ? member.bytes.length : 0, `${member.path} size`);
  writeTarOctal(header, 136, 12, 0, `${member.path} mtime`);
  header.fill(0x20, 148, 156);
  header[156] = member.kind === "regular" ? 0x30 : member.kind === "directory" ? 0x35 : 0x32;
  if (member.kind === "symlink") writeTarText(header, 157, 100, member.target, `${member.path} symlink target`);
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  writeTarText(header, 345, 155, prefix, `${member.path} prefix`);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumOctal = checksum.toString(8);
  if (checksumOctal.length > 6) throw new Error(`${member.path}: ustar checksum overflow`);
  header.write(`${checksumOctal.padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function normalizeUstarMembers(members) {
  const normalized = members.map((member) => {
    assertExactKeys(
      member,
      member.kind === "regular"
        ? ["path", "kind", "bytes", "executable"]
        : member.kind === "directory"
          ? ["path", "kind"]
          : ["path", "kind", "target"],
      `archive member ${member.path ?? "<unknown>"}`,
    );
    assertNormalizedPayloadPath(member.path, "archive member path");
    if (member.path.startsWith("payload/") === false && member.path !== "payload" && member.path !== "META-INF" && member.path !== "META-INF/portable-engine-manifest.json") {
      throw new Error(`${member.path}: archive member is outside the closed envelope`);
    }
    if (member.kind === "regular") {
      if (typeof member.executable !== "boolean") throw new Error(`${member.path}: executable must be boolean`);
      return { ...member, bytes: Buffer.from(member.bytes) };
    }
    if (member.kind === "symlink") assertSafeRelativeSymlink(member.path, member.target);
    if (member.kind !== "directory" && member.kind !== "symlink") throw new Error(`${member.path}: unsupported archive kind`);
    return { ...member };
  });
  assertUniquePortablePaths(normalized.map(({ path }) => path));
  normalized.sort((left, right) => compareUtf8(left.path, right.path));
  return normalized;
}

export function deterministicUstarSize(members) {
  const normalized = normalizeUstarMembers(members);
  let tarSize = 1024;
  for (const member of normalized) {
    const bodySize = member.kind === "regular" ? Math.ceil(member.bytes.length / 512) * 512 : 0;
    tarSize += 512 + bodySize;
    if (!Number.isSafeInteger(tarSize)) throw new Error("deterministic ustar size is not a safe integer");
  }
  return tarSize;
}

export function deterministicUstarGzipSize(members) {
  const tarSize = deterministicUstarSize(members);
  const deflateBlocks = Math.ceil(tarSize / 0xffff);
  const archiveSize = 10 + tarSize + deflateBlocks * 5 + 8;
  if (!Number.isSafeInteger(archiveSize)) throw new Error("deterministic gzip size is not a safe integer");
  return archiveSize;
}

export function buildDeterministicUstar(members) {
  const normalized = normalizeUstarMembers(members);
  const chunks = [];
  for (const member of normalized) {
    chunks.push(tarHeader(member));
    if (member.kind === "regular") {
      chunks.push(member.bytes);
      const padding = (512 - (member.bytes.length % 512)) % 512;
      if (padding) chunks.push(Buffer.alloc(padding));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function buildDeterministicUstarGzip(members) {
  const tar = buildDeterministicUstar(members);
  // Emit DEFLATE stored blocks ourselves. zlib's compressed bitstream is not
  // stable across library versions, whereas stored blocks have one obvious
  // byte projection and remain bounded by the archive limits.
  const blocks = [];
  for (let offset = 0; offset < tar.length; offset += 0xffff) {
    const size = Math.min(0xffff, tar.length - offset);
    const block = Buffer.alloc(5 + size);
    block[0] = offset + size === tar.length ? 0x01 : 0x00;
    block.writeUInt16LE(size, 1);
    block.writeUInt16LE((~size) & 0xffff, 3);
    tar.copy(block, 5, offset, offset + size);
    blocks.push(block);
  }
  const compressed = Buffer.concat(blocks);
  const header = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(tar), 0);
  trailer.writeUInt32LE(tar.length >>> 0, 4);
  return Buffer.concat([header, compressed, trailer]);
}

function parseTarOctal(field, label) {
  const text = field.toString("ascii").replace(/\0.*$/u, "").trim();
  if (!/^[0-7]+$/u.test(text)) throw new Error(`${label}: invalid ustar octal field`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw new Error(`${label}: ustar integer is unsafe`);
  return value;
}

function assertDeclaredArchiveGraph(members, maxSymlinkDepth) {
  const byPath = new Map(members.map((member) => [member.path, member]));
  if (byPath.size !== members.length) throw new Error("ustar archive contains duplicate member paths");
  for (const member of members) {
    const segments = member.path.split("/");
    for (let length = 1; length < segments.length; length += 1) {
      const parent = segments.slice(0, length).join("/");
      const parentMember = byPath.get(parent);
      if (!parentMember || parentMember.kind !== "directory") {
        throw new Error(`${member.path}: parent ${parent} is not a declared directory`);
      }
    }
  }

  const resolvePath = (pathname, resolving = new Set(), depth = 0) => {
    if (depth > maxSymlinkDepth) {
      throw new Error(`${pathname}: symlink resolution exceeds ${maxSymlinkDepth} steps`);
    }
    const segments = pathname.split("/");
    for (let index = 0; index < segments.length; index += 1) {
      const candidate = segments.slice(0, index + 1).join("/");
      const entry = byPath.get(candidate);
      if (!entry) throw new Error(`${pathname}: symlink traversal reaches undeclared ${candidate}`);
      if (entry.kind === "symlink") {
        if (resolving.has(candidate)) throw new Error(`${candidate}: symlink cycle`);
        const nextResolving = new Set(resolving);
        nextResolving.add(candidate);
        const lexicalTarget = assertSafeRelativeSymlink(candidate, entry.target);
        const resolvedTarget = resolvePath(lexicalTarget, nextResolving, depth + 1);
        const remainder = segments.slice(index + 1);
        return resolvePath(
          remainder.length === 0 ? resolvedTarget : `${resolvedTarget}/${remainder.join("/")}`,
          nextResolving,
          depth + 1,
        );
      }
      if (index < segments.length - 1 && entry.kind !== "directory") {
        throw new Error(`${pathname}: traversal crosses non-directory ${candidate}`);
      }
    }
    return pathname;
  };

  for (const member of members) {
    if (member.kind === "symlink") resolvePath(member.path);
  }
}

export function inspectUstarGzip(
  bytes,
  {
    maxArchiveBytes = 1_073_741_824,
    maxOutputBytes = 2_147_483_648,
    maxMemberCount = 4096,
    maxRegularFileBytes = 536_870_912,
    maxExpandedBytes = 2_147_483_648,
    maxSymlinkDepth = 32,
  } = {},
) {
  const archive = Buffer.from(bytes);
  if (!Number.isSafeInteger(maxArchiveBytes) || maxArchiveBytes <= 0) {
    throw new Error("invalid archive-byte limit");
  }
  if (archive.length > maxArchiveBytes) throw new Error("archive exceeds its byte limit");
  if (archive.length < 18 || !archive.subarray(0, 10).equals(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff]))) {
    throw new Error("archive does not use the deterministic gzip envelope");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) throw new Error("invalid gzip output limit");
  if (!Number.isSafeInteger(maxMemberCount) || maxMemberCount <= 0) {
    throw new Error("invalid archive member-count limit");
  }
  if (!Number.isSafeInteger(maxRegularFileBytes) || maxRegularFileBytes <= 0) {
    throw new Error("invalid regular-file limit");
  }
  if (!Number.isSafeInteger(maxExpandedBytes) || maxExpandedBytes <= 0) {
    throw new Error("invalid expanded-byte limit");
  }
  if (!Number.isSafeInteger(maxSymlinkDepth) || maxSymlinkDepth <= 0) {
    throw new Error("invalid symlink-depth limit");
  }
  const tar = gunzipSync(archive, { maxOutputLength: maxOutputBytes });
  const members = [];
  let expandedBytes = 0;
  let cursor = 0;
  while (cursor + 512 <= tar.length) {
    const header = tar.subarray(cursor, cursor + 512);
    if (header.every((byte) => byte === 0)) {
      if (cursor + 1024 !== tar.length || !tar.subarray(cursor + 512).every((byte) => byte === 0)) {
        throw new Error("ustar archive does not end with exactly two zero blocks");
      }
      const sortedPaths = members.map(({ path: pathname }) => pathname).sort(compareUtf8);
      if (members.some((member, index) => member.path !== sortedPaths[index])) {
        throw new Error("ustar members are not in canonical UTF-8 path order");
      }
      assertDeclaredArchiveGraph(members, maxSymlinkDepth);
      const reconstructed = buildDeterministicUstarGzip(members);
      if (!reconstructed.equals(archive)) {
        throw new Error("archive bytes differ from the deterministic ustar+gzip projection");
      }
      return members;
    }
    if (header.toString("ascii", 257, 263) !== "ustar\0") throw new Error("archive member is not ustar");
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/u, "");
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/u, "");
    let pathname = prefix ? `${prefix}/${name}` : name;
    const type = String.fromCharCode(header[156]);
    if (type === "5" && pathname.endsWith("/")) pathname = pathname.slice(0, -1);
    assertNormalizedPayloadPath(pathname, "ustar member path");
    const size = parseTarOctal(header.subarray(124, 136), `${pathname} size`);
    const mode = parseTarOctal(header.subarray(100, 108), `${pathname} mode`);
    const uid = parseTarOctal(header.subarray(108, 116), `${pathname} uid`);
    const gid = parseTarOctal(header.subarray(116, 124), `${pathname} gid`);
    const mtime = parseTarOctal(header.subarray(136, 148), `${pathname} mtime`);
    const storedChecksum = parseTarOctal(header.subarray(148, 156), `${pathname} checksum`);
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    let computedChecksum = 0;
    for (const byte of checksumHeader) computedChecksum += byte;
    if (storedChecksum !== computedChecksum) throw new Error(`${pathname}: ustar checksum mismatch`);
    if (uid !== 0 || gid !== 0 || mtime !== 0) throw new Error(`${pathname}: ustar ownership/time metadata is not normalized`);
    if (header.toString("ascii", 263, 265) !== "00") throw new Error(`${pathname}: unsupported ustar version`);
    if (!header.subarray(265, 345).every((byte) => byte === 0) || !header.subarray(500, 512).every((byte) => byte === 0)) {
      throw new Error(`${pathname}: ustar user/group/device padding metadata is not normalized`);
    }
    const kind = type === "0" || type === "\0" ? "regular" : type === "5" ? "directory" : type === "2" ? "symlink" : null;
    if (!kind) throw new Error(`${pathname}: unsupported ustar type ${JSON.stringify(type)}`);
    if (members.length + 1 > maxMemberCount) throw new Error("ustar member count exceeds policy");
    if (kind !== "regular" && size !== 0) throw new Error(`${pathname}: non-regular ustar member has data`);
    if (kind === "regular") {
      if (size > maxRegularFileBytes) throw new Error(`${pathname}: regular file exceeds policy`);
      expandedBytes += size;
      if (!Number.isSafeInteger(expandedBytes) || expandedBytes > maxExpandedBytes) {
        throw new Error("ustar expanded regular bytes exceed policy");
      }
    }
    const dataStart = cursor + 512;
    checkedRange(tar, dataStart, size, `${pathname} body`);
    const expectedMode = kind === "symlink" ? 0o777 : kind === "directory" || mode === 0o755 ? 0o755 : 0o644;
    if (mode !== expectedMode || (kind === "regular" && mode !== 0o644 && mode !== 0o755)) {
      throw new Error(`${pathname}: ustar mode is not normalized`);
    }
    const member = { path: pathname, kind };
    if (kind === "regular") {
      member.bytes = Buffer.from(tar.subarray(dataStart, dataStart + size));
      member.executable = mode === 0o755;
    }
    if (kind === "symlink") {
      member.target = header.subarray(157, 257).toString("utf8").replace(/\0.*$/u, "");
      assertSafeRelativeSymlink(pathname, member.target);
    }
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;
    if (!tar.subarray(dataStart + size, paddedEnd).every((byte) => byte === 0)) {
      throw new Error(`${pathname}: ustar body padding is not zero`);
    }
    members.push(member);
    cursor = paddedEnd;
  }
  throw new Error("ustar archive is missing its end markers");
}
