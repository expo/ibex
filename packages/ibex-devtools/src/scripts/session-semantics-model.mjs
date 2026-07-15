/**
 * Executable reference model for LLP 0024 section 7.
 *
 * The model consumes a deliberately small declaration/action IR. It does not
 * parse JavaScript and it never evaluates fixture values. Session lowering and
 * the engine implementation must eventually translate real source into the
 * same abstract operations and compare their observations with these fixtures.
 *
 * @ref LLP 0024#7-the-session-record — the checked-cell session environment,
 * cross-kind replacement, provenance, journal, and display acknowledgement are
 * normative executable data rather than a hand-maintained prose table.
 * @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them — each gate
 * has a distinct oracle; unavailable engine/lowering oracles remain pending.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const repoRoot = path.resolve(__dirname, "../../../..");
export const modelVersion = 1;
export const modelSourcePath =
  "packages/ibex-devtools/src/scripts/session-semantics-model.mjs";
export const generatedRoot = path.join(
  repoRoot,
  "capsec",
  "session-semantics",
);

export const generatedPaths = Object.freeze({
  fixtures: path.join(generatedRoot, "fixtures.json"),
  tables: path.join(generatedRoot, "tables.md"),
  manifest: path.join(generatedRoot, "manifest.json"),
});

export const EMPTY = Object.freeze({ $sessionValue: "empty" });
export const UNDEFINED = Object.freeze({ $sessionValue: "undefined" });

const LEXICAL_KINDS = new Set(["let", "const", "class", "import"]);
const MUTABLE_LEXICAL_KINDS = new Set(["let", "class"]);
const DECLARATION_KINDS = new Set([
  "var",
  "function",
  ...LEXICAL_KINDS,
]);

const LAST_VALUE_GETTER = "ibex/session-last-value-getter/1";
const LAST_VALUE_SETTER = "ibex/session-last-value-setter/1";

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedEntries(map) {
  return [...map.entries()].sort(([left], [right]) =>
    compareText(left, right),
  );
}

function sortedValues(set) {
  return [...set].sort(compareText);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => compareText(left, right))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

function prettyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function digestBytes(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

export function modelSourceDigest() {
  return digestBytes(fs.readFileSync(__filename));
}

export function dataDescriptor(
  value = UNDEFINED,
  {
    writable = true,
    enumerable = true,
    configurable = true,
  } = {},
) {
  return {
    type: "data",
    value: clone(value),
    writable,
    enumerable,
    configurable,
  };
}

export function accessorDescriptor(
  getter,
  setter,
  { enumerable = false, configurable = true } = {},
) {
  return {
    type: "accessor",
    getter,
    setter,
    enumerable,
    configurable,
  };
}

export function functionValue(name, revision = 1) {
  return { $sessionValue: "function", name, revision };
}

class SessionAbrupt extends Error {
  constructor(errorType, message) {
    super(message);
    this.name = "SessionAbrupt";
    this.errorType = errorType;
  }
}

function abrupt(errorType, message) {
  throw new SessionAbrupt(errorType, message);
}

/**
 * These rows drive declaration instantiation and the generated cross-kind
 * table. The operation field is executable; it is not documentation pasted
 * beside a separate implementation.
 */
export const MATRIX_ROWS = Object.freeze([
  Object.freeze({
    id: "absent-var-create",
    prior: "absent",
    declaration: "var",
    operation: "create-var",
    result: "create non-configurable writable enumerable own property",
    populate: "created",
  }),
  Object.freeze({
    id: "absent-function-create",
    prior: "absent",
    declaration: "function",
    operation: "create-function",
    result: "create reset-descriptor own property holding the function",
    populate: "created",
  }),
  Object.freeze({
    id: "var-own-var-noop",
    prior: "var-own",
    declaration: "var",
    operation: "adopt-var",
    result: "leave the property descriptor and value untouched",
    populate: "unchanged",
  }),
  Object.freeze({
    id: "var-own-function-overwrite",
    prior: "var-own",
    declaration: "function",
    operation: "overwrite-function",
    result: "overwrite with the reset descriptor and function value",
    populate: "unchanged",
  }),
  Object.freeze({
    id: "var-deleted-var-recreate",
    prior: "var-deleted",
    declaration: "var",
    operation: "create-var",
    result: "recreate the missing own property as a fresh var",
    populate: "created",
  }),
  Object.freeze({
    id: "var-deleted-function-recreate",
    prior: "var-deleted",
    declaration: "function",
    operation: "create-function",
    result: "recreate the missing own property as a fresh function",
    populate: "created",
  }),
  Object.freeze({
    id: "kindless-own-var-adopt",
    prior: "kindless-own",
    declaration: "var",
    operation: "adopt-var",
    result: "adopt without changing the existing descriptor or value",
    populate: "adopted",
  }),
  Object.freeze({
    id: "kindless-own-function-overwrite",
    prior: "kindless-own",
    declaration: "function",
    operation: "overwrite-function",
    result: "overwrite with the reset descriptor and function value",
    populate: "not-created",
  }),
  Object.freeze({
    id: "inherited-var-create-own",
    prior: "inherited",
    declaration: "var",
    operation: "create-var",
    result: "create a fresh own property initialized to undefined",
    populate: "created",
  }),
  Object.freeze({
    id: "inherited-function-create-own",
    prior: "inherited",
    declaration: "function",
    operation: "create-function",
    result: "create a fresh own property holding the function",
    populate: "created",
  }),
  Object.freeze({
    id: "object-name-to-lexical-shadow",
    prior: "object-name",
    declaration: "lexical",
    operation: "create-lexical",
    result: "create an uninitialized lexical cell; leave the property untouched",
    populate: "not-applicable",
  }),
  Object.freeze({
    id: "lexical-to-var-replace",
    prior: "lexical",
    declaration: "var",
    operation: "replace-lexical-then-var",
    result: "remove only the lexical cell, then apply the object-record var row",
    populate: "per-object-row",
  }),
  Object.freeze({
    id: "lexical-to-function-replace",
    prior: "lexical",
    declaration: "function",
    operation: "replace-lexical-then-function",
    result:
      "remove only the lexical cell, then apply the object-record function row",
    populate: "per-object-row",
  }),
  Object.freeze({
    id: "lexical-to-lexical-replace",
    prior: "lexical",
    declaration: "lexical",
    operation: "create-lexical",
    result: "replace the lexical cell; leave the object record untouched",
    populate: "not-applicable",
  }),
]);

const MATRIX_BY_KEY = new Map(
  MATRIX_ROWS.map((row) => [`${row.prior}:${row.declaration}`, row]),
);

export const RESTRICTED_GLOBAL_ROWS = Object.freeze([
  Object.freeze({
    id: "no-own-property",
    ownProperty: false,
    configurable: null,
    sessionCreated: false,
    restricted: false,
  }),
  Object.freeze({
    id: "configurable-own-property",
    ownProperty: true,
    configurable: true,
    sessionCreated: false,
    restricted: false,
  }),
  Object.freeze({
    id: "nonconfigurable-adopted-property",
    ownProperty: true,
    configurable: false,
    sessionCreated: false,
    restricted: true,
  }),
  Object.freeze({
    id: "nonconfigurable-session-created-property",
    ownProperty: true,
    configurable: false,
    sessionCreated: true,
    restricted: false,
  }),
]);

export function hasRestrictedGlobalProperty(session, name) {
  const descriptor = session.objectRecord.own.get(name);
  return Boolean(
    descriptor &&
      descriptor.configurable === false &&
      !session.sessionCreatedVars.has(name),
  );
}

function assertName(name, label) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error(`${label}: name must be a non-empty string`);
  }
}

function normalizeDescriptor(descriptor, label) {
  if (!descriptor || typeof descriptor !== "object") {
    throw new Error(`${label}: descriptor must be an object`);
  }
  if (descriptor.type === "data") {
    for (const key of ["writable", "enumerable", "configurable"]) {
      if (typeof descriptor[key] !== "boolean") {
        throw new Error(`${label}: ${key} must be boolean`);
      }
    }
    return clone(descriptor);
  }
  if (descriptor.type === "accessor") {
    for (const key of ["enumerable", "configurable"]) {
      if (typeof descriptor[key] !== "boolean") {
        throw new Error(`${label}: ${key} must be boolean`);
      }
    }
    if (
      descriptor.getter !== null &&
      typeof descriptor.getter !== "string"
    ) {
      throw new Error(`${label}: getter must be a symbolic string or null`);
    }
    if (
      descriptor.setter !== null &&
      typeof descriptor.setter !== "string"
    ) {
      throw new Error(`${label}: setter must be a symbolic string or null`);
    }
    return clone(descriptor);
  }
  throw new Error(`${label}: unknown descriptor type ${descriptor.type}`);
}

function mapFromDescriptors(properties, label) {
  const result = new Map();
  for (const [name, descriptor] of Object.entries(properties)) {
    assertName(name, label);
    result.set(name, normalizeDescriptor(descriptor, `${label}.${name}`));
  }
  return result;
}

function observeDescriptor(descriptor) {
  return descriptor ? clone(descriptor) : null;
}

function observeCell(cell) {
  return cell
    ? {
        id: cell.id,
        kind: cell.kind,
        initialized: cell.initialized,
        value: clone(cell.value),
      }
    : null;
}

function updateEmpty(previous, produced) {
  return canonicalJson(produced) === canonicalJson(EMPTY)
    ? previous
    : produced;
}

export class SessionSemanticsModel {
  constructor({
    ownProperties = {},
    inheritedProperties = {},
    extensible = true,
  } = {}) {
    if (typeof extensible !== "boolean") {
      throw new Error("extensible must be boolean");
    }
    this.objectRecord = {
      own: mapFromDescriptors(ownProperties, "ownProperties"),
      inherited: mapFromDescriptors(
        inheritedProperties,
        "inheritedProperties",
      ),
      extensible,
    };
    if (this.objectRecord.own.has("$_")) {
      throw new Error("ownProperties must not replace the runtime-owned $_ binding");
    }
    this.declarativeRecord = new Map();
    this.varDeclaredNames = new Set();
    this.sessionCreatedVars = new Set();
    this.nextCellId = 1;
    this.lastValue = {
      value: clone(UNDEFINED),
      autoUpdateEnabled: true,
      getterIdentity: LAST_VALUE_GETTER,
      setterIdentity: LAST_VALUE_SETTER,
      mutationGeneration: 0,
      disableReason: null,
      pendingNotice: false,
    };
    this.objectRecord.own.set(
      "$_",
      accessorDescriptor(LAST_VALUE_GETTER, LAST_VALUE_SETTER),
    );
    this.activeJournal = null;
    this.lastTransaction = null;
  }

  ownDescriptor(name) {
    return this.objectRecord.own.get(name) ?? null;
  }

  inheritedDescriptor(name) {
    return this.objectRecord.inherited.get(name) ?? null;
  }

  classifyName(name, { ignoreLexical = false } = {}) {
    if (!ignoreLexical && this.declarativeRecord.has(name)) return "lexical";
    if (this.objectRecord.own.has(name)) {
      return this.varDeclaredNames.has(name) ? "var-own" : "kindless-own";
    }
    if (this.varDeclaredNames.has(name)) return "var-deleted";
    if (this.objectRecord.inherited.has(name)) return "inherited";
    return "absent";
  }

  matrixRow(name, kind, { ignoreLexical = false } = {}) {
    const prior = this.classifyName(name, { ignoreLexical });
    const declaration = LEXICAL_KINDS.has(kind) ? "lexical" : kind;
    const normalizedPrior =
      declaration === "lexical" && prior !== "lexical" ? "object-name" : prior;
    const row = MATRIX_BY_KEY.get(`${normalizedPrior}:${declaration}`);
    if (!row) {
      throw new Error(
        `no matrix row for prior=${normalizedPrior} declaration=${declaration}`,
      );
    }
    return row;
  }

  canDeclareGlobalVar(name) {
    return this.objectRecord.own.has(name) || this.objectRecord.extensible;
  }

  canDeclareGlobalFunction(name) {
    const current = this.objectRecord.own.get(name);
    if (!current) return this.objectRecord.extensible;
    if (current.configurable) return true;
    return (
      current.type === "data" &&
      current.writable === true &&
      current.enumerable === true
    );
  }

  feasibilityError(declarations) {
    const collected = collectDeclarations(declarations);
    for (const name of collected.effectiveVarOrder) {
      const functionDeclaration = collected.functions.get(name);
      if (functionDeclaration) {
        if (!this.canDeclareGlobalFunction(name)) {
          return {
            type: "TypeError",
            name,
            predicate: "CanDeclareGlobalFunction",
          };
        }
      } else if (!this.canDeclareGlobalVar(name)) {
        return {
          type: "TypeError",
          name,
          predicate: "CanDeclareGlobalVar",
        };
      }
    }
    for (const declaration of collected.lexicals) {
      if (hasRestrictedGlobalProperty(this, declaration.name)) {
        return {
          type: "SyntaxError",
          name: declaration.name,
          predicate: "ModifiedHasRestrictedGlobalProperty",
        };
      }
    }
    return null;
  }

  defineGlobalProperty(name, descriptor, { userMutation = true } = {}) {
    assertName(name, "defineGlobalProperty");
    const normalized = normalizeDescriptor(
      descriptor,
      `defineGlobalProperty(${name})`,
    );
    const current = this.objectRecord.own.get(name);
    if (!current && !this.objectRecord.extensible) {
      abrupt("TypeError", `global object is not extensible for ${name}`);
    }
    if (current && current.configurable === false) {
      const same = canonicalJson(current) === canonicalJson(normalized);
      if (!same) {
        abrupt("TypeError", `cannot redefine non-configurable global ${name}`);
      }
    }
    this.objectRecord.own.set(name, normalized);
    // A descriptor replacement is observed by the identity check immediately
    // before a display ACK, not synchronously here. That distinction preserves
    // LLP 0024's honest exact-descriptor ABA limitation.
    void userMutation;
  }

  deleteGlobalProperty(name, { userMutation = true } = {}) {
    assertName(name, "deleteGlobalProperty");
    const current = this.objectRecord.own.get(name);
    if (!current) return true;
    if (!current.configurable) return false;
    this.objectRecord.own.delete(name);
    this.sessionCreatedVars.delete(name);
    // As above, a persistent deletion is discovered at display ACK time. A
    // delete followed by restoration of the exact runtime descriptor cannot be
    // distinguished in pure JavaScript and therefore must not be overclaimed.
    void userMutation;
    return true;
  }

  preventExtensions() {
    this.objectRecord.extensible = false;
  }

  disableLastValueForMutation(reason) {
    this.lastValue.autoUpdateEnabled = false;
    this.lastValue.disableReason = `mutation:${reason}`;
    this.lastValue.pendingNotice = true;
    this.lastValue.mutationGeneration += 1;
  }

  disableLastValueForDeclaration(kind) {
    this.lastValue.autoUpdateEnabled = false;
    this.lastValue.disableReason = `declaration:${kind}`;
    this.lastValue.pendingNotice = true;
  }

  lastValueAccessorIntact() {
    const descriptor = this.objectRecord.own.get("$_");
    return Boolean(
      descriptor &&
        descriptor.type === "accessor" &&
        descriptor.getter === this.lastValue.getterIdentity &&
        descriptor.setter === this.lastValue.setterIdentity,
    );
  }

  acknowledgeDisplay(value, disposition = "displayed") {
    if (disposition !== "displayed") {
      return { updated: false, reason: `display-${disposition}` };
    }
    if (!this.lastValue.autoUpdateEnabled) {
      return { updated: false, reason: "auto-update-disabled" };
    }
    if (!this.lastValueAccessorIntact()) {
      this.disableLastValueForMutation("accessor-identity-mismatch");
      return { updated: false, reason: "accessor-identity-mismatch" };
    }
    this.lastValue.value = clone(value);
    return { updated: true, reason: "displayed" };
  }

  resolve(name, { typeofMode = false } = {}) {
    assertName(name, "resolve");
    const cell = this.declarativeRecord.get(name);
    if (cell) {
      if (!cell.initialized) {
        abrupt("ReferenceError", `${name} is in the temporal dead zone`);
      }
      return clone(cell.value);
    }
    const descriptor =
      this.objectRecord.own.get(name) ??
      this.objectRecord.inherited.get(name) ??
      null;
    if (!descriptor) {
      if (typeofMode) return "undefined";
      abrupt("ReferenceError", `${name} is not defined`);
    }
    if (descriptor.type === "data") return clone(descriptor.value);
    if (
      name === "$_" &&
      descriptor.getter === this.lastValue.getterIdentity
    ) {
      return clone(this.lastValue.value);
    }
    return { $sessionValue: "accessor-get", getter: descriptor.getter };
  }

  assign(name, value, { strict = false } = {}) {
    assertName(name, "assign");
    const cell = this.declarativeRecord.get(name);
    if (cell) {
      if (!cell.initialized) {
        abrupt("ReferenceError", `${name} is in the temporal dead zone`);
      }
      if (!MUTABLE_LEXICAL_KINDS.has(cell.kind)) {
        abrupt("TypeError", `assignment to read-only ${cell.kind} ${name}`);
      }
      cell.value = clone(value);
      return clone(value);
    }

    return this.assignGlobal(name, value, { strict });
  }

  assignGlobal(name, value, { strict = false } = {}) {
    assertName(name, "assignGlobal");
    const own = this.objectRecord.own.get(name);
    if (own) {
      if (own.type === "accessor") {
        if (!own.setter) {
          if (strict) abrupt("TypeError", `global accessor ${name} has no setter`);
          return clone(value);
        }
        if (name === "$_" && own.setter === this.lastValue.setterIdentity) {
          this.lastValue.value = clone(value);
          this.disableLastValueForMutation("setter-fired");
          return clone(value);
        }
        return { $sessionValue: "accessor-set", setter: own.setter, value };
      }
      if (!own.writable) {
        if (strict) abrupt("TypeError", `global ${name} is not writable`);
        return clone(value);
      }
      own.value = clone(value);
      return clone(value);
    }

    const inherited = this.objectRecord.inherited.get(name);
    if (inherited?.type === "accessor") {
      if (inherited.setter) {
        return {
          $sessionValue: "accessor-set",
          setter: inherited.setter,
          value: clone(value),
        };
      }
      if (strict) {
        abrupt("TypeError", `inherited global accessor ${name} has no setter`);
      }
      return clone(value);
    }
    if (inherited?.type === "data" && !inherited.writable) {
      if (strict) abrupt("TypeError", `inherited global ${name} is not writable`);
      return clone(value);
    }
    if (strict) abrupt("ReferenceError", `${name} is not defined`);
    if (!this.objectRecord.extensible) {
      abrupt("TypeError", `global object is not extensible for ${name}`);
    }
    this.objectRecord.own.set(name, dataDescriptor(value));
    return clone(value);
  }

  initializeBinding(name, value) {
    const cell = this.declarativeRecord.get(name);
    if (!cell) abrupt("ReferenceError", `no lexical binding named ${name}`);
    if (cell.initialized) {
      abrupt("TypeError", `${name} is already initialized`);
    }
    cell.initialized = true;
    cell.value = clone(value);
    return clone(value);
  }

  createCell(kind) {
    return {
      id: this.nextCellId++,
      kind,
      initialized: false,
      value: clone(UNDEFINED),
    };
  }

  applyObjectOperation(row, name, declaration) {
    const hadOwn = this.objectRecord.own.has(name);
    switch (row.operation) {
      case "create-var":
        this.objectRecord.own.set(
          name,
          dataDescriptor(UNDEFINED, { configurable: false }),
        );
        this.sessionCreatedVars.add(name);
        break;
      case "create-function":
        this.objectRecord.own.set(
          name,
          dataDescriptor(
            declaration.value ?? functionValue(name),
            { configurable: false },
          ),
        );
        this.sessionCreatedVars.add(name);
        break;
      case "adopt-var":
        break;
      case "overwrite-function":
        this.objectRecord.own.set(
          name,
          dataDescriptor(
            declaration.value ?? functionValue(name),
            { configurable: false },
          ),
        );
        if (!hadOwn) {
          throw new Error(`${row.id}: overwrite requires an own property`);
        }
        break;
      default:
        throw new Error(`${row.id}: unsupported object operation ${row.operation}`);
    }
    this.varDeclaredNames.add(name);
  }

  instantiateDeclaration(name, declaration, journal) {
    const priorCell = this.declarativeRecord.get(name) ?? null;
    const priorProperty = this.objectRecord.own.get(name) ?? null;
    const priorLastValue = name === "$_" ? clone(this.lastValue) : null;
    const matrixRows = [];
    let effectiveRow = this.matrixRow(name, declaration.kind);
    matrixRows.push(effectiveRow.id);

    if (LEXICAL_KINDS.has(declaration.kind)) {
      const cell = this.createCell(declaration.kind);
      this.declarativeRecord.set(name, cell);
      if (declaration.kind === "import") {
        cell.initialized = true;
        cell.value = clone(declaration.value);
      }
      if (name === "$_") this.disableLastValueForDeclaration(declaration.kind);
      const entry = {
        name,
        declarationKind: declaration.kind,
        matrixRows,
        displaced: {
          declarative: observeCell(priorCell),
          object: observeDescriptor(priorProperty),
        },
        binding: { record: "declarative", cellId: cell.id },
        initializedAtInstantiation: cell.initialized,
        lastValueBefore: priorLastValue,
        lastValueMutationGenerationAtInstantiation:
          this.lastValue.mutationGeneration,
        fate: "pending",
      };
      journal.push(entry);
      return entry;
    }

    if (priorCell) {
      this.declarativeRecord.delete(name);
      effectiveRow = this.matrixRow(name, declaration.kind, {
        ignoreLexical: true,
      });
      matrixRows.push(effectiveRow.id);
    }
    this.applyObjectOperation(effectiveRow, name, declaration);
    if (name === "$_") this.disableLastValueForDeclaration(declaration.kind);
    const entry = {
      name,
      declarationKind: declaration.kind,
      matrixRows,
      displaced: {
        declarative: observeCell(priorCell),
        object: observeDescriptor(priorProperty),
      },
      binding: { record: "object", property: name },
      initializedAtInstantiation: true,
      lastValueBefore: priorLastValue,
      lastValueMutationGenerationAtInstantiation:
        this.lastValue.mutationGeneration,
      fate: "committed",
    };
    journal.push(entry);
    return entry;
  }

  instantiate(declarations, journal) {
    const collected = collectDeclarations(declarations);
    for (const name of collected.effectiveVarOrder) {
      const declaration =
        collected.functions.get(name) ?? collected.vars.get(name);
      this.instantiateDeclaration(name, declaration, journal);
    }
    for (const declaration of collected.lexicals) {
      this.instantiateDeclaration(declaration.name, declaration, journal);
    }
  }

  finishJournal(journal, { abruptCompletion }) {
    for (const entry of [...journal].reverse()) {
      if (entry.binding.record === "object") {
        entry.fate = "committed";
        continue;
      }
      const current = this.declarativeRecord.get(entry.name);
      if (!current || current.id !== entry.binding.cellId) {
        throw new Error(`journal lost lexical cell ${entry.name}`);
      }
      if (!abruptCompletion || current.initialized) {
        if (!current.initialized) {
          throw new Error(
            `successful input left lexical ${entry.name} uninitialized`,
          );
        }
        entry.fate = "committed";
        continue;
      }

      this.declarativeRecord.delete(entry.name);
      if (entry.displaced.declarative) {
        this.declarativeRecord.set(
          entry.name,
          clone(entry.displaced.declarative),
        );
        this.nextCellId = Math.max(
          this.nextCellId,
          entry.displaced.declarative.id + 1,
        );
      }
      entry.fate = "rolled-back";
      if (
        entry.name === "$_" &&
        this.lastValue.mutationGeneration ===
          entry.lastValueMutationGenerationAtInstantiation
      ) {
        this.lastValue = clone(entry.lastValueBefore);
      }
    }
  }

  applyEffectStep(step) {
    switch (step.op) {
      case "define-global":
        this.defineGlobalProperty(step.name, step.descriptor);
        return clone(EMPTY);
      case "delete-global":
        return this.deleteGlobalProperty(step.name);
      case "prevent-extensions":
        this.preventExtensions();
        return clone(EMPTY);
      case "assign":
        return this.assign(step.name, step.value, { strict: step.strict });
      case "assign-global":
        return this.assignGlobal(step.name, step.value, {
          strict: step.strict,
        });
      case "throw":
        abrupt(step.errorType ?? "Error", step.message ?? "fixture throw");
        break;
      default:
        throw new Error(`unsupported effect operation ${step.op}`);
    }
  }

  applyStatementStep(step) {
    switch (step.op) {
      case "initialize":
        this.initializeBinding(step.name, step.value ?? UNDEFINED);
        return step.completion ?? clone(EMPTY);
      case "assign": {
        const value = this.assign(step.name, step.value, {
          strict: step.strict,
        });
        return step.completion ?? value;
      }
      case "assign-global": {
        const value = this.assignGlobal(step.name, step.value, {
          strict: step.strict,
        });
        return step.completion ?? value;
      }
      case "read": {
        const value = this.resolve(step.name, { typeofMode: step.typeofMode });
        return step.completion ?? value;
      }
      case "complete":
        return clone(step.value);
      case "empty":
        return clone(EMPTY);
      case "define-global":
      case "delete-global":
      case "prevent-extensions":
        this.applyEffectStep(step);
        return step.completion ?? clone(EMPTY);
      case "throw":
        abrupt(step.errorType ?? "Error", step.message ?? "fixture throw");
        break;
      case "cancel":
        abrupt("Cancelled", step.message ?? "fixture cancellation");
        break;
      default:
        throw new Error(`unsupported statement operation ${step.op}`);
    }
  }

  evaluateInput(input) {
    validateInput(input);
    const declarations = input.declarations ?? [];
    let collected;
    try {
      collected = collectDeclarations(declarations);
    } catch (error) {
      if (!(error instanceof SessionAbrupt)) throw error;
      const result = {
        outcome: "throw",
        phase: 2,
        error: { type: error.errorType, message: error.message },
        completion: clone(EMPTY),
        journal: [],
      };
      this.lastTransaction = clone(result);
      return result;
    }

    const phase3Error = this.feasibilityError(collected.declarations);
    if (phase3Error) {
      const result = {
        outcome: "throw",
        phase: 3,
        error: phase3Error,
        completion: clone(EMPTY),
        journal: [],
      };
      this.lastTransaction = clone(result);
      return result;
    }

    try {
      for (const step of input.importSteps ?? []) this.applyEffectStep(step);
    } catch (error) {
      if (!(error instanceof SessionAbrupt)) throw error;
      const result = {
        outcome: "throw",
        phase: 4,
        error: { type: error.errorType, message: error.message },
        completion: clone(EMPTY),
        journal: [],
      };
      this.lastTransaction = clone(result);
      return result;
    }

    const phase5Error = this.feasibilityError(collected.declarations);
    if (phase5Error) {
      const result = {
        outcome: "throw",
        phase: 5,
        error: phase5Error,
        completion: clone(EMPTY),
        journal: [],
      };
      this.lastTransaction = clone(result);
      return result;
    }

    const journal = [];
    this.activeJournal = journal;
    this.instantiate(collected.declarations, journal);

    let completion = clone(EMPTY);
    try {
      for (const step of input.steps ?? []) {
        completion = updateEmpty(completion, this.applyStatementStep(step));
      }
      this.finishJournal(journal, { abruptCompletion: false });
      const result = {
        outcome: "success",
        phase: 6,
        completion,
        journal: clone(journal),
      };
      this.activeJournal = null;
      this.lastTransaction = clone(result);
      return result;
    } catch (error) {
      if (!(error instanceof SessionAbrupt)) {
        this.activeJournal = null;
        throw error;
      }
      this.finishJournal(journal, { abruptCompletion: true });
      const result = {
        outcome: error.errorType === "Cancelled" ? "cancelled" : "throw",
        phase: 6,
        error: { type: error.errorType, message: error.message },
        completion: clone(EMPTY),
        journal: clone(journal),
      };
      this.activeJournal = null;
      this.lastTransaction = clone(result);
      return result;
    }
  }

  observe() {
    return {
      declarativeRecord: Object.fromEntries(
        sortedEntries(this.declarativeRecord).map(([name, cell]) => [
          name,
          observeCell(cell),
        ]),
      ),
      objectRecord: {
        extensible: this.objectRecord.extensible,
        own: Object.fromEntries(
          sortedEntries(this.objectRecord.own).map(([name, descriptor]) => [
            name,
            observeDescriptor(descriptor),
          ]),
        ),
        inherited: Object.fromEntries(
          sortedEntries(this.objectRecord.inherited).map(
            ([name, descriptor]) => [name, observeDescriptor(descriptor)],
          ),
        ),
      },
      varDeclaredNames: sortedValues(this.varDeclaredNames),
      sessionCreatedVars: sortedValues(this.sessionCreatedVars),
      lastValue: clone(this.lastValue),
      activeJournal: clone(this.activeJournal),
      lastTransaction: clone(this.lastTransaction),
    };
  }
}

function validateDeclaration(declaration, index) {
  if (!declaration || typeof declaration !== "object") {
    throw new Error(`declaration ${index} must be an object`);
  }
  assertName(declaration.name, `declaration ${index}`);
  if (!DECLARATION_KINDS.has(declaration.kind)) {
    throw new Error(
      `declaration ${index}: unsupported kind ${declaration.kind}`,
    );
  }
  return clone(declaration);
}

function collectDeclarations(declarations) {
  const normalized = declarations.map(validateDeclaration);
  const lexicalNames = new Set();
  const varNames = new Set();
  const lexicals = [];
  const effectiveVarOrder = [];
  const vars = new Map();
  const functions = new Map();

  for (const declaration of normalized) {
    if (LEXICAL_KINDS.has(declaration.kind)) {
      if (lexicalNames.has(declaration.name)) {
        abrupt(
          "SyntaxError",
          `duplicate lexical declaration ${declaration.name}`,
        );
      }
      lexicalNames.add(declaration.name);
      lexicals.push(declaration);
      continue;
    }
    if (!varNames.has(declaration.name)) {
      varNames.add(declaration.name);
      effectiveVarOrder.push(declaration.name);
    }
    if (declaration.kind === "function") {
      // GlobalDeclarationInstantiation processes the last function declaration
      // for a duplicated var-scoped name.
      functions.set(declaration.name, declaration);
    } else if (!vars.has(declaration.name)) {
      vars.set(declaration.name, declaration);
    }
  }

  for (const name of lexicalNames) {
    if (varNames.has(name)) {
      abrupt(
        "SyntaxError",
        `lexical declaration ${name} collides with a var-scoped declaration`,
      );
    }
  }

  return {
    declarations: normalized,
    lexicalNames,
    varNames,
    lexicals,
    effectiveVarOrder,
    vars,
    functions,
  };
}

function validateInput(input) {
  if (!input || typeof input !== "object") {
    throw new Error("input must be an object");
  }
  if (input.declarations !== undefined && !Array.isArray(input.declarations)) {
    throw new Error("input.declarations must be an array");
  }
  if (input.importSteps !== undefined && !Array.isArray(input.importSteps)) {
    throw new Error("input.importSteps must be an array");
  }
  if (input.steps !== undefined && !Array.isArray(input.steps)) {
    throw new Error("input.steps must be an array");
  }
}

export const RESTRICTED_CLASS_EXCLUSION_IDS = Object.freeze([
  "cross-input-redeclaration",
  "forward-reference-or-assignment",
  "failure",
  "import",
  "top-level-await",
  "directive-prologue",
  "declared-global-mutation",
  "runtime-owned-binding",
]);

export function restrictedClassExclusions(testCase) {
  const inputs = testCase.inputs ?? [];
  const exclusions = new Set();
  const declaredByInput = inputs.map(
    (input) => new Set((input.declarations ?? []).map(({ name }) => name)),
  );
  const allDeclared = new Set(declaredByInput.flatMap((names) => [...names]));
  const firstDeclaration = new Map();

  for (let index = 0; index < inputs.length; index += 1) {
    for (const name of declaredByInput[index]) {
      if (firstDeclaration.has(name)) {
        exclusions.add("cross-input-redeclaration");
      } else {
        firstDeclaration.set(name, index);
      }
    }
  }

  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    const laterNames = new Set(
      declaredByInput.slice(index + 1).flatMap((names) => [...names]),
    );
    const earlyNames = [
      ...(input.analysis?.referencedNames ?? []),
      ...(input.analysis?.assignedNames ?? []),
      ...declaredByInput[index],
    ];
    if (earlyNames.some((name) => laterNames.has(name))) {
      exclusions.add("forward-reference-or-assignment");
    }
    if (input.analysis?.fails) exclusions.add("failure");
    if (
      (input.declarations ?? []).some(({ kind }) => kind === "import") ||
      (input.importSteps ?? []).length > 0
    ) {
      exclusions.add("import");
    }
    if (input.analysis?.topLevelAwait) exclusions.add("top-level-await");
    if (input.analysis?.beginsWithDirectivePrologue) {
      exclusions.add("directive-prologue");
    }
    if (
      (input.analysis?.dynamicallyMutatedGlobalNames ?? []).some((name) =>
        allDeclared.has(name),
      )
    ) {
      exclusions.add("declared-global-mutation");
    }
    if (
      [
        ...(input.analysis?.referencedNames ?? []),
        ...(input.analysis?.assignedNames ?? []),
        ...(input.declarations ?? []).map(({ name }) => name),
      ].includes("$_")
    ) {
      exclusions.add("runtime-owned-binding");
    }
  }
  return [...exclusions].sort(compareText);
}

export function isRestrictedClassCase(testCase) {
  return restrictedClassExclusions(testCase).length === 0;
}

export const GATE_CATALOG = Object.freeze([
  Object.freeze({
    id: "gate-1-model-conformance",
    compares: "implementation vs reference model",
    domain: "every session",
    selfContainedCoverage:
      "generated model fixtures and an observation comparator",
    status: "implementation-adapter-pending",
  }),
  Object.freeze({
    id: "gate-2-model-validation",
    compares:
      "reference model vs one growing script on the same engine and lowering",
    domain: "restricted class",
    selfContainedCoverage:
      "executable restricted-class classifier and exclusion fixtures",
    status: "engine-and-lowering-adapters-pending",
  }),
  Object.freeze({
    id: "gate-2b-model-correctness",
    compares: "reference rows vs fresh-process standards Script semantics",
    domain: "descriptor and created/adopted rows",
    selfContainedCoverage:
      "fresh Node subprocess probes with owner-authored expected observations",
    status: "self-contained-probes-runnable",
  }),
  Object.freeze({
    id: "gate-3-lowering-fidelity",
    compares: "one input through lowering vs direct execution",
    domain: "single inputs",
    selfContainedCoverage: "generic exact-observation comparator",
    status: "session-lowering-adapter-pending",
  }),
]);

export function compareGateObservations(cases, left, right) {
  const mismatches = [];
  for (const testCase of cases) {
    const leftObservation = left(testCase);
    const rightObservation = right(testCase);
    if (canonicalJson(leftObservation) !== canonicalJson(rightObservation)) {
      mismatches.push({
        id: testCase.id,
        left: clone(leftObservation),
        right: clone(rightObservation),
      });
    }
  }
  return mismatches;
}

const BUILTIN_OBJECT = Object.freeze({ $sessionValue: "builtin", name: "Object" });

export const MODEL_FIXTURES = Object.freeze([
  Object.freeze({
    id: "var-created-then-lexical-shadows",
    gates: ["gate-1-model-conformance"],
    expectedDeviation: "a-cross-input-redeclaration",
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "var", name: "x" }],
          steps: [{ op: "assign", name: "x", value: 1, completion: EMPTY }],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "x" }],
          steps: [{ op: "initialize", name: "x", value: 2 }],
        },
      },
      { type: "read", name: "x" },
    ],
  }),
  Object.freeze({
    id: "bare-var-object-adopts-without-clobber",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      ownProperties: {
        Object: dataDescriptor(BUILTIN_OBJECT, {
          writable: true,
          enumerable: false,
          configurable: true,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "Object" }] },
      },
    ],
  }),
  Object.freeze({
    id: "function-object-clobbers-without-creation-provenance",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      ownProperties: {
        Object: dataDescriptor(BUILTIN_OBJECT, {
          writable: true,
          enumerable: false,
          configurable: true,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "Object",
              value: functionValue("Object", 2),
            },
          ],
        },
      },
    ],
  }),
  Object.freeze({
    id: "var-undefined-cannot-launder-restricted-global",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      ownProperties: {
        undefined: dataDescriptor(UNDEFINED, {
          writable: false,
          enumerable: false,
          configurable: false,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "undefined" }] },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "undefined" }],
          steps: [{ op: "initialize", name: "undefined", value: 1 }],
        },
      },
    ],
  }),
  Object.freeze({
    id: "function-overwrite-does-not-launder-provenance",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      ownProperties: {
        p: dataDescriptor("endowment", {
          writable: true,
          enumerable: true,
          configurable: false,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "function", name: "p", value: functionValue("p") },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "p" }],
          steps: [{ op: "initialize", name: "p", value: 1 }],
        },
      },
    ],
  }),
  Object.freeze({
    id: "inherited-var-creates-own-property",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      inheritedProperties: {
        inheritedName: dataDescriptor("prototype-value", {
          configurable: false,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "inheritedName" }] },
      },
    ],
  }),
  Object.freeze({
    id: "uninitialized-lexical-restores-displaced-cell",
    gates: ["gate-1-model-conformance"],
    expectedDeviation: "c-uninitialized-lexical-rollback",
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "const", name: "x" }],
          steps: [{ op: "initialize", name: "x", value: 1 }],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "x" }],
          steps: [{ op: "throw", message: "initializer failed" }],
        },
      },
      { type: "read", name: "x" },
    ],
  }),
  Object.freeze({
    id: "initialized-lexical-commits-on-throw",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "x" }],
          steps: [
            { op: "initialize", name: "x", value: 1 },
            { op: "throw", message: "after initialization" },
          ],
        },
      },
      { type: "read", name: "x" },
    ],
  }),
  Object.freeze({
    id: "destructuring-commits-per-initialized-cell",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "let", name: "a" },
            { kind: "let", name: "b" },
          ],
          steps: [
            { op: "initialize", name: "a", value: 1 },
            { op: "throw", message: "iterator failed before b" },
          ],
        },
      },
      { type: "read", name: "a" },
      { type: "typeof", name: "b" },
    ],
  }),
  Object.freeze({
    id: "var-commits-and-displaces-lexical-on-throw",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "x" }],
          steps: [{ op: "initialize", name: "x", value: 1 }],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "var", name: "x" }],
          steps: [
            { op: "assign", name: "x", value: 2, completion: EMPTY },
            { op: "throw", message: "after var assignment" },
          ],
        },
      },
      { type: "read", name: "x" },
    ],
  }),
  Object.freeze({
    id: "throwing-import-publishes-no-declarations",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "import", name: "imported", value: 7 },
            { kind: "var", name: "w" },
          ],
          importSteps: [
            {
              op: "define-global",
              name: "moduleSideEffect",
              descriptor: dataDescriptor(1),
            },
            { op: "throw", message: "module failed" },
          ],
        },
      },
    ],
  }),
  Object.freeze({
    id: "phase-five-recheck-prevents-partial-instantiation",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "import", name: "imported", value: 7 },
            { kind: "var", name: "x" },
            { kind: "var", name: "y" },
          ],
          importSteps: [{ op: "prevent-extensions" }],
        },
      },
    ],
  }),
  Object.freeze({
    id: "import-cell-is-initialized-and-read-only",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "import", name: "imported", value: 42 }],
          steps: [{ op: "throw", message: "after import commit" }],
        },
      },
      {
        type: "input",
        input: { steps: [{ op: "assign", name: "imported", value: 43 }] },
      },
      { type: "read", name: "imported" },
    ],
  }),
  Object.freeze({
    id: "last-value-updates-only-on-displayed-ack",
    gates: ["gate-1-model-conformance"],
    program: [
      { type: "display-ack", value: 1, disposition: "displayed" },
      { type: "display-ack", value: 2, disposition: "fallback" },
      { type: "read", name: "$_" },
    ],
  }),
  Object.freeze({
    id: "last-value-user-mutation-disables-auto-update",
    gates: ["gate-1-model-conformance"],
    program: [
      { type: "display-ack", value: 1, disposition: "displayed" },
      { type: "assign", name: "$_", value: 7 },
      { type: "display-ack", value: 9, disposition: "displayed" },
      { type: "read", name: "$_" },
    ],
  }),
  Object.freeze({
    id: "last-value-uninitialized-lexical-disable-rolls-back",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "$_" }],
          steps: [{ op: "throw", message: "before initializer" }],
        },
      },
      { type: "display-ack", value: 5, disposition: "displayed" },
      { type: "read", name: "$_" },
    ],
  }),
  Object.freeze({
    id: "last-value-initialized-lexical-disable-commits",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "$_" }],
          steps: [
            { op: "initialize", name: "$_", value: 5 },
            { op: "throw", message: "after initializer" },
          ],
        },
      },
      { type: "display-ack", value: 9, disposition: "displayed" },
      { type: "read", name: "$_" },
    ],
  }),
  Object.freeze({
    id: "same-input-lexical-var-collision-is-atomic",
    gates: ["gate-1-model-conformance"],
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "var", name: "x" },
            { kind: "let", name: "x" },
          ],
        },
      },
    ],
  }),
  Object.freeze({
    id: "same-input-var-function-function-wins",
    gates: ["gate-1-model-conformance", "gate-2-model-validation"],
    program: [
      {
        type: "input",
        input: {
          declarations: [
            { kind: "var", name: "f" },
            { kind: "function", name: "f", value: functionValue("f") },
          ],
        },
      },
      { type: "read", name: "f" },
    ],
  }),
  Object.freeze({
    id: "const-assignment-throws-without-changing-value",
    gates: ["gate-1-model-conformance", "gate-2-model-validation"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "const", name: "c" }],
          steps: [{ op: "initialize", name: "c", value: 9 }],
        },
      },
      {
        type: "input",
        input: { steps: [{ op: "assign", name: "c", value: 10 }] },
      },
      { type: "read", name: "c" },
    ],
  }),
  Object.freeze({
    id: "class-cell-initializes-and-remains-mutable",
    gates: ["gate-1-model-conformance", "gate-2-model-validation"],
    program: [
      {
        type: "input",
        input: {
          declarations: [{ kind: "class", name: "C" }],
          steps: [
            {
              op: "initialize",
              name: "C",
              value: { $sessionValue: "class", name: "C" },
            },
          ],
        },
      },
      {
        type: "input",
        input: { steps: [{ op: "assign", name: "C", value: "replacement" }] },
      },
      { type: "read", name: "C" },
    ],
  }),
  Object.freeze({
    id: "adopted-configurable-property-can-delete-and-recreate",
    gates: ["gate-1-model-conformance", "gate-2b-model-correctness"],
    initial: {
      ownProperties: {
        q: dataDescriptor("before", {
          writable: false,
          enumerable: false,
          configurable: true,
        }),
      },
    },
    program: [
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "q" }] },
      },
      { type: "delete-global", name: "q" },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "q" }] },
      },
    ],
  }),
  Object.freeze({
    id: "all-cross-kind-matrix-rows-are-executable",
    gates: ["gate-1-model-conformance"],
    initial: {
      ownProperties: {
        adoptedVar: dataDescriptor("adopted-var"),
        adoptedFunction: dataDescriptor("adopted-function"),
        deletedVar: dataDescriptor("delete-var"),
        deletedFunction: dataDescriptor("delete-function"),
        objectToLexical: dataDescriptor("under-lexical"),
      },
      inheritedProperties: {
        inheritedVar: dataDescriptor("inherited-var"),
        inheritedFunction: dataDescriptor("inherited-function"),
      },
    },
    program: [
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "absentVar" }] },
      },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "absentFunction",
              value: functionValue("absentFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "varOwnVar" }] },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "varOwnVar" }] },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "varOwnFunction" }] },
      },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "varOwnFunction",
              value: functionValue("varOwnFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "deletedVar" }] },
      },
      { type: "delete-global", name: "deletedVar" },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "deletedVar" }] },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "var", name: "deletedFunction" }],
        },
      },
      { type: "delete-global", name: "deletedFunction" },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "deletedFunction",
              value: functionValue("deletedFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "adoptedVar" }] },
      },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "adoptedFunction",
              value: functionValue("adoptedFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "inheritedVar" }] },
      },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "inheritedFunction",
              value: functionValue("inheritedFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "objectToLexical" }],
          steps: [
            { op: "initialize", name: "objectToLexical", value: "lexical" },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "lexicalToVar" }],
          steps: [{ op: "initialize", name: "lexicalToVar", value: 1 }],
        },
      },
      {
        type: "input",
        input: { declarations: [{ kind: "var", name: "lexicalToVar" }] },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "lexicalToFunction" }],
          steps: [
            { op: "initialize", name: "lexicalToFunction", value: 1 },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [
            {
              kind: "function",
              name: "lexicalToFunction",
              value: functionValue("lexicalToFunction"),
            },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "let", name: "lexicalToLexical" }],
          steps: [
            { op: "initialize", name: "lexicalToLexical", value: 1 },
          ],
        },
      },
      {
        type: "input",
        input: {
          declarations: [{ kind: "const", name: "lexicalToLexical" }],
          steps: [
            { op: "initialize", name: "lexicalToLexical", value: 2 },
          ],
        },
      },
    ],
  }),
]);

export function executeFixture(fixture) {
  const session = new SessionSemanticsModel(fixture.initial);
  const events = [];
  for (const action of fixture.program) {
    switch (action.type) {
      case "input":
        events.push({ type: "input", result: session.evaluateInput(action.input) });
        break;
      case "read":
        try {
          events.push({ type: "read", name: action.name, value: session.resolve(action.name) });
        } catch (error) {
          if (!(error instanceof SessionAbrupt)) throw error;
          events.push({
            type: "read",
            name: action.name,
            error: { type: error.errorType, message: error.message },
          });
        }
        break;
      case "typeof":
        try {
          events.push({
            type: "typeof",
            name: action.name,
            value: session.resolve(action.name, { typeofMode: true }),
          });
        } catch (error) {
          if (!(error instanceof SessionAbrupt)) throw error;
          events.push({
            type: "typeof",
            name: action.name,
            error: { type: error.errorType, message: error.message },
          });
        }
        break;
      case "assign":
        try {
          events.push({
            type: "assign",
            name: action.name,
            value: session.assign(action.name, action.value, {
              strict: action.strict,
            }),
          });
        } catch (error) {
          if (!(error instanceof SessionAbrupt)) throw error;
          events.push({
            type: "assign",
            name: action.name,
            error: { type: error.errorType, message: error.message },
          });
        }
        break;
      case "assign-global":
        try {
          events.push({
            type: "assign-global",
            name: action.name,
            value: session.assignGlobal(action.name, action.value, {
              strict: action.strict,
            }),
          });
        } catch (error) {
          if (!(error instanceof SessionAbrupt)) throw error;
          events.push({
            type: "assign-global",
            name: action.name,
            error: { type: error.errorType, message: error.message },
          });
        }
        break;
      case "delete-global":
        events.push({
          type: "delete-global",
          name: action.name,
          deleted: session.deleteGlobalProperty(action.name),
        });
        break;
      case "display-ack":
        events.push({
          type: "display-ack",
          result: session.acknowledgeDisplay(
            action.value,
            action.disposition,
          ),
        });
        break;
      default:
        throw new Error(`fixture ${fixture.id}: unsupported action ${action.type}`);
    }
  }
  return {
    id: fixture.id,
    gates: [...fixture.gates],
    expectedDeviation: fixture.expectedDeviation ?? null,
    program: clone(fixture.program),
    events,
    final: session.observe(),
  };
}

export const RESTRICTED_CLASS_CASES = Object.freeze([
  Object.freeze({
    id: "eligible",
    expectedExclusions: [],
    inputs: [
      { declarations: [{ kind: "var", name: "a" }] },
      { analysis: { referencedNames: ["a"] } },
    ],
  }),
  Object.freeze({
    id: "cross-input-redeclaration",
    expectedExclusions: [
      "cross-input-redeclaration",
      "forward-reference-or-assignment",
    ],
    inputs: [
      { declarations: [{ kind: "var", name: "a" }] },
      { declarations: [{ kind: "let", name: "a" }] },
    ],
  }),
  Object.freeze({
    id: "forward-reference",
    expectedExclusions: ["forward-reference-or-assignment"],
    inputs: [
      { analysis: { referencedNames: ["later"] } },
      { declarations: [{ kind: "let", name: "later" }] },
    ],
  }),
  Object.freeze({
    id: "failure",
    expectedExclusions: ["failure"],
    inputs: [{ analysis: { fails: true } }],
  }),
  Object.freeze({
    id: "import",
    expectedExclusions: ["import"],
    inputs: [{ declarations: [{ kind: "import", name: "x" }] }],
  }),
  Object.freeze({
    id: "top-level-await",
    expectedExclusions: ["top-level-await"],
    inputs: [{ analysis: { topLevelAwait: true } }],
  }),
  Object.freeze({
    id: "directive-prologue",
    expectedExclusions: ["directive-prologue"],
    inputs: [{ analysis: { beginsWithDirectivePrologue: true } }],
  }),
  Object.freeze({
    id: "declared-global-mutation",
    expectedExclusions: ["declared-global-mutation"],
    inputs: [
      {
        declarations: [{ kind: "var", name: "x" }],
        analysis: { dynamicallyMutatedGlobalNames: ["x"] },
      },
    ],
  }),
  Object.freeze({
    id: "runtime-owned-binding",
    expectedExclusions: ["runtime-owned-binding"],
    inputs: [{ analysis: { referencedNames: ["$_"] } }],
  }),
]);

function standardsProbeBody(setup, source, observation) {
  return `
"use strict";
const vm = require("node:vm");
const getOwn = Object.getOwnPropertyDescriptor;
const define = Object.defineProperty;
const hasOwn = Function.call.bind(Object.prototype.hasOwnProperty);
${setup}
${source}
const observation = (${observation})();
process.stdout.write(JSON.stringify(observation));
`;
}

export const STANDARDS_PROBES = Object.freeze([
  Object.freeze({
    id: "absent-var-creates-nonconfigurable-own-property",
    relation: "matches-model",
    modelScenario: "absent-var",
    expected: {
      configurable: false,
      enumerable: true,
      hasOwn: true,
      valueUndefined: true,
      writable: true,
    },
    script: standardsProbeBody(
      "const name = '__ibex_g2b_absent_var__';",
      "vm.runInThisContext(`var ${name}`);",
      `() => {
        const descriptor = getOwn(globalThis, name);
        return {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          hasOwn: hasOwn(globalThis, name),
          valueUndefined: descriptor.value === undefined,
          writable: descriptor.writable,
        };
      }`,
    ),
  }),
  Object.freeze({
    id: "kindless-configurable-property-is-adopted",
    relation: "matches-model",
    modelScenario: "adopted-var",
    expected: {
      configurable: true,
      enumerable: false,
      value: "before",
      writable: false,
    },
    script: standardsProbeBody(
      `const name = "__ibex_g2b_adopt__";
       define(globalThis, name, {
         value: "before", writable: false, enumerable: false, configurable: true
       });`,
      "vm.runInThisContext(`var ${name}`);",
      `() => {
        const descriptor = getOwn(globalThis, name);
        return {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          value: descriptor.value,
          writable: descriptor.writable,
        };
      }`,
    ),
  }),
  Object.freeze({
    id: "inherited-name-gets-fresh-own-var",
    relation: "matches-model",
    modelScenario: "inherited-var",
    expected: {
      configurable: false,
      enumerable: true,
      hasOwn: true,
      valueUndefined: true,
      writable: true,
    },
    script: standardsProbeBody(
      `const name = "__ibex_g2b_inherited__";
       define(Object.getPrototypeOf(globalThis), name, {
         value: "prototype", writable: true, enumerable: true, configurable: true
       });`,
      "vm.runInThisContext(`var ${name}`);",
      `() => {
        const descriptor = getOwn(globalThis, name);
        return {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          hasOwn: hasOwn(globalThis, name),
          valueUndefined: descriptor.value === undefined,
          writable: descriptor.writable,
        };
      }`,
    ),
  }),
  Object.freeze({
    id: "bare-var-object-is-a-noop",
    relation: "matches-model",
    modelScenario: "bare-var-object",
    expected: {
      configurable: true,
      enumerable: false,
      identityPreserved: true,
      writable: true,
    },
    script: standardsProbeBody(
      `const before = globalThis.Object;
       const beforeDescriptor = getOwn(globalThis, "Object");`,
      'vm.runInThisContext("var Object");',
      `() => {
        const descriptor = getOwn(globalThis, "Object");
        return {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          identityPreserved: globalThis.Object === before,
          writable: descriptor.writable,
        };
      }`,
    ),
  }),
  Object.freeze({
    id: "function-object-clobbers-the-builtin",
    relation: "matches-model",
    modelScenario: "function-object",
    expected: {
      configurable: false,
      enumerable: true,
      identityPreserved: false,
      valueType: "function",
      writable: true,
    },
    script: standardsProbeBody(
      "const before = globalThis.Object;",
      'vm.runInThisContext("function Object() {};");',
      `() => {
        const descriptor = getOwn(globalThis, "Object");
        return {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          identityPreserved: globalThis.Object === before,
          valueType: typeof descriptor.value,
          writable: descriptor.writable,
        };
      }`,
    ),
  }),
  Object.freeze({
    id: "function-overwrite-does-not-free-a-restricted-name",
    relation: "matches-model",
    modelScenario: "function-restricted-name",
    expected: { secondOutcome: "SyntaxError" },
    script: standardsProbeBody(
      `const name = "__ibex_g2b_function_restricted__";
       define(globalThis, name, {
         value: "before", writable: true, enumerable: true, configurable: false
       });`,
      `vm.runInThisContext(\`function \${name}() {}\`);
       let secondOutcome = "success";
       try { vm.runInThisContext(\`let \${name}\`); }
       catch (error) { secondOutcome = error.name; }`,
      "() => ({ secondOutcome })",
    ),
  }),
  Object.freeze({
    id: "cross-input-var-to-let-is-an-expected-deviation",
    relation: "expected-deviation",
    modelScenario: "cross-input-var-to-let",
    deviation: "a-cross-input-redeclaration",
    expected: { secondOutcome: "SyntaxError" },
    script: standardsProbeBody(
      'const name = "__ibex_g2b_cross_kind__";',
      `vm.runInThisContext(\`var \${name}\`);
       let secondOutcome = "success";
       try { vm.runInThisContext(\`let \${name}\`); }
       catch (error) { secondOutcome = error.name; }`,
      "() => ({ secondOutcome })",
    ),
  }),
]);

export function runStandardsProbe(probe, { nodeBinary = "node" } = {}) {
  const stdout = execFileSync(
    nodeBinary,
    ["--input-type=commonjs", "-e", probe.script],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  return JSON.parse(stdout);
}

function descriptorProjection(descriptor) {
  return {
    configurable: descriptor.configurable,
    enumerable: descriptor.enumerable,
    hasOwn: true,
    valueUndefined:
      canonicalJson(descriptor.value) === canonicalJson(UNDEFINED),
    writable: descriptor.writable,
  };
}

/**
 * Produce the reference-model side of each Gate 2b row. The standards side is
 * deliberately a separate fresh-process program above; sharing an evaluator
 * would make the oracle circular.
 */
export function runModelStandardsProbe(probe) {
  const name = "probeName";
  switch (probe.modelScenario) {
    case "absent-var": {
      const session = new SessionSemanticsModel();
      session.evaluateInput({ declarations: [{ kind: "var", name }] });
      return descriptorProjection(session.ownDescriptor(name));
    }
    case "adopted-var": {
      const session = new SessionSemanticsModel({
        ownProperties: {
          [name]: dataDescriptor("before", {
            writable: false,
            enumerable: false,
            configurable: true,
          }),
        },
      });
      session.evaluateInput({ declarations: [{ kind: "var", name }] });
      const descriptor = session.ownDescriptor(name);
      return {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        value: descriptor.value,
        writable: descriptor.writable,
      };
    }
    case "inherited-var": {
      const session = new SessionSemanticsModel({
        inheritedProperties: { [name]: dataDescriptor("prototype") },
      });
      session.evaluateInput({ declarations: [{ kind: "var", name }] });
      return descriptorProjection(session.ownDescriptor(name));
    }
    case "bare-var-object": {
      const before = clone(BUILTIN_OBJECT);
      const session = new SessionSemanticsModel({
        ownProperties: {
          Object: dataDescriptor(before, {
            writable: true,
            enumerable: false,
            configurable: true,
          }),
        },
      });
      session.evaluateInput({ declarations: [{ kind: "var", name: "Object" }] });
      const descriptor = session.ownDescriptor("Object");
      return {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        identityPreserved:
          canonicalJson(descriptor.value) === canonicalJson(before),
        writable: descriptor.writable,
      };
    }
    case "function-object": {
      const before = clone(BUILTIN_OBJECT);
      const session = new SessionSemanticsModel({
        ownProperties: {
          Object: dataDescriptor(before, {
            writable: true,
            enumerable: false,
            configurable: true,
          }),
        },
      });
      session.evaluateInput({
        declarations: [
          { kind: "function", name: "Object", value: functionValue("Object") },
        ],
      });
      const descriptor = session.ownDescriptor("Object");
      return {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        identityPreserved:
          canonicalJson(descriptor.value) === canonicalJson(before),
        valueType:
          descriptor.value?.$sessionValue === "function"
            ? "function"
            : typeof descriptor.value,
        writable: descriptor.writable,
      };
    }
    case "function-restricted-name": {
      const session = new SessionSemanticsModel({
        ownProperties: {
          [name]: dataDescriptor("before", {
            writable: true,
            enumerable: true,
            configurable: false,
          }),
        },
      });
      session.evaluateInput({
        declarations: [
          { kind: "function", name, value: functionValue(name) },
        ],
      });
      const second = session.evaluateInput({
        declarations: [{ kind: "let", name }],
        steps: [{ op: "initialize", name, value: 1 }],
      });
      return {
        secondOutcome:
          second.outcome === "success" ? "success" : second.error.type,
      };
    }
    case "cross-input-var-to-let": {
      const session = new SessionSemanticsModel();
      session.evaluateInput({ declarations: [{ kind: "var", name }] });
      const second = session.evaluateInput({
        declarations: [{ kind: "let", name }],
        steps: [{ op: "initialize", name, value: 1 }],
      });
      return {
        secondOutcome:
          second.outcome === "success" ? "success" : second.error.type,
      };
    }
    default:
      throw new Error(
        `${probe.id}: unknown Gate 2b model scenario ${probe.modelScenario}`,
      );
  }
}

function generatedFixtureDocument(sourceDigest) {
  return {
    schema: "ibex/session-semantics-fixtures/1",
    modelVersion,
    modelSource: { path: modelSourcePath, digest: sourceDigest },
    valueEncoding: {
      empty: EMPTY,
      undefined: UNDEFINED,
      note: "Fixture values are inert JSON symbols; the model never evaluates them.",
    },
    gates: GATE_CATALOG,
    restrictedClass: {
      exclusions: RESTRICTED_CLASS_EXCLUSION_IDS,
      cases: RESTRICTED_CLASS_CASES.map((testCase) => ({
        id: testCase.id,
        expectedExclusions: [...testCase.expectedExclusions],
        observedExclusions: restrictedClassExclusions(testCase),
      })),
    },
    matrixRows: MATRIX_ROWS,
    restrictedGlobalRows: RESTRICTED_GLOBAL_ROWS,
    standardsProbes: STANDARDS_PROBES.map(
      ({ script: _script, ...probe }) => probe,
    ),
    fixtures: MODEL_FIXTURES.map(executeFixture),
    limitations: [
      "Gate 1 needs the production session implementation adapter before it can claim conformance.",
      "Gate 2 needs the shipping Hermes engine and real session lowering; this artifact supplies only the exact restricted-class classifier.",
      "Gate 3 needs the real parser/lowering and direct engine execution adapters.",
      "The action IR models declaration and environment semantics; it is not a JavaScript parser or a substitute for syntax-directed lowering tests.",
      "Import steps model visible ordering and interference but do not execute module code.",
      "The $_ accessor-identity model shares the pure-JavaScript exact-descriptor ABA limitation documented by LLP 0024.",
    ],
  };
}

function markdownCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

function renderTables(sourceDigest) {
  const lines = [
    "<!-- Generated by session-semantics-model.mjs; do not edit. -->",
    "# LLP 0024 session-semantics model tables",
    "",
    `Model version: ${modelVersion}`,
    `Model source digest: \`${sourceDigest}\``,
    "",
    "## Cross-kind declaration matrix",
    "",
    "| Row | Prior state | Declaration | Executable operation | Result | Provenance |",
    "| --- | --- | --- | --- | --- | --- |",
    ...MATRIX_ROWS.map(
      (row) =>
        `| \`${markdownCell(row.id)}\` | ${markdownCell(row.prior)} | ${markdownCell(row.declaration)} | \`${markdownCell(row.operation)}\` | ${markdownCell(row.result)} | ${markdownCell(row.populate)} |`,
    ),
    "",
    "## Restricted-global predicate",
    "",
    "A name is restricted exactly when it has a non-configurable own property that is not in `[[SessionCreatedVars]]`.",
    "",
    "| Row | Own property | Configurable | Session-created | Restricted |",
    "| --- | --- | --- | --- | --- |",
    ...RESTRICTED_GLOBAL_ROWS.map(
      (row) =>
        `| \`${row.id}\` | ${row.ownProperty} | ${row.configurable ?? "n/a"} | ${row.sessionCreated} | ${row.restricted} |`,
    ),
    "",
    "## Four gates",
    "",
    "| Gate | Comparison | Domain | Checked here | Status |",
    "| --- | --- | --- | --- | --- |",
    ...GATE_CATALOG.map(
      (gate) =>
        `| \`${gate.id}\` | ${markdownCell(gate.compares)} | ${markdownCell(gate.domain)} | ${markdownCell(gate.selfContainedCoverage)} | \`${gate.status}\` |`,
    ),
    "",
    "Pending means pending: generated fixtures do not attest that an engine or lowering which is not connected to the harness conforms.",
  ];
  return `${lines.join("\n")}\n`;
}

export function renderGeneratedArtifacts() {
  const sourceDigest = modelSourceDigest();
  const fixturesContent = prettyJson(generatedFixtureDocument(sourceDigest));
  const tablesContent = renderTables(sourceDigest);
  const outputRows = [
    {
      path: "capsec/session-semantics/fixtures.json",
      kind: "model-fixtures",
      digest: digestBytes(fixturesContent),
    },
    {
      path: "capsec/session-semantics/tables.md",
      kind: "generated-tables",
      digest: digestBytes(tablesContent),
    },
  ];
  const artifactSetDigest = digestBytes(
    outputRows.map((row) => `${row.path}\0${row.digest}\n`).join(""),
  );
  const manifestContent = prettyJson({
    schema: "ibex/session-semantics-manifest/1",
    modelVersion,
    modelSource: { path: modelSourcePath, digest: sourceDigest },
    artifactSetDigest,
    outputs: outputRows,
  });
  return [
    {
      path: generatedPaths.fixtures,
      content: fixturesContent,
      label: "session semantics fixtures",
    },
    {
      path: generatedPaths.tables,
      content: tablesContent,
      label: "session semantics tables",
    },
    {
      path: generatedPaths.manifest,
      content: manifestContent,
      label: "session semantics manifest",
    },
  ];
}

export function checkGeneratedArtifacts() {
  const expected = renderGeneratedArtifacts();
  for (const entry of expected) {
    const { path: confined } = assertConfinedGeneratedFile(
      repoRoot,
      entry.path,
      entry.label,
    );
    const actual = fs.readFileSync(confined);
    if (!actual.equals(Buffer.from(entry.content))) {
      throw new Error(
        `${path.relative(repoRoot, entry.path)} is stale; run ${modelSourcePath} --write`,
      );
    }
  }

  const manifest = JSON.parse(fs.readFileSync(generatedPaths.manifest, "utf8"));
  if (manifest.modelSource.digest !== modelSourceDigest()) {
    throw new Error("session semantics manifest has a stale model source digest");
  }
  for (const row of manifest.outputs) {
    const outputPath = path.join(repoRoot, row.path);
    const actualDigest = digestBytes(fs.readFileSync(outputPath));
    if (actualDigest !== row.digest) {
      throw new Error(`${row.path}: manifest digest mismatch`);
    }
  }
  const actualSetDigest = digestBytes(
    manifest.outputs
      .map((row) => `${row.path}\0${row.digest}\n`)
      .join(""),
  );
  if (actualSetDigest !== manifest.artifactSetDigest) {
    throw new Error("session semantics artifact-set digest mismatch");
  }
  return {
    fixtures: MODEL_FIXTURES.length,
    matrixRows: MATRIX_ROWS.length,
    standardsProbes: STANDARDS_PROBES.length,
    sourceDigest: manifest.modelSource.digest,
  };
}

export function writeGeneratedArtifacts() {
  const entries = renderGeneratedArtifacts();
  return writeGeneratedFilesTransactionally(repoRoot, entries, () =>
    checkGeneratedArtifacts(),
  );
}

if (path.resolve(process.argv[1] ?? "") === __filename) {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  if (write === check || process.argv.length !== 3) {
    console.error("usage: session-semantics-model.mjs (--write | --check)");
    process.exitCode = 2;
  } else {
    try {
      const result = write ? writeGeneratedArtifacts() : checkGeneratedArtifacts();
      console.log(
        `session semantics model: ${write ? "wrote" : "checked"} ${result.fixtures} fixtures, ${result.matrixRows} matrix rows, ${result.standardsProbes} standards probes (${result.sourceDigest})`,
      );
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}
