/**
 * Discover the Android Java/JNI half of Ibex's native bridge.
 *
 * The main WP1 inventory is source-derived.  Treating the C++ side of the
 * Android bridge as the whole implementation would hide public embedder entry
 * points and Java-to-native callback routes from that inventory.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — every
 * production host/embedder route must have an explicit classified surface.
 * @ref LLP 0008#android-backend-matrix — Android framework authority is
 * implemented by the Java/JNI bridge rather than the generic Unix backend.
 */

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sourceSymbol(file, symbol) {
  return `${file}#${symbol}`;
}

function makeSurface(name, sourcePath, symbol, metadata) {
  return {
    kind: "host-abi",
    name,
    observedKey: `host-abi:${name}`,
    sourceRefs: [sourceSymbol(sourcePath, symbol)],
    metadata,
  };
}

function lexJava(text, sourcePath) {
  const tokens = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && text[index + 1] === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && text[index + 1] === "*") {
      const close = text.indexOf("*/", index + 2);
      if (close === -1) {
        throw new Error(`${sourcePath}: unterminated Java block comment`);
      }
      index = close + 2;
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      const textBlock =
        quote === '"' && text.slice(index, index + 3) === '\"\"\"';
      index += textBlock ? 3 : 1;
      let closed = false;
      while (index < text.length) {
        if (textBlock && text.slice(index, index + 3) === '\"\"\"') {
          index += 3;
          closed = true;
          break;
        }
        if (!textBlock && text[index] === quote) {
          index += 1;
          closed = true;
          break;
        }
        if (text[index] === "\\") index += 1;
        index += 1;
      }
      if (!closed) throw new Error(`${sourcePath}: unterminated Java literal`);
      tokens.push({ type: "literal", value: "<literal>" });
      continue;
    }
    if (/[A-Za-z_$]/u.test(char)) {
      let end = index + 1;
      while (end < text.length && /[A-Za-z0-9_$]/u.test(text[end])) end += 1;
      tokens.push({ type: "identifier", value: text.slice(index, end) });
      index = end;
      continue;
    }
    tokens.push({ type: "punctuation", value: char });
    index += 1;
  }
  return tokens;
}

function lexCppBridge(text, sourcePath) {
  const tokens = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && text[index + 1] === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && text[index + 1] === "*") {
      const close = text.indexOf("*/", index + 2);
      if (close === -1) {
        throw new Error(`${sourcePath}: unterminated C++ block comment`);
      }
      index = close + 2;
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      let value = "";
      index += 1;
      let closed = false;
      while (index < text.length) {
        if (text[index] === quote) {
          index += 1;
          closed = true;
          break;
        }
        if (text[index] === "\\") {
          index += 1;
          if (index >= text.length) break;
        }
        value += text[index];
        index += 1;
      }
      if (!closed) throw new Error(`${sourcePath}: unterminated C++ literal`);
      tokens.push({ type: quote === '"' ? "string" : "character", value });
      continue;
    }
    if (/[A-Za-z_]/u.test(char)) {
      let end = index + 1;
      while (end < text.length && /[A-Za-z0-9_]/u.test(text[end])) end += 1;
      tokens.push({ type: "identifier", value: text.slice(index, end) });
      index = end;
      continue;
    }
    const pair = text.slice(index, index + 2);
    if (["::", "->"].includes(pair)) {
      tokens.push({ type: "punctuation", value: pair });
      index += 2;
      continue;
    }
    tokens.push({ type: "punctuation", value: char });
    index += 1;
  }
  return tokens;
}

function matchingToken(tokens, openIndex, open, close, sourcePath) {
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index].value === open) depth += 1;
    if (tokens[index].value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error(`${sourcePath}: unmatched Java ${open}`);
}

function packageName(tokens, sourcePath) {
  const packageIndex = tokens.findIndex((token) => token.value === "package");
  if (packageIndex === -1)
    throw new Error(`${sourcePath}: Java package is absent`);
  const segments = [];
  for (let index = packageIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.value === ";") break;
    if (token.type === "identifier") segments.push(token.value);
    else if (token.value !== ".") {
      throw new Error(`${sourcePath}: malformed Java package declaration`);
    }
  }
  if (segments.length === 0)
    throw new Error(`${sourcePath}: empty Java package`);
  return segments.join(".");
}

function directDepths(tokens) {
  const depths = [];
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    depths[index] = depth;
    if (tokens[index].value === "{") depth += 1;
    if (tokens[index].value === "}") depth -= 1;
    if (depth < 0)
      throw new Error("Java source has an unmatched closing brace");
  }
  if (depth !== 0)
    throw new Error("Java source has an unmatched opening brace");
  return depths;
}

function namedType(
  tokens,
  depths,
  typeKeyword,
  typeName,
  expectedDepth,
  sourcePath,
) {
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      depths[index] !== expectedDepth ||
      tokens[index].value !== typeKeyword ||
      tokens[index + 1]?.value !== typeName
    ) {
      continue;
    }
    const openIndex = tokens.findIndex(
      (token, candidate) => candidate > index + 1 && token.value === "{",
    );
    if (openIndex === -1)
      throw new Error(`${sourcePath}: ${typeName} has no body`);
    return {
      bodyOpen: openIndex,
      bodyClose: matchingToken(tokens, openIndex, "{", "}", sourcePath),
    };
  }
  throw new Error(`${sourcePath}: Java ${typeKeyword} ${typeName} is absent`);
}

function methodAt(
  tokens,
  depths,
  startIndex,
  memberDepth,
  requiredModifiers,
  sourcePath,
) {
  if (depths[startIndex] !== memberDepth) return null;
  let parenIndex = -1;
  for (let index = startIndex; index < tokens.length; index += 1) {
    if (depths[index] < memberDepth) return null;
    if (depths[index] > memberDepth) continue;
    if (["=", ";", "{"].includes(tokens[index].value)) return null;
    if (tokens[index].value === "(") {
      parenIndex = index;
      break;
    }
  }
  if (parenIndex === -1) return null;
  const prefix = tokens
    .slice(startIndex, parenIndex)
    .map((token) => token.value);
  if (!requiredModifiers.every((modifier) => prefix.includes(modifier)))
    return null;
  if (prefix.some((token) => token === "class" || token === "interface"))
    return null;
  const nameToken = [...tokens.slice(startIndex, parenIndex)]
    .reverse()
    .find((token) => token.type === "identifier");
  if (!nameToken) throw new Error(`${sourcePath}: Java method has no name`);
  return { name: nameToken.value, parenIndex };
}

function collectOuterMethods(
  tokens,
  depths,
  body,
  requiredStart,
  requiredModifiers,
  sourcePath,
) {
  const methods = [];
  const memberDepth = depths[body.bodyOpen] + 1;
  for (let index = body.bodyOpen + 1; index < body.bodyClose; index += 1) {
    if (depths[index] !== memberDepth || tokens[index].value !== requiredStart)
      continue;
    const method = methodAt(
      tokens,
      depths,
      index,
      memberDepth,
      requiredModifiers,
      sourcePath,
    );
    if (method) methods.push(method.name);
  }
  return methods;
}

function directInterfaces(tokens, depths, body, sourcePath) {
  const interfaces = [];
  const memberDepth = depths[body.bodyOpen] + 1;
  for (let index = body.bodyOpen + 1; index < body.bodyClose - 1; index += 1) {
    if (
      depths[index] !== memberDepth ||
      tokens[index].value !== "public" ||
      tokens[index + 1]?.value !== "interface" ||
      tokens[index + 2]?.type !== "identifier"
    ) {
      continue;
    }
    interfaces.push({
      name: tokens[index + 2].value,
      ...namedType(
        tokens,
        depths,
        "interface",
        tokens[index + 2].value,
        memberDepth,
        sourcePath,
      ),
    });
  }
  return interfaces;
}

function interfaceMethods(tokens, depths, type, sourcePath) {
  const methods = [];
  const memberDepth = depths[type.bodyOpen] + 1;
  for (let index = type.bodyOpen + 1; index < type.bodyClose; index += 1) {
    if (depths[index] !== memberDepth || tokens[index].type !== "identifier")
      continue;
    const method = methodAt(tokens, depths, index, memberDepth, [], sourcePath);
    if (!method) continue;
    const closeParen = matchingToken(
      tokens,
      method.parenIndex,
      "(",
      ")",
      sourcePath,
    );
    let terminator = closeParen + 1;
    while (terminator < type.bodyClose && depths[terminator] === memberDepth) {
      if (tokens[terminator].value === ";") {
        methods.push(method.name);
        break;
      }
      if (tokens[terminator].value === "{") break;
      terminator += 1;
    }
    index = closeParen;
  }
  return [...new Set(methods)];
}

function assertUnique(rows, sourcePath) {
  const seen = new Set();
  for (const row of rows) {
    if (seen.has(row.observedKey)) {
      throw new Error(
        `${sourcePath}: overloaded or duplicate Android bridge surface ${row.observedKey}; encode the overload explicitly`,
      );
    }
    seen.add(row.observedKey);
  }
}

function addUniqueBinding(bindings, methodName, binding, sourcePath) {
  if (bindings.has(methodName)) {
    throw new Error(
      `${sourcePath}: duplicate Android JNI binding ${methodName}`,
    );
  }
  bindings.set(methodName, binding);
}

/**
 * Join Java declarations to the C++ method cache and RegisterNatives table.
 * The result deliberately contains only structural names/signatures; semantic
 * classification remains in the coverage model.
 */
export function scanAndroidCppBridgeBindings(
  text,
  sourcePath = "src/engine/native_android_networking.cc",
) {
  const tokens = lexCppBridge(text, sourcePath);
  const staticMethods = new Map();
  const nativeCallbacks = new Map();

  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (
      tokens[index].value !== "GetStaticMethodID" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")", sourcePath);
    const strings = tokens
      .slice(index + 2, close)
      .filter((token) => token.type === "string")
      .map((token) => token.value);
    if (strings.length !== 2) {
      throw new Error(
        `${sourcePath}: GetStaticMethodID must contain one exact name and descriptor`,
      );
    }
    addUniqueBinding(
      staticMethods,
      strings[0],
      { descriptor: strings[1], functionName: strings[0] },
      sourcePath,
    );
    index = close;
  }

  const tableIndex = tokens.findIndex(
    (token, index) =>
      token.value === "JNINativeMethod" &&
      tokens[index + 1]?.value === "methods",
  );
  if (tableIndex === -1) {
    throw new Error(`${sourcePath}: JNINativeMethod table is absent`);
  }
  const tableOpen = tokens.findIndex(
    (token, index) => index > tableIndex && token.value === "{",
  );
  if (tableOpen === -1) throw new Error(`${sourcePath}: JNI table has no body`);
  const tableClose = matchingToken(tokens, tableOpen, "{", "}", sourcePath);
  for (let index = tableOpen + 1; index < tableClose; index += 1) {
    if (tokens[index].value !== "{") continue;
    const entryClose = matchingToken(tokens, index, "{", "}", sourcePath);
    const entry = tokens.slice(index + 1, entryClose);
    const strings = entry
      .filter((token) => token.type === "string")
      .map((token) => token.value);
    const castIndex = entry.findIndex(
      (token) => token.value === "reinterpret_cast",
    );
    const functionName = entry
      .slice(castIndex + 1)
      .find(
        (token) =>
          token.type === "identifier" &&
          /^android_[a-z0-9_]+$/u.test(token.value),
      )?.value;
    if (strings.length !== 2 || castIndex === -1 || !functionName) {
      throw new Error(`${sourcePath}: malformed JNINativeMethod entry`);
    }
    addUniqueBinding(
      nativeCallbacks,
      strings[0],
      { descriptor: strings[1], functionName },
      sourcePath,
    );
    index = entryClose;
  }

  const exportedPrefix = "Java_dev_ibex_runtime_IbexNetworking_";
  for (const token of tokens) {
    if (
      token.type !== "identifier" ||
      !token.value.startsWith(exportedPrefix)
    ) {
      continue;
    }
    const methodName = token.value.slice(exportedPrefix.length);
    addUniqueBinding(
      nativeCallbacks,
      methodName,
      { descriptor: "exported-jni-symbol", functionName: token.value },
      sourcePath,
    );
  }

  if (staticMethods.size === 0 || nativeCallbacks.size === 0) {
    throw new Error(`${sourcePath}: Android C++ bridge bindings are empty`);
  }
  return { nativeCallbacks, staticMethods };
}

export function joinAndroidBridgeImplementationRefs(
  javaRows,
  bindings,
  sourcePath = "src/engine/native_android_networking.cc",
) {
  const rows = javaRows.map((row) => structuredClone(row));
  const seenStatic = new Set();
  const seenNative = new Set();
  for (const row of rows) {
    const { bridgeRole, memberName } = row.metadata;
    const binding =
      bridgeRole === "java-to-native-callback"
        ? bindings.nativeCallbacks.get(memberName)
        : bridgeRole === "public-static"
          ? bindings.staticMethods.get(memberName)
          : undefined;
    if (!binding) continue;
    row.sourceRefs.push(
      sourceSymbol(
        sourcePath,
        `${bridgeRole === "java-to-native-callback" ? "jni-callback" : "java-call"}:${memberName}:${binding.functionName}`,
      ),
    );
    row.sourceRefs.sort(compareText);
    row.metadata.cppBinding = { ...binding };
    if (bridgeRole === "java-to-native-callback") seenNative.add(memberName);
    else seenStatic.add(memberName);
  }
  for (const methodName of bindings.nativeCallbacks.keys()) {
    if (!seenNative.has(methodName)) {
      throw new Error(
        `${sourcePath}: C++ JNI callback ${methodName} has no Java declaration surface`,
      );
    }
  }
  for (const methodName of bindings.staticMethods.keys()) {
    if (!seenStatic.has(methodName)) {
      throw new Error(
        `${sourcePath}: cached Java method ${methodName} has no public static surface`,
      );
    }
  }
  return rows;
}

export function scanAndroidJavaBridgeSurfaces(
  text,
  sourcePath = "platform/android/java/dev/ibex/runtime/IbexNetworking.java",
) {
  const tokens = lexJava(text, sourcePath);
  const depths = directDepths(tokens);
  const packageId = packageName(tokens, sourcePath);
  const className = "IbexNetworking";
  const qualifiedClass = `${packageId}.${className}`;
  const body = namedType(tokens, depths, "class", className, 0, sourcePath);
  const rows = [];

  for (const methodName of collectOuterMethods(
    tokens,
    depths,
    body,
    "public",
    ["public", "static"],
    sourcePath,
  )) {
    const name = `java:${qualifiedClass}.${methodName}`;
    rows.push(
      makeSurface(name, sourcePath, name, {
        bridgeRole: "public-static",
        className: qualifiedClass,
        language: "java",
        memberName: methodName,
        targetVariant: "android",
      }),
    );
  }

  for (const type of directInterfaces(tokens, depths, body, sourcePath)) {
    for (const methodName of interfaceMethods(
      tokens,
      depths,
      type,
      sourcePath,
    )) {
      const name = `java:${qualifiedClass}.${type.name}.${methodName}`;
      rows.push(
        makeSurface(name, sourcePath, name, {
          bridgeRole: "provider-interface",
          className: `${qualifiedClass}.${type.name}`,
          language: "java",
          memberName: methodName,
          targetVariant: "android",
        }),
      );
    }
  }

  for (const methodName of collectOuterMethods(
    tokens,
    depths,
    body,
    "private",
    ["private", "static", "native"],
    sourcePath,
  )) {
    const name = `jni:${qualifiedClass}.${methodName}`;
    rows.push(
      makeSurface(name, sourcePath, name, {
        bridgeRole: "java-to-native-callback",
        className: qualifiedClass,
        language: "java",
        memberName: methodName,
        targetVariant: "android",
      }),
    );
  }

  rows.sort((left, right) => compareText(left.observedKey, right.observedKey));
  assertUnique(rows, sourcePath);
  if (!rows.some((row) => row.metadata.bridgeRole === "public-static")) {
    throw new Error(
      `${sourcePath}: Android bridge has no public static routes`,
    );
  }
  if (
    !rows.some((row) => row.metadata.bridgeRole === "java-to-native-callback")
  ) {
    throw new Error(`${sourcePath}: Android bridge has no JNI callback routes`);
  }
  return rows;
}
