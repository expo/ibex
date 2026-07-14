/**
 * URLPattern - Web API Implementation
 *
 * Implements the URLPattern standard for matching URLs against patterns.
 * Supports wildcards (*), named groups (:name), regex groups ((regex)),
 * brace groups ({pattern}), and the ? / + / * modifiers after any group
 * ("/users/:id?", "/files/:path*"). Inputs and pattern literals are
 * canonicalized (hostname lowercasing, default-port stripping, URL
 * resolution against baseURL) before matching.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/URLPattern
 * @see https://urlpattern.spec.whatwg.org/
 */

import {
  URL,
  _percentEncode,
  _inPathPercentEncodeSet,
  _inQueryPercentEncodeSet,
  _inFragmentPercentEncodeSet,
  _DEFAULT_PORTS,
} from "./URL";

// ============================================================================
// Types
// ============================================================================

/**
 * Input for URLPattern constructor - either a string URL pattern or
 * an object with component patterns.
 */
export interface URLPatternInit {
  protocol?: string;
  username?: string;
  password?: string;
  hostname?: string;
  port?: string;
  pathname?: string;
  search?: string;
  hash?: string;
  baseURL?: string;
}

/**
 * Result of a component match, containing the matched input and
 * any named/positional capture groups.
 */
export interface URLPatternComponentResult {
  input: string;
  groups: Record<string, string | undefined>;
}

/**
 * Full result of URLPattern.exec(), with match results for each component.
 */
export interface URLPatternResult {
  inputs: [URLPatternInput] | [URLPatternInput, string];
  protocol: URLPatternComponentResult;
  username: URLPatternComponentResult;
  password: URLPatternComponentResult;
  hostname: URLPatternComponentResult;
  port: URLPatternComponentResult;
  pathname: URLPatternComponentResult;
  search: URLPatternComponentResult;
  hash: URLPatternComponentResult;
}

export type URLPatternInput = string | URLPatternInit;

// ============================================================================
// Internal: Pattern Compilation
// ============================================================================

/**
 * Represents a compiled component pattern with its regex and group names.
 */
interface CompiledComponent {
  pattern: string;
  regex: RegExp;
  groupNames: string[];
}

/** The set of URL component names we track. */
const COMPONENTS = [
  "protocol",
  "username",
  "password",
  "hostname",
  "port",
  "pathname",
  "search",
  "hash",
] as const;

type ComponentName = (typeof COMPONENTS)[number];

/**
 * Default patterns for each component when not specified.
 * These match "anything" in a way appropriate for that component.
 */
const DEFAULT_PATTERNS: Record<ComponentName, string> = {
  protocol: "*",
  username: "*",
  password: "*",
  hostname: "*",
  port: "*",
  pathname: "*",
  search: "*",
  hash: "*",
};

/**
 * Characters that separate segments in each component.
 * Used to determine what a bare `:name` group should NOT match.
 */
function getSegmentWildcard(component: ComponentName): string {
  switch (component) {
    case "pathname":
      // Named groups in pathname should not cross `/`
      return "[^/]+";
    case "hostname":
      // Named groups in hostname should not cross `.`
      return "[^.]+";
    default:
      // For other components, match everything
      return "[^]+";
  }
}

/**
 * For a full wildcard `*`, determine what regex to use.
 */
function getFullWildcard(component: ComponentName): string {
  return ".*";
}

/**
 * Escape a string for use in a regular expression.
 */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Parse and compile a pattern string for a given component into a RegExp.
 *
 * Supported syntax:
 *   :name       - Named parameter (matches segment chars)
 *   *           - Wildcard (matches everything, captured as group 0, 1, ...)
 *   (regex)     - Custom regex group
 *   :name(regex)- Named parameter with custom regex
 *   {pattern}   - Brace group (composable with modifiers)
 *   <group>?    - Optional: "/users/:id?" also matches "/users"
 *   <group>+    - One or more segments: "/files/:path+" matches "/files/a/b"
 *   <group>*    - Zero or more segments: "/files/:path*" also matches "/files"
 *   literal     - Literal text (escaped)
 *
 * In pathnames, a "/" delimiter immediately before a modified group is folded
 * into the group per the URLPattern part-prefix rules, so "/users/:id?"
 * compiles to /^\/users(?:\/([^/]+))?$/ and matches "/users".
 *
 * Returns a CompiledComponent with the original pattern, compiled regex,
 * and an ordered list of group names.
 */
function compileComponent(
  pattern: string,
  component: ComponentName,
): CompiledComponent {
  const groupNames: string[] = [];
  let regexStr = "^";
  let i = 0;
  let unnamedIndex = 0;

  // Consume a single ? / + / * modifier following a group. Two consecutive
  // modifiers are a pattern syntax error (matching the platform: "/:a??",
  // "/:a?+", "/:a*?" all throw TypeError). A "*" after a modifier is NOT an
  // error — it starts a new full-wildcard part.
  const consumeModifier = (): string => {
    if (i >= pattern.length) return "";
    const ch = pattern[i];
    if (ch !== "?" && ch !== "+" && ch !== "*") return "";
    i++;
    const next = pattern[i];
    if (next === "?" || next === "+") {
      throw new TypeError(
        `Invalid pattern "${pattern}": modifier "${ch}" cannot be followed by "${next}"`,
      );
    }
    return ch;
  };

  // Emit a capture group with an optional modifier. In pathnames the "/"
  // delimiter just before a modified group is folded into it, and + / *
  // repetition re-uses that delimiter as the segment separator (so the
  // capture for "/files/:path+" on "/files/a/b" is "a/b").
  const emitGroup = (name: string, segRegex: string, modifier: string): void => {
    groupNames.push(name);
    let prefix = "";
    if (modifier !== "" && component === "pathname" && regexStr.endsWith("/")) {
      regexStr = regexStr.slice(0, -1);
      prefix = "/";
    }
    if (modifier === "?") {
      regexStr += `(?:${prefix}(${segRegex}))?`;
    } else if (modifier === "+" || modifier === "*") {
      regexStr += `(?:${prefix}((?:${segRegex})(?:${prefix}(?:${segRegex}))*))`;
      if (modifier === "*") {
        regexStr += "?";
      }
    } else {
      regexStr += `(${segRegex})`;
    }
  };

  while (i < pattern.length) {
    const ch = pattern[i];

    // A backslash quotes the next pattern character. Without this branch an
    // escaped '*', ':', '{', or '(' was still interpreted as syntax.
    if (ch === "\\" && i + 1 < pattern.length) {
      regexStr += escapeRegExp(pattern[i + 1]);
      i += 2;
      continue;
    }

    // ----- Brace group: {pattern} with optional modifier -----
    if (ch === "{") {
      const closeBrace = findMatchingBrace(pattern, i);
      if (closeBrace === -1) {
        // No matching brace, treat as literal
        regexStr += escapeRegExp(ch);
        i++;
        continue;
      }

      const innerPattern = pattern.slice(i + 1, closeBrace);
      i = closeBrace + 1;
      const modifier = consumeModifier();

      // Recursively compile the inner pattern
      const inner = compileComponent(innerPattern, component);
      // Strip the ^ and $ anchors from inner regex
      const innerRegex = inner.regex.source.slice(1, -1);
      regexStr += `(?:${innerRegex})${modifier}`;

      // Merge inner group names
      for (const name of inner.groupNames) {
        groupNames.push(name);
      }
      continue;
    }

    // ----- Named parameter: :name or :name(regex) -----
    if (ch === ":") {
      i++;
      let name = "";
      while (i < pattern.length && /[\w]/.test(pattern[i])) {
        name += pattern[i];
        i++;
      }

      if (name === "") {
        // Bare colon, treat as literal
        regexStr += escapeRegExp(":");
        continue;
      }

      // Check for custom regex after the name: :name(regex)
      let segRegex = getSegmentWildcard(component);
      if (i < pattern.length && pattern[i] === "(") {
        const closeParen = findMatchingParen(pattern, i);
        if (closeParen !== -1) {
          segRegex = pattern.slice(i + 1, closeParen);
          i = closeParen + 1;
        }
      }
      emitGroup(name, segRegex, consumeModifier());
      continue;
    }

    // ----- Wildcard: * -----
    if (ch === "*") {
      i++;
      emitGroup(String(unnamedIndex++), getFullWildcard(component), consumeModifier());
      continue;
    }

    // ----- Custom regex group: (regex) -----
    if (ch === "(") {
      const closeParen = findMatchingParen(pattern, i);
      if (closeParen !== -1) {
        const customRegex = pattern.slice(i + 1, closeParen);
        i = closeParen + 1;
        emitGroup(String(unnamedIndex++), customRegex, consumeModifier());
        continue;
      }
      // No matching paren, treat as literal
      regexStr += escapeRegExp(ch);
      i++;
      continue;
    }

    // ----- Literal character -----
    regexStr += escapeRegExp(ch);
    i++;
  }

  regexStr += "$";

  return {
    pattern,
    regex: new RegExp(regexStr),
    groupNames,
  };
}

/**
 * Find the matching closing brace for an opening brace at position `start`.
 * Handles nested braces.
 */
function findMatchingBrace(str: string, start: number): number {
  let depth = 1;
  let i = start + 1;
  while (i < str.length && depth > 0) {
    if (str[i] === "{") depth++;
    else if (str[i] === "}") depth--;
    if (depth === 0) return i;
    i++;
  }
  return -1;
}

/**
 * Find the matching closing parenthesis for an opening paren at position `start`.
 * Handles nested parens and escaped chars.
 */
function findMatchingParen(str: string, start: number): number {
  let depth = 1;
  let i = start + 1;
  while (i < str.length && depth > 0) {
    if (str[i] === "\\") {
      i += 2; // Skip escaped character
      continue;
    }
    if (str[i] === "(") depth++;
    else if (str[i] === ")") depth--;
    if (depth === 0) return i;
    i++;
  }
  return -1;
}

// ============================================================================
// Internal: URL Parsing Helpers
// ============================================================================

/**
 * The URL-structure specificity order used for baseURL inheritance. When a
 * pattern (or input init) specifies a component, only components EARLIER in
 * this order inherit from the baseURL; the rest default ("*" for patterns,
 * "" for inputs). E.g. `new URLPattern("/api/*", base)` inherits
 * protocol/hostname/port but not search/hash. username/password never
 * inherit.
 */
const INHERITANCE_ORDER: ComponentName[] = [
  "protocol",
  "hostname",
  "port",
  "pathname",
  "search",
  "hash",
];

function applyBaseComponents(
  values: Record<ComponentName, string>,
  specified: Set<ComponentName>,
  base: Record<ComponentName, string>,
  fallback: string,
): void {
  let earliest = INHERITANCE_ORDER.length;
  for (let idx = 0; idx < INHERITANCE_ORDER.length; idx++) {
    if (specified.has(INHERITANCE_ORDER[idx])) {
      earliest = idx;
      break;
    }
  }
  for (let idx = 0; idx < INHERITANCE_ORDER.length; idx++) {
    const comp = INHERITANCE_ORDER[idx];
    if (specified.has(comp)) continue;
    values[comp] = idx < earliest ? base[comp] : fallback;
  }
  // Resolve a relative pathname against the baseURL's directory.
  if (specified.has("pathname") && !values.pathname.startsWith("/")) {
    const basePath = base.pathname;
    const dir = basePath.slice(0, basePath.lastIndexOf("/") + 1);
    values.pathname = dir + values.pathname;
  }
}

/**
 * Extract URLPattern component values from a parsed URL. Component values
 * carry no delimiters: protocol has no trailing ":", search no leading "?",
 * hash no leading "#".
 */
function urlToComponents(url: URL): Record<ComponentName, string> {
  return {
    protocol: url.protocol.replace(/:$/, ""),
    username: url.username,
    password: url.password,
    hostname: url.hostname,
    port: url.port,
    pathname: url.pathname,
    search: url.search.replace(/^\?/, ""),
    hash: url.hash.replace(/^#/, ""),
  };
}

/**
 * Canonicalize the components of a non-string match input (URLPatternInit):
 * lowercase protocol/hostname, strip the default port, normalize and
 * percent-encode an absolute pathname, drop search/hash delimiters. String
 * inputs get this for free by round-tripping through the URL parser.
 */
function canonicalizeUrlComponents(values: Record<ComponentName, string>): void {
  values.protocol = values.protocol.replace(/:$/, "").toLowerCase();
  values.hostname = values.hostname.toLowerCase();
  if (/^\d+$/.test(values.port)) {
    const canonical = String(Number(values.port));
    values.port = _DEFAULT_PORTS[values.protocol] === canonical ? "" : canonical;
  }
  if (values.search.startsWith("?")) values.search = values.search.slice(1);
  if (values.hash.startsWith("#")) values.hash = values.hash.slice(1);
  if (values.pathname.startsWith("/") && !/[?#]/.test(values.pathname)) {
    try {
      values.pathname = new URL(`http://urlpattern.invalid${values.pathname}`).pathname;
    } catch {
      // Keep the raw pathname if it cannot be canonicalized.
    }
  }
}

/**
 * Parse a URL string (or URLPatternInit) into canonicalized component values
 * for matching. Throws on unparseable absolute URLs / baseURLs (callers turn
 * that into a non-match).
 */
function parseURLInput(
  input: URLPatternInput,
  baseURL?: string,
): Record<ComponentName, string> {
  if (typeof input === "object") {
    const values: Record<ComponentName, string> = {
      protocol: "",
      username: "",
      password: "",
      hostname: "",
      port: "",
      pathname: "",
      search: "",
      hash: "",
    };
    const specified = new Set<ComponentName>();
    for (const comp of COMPONENTS) {
      if (input[comp] !== undefined) {
        values[comp] = String(input[comp]);
        specified.add(comp);
      }
    }

    if (input.baseURL) {
      const base = urlToComponents(new URL(String(input.baseURL)));
      applyBaseComponents(values, specified, base, "");
    }

    canonicalizeUrlComponents(values);
    return values;
  }

  // String input: resolve/canonicalize through the URL parser whenever it is
  // absolute or a baseURL was given.
  if (baseURL !== undefined) {
    return urlToComponents(new URL(input, baseURL));
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input)) {
    return urlToComponents(new URL(input));
  }
  // Relative string with no baseURL: split into components without failing
  // (a pathname-ish string still matches pathname patterns, per the
  // platform's behavior).
  const values = parseURLString(input);
  if (
    values.pathname &&
    !values.pathname.startsWith("/") &&
    !values.protocol &&
    !values.hostname
  ) {
    values.pathname = "/" + values.pathname;
  }
  return values;
}

/**
 * Parse a URL string into its component parts.
 * This is a pattern-aware parser that handles both actual URLs and patterns.
 */
function parseURLString(url: string): Record<ComponentName, string> {
  const result: Record<ComponentName, string> = {
    protocol: "",
    username: "",
    password: "",
    hostname: "",
    port: "",
    pathname: "",
    search: "",
    hash: "",
  };

  let remaining = url;

  // Extract hash
  const hashIdx = remaining.indexOf("#");
  if (hashIdx !== -1) {
    result.hash = remaining.slice(hashIdx + 1);
    remaining = remaining.slice(0, hashIdx);
  }

  // Extract search
  const searchIdx = remaining.indexOf("?");
  if (searchIdx !== -1) {
    result.search = remaining.slice(searchIdx + 1);
    remaining = remaining.slice(0, searchIdx);
  }

  // Extract protocol
  const protoMatch = remaining.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/);
  if (protoMatch) {
    result.protocol = protoMatch[1].toLowerCase();
    remaining = protoMatch[2];
  }

  // Extract authority
  if (remaining.startsWith("//")) {
    remaining = remaining.slice(2);

    // Find end of authority (starts of path)
    let authEnd = remaining.length;
    const slashIdx = remaining.indexOf("/");
    if (slashIdx !== -1) {
      authEnd = slashIdx;
    }

    const authority = remaining.slice(0, authEnd);
    remaining = remaining.slice(authEnd);

    // Parse userinfo
    const atIdx = authority.lastIndexOf("@");
    let hostPart = authority;
    if (atIdx !== -1) {
      const userinfo = authority.slice(0, atIdx);
      hostPart = authority.slice(atIdx + 1);

      const colonIdx = userinfo.indexOf(":");
      if (colonIdx !== -1) {
        result.username = userinfo.slice(0, colonIdx);
        result.password = userinfo.slice(colonIdx + 1);
      } else {
        result.username = userinfo;
      }
    }

    // Parse host:port
    // Handle IPv6
    if (hostPart.startsWith("[")) {
      const bracketEnd = hostPart.indexOf("]");
      if (bracketEnd !== -1) {
        result.hostname = hostPart.slice(0, bracketEnd + 1);
        if (
          bracketEnd + 1 < hostPart.length &&
          hostPart[bracketEnd + 1] === ":"
        ) {
          result.port = hostPart.slice(bracketEnd + 2);
        }
      } else {
        result.hostname = hostPart;
      }
    } else {
      const colonIdx = hostPart.lastIndexOf(":");
      if (colonIdx !== -1) {
        result.hostname = hostPart.slice(0, colonIdx);
        result.port = hostPart.slice(colonIdx + 1);
      } else {
        result.hostname = hostPart;
      }
    }
  }

  // Remaining is the pathname
  result.pathname = remaining || "/";

  return result;
}

/** The result of parsing a pattern string into per-component patterns. */
interface ParsedPatternString {
  values: Record<ComponentName, string>;
  /** Components the pattern string explicitly specified. */
  specified: Set<ComponentName>;
}

/**
 * Parse a pattern string that may contain URL components.
 * Similar to parseURLString but designed for patterns where components
 * may contain wildcard and pattern syntax. Unspecified components stay at
 * their "*" defaults and are reported via `specified` so the constructor can
 * apply baseURL inheritance.
 */
function parsePatternString(pattern: string): ParsedPatternString {
  const values: Record<ComponentName, string> = { ...DEFAULT_PATTERNS };
  const specified = new Set<ComponentName>();

  let remaining = pattern;

  // Extract hash
  const hashIdx = findUnescapedChar(remaining, "#");
  if (hashIdx !== -1) {
    values.hash = remaining.slice(hashIdx + 1);
    specified.add("hash");
    remaining = remaining.slice(0, hashIdx);
  }

  // Extract search
  const searchIdx = findSearchDelimiter(remaining);
  if (searchIdx !== -1) {
    values.search = remaining.slice(searchIdx + 1);
    specified.add("search");
    remaining = remaining.slice(0, searchIdx);
  }

  // Extract protocol
  // Look for a protocol-like pattern: something followed by ://
  // But be careful not to match :name patterns
  const protoEndIdx = remaining.indexOf("://");
  if (protoEndIdx !== -1) {
    values.protocol = remaining.slice(0, protoEndIdx);
    specified.add("protocol");
    remaining = remaining.slice(protoEndIdx + 3);

    // Extract authority - everything up to the first /
    const slashIdx = remaining.indexOf("/");
    let authority: string;
    if (slashIdx !== -1) {
      authority = remaining.slice(0, slashIdx);
      remaining = remaining.slice(slashIdx);
    } else {
      authority = remaining;
      remaining = "";
    }

    // Parse userinfo@host from authority
    const atIdx = authority.lastIndexOf("@");
    let hostPart = authority;
    if (atIdx !== -1) {
      const userinfo = authority.slice(0, atIdx);
      hostPart = authority.slice(atIdx + 1);

      const colonIdx = userinfo.indexOf(":");
      if (colonIdx !== -1) {
        values.username = userinfo.slice(0, colonIdx);
        values.password = userinfo.slice(colonIdx + 1);
        specified.add("username");
        specified.add("password");
      } else {
        values.username = userinfo;
        specified.add("username");
      }
    }

    // Parse host:port - but be careful with patterns
    // We need to find a colon that separates hostname from port,
    // not one that's part of a :name pattern
    const portSep = findPortSeparator(hostPart);
    if (portSep !== -1) {
      values.hostname = hostPart.slice(0, portSep);
      values.port = hostPart.slice(portSep + 1);
    } else {
      values.hostname = hostPart;
      // An authority with no ":port" pins the port to the canonical empty
      // (default) port, like the URL syntax position it occupies:
      // "https://example.com/*" does not match "https://example.com:8080/".
      values.port = "";
    }
    specified.add("hostname");
    specified.add("port");
  }

  // Remaining is pathname
  if (remaining) {
    values.pathname = remaining;
    specified.add("pathname");
  }

  return { values, specified };
}

/**
 * Find a character in a string, skipping characters inside parentheses and
 * braces.
 */
function findUnescapedChar(str: string, ch: string): number {
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "(" || c === "{") depth++;
    else if (c === ")" || c === "}") depth--;
    else if (c === ch && depth === 0) {
      return i;
    }
  }
  return -1;
}

/**
 * Find the "?" that starts the search component of a pattern string. A "?"
 * that directly follows a group (":name", "(regex)", "{...}", "*", or one of
 * their modifiers) is a MODIFIER, not the search delimiter — the pattern
 * string "/users/:id?" has an optional :id group and no search pattern,
 * while "/users/x?q" has search "q".
 */
function findSearchDelimiter(str: string): number {
  let i = 0;
  // Whether the previous token can take a modifier: a group for the first
  // modifier char, or a modifier itself (so "/:a+?" keeps the "?" in the
  // pathname, where compilation rejects the double modifier).
  let modifierAllowed = false;
  while (i < str.length) {
    const ch = str[i];
    if (ch === "(") {
      const close = findMatchingParen(str, i);
      if (close !== -1) {
        i = close + 1;
        modifierAllowed = true;
        continue;
      }
    } else if (ch === "{") {
      const close = findMatchingBrace(str, i);
      if (close !== -1) {
        i = close + 1;
        modifierAllowed = true;
        continue;
      }
    } else if (ch === ":") {
      i++;
      let sawName = false;
      while (i < str.length && /[\w]/.test(str[i])) {
        i++;
        sawName = true;
      }
      modifierAllowed = sawName;
      continue;
    } else if (ch === "*") {
      i++;
      modifierAllowed = true;
      continue;
    } else if (ch === "+" && modifierAllowed) {
      i++;
      // keep modifierAllowed: a "?" after "+" belongs to the pathname so the
      // compiler can reject the invalid modifier sequence.
      continue;
    } else if (ch === "?") {
      if (modifierAllowed) {
        i++;
        modifierAllowed = false;
        continue;
      }
      return i;
    }
    modifierAllowed = false;
    i++;
  }
  return -1;
}

/**
 * Find the colon that separates hostname from port in a host pattern.
 * Must distinguish between `host:port` and `host:name` patterns.
 * A port separator colon is one where the part after it looks like
 * a port (digits, *, or a named param).
 * We scan from the right side.
 */
function findPortSeparator(hostPart: string): number {
  // Simple heuristic: find the last colon that's not preceded by
  // the start-of-pattern or another colon (which would make it :name)
  // and where the right side looks like a port pattern.

  // If the entire string is a wildcard or named param, no port sep
  if (hostPart === "*" || (hostPart.startsWith(":") && !hostPart.includes("."))) {
    return -1;
  }

  // Look for pattern like hostname:port where port is \d+, *, or :name
  // We look for a colon from the right
  for (let i = hostPart.length - 1; i >= 0; i--) {
    if (hostPart[i] === ":") {
      // Check if this colon is a port separator
      // The part after should look like a port (number, *, :name, or pattern)
      const after = hostPart.slice(i + 1);
      const before = hostPart.slice(0, i);

      // If 'before' is empty, it's not a port separator
      if (!before) continue;

      // If 'after' is all digits, *, or starts with :, it's a port
      if (/^\d+$/.test(after) || after === "*" || after.startsWith(":")) {
        return i;
      }

      // If 'after' is a pattern in parens, it's a port
      if (after.startsWith("(")) {
        return i;
      }
    }
  }

  return -1;
}

// ============================================================================
// Internal: Pattern Canonicalization
// ============================================================================

/**
 * Apply `transform` to the LITERAL text of a pattern, leaving pattern syntax
 * (":name", "(regex)" bodies, "{", "}", "*", and modifiers) untouched. Used
 * to canonicalize pattern components the way the platform does: hostname and
 * protocol literals are lowercased, pathname/search/hash literals are
 * percent-encoded ({pathname: "/a b"} compiles to "/a%20b").
 */
function transformPatternLiterals(
  pattern: string,
  transform: (literal: string) => string,
): string {
  let out = "";
  let literal = "";
  let i = 0;
  const flush = (): void => {
    if (literal) {
      out += transform(literal);
      literal = "";
    }
  };
  const copyModifier = (): void => {
    // Copy every consecutive modifier character through untouched so that
    // invalid sequences (":b??") still reach compileComponent, which rejects
    // them, instead of being percent-encoded into a valid literal.
    while (pattern[i] === "?" || pattern[i] === "+" || pattern[i] === "*") {
      out += pattern[i];
      i++;
    }
  };
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === "(") {
      const close = findMatchingParen(pattern, i);
      if (close !== -1) {
        flush();
        out += pattern.slice(i, close + 1);
        i = close + 1;
        copyModifier();
        continue;
      }
    } else if (ch === "{") {
      const close = findMatchingBrace(pattern, i);
      if (close !== -1) {
        flush();
        out += "{" + transformPatternLiterals(pattern.slice(i + 1, close), transform) + "}";
        i = close + 1;
        copyModifier();
        continue;
      }
    } else if (ch === ":") {
      flush();
      out += ch;
      i++;
      while (i < pattern.length && /[\w]/.test(pattern[i])) {
        out += pattern[i];
        i++;
      }
      if (pattern[i] === "(") {
        const close = findMatchingParen(pattern, i);
        if (close !== -1) {
          out += pattern.slice(i, close + 1);
          i = close + 1;
        }
      }
      copyModifier();
      continue;
    } else if (ch === "*") {
      flush();
      out += ch;
      i++;
      copyModifier();
      continue;
    }
    literal += ch;
    i++;
  }
  flush();
  return out;
}

/**
 * Canonicalize compiled pattern component values in place: strip a trailing
 * ":" from the protocol, lowercase protocol/hostname literals, normalize an
 * all-digits port (dropping it when it is the default for a literal
 * protocol, so "https://example.com:443/*" matches "https://example.com/x"),
 * and percent-encode userinfo/pathname/search/hash literals.
 */
function canonicalizePatternValues(values: Record<ComponentName, string>): void {
  const lower = (literal: string): string => literal.toLowerCase();
  if (values.protocol.endsWith(":")) {
    values.protocol = values.protocol.slice(0, -1);
  }
  values.protocol = transformPatternLiterals(values.protocol, lower);
  values.hostname = transformPatternLiterals(values.hostname, lower);
  if (/^\d+$/.test(values.port)) {
    const canonical = String(Number(values.port));
    values.port = _DEFAULT_PORTS[values.protocol] === canonical ? "" : canonical;
  }
  values.username = transformPatternLiterals(values.username, (literal) =>
    _percentEncode(literal, _inPathPercentEncodeSet),
  );
  values.password = transformPatternLiterals(values.password, (literal) =>
    _percentEncode(literal, _inPathPercentEncodeSet),
  );
  values.pathname = transformPatternLiterals(values.pathname, (literal) =>
    _percentEncode(literal, _inPathPercentEncodeSet),
  );
  values.search = transformPatternLiterals(values.search, (literal) =>
    _percentEncode(literal, _inQueryPercentEncodeSet),
  );
  values.hash = transformPatternLiterals(values.hash, (literal) =>
    _percentEncode(literal, _inFragmentPercentEncodeSet),
  );
}

// ============================================================================
// URLPattern Class
// ============================================================================

export class URLPattern {
  private _components: Record<ComponentName, CompiledComponent>;

  /**
   * Create a new URLPattern.
   *
   * @param input - A pattern string (like "https://example.com/:path") or
   *   an object with component patterns ({pathname: "/users/:id"}).
   *   Defaults to the all-wildcard pattern.
   * @param baseURL - Optional base URL string (only when input is a string)
   */
  constructor(input: URLPatternInput = {}, baseURL?: string) {
    let values: Record<ComponentName, string>;
    let specified: Set<ComponentName>;
    let base: Record<ComponentName, string> | null = null;

    if (typeof input === "string") {
      const parsed = parsePatternString(input);
      values = parsed.values;
      specified = parsed.specified;
      if (baseURL !== undefined) {
        // Invalid base URLs propagate as TypeError from the URL constructor.
        base = urlToComponents(new URL(baseURL));
      } else if (!specified.has("protocol")) {
        throw new TypeError(
          `Relative URLPattern string "${input}" requires a baseURL`,
        );
      }
    } else {
      if (baseURL !== undefined) {
        throw new TypeError(
          "A baseURL argument is only valid with a string pattern",
        );
      }
      values = { ...DEFAULT_PATTERNS };
      specified = new Set<ComponentName>();
      for (let i = 0; i < COMPONENTS.length; i++) {
        const comp = COMPONENTS[i];
        if (input[comp] !== undefined) {
          values[comp] = String(input[comp]);
          specified.add(comp);
        }
      }
      if (input.baseURL !== undefined) {
        base = urlToComponents(new URL(String(input.baseURL)));
      }
    }

    if (base) {
      applyBaseComponents(values, specified, base, "*");
    }
    if (specified.has("hash") && !specified.has("search")) {
      values.search = "";
    }
    canonicalizePatternValues(values);

    // Compile each component pattern into a regex
    this._components = {} as Record<ComponentName, CompiledComponent>;
    for (let i = 0; i < COMPONENTS.length; i++) {
      const comp = COMPONENTS[i];
      this._components[comp] = compileComponent(values[comp], comp);
    }
  }

  /**
   * The compiled pattern string for the protocol component.
   */
  get protocol(): string {
    return this._components.protocol.pattern;
  }

  /**
   * The compiled pattern string for the username component.
   */
  get username(): string {
    return this._components.username.pattern;
  }

  /**
   * The compiled pattern string for the password component.
   */
  get password(): string {
    return this._components.password.pattern;
  }

  /**
   * The compiled pattern string for the hostname component.
   */
  get hostname(): string {
    return this._components.hostname.pattern;
  }

  /**
   * The compiled pattern string for the port component.
   */
  get port(): string {
    return this._components.port.pattern;
  }

  /**
   * The compiled pattern string for the pathname component.
   */
  get pathname(): string {
    return this._components.pathname.pattern;
  }

  /**
   * The compiled pattern string for the search component.
   */
  get search(): string {
    return this._components.search.pattern;
  }

  /**
   * The compiled pattern string for the hash component.
   */
  get hash(): string {
    return this._components.hash.pattern;
  }

  /**
   * Test whether a URL matches this pattern.
   *
   * @param input - A URL string or URLPatternInit to test
   * @param baseURL - Optional base URL (only when input is a string)
   * @returns true if the URL matches the pattern
   */
  test(input: URLPatternInput = {}, baseURL?: string): boolean {
    return this.exec(input, baseURL) !== null;
  }

  /**
   * Execute this pattern against a URL, returning match details or null.
   *
   * @param input - A URL string or URLPatternInit to match
   * @param baseURL - Optional base URL (only when input is a string)
   * @returns URLPatternResult with match details, or null if no match
   */
  exec(input: URLPatternInput = {}, baseURL?: string): URLPatternResult | null {
    if (typeof input !== "string" && baseURL !== undefined) {
      throw new TypeError(
        "A baseURL argument is only valid with a string input",
      );
    }

    let urlComponents: Record<ComponentName, string>;

    try {
      urlComponents = parseURLInput(input, baseURL);
    } catch {
      // Unparseable absolute inputs / base URLs simply do not match.
      return null;
    }

    const result: Partial<URLPatternResult> = {};

    // Build inputs array
    if (baseURL) {
      (result as any).inputs = [input, baseURL];
    } else {
      (result as any).inputs = [input];
    }

    // Match each component
    for (const comp of COMPONENTS) {
      const compiled = this._components[comp];
      const value = urlComponents[comp];
      const match = compiled.regex.exec(value);

      if (!match) {
        return null;
      }

      // Build groups from captures
      const groups: Record<string, string | undefined> = {};
      for (let i = 0; i < compiled.groupNames.length; i++) {
        groups[compiled.groupNames[i]] = match[i + 1];
      }

      (result as any)[comp] = {
        input: value,
        groups,
      };
    }

    return result as URLPatternResult;
  }
}
