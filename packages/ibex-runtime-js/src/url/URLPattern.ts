/**
 * URLPattern - Web API Implementation
 *
 * Implements the URLPattern standard for matching URLs against patterns.
 * Supports wildcards (*), named groups (:name), regex groups ((regex)),
 * and optional segments ({pattern}?).
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/URLPattern
 * @see https://urlpattern.spec.whatwg.org/
 */

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
 *   {pattern}?  - Optional group (the ? makes the entire group optional)
 *   literal     - Literal text (escaped)
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

  while (i < pattern.length) {
    const ch = pattern[i];

    // ----- Optional group: {pattern}? -----
    if (ch === "{") {
      const closeBrace = findMatchingBrace(pattern, i);
      if (closeBrace === -1) {
        // No matching brace, treat as literal
        regexStr += escapeRegExp(ch);
        i++;
        continue;
      }

      const innerPattern = pattern.slice(i + 1, closeBrace);
      const isOptional =
        closeBrace + 1 < pattern.length && pattern[closeBrace + 1] === "?";

      // Recursively compile the inner pattern
      const inner = compileComponent(innerPattern, component);
      // Strip the ^ and $ anchors from inner regex
      const innerRegex = inner.regex.source.slice(1, -1);

      if (isOptional) {
        regexStr += `(?:${innerRegex})?`;
        i = closeBrace + 2; // skip }?
      } else {
        regexStr += `(?:${innerRegex})`;
        i = closeBrace + 1; // skip }
      }

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

      groupNames.push(name);

      // Check for custom regex after the name: :name(regex)
      if (i < pattern.length && pattern[i] === "(") {
        const closeParen = findMatchingParen(pattern, i);
        if (closeParen !== -1) {
          const customRegex = pattern.slice(i + 1, closeParen);
          regexStr += `(${customRegex})`;
          i = closeParen + 1;
        } else {
          regexStr += `(${getSegmentWildcard(component)})`;
        }
      } else {
        regexStr += `(${getSegmentWildcard(component)})`;
      }
      continue;
    }

    // ----- Wildcard: * -----
    if (ch === "*") {
      groupNames.push(String(unnamedIndex));
      unnamedIndex++;
      regexStr += `(${getFullWildcard(component)})`;
      i++;
      continue;
    }

    // ----- Custom regex group: (regex) -----
    if (ch === "(") {
      const closeParen = findMatchingParen(pattern, i);
      if (closeParen !== -1) {
        const customRegex = pattern.slice(i + 1, closeParen);
        groupNames.push(String(unnamedIndex));
        unnamedIndex++;
        regexStr += `(${customRegex})`;
        i = closeParen + 1;
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
 * Parse a URL string (or URLPatternInit) into its components.
 * Returns an object with each component as a string.
 */
function parseURLInput(
  input: URLPatternInput,
  baseURL?: string,
): Record<ComponentName, string> {
  if (typeof input === "object") {
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

    // If baseURL is provided, use it as defaults
    if (input.baseURL) {
      const base = parseURLString(input.baseURL);
      for (const comp of COMPONENTS) {
        result[comp] = base[comp];
      }
    }

    // Override with provided values
    for (const comp of COMPONENTS) {
      if (input[comp] !== undefined) {
        result[comp] = input[comp]!;
      }
    }

    return result;
  }

  // It's a string URL
  const urlStr = baseURL ? resolveURL(input, baseURL) : input;
  return parseURLString(urlStr);
}

/**
 * Simple URL resolution: resolve `url` against `base`.
 */
function resolveURL(url: string, base: string): string {
  // If url already has a protocol, it's absolute
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
    return url;
  }

  const baseParts = parseURLString(base);

  if (url.startsWith("//")) {
    // Protocol-relative
    return baseParts.protocol + ":" + url;
  }

  if (url.startsWith("/")) {
    // Absolute path
    const authority = buildAuthority(baseParts);
    return baseParts.protocol + "://" + authority + url;
  }

  // Relative path
  const authority = buildAuthority(baseParts);
  const basePath = baseParts.pathname.slice(
    0,
    baseParts.pathname.lastIndexOf("/") + 1,
  );
  return baseParts.protocol + "://" + authority + basePath + url;
}

/**
 * Build the authority section (user:pass@host:port) from parsed components.
 */
function buildAuthority(parts: Record<ComponentName, string>): string {
  let authority = "";
  if (parts.username) {
    authority += parts.username;
    if (parts.password) {
      authority += ":" + parts.password;
    }
    authority += "@";
  }
  authority += parts.hostname;
  if (parts.port) {
    authority += ":" + parts.port;
  }
  return authority;
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

/**
 * Parse a pattern string that may contain URL components.
 * Similar to parseURLString but designed for patterns where components
 * may contain wildcard and pattern syntax.
 */
function parsePatternString(pattern: string): Record<ComponentName, string> {
  const result: Record<ComponentName, string> = {
    protocol: "*",
    username: "*",
    password: "*",
    hostname: "*",
    port: "*",
    pathname: "*",
    search: "*",
    hash: "*",
  };

  let remaining = pattern;

  // Extract hash
  const hashIdx = findUnescapedChar(remaining, "#");
  if (hashIdx !== -1) {
    result.hash = remaining.slice(hashIdx + 1);
    remaining = remaining.slice(0, hashIdx);
  }

  // Extract search
  const searchIdx = findUnescapedChar(remaining, "?", true);
  if (searchIdx !== -1) {
    result.search = remaining.slice(searchIdx + 1);
    remaining = remaining.slice(0, searchIdx);
  }

  // Extract protocol
  // Look for a protocol-like pattern: something followed by ://
  // But be careful not to match :name patterns
  const protoEndIdx = remaining.indexOf("://");
  if (protoEndIdx !== -1) {
    result.protocol = remaining.slice(0, protoEndIdx);
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
        result.username = userinfo.slice(0, colonIdx);
        result.password = userinfo.slice(colonIdx + 1);
      } else {
        result.username = userinfo;
      }
    }

    // Parse host:port - but be careful with patterns
    // We need to find a colon that separates hostname from port,
    // not one that's part of a :name pattern
    const portSep = findPortSeparator(hostPart);
    if (portSep !== -1) {
      result.hostname = hostPart.slice(0, portSep);
      result.port = hostPart.slice(portSep + 1);
    } else {
      result.hostname = hostPart;
      result.port = "*";
    }
  } else {
    // No protocol, might be just a pathname pattern
    // Check if it looks like an absolute path
    if (
      remaining.startsWith("/") ||
      remaining.startsWith(":") ||
      remaining.startsWith("*")
    ) {
      result.protocol = "*";
      result.hostname = "*";
    }
  }

  // Remaining is pathname
  if (remaining) {
    result.pathname = remaining;
  }

  return result;
}

/**
 * Find a character in a string, skipping characters inside parentheses and braces.
 * For '?', `topLevelOnly` skips '?' that are part of {pattern}? syntax.
 */
function findUnescapedChar(
  str: string,
  ch: string,
  topLevelOnly: boolean = false,
): number {
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "(" || c === "{") depth++;
    else if (c === ")" || c === "}") depth--;
    else if (c === ch && depth === 0) {
      if (topLevelOnly && ch === "?") {
        // Skip ? that follows } (part of optional syntax)
        if (i > 0 && str[i - 1] === "}") {
          continue;
        }
      }
      return i;
    }
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
// URLPattern Class
// ============================================================================

export class URLPattern {
  private _components: Record<ComponentName, CompiledComponent>;

  /**
   * Create a new URLPattern.
   *
   * @param input - A pattern string (like "https://example.com/:path") or
   *   an object with component patterns ({pathname: "/users/:id"})
   * @param baseURL - Optional base URL string (only when input is a string)
   */
  constructor(input: URLPatternInput, baseURL?: string) {
    let patterns: Record<ComponentName, string>;

    if (typeof input === "string") {
      // Parse the pattern string into components
      if (baseURL) {
        // If baseURL is provided, parse the base first, then overlay the input
        const baseParts = parsePatternString(baseURL);
        const inputParts = parsePatternString(input);

        // The input overrides the base for components it specifies
        patterns = { ...baseParts };
        for (const comp of COMPONENTS) {
          if (inputParts[comp] !== "*" || comp === "pathname") {
            patterns[comp] = inputParts[comp];
          }
        }
      } else {
        patterns = parsePatternString(input);
      }
    } else {
      // Object input - use defaults for unspecified components
      patterns = { ...DEFAULT_PATTERNS };

      // If baseURL is provided in the init object, parse it first
      if (input.baseURL) {
        const baseParts = parsePatternString(input.baseURL);
        for (let i = 0; i < COMPONENTS.length; i++) {
          const comp = COMPONENTS[i];
          patterns[comp] = baseParts[comp];
        }
      }

      // Override with explicitly provided values
      for (let i = 0; i < COMPONENTS.length; i++) {
        const comp = COMPONENTS[i];
        if (input[comp] !== undefined) {
          patterns[comp] = input[comp]!;
        }
      }
    }

    // Compile each component pattern into a regex
    this._components = {} as Record<ComponentName, CompiledComponent>;
    for (let i = 0; i < COMPONENTS.length; i++) {
      const comp = COMPONENTS[i];
      this._components[comp] = compileComponent(patterns[comp], comp);
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
  test(input: URLPatternInput, baseURL?: string): boolean {
    return this.exec(input, baseURL) !== null;
  }

  /**
   * Execute this pattern against a URL, returning match details or null.
   *
   * @param input - A URL string or URLPatternInit to match
   * @param baseURL - Optional base URL (only when input is a string)
   * @returns URLPatternResult with match details, or null if no match
   */
  exec(input: URLPatternInput, baseURL?: string): URLPatternResult | null {
    let urlComponents: Record<ComponentName, string>;

    try {
      urlComponents = parseURLInput(input, baseURL);
    } catch {
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
