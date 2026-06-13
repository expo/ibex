/**
 * Console - Web Standard Console Implementation
 *
 * @see https://console.spec.whatwg.org/
 */

import { inspect } from "../inspect";

export type LogLevel = "log" | "info" | "warn" | "error" | "debug" | "trace";

export interface ConsoleOutput {
  log(level: LogLevel, args: any[]): void;
  group?(label: string, collapsed: boolean): void;
  groupEnd?(): void;
  clear?(): void;
}

// Capture the native console BEFORE we overwrite it
// The native layer (Hermes/JSC) sets up globalThis.console with native logging
const _nativeConsole = (globalThis as any).console;

// Default output sends to native console
// Note: We need to look up console dynamically because it might be
// set up AFTER our module loads but BEFORE our methods are called
let output: ConsoleOutput = {
  log: (level, args) => {
    // First try: use captured native console
    if (_nativeConsole && typeof _nativeConsole[level] === 'function') {
      _nativeConsole[level](...args);
      return;
    }
    // Second try: use current global console (might be set up later)
    const currentConsole = (globalThis as any).console;
    if (currentConsole && currentConsole !== _nativeConsole && typeof currentConsole[level] === 'function') {
      currentConsole[level](...args);
      return;
    }
  },
};

export function setConsoleOutput(newOutput: ConsoleOutput): void {
  output = newOutput;
}

// Counters for console.count
const counters = new Map<string, number>();

// Timers for console.time
const timers = new Map<string, number>();

// Group depth tracking
let groupDepth = 0;

/**
 * Format a single value for output.
 */
function formatValue(arg: any): string {
  if (arg === undefined) return "undefined";
  if (arg === null) return "null";
  if (typeof arg === "object") {
    return inspect(arg, { colors: false });
  }
  return String(arg);
}

/**
 * Format arguments, supporting printf-style format specifiers.
 * Supports: %s (string), %d/%i (integer), %f (float), %o/%O (object), %c (CSS - ignored)
 * 
 * @see https://console.spec.whatwg.org/#formatter
 */
function formatArgs(args: any[]): any[] {
  if (args.length === 0) return [];
  
  const first = args[0];
  
  // If first arg is not a string or has no format specifiers, just format all args
  if (typeof first !== 'string' || !/%[sdifoOc%]/.test(first)) {
    return args.map(formatValue);
  }
  
  // Process format specifiers
  let result = '';
  let argIndex = 1;
  let i = 0;
  
  while (i < first.length) {
    if (first[i] === '%' && i + 1 < first.length) {
      const specifier = first[i + 1];
      
      switch (specifier) {
        case 's': // String
          if (argIndex < args.length) {
            result += String(args[argIndex++]);
          } else {
            result += '%s';
          }
          i += 2;
          break;
          
        case 'd': // Integer
        case 'i':
          if (argIndex < args.length) {
            const num = Number(args[argIndex++]);
            result += isNaN(num) ? 'NaN' : String(Math.trunc(num));
          } else {
            result += `%${specifier}`;
          }
          i += 2;
          break;
          
        case 'f': // Float
          if (argIndex < args.length) {
            const num = Number(args[argIndex++]);
            result += isNaN(num) ? 'NaN' : String(num);
          } else {
            result += '%f';
          }
          i += 2;
          break;
          
        case 'o': // Object (compact)
        case 'O': // Object (verbose)
          if (argIndex < args.length) {
            result += inspect(args[argIndex++], {
              colors: false,
              compact: specifier === 'o',
            });
          } else {
            result += `%${specifier}`;
          }
          i += 2;
          break;
          
        case 'c': // CSS styling (ignored in non-browser environments)
          // Skip the style argument but don't output anything
          if (argIndex < args.length) {
            argIndex++;
          }
          i += 2;
          break;
          
        case '%': // Literal %
          result += '%';
          i += 2;
          break;
          
        default:
          // Unknown specifier, output as-is
          result += first[i];
          i++;
      }
    } else {
      result += first[i];
      i++;
    }
  }
  
  // Append any remaining arguments
  const remaining = args.slice(argIndex).map(formatValue);
  
  if (remaining.length > 0) {
    return [result, ...remaining];
  }
  
  return [result];
}

function getIndent(): string {
  return "  ".repeat(groupDepth);
}

export class Console {
  log(...args: any[]): void {
    output.log("log", formatArgs(args));
  }

  info(...args: any[]): void {
    output.log("info", formatArgs(args));
  }

  warn(...args: any[]): void {
    output.log("warn", formatArgs(args));
  }

  error(...args: any[]): void {
    output.log("error", formatArgs(args));
  }

  debug(...args: any[]): void {
    output.log("debug", formatArgs(args));
  }

  trace(...args: any[]): void {
    // Create stack trace
    const err = new Error();
    const stack = err.stack?.split("\n").slice(2).join("\n") ?? "";
    output.log("trace", [...formatArgs(args), "\n" + stack]);
  }

  assert(condition?: boolean, ...args: any[]): void {
    if (!condition) {
      const message = args.length > 0 ? formatArgs(args) : ["Assertion failed"];
      output.log("error", ["Assertion failed:", ...message]);
    }
  }

  table(data: any, columns?: string[]): void {
    if (data === null || data === undefined) {
      output.log("log", [data]);
      return;
    }

    if (typeof data !== "object") {
      output.log("log", [data]);
      return;
    }

    // Simple table implementation
    const isArray = Array.isArray(data);
    const entries = isArray
      ? data.map((item, index) => [index, item])
      : Object.entries(data);

    if (entries.length === 0) {
      output.log("log", [isArray ? "[]" : "{}"]);
      return;
    }

    // Build table string
    const header = isArray ? "(index)" : "(key)";
    let tableStr = `\n${header}\tValue\n`;
    tableStr += "-".repeat(40) + "\n";

    for (const [key, value] of entries) {
      const valueStr =
        typeof value === "object" ? JSON.stringify(value) : String(value);
      tableStr += `${key}\t${valueStr}\n`;
    }

    output.log("log", [tableStr]);
  }

  group(label?: string): void {
    const groupLabel = label ?? "console.group";
    if (output.group) {
      output.group(groupLabel, false);
    } else {
      output.log("log", [`${getIndent()}▼ ${groupLabel}`]);
    }
    groupDepth++;
  }

  groupCollapsed(label?: string): void {
    const groupLabel = label ?? "console.group";
    if (output.group) {
      output.group(groupLabel, true);
    } else {
      output.log("log", [`${getIndent()}▶ ${groupLabel}`]);
    }
    groupDepth++;
  }

  groupEnd(): void {
    if (groupDepth > 0) {
      groupDepth--;
    }
    if (output.groupEnd) {
      output.groupEnd();
    }
  }

  count(label?: string): void {
    const countLabel = label ?? "default";
    const count = (counters.get(countLabel) ?? 0) + 1;
    counters.set(countLabel, count);
    output.log("log", [`${countLabel}: ${count}`]);
  }

  countReset(label?: string): void {
    const countLabel = label ?? "default";
    if (counters.has(countLabel)) {
      counters.set(countLabel, 0);
    } else {
      output.log("warn", [`Count for '${countLabel}' does not exist`]);
    }
  }

  time(label?: string): void {
    const timerLabel = label ?? "default";
    if (timers.has(timerLabel)) {
      output.log("warn", [`Timer '${timerLabel}' already exists`]);
      return;
    }
    timers.set(timerLabel, performance?.now?.() ?? Date.now());
  }

  timeEnd(label?: string): void {
    const timerLabel = label ?? "default";
    const startTime = timers.get(timerLabel);
    if (startTime === undefined) {
      output.log("warn", [`Timer '${timerLabel}' does not exist`]);
      return;
    }
    const duration = (performance?.now?.() ?? Date.now()) - startTime;
    timers.delete(timerLabel);
    output.log("log", [`${timerLabel}: ${duration.toFixed(3)}ms`]);
  }

  timeLog(label?: string, ...args: any[]): void {
    const timerLabel = label ?? "default";
    const startTime = timers.get(timerLabel);
    if (startTime === undefined) {
      output.log("warn", [`Timer '${timerLabel}' does not exist`]);
      return;
    }
    const duration = (performance?.now?.() ?? Date.now()) - startTime;
    output.log("log", [`${timerLabel}: ${duration.toFixed(3)}ms`, ...formatArgs(args)]);
  }

  clear(): void {
    if (output.clear) {
      output.clear();
    } else {
      // Output some newlines or clear indicator
      output.log("log", ["\n".repeat(50) + "--- Console cleared ---"]);
    }
  }

  // Aliases
  dir(obj: any): void {
    this.log(obj);
  }

  dirxml(obj: any): void {
    this.log(obj);
  }
}

// Create singleton instance
export const console = new Console();
