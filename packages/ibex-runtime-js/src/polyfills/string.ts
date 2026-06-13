// @ts-nocheck
/**
 * ES2024 String well-formed polyfills for Hermes engine
 *
 * - String.prototype.isWellFormed()
 * - String.prototype.toWellFormed()
 */

export function installStringPolyfills(): void {
  // --------------------------------------------------------------------------
  // String.prototype.isWellFormed (ES2024)
  // Returns true if the string contains no lone surrogates.
  // A lone surrogate is a code unit in the range 0xD800-0xDBFF (high surrogate)
  // not followed by 0xDC00-0xDFFF (low surrogate), or a low surrogate not
  // preceded by a high surrogate.
  // --------------------------------------------------------------------------
  if (typeof String.prototype.isWellFormed !== 'function') {
    Object.defineProperty(String.prototype, 'isWellFormed', {
      value: function isWellFormed(this: string): boolean {
        if (this == null) {
          throw new TypeError('String.prototype.isWellFormed called on null or undefined');
        }
        const str = String(this);
        for (let i = 0; i < str.length; i++) {
          const code = str.charCodeAt(i);
          // High surrogate
          if (code >= 0xD800 && code <= 0xDBFF) {
            const next = str.charCodeAt(i + 1);
            // Must be followed by a low surrogate
            if (next < 0xDC00 || next > 0xDFFF || i + 1 >= str.length) {
              return false;
            }
            i++; // Skip the low surrogate
          } else if (code >= 0xDC00 && code <= 0xDFFF) {
            // Lone low surrogate
            return false;
          }
        }
        return true;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // String.prototype.toWellFormed (ES2024)
  // Returns a new string with lone surrogates replaced by U+FFFD.
  // --------------------------------------------------------------------------
  if (typeof String.prototype.toWellFormed !== 'function') {
    Object.defineProperty(String.prototype, 'toWellFormed', {
      value: function toWellFormed(this: string): string {
        if (this == null) {
          throw new TypeError('String.prototype.toWellFormed called on null or undefined');
        }
        const str = String(this);
        const result: string[] = [];
        for (let i = 0; i < str.length; i++) {
          const code = str.charCodeAt(i);
          if (code >= 0xD800 && code <= 0xDBFF) {
            const next = str.charCodeAt(i + 1);
            if (next >= 0xDC00 && next <= 0xDFFF && i + 1 < str.length) {
              // Valid surrogate pair
              result.push(str[i], str[i + 1]);
              i++;
            } else {
              // Lone high surrogate
              result.push('\uFFFD');
            }
          } else if (code >= 0xDC00 && code <= 0xDFFF) {
            // Lone low surrogate
            result.push('\uFFFD');
          } else {
            result.push(str[i]);
          }
        }
        return result.join('');
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
