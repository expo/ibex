/**
 * Intl polyfills for Hermes engine
 *
 * Hermes has limited Intl support. It provides basic Intl.DateTimeFormat and
 * Intl.NumberFormat, but may lack newer methods (formatRange, formatToParts)
 * and entirely missing APIs like:
 * - Intl.PluralRules
 * - Intl.ListFormat
 * - Intl.RelativeTimeFormat
 * - Intl.Segmenter
 * - Intl.DisplayNames
 * - Intl.Collator
 *
 * These polyfills cover the API surface with locale-aware plural rules for
 * the top 14 locales, proper formatToParts decomposition for NumberFormat
 * and DateTimeFormat, improved grapheme segmentation for emoji, and more.
 * They will be superseded by native implementations when available.
 */

import {
  canonicalizeLocaleTag,
  directionForLocaleTag,
  parseLocaleTag,
} from '../core/i18n-helpers.js';

const __DEV__ = process.env.NODE_ENV !== 'production';

function parseUnicodeExtensionKeyword(
  localeTag: string,
  keyword: string,
): string | undefined {
  const extensions = localeTag.split('-u-')[1];
  if (!extensions) {
    return undefined;
  }

  const tokens = extensions.split('-').filter(Boolean);
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index] !== keyword) {
      continue;
    }

    const value = tokens[index + 1];
    return value && value.length > 0 ? value : undefined;
  }

  return undefined;
}

export function installIntlPolyfills(): void {
  const g = globalThis as any;

  // Ensure Intl namespace exists
  if (typeof g.Intl === 'undefined') {
    g.Intl = {};
  }

  const Intl = g.Intl;

  // --------------------------------------------------------------------------
  // Intl.getCanonicalLocales
  // Canonicalizes locale tags (lowercase language, uppercase region, titlecase script).
  // --------------------------------------------------------------------------
  if (typeof Intl.getCanonicalLocales !== 'function') {
    Object.defineProperty(Intl, 'getCanonicalLocales', {
      value: function getCanonicalLocales(locales?: string | string[]): string[] {
        if (!locales) return [];
        const input = typeof locales === 'string' ? [locales] : Array.from(locales);
        return input.map(tag => {
          const str = String(tag);
          if (str.length === 0) {
            throw new RangeError('invalid language tag: ""');
          }
          // Basic canonicalization: lowercase language, uppercase region, titlecase script
          const parts = str.split('-');
          if (parts.length >= 1) parts[0] = parts[0].toLowerCase();
          if (parts.length >= 2) {
            if (parts[1].length === 4) {
              // Script subtag: titlecase
              parts[1] = parts[1][0].toUpperCase() + parts[1].slice(1).toLowerCase();
            } else if (parts[1].length === 2) {
              // Region subtag: uppercase
              parts[1] = parts[1].toUpperCase();
            }
          }
          if (parts.length >= 3 && parts[2].length === 2) {
            parts[2] = parts[2].toUpperCase();
          }
          return parts.join('-');
        });
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.Locale subset
  // Covers algorithmic BCP 47 parsing plus text direction and unicode keyword reads.
  // --------------------------------------------------------------------------
  if (typeof Intl.Locale !== 'function') {
    class LocalePolyfill {
      private readonly _tag: string;
      private readonly _baseName: string;
      private readonly _parsed: ReturnType<typeof parseLocaleTag>;

      constructor(tag: string) {
        if (typeof tag !== 'string' || tag.trim().length === 0) {
          throw new TypeError('Intl.Locale requires a non-empty locale tag');
        }

        this._tag = canonicalizeLocaleTag(tag);
        this._baseName = this._tag.split('-u-')[0] ?? this._tag;
        this._parsed = parseLocaleTag(this._tag);
      }

      get baseName(): string {
        return this._baseName;
      }

      get language(): string {
        return this._parsed.language;
      }

      get region(): string | undefined {
        return this._parsed.region;
      }

      get script(): string | undefined {
        return this._parsed.script;
      }

      get calendar(): string | undefined {
        return parseUnicodeExtensionKeyword(this._tag, 'ca');
      }

      get numberingSystem(): string | undefined {
        return parseUnicodeExtensionKeyword(this._tag, 'nu');
      }

      get textInfo(): { direction: 'ltr' | 'rtl' } {
        return {
          direction: directionForLocaleTag(this._tag),
        };
      }

      maximize(): this {
        if (__DEV__) {
          console.warn('Intl.Locale.prototype.maximize() is not implemented in Exact core.');
        }
        return this;
      }

      minimize(): this {
        if (__DEV__) {
          console.warn('Intl.Locale.prototype.minimize() is not implemented in Exact core.');
        }
        return this;
      }

      toString(): string {
        return this._tag;
      }

      toJSON(): string {
        return this._tag;
      }
    }

    Object.defineProperty(Intl, 'Locale', {
      value: LocalePolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  } else if (
    Intl.Locale?.prototype &&
    !('textInfo' in Intl.Locale.prototype)
  ) {
    Object.defineProperty(Intl.Locale.prototype, 'textInfo', {
      get(this: { toString(): string }) {
        return {
          direction: directionForLocaleTag(String(this)),
        };
      },
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.DateTimeFormat enhancements
  // Hermes may have a basic DateTimeFormat but lack formatRange/formatToParts.
  // --------------------------------------------------------------------------
  if (typeof Intl.DateTimeFormat === 'function') {
    const DTFProto = Intl.DateTimeFormat.prototype;

    // formatToParts - returns an array of parts for a formatted date
    // Strategy: format individual components and find them in the full string
    if (typeof DTFProto.formatToParts !== 'function') {
      Object.defineProperty(DTFProto, 'formatToParts', {
        value: function formatToParts(date?: Date | number): Array<{type: string; value: string}> {
          const d = date === undefined ? new Date() : new Date(date);
          const formatted = this.format(d);
          const opts = this.resolvedOptions ? this.resolvedOptions() : {};
          const locale = opts.locale || 'en';
          const parts: Array<{type: string; value: string}> = [];

          // Build a list of component values by formatting with single options
          // Each entry: [type, value, optionKey]
          type ComponentEntry = { type: string; value: string; priority: number };
          const components: ComponentEntry[] = [];

          // Helper to safely format with a single option
          const tryFormat = (type: string, fmtOpts: any, priority: number): void => {
            try {
              const fmt = new Intl.DateTimeFormat(locale, fmtOpts);
              const val = fmt.format(d);
              if (val && val.length > 0) {
                components.push({ type, value: val, priority });
              }
            } catch (_e) {
              // If the engine doesn't support this option combo, skip
            }
          };

          // Try each date/time component that might be in the format
          // Priority determines matching order (longer/more specific first)
          if (opts.era) tryFormat('era', { era: opts.era }, 10);
          if (opts.year) tryFormat('year', { year: opts.year }, 20);
          if (opts.month) tryFormat('month', { month: opts.month }, 15);
          if (opts.day) tryFormat('day', { day: opts.day }, 30);
          if (opts.weekday) tryFormat('weekday', { weekday: opts.weekday }, 5);
          if (opts.hour) tryFormat('hour', { hour: opts.hour, hour12: opts.hour12 }, 40);
          if (opts.minute) tryFormat('minute', { minute: opts.minute }, 50);
          if (opts.second) tryFormat('second', { second: opts.second }, 60);
          if (opts.dayPeriod || opts.hour12) tryFormat('dayPeriod', { hour: 'numeric', hour12: true }, 45);
          if (opts.timeZoneName) tryFormat('timeZoneName', { timeZoneName: opts.timeZoneName }, 70);

          // If we have no components, try the default date components
          if (components.length === 0) {
            tryFormat('month', { month: 'numeric' }, 15);
            tryFormat('day', { day: 'numeric' }, 30);
            tryFormat('year', { year: 'numeric' }, 20);
          }

          // Now try to locate each component in the formatted string
          // Sort by value length descending so we match longer strings first
          components.sort((a, b) => b.value.length - a.value.length || a.priority - b.priority);

          // Track which character positions in the formatted string are assigned
          const assigned = new Array(formatted.length).fill(false);
          const charType = new Array(formatted.length).fill('');

          for (const comp of components) {
            const idx = findUnassigned(formatted, comp.value, assigned);
            if (idx >= 0) {
              for (let ci = idx; ci < idx + comp.value.length; ci++) {
                assigned[ci] = true;
                charType[ci] = comp.type;
              }
            }
          }

          // Extract dayPeriod from hour formatting (AM/PM)
          // The hour format might include the period; strip it out
          // by checking if any 'dayPeriod' character overlaps with 'hour'

          // Build the parts array by grouping consecutive chars of same type
          let currentType = '';
          let currentValue = '';
          for (let ci = 0; ci < formatted.length; ci++) {
            const t = charType[ci] || 'literal';
            if (t !== currentType) {
              if (currentValue) {
                parts.push({ type: currentType || 'literal', value: currentValue });
              }
              currentType = t;
              currentValue = formatted[ci];
            } else {
              currentValue += formatted[ci];
            }
          }
          if (currentValue) {
            parts.push({ type: currentType || 'literal', value: currentValue });
          }

          // If no parts were produced (shouldn't happen), fall back
          if (parts.length === 0) {
            return [{ type: 'literal', value: formatted }];
          }

          return parts;
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });

      function findUnassigned(str: string, substr: string, assigned: boolean[]): number {
        let startIdx = 0;
        while (startIdx <= str.length - substr.length) {
          const idx = str.indexOf(substr, startIdx);
          if (idx < 0) return -1;
          // Check that none of these positions are already assigned
          let allFree = true;
          for (let i = idx; i < idx + substr.length; i++) {
            if (assigned[i]) {
              allFree = false;
              break;
            }
          }
          if (allFree) return idx;
          startIdx = idx + 1;
        }
        return -1;
      }
    }

    // formatRange - formats a date range
    if (typeof DTFProto.formatRange !== 'function') {
      Object.defineProperty(DTFProto, 'formatRange', {
        value: function formatRange(startDate: Date | number, endDate: Date | number): string {
          if (startDate === undefined || endDate === undefined) {
            throw new TypeError('formatRange requires two dates');
          }
          const start = this.format(new Date(startDate));
          const end = this.format(new Date(endDate));
          if (start === end) return start;
          return `${start} \u2013 ${end}`;
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }

    // formatRangeToParts - returns parts for a formatted date range
    if (typeof DTFProto.formatRangeToParts !== 'function') {
      Object.defineProperty(DTFProto, 'formatRangeToParts', {
        value: function formatRangeToParts(
          startDate: Date | number,
          endDate: Date | number,
        ): Array<{type: string; value: string; source: string}> {
          if (startDate === undefined || endDate === undefined) {
            throw new TypeError('formatRangeToParts requires two dates');
          }
          const start = this.format(new Date(startDate));
          const end = this.format(new Date(endDate));
          if (start === end) {
            return [{ type: 'literal', value: start, source: 'shared' }];
          }
          return [
            { type: 'literal', value: start, source: 'startRange' },
            { type: 'literal', value: ' \u2013 ', source: 'shared' },
            { type: 'literal', value: end, source: 'endRange' },
          ];
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }
  }

  // --------------------------------------------------------------------------
  // Intl.NumberFormat enhancements
  // Hermes may have basic NumberFormat but lack formatToParts/formatRange.
  // --------------------------------------------------------------------------
  if (typeof Intl.NumberFormat === 'function') {
    const NFProto = Intl.NumberFormat.prototype;

    // formatToParts - returns parts of a formatted number
    // Strategy: use native format() to get the string, then decompose it
    // by analyzing the resolved options (style, currency, etc.)
    if (typeof NFProto.formatToParts !== 'function') {
      Object.defineProperty(NFProto, 'formatToParts', {
        value: function formatToParts(value?: number): Array<{type: string; value: string}> {
          const num = value === undefined ? NaN : Number(value);
          const formatted = this.format(num);

          if (isNaN(num)) {
            return [{ type: 'nan', value: formatted }];
          }
          if (!isFinite(num)) {
            return [{ type: 'infinity', value: formatted }];
          }

          const opts = this.resolvedOptions ? this.resolvedOptions() : {};
          const parts: Array<{type: string; value: string}> = [];

          // Determine sign
          const isNeg = num < 0 || (Object.is && Object.is(num, -0));
          const absNum = Math.abs(num);

          // Format the absolute value to get the core number string
          let absFormatted: string;
          try {
            // Create a formatter without currency/percent to get just the number
            const absOpts: any = {};
            if (opts.minimumIntegerDigits) absOpts.minimumIntegerDigits = opts.minimumIntegerDigits;
            if (opts.minimumFractionDigits != null) absOpts.minimumFractionDigits = opts.minimumFractionDigits;
            if (opts.maximumFractionDigits != null) absOpts.maximumFractionDigits = opts.maximumFractionDigits;
            if (opts.minimumSignificantDigits) absOpts.minimumSignificantDigits = opts.minimumSignificantDigits;
            if (opts.maximumSignificantDigits) absOpts.maximumSignificantDigits = opts.maximumSignificantDigits;
            if (opts.useGrouping != null) absOpts.useGrouping = opts.useGrouping;
            const absFmt = new Intl.NumberFormat(opts.locale || 'en', absOpts);
            absFormatted = absFmt.format(absNum);
          } catch (_e) {
            absFormatted = String(absNum);
          }

          // Handle different styles
          const style = opts.style || 'decimal';

          if (style === 'percent') {
            // Percent: the formatted string includes the % sign
            return _parsePercentParts(formatted, isNeg);
          }

          if (style === 'currency') {
            return _parseCurrencyParts(formatted, absFormatted, isNeg, opts);
          }

          // Decimal or other: parse the number string
          if (isNeg) {
            // Find and remove the minus sign
            const minusIdx = formatted.indexOf('-') >= 0 ? formatted.indexOf('-') : formatted.indexOf('\u2212');
            if (minusIdx >= 0) {
              const minusChar = formatted[minusIdx];
              const before = formatted.substring(0, minusIdx);
              const after = formatted.substring(minusIdx + minusChar.length);
              if (before.length > 0) parts.push({ type: 'literal', value: before });
              parts.push({ type: 'minusSign', value: minusChar });
              const numberStr = after.trim() || after;
              parts.push(..._parseDecimalParts(numberStr.length > 0 ? numberStr : absFormatted));
              return parts;
            }
          }

          return _parseDecimalParts(formatted);
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });

      /**
       * Parse a decimal number string (potentially with grouping) into parts.
       * Handles patterns like: "12,345.67" or "12.345,67" (European)
       *
       * Known edge case: For numbers with exactly 3 digits after the last
       * separator (e.g., "1.234"), the last separator is ambiguous -- it could
       * be a group separator (1234) or a decimal point (1.234). We treat it
       * as a decimal point (last separator = decimal), which is correct for
       * most locales when a single separator is present, but may be incorrect
       * for locales like German where "1.234" means one thousand two hundred
       * thirty-four. This is inherent to string-based decomposition without
       * knowing the locale's separator convention.
       */
      function _parseDecimalParts(str: string): Array<{type: string; value: string}> {
        const parts: Array<{type: string; value: string}> = [];
        const trimmed = str.trim();

        if (trimmed.length === 0) {
          return [{ type: 'integer', value: '0' }];
        }

        // Identify the decimal separator: it's the last non-digit punctuation
        // that is followed only by digits (and possibly trailing chars)
        // Common decimal separators: . , ·
        // Common group separators: , . ' (space) (narrow no-break space)
        let decimalPos = -1;
        let decimalChar = '';

        // Find the last separator character
        // Walk from the end to find the decimal point
        for (let i = trimmed.length - 1; i >= 0; i--) {
          const ch = trimmed[i];
          if (ch === '.' || ch === ',' || ch === '\u00B7') {
            // Check if everything after this char (to end) is digits
            const afterSep = trimmed.substring(i + 1);
            if (/^\d+$/.test(afterSep)) {
              decimalPos = i;
              decimalChar = ch;
              break;
            }
          }
        }

        let integerPart: string;
        let fractionPart: string | null = null;

        if (decimalPos >= 0) {
          integerPart = trimmed.substring(0, decimalPos);
          fractionPart = trimmed.substring(decimalPos + 1);
        } else {
          integerPart = trimmed;
        }

        // Parse the integer part, splitting on group separators
        // Group separators are non-digit characters within the integer part
        if (integerPart.length > 0) {
          _parseIntegerWithGroups(integerPart, parts);
        } else {
          parts.push({ type: 'integer', value: '0' });
        }

        if (fractionPart !== null) {
          parts.push({ type: 'decimal', value: decimalChar });
          parts.push({ type: 'fraction', value: fractionPart });
        }

        return parts;
      }

      /**
       * Parse integer part, identifying group separators.
       */
      function _parseIntegerWithGroups(str: string, parts: Array<{type: string; value: string}>): void {
        // Split on any non-digit character that acts as a group separator
        let current = '';
        let firstGroup = true;
        for (let i = 0; i < str.length; i++) {
          const ch = str[i];
          if (/\d/.test(ch)) {
            current += ch;
          } else {
            // This is a group separator
            if (current.length > 0) {
              parts.push({ type: 'integer', value: current });
              current = '';
              firstGroup = false;
            }
            parts.push({ type: 'group', value: ch });
          }
        }
        if (current.length > 0) {
          parts.push({ type: 'integer', value: current });
        }
      }

      /**
       * Parse a percent-formatted number string into parts.
       */
      function _parsePercentParts(formatted: string, isNeg: boolean): Array<{type: string; value: string}> {
        const parts: Array<{type: string; value: string}> = [];

        // Find the percent sign
        const percentIdx = formatted.indexOf('%');
        if (percentIdx < 0) {
          // No % sign found, just return as literal
          return [{ type: 'literal', value: formatted }];
        }

        let beforePercent = formatted.substring(0, percentIdx);
        let afterPercent = formatted.substring(percentIdx + 1);

        // Handle minus sign
        if (isNeg) {
          const minusIdx = beforePercent.indexOf('-') >= 0 ? beforePercent.indexOf('-') : beforePercent.indexOf('\u2212');
          if (minusIdx >= 0) {
            const minusChar = beforePercent[minusIdx];
            const preSign = beforePercent.substring(0, minusIdx);
            const postSign = beforePercent.substring(minusIdx + 1);
            if (preSign.length > 0) parts.push({ type: 'literal', value: preSign });
            parts.push({ type: 'minusSign', value: minusChar });
            beforePercent = postSign;
          }
        }

        // The number part is before the percent (trimmed)
        const numStr = beforePercent.trim();
        if (numStr.length > 0) {
          parts.push(..._parseDecimalParts(numStr));
        }

        // Space before percent if present
        const trailingSpace = beforePercent.length - beforePercent.trimEnd().length;
        if (trailingSpace > 0) {
          parts.push({ type: 'literal', value: beforePercent.substring(beforePercent.trimEnd().length) });
        }

        parts.push({ type: 'percentSign', value: '%' });

        if (afterPercent.length > 0) {
          parts.push({ type: 'literal', value: afterPercent });
        }

        return parts;
      }

      /**
       * Parse a currency-formatted number string into parts.
       */
      function _parseCurrencyParts(
        formatted: string,
        absFormatted: string,
        isNeg: boolean,
        opts: any,
      ): Array<{type: string; value: string}> {
        const parts: Array<{type: string; value: string}> = [];
        const currencyCode = opts.currency || 'USD';
        const currencyDisplay = opts.currencyDisplay || 'symbol';

        // Common currency symbols
        const currencySymbols: Record<string, string> = {
          USD: '$', EUR: '\u20AC', GBP: '\u00A3', JPY: '\u00A5', CNY: '\u00A5',
          KRW: '\u20A9', INR: '\u20B9', BRL: 'R$', CAD: 'CA$', AUD: 'A$',
          CHF: 'CHF', MXN: 'MX$', SEK: 'kr', NOK: 'kr', DKK: 'kr',
          PLN: 'z\u0142', TRY: '\u20BA', RUB: '\u20BD', THB: '\u0E3F',
        };

        // Determine what the currency symbol/code looks like in the string
        let currencyStr = '';
        if (currencyDisplay === 'code') {
          currencyStr = currencyCode;
        } else if (currencyDisplay === 'name') {
          // Name display is locale-dependent; hard to detect
          currencyStr = '';
        } else {
          // symbol or narrowSymbol
          currencyStr = currencySymbols[currencyCode.toUpperCase()] || currencyCode;
        }

        // Try to find the currency string in the formatted output
        let workStr = formatted;

        // Handle minus sign first
        if (isNeg) {
          const minusIdx = workStr.indexOf('-') >= 0 ? workStr.indexOf('-') : workStr.indexOf('\u2212');
          if (minusIdx >= 0) {
            const minusChar = workStr[minusIdx];
            if (minusIdx > 0) {
              // Something before minus - might be currency
              const pre = workStr.substring(0, minusIdx);
              if (pre.trim() === currencyStr && currencyStr.length > 0) {
                parts.push({ type: 'currency', value: currencyStr });
                if (pre.length > currencyStr.length) {
                  parts.push({ type: 'literal', value: pre.substring(currencyStr.length) });
                }
              } else if (pre.trim().length > 0) {
                parts.push({ type: 'literal', value: pre });
              }
            }
            parts.push({ type: 'minusSign', value: minusChar });
            workStr = workStr.substring(minusIdx + 1);
          }
        }

        // Find currency in remaining string
        if (currencyStr.length > 0) {
          const curIdx = workStr.indexOf(currencyStr);
          if (curIdx >= 0) {
            const before = workStr.substring(0, curIdx);
            const after = workStr.substring(curIdx + currencyStr.length);

            if (curIdx === 0) {
              // Currency at start (e.g., "$1,234.56")
              parts.push({ type: 'currency', value: currencyStr });
              // There may be a space/NBSP between currency and number
              if (after.length > 0 && /^[\s\u00A0\u202F]/.test(after)) {
                parts.push({ type: 'literal', value: after[0] });
                const numStr = after.substring(1).trim();
                if (numStr.length > 0) {
                  parts.push(..._parseDecimalParts(numStr));
                }
              } else {
                const numStr = after.trim();
                if (numStr.length > 0) {
                  parts.push(..._parseDecimalParts(numStr));
                }
              }
            } else {
              // Currency at end or middle (e.g., "1.234,56 EUR" or "1,234.56kr")
              const numStr = before.trim();
              if (numStr.length > 0) {
                parts.push(..._parseDecimalParts(numStr));
              }
              // Space between number and currency
              if (before.length > before.trimEnd().length) {
                parts.push({ type: 'literal', value: before.substring(before.trimEnd().length) });
              }
              parts.push({ type: 'currency', value: currencyStr });
              if (after.trim().length > 0) {
                parts.push({ type: 'literal', value: after });
              }
            }
          } else {
            // Currency not found in string, just parse as decimal
            parts.push(..._parseDecimalParts(workStr.trim()));
          }
        } else {
          // No known currency string, parse what we have
          parts.push(..._parseDecimalParts(workStr.trim()));
        }

        return parts.length > 0 ? parts : [{ type: 'literal', value: formatted }];
      }
    }

    // formatRange - formats a number range
    if (typeof NFProto.formatRange !== 'function') {
      Object.defineProperty(NFProto, 'formatRange', {
        value: function formatRange(start: number, end: number): string {
          if (start === undefined || end === undefined) {
            throw new TypeError('formatRange requires two numbers');
          }
          const startStr = this.format(Number(start));
          const endStr = this.format(Number(end));
          if (startStr === endStr) return startStr;
          return `${startStr}\u2013${endStr}`;
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }

    // formatRangeToParts - returns parts for a formatted number range
    if (typeof NFProto.formatRangeToParts !== 'function') {
      Object.defineProperty(NFProto, 'formatRangeToParts', {
        value: function formatRangeToParts(
          start: number,
          end: number,
        ): Array<{type: string; value: string; source: string}> {
          if (start === undefined || end === undefined) {
            throw new TypeError('formatRangeToParts requires two numbers');
          }
          const startStr = this.format(Number(start));
          const endStr = this.format(Number(end));
          if (startStr === endStr) {
            return [{ type: 'literal', value: startStr, source: 'shared' }];
          }
          return [
            { type: 'literal', value: startStr, source: 'startRange' },
            { type: 'literal', value: '\u2013', source: 'shared' },
            { type: 'literal', value: endStr, source: 'endRange' },
          ];
        },
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }
  }

  // --------------------------------------------------------------------------
  // Intl.PluralRules
  // Provides CLDR plural rules for the top 14+ locales.
  // Supports "cardinal" and "ordinal" types.
  // --------------------------------------------------------------------------
  if (typeof Intl.PluralRules !== 'function') {
    /**
     * CLDR plural rule functions per locale.
     * Each function receives the absolute number and the type ('cardinal' | 'ordinal').
     * Returns the plural category: 'zero' | 'one' | 'two' | 'few' | 'many' | 'other'.
     *
     * Sources: https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html
     */
    const pluralRules: Record<string, (n: number, type: string) => string> = {
      // English: cardinal: 1 = one, else other; ordinal: 1st, 2nd, 3rd, Nth
      en: (n: number, type: string): string => {
        const i = Math.floor(Math.abs(n));
        if (type === 'ordinal') {
          const mod10 = i % 10;
          const mod100 = i % 100;
          if (mod10 === 1 && mod100 !== 11) return 'one';
          if (mod10 === 2 && mod100 !== 12) return 'two';
          if (mod10 === 3 && mod100 !== 13) return 'few';
          return 'other';
        }
        // CLDR operands are absolute-value based, so -1 is 'one' (not 'other').
        // Math.abs(n) === 1 keeps fractions like 1.5 as 'other'. (ENG-22984)
        if (i === 1 && Math.abs(n) === 1) return 'one';
        return 'other';
      },

      // French: cardinal: 0 and 1 are "one", else "other"; ordinal: 1 is "one", else "other"
      fr: (n: number, type: string): string => {
        const i = Math.floor(Math.abs(n));
        if (type === 'ordinal') {
          return i === 1 ? 'one' : 'other';
        }
        return (i === 0 || i === 1) ? 'one' : 'other';
      },

      // German: same as English cardinal (1 = one, else other); ordinal all "other"
      de: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        // CLDR operands are absolute-value based, so -1 is 'one' (not 'other').
        // Math.abs(n) === 1 keeps fractions like 1.5 as 'other'. (ENG-22984)
        if (i === 1 && Math.abs(n) === 1) return 'one';
        return 'other';
      },

      // Spanish: 1 = one, many for large even, else other (simplified: 1 = one, else other)
      es: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        // Absolute-value operand: -1 is 'one', 1.5 stays 'other'. (ENG-22984)
        return Math.abs(n) === 1 ? 'one' : 'other';
      },

      // Portuguese: cardinal: 0 and 1 are "one" (Brazilian), else "other"
      // (European Portuguese: only 1, but we use Brazilian as more common)
      pt: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        return (i === 0 || i === 1) ? 'one' : 'other';
      },

      // Italian: cardinal: 1 = "one", else "other"; ordinal: 8, 11, 80, 800 = "many", else "other"
      it: (n: number, type: string): string => {
        const i = Math.floor(Math.abs(n));
        if (type === 'ordinal') {
          if (i === 8 || i === 11 || i === 80 || i === 800) return 'many';
          return 'other';
        }
        // CLDR operands are absolute-value based, so -1 is 'one' (not 'other').
        // Math.abs(n) === 1 keeps fractions like 1.5 as 'other'. (ENG-22984)
        if (i === 1 && Math.abs(n) === 1) return 'one';
        return 'other';
      },

      // Russian: complex plural rules
      // cardinal: n%10=1 && n%100!=11 -> one; n%10 in 2..4 && n%100 not in 12..14 -> few;
      //           n%10=0 || n%10 in 5..9 || n%100 in 11..14 -> many; else other
      // ordinal: all other
      ru: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        // CLDR: every ru cardinal category other than 'other' requires v = 0
        // (no visible fraction digits), so 1.5 is 'other', not 'one'. Extends
        // ENG-22984's fractional fix (en/de/...) to the ru/pl rule set. (ENG-23140)
        if (Math.abs(n) !== i) return 'other';
        const mod10 = i % 10;
        const mod100 = i % 100;
        if (mod10 === 1 && mod100 !== 11) return 'one';
        if (mod10 >= 2 && mod10 <= 4 && !(mod100 >= 12 && mod100 <= 14)) return 'few';
        if (mod10 === 0 || (mod10 >= 5 && mod10 <= 9) || (mod100 >= 11 && mod100 <= 14)) return 'many';
        return 'other';
      },

      // Polish: complex plural rules
      // cardinal: 1 -> one; n%10 in 2..4 && n%100 not in 12..14 -> few; else many/other
      // ordinal: all other
      pl: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        // CLDR: pl cardinal one/few/many all require v = 0; fractions are
        // 'other' (1.5 must not be 'one'). (ENG-23140)
        if (Math.abs(n) !== i) return 'other';
        if (i === 1) return 'one';
        const mod10 = i % 10;
        const mod100 = i % 100;
        if (mod10 >= 2 && mod10 <= 4 && !(mod100 >= 12 && mod100 <= 14)) return 'few';
        if ((mod10 === 0 || mod10 === 1) || (mod10 >= 5 && mod10 <= 9) || (mod100 >= 12 && mod100 <= 14)) return 'many';
        return 'other';
      },

      // Arabic: most complex, 6 categories
      // 0 -> zero, 1 -> one, 2 -> two, n%100 in 3..10 -> few, n%100 in 11..99 -> many, else other
      ar: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        // CLDR: ar cardinal rules match on the operand n itself and its ranges
        // only contain integers, so any fractional value (1.5, 3.2, 11.5) is
        // 'other' rather than borrowing the truncated integer's category. (ENG-23140)
        if (Math.abs(n) !== i) return 'other';
        if (i === 0) return 'zero';
        if (i === 1) return 'one';
        if (i === 2) return 'two';
        const mod100 = i % 100;
        if (mod100 >= 3 && mod100 <= 10) return 'few';
        if (mod100 >= 11 && mod100 <= 99) return 'many';
        return 'other';
      },

      // Japanese: no plural distinctions, always "other"
      ja: (_n: number, _type: string): string => 'other',

      // Korean: no plural distinctions, always "other"
      ko: (_n: number, _type: string): string => 'other',

      // Chinese: no plural distinctions, always "other"
      zh: (_n: number, _type: string): string => 'other',

      // Turkish: cardinal: 1 = "one", else "other"; ordinal: all other
      tr: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        // Absolute-value operand: -1 is 'one', 1.5 stays 'other'. (ENG-22984)
        return Math.abs(n) === 1 ? 'one' : 'other';
      },

      // Dutch: same as English cardinal (1 = one, else other); ordinal all other
      nl: (n: number, type: string): string => {
        if (type === 'ordinal') return 'other';
        const i = Math.floor(Math.abs(n));
        // CLDR operands are absolute-value based, so -1 is 'one' (not 'other').
        // Math.abs(n) === 1 keeps fractions like 1.5 as 'other'. (ENG-22984)
        if (i === 1 && Math.abs(n) === 1) return 'one';
        return 'other';
      },

      // Swedish: same as English cardinal (1 = one, else other); ordinal: 1,2 = "one", else "other"
      sv: (n: number, type: string): string => {
        const i = Math.floor(Math.abs(n));
        if (type === 'ordinal') {
          const mod10 = i % 10;
          const mod100 = i % 100;
          if ((mod10 === 1 || mod10 === 2) && mod100 !== 11 && mod100 !== 12) return 'one';
          return 'other';
        }
        // CLDR operands are absolute-value based, so -1 is 'one' (not 'other').
        // Math.abs(n) === 1 keeps fractions like 1.5 as 'other'. (ENG-22984)
        if (i === 1 && Math.abs(n) === 1) return 'one';
        return 'other';
      },
    };

    // Map of locale -> plural categories that this locale uses
    const pluralCategories: Record<string, Record<string, string[]>> = {
      en: { cardinal: ['one', 'other'], ordinal: ['one', 'two', 'few', 'other'] },
      fr: { cardinal: ['one', 'other'], ordinal: ['one', 'other'] },
      de: { cardinal: ['one', 'other'], ordinal: ['other'] },
      es: { cardinal: ['one', 'other'], ordinal: ['other'] },
      pt: { cardinal: ['one', 'other'], ordinal: ['other'] },
      it: { cardinal: ['one', 'other'], ordinal: ['many', 'other'] },
      ru: { cardinal: ['one', 'few', 'many', 'other'], ordinal: ['other'] },
      pl: { cardinal: ['one', 'few', 'many', 'other'], ordinal: ['other'] },
      ar: { cardinal: ['zero', 'one', 'two', 'few', 'many', 'other'], ordinal: ['other'] },
      ja: { cardinal: ['other'], ordinal: ['other'] },
      ko: { cardinal: ['other'], ordinal: ['other'] },
      zh: { cardinal: ['other'], ordinal: ['other'] },
      tr: { cardinal: ['one', 'other'], ordinal: ['other'] },
      nl: { cardinal: ['one', 'other'], ordinal: ['other'] },
      sv: { cardinal: ['one', 'other'], ordinal: ['one', 'other'] },
    };

    /**
     * Resolve the plural rule function for a given locale.
     * Falls back to the language subtag, then to English.
     */
    function getPluralRule(locale: string): (n: number, type: string) => string {
      const key = locale.toLowerCase();
      if (pluralRules[key]) return pluralRules[key];
      const lang = key.split('-')[0];
      if (pluralRules[lang]) return pluralRules[lang];
      return pluralRules.en;
    }

    function getPluralCategories(locale: string, type: string): string[] {
      const key = locale.toLowerCase();
      const lang = key.split('-')[0];
      const catMap = pluralCategories[key] || pluralCategories[lang] || pluralCategories.en;
      return catMap[type] || catMap.cardinal || ['one', 'other'];
    }

    class PluralRulesPolyfill {
      private _locale: string;
      private _type: string;
      private _minimumIntegerDigits: number;
      private _minimumFractionDigits: number;
      private _maximumFractionDigits: number;
      private _rule: (n: number, type: string) => string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._type = opts.type || 'cardinal';
        this._minimumIntegerDigits = opts.minimumIntegerDigits || 1;
        this._minimumFractionDigits = opts.minimumFractionDigits || 0;
        this._maximumFractionDigits = opts.maximumFractionDigits || 3;
        this._rule = getPluralRule(this._locale);
      }

      select(n: number): string {
        return this._rule(Number(n), this._type);
      }

      selectRange(start: number, end: number): string {
        // Per spec, returns the plural category appropriate for a range.
        // Most languages use the category of the end value for ranges.
        return this._rule(Number(end), this._type);
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          type: this._type,
          minimumIntegerDigits: this._minimumIntegerDigits,
          minimumFractionDigits: this._minimumFractionDigits,
          maximumFractionDigits: this._maximumFractionDigits,
          pluralCategories: getPluralCategories(this._locale, this._type),
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        // We support all locales (with English fallback)
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    Object.defineProperty(Intl, 'PluralRules', {
      value: PluralRulesPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.ListFormat
  // Formats lists of items (e.g., "A, B, and C" or "A, B, or C").
  // --------------------------------------------------------------------------
  if (typeof Intl.ListFormat !== 'function') {
    class ListFormatPolyfill {
      private _locale: string;
      private _type: string;
      private _style: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._type = opts.type || 'conjunction'; // conjunction, disjunction, unit
        this._style = opts.style || 'long'; // long, short, narrow
      }

      format(list: Iterable<string>): string {
        const items = Array.from(list);
        if (items.length === 0) return '';
        if (items.length === 1) return String(items[0]);

        const conjunction = this._type === 'disjunction' ? 'or' : 'and';

        if (this._type === 'unit') {
          // Unit type uses different separators based on style
          if (this._style === 'narrow') {
            return items.join(' ');
          }
          return items.join(', ');
        }

        if (items.length === 2) {
          if (this._style === 'narrow') {
            return `${items[0]}, ${items[1]}`;
          }
          return `${items[0]} ${conjunction} ${items[1]}`;
        }

        // 3+ items
        const last = items[items.length - 1];
        const rest = items.slice(0, -1);
        if (this._style === 'narrow') {
          return `${rest.join(', ')}, ${last}`;
        }
        return `${rest.join(', ')}, ${conjunction} ${last}`;
      }

      formatToParts(list: Iterable<string>): Array<{type: string; value: string}> {
        const items = Array.from(list);
        if (items.length === 0) return [];
        if (items.length === 1) {
          return [{ type: 'element', value: String(items[0]) }];
        }

        const conjunction = this._type === 'disjunction' ? 'or' : 'and';
        const parts: Array<{type: string; value: string}> = [];

        for (let i = 0; i < items.length; i++) {
          if (i > 0) {
            if (i === items.length - 1) {
              if (this._type === 'unit') {
                parts.push({ type: 'literal', value: this._style === 'narrow' ? ' ' : ', ' });
              } else if (this._style === 'narrow') {
                parts.push({ type: 'literal', value: ', ' });
              } else if (items.length === 2) {
                parts.push({ type: 'literal', value: ` ${conjunction} ` });
              } else {
                parts.push({ type: 'literal', value: `, ${conjunction} ` });
              }
            } else {
              parts.push({ type: 'literal', value: ', ' });
            }
          }
          parts.push({ type: 'element', value: String(items[i]) });
        }

        return parts;
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          type: this._type,
          style: this._style,
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    Object.defineProperty(Intl, 'ListFormat', {
      value: ListFormatPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.RelativeTimeFormat
  // Formats relative time strings (e.g., "3 days ago", "in 2 hours").
  // --------------------------------------------------------------------------
  if (typeof Intl.RelativeTimeFormat !== 'function') {
    // Unit names for long/short/narrow styles
    const UNITS_LONG: Record<string, [string, string]> = {
      year: ['year', 'years'],
      quarter: ['quarter', 'quarters'],
      month: ['month', 'months'],
      week: ['week', 'weeks'],
      day: ['day', 'days'],
      hour: ['hour', 'hours'],
      minute: ['minute', 'minutes'],
      second: ['second', 'seconds'],
    };
    const UNITS_SHORT: Record<string, string> = {
      year: 'yr.',
      quarter: 'qtr.',
      month: 'mo.',
      week: 'wk.',
      day: 'day',
      hour: 'hr.',
      minute: 'min.',
      second: 'sec.',
    };
    const UNITS_NARROW: Record<string, string> = {
      year: 'y',
      quarter: 'q',
      month: 'm',
      week: 'w',
      day: 'd',
      hour: 'h',
      minute: 'm',
      second: 's',
    };

    const VALID_UNITS = new Set([
      'year', 'years',
      'quarter', 'quarters',
      'month', 'months',
      'week', 'weeks',
      'day', 'days',
      'hour', 'hours',
      'minute', 'minutes',
      'second', 'seconds',
    ]);

    function normalizeUnit(unit: string): string {
      if (!VALID_UNITS.has(unit)) {
        throw new RangeError(`Invalid unit argument for RelativeTimeFormat: ${unit}`);
      }
      // Remove trailing 's' for plural form
      return unit.replace(/s$/, '');
    }

    class RelativeTimeFormatPolyfill {
      private _locale: string;
      private _style: string;
      private _numeric: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._style = opts.style || 'long';
        this._numeric = opts.numeric || 'always';
      }

      format(value: number, unit: string): string {
        const normalizedUnit = normalizeUnit(unit);
        const n = Number(value);

        // "auto" numeric: use special words for -1, 0, 1
        if (this._numeric === 'auto') {
          if (normalizedUnit === 'day') {
            if (n === -1) return 'yesterday';
            if (n === 0) return 'today';
            if (n === 1) return 'tomorrow';
          }
          if (n === 0) return `this ${normalizedUnit}`;
          if (n === -1) return `last ${normalizedUnit}`;
          if (n === 1) return `next ${normalizedUnit}`;
        }

        const abs = Math.abs(n);
        let unitStr: string;

        if (this._style === 'narrow') {
          unitStr = UNITS_NARROW[normalizedUnit] || normalizedUnit;
          if (n < 0) return `${abs}${unitStr} ago`;
          return `in ${abs}${unitStr}`;
        }

        if (this._style === 'short') {
          unitStr = UNITS_SHORT[normalizedUnit] || normalizedUnit;
        } else {
          // long
          const names = UNITS_LONG[normalizedUnit];
          unitStr = names ? (abs === 1 ? names[0] : names[1]) : normalizedUnit;
        }

        if (n < 0) return `${abs} ${unitStr} ago`;
        return `in ${abs} ${unitStr}`;
      }

      formatToParts(value: number, unit: string): Array<{type: string; value: string; unit?: string}> {
        const formatted = this.format(value, unit);
        const normalizedUnit = normalizeUnit(unit);
        const n = Number(value);

        // Simple implementation: return as literal + integer parts
        if (n < 0) {
          const abs = Math.abs(n);
          return [
            { type: 'integer', value: String(abs), unit: normalizedUnit },
            { type: 'literal', value: ' ' },
            { type: 'literal', value: formatted.replace(/^\d+\s*/, '').replace(/^\s+/, '') },
          ];
        }
        return [{ type: 'literal', value: formatted }];
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          style: this._style,
          numeric: this._numeric,
          numberingSystem: 'latn',
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    Object.defineProperty(Intl, 'RelativeTimeFormat', {
      value: RelativeTimeFormatPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.Segmenter
  // Lightweight grapheme/word/sentence segmenter.
  // Handles surrogate pairs, ZWJ sequences, regional indicators, variation
  // selectors, and combining marks for proper emoji segmentation.
  // --------------------------------------------------------------------------
  if (typeof Intl.Segmenter !== 'function') {
    const WORD_REGEX = /[^\s]+|\s+/g;
    const SENTENCE_REGEX = /[^.!?]+[.!?]+\s*|[^.!?]+$/g;

    // Unicode constants for grapheme segmentation
    const ZWJ = 0x200D;
    const VS15 = 0xFE0E;       // text variation selector
    const VS16 = 0xFE0F;       // emoji variation selector
    const RI_START = 0x1F1E6;   // Regional Indicator A
    const RI_END = 0x1F1FF;     // Regional Indicator Z
    const SKIN_TONE_START = 0x1F3FB;
    const SKIN_TONE_END = 0x1F3FF;
    // Enclosing keycap
    const KEYCAP = 0x20E3;
    // Tags block
    const TAG_START = 0xE0020;
    const TAG_END = 0xE007E;
    const CANCEL_TAG = 0xE007F;

    /**
     * Get the code point at position i in the string.
     * Returns [codePoint, charCount] where charCount is 1 for BMP, 2 for surrogate pairs.
     */
    function codePointAt(str: string, i: number): [number, number] {
      const code = str.charCodeAt(i);
      if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
        const next = str.charCodeAt(i + 1);
        if (next >= 0xDC00 && next <= 0xDFFF) {
          const cp = ((code - 0xD800) << 10) + (next - 0xDC00) + 0x10000;
          return [cp, 2];
        }
      }
      return [code, 1];
    }

    /**
     * Check if a code point is a regional indicator symbol.
     */
    function isRegionalIndicator(cp: number): boolean {
      return cp >= RI_START && cp <= RI_END;
    }

    /**
     * Check if a code point is a combining mark (Unicode categories Mn, Mc, Me).
     * This is a simplified check covering the most common ranges.
     */
    function isCombiningMark(cp: number): boolean {
      // Combining Diacritical Marks (0300-036F)
      if (cp >= 0x0300 && cp <= 0x036F) return true;
      // Combining Diacritical Marks Extended (1AB0-1AFF)
      if (cp >= 0x1AB0 && cp <= 0x1AFF) return true;
      // Combining Diacritical Marks Supplement (1DC0-1DFF)
      if (cp >= 0x1DC0 && cp <= 0x1DFF) return true;
      // Combining Diacritical Marks for Symbols (20D0-20FF)
      if (cp >= 0x20D0 && cp <= 0x20FF) return true;
      // Combining Half Marks (FE20-FE2F)
      if (cp >= 0xFE20 && cp <= 0xFE2F) return true;
      // Cyrillic combining marks (0483-0489)
      if (cp >= 0x0483 && cp <= 0x0489) return true;
      // Hebrew combining marks (0591-05BD, 05BF, 05C1-05C2, 05C4-05C5, 05C7)
      if (cp >= 0x0591 && cp <= 0x05BD) return true;
      if (cp === 0x05BF || cp === 0x05C1 || cp === 0x05C2 || cp === 0x05C4 || cp === 0x05C5 || cp === 0x05C7) return true;
      // Arabic combining marks (0610-061A, 064B-065F, 0670, 06D6-06DC, 06DF-06E4, 06E7-06E8, 06EA-06ED)
      if (cp >= 0x0610 && cp <= 0x061A) return true;
      if (cp >= 0x064B && cp <= 0x065F) return true;
      if (cp === 0x0670) return true;
      if (cp >= 0x06D6 && cp <= 0x06DC) return true;
      if (cp >= 0x06DF && cp <= 0x06E4) return true;
      if (cp >= 0x06E7 && cp <= 0x06E8) return true;
      if (cp >= 0x06EA && cp <= 0x06ED) return true;
      // Devanagari, Bengali, etc. combining marks (0900-0903, 093A-094F, 0951-0957, 0962-0963)
      if (cp >= 0x0900 && cp <= 0x0903) return true;
      if (cp >= 0x093A && cp <= 0x094F) return true;
      if (cp >= 0x0951 && cp <= 0x0957) return true;
      if (cp >= 0x0962 && cp <= 0x0963) return true;
      return false;
    }

    /**
     * Check if a code point is a skin tone modifier.
     */
    function isSkinToneModifier(cp: number): boolean {
      return cp >= SKIN_TONE_START && cp <= SKIN_TONE_END;
    }

    /**
     * Check if a code point is a variation selector (VS1-VS16 or VS17-VS256).
     */
    function isVariationSelector(cp: number): boolean {
      // VS1-VS16 (FE00-FE0F)
      if (cp >= 0xFE00 && cp <= 0xFE0F) return true;
      // VS17-VS256 (E0100-E01EF)
      if (cp >= 0xE0100 && cp <= 0xE01EF) return true;
      return false;
    }

    /**
     * Check if a code point is a tag character.
     */
    function isTagCharacter(cp: number): boolean {
      return (cp >= TAG_START && cp <= TAG_END) || cp === CANCEL_TAG;
    }

    /**
     * Check if a code point is an emoji presentation character.
     * Simplified check covering common emoji ranges.
     */
    function isEmojiLike(cp: number): boolean {
      // Common emoji ranges
      if (cp >= 0x1F600 && cp <= 0x1F64F) return true; // Emoticons
      if (cp >= 0x1F300 && cp <= 0x1F5FF) return true; // Misc Symbols and Pictographs
      if (cp >= 0x1F680 && cp <= 0x1F6FF) return true; // Transport and Map
      if (cp >= 0x1F700 && cp <= 0x1F77F) return true; // Alchemical Symbols
      if (cp >= 0x1F780 && cp <= 0x1F7FF) return true; // Geometric Shapes Extended
      if (cp >= 0x1F800 && cp <= 0x1F8FF) return true; // Supplemental Arrows-C
      if (cp >= 0x1F900 && cp <= 0x1F9FF) return true; // Supplemental Symbols and Pictographs
      if (cp >= 0x1FA00 && cp <= 0x1FA6F) return true; // Chess Symbols
      if (cp >= 0x1FA70 && cp <= 0x1FAFF) return true; // Symbols and Pictographs Extended-A
      if (cp >= 0x2600 && cp <= 0x26FF) return true;   // Misc symbols
      if (cp >= 0x2700 && cp <= 0x27BF) return true;   // Dingbats
      if (cp >= 0x231A && cp <= 0x23FF) return true;   // Misc technical (includes clock faces)
      if (cp >= 0xFE00 && cp <= 0xFE0F) return true;   // Variation selectors
      if (cp === 0x200D) return true;                    // ZWJ
      if (cp >= 0x2702 && cp <= 0x27B0) return true;   // Dingbats
      if (cp === 0x2764) return true;                    // Heavy heart
      if (cp === 0x2049 || cp === 0x203C) return true;  // Exclamation marks
      return false;
    }

    class SegmenterPolyfill {
      private _locale: string;
      private _granularity: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._granularity = opts.granularity || 'grapheme';
        if (!['grapheme', 'word', 'sentence'].includes(this._granularity)) {
          throw new RangeError(`Invalid granularity: ${this._granularity}`);
        }
      }

      segment(input: string): SegmentsPolyfill {
        return new SegmentsPolyfill(String(input), this._granularity);
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          granularity: this._granularity,
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    class SegmentsPolyfill {
      private _input: string;
      private _granularity: string;
      // Segmenting the whole input is O(n); cache it so repeated containing()/
      // iteration don't re-segment. The input is immutable, so the cache is
      // always valid once computed. (ENG-22984)
      private _segments: Array<{segment: string; index: number; input: string; isWordLike?: boolean}> | null;

      constructor(input: string, granularity: string) {
        this._input = input;
        this._granularity = granularity;
        this._segments = null;
      }

      containing(index: number): {segment: string; index: number; input: string; isWordLike?: boolean} | undefined {
        if (index < 0 || index >= this._input.length) return undefined;
        const segments = this._getSegments();
        // Segments partition the input and are sorted by ascending index, so a
        // binary search locates the containing segment in O(log n) instead of
        // scanning every segment. The cursor-movement pattern (containing(i) for
        // each index) is thus O(n log n) overall, not O(n^2). (ENG-22984)
        let lo = 0;
        let hi = segments.length - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >>> 1;
          const seg = segments[mid];
          if (index < seg.index) {
            hi = mid - 1;
          } else if (index >= seg.index + seg.segment.length) {
            lo = mid + 1;
          } else {
            return seg;
          }
        }
        return undefined;
      }

      [Symbol.iterator](): Iterator<{segment: string; index: number; input: string; isWordLike?: boolean}> {
        const segments = this._getSegments();
        let i = 0;
        return {
          next(): IteratorResult<{segment: string; index: number; input: string; isWordLike?: boolean}> {
            if (i >= segments.length) return { value: undefined, done: true };
            return { value: segments[i++], done: false };
          },
        };
      }

      private _getSegments(): Array<{segment: string; index: number; input: string; isWordLike?: boolean}> {
        if (this._segments === null) {
          this._segments = this._computeSegments();
        }
        return this._segments;
      }

      private _computeSegments(): Array<{segment: string; index: number; input: string; isWordLike?: boolean}> {
        const input = this._input;
        const results: Array<{segment: string; index: number; input: string; isWordLike?: boolean}> = [];

        if (this._granularity === 'grapheme') {
          // Extended grapheme cluster segmentation
          // Handles: surrogate pairs, ZWJ sequences, regional indicators (flags),
          // variation selectors, skin tone modifiers, combining marks, tag sequences
          let i = 0;
          while (i < input.length) {
            const startIdx = i;
            const [cp, cpLen] = codePointAt(input, i);
            i += cpLen;

            // Check if this is a regional indicator (flag emoji)
            if (isRegionalIndicator(cp)) {
              // Flags are pairs of regional indicators
              if (i < input.length) {
                const [nextCp, nextLen] = codePointAt(input, i);
                if (isRegionalIndicator(nextCp)) {
                  i += nextLen;
                }
              }
              // After the flag, absorb any variation selectors
              while (i < input.length) {
                const [nextCp, nextLen] = codePointAt(input, i);
                if (isVariationSelector(nextCp)) {
                  i += nextLen;
                } else {
                  break;
                }
              }
              results.push({ segment: input.substring(startIdx, i), index: startIdx, input });
              continue;
            }

            // Absorb combining marks, variation selectors, skin tone modifiers
            while (i < input.length) {
              const [nextCp, nextLen] = codePointAt(input, i);

              // Combining marks
              if (isCombiningMark(nextCp)) {
                i += nextLen;
                continue;
              }

              // Variation selectors (FE0E text, FE0F emoji)
              if (isVariationSelector(nextCp)) {
                i += nextLen;
                continue;
              }

              // Skin tone modifiers
              if (isSkinToneModifier(nextCp)) {
                i += nextLen;
                continue;
              }

              // Enclosing keycap
              if (nextCp === KEYCAP) {
                i += nextLen;
                continue;
              }

              // Tag characters (for flag tag sequences like England flag)
              if (isTagCharacter(nextCp)) {
                i += nextLen;
                // Continue absorbing tags until cancel tag or non-tag
                while (i < input.length) {
                  const [tagCp, tagLen] = codePointAt(input, i);
                  if (isTagCharacter(tagCp)) {
                    i += tagLen;
                    if (tagCp === CANCEL_TAG) break;
                  } else {
                    break;
                  }
                }
                continue;
              }

              // ZWJ: merge with the next character/sequence
              if (nextCp === ZWJ) {
                i += nextLen;
                // Consume the next code point after ZWJ
                if (i < input.length) {
                  const [joinedCp, joinedLen] = codePointAt(input, i);
                  i += joinedLen;
                  // Continue the loop to absorb more modifiers/ZWJ after the joined char
                }
                continue;
              }

              break;
            }

            // Handle \r\n as a single grapheme
            if (cp === 0x0D && i < input.length && input.charCodeAt(i) === 0x0A) {
              // \r was consumed, \n follows
              // Actually, \r is at startIdx, need to re-check
            }

            results.push({ segment: input.substring(startIdx, i), index: startIdx, input });
          }
        } else if (this._granularity === 'word') {
          let match: RegExpExecArray | null;
          const regex = new RegExp(WORD_REGEX.source, 'g');
          while ((match = regex.exec(input)) !== null) {
            const segment = match[0];
            const isWordLike = !/^\s+$/.test(segment);
            results.push({ segment, index: match.index, input, isWordLike });
          }
        } else if (this._granularity === 'sentence') {
          if (input.length === 0) return results;
          let match: RegExpExecArray | null;
          const regex = new RegExp(SENTENCE_REGEX.source, 'g');
          while ((match = regex.exec(input)) !== null) {
            results.push({ segment: match[0], index: match.index, input });
          }
          // If regex didn't match anything (no sentence-ending punctuation), treat whole string as one sentence
          if (results.length === 0) {
            results.push({ segment: input, index: 0, input });
          }
        }

        return results;
      }
    }

    Object.defineProperty(Intl, 'Segmenter', {
      value: SegmenterPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.DisplayNames
  // Provides display names for languages, regions, scripts, currencies.
  // Lightweight stub with a small set of common English names.
  // --------------------------------------------------------------------------
  if (typeof Intl.DisplayNames !== 'function') {
    const LANGUAGE_NAMES: Record<string, string> = {
      en: 'English', es: 'Spanish', fr: 'French', de: 'German', it: 'Italian',
      pt: 'Portuguese', ja: 'Japanese', ko: 'Korean', zh: 'Chinese',
      ar: 'Arabic', hi: 'Hindi', ru: 'Russian', nl: 'Dutch', sv: 'Swedish',
      pl: 'Polish', tr: 'Turkish', th: 'Thai', vi: 'Vietnamese',
    };

    const REGION_NAMES: Record<string, string> = {
      US: 'United States', GB: 'United Kingdom', CA: 'Canada', AU: 'Australia',
      DE: 'Germany', FR: 'France', JP: 'Japan', CN: 'China', IN: 'India',
      BR: 'Brazil', MX: 'Mexico', ES: 'Spain', IT: 'Italy', KR: 'South Korea',
      RU: 'Russia', NL: 'Netherlands', SE: 'Sweden', NO: 'Norway', DK: 'Denmark',
    };

    const CURRENCY_NAMES: Record<string, string> = {
      USD: 'US Dollar', EUR: 'Euro', GBP: 'British Pound', JPY: 'Japanese Yen',
      CNY: 'Chinese Yuan', KRW: 'South Korean Won', INR: 'Indian Rupee',
      BRL: 'Brazilian Real', CAD: 'Canadian Dollar', AUD: 'Australian Dollar',
      CHF: 'Swiss Franc', MXN: 'Mexican Peso', SEK: 'Swedish Krona',
    };

    class DisplayNamesPolyfill {
      private _locale: string;
      private _type: string;
      private _style: string;
      private _fallback: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        if (!opts.type) {
          throw new TypeError('DisplayNames requires a "type" option');
        }
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._type = opts.type;
        this._style = opts.style || 'long';
        this._fallback = opts.fallback || 'code';

        if (!['language', 'region', 'script', 'currency', 'calendar', 'dateTimeField'].includes(this._type)) {
          throw new RangeError(`Invalid type: ${this._type}`);
        }
      }

      of(code: string): string | undefined {
        if (typeof code !== 'string' || code.length === 0) {
          throw new RangeError('Invalid code for DisplayNames');
        }

        let result: string | undefined;

        switch (this._type) {
          case 'language':
            result = LANGUAGE_NAMES[code.toLowerCase()] || LANGUAGE_NAMES[code.split('-')[0].toLowerCase()];
            break;
          case 'region':
            result = REGION_NAMES[code.toUpperCase()];
            break;
          case 'currency':
            result = CURRENCY_NAMES[code.toUpperCase()];
            break;
          default:
            result = undefined;
        }

        if (result === undefined) {
          if (this._fallback === 'code') return code;
          return undefined;
        }

        return result;
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          type: this._type,
          style: this._style,
          fallback: this._fallback,
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    Object.defineProperty(Intl, 'DisplayNames', {
      value: DisplayNamesPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.Collator
  // Fallback using String.prototype.localeCompare.
  // --------------------------------------------------------------------------
  if (typeof Intl.Collator !== 'function') {
    class CollatorPolyfill {
      private _locale: string;
      private _usage: string;
      private _sensitivity: string;
      private _ignorePunctuation: boolean;
      private _numeric: boolean;
      private _caseFirst: string;
      private _collation: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._usage = opts.usage || 'sort';
        this._sensitivity = opts.sensitivity || 'variant';
        this._ignorePunctuation = opts.ignorePunctuation || false;
        this._numeric = opts.numeric || false;
        this._caseFirst = opts.caseFirst || 'false';
        this._collation = opts.collation || 'default';
        // Per spec, Intl.Collator#compare is an accessor returning a function
        // bound to the collator, precisely so `arr.sort(collator.compare)`
        // works. As a detached plain method `this` was undefined, the internal
        // throw was swallowed by the catch below, and the sort silently fell
        // back to option-less localeCompare (numeric/sensitivity/caseFirst all
        // dropped). (ENG-23140)
        this.compare = this.compare.bind(this);
      }

      compare(a: string, b: string): number {
        try {
          return String(a).localeCompare(String(b), this._locale, {
            sensitivity: this._sensitivity as any,
            ignorePunctuation: this._ignorePunctuation,
            numeric: this._numeric,
            caseFirst: this._caseFirst as any,
          });
        } catch (_e) {
          // If localeCompare doesn't support options, fall back to basic comparison
          return String(a).localeCompare(String(b));
        }
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          usage: this._usage,
          sensitivity: this._sensitivity,
          ignorePunctuation: this._ignorePunctuation,
          numeric: this._numeric,
          caseFirst: this._caseFirst,
          collation: this._collation,
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }
    }

    Object.defineProperty(Intl, 'Collator', {
      value: CollatorPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Intl.DurationFormat
  // Formats durations (e.g., "1 hour, 2 minutes, 3 seconds" or "1:02:03").
  // Supports styles: long, short, narrow, digital.
  // --------------------------------------------------------------------------
  if (typeof Intl.DurationFormat !== 'function') {
    // Duration field definitions in display order
    const DURATION_FIELDS: Array<{
      field: string;
      long: [string, string];
      short: string;
      narrow: string;
    }> = [
      { field: 'years',        long: ['year', 'years'],       short: 'yr',  narrow: 'y' },
      { field: 'months',       long: ['month', 'months'],     short: 'mo',  narrow: 'mo' },
      { field: 'weeks',        long: ['week', 'weeks'],       short: 'wk',  narrow: 'w' },
      { field: 'days',         long: ['day', 'days'],         short: 'day', narrow: 'd' },
      { field: 'hours',        long: ['hour', 'hours'],       short: 'hr',  narrow: 'h' },
      { field: 'minutes',      long: ['minute', 'minutes'],   short: 'min', narrow: 'm' },
      { field: 'seconds',      long: ['second', 'seconds'],   short: 'sec', narrow: 's' },
      { field: 'milliseconds', long: ['millisecond', 'milliseconds'], short: 'ms', narrow: 'ms' },
      { field: 'microseconds', long: ['microsecond', 'microseconds'], short: '\u00B5s', narrow: '\u00B5s' },
      { field: 'nanoseconds',  long: ['nanosecond', 'nanoseconds'],   short: 'ns', narrow: 'ns' },
    ];

    // Fields that belong to the time portion (used for digital style)
    const TIME_FIELDS = new Set(['hours', 'minutes', 'seconds']);
    const SUB_SECOND_FIELDS = new Set(['milliseconds', 'microseconds', 'nanoseconds']);

    class DurationFormatPolyfill {
      _locale: string;
      _style: string;

      constructor(locales?: string | string[], options?: any) {
        const opts = options || {};
        this._locale = Array.isArray(locales) ? (locales[0] || 'en') : (locales || 'en');
        this._style = opts.style || 'short';
        if (!['long', 'short', 'narrow', 'digital'].includes(this._style)) {
          throw new RangeError(`Invalid style: ${this._style}`);
        }
      }

      format(duration: any): string {
        if (duration === null || duration === undefined || typeof duration !== 'object') {
          throw new TypeError('Duration must be an object');
        }
        const parts = this._buildParts(duration);
        return parts.map((p: any) => p.value).join('');
      }

      formatToParts(duration: any): Array<{type: string; value: string}> {
        if (duration === null || duration === undefined || typeof duration !== 'object') {
          throw new TypeError('Duration must be an object');
        }
        return this._buildParts(duration);
      }

      resolvedOptions(): any {
        return {
          locale: this._locale,
          style: this._style,
          numberingSystem: 'latn',
        };
      }

      static supportedLocalesOf(locales?: string | string[]): string[] {
        if (!locales) return [];
        const list = Array.isArray(locales) ? locales : [locales];
        return list.filter((l) => typeof l === 'string');
      }

      _buildParts(duration: any): Array<{type: string; value: string}> {
        if (this._style === 'digital') {
          return this._buildDigitalParts(duration);
        }
        return this._buildTextParts(duration);
      }

      /**
       * Build parts for text styles: long, short, narrow.
       */
      _buildTextParts(duration: any): Array<{type: string; value: string}> {
        const parts: Array<{type: string; value: string}> = [];
        const segments: Array<{type: string; value: number; formatted: string}> = [];

        for (const def of DURATION_FIELDS) {
          const val = Number(duration[def.field]) || 0;
          if (val === 0) continue;

          let unitStr: string;
          if (this._style === 'long') {
            unitStr = val === 1 ? def.long[0] : def.long[1];
          } else if (this._style === 'short') {
            unitStr = def.short;
          } else {
            // narrow
            unitStr = def.narrow;
          }

          let formatted: string;
          if (this._style === 'narrow') {
            formatted = `${val}${unitStr}`;
          } else {
            formatted = `${val} ${unitStr}`;
          }

          segments.push({ type: def.field, value: val, formatted });
        }

        for (let i = 0; i < segments.length; i++) {
          if (i > 0) {
            if (this._style === 'narrow') {
              parts.push({ type: 'literal', value: ' ' });
            } else {
              parts.push({ type: 'literal', value: ', ' });
            }
          }

          const seg = segments[i];
          // Emit the integer part
          parts.push({ type: 'integer', value: String(seg.value) });
          // Emit the unit part
          if (this._style === 'narrow') {
            parts.push({ type: 'unit', value: seg.formatted.substring(String(seg.value).length) });
          } else {
            parts.push({ type: 'literal', value: ' ' });
            parts.push({ type: 'unit', value: seg.formatted.split(' ').slice(1).join(' ') });
          }
        }

        return parts;
      }

      /**
       * Build parts for digital style: "1:02:03"
       * Date fields (years, months, weeks, days) are formatted as text (short).
       * Time fields (hours, minutes, seconds) are formatted as HH:MM:SS.
       * Sub-second fields are appended after seconds with a decimal point.
       */
      _buildDigitalParts(duration: any): Array<{type: string; value: string}> {
        const parts: Array<{type: string; value: string}> = [];

        // First, handle non-time fields (years, months, weeks, days) as short text
        const dateSegments: string[] = [];
        for (const def of DURATION_FIELDS) {
          if (TIME_FIELDS.has(def.field) || SUB_SECOND_FIELDS.has(def.field)) continue;
          const val = Number(duration[def.field]) || 0;
          if (val === 0) continue;
          dateSegments.push(`${val} ${def.short}`);
        }

        if (dateSegments.length > 0) {
          parts.push({ type: 'literal', value: dateSegments.join(', ') });
        }

        // Now handle time fields
        const hours = Number(duration.hours) || 0;
        const minutes = Number(duration.minutes) || 0;
        const seconds = Number(duration.seconds) || 0;
        const milliseconds = Number(duration.milliseconds) || 0;
        const microseconds = Number(duration.microseconds) || 0;
        const nanoseconds = Number(duration.nanoseconds) || 0;

        const hasTimePart = hours > 0 || minutes > 0 || seconds > 0 ||
          milliseconds > 0 || microseconds > 0 || nanoseconds > 0;

        if (!hasTimePart && parts.length > 0) {
          return parts;
        }

        if (!hasTimePart && parts.length === 0) {
          // No fields at all - return "0:00:00"
          parts.push({ type: 'integer', value: '0' });
          parts.push({ type: 'literal', value: ':' });
          parts.push({ type: 'integer', value: '00' });
          parts.push({ type: 'literal', value: ':' });
          parts.push({ type: 'integer', value: '00' });
          return parts;
        }

        if (dateSegments.length > 0) {
          parts.push({ type: 'literal', value: ', ' });
        }

        // Format time as H:MM:SS
        const pad2 = (n: number): string => n < 10 ? `0${n}` : String(n);

        parts.push({ type: 'integer', value: String(hours) });
        parts.push({ type: 'literal', value: ':' });
        parts.push({ type: 'integer', value: pad2(minutes) });
        parts.push({ type: 'literal', value: ':' });
        parts.push({ type: 'integer', value: pad2(seconds) });

        // Sub-second precision
        const hasSubSecond = milliseconds > 0 || microseconds > 0 || nanoseconds > 0;
        if (hasSubSecond) {
          // Convert to fractional seconds string
          const totalNanos = milliseconds * 1_000_000 + microseconds * 1_000 + nanoseconds;
          const fracStr = String(totalNanos).padStart(9, '0').replace(/0+$/, '');
          parts.push({ type: 'literal', value: '.' });
          parts.push({ type: 'fraction', value: fracStr });
        }

        return parts;
      }
    }

    Object.defineProperty(Intl, 'DurationFormat', {
      value: DurationFormatPolyfill,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
