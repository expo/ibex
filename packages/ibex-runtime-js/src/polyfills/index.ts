/**
 * ES2023+ Polyfills for Hermes Engine
 *
 * Installs all modern JavaScript polyfills that Hermes doesn't natively support.
 * Each polyfill checks for existing implementations before installing.
 *
 * Covers:
 * - Array: toSorted, toReversed, with, toSpliced, fromAsync
 * - Object/Map: groupBy
 * - Set: union, intersection, difference, symmetricDifference, isSubsetOf, isSupersetOf, isDisjointFrom
 * - Promise: withResolvers
 * - String: isWellFormed, toWellFormed
 * - ArrayBuffer: transfer, transferToFixedLength
 * - Iterator: map, filter, take, drop, flatMap, reduce, toArray, forEach, some, every, find, from
 * - Intl: PluralRules, ListFormat, RelativeTimeFormat, Segmenter, DisplayNames,
 *         DateTimeFormat.formatRange/formatToParts, NumberFormat.formatRange/formatToParts
 */

import { installArrayPolyfills } from './array';
import { installGroupByPolyfills } from './groupby';
import { installSetPolyfills } from './set';
import { installPromisePolyfills } from './promise';
import { installStringPolyfills } from './string';
import { installArrayBufferPolyfills } from './arraybuffer';
import { installTypedArrayPolyfills } from './typedarray';
import { installIteratorPolyfills } from './iterator';
import { installIntlPolyfills } from './intl';

/**
 * Install all ES2023+ polyfills.
 * Safe to call multiple times; each polyfill checks before installing.
 */
export function installPolyfills(): void {
  installArrayPolyfills();
  installGroupByPolyfills();
  installSetPolyfills();
  installPromisePolyfills();
  installStringPolyfills();
  installArrayBufferPolyfills();
  installTypedArrayPolyfills();
  installIteratorPolyfills();

  // Intl polyfills are deferred until first access to reduce startup cost.
  // Hermes provides an empty Intl object; we proxy it so that accessing
  // any Intl method (e.g., Intl.DateTimeFormat) triggers the full install.
  const g = globalThis as any;
  if (typeof g.Intl === 'object' && g.Intl !== null) {
    const realIntl = g.Intl;
    let installed = false;
    function ensureIntl() {
      if (installed) return;
      installed = true;
      // Restore the real Intl before installing so the polyfills
      // can detect what's already there.
      g.Intl = realIntl;
      installIntlPolyfills();
    }
    g.Intl = new Proxy(realIntl, {
      get(target: any, prop: string | symbol, receiver: any) {
        ensureIntl();
        return Reflect.get(g.Intl, prop, receiver);
      },
      has(target: any, prop: string | symbol) {
        ensureIntl();
        return Reflect.has(g.Intl, prop);
      },
    });
  } else {
    // No Intl object at all — install eagerly
    installIntlPolyfills();
  }
}

// Re-export individual installers for selective use
export {
  installArrayPolyfills,
  installGroupByPolyfills,
  installSetPolyfills,
  installPromisePolyfills,
  installStringPolyfills,
  installArrayBufferPolyfills,
  installTypedArrayPolyfills,
  installIteratorPolyfills,
  installIntlPolyfills,
};
