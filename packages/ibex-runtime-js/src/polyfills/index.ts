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

  // @ref LLP 0023#6-path-bearing-observables — install the finite authored
  // Intl surface directly. A Proxy over the host namespace would expose an
  // engine-dependent open member domain to packages.
  installIntlPolyfills();
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
