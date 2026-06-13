/**
 * Clipboard - Web Clipboard API implementation for Exact runtime
 *
 * Provides async read/write access to the system clipboard.
 * By default, stores data in memory. When native bridge functions
 * (__exactClipboardRead / __exactClipboardWrite) are available,
 * they are used for actual system clipboard access.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Clipboard
 * @see https://w3c.github.io/clipboard-apis/#clipboard-interface
 */

import { ClipboardItem } from './ClipboardItem';

/**
 * The Clipboard interface provides read and write access to the contents
 * of the system clipboard, allowing cut, copy, and paste operations in
 * web applications.
 *
 * This implementation falls back to in-memory storage when native clipboard
 * access is not available. Native bridge functions can be plugged in via:
 * - globalThis.__exactClipboardRead: () => string
 * - globalThis.__exactClipboardWrite: (text: string) => void
 */
export class Clipboard {
  /** In-memory fallback for clipboard text. */
  #text: string = '';

  /** In-memory fallback for clipboard items. */
  #items: ClipboardItem[] = [];

  /**
   * Read text from the clipboard.
   *
   * Uses the native bridge if available (__exactClipboardRead),
   * otherwise returns from in-memory storage.
   *
   * @returns A Promise resolving to the clipboard text content.
   */
  async readText(): Promise<string> {
    const g = globalThis as any;
    if (typeof g.__exactClipboardRead === 'function') {
      return String(g.__exactClipboardRead());
    }
    return this.#text;
  }

  /**
   * Write text to the clipboard.
   *
   * Uses the native bridge if available (__exactClipboardWrite),
   * otherwise stores in memory.
   *
   * @param text - The text to write to the clipboard.
   */
  async writeText(text: string): Promise<void> {
    const g = globalThis as any;
    if (typeof g.__exactClipboardWrite === 'function') {
      g.__exactClipboardWrite(String(text));
    }
    this.#text = String(text);
    // Also update the items to keep them in sync
    this.#items = [
      new ClipboardItem({ 'text/plain': text }),
    ];
  }

  /**
   * Read structured data from the clipboard as ClipboardItem[].
   *
   * For now, returns items from the in-memory store. If only text was
   * written, wraps it as a ClipboardItem with 'text/plain' type.
   *
   * @returns A Promise resolving to an array of ClipboardItems.
   */
  async read(): Promise<ClipboardItem[]> {
    // If native bridge is available, read text and wrap it
    const g = globalThis as any;
    if (typeof g.__exactClipboardRead === 'function') {
      const text = String(g.__exactClipboardRead());
      if (text) {
        return [new ClipboardItem({ 'text/plain': text })];
      }
      return [];
    }

    // Return a copy of the stored items
    return [...this.#items];
  }

  /**
   * Write structured data to the clipboard.
   *
   * Stores the items in memory. If any item contains 'text/plain',
   * also updates the text representation for readText() compatibility.
   *
   * @param items - An array of ClipboardItems to write.
   */
  async write(items: ClipboardItem[]): Promise<void> {
    if (!Array.isArray(items)) {
      throw new TypeError('Clipboard.write: argument must be an array of ClipboardItems');
    }

    this.#items = [...items];

    // Sync text representation from the first text/plain item
    for (const item of items) {
      if (item.types.includes('text/plain')) {
        try {
          const blob = await item.getType('text/plain');
          this.#text = await blob.text();

          // Also write to native if available
          const g = globalThis as any;
          if (typeof g.__exactClipboardWrite === 'function') {
            g.__exactClipboardWrite(this.#text);
          }
        } catch {
          // Ignore errors extracting text
        }
        break;
      }
    }
  }

  get [Symbol.toStringTag](): string {
    return 'Clipboard';
  }
}
