/**
 * ClipboardItem - Web Clipboard API ClipboardItem implementation
 *
 * Represents a single item on the clipboard, potentially with multiple
 * representations (e.g., text/plain and text/html for the same content).
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/ClipboardItem
 * @see https://w3c.github.io/clipboard-apis/#clipboarditem
 */

/**
 * A ClipboardItem represents data that can be placed on or read from
 * the system clipboard. Each item can have multiple MIME-typed representations.
 */
export class ClipboardItem {
  readonly #items: Map<string, Blob | string | Promise<Blob | string>>;
  readonly #types: readonly string[];

  /**
   * Create a new ClipboardItem.
   *
   * @param items - A record mapping MIME types to their data. Values can be
   *   Blob, string, or Promise resolving to either.
   * @param options - Optional settings (presentationStyle, etc.) - reserved for future use.
   */
  constructor(
    items: Record<string, Blob | string | Promise<Blob | string>>,
    _options?: { presentationStyle?: 'unspecified' | 'inline' | 'attachment' },
  ) {
    if (!items || typeof items !== 'object') {
      throw new TypeError('ClipboardItem constructor: items must be an object');
    }

    const keys = Object.keys(items);
    if (keys.length === 0) {
      throw new TypeError('ClipboardItem constructor: items must not be empty');
    }

    this.#items = new Map();
    for (let i = 0; i < keys.length; i++) {
      const type = keys[i];
      this.#items.set(type, items[type]);
    }
    this.#types = Object.freeze([...keys]);
  }

  /**
   * The MIME types available for this clipboard item.
   */
  get types(): readonly string[] {
    return this.#types;
  }

  /**
   * Retrieve the data for a specific MIME type as a Blob.
   *
   * @param type - The MIME type to retrieve.
   * @returns A Promise resolving to a Blob containing the data.
   * @throws DOMException with name "NotFoundError" if the type is not available.
   */
  async getType(type: string): Promise<Blob> {
    const data = this.#items.get(type);
    if (data === undefined) {
      throw new DOMException(
        `ClipboardItem.getType: type '${type}' not found`,
        'NotFoundError',
      );
    }

    const resolved = await data;

    if (typeof resolved === 'string') {
      return new Blob([resolved], { type });
    }

    if (resolved instanceof Blob) {
      return resolved;
    }

    throw new TypeError(
      `ClipboardItem.getType: unexpected data type for '${type}'`,
    );
  }

  get [Symbol.toStringTag](): string {
    return 'ClipboardItem';
  }
}

// DOMException polyfill for this module
class DOMException extends Error {
  readonly code: number = 0;
  constructor(message: string, name: string) {
    super(message);
    this.name = name;
  }
}
