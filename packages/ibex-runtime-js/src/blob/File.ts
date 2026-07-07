/**
 * File implementation for Ibex runtime
 *
 * Implements the WHATWG File API.
 * https://w3c.github.io/FileAPI/#file-section
 */

import { Blob, BlobPart, BlobPropertyBag } from './Blob';

export interface FilePropertyBag extends BlobPropertyBag {
  lastModified?: number;
}

/**
 * File represents a file with a name and optional last modified date.
 * Extends Blob with file-specific metadata.
 */
export class File extends Blob {
  readonly #name: string;
  readonly #lastModified: number;

  constructor(fileBits: BlobPart[], fileName: string, options?: FilePropertyBag) {
    super(fileBits, options);
    
    // Per spec, convert to string
    this.#name = String(fileName);
    
    // Default to current time if not specified
    this.#lastModified = options?.lastModified ?? Date.now();
  }

  /**
   * The name of the file.
   */
  get name(): string {
    return this.#name;
  }

  /**
   * The last modified time of the file, in milliseconds since the Unix epoch.
   */
  get lastModified(): number {
    return this.#lastModified;
  }

  /**
   * The relative path of the file (empty for files not from a directory picker).
   * This is a legacy property, always returns empty string.
   */
  get webkitRelativePath(): string {
    return '';
  }

  get [Symbol.toStringTag](): string {
    return 'File';
  }
}

export default File;
