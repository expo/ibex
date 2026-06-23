// @ts-nocheck
/**
 * FileReader implementation for Ibex runtime (Legacy API)
 * 
 * @see https://w3c.github.io/FileAPI/#dfn-filereader
 * 
 * Note: Modern code should use Blob.arrayBuffer(), Blob.text(), etc.
 * This is provided for compatibility with legacy libraries.
 */

import { EventTarget } from '../events/EventTarget';
import { Event } from '../events/Event';
import { ProgressEvent } from '../events/ProgressEvent';
import { DOMException, createInvalidStateError, createNotSupportedError } from '../events/DOMException';
import { Blob } from '../blob/Blob';

// FileReader states
const EMPTY = 0;
const LOADING = 1;
const DONE = 2;

/**
 * FileReader enables asynchronous reading of file or blob contents.
 */
export class FileReader extends EventTarget {
  static readonly EMPTY = EMPTY;
  static readonly LOADING = LOADING;
  static readonly DONE = DONE;

  readonly EMPTY = EMPTY;
  readonly LOADING = LOADING;
  readonly DONE = DONE;

  #readyState: number = EMPTY;
  #result: string | ArrayBuffer | null = null;
  #error: DOMException | null = null;
  #aborted = false;

  // Event handlers
  onloadstart: ((this: FileReader, ev: ProgressEvent) => any) | null = null;
  onprogress: ((this: FileReader, ev: ProgressEvent) => any) | null = null;
  onload: ((this: FileReader, ev: ProgressEvent) => any) | null = null;
  onabort: ((this: FileReader, ev: ProgressEvent) => any) | null = null;
  onerror: ((this: FileReader, ev: ProgressEvent) => any) | null = null;
  onloadend: ((this: FileReader, ev: ProgressEvent) => any) | null = null;

  get readyState(): number {
    return this.#readyState;
  }

  get result(): string | ArrayBuffer | null {
    return this.#result;
  }

  get error(): DOMException | null {
    return this.#error;
  }

  /**
   * Check if reader is ready to start a new read operation.
   * Throws InvalidStateError if already loading.
   */
  #checkReadyState(): void {
    if (this.#readyState === LOADING) {
      throw createInvalidStateError('FileReader is already loading');
    }
  }

  /**
   * Read blob as ArrayBuffer.
   */
  readAsArrayBuffer(blob: Blob): void {
    this.#checkReadyState();
    this.#read(blob, 'arraybuffer');
  }

  /**
   * Read blob as binary string.
   * @deprecated Use readAsArrayBuffer instead.
   */
  readAsBinaryString(blob: Blob): void {
    this.#checkReadyState();
    this.#read(blob, 'binarystring');
  }

  /**
   * Read blob as text.
   */
  readAsText(blob: Blob, encoding?: string): void {
    this.#checkReadyState();
    this.#read(blob, 'text', encoding);
  }

  /**
   * Read blob as data URL.
   */
  readAsDataURL(blob: Blob): void {
    this.#checkReadyState();
    this.#read(blob, 'dataurl');
  }

  /**
   * Abort the read operation.
   */
  abort(): void {
    if (this.#readyState === EMPTY || this.#readyState === DONE) {
      this.#result = null;
      return;
    }

    if (this.#readyState === LOADING) {
      this.#readyState = DONE;
      this.#result = null;
      this.#aborted = true;

      this.#fireEvent('abort');
      this.#fireEvent('loadend');
    }
  }

  /**
   * Internal read implementation.
   */
  async #read(blob: Blob, format: 'arraybuffer' | 'binarystring' | 'text' | 'dataurl', encoding?: string): Promise<void> {
    // State check is done in #checkReadyState() before calling this method
    this.#readyState = LOADING;
    this.#result = null;
    this.#error = null;
    this.#aborted = false;

    this.#fireProgressEvent('loadstart', 0, blob.size);

    try {
      // Read the blob data
      const buffer = await blob.arrayBuffer();
      
      if (this.#aborted) {
        return;
      }

      // Fire progress event
      this.#fireProgressEvent('progress', buffer.byteLength, blob.size);

      // Convert to requested format
      switch (format) {
        case 'arraybuffer':
          this.#result = buffer;
          break;

        case 'binarystring': {
          const bytes = new Uint8Array(buffer);
          let result = '';
          for (let i = 0; i < bytes.length; i++) {
            result += String.fromCharCode(bytes[i]);
          }
          this.#result = result;
          break;
        }

        case 'text': {
          const decoder = new TextDecoder(encoding || 'utf-8');
          this.#result = decoder.decode(buffer);
          break;
        }

        case 'dataurl': {
          const bytes = new Uint8Array(buffer);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          const base64 = btoa(binary);
          const mimeType = blob.type || 'application/octet-stream';
          this.#result = `data:${mimeType};base64,${base64}`;
          break;
        }
      }

      this.#readyState = DONE;
      this.#fireProgressEvent('load', buffer.byteLength, blob.size);
      this.#fireProgressEvent('loadend', buffer.byteLength, blob.size);

    } catch (err) {
      if (this.#aborted) {
        return;
      }

      this.#readyState = DONE;
      this.#error = new DOMException(
        err instanceof Error ? err.message : 'Read failed',
        'NotReadableError'
      );
      
      this.#fireProgressEvent('error', 0, blob.size);
      this.#fireProgressEvent('loadend', 0, blob.size);
    }
  }

  /**
   * Fire a simple event.
   */
  #fireEvent(type: string): void {
    const event = new Event(type);
    
    const handler = (this as any)[`on${type}`];
    if (handler) {
      handler.call(this, event);
    }
    
    this.dispatchEvent(event);
  }

  /**
   * Fire a progress event.
   */
  #fireProgressEvent(type: string, loaded: number, total: number): void {
    const event = new ProgressEvent(type, {
      lengthComputable: total > 0,
      loaded,
      total,
    });

    const handler = (this as any)[`on${type}`];
    if (handler) {
      handler.call(this, event);
    }

    this.dispatchEvent(event);
  }

  get [Symbol.toStringTag](): string {
    return 'FileReader';
  }
}

export default FileReader;
