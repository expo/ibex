// @ts-nocheck
/**
 * TextDecoderStream - Web Standard TextDecoderStream Implementation
 *
 * @see https://encoding.spec.whatwg.org/#interface-textdecoderstream
 *
 * Wraps a TransformStream that decodes Uint8Array chunks into string chunks
 * using TextDecoder in streaming mode.
 */

import { TransformStream } from '../streams/TransformStream';
import { TextDecoder } from './TextDecoder';
import type { TextDecoderOptions } from './TextDecoder';

export class TextDecoderStream {
  readonly encoding: string;
  readonly fatal: boolean;
  readonly ignoreBOM: boolean;
  readonly readable: ReadableStream<string>;
  readonly writable: WritableStream<Uint8Array>;

  /** @internal */
  private _transform: TransformStream<Uint8Array, string>;

  constructor(label?: string, options?: TextDecoderOptions) {
    // Create the underlying TextDecoder (validates the label/options)
    const decoder = new TextDecoder(label, options);

    this.encoding = decoder.encoding;
    this.fatal = decoder.fatal;
    this.ignoreBOM = decoder.ignoreBOM;

    this._transform = new TransformStream<Uint8Array, string>({
      transform(chunk: Uint8Array, controller) {
        // Decode in streaming mode so incomplete multi-byte sequences
        // are buffered until the next chunk arrives
        const decoded = decoder.decode(chunk, { stream: true });
        if (decoded.length > 0) {
          controller.enqueue(decoded);
        }
      },
      flush(controller) {
        // Final call without stream: true to flush any pending bytes
        const final = decoder.decode(undefined, { stream: false });
        if (final.length > 0) {
          controller.enqueue(final);
        }
      },
    });

    this.readable = this._transform.readable as unknown as ReadableStream<string>;
    this.writable = this._transform.writable as unknown as WritableStream<Uint8Array>;
  }

  get [Symbol.toStringTag](): string {
    return 'TextDecoderStream';
  }
}
