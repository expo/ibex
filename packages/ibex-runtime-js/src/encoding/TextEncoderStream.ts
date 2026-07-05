/**
 * TextEncoderStream - Web Standard TextEncoderStream Implementation
 *
 * @see https://encoding.spec.whatwg.org/#interface-textencoderstream
 *
 * Wraps a TransformStream that encodes string chunks into UTF-8 Uint8Array chunks.
 */

import { TransformStream } from '../streams/TransformStream';
import { TextEncoder } from './TextEncoder';

export class TextEncoderStream {
  readonly encoding: "utf-8" = "utf-8";
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<string>;

  /** @internal */
  private _transform: TransformStream<string, Uint8Array>;

  constructor() {
    const encoder = new TextEncoder();

    // A surrogate pair can straddle a chunk boundary: the high surrogate may end
    // one chunk and the low surrogate begin the next. We hold back a trailing
    // high surrogate and prepend it to the following chunk so the pair encodes as
    // a single code point rather than two U+FFFD replacements. A lone high
    // surrogate still pending at end-of-stream is flushed as U+FFFD.
    // @see https://encoding.spec.whatwg.org/#interface-textencoderstream
    let pendingHighSurrogate = "";

    this._transform = new TransformStream<string, Uint8Array>({
      transform(chunk: string, controller) {
        let input = pendingHighSurrogate + String(chunk);
        pendingHighSurrogate = "";

        // If the input ends with a lone high surrogate, defer it to the next
        // chunk (it may be completed by a leading low surrogate there).
        if (input.length > 0) {
          const lastUnit = input.charCodeAt(input.length - 1);
          if (lastUnit >= 0xd800 && lastUnit <= 0xdbff) {
            pendingHighSurrogate = input.slice(input.length - 1);
            input = input.slice(0, input.length - 1);
          }
        }

        if (input.length > 0) {
          const encoded = encoder.encode(input);
          if (encoded.length > 0) {
            controller.enqueue(encoded);
          }
        }
      },
      flush(controller) {
        if (pendingHighSurrogate.length > 0) {
          // Unpaired high surrogate at end of stream -> U+FFFD.
          const encoded = encoder.encode(pendingHighSurrogate);
          pendingHighSurrogate = "";
          if (encoded.length > 0) {
            controller.enqueue(encoded);
          }
        }
      },
    });

    this.readable = this._transform.readable as unknown as ReadableStream<Uint8Array>;
    this.writable = this._transform.writable as unknown as WritableStream<string>;
  }

  get [Symbol.toStringTag](): string {
    return 'TextEncoderStream';
  }
}
