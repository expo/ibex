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

    this._transform = new TransformStream<string, Uint8Array>({
      transform(chunk: string, controller) {
        const encoded = encoder.encode(String(chunk));
        if (encoded.length > 0) {
          controller.enqueue(encoded);
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
