/**
 * CompressionStream - Web Compression API
 *
 * Implements the CompressionStream class that compresses data using gzip, deflate, deflate-raw, or brotli.
 * Uses the native __exactDeflateSync bridge for actual compression.
 */

const g = globalThis as any;

export type CompressionFormat = 'gzip' | 'deflate' | 'deflate-raw' | 'brotli';

function isTypeError(error: unknown): error is TypeError {
  return error instanceof TypeError;
}

function toTypeError(error: unknown): TypeError {
  if (error instanceof TypeError) {
    return error;
  }

  if (error instanceof Error) {
    let message = "TypeError";
    try {
      message = String(error.message);
    } catch (_ignored) {
      message = "TypeError";
    }
    return new TypeError(message);
  }

  try {
    return new TypeError(String(error));
  } catch (_ignored) {
    return new TypeError("TypeError");
  }
}

export class CompressionStream {
  private _format: CompressionFormat;
  private _readable: ReadableStream<Uint8Array>;
  private _writable: WritableStream<Uint8Array>;

  constructor(format: CompressionFormat) {
    if (format !== 'gzip' && format !== 'deflate' && format !== 'deflate-raw' && format !== 'brotli') {
      throw new TypeError(`Unsupported compression format: '${format}'`);
    }
    this._format = format;

    // Native bridge mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw deflate (no header)
    const mode = format === 'gzip' ? 1 : format === 'deflate-raw' ? 2 : 0;
    const compressChunk = (chunk: Uint8Array): Uint8Array => {
      // Convert to Uint8Array if needed
      const input = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

      if (format === 'brotli') {
        if (typeof g.__exactBrotliCompressSync !== 'function') {
          throw new Error('Native compression bridge (__exactBrotliCompressSync) not available');
        }
        return g.__exactBrotliCompressSync(input);
      }

      if (typeof g.__exactDeflateSync !== 'function') {
        throw new Error('Native compression bridge (__exactDeflateSync) not available');
      }
      return g.__exactDeflateSync(input, -1, mode);
    };

    // The native bridge is one-shot (a full deflate/gzip stream must be produced
    // in a single call), so all input is buffered until close(). Collect chunks
    // in a list and concatenate exactly once instead of reallocating and copying
    // the entire accumulated buffer on every write() — the old approach was
    // O(n^2) in total bytes copied (a 100 MB upload in 64 KB chunks did ~1600
    // full-buffer copies) and pinned two full-size buffers.
    const inputChunks: Uint8Array[] = [];
    let inputLength = 0;
    let streamError: TypeError | null = null;

    const appendInput = (chunk: Uint8Array): void => {
      const view = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      inputChunks.push(view);
      inputLength += view.length;
    };

    const collectInput = (): Uint8Array => {
      if (inputChunks.length === 1) {
        return inputChunks[0];
      }
      const combined = new Uint8Array(inputLength);
      let offset = 0;
      for (const c of inputChunks) {
        combined.set(c, offset);
        offset += c.length;
      }
      return combined;
    };

    let readableController: ReadableStreamDefaultController<Uint8Array> | undefined;

    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        readableController = controller;
      },
      cancel() {
        readableController = undefined;
      },
    });

    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        if (streamError) {
          throw streamError;
        }

        if (chunk && chunk.length > 0) {
          appendInput(chunk);
        }
      },
      close() {
        if (streamError) {
          if (readableController) {
            readableController.error(streamError);
          }
          return;
        }

        try {
          const compressed = compressChunk(collectInput());
          if (readableController && compressed.length > 0) {
            readableController.enqueue(compressed);
          }
          if (readableController) {
            readableController.close();
          }
        } catch (e) {
          streamError = e instanceof TypeError ? e : toTypeError(e);
          if (readableController) {
            readableController.error(streamError);
          }
          throw streamError;
        }
      },
      abort(reason) {
        if (reason instanceof Error) {
          streamError = toTypeError(reason);
        } else {
          streamError = new TypeError(String(reason));
        }
        if (readableController) {
          readableController.error(streamError);
        }
      },
    });

    this._readable = readable;
    this._writable = writable;
  }

  get readable(): ReadableStream<Uint8Array> {
    return this._readable;
  }

  get writable(): WritableStream<Uint8Array> {
    return this._writable;
  }
}
