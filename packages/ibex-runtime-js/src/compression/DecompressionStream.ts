/**
 * DecompressionStream - Web Compression API
 *
 * Implements the DecompressionStream class that decompresses data using gzip, deflate, deflate-raw, or brotli.
 * Uses the native __exactInflateSync bridge for actual decompression.
 */

const g = globalThis as any;
const trailingDataErrorSymbol = Symbol.for("__exact.decompression.trailing-data-error");

function installTrailingDataUnhandledFilter(): void {
  if (g.__exactHasDecompressionUnhandledFilter) {
    return;
  }

  if (typeof g.addEventListener !== "function") {
    return;
  }

  g.__exactHasDecompressionUnhandledFilter = true;
  g.addEventListener("unhandledrejection", (event: any) => {
    if (event && event.reason && event.reason[trailingDataErrorSymbol]) {
      if (typeof event.preventDefault === "function") {
        event.preventDefault();
      }
      if (typeof event.stopImmediatePropagation === "function") {
        event.stopImmediatePropagation();
      }
      if (typeof event.stopPropagation === "function") {
        event.stopPropagation();
      }
    }
  });
}

installTrailingDataUnhandledFilter();
// Retry via microtask in case addEventListener wasn't available at module load time.
// Use queueMicrotask (no timer ID, doesn't keep event loop alive) instead of setTimeout.
if (!g.__exactHasDecompressionUnhandledFilter) {
  if (typeof g.queueMicrotask === "function") {
    g.queueMicrotask(installTrailingDataUnhandledFilter);
  } else if (typeof g.setTimeout === "function") {
    const _h = g.setTimeout(installTrailingDataUnhandledFilter, 0);
    if (_h && typeof _h === "object" && typeof _h.unref === "function") {
      _h.unref();
    }
  }
}

export type DecompressionFormat = 'gzip' | 'deflate' | 'deflate-raw' | 'brotli';

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

function isRecoverableIncompleteError(error: TypeError): boolean {
  // The zlib bridge reports truncated deflate/gzip input as "unexpected end of
  // file"; the brotli bridge reports it as "incomplete data". Both mean the
  // accumulated input is not yet a complete stream.
  const message = error.message.toLowerCase();
  return message.includes("incomplete data") || message.includes("unexpected end of file");
}

function isTrailingDataError(error: TypeError): boolean {
  return error.message.toLowerCase().includes("trailing data");
}

function markTrailingDataError(error: TypeError): TypeError {
  const flagged = error as unknown as { [key: symbol]: true };
  flagged[trailingDataErrorSymbol] = true;
  return error;
}

/**
 * Normalize a `write()`-supplied chunk to a `Uint8Array` view over its exact
 * bytes. The Compression Streams spec accepts any `BufferSource` (not just
 * `Uint8Array`), and `chunk instanceof Uint8Array ? chunk : new
 * Uint8Array(chunk)` is only correct for `Uint8Array`/`ArrayBuffer` inputs: a
 * multi-byte typed-array view (`Uint16Array`, `Float64Array`, ...) fed to
 * `new Uint8Array(typedArray)` gets element-wise *value* converted (e.g. each
 * `Uint16` truncated to its low byte) instead of byte-for-byte reinterpreted,
 * and a `DataView` — not array-like — silently produces an empty result.
 */
function normalizeDecompressionInputChunk(chunk: Uint8Array): Uint8Array {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  const maybeView = chunk as unknown as ArrayBufferView | ArrayBuffer;
  if (ArrayBuffer.isView(maybeView)) {
    return new Uint8Array(maybeView.buffer, maybeView.byteOffset, maybeView.byteLength);
  }
  return new Uint8Array(maybeView as ArrayBuffer);
}

export class DecompressionStream {
  private _format: DecompressionFormat;
  private _readable: ReadableStream<Uint8Array>;
  private _writable: WritableStream<Uint8Array>;

  constructor(format: DecompressionFormat) {
    if (format !== 'gzip' && format !== 'deflate' && format !== 'deflate-raw' && format !== 'brotli') {
      throw new TypeError(`Unsupported decompression format: '${format}'`);
    }
    this._format = format;

    // Native bridge mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw deflate (no header)
    const mode = format === 'gzip' ? 1 : format === 'deflate-raw' ? 2 : 0;

    const decompressChunk = (chunk: Uint8Array, strict = false): Uint8Array => {
      const input = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

      if (format === 'brotli') {
        if (typeof g.__exactBrotliDecompressSync !== 'function') {
          throw new Error('Native decompression bridge (__exactBrotliDecompressSync) not available');
        }

        try {
          return g.__exactBrotliDecompressSync(input, strict);
        } catch (error) {
          throw toTypeError(error);
        }
      }

      if (typeof g.__exactInflateSync !== 'function') {
        throw new Error('Native decompression bridge (__exactInflateSync) not available');
      }

      try {
        return g.__exactInflateSync(input, mode, strict);
      } catch (error) {
        throw toTypeError(error);
      }
    };

    let streamError: TypeError | null = null;
    let streamFinished = false;
    let readableController: ReadableStreamDefaultController<Uint8Array> | undefined;

    // The native inflate/brotli bridge is one-shot: it decodes a *complete*
    // stream in a single call and throws (rather than emitting partial output)
    // when the input is truncated. A mid-stream deflate chunk is headerless and
    // cannot be decoded on its own, so every chunk must be accumulated and the
    // full input decoded once the writable side closes. Buffer chunks in a list
    // and concatenate exactly once (O(n)) instead of reallocating the whole
    // accumulated buffer on every write (the old O(n^2) pattern).
    const inputChunks: Uint8Array[] = [];
    let inputLength = 0;

    const appendInput = (chunk: Uint8Array): void => {
      const view = normalizeDecompressionInputChunk(chunk);
      if (view.byteLength === 0) {
        return;
      }
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

    // Decode all accumulated input in one pass and drive the readable side.
    // Called once, when the writable side closes.
    const finalizeDecompression = (): void => {
      if (streamFinished) {
        return;
      }
      if (streamError) {
        if (readableController) {
          readableController.error(streamError);
        }
        return;
      }

      let output: Uint8Array;
      try {
        output = decompressChunk(collectInput(), false);
      } catch (error) {
        const decodedError = toTypeError(error);
        if (isTrailingDataError(decodedError)) {
          // Mark so the module's unhandledrejection filter can suppress a noisy
          // unhandled rejection if nobody is awaiting the readable.
          markTrailingDataError(decodedError);
          streamError = decodedError;
        } else if (isRecoverableIncompleteError(decodedError)) {
          // All input was written but it never formed a complete stream.
          streamError = new TypeError("Decompression stream failed: incomplete data");
        } else {
          streamError = decodedError;
        }
        streamFinished = true;
        if (readableController) {
          readableController.error(streamError);
        }
        return;
      }

      streamFinished = true;
      if (readableController) {
        if (output.byteLength > 0) {
          readableController.enqueue(output);
        }
        readableController.close();
      }
    };

    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        readableController = controller;
        if (streamError) {
          controller.error(streamError);
        }
      },
      pull(controller) {
        // Output is produced only when the writable side closes (one-shot
        // bridge), so pull only needs to surface a pre-existing error.
        if (streamError) {
          controller.error(streamError);
        }
        return Promise.resolve();
      },
      cancel() {
        return Promise.resolve();
      },
    });

    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        if (streamError) {
          throw streamError;
        }
        appendInput(chunk);
      },
      close() {
        finalizeDecompression();
      },
      abort(reason) {
        if (streamError === null) {
          streamError = reason === undefined ? new TypeError("The operation was aborted.") : toTypeError(reason);
        }
        streamFinished = true;
        if (readableController) {
          readableController.error(streamError);
        }
      },
    });

    this._readable = readable;
    this._writable = writable;
    return;
  }

  get readable(): ReadableStream<Uint8Array> {
    return this._readable;
  }

  get writable(): WritableStream<Uint8Array> {
    return this._writable;
  }
}
