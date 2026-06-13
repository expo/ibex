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
  return error.message.toLowerCase().includes("incomplete data");
}

function isTrailingDataError(error: TypeError): boolean {
  return error.message.toLowerCase().includes("trailing data");
}

function markTrailingDataError(error: TypeError): TypeError {
  const flagged = error as unknown as { [key: symbol]: true };
  flagged[trailingDataErrorSymbol] = true;
  return error;
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
    let trailingDataError = false;
    let writableClosed = false;
    let readableController: ReadableStreamDefaultController<Uint8Array> | undefined;
    const isBrotliFormat = format === 'brotli';
    let streamInput = new Uint8Array(0);
    let brotliOutputByteLength = 0;

    const appendInput = (chunk: Uint8Array): void => {
      if (chunk.length === 0) {
        return;
      }

      const combined = new Uint8Array(streamInput.length + chunk.length);
      combined.set(streamInput, 0);
      combined.set(chunk, streamInput.length);
      streamInput = combined;
    };

    const validateChunkCompletion = (): void => {
      if (streamError || streamFinished) {
        return;
      }

      try {
        decompressChunk(streamInput, false);
        streamFinished = true;
      } catch (error) {
        const decodedError = toTypeError(error);
        if (isRecoverableIncompleteError(decodedError)) {
          return;
        }
        if (isTrailingDataError(decodedError)) {
          markTrailingDataError(decodedError);
          streamError = decodedError;
          trailingDataError = true;
          streamFinished = true;
          return;
        }

        streamError = decodedError;
        if (readableController) {
          readableController.error(streamError);
        }
      }
    };

    const processBrotliChunk = (): void => {
      if (streamError || !readableController) {
        return;
      }

      let output: Uint8Array;
      try {
        output = decompressChunk(streamInput);
      } catch (error) {
        const decodedError = toTypeError(error);
        if (isRecoverableIncompleteError(decodedError)) {
          return;
        }
        if (isTrailingDataError(decodedError)) {
          markTrailingDataError(decodedError);
          trailingDataError = true;
        }

        streamError = decodedError;
        return;
      }

      if (output.byteLength > brotliOutputByteLength) {
        readableController.enqueue(output.slice(brotliOutputByteLength));
        brotliOutputByteLength = output.byteLength;
      }
    };

    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        readableController = controller;
        if (streamError) {
          controller.error(streamError);
          return;
        }
      },
      pull(controller) {
        if (!streamFinished && streamInput.length > 0 && !streamError) {
          validateChunkCompletion();
        }

        if (streamError && trailingDataError) {
          controller.error(streamError);
          return Promise.resolve();
        }
        if (streamError) {
          controller.error(streamError);
          return Promise.resolve();
        }
        if (writableClosed && streamError === null && !streamFinished) {
          streamError = new TypeError("Decompression stream failed: incomplete data");
          controller.error(streamError);
          return Promise.resolve();
        }
        if (writableClosed && readableController && streamError === null) {
          controller.close();
          return Promise.resolve();
        }

        return Promise.resolve();
      },
      cancel() {
        writableClosed = true;
        return Promise.resolve();
      },
    });

    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        try {
          if (streamError) {
            throw streamError;
          }

        if (isBrotliFormat) {
          if (chunk.length === 0) {
            return;
          }

          const output = decompressChunk(chunk);
          streamFinished = true;
          if (output.byteLength > 0 && readableController) {
            readableController.enqueue(output);
          }
          return;
        }

          appendInput(chunk);

          let output: Uint8Array;
          try {
            output = decompressChunk(chunk);
            streamFinished = true;
          } catch (error) {
            streamError = toTypeError(error);
            if (readableController) {
              readableController.error(streamError);
            }
            return;
          }

          if (output.byteLength > 0 && readableController) {
            readableController.enqueue(output);
          }
        } catch (error) {
          streamError = toTypeError(error);
          if (readableController) {
            readableController.error(streamError);
          }
          return;
        }
      },
      async close() {
        try {
          writableClosed = true;

          if (streamError) {
            if (readableController) {
              readableController.error(streamError);
            }
            return;
          }

          if (!streamFinished && streamInput.length > 0 && !streamError) {
            validateChunkCompletion();
          }

          if (streamError === null && !streamFinished) {
            streamError = new TypeError("Decompression stream failed: incomplete data");
            if (readableController) {
              readableController.error(streamError);
            }
            return;
          }

          if (streamError === null && readableController) {
            readableController.close();
          }
        } catch (error) {
          streamError = streamError || toTypeError(error);
          if (readableController) {
            readableController.error(streamError);
          }
        }
      },
      async abort(reason) {
        if (streamError === null) {
          streamError = reason === undefined ? new TypeError("The operation was aborted.") : toTypeError(reason);
        }
        writableClosed = true;
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
