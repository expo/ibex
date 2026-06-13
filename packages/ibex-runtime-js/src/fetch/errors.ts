/**
 * Fetch API Errors
 *
 * Custom error types for the Fetch API implementation.
 */

/**
 * Error thrown when a fetch request fails.
 */
export class FetchError implements Error {
  name = 'FetchError';
  message: string;
  stack?: string;
  cause?: unknown;

  constructor(
    message: string,
    options?: { cause?: unknown; stack?: string }
  ) {
    this.message = `fetch failed: ${message}`;
    this.cause = options?.cause;
    this.stack = options?.stack ?? new Error(this.message).stack;
  }

  /**
   * Create a FetchError from an existing Error.
   */
  static createFromError(error: Error): FetchError {
    return new FetchError(error.message, {
      cause: (error as Error & { cause?: unknown }).cause,
      stack: error.stack,
    });
  }
}
Object.setPrototypeOf(FetchError.prototype, Error.prototype);
Object.setPrototypeOf(FetchError, Error);

/**
 * Error thrown when a request is aborted.
 */
export class AbortError implements Error {
  name = 'AbortError';
  message: string;
  stack?: string;

  constructor(message = 'The operation was aborted') {
    this.message = message;
    this.stack = new Error(this.message).stack;
  }
}
Object.setPrototypeOf(AbortError.prototype, Error.prototype);
Object.setPrototypeOf(AbortError, Error);

/**
 * Error thrown for network failures.
 */
export class NetworkError implements Error {
  name = 'NetworkError';
  message: string;
  stack?: string;

  constructor(message = 'Network request failed') {
    this.message = message;
    this.stack = new Error(this.message).stack;
  }
}
Object.setPrototypeOf(NetworkError.prototype, Error.prototype);
Object.setPrototypeOf(NetworkError, Error);

/**
 * Error thrown for invalid URLs.
 */
export class URLError implements Error {
  name = 'URLError';
  message: string;
  stack?: string;

  constructor(url: string) {
    this.message = `Invalid URL: ${url}`;
    this.stack = new Error(this.message).stack;
  }
}
Object.setPrototypeOf(URLError.prototype, Error.prototype);
Object.setPrototypeOf(URLError, Error);

/**
 * Error thrown when body has already been consumed.
 * Extends TypeError per the Fetch spec.
 */
export class BodyConsumedError implements Error {
  name = 'TypeError';
  message: string;
  stack?: string;

  constructor() {
    this.message = 'Body already used';
    this.stack = new TypeError(this.message).stack;
  }
}
Object.setPrototypeOf(BodyConsumedError.prototype, TypeError.prototype);
Object.setPrototypeOf(BodyConsumedError, TypeError);
