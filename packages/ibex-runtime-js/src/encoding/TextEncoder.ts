/**
 * TextEncoder - Web Standard TextEncoder Implementation
 *
 * @see https://encoding.spec.whatwg.org/#textencoder
 */

import { getNativeModule } from '../native/NativeModules';

export interface TextEncoderEncodeIntoResult {
  read: number;
  written: number;
}

export class TextEncoder {
  readonly encoding: "utf-8" = "utf-8";

  /**
   * Encode a string to UTF-8 bytes
   *
   * @param input String to encode
   * @returns Uint8Array of UTF-8 bytes
   */
  encode(input?: string): Uint8Array {
    if (input === undefined) {
      return new Uint8Array(0);
    }

    const str = String(input);
    
    // Try native encoding for better performance
    const nativeEncoding = getNativeModule('encoding');
    if (nativeEncoding) {
      return nativeEncoding.encodeUTF8(str);
    }

    // Fallback to JS implementation
    const bytes: number[] = [];

    for (let i = 0; i < str.length; i++) {
      let codePoint = str.charCodeAt(i);

      // Handle surrogate pairs
      if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
        const high = codePoint;
        const low = str.charCodeAt(++i);

        if (low >= 0xdc00 && low <= 0xdfff) {
          codePoint = (high - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000;
        } else {
          // Unpaired high surrogate - use replacement character
          codePoint = 0xfffd;
          i--;
        }
      } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
        // Unpaired low surrogate - use replacement character
        codePoint = 0xfffd;
      }

      // Encode code point to UTF-8
      if (codePoint <= 0x7f) {
        bytes.push(codePoint);
      } else if (codePoint <= 0x7ff) {
        bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
      } else if (codePoint <= 0xffff) {
        bytes.push(
          0xe0 | (codePoint >> 12),
          0x80 | ((codePoint >> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      } else {
        bytes.push(
          0xf0 | (codePoint >> 18),
          0x80 | ((codePoint >> 12) & 0x3f),
          0x80 | ((codePoint >> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      }
    }

    return new Uint8Array(bytes);
  }

  /**
   * Encode a string into an existing Uint8Array
   *
   * @param source String to encode
   * @param destination Uint8Array to write into
   * @returns Object with read (chars) and written (bytes) counts
   */
  encodeInto(source: string, destination: Uint8Array): TextEncoderEncodeIntoResult {
    if (!(destination instanceof Uint8Array)) {
      throw new TypeError("encodeInto requires a Uint8Array destination");
    }

    // Handle detached ArrayBuffer
    if (destination.buffer.byteLength === 0 && destination.byteLength === 0 && destination.length === 0) {
      return { read: 0, written: 0 };
    }

    if (!source) {
      return { read: 0, written: 0 };
    }

    let read = 0;
    let written = 0;

    for (let i = 0; i < source.length; i++) {
      let codePoint = source.charCodeAt(i);
      let bytesNeeded: number;
      let isSurrogatePair = false;

      // Handle surrogate pairs
      if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
        const high = codePoint;
        const low = source.charCodeAt(i + 1);

        if (low >= 0xdc00 && low <= 0xdfff) {
          codePoint = (high - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000;
          isSurrogatePair = true;
        } else {
          codePoint = 0xfffd;
        }
      } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
        codePoint = 0xfffd;
      }

      // Calculate bytes needed
      if (codePoint <= 0x7f) {
        bytesNeeded = 1;
      } else if (codePoint <= 0x7ff) {
        bytesNeeded = 2;
      } else if (codePoint <= 0xffff) {
        bytesNeeded = 3;
      } else {
        bytesNeeded = 4;
      }

      // Check if we have room. Per the Encoding spec, encodeInto must stop
      // *before* a code point that does not fully fit so the caller can grow the
      // buffer and resume. Emitting a partial encoding (or substituting U+FFFD
      // for a valid surrogate pair and then reprocessing the low surrogate as a
      // second lone surrogate) permanently corrupts resize-and-continue encoders.
      if (written + bytesNeeded > destination.length) {
        break;
      }

      // Write bytes
      if (codePoint <= 0x7f) {
        destination[written++] = codePoint;
      } else if (codePoint <= 0x7ff) {
        destination[written++] = 0xc0 | (codePoint >> 6);
        destination[written++] = 0x80 | (codePoint & 0x3f);
      } else if (codePoint <= 0xffff) {
        destination[written++] = 0xe0 | (codePoint >> 12);
        destination[written++] = 0x80 | ((codePoint >> 6) & 0x3f);
        destination[written++] = 0x80 | (codePoint & 0x3f);
      } else {
        destination[written++] = 0xf0 | (codePoint >> 18);
        destination[written++] = 0x80 | ((codePoint >> 12) & 0x3f);
        destination[written++] = 0x80 | ((codePoint >> 6) & 0x3f);
        destination[written++] = 0x80 | (codePoint & 0x3f);
      }

      // Count characters read
      if (isSurrogatePair) {
        // Surrogate pair = 2 UTF-16 code units
        read += 2;
        i++; // Skip the low surrogate
      } else {
        read += 1;
      }
    }

    return { read, written };
  }
}
