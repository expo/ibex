/**
 * Base64 Encoding - atob/btoa
 *
 * @see https://html.spec.whatwg.org/multipage/webappapis.html#atob
 *
 * Note: These only handle Latin-1 (bytes 0-255).
 * For Unicode, use TextEncoder first.
 */

// Base64 character set
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Reverse lookup table
const BASE64_LOOKUP = new Uint8Array(256);
for (let i = 0; i < BASE64_CHARS.length; i++) {
  BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}
BASE64_LOOKUP["=".charCodeAt(0)] = 0; // Padding

/**
 * btoa - Encode a binary string to Base64
 *
 * @param data Binary string (each char code must be 0-255)
 * @returns Base64 encoded string
 * @throws DOMException if string contains characters outside Latin-1
 */
export function btoa(data: string): string {
  if (data === undefined || data === null) {
    data = "undefined";
  }

  const str = String(data);
  const bytes: number[] = [];

  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    if (charCode > 255) {
      throw new DOMException(
        "The string to be encoded contains characters outside of the Latin1 range.",
        "InvalidCharacterError"
      );
    }
    bytes.push(charCode);
  }

  // Encode to Base64
  let result = "";
  let i = 0;

  while (i < bytes.length) {
    const b1 = bytes[i++] ?? 0;
    const b2 = bytes[i++];
    const b3 = bytes[i++];

    result += BASE64_CHARS[b1 >> 2];
    result += BASE64_CHARS[((b1 & 0x03) << 4) | ((b2 ?? 0) >> 4)];

    if (b2 !== undefined) {
      result += BASE64_CHARS[((b2 & 0x0f) << 2) | ((b3 ?? 0) >> 6)];
    } else {
      result += "=";
    }

    if (b3 !== undefined) {
      result += BASE64_CHARS[b3 & 0x3f];
    } else {
      result += "=";
    }
  }

  return result;
}

/**
 * atob - Decode a Base64 string to binary
 *
 * @param data Base64 encoded string
 * @returns Decoded binary string
 * @throws DOMException if string is not valid Base64
 */
export function atob(data: string): string {
  if (data === undefined || data === null) {
    throw new DOMException(
      "The string to be decoded is not correctly encoded.",
      "InvalidCharacterError"
    );
  }

  // Step 1: Strip ASCII whitespace (0x09, 0x0A, 0x0C, 0x0D, 0x20)
  let str = "";
  const raw = String(data);
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c !== 0x09 && c !== 0x0a && c !== 0x0c && c !== 0x0d && c !== 0x20) {
      str += raw[i];
    }
  }

  if (str.length === 0) {
    return "";
  }

  // Step 2: If length mod 4 === 0, strip up to 2 trailing '='
  let len = str.length;
  if (len % 4 === 0) {
    if (str[len - 1] === "=") { len--; }
    if (str[len - 1] === "=") { len--; }
    str = str.slice(0, len);
  }

  // Step 3: If remaining length mod 4 === 1, throw
  if (str.length % 4 === 1) {
    throw new DOMException(
      "The string to be decoded is not correctly encoded.",
      "InvalidCharacterError"
    );
  }

  // Step 4: Validate characters - only [A-Za-z0-9+/] allowed (no '=' at this point)
  for (let i = 0; i < str.length; i++) {
    if (!BASE64_CHARS.includes(str[i])) {
      throw new DOMException(
        "The string to be decoded is not correctly encoded.",
        "InvalidCharacterError"
      );
    }
  }

  // Step 5: Pad with '=' to make length a multiple of 4
  const remainder = str.length % 4;
  if (remainder === 2) {
    str += "==";
  } else if (remainder === 3) {
    str += "=";
  }

  // Decode
  const result: number[] = [];
  let i = 0;

  while (i < str.length) {
    const c1 = BASE64_LOOKUP[str.charCodeAt(i++)];
    const c2 = BASE64_LOOKUP[str.charCodeAt(i++)];
    const c3 = BASE64_LOOKUP[str.charCodeAt(i++)];
    const c4 = BASE64_LOOKUP[str.charCodeAt(i++)];

    result.push((c1 << 2) | (c2 >> 4));

    if (str[i - 2] !== "=") {
      result.push(((c2 & 0x0f) << 4) | (c3 >> 2));
    }

    if (str[i - 1] !== "=") {
      result.push(((c3 & 0x03) << 6) | c4);
    }
  }

  return String.fromCharCode(...result);
}

// DOMException for this module (avoid circular dependency)
class DOMException extends Error {
  readonly code: number = 0;
  constructor(message: string, name: string) {
    super(message);
    this.name = name;
  }
}
