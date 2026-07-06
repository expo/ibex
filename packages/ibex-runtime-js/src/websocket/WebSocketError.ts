import { DOMException } from '../events/DOMException';

export interface WebSocketErrorInit {
  closeCode?: number | null;
  reason?: string;
}

function isValidCloseCode(code: number): boolean {
  return code === 1000 || code === 1005 || code === 1006 || (code >= 3000 && code <= 4999);
}

// Close codes and reasons received from the wire are peer-controlled: a
// conforming server may close with any standard code (1001 "going away",
// 1011 "internal error", ...), not just the codes a *user* may pass. Wire
// values must never make the constructor throw, or the close listener that
// builds the terminal error dies and WebSocketStream's opened/closed promises
// hang forever (ENG-23133). This flag lets the internal factory below skip
// the user-input validation; it is set only around a synchronous construction.
let _constructingWireError = false;

/**
 * Internal factory for WebSocketError instances that represent a close
 * received from the network. Skips the user-supplied-code validation that the
 * public constructor performs. Not exported from the package index.
 */
export function createWireWebSocketError(
  message: string,
  closeCode: number | null,
  reason: string
): WebSocketError {
  _constructingWireError = true;
  try {
    return new WebSocketError(message, { closeCode, reason });
  } finally {
    _constructingWireError = false;
  }
}

function createRealmDomException(message: string, name: string): DOMException {
  const DOMExceptionCtor = ((globalThis as any).DOMException || DOMException) as typeof DOMException;
  return new DOMExceptionCtor(message, name);
}

export class WebSocketError extends DOMException {
  readonly closeCode: number | null;
  readonly reason: string;

  constructor(message: string = '', init: WebSocketErrorInit = {}) {
    const reason = typeof init.reason === 'string' ? init.reason : '';
    let closeCode = init.closeCode ?? null;

    if (reason !== '' && closeCode === null) {
      closeCode = 1000;
    }

    if (!_constructingWireError) {
      if (closeCode !== null) {
        if (typeof closeCode !== 'number' || !Number.isInteger(closeCode) || !isValidCloseCode(closeCode)) {
          throw createRealmDomException('Invalid close code', 'InvalidAccessError');
        }
      }

      if (reason !== '') {
        const encoded = new TextEncoder().encode(reason);
        if (encoded.byteLength > 123) {
          throw createRealmDomException('Close reason is too long', 'SyntaxError');
        }
      }
    }

    super(message, 'WebSocketError');
    this.closeCode = closeCode;
    this.reason = reason;
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocketError';
  }
}

export default WebSocketError;
