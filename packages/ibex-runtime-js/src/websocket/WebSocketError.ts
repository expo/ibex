import { DOMException } from '../events/DOMException';

export interface WebSocketErrorInit {
  closeCode?: number | null;
  reason?: string;
}

function isValidCloseCode(code: number): boolean {
  return code === 1000 || code === 1005 || code === 1006 || (code >= 3000 && code <= 4999);
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

    super(message, 'WebSocketError');
    this.closeCode = closeCode;
    this.reason = reason;
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocketError';
  }
}

export default WebSocketError;
