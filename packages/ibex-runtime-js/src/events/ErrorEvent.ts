/**
 * ErrorEvent - Event for runtime errors
 * 
 * Used for reporting script errors and Worker errors.
 * @see https://html.spec.whatwg.org/multipage/webappapis.html#errorevent
 */

import { Event, EventInit } from './Event';

export interface ErrorEventInit extends EventInit {
  message?: string;
  filename?: string;
  lineno?: number;
  colno?: number;
  error?: any;
}

export class ErrorEvent extends Event {
  readonly message: string;
  readonly filename: string;
  readonly lineno: number;
  readonly colno: number;
  readonly error: any;

  constructor(type: string, eventInitDict?: ErrorEventInit) {
    super(type, eventInitDict);
    this.message = eventInitDict?.message ?? '';
    this.filename = eventInitDict?.filename ?? '';
    this.lineno = eventInitDict?.lineno ?? 0;
    this.colno = eventInitDict?.colno ?? 0;
    this.error = eventInitDict?.error ?? null;
  }

  get [Symbol.toStringTag](): string {
    return 'ErrorEvent';
  }
}

export default ErrorEvent;
