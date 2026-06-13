/**
 * CloseEvent - Event for WebSocket close events
 * 
 * @see https://html.spec.whatwg.org/multipage/web-sockets.html#closeevent
 */

import { Event, EventInit } from './Event';

export interface CloseEventInit extends EventInit {
  wasClean?: boolean;
  code?: number;
  reason?: string;
}

function assertCloseEventBrand(value: unknown): CloseEvent {
  if (!(value instanceof CloseEvent)) {
    throw new TypeError('Illegal invocation');
  }
  return value;
}

export class CloseEvent extends Event {
  _wasClean: boolean;
  _code: number;
  _reason: string;

  constructor(type: string, eventInitDict?: CloseEventInit) {
    super(type, eventInitDict);
    this._wasClean = eventInitDict?.wasClean ?? false;
    this._code = eventInitDict?.code ?? 0;
    this._reason = eventInitDict?.reason ?? '';
  }

  get wasClean(): boolean {
    return assertCloseEventBrand(this)._wasClean;
  }

  get code(): number {
    return assertCloseEventBrand(this)._code;
  }

  get reason(): string {
    return assertCloseEventBrand(this)._reason;
  }

  get [Symbol.toStringTag](): string {
    return 'CloseEvent';
  }
}

Object.defineProperty(CloseEvent, 'length', {
  value: 1,
  configurable: true,
});

function nameAccessor(
  descriptor: PropertyDescriptor | undefined,
  propertyName: string
): PropertyDescriptor | undefined {
  if (!descriptor) {
    return descriptor;
  }
  if (typeof descriptor.get === 'function') {
    Object.defineProperty(descriptor.get, 'name', {
      value: `get ${propertyName}`,
      configurable: true,
    });
  }
  if (typeof descriptor.set === 'function') {
    Object.defineProperty(descriptor.set, 'name', {
      value: `set ${propertyName}`,
      configurable: true,
    });
  }
  return descriptor;
}

const wasCleanDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(CloseEvent.prototype, 'wasClean'), 'wasClean')!;
const codeDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(CloseEvent.prototype, 'code'), 'code')!;
const reasonDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(CloseEvent.prototype, 'reason'), 'reason')!;

Object.defineProperties(CloseEvent.prototype, {
  wasClean: { get: wasCleanDescriptor.get, enumerable: true, configurable: true },
  code: { get: codeDescriptor.get, enumerable: true, configurable: true },
  reason: { get: reasonDescriptor.get, enumerable: true, configurable: true },
});

Object.setPrototypeOf(CloseEvent.prototype, Event.prototype);
Object.setPrototypeOf(CloseEvent, Event);

export default CloseEvent;
