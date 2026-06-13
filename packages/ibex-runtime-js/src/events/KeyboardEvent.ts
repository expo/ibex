/**
 * KeyboardEvent - Minimal DOM-compatible keyboard event implementation.
 *
 * The DOM shim only needs the standard readonly keyboard fields that framework
 * event handlers commonly read (`key`, `code`, and modifier flags). The base
 * Event implementation already handles cancelation and dispatch bookkeeping.
 */

import { Event, type EventInit } from './Event';

export interface KeyboardEventInit extends EventInit {
  key?: string;
  code?: string;
  altKey?: boolean;
  ctrlKey?: boolean;
  metaKey?: boolean;
  shiftKey?: boolean;
  repeat?: boolean;
}

export class KeyboardEvent extends Event {
  readonly key: string;
  readonly code: string;
  readonly altKey: boolean;
  readonly ctrlKey: boolean;
  readonly metaKey: boolean;
  readonly shiftKey: boolean;
  readonly repeat: boolean;

  constructor(type: string, eventInitDict?: KeyboardEventInit) {
    super(type, eventInitDict);
    this.key = eventInitDict?.key ?? '';
    this.code = eventInitDict?.code ?? '';
    this.altKey = eventInitDict?.altKey === true;
    this.ctrlKey = eventInitDict?.ctrlKey === true;
    this.metaKey = eventInitDict?.metaKey === true;
    this.shiftKey = eventInitDict?.shiftKey === true;
    this.repeat = eventInitDict?.repeat === true;
  }

  get [Symbol.toStringTag](): string {
    return 'KeyboardEvent';
  }
}

export default KeyboardEvent;
