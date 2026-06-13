/**
 * FocusEvent - Minimal DOM-compatible focus event implementation.
 *
 * The DOM shim uses this for focus/blur/focusin/focusout payload wrapping so
 * handlers can read `relatedTarget` without special Exact-specific branching.
 */

import { Event, type EventInit } from './Event';

export interface FocusEventInit extends EventInit {
  relatedTarget?: EventTarget | null;
}

export class FocusEvent extends Event {
  readonly relatedTarget: EventTarget | null;

  constructor(type: string, eventInitDict?: FocusEventInit) {
    super(type, eventInitDict);
    this.relatedTarget = eventInitDict?.relatedTarget ?? null;
  }

  get [Symbol.toStringTag](): string {
    return 'FocusEvent';
  }
}

export default FocusEvent;
