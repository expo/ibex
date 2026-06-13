/**
 * MessageEvent - Event for messaging APIs
 * 
 * Used by WebSocket, MessagePort, BroadcastChannel, and postMessage.
 * @see https://html.spec.whatwg.org/multipage/comms.html#messageevent
 */

import { Event, EventInit } from './Event';

export interface MessageEventInit<T = any> extends EventInit {
  data?: T;
  origin?: string;
  lastEventId?: string;
  source?: MessageEventSource | null;
  ports?: MessagePort[];
}

// MessageEventSource can be WindowProxy, MessagePort, or ServiceWorker
// In our runtime, we only support MessagePort
export type MessageEventSource = MessagePort | null;

export class MessageEvent<T = any> extends Event {
  readonly data: T;
  readonly origin: string;
  readonly lastEventId: string;
  readonly source: MessageEventSource;
  readonly ports: ReadonlyArray<MessagePort>;

  constructor(type: string, eventInitDict?: MessageEventInit<T>) {
    super(type, eventInitDict);
    this.data = eventInitDict?.data as T;
    this.origin = eventInitDict?.origin ?? '';
    this.lastEventId = eventInitDict?.lastEventId ?? '';
    this.source = eventInitDict?.source ?? null;
    this.ports = Object.freeze(eventInitDict?.ports ? [...eventInitDict.ports] : []);
  }

  /**
   * Legacy method for initializing a MessageEvent.
   * @deprecated Use the constructor instead.
   */
  initMessageEvent(
    type: string,
    bubbles?: boolean,
    cancelable?: boolean,
    data?: T,
    origin?: string,
    lastEventId?: string,
    source?: MessageEventSource,
    ports?: MessagePort[]
  ): void {
    // This is a no-op in modern implementations since events are immutable
    // Included for compatibility only
  }

  get [Symbol.toStringTag](): string {
    return 'MessageEvent';
  }
}

export default MessageEvent;
