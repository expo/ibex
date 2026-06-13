/**
 * PromiseRejectionEvent - Event for unhandled promise rejections
 *
 * Fired when a Promise is rejected and no rejection handler is attached,
 * or when a previously unhandled rejection becomes handled.
 * @see https://html.spec.whatwg.org/multipage/webappapis.html#promiserejectionevent
 */

import { Event, EventInit } from './Event';

export interface PromiseRejectionEventInit extends EventInit {
  promise: Promise<any>;
  reason?: any;
}

export class PromiseRejectionEvent extends Event {
  readonly promise: Promise<any>;
  readonly reason: any;

  constructor(type: string, eventInitDict: PromiseRejectionEventInit) {
    super(type, eventInitDict);
    this.promise = eventInitDict.promise;
    this.reason = 'reason' in eventInitDict ? eventInitDict.reason : undefined;
  }

  get [Symbol.toStringTag](): string {
    return 'PromiseRejectionEvent';
  }
}

export default PromiseRejectionEvent;
