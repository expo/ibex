/**
 * MessageChannel implementation for Ibex runtime
 * 
 * Creates a pair of connected MessagePorts for two-way communication.
 * @see https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels
 */

import { MessagePort } from './MessagePort';

/**
 * MessageChannel creates a new channel with two connected ports.
 * Messages sent through port1 are received by port2 and vice versa.
 */
export class MessageChannel {
  readonly port1: MessagePort;
  readonly port2: MessagePort;

  constructor() {
    this.port1 = new MessagePort();
    this.port2 = new MessagePort();
    
    // Set up the bidirectional connection
    MessagePort._pair(this.port1, this.port2);
  }

  get [Symbol.toStringTag](): string {
    return 'MessageChannel';
  }
}

export default MessageChannel;
