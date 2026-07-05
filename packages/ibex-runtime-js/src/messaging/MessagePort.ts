// @ts-nocheck
/**
 * MessagePort implementation for Ibex runtime
 * 
 * Implements the HTML MessagePort API for two-way communication.
 * @see https://html.spec.whatwg.org/multipage/web-messaging.html#message-ports
 */

import { EventTarget } from '../events/EventTarget';
import { MessageEvent } from '../events/MessageEvent';
import { structuredClone } from '../clone/structuredClone';
import { structuredCloneTransferSymbol } from '../clone/transferableSymbols';

// Store for port pairs - weak references to avoid memory leaks
const portPairs = new WeakMap<MessagePort, MessagePort>();

/**
 * MessagePort represents one end of a two-way communication channel.
 * Messages sent through one port are received by the other port.
 */
export class MessagePort extends EventTarget {
  #started = false;
  #closed = false;
  #queue: Array<{ data: any; ports: MessagePort[] }> = [];
  #onmessage: ((this: MessagePort, ev: MessageEvent) => any) | null = null;
  #onmessageerror: ((this: MessagePort, ev: MessageEvent) => any) | null = null;

  constructor() {
    super();
  }

  get onmessage(): ((this: MessagePort, ev: MessageEvent) => any) | null {
    return this.#onmessage;
  }

  set onmessage(value: ((this: MessagePort, ev: MessageEvent) => any) | null) {
    this.#onmessage = value;
    if (value !== null) {
      this.start();
    }
  }

  get onmessageerror(): ((this: MessagePort, ev: MessageEvent) => any) | null {
    return this.#onmessageerror;
  }

  set onmessageerror(value: ((this: MessagePort, ev: MessageEvent) => any) | null) {
    this.#onmessageerror = value;
  }

  /**
   * Posts a message through the channel.
   * The message is cloned using the structured clone algorithm.
   */
  postMessage(message: any, transfer?: Transferable[]): void;
  postMessage(message: any, options?: StructuredSerializeOptions): void;
  postMessage(message: any, transferOrOptions?: Transferable[] | StructuredSerializeOptions): void {
    if (this.#closed) {
      return; // Silently ignore messages on closed ports
    }

    const transfer: Transferable[] = Array.isArray(transferOrOptions)
      ? transferOrOptions
      : (transferOrOptions?.transfer ?? []);

    const otherPort = portPairs.get(this);
    if (!otherPort) {
      return; // No paired port, message is lost
    }

    // Partition the transfer list: MessagePorts are surfaced to the receiver as
    // MessageEvent.ports; other transferables (ArrayBuffers) move via the clone.
    // The canonical `port.postMessage(msg, [channel.port2])` pattern lists the
    // port only in the transfer list, so it must be transferred and delivered as
    // event.ports here rather than through the structured-clone graph walk.
    // @see https://html.spec.whatwg.org/multipage/web-messaging.html#message-port-post-message-steps
    const bufferTransfers: Transferable[] = [];
    const portsToTransfer: MessagePort[] = [];
    for (const item of transfer) {
      if (item instanceof MessagePort) {
        portsToTransfer.push(item);
      } else {
        bufferTransfers.push(item);
      }
    }

    // Clone the message
    const clonedMessage = structuredClone(message, { transfer: bufferTransfers });
    const transferredPorts = portsToTransfer.map(
      (port) => port[structuredCloneTransferSymbol]() as MessagePort
    );

    // Queue or deliver the message
    if (otherPort.#started) {
      otherPort._deliverMessage(clonedMessage, transferredPorts);
    } else {
      otherPort.#queue.push({ data: clonedMessage, ports: transferredPorts });
    }
  }

  /**
   * Begins dispatching messages received on the port.
   * Messages are held in a queue until start() is called.
   */
  start(): void {
    if (this.#started || this.#closed) {
      return;
    }

    this.#started = true;

    // Deliver queued messages
    const queue = this.#queue;
    this.#queue = [];

    for (const { data, ports } of queue) {
      this._deliverMessage(data, ports);
    }
  }

  /**
   * Disconnects the port, preventing any further messages.
   */
  close(): void {
    this.#closed = true;
    this.#started = false;
    this.#queue = [];
    
    // Disconnect from paired port
    const otherPort = portPairs.get(this);
    if (otherPort) {
      portPairs.delete(this);
      portPairs.delete(otherPort);
    }
  }

  /**
   * Internal method to deliver a message to this port.
   */
  _deliverMessage(data: any, ports: MessagePort[]): void {
    // Dispatch asynchronously per spec
    queueMicrotask(() => {
      if (this.#closed) {
        return;
      }

      const event = new MessageEvent('message', {
        data,
        origin: '',
        lastEventId: '',
        source: null,
        ports,
      });

      // Call onmessage handler
      if (this.#onmessage) {
        this.#onmessage.call(this, event);
      }

      // Dispatch event
      this.dispatchEvent(event);
    });
  }

  /**
   * Internal method to set up port pairing.
   */
  static _pair(port1: MessagePort, port2: MessagePort): void {
    portPairs.set(port1, port2);
    portPairs.set(port2, port1);
  }

  [structuredCloneTransferSymbol](): MessagePort {
    const transferredPort = new MessagePort();
    const otherPort = portPairs.get(this);
    transferredPort.#queue = this.#queue;
    if (otherPort) {
      portPairs.set(transferredPort, otherPort);
      portPairs.set(otherPort, transferredPort);
      portPairs.delete(this);
    }
    this.#queue = [];
    this.#closed = true;
    this.#started = false;
    this.#onmessage = null;
    this.#onmessageerror = null;
    return transferredPort;
  }

  get [Symbol.toStringTag](): string {
    return 'MessagePort';
  }
}

interface StructuredSerializeOptions {
  transfer?: Transferable[];
}

export default MessagePort;
