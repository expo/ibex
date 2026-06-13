/**
 * MessagePort and MessageChannel - Web Standard Messaging API
 *
 * Provides in-process message passing between ports via the structured clone
 * algorithm.  Messages are always delivered asynchronously (via queueMicrotask)
 * to match the HTML specification behaviour.
 *
 * @see https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels
 * @see https://html.spec.whatwg.org/multipage/web-messaging.html#message-ports
 */

import { EventTarget } from './events/EventTarget';
import { MessageEvent } from './events/MessageEvent';
import { structuredClone } from './clone/structuredClone';
import { structuredCloneTransferSymbol } from './clone/transferableSymbols';

// ---------------------------------------------------------------------------
// MessagePort
// ---------------------------------------------------------------------------

/**
 * A MessagePort represents one end of a two-port message channel.
 *
 * The port must be *started* before it will dispatch queued messages.
 * Setting the `onmessage` property implicitly calls `start()` (per spec).
 * Using `addEventListener('message', ...)` does NOT auto-start; the caller
 * must invoke `start()` explicitly.
 */
export class MessagePort extends EventTarget {
  /** The entangled remote port, or null if not yet wired / closed. */
  #remotePort: MessagePort | null = null;

  /** Whether `start()` has been called. */
  #started = false;

  /** Whether `close()` has been called. */
  #closed = false;

  /** Messages received before `start()` was called. */
  #queue: unknown[] = [];

  /** Backing field for the `onmessage` property. */
  #onmessage: ((this: MessagePort, ev: MessageEvent) => any) | null = null;

  /** Backing field for the `onmessageerror` property. */
  #onmessageerror: ((this: MessagePort, ev: MessageEvent) => any) | null = null;

  // -- Event handler properties (IDL attributes) ---------------------------

  /**
   * Setting `onmessage` implicitly calls `start()` per the HTML spec.
   */
  get onmessage(): ((this: MessagePort, ev: MessageEvent) => any) | null {
    return this.#onmessage;
  }

  set onmessage(handler: ((this: MessagePort, ev: MessageEvent) => any) | null) {
    this.#onmessage = handler;
    // Per spec: setting onmessage implicitly starts the port
    this.start();
  }

  get onmessageerror(): ((this: MessagePort, ev: MessageEvent) => any) | null {
    return this.#onmessageerror;
  }

  set onmessageerror(handler: ((this: MessagePort, ev: MessageEvent) => any) | null) {
    this.#onmessageerror = handler;
  }

  // -- Public API -----------------------------------------------------------

  /**
   * Post a message through this port to the entangled remote port.
   *
   * The `value` is cloned via `structuredClone` before delivery so that the
   * sender and receiver hold independent copies.
   *
   * @param value  The message payload (must be structured-cloneable).
   * @param transferList  Optional transfer list for ArrayBuffer ownership move.
   */
  postMessage(value: unknown, transferList?: Transferable[]): void {
    if (this.#closed) {
      return; // Silently ignore per spec (sender side closed)
    }

    const remote = this.#remotePort;
    if (!remote || remote.#closed) {
      return; // No entangled port or remote is closed
    }

    // Clone the message data
    let clonedData: unknown;
    try {
      clonedData = structuredClone(value, { transfer: transferList as ArrayBuffer[] | undefined });
    } catch (err) {
      // Cloning failed — dispatch messageerror on the remote port
      queueMicrotask(() => {
        if (!remote.#closed) {
          remote.#dispatchMessageError(err);
        }
      });
      return;
    }

    // Deliver asynchronously
    if (remote.#started) {
      queueMicrotask(() => {
        if (!remote.#closed) {
          remote.#dispatchMessage(clonedData);
        }
      });
    } else {
      // Queue the message until the remote port is started
      remote.#queue.push(clonedData);
    }
  }

  /**
   * Begin dispatching messages.  Messages posted before `start()` is called
   * are buffered and flushed when start is invoked.
   */
  start(): void {
    if (this.#started) {
      return; // Idempotent
    }

    this.#started = true;

    // Flush any queued messages
    if (this.#queue.length > 0) {
      const pending = this.#queue.splice(0);
      for (const data of pending) {
        queueMicrotask(() => {
          if (!this.#closed) {
            this.#dispatchMessage(data);
          }
        });
      }
    }
  }

  /**
   * Disentangle this port.  After calling `close()`, no more messages will
   * be sent or received through this port.
   */
  close(): void {
    this.#closed = true;
    this.#queue.length = 0;
    this.#remotePort = null;
    this.#onmessage = null;
    this.#onmessageerror = null;
  }

  // -- Internal wiring (used by MessageChannel) ----------------------------

  /** @internal Wire this port to its remote partner. */
  _setRemotePort(remote: MessagePort): void {
    this.#remotePort = remote;
  }

  [structuredCloneTransferSymbol](): MessagePort {
    const transferredPort = new MessagePort();
    const remote = this.#remotePort;

    transferredPort.#queue = this.#queue;
    transferredPort.#started = this.#started;

    if (remote && !remote.#closed) {
      transferredPort._setRemotePort(remote);
      remote._setRemotePort(transferredPort);
    }

    this.#queue = [];
    this.#started = false;
    this.#closed = true;
    this.#remotePort = null;
    this.#onmessage = null;
    this.#onmessageerror = null;

    return transferredPort;
  }

  // -- Private helpers ------------------------------------------------------

  #dispatchMessage(data: unknown): void {
    const event = new MessageEvent('message', { data });

    // Call the IDL onmessage handler first
    if (this.#onmessage) {
      try {
        this.#onmessage.call(this, event);
      } catch (error) {
        console.error('[MessagePort] onmessage handler threw:', error);
      }
    }

    // Then dispatch to addEventListener listeners
    this.dispatchEvent(event);
  }

  #dispatchMessageError(error: unknown): void {
    const event = new MessageEvent('messageerror', { data: error });

    if (this.#onmessageerror) {
      try {
        this.#onmessageerror.call(this, event);
      } catch (e) {
        console.error('[MessagePort] onmessageerror handler threw:', e);
      }
    }

    this.dispatchEvent(event);
  }

  // -- Symbol.toStringTag ---------------------------------------------------

  get [Symbol.toStringTag](): string {
    return 'MessagePort';
  }
}

// ---------------------------------------------------------------------------
// MessageChannel
// ---------------------------------------------------------------------------

/**
 * A MessageChannel creates a pair of entangled MessagePort objects.  Messages
 * posted on one port are delivered to the other and vice versa.
 */
export class MessageChannel {
  readonly port1: MessagePort;
  readonly port2: MessagePort;

  constructor() {
    this.port1 = new MessagePort();
    this.port2 = new MessagePort();

    // Wire the two ports together
    this.port1._setRemotePort(this.port2);
    this.port2._setRemotePort(this.port1);
  }

  get [Symbol.toStringTag](): string {
    return 'MessageChannel';
  }
}
