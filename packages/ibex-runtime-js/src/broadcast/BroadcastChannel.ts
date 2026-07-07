/**
 * BroadcastChannel - Cross-context messaging API
 * 
 * Allows communication between different browsing contexts (views, windows)
 * with the same origin. In Exact, this enables communication between
 * different views within the same app.
 * 
 * @see https://html.spec.whatwg.org/multipage/web-messaging.html#broadcasting-to-other-browsing-contexts
 */

import { EventTarget } from '../events/EventTarget';
import { MessageEvent } from '../events/MessageEvent';
import { structuredClone } from '../clone/structuredClone';

/**
 * Registry of all active BroadcastChannel instances by channel name.
 * This enables message delivery within the same runtime.
 * 
 * For cross-view messaging, the native layer should call
 * `BroadcastChannel._deliverMessage(name, data)` when a message arrives
 * from another view.
 */
const channelRegistry = new Map<string, Set<BroadcastChannel>>();

/**
 * Native broadcast module interface for cross-view messaging.
 * The native layer should provide this for true cross-context communication.
 */
interface NativeBroadcastModule {
  /**
   * Post a message to all other contexts with channels of this name.
   */
  postMessage(channelName: string, data: unknown): void;
  
  /**
   * Register a channel to receive messages from other contexts.
   */
  registerChannel(channelName: string): void;
  
  /**
   * Unregister a channel (called when all local channels with this name close).
   */
  unregisterChannel(channelName: string): void;
}

let nativeBroadcastModule: NativeBroadcastModule | null = null;

/**
 * Set the native broadcast module for cross-view messaging.
 * Called by the native layer during initialization.
 */
export function setNativeBroadcastModule(module: NativeBroadcastModule): void {
  nativeBroadcastModule = module;
}

/**
 * BroadcastChannel enables simple communication between browsing contexts
 * (views, windows, tabs) with the same origin.
 * 
 * Messages sent via postMessage() are delivered to all other BroadcastChannel
 * objects with the same name, but NOT to the sender.
 * 
 * @example
 * ```ts
 * // In View A
 * const channel = new BroadcastChannel('my-channel');
 * channel.postMessage({ type: 'update', data: 'hello' });
 * 
 * // In View B
 * const channel = new BroadcastChannel('my-channel');
 * channel.onmessage = (event) => {
 *   console.log('Received:', event.data);
 * };
 * ```
 */
export class BroadcastChannel extends EventTarget {
  readonly name: string;
  
  #closed = false;
  
  // Event handlers
  onmessage: ((this: BroadcastChannel, ev: MessageEvent) => any) | null = null;
  onmessageerror: ((this: BroadcastChannel, ev: MessageEvent) => any) | null = null;

  constructor(name: string) {
    super();
    
    // Convert to string per spec
    this.name = String(name);
    
    // Register in the channel registry
    let channels = channelRegistry.get(this.name);
    if (!channels) {
      channels = new Set();
      channelRegistry.set(this.name, channels);
      
      // Notify native layer of new channel name
      nativeBroadcastModule?.registerChannel(this.name);
    }
    channels.add(this);
  }

  /**
   * Send a message to all other BroadcastChannel objects with the same name.
   * The message is NOT delivered to this channel instance.
   * 
   * @param message - The message to send (will be structured cloned)
   * @throws DOMException if the channel is closed
   */
  postMessage(message: unknown): void {
    if (this.#closed) {
      throw new DOMException(
        'BroadcastChannel is closed',
        'InvalidStateError'
      );
    }

    // Clone failure is a sender-side StructuredSerialize failure and must
    // throw synchronously; messageerror is reserved for receive-side failures.
    const clonedMessage = structuredClone(message);

    // Deliver to all other local channels with the same name
    const channels = channelRegistry.get(this.name);
    if (channels) {
      for (const channel of channels) {
        if (channel !== this && !channel.#closed) {
          // Queue message delivery asynchronously per spec
          queueMicrotask(() => {
            if (!channel.#closed) {
              channel.#receiveMessage(clonedMessage);
            }
          });
        }
      }
    }

    // Send to native layer for cross-view delivery
    if (nativeBroadcastModule) {
      try {
        nativeBroadcastModule.postMessage(this.name, clonedMessage);
      } catch (error) {
        // Native errors are logged but don't affect local delivery
        console.warn('[BroadcastChannel] Native postMessage failed:', error);
      }
    }
  }

  /**
   * Close this BroadcastChannel. After closing, postMessage() will throw
   * and no more messages will be received.
   */
  close(): void {
    if (this.#closed) {
      return;
    }
    
    this.#closed = true;
    
    // Remove from registry
    const channels = channelRegistry.get(this.name);
    if (channels) {
      channels.delete(this);
      
      // If no more channels with this name, clean up
      if (channels.size === 0) {
        channelRegistry.delete(this.name);
        
        // Notify native layer
        nativeBroadcastModule?.unregisterChannel(this.name);
      }
    }
  }

  /**
   * Internal method to receive a message.
   * Called when a message arrives from another channel.
   */
  #receiveMessage(data: unknown): void {
    if (this.#closed) {
      return;
    }

    const event = new MessageEvent('message', {
      data,
      origin: '', // Same-origin, no origin needed
    });

    // Call onmessage handler
    if (this.onmessage) {
      try {
        this.onmessage.call(this, event);
      } catch (error) {
        console.error('[BroadcastChannel] onmessage handler threw:', error);
      }
    }

    // Dispatch event
    this.dispatchEvent(event);
  }

  /**
   * Static method for native layer to deliver messages from other contexts.
   * This should be called when a message arrives from another view.
   * 
   * @param channelName - The channel name
   * @param data - The message data (already cloned by sender)
   */
  static _deliverMessage(channelName: string, data: unknown): void {
    const channels = channelRegistry.get(channelName);
    if (channels) {
      for (const channel of channels) {
        if (!channel.#closed) {
          queueMicrotask(() => {
            if (!channel.#closed) {
              channel.#receiveMessage(data);
            }
          });
        }
      }
    }
  }

  /**
   * Static method to get the count of active channels for a name.
   * Useful for debugging and testing.
   */
  static _getChannelCount(channelName: string): number {
    return channelRegistry.get(channelName)?.size ?? 0;
  }

  /**
   * Static method to get all active channel names.
   * Useful for debugging.
   */
  static _getChannelNames(): string[] {
    return Array.from(channelRegistry.keys());
  }

  get [Symbol.toStringTag](): string {
    return 'BroadcastChannel';
  }
}

export default BroadcastChannel;
