// @ts-nocheck
/**
 * EventSource implementation for Ibex runtime
 *
 * Implements the WHATWG EventSource (Server-Sent Events) API.
 * @see https://html.spec.whatwg.org/multipage/server-sent-events.html
 */

import { EventTarget } from '../events/EventTarget';
import { Event } from '../events/Event';
import { MessageEvent } from '../events/MessageEvent';

// EventSource ready states
const CONNECTING = 0;
const OPEN = 1;
const CLOSED = 2;

// Default reconnection time in milliseconds
const DEFAULT_RECONNECT_TIME = 3000;

// Maximum reconnection time (cap for exponential backoff)
const MAX_RECONNECT_TIME = 60000;

/**
 * EventSourceInit options for the EventSource constructor.
 */
export interface EventSourceInit {
  withCredentials?: boolean;
}

/**
 * EventSource provides a persistent connection to a server that sends events
 * in the text/event-stream format. Unlike WebSocket, EventSource is a
 * unidirectional channel (server to client only).
 */
export class EventSource extends EventTarget {
  // Ready state constants (static)
  static readonly CONNECTING = CONNECTING;
  static readonly OPEN = OPEN;
  static readonly CLOSED = CLOSED;

  // Ready state constants (instance)
  readonly CONNECTING = CONNECTING;
  readonly OPEN = OPEN;
  readonly CLOSED = CLOSED;

  // Public properties
  readonly url: string;
  readonly withCredentials: boolean;

  // Internal state
  #readyState: number = CONNECTING;
  #reconnectionTime: number = DEFAULT_RECONNECT_TIME;
  #lastEventId: string = '';
  #abortController: AbortController | null = null;
  #reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  #consecutiveFailures: number = 0;

  // Event handler properties
  onopen: ((this: EventSource, ev: Event) => any) | null = null;
  onmessage: ((this: EventSource, ev: MessageEvent) => any) | null = null;
  onerror: ((this: EventSource, ev: Event) => any) | null = null;

  constructor(url: string | URL, eventSourceInitDict?: EventSourceInit) {
    super();

    // Normalize URL
    const urlString = url instanceof URL ? url.href : url;

    // Validate URL
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlString);
    } catch {
      throw new DOMException('Invalid URL', 'SyntaxError');
    }

    this.url = parsedUrl.href;
    this.withCredentials = eventSourceInitDict?.withCredentials ?? false;

    // Start connection
    this.#connect();
  }

  get readyState(): number {
    return this.#readyState;
  }

  /**
   * Close the EventSource connection.
   */
  close(): void {
    if (this.#readyState === CLOSED) {
      return;
    }

    this.#readyState = CLOSED;

    // Abort any in-flight fetch
    if (this.#abortController) {
      this.#abortController.abort();
      this.#abortController = null;
    }

    // Clear any pending reconnect timer
    if (this.#reconnectTimer !== null) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
  }

  /**
   * Initiate the fetch connection to the SSE endpoint.
   */
  #connect(): void {
    if (this.#readyState === CLOSED) {
      return;
    }

    this.#readyState = CONNECTING;
    this.#abortController = new AbortController();

    const headers: Record<string, string> = {
      'Accept': 'text/event-stream',
      'Cache-Control': 'no-cache',
    };

    // Send Last-Event-ID on reconnects
    if (this.#lastEventId) {
      headers['Last-Event-ID'] = this.#lastEventId;
    }

    fetch(this.url, {
      headers,
      signal: this.#abortController.signal,
      cache: 'no-store' as any,
    })
      .then((response) => {
        if (this.#readyState === CLOSED) {
          return;
        }

        // Per the SSE spec a non-200 status must fail the connection
        // permanently. `response.ok` also accepts 201-299, which the spec
        // treats as failure, so check for exactly 200.
        if (response.status !== 200) {
          this.#failConnection();
          return;
        }

        // A missing or incorrect Content-Type must also fail permanently.
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('text/event-stream')) {
          this.#failConnection();
          return;
        }

        // Connection established
        this.#readyState = OPEN;
        this.#consecutiveFailures = 0;

        const openEvent = new Event('open');
        if (this.onopen) {
          this.onopen.call(this, openEvent);
        }
        this.dispatchEvent(openEvent);

        // Read the stream
        this.#readStream(response);
      })
      .catch((error) => {
        if (this.#readyState === CLOSED) {
          return;
        }

        // AbortError means we called close() or are reconnecting
        if (error && error.name === 'AbortError') {
          return;
        }

        // A network-level failure is transient: reconnect per the spec.
        this.#reestablishConnection();
      });
  }

  /**
   * Read the response body as a stream and parse SSE events.
   */
  async #readStream(response: Response): Promise<void> {
    const body = response.body;
    if (!body) {
      this.#reestablishConnection();
      return;
    }

    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    // SSE parser state
    let eventType = '';
    let dataBuffer = '';
    let lastEventId: string | undefined;

    try {
      while (true) {
        if (this.#readyState === CLOSED) {
          try {
            reader.cancel().catch(() => {});
          } catch (_) {}
          return;
        }

        const { done, value } = await reader.read();

        if (done) {
          // Stream ended - attempt reconnect
          if (this.#readyState !== CLOSED) {
            this.#reestablishConnection();
          }
          return;
        }

        buffer += decoder.decode(value, { stream: true });

        // Process complete lines
        let lineEnd: number;
        while ((lineEnd = buffer.indexOf('\n')) !== -1) {
          const line = buffer.substring(0, lineEnd);
          buffer = buffer.substring(lineEnd + 1);

          // Remove trailing \r if present (handle \r\n line endings)
          const cleanLine = line.endsWith('\r') ? line.slice(0, -1) : line;

          if (cleanLine === '') {
            // Empty line = dispatch event
            if (dataBuffer !== '') {
              // Remove trailing newline from data buffer
              if (dataBuffer.endsWith('\n')) {
                dataBuffer = dataBuffer.slice(0, -1);
              }

              const eventName = eventType || 'message';

              if (lastEventId !== undefined) {
                this.#lastEventId = lastEventId;
              }

              const messageEvent = new MessageEvent(eventName, {
                data: dataBuffer,
                origin: new URL(this.url).origin,
                lastEventId: this.#lastEventId,
              });

              // Fire onmessage only for "message" type events
              if (eventName === 'message' && this.onmessage) {
                this.onmessage.call(this, messageEvent);
              }
              this.dispatchEvent(messageEvent);
            }

            // Reset per-event state
            eventType = '';
            dataBuffer = '';
            lastEventId = undefined;
          } else if (cleanLine.startsWith(':')) {
            // Comment line - ignore
          } else {
            // Parse field
            const colonIndex = cleanLine.indexOf(':');
            let field: string;
            let fieldValue: string;

            if (colonIndex === -1) {
              // No colon: treat entire line as field name with empty value
              field = cleanLine;
              fieldValue = '';
            } else {
              field = cleanLine.substring(0, colonIndex);
              // Skip optional space after colon
              fieldValue = cleanLine.substring(colonIndex + 1);
              if (fieldValue.startsWith(' ')) {
                fieldValue = fieldValue.substring(1);
              }
            }

            switch (field) {
              case 'data':
                dataBuffer += fieldValue + '\n';
                break;
              case 'event':
                eventType = fieldValue;
                break;
              case 'id':
                // Per spec: if the field value does not contain U+0000 NULL
                if (!fieldValue.includes('\0')) {
                  lastEventId = fieldValue;
                }
                break;
              case 'retry':
                // Only set if the value consists solely of ASCII digits
                if (/^\d+$/.test(fieldValue)) {
                  this.#reconnectionTime = parseInt(fieldValue, 10);
                }
                break;
              // Unknown fields are ignored per spec
            }
          }
        }
      }
    } catch (error: any) {
      if (this.#readyState === CLOSED) {
        return;
      }

      if (error && error.name === 'AbortError') {
        return;
      }

      // Stream read error - transient, attempt reconnect
      this.#reestablishConnection();
    }
  }

  /**
   * Permanently fail the connection: set readyState to CLOSED, fire a single
   * error event, and never reconnect. Per the SSE spec this is required when
   * the server responds with a non-200 status or a wrong/absent Content-Type.
   */
  #failConnection(): void {
    if (this.#readyState === CLOSED) {
      return;
    }

    this.#readyState = CLOSED;

    // Abort the in-flight fetch and cancel any pending reconnect.
    if (this.#abortController) {
      this.#abortController.abort();
      this.#abortController = null;
    }
    if (this.#reconnectTimer !== null) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }

    const errorEvent = new Event('error');
    if (this.onerror) {
      this.onerror.call(this, errorEvent);
    }
    this.dispatchEvent(errorEvent);
  }

  /**
   * Reestablish the connection after a transient failure (network error, null
   * body, or a stream read error): fire an error event, then schedule a
   * reconnect with backoff. Unlike failing the connection, the EventSource
   * stays alive and keeps trying.
   */
  #reestablishConnection(): void {
    if (this.#readyState === CLOSED) {
      return;
    }

    this.#readyState = CONNECTING;
    const errorEvent = new Event('error');
    if (this.onerror) {
      this.onerror.call(this, errorEvent);
    }
    this.dispatchEvent(errorEvent);

    this.#scheduleReconnect();
  }

  /**
   * Schedule a reconnection attempt with exponential backoff.
   */
  #scheduleReconnect(): void {
    if (this.#readyState === CLOSED) {
      return;
    }

    this.#readyState = CONNECTING;
    this.#consecutiveFailures++;

    // Exponential backoff: reconnectionTime * 2^(failures-1), capped at MAX
    const backoff = Math.min(
      this.#reconnectionTime * Math.pow(2, this.#consecutiveFailures - 1),
      MAX_RECONNECT_TIME
    );

    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      if (this.#readyState !== CLOSED) {
        this.#connect();
      }
    }, backoff);
  }

  get [Symbol.toStringTag](): string {
    return 'EventSource';
  }
}

export default EventSource;
