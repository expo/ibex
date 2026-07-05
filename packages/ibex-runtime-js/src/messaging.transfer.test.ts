// ENG-22977 — MessagePort.postMessage must transfer ports listed in the
// transfer list and surface them to the receiver as MessageEvent.ports.
// Previously delivery always passed [] as the port list, so event.ports was
// always empty and the canonical `port.postMessage(msg, [channel.port2])`
// pattern (port only in the transfer list, not the message graph) neither
// transferred nor delivered the port — `e.ports[0]` was undefined.
//
// Covers both the live implementation (src/messaging.ts, used by bootstrap) and
// the parallel implementation under src/messaging/ referenced by the audit.
//
// Run with: bun test.

import { expect, test, describe } from 'bun:test';
import { MessageChannel as LiveMessageChannel } from './messaging';
import { MessageChannel as DirMessageChannel } from './messaging/index';

type ChannelCtor = typeof LiveMessageChannel;

const implementations: Array<[string, ChannelCtor]> = [
  ['messaging.ts (live)', LiveMessageChannel as ChannelCtor],
  ['messaging/ (directory)', DirMessageChannel as unknown as ChannelCtor],
];

for (const [label, MessageChannel] of implementations) {
  describe(label, () => {
    test('a port in the transfer list is delivered as event.ports and stays entangled', async () => {
      const transport = new MessageChannel();
      const moved = new MessageChannel();

      const received = new Promise<any>((resolve) => {
        (transport.port2 as any).onmessage = (e: any) => resolve(e);
      });

      // Port only appears in the transfer list, never in the message body.
      (transport.port1 as any).postMessage('hello', [moved.port2]);

      const event = await received;
      expect(event.data).toBe('hello');
      expect(event.ports.length).toBe(1);

      // The delivered port must be entangled with moved.port1: a message from
      // moved.port1 must arrive at event.ports[0].
      const roundTrip = new Promise<any>((resolve) => {
        event.ports[0].onmessage = (ev: any) => resolve(ev.data);
      });
      (moved.port1 as any).postMessage('via-transferred-port');
      expect(await roundTrip).toBe('via-transferred-port');
    });

    test('ports queued before the receiver starts are still delivered as event.ports', async () => {
      const transport = new MessageChannel();
      const moved = new MessageChannel();

      // Post BEFORE wiring onmessage, so the message is buffered in the queue.
      (transport.port1 as any).postMessage('queued', [moved.port2]);

      const event = await new Promise<any>((resolve) => {
        // Setting onmessage starts the port and flushes the queue.
        (transport.port2 as any).onmessage = (e: any) => resolve(e);
      });

      expect(event.data).toBe('queued');
      expect(event.ports.length).toBe(1);
    });

    test('a transferred ArrayBuffer moves via the message and is not added to event.ports', async () => {
      const transport = new MessageChannel();
      const buf = new ArrayBuffer(8);
      new Uint8Array(buf).fill(3);

      const event = await new Promise<any>((resolve) => {
        (transport.port2 as any).onmessage = (e: any) => resolve(e);
        (transport.port1 as any).postMessage({ buf }, [buf]);
      });

      expect(event.ports.length).toBe(0);
      expect(new Uint8Array(event.data.buf)[0]).toBe(3);
      // Source buffer detached by the transfer.
      expect(buf.byteLength).toBe(0);
    });
  });
}
