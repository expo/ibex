import { afterEach, describe, expect, test } from "bun:test";
import dgram, { type Socket } from "node:dgram";

// Load Ibex's implementation rather than Bun's node:dns builtin. The custom
// Resolver path is pure JS over dgram, so a real loopback UDP peer exercises
// the exact parser/retry/rotation code without relying on public DNS.
const ibexDns = require("../../../src/builtins/dns.js");

const sockets: Socket[] = [];

afterEach(() => {
  for (const socket of sockets.splice(0)) {
    try {
      socket.close();
    } catch {}
  }
});

async function answerServer(label: string): Promise<number> {
  const socket = dgram.createSocket("udp4");
  sockets.push(socket);
  socket.on("message", (query, peer) => {
    socket.send(dnsTxtResponse(query, label), peer.port, peer.address);
  });
  await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));
  return (socket.address() as { port: number }).port;
}

function dnsTxtResponse(query: Buffer, label: string): Buffer {
  const response = Buffer.from(query);
  response.writeUInt16BE(0x8180, 2); // QR | RD | RA, NOERROR
  response.writeUInt16BE(1, 6); // one answer
  const text = Buffer.from(label);
  const answer = Buffer.alloc(13 + text.length);
  answer.writeUInt16BE(0xc00c, 0); // name pointer -> question
  answer.writeUInt16BE(16, 2); // TXT
  answer.writeUInt16BE(1, 4); // IN
  answer.writeUInt32BE(60, 6); // TTL
  answer.writeUInt16BE(text.length + 1, 10);
  answer[12] = text.length;
  text.copy(answer, 13);
  return Buffer.concat([response, answer]);
}

function resolveTxt(resolver: any): Promise<string[][]> {
  return new Promise((resolve, reject) => {
    resolver.resolveTxt("custom-resolver.test", (error: Error | null, records: string[][]) => {
      if (error) reject(error);
      else resolve(records);
    });
  });
}

describe("Ibex custom DNS Resolver", () => {
  test("rejects invalid rrtypes before every custom resolver packet path", async () => {
    const resolver = new ibexDns.Resolver({ timeout: 25, tries: 1 });
    resolver.setServers(["127.0.0.1:9"]);
    expect(() => resolver.resolve("custom-resolver.test", "BOGUS", () => {})).toThrow(
      /rrtype.*invalid/i,
    );

    const promiseResolver = new ibexDns.promises.Resolver({ timeout: 25, tries: 1 });
    promiseResolver.setServers(["127.0.0.1:9"]);
    await expect(promiseResolver.resolve("custom-resolver.test", "BOGUS")).rejects.toMatchObject({
      code: "ERR_INVALID_ARG_VALUE",
    });
  });

  test("an explicitly empty custom server list fails asynchronously without crashing", async () => {
    const resolver = new ibexDns.Resolver({ timeout: 25, tries: 1 });
    resolver.setServers([]);
    const error = await new Promise<any>((resolve) => {
      resolver.resolve("custom-resolver.test", "A", (err: any) => resolve(err));
    });
    expect(error).toMatchObject({ code: "ENOTSUP" });

    const promiseResolver = new ibexDns.promises.Resolver({ timeout: 25, tries: 1 });
    promiseResolver.setServers([]);
    await expect(promiseResolver.resolve("custom-resolver.test", "A")).rejects.toMatchObject({
      code: "ENOTSUP",
    });
  });

  test("performs a real UDP query through Resolver.setServers", async () => {
    const port = await answerServer("ibex-custom");
    const resolver = new ibexDns.Resolver({ timeout: 100, tries: 1 });
    resolver.setServers([`127.0.0.1:${port}`]);
    expect(await resolveTxt(resolver)).toEqual([["ibex-custom"]]);
  });

  test("rotates the starting server across queries", async () => {
    const first = await answerServer("first");
    const second = await answerServer("second");
    const resolver = new ibexDns.Resolver({ timeout: 100, tries: 1 });
    resolver.setServers([`127.0.0.1:${first}`, `127.0.0.1:${second}`]);
    expect(await resolveTxt(resolver)).toEqual([["first"]]);
    expect(await resolveTxt(resolver)).toEqual([["second"]]);
  });

  test("retries a dead starting server on the next configured server", async () => {
    const reservation = dgram.createSocket("udp4");
    await new Promise<void>((resolve) => reservation.bind(0, "127.0.0.1", resolve));
    const deadPort = (reservation.address() as { port: number }).port;
    reservation.close();
    const livePort = await answerServer("fallback");
    const resolver = new ibexDns.Resolver({ timeout: 25, maxTimeout: 25, tries: 2 });
    resolver.setServers([`127.0.0.1:${deadPort}`, `127.0.0.1:${livePort}`]);
    expect(await resolveTxt(resolver)).toEqual([["fallback"]]);
  });

  test("ignores a matching-id response that echoes the wrong question", async () => {
    const socket = dgram.createSocket("udp4");
    sockets.push(socket);
    socket.on("message", (query, peer) => {
      const forged = dnsTxtResponse(query, "wrong-question");
      // Same encoded-label length, but a different question name.
      forged[13] = forged[13] === 0x63 ? 0x78 : 0x63;
      socket.send(forged, peer.port, peer.address);
      setTimeout(() => {
        socket.send(dnsTxtResponse(query, "verified-question"), peer.port, peer.address);
      }, 10);
    });
    await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));

    const resolver = new ibexDns.Resolver({ timeout: 100, tries: 1 });
    resolver.setServers([`127.0.0.1:${(socket.address() as any).port}`]);
    expect(await resolveTxt(resolver)).toEqual([["verified-question"]]);
  });

  test("connected resolver socket rejects a forged response from another source port", async () => {
    const server = dgram.createSocket("udp4");
    const attacker = dgram.createSocket("udp4");
    sockets.push(server, attacker);
    await new Promise<void>((resolve) => attacker.bind(0, "127.0.0.1", resolve));
    server.on("message", (query, peer) => {
      attacker.send(dnsTxtResponse(query, "forged-source"), peer.port, peer.address);
      setTimeout(() => {
        server.send(dnsTxtResponse(query, "real-source"), peer.port, peer.address);
      }, 10);
    });
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", resolve));

    const resolver = new ibexDns.Resolver({ timeout: 100, tries: 1 });
    resolver.setServers([`127.0.0.1:${(server.address() as any).port}`]);
    expect(await resolveTxt(resolver)).toEqual([["real-source"]]);
  });

  test("uses noncolliding unpredictable transaction ids for concurrent queries", async () => {
    const socket = dgram.createSocket("udp4");
    sockets.push(socket);
    const ids: number[] = [];
    socket.on("message", (query, peer) => {
      ids.push(query.readUInt16BE(0));
      socket.send(dnsTxtResponse(query, "random-id"), peer.port, peer.address);
    });
    await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));

    const resolver = new ibexDns.Resolver({ timeout: 200, tries: 1 });
    resolver.setServers([`127.0.0.1:${(socket.address() as any).port}`]);
    await Promise.all(Array.from({ length: 32 }, () => resolveTxt(resolver)));
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every((id, index) => index === 0 || id === ((ids[index - 1] + 1) & 0xffff))).toBe(false);
  });
});
