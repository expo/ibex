import http from "node:http";

const expectedBody = "ibex-standalone-http-server";
let server: ReturnType<typeof http.createServer> | undefined;

const roundTrip = new Promise<string>((resolve) => {
  server = http.createServer((_request, response) => {
    response.statusCode = 200;
    response.end(expectedBody);
  });
  server.once("error", (error: unknown) => {
    resolve(`error:${error instanceof Error ? error.message : String(error)}`);
  });
  server.listen(0, "127.0.0.1", async () => {
    try {
      const address = server?.address();
      if (!address || typeof address === "string") {
        resolve("error:server address unavailable");
        return;
      }
      const response = await fetch(`http://127.0.0.1:${address.port}/proof`);
      resolve(`${response.status}:${await response.text()}`);
    } catch (error) {
      resolve(`error:${error instanceof Error ? error.message : String(error)}`);
    } finally {
      server?.close();
    }
  });
});

const timeout = new Promise<string>((resolve) => {
  setTimeout(() => {
    server?.close();
    resolve("error:server round trip timed out");
  }, 2_000);
});

const result = await Promise.race([roundTrip, timeout]);
console.log(`http-server=${result}`);
process.exitCode = result === `200:${expectedBody}` ? 0 : 33;
