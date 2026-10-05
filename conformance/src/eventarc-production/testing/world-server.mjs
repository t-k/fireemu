// The model of the channel service (world.mjs) behind a loopback HTTP server, for the tests that run the
// recorder end to end through its real transport and the Admin SDK forwarder. The server derives the
// operation from the method and the path, like the service routes do.

import { createServer } from "node:http";

function operationOf(method, pathname) {
  if (method === "POST" && pathname.endsWith(":publishEvents")) return "publishEvents";
  if (method === "POST" && pathname.endsWith("/channels")) return "createChannel";
  if (method === "DELETE") return "deleteChannel";
  if (method === "GET" && /\/services\/[^/]+$/.test(pathname)) return "getService";
  if (method === "GET" && /\/operations\//.test(pathname)) return "getOperation";
  if (method === "GET" && pathname.endsWith("/channels")) return "listChannels";
  if (method === "GET" && /\/channels\/[^/]+$/.test(pathname)) return "getChannel";
  return null;
}

export async function serveWorld(world) {
  const seen = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", async () => {
      const url = new URL(request.url, "http://world");
      const op = operationOf(request.method, url.pathname);
      let body;
      const text = Buffer.concat(chunks).toString("utf8");
      if (text !== "") body = JSON.parse(text);
      seen.push({ method: request.method, url: request.url, headers: request.headers, body });
      response.setHeader("content-type", "application/json");
      if (op === null) {
        response.statusCode = 404;
        return response.end('{"error":{"status":"NOT_FOUND"}}');
      }
      const answer = await world.request({ op, method: request.method, path: request.url, body });
      response.statusCode = answer.status;
      response.end(JSON.stringify(answer.body ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    seen,
    host: `http://127.0.0.1:${server.address().port}`,
    close: () => server.closeAllConnections?.() ?? server.close(),
  };
}
