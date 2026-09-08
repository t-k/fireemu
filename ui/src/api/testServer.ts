import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** One request the server saw, as the client sent it. */
export type Seen = {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
};

export type Scripted = {
  status?: number;
  headers?: Record<string, string>;
  body?: string | Buffer;
  /** Writes the response in pieces with a pause between them (streams). */
  chunks?: (string | Buffer)[];
  /** Ends the socket without a response. */
  drop?: boolean;
};

/**
 * A real HTTP server for the API client tests: every request is recorded and answered from a
 * script keyed by `METHOD path` (path without the query), else 404.
 */
export const startTestServer = async (): Promise<{
  base: string;
  seen: Seen[];
  script: Map<string, Scripted | ((req: Seen) => Scripted)>;
  close: () => Promise<void>;
}> => {
  const seen: Seen[] = [];
  const script = new Map<string, Scripted | ((req: Seen) => Scripted)>();
  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = await new Promise<string>((resolve) => {
      let text = "";
      req.on("data", (d: Buffer) => {
        text += d.toString();
      });
      req.on("end", () => resolve(text));
    });
    const record: Seen = {
      method: req.method ?? "",
      url: req.url ?? "",
      headers: req.headers,
      body,
    };
    seen.push(record);
    const path = (req.url ?? "").split("?")[0] ?? "";
    const entry = script.get(`${req.method} ${path}`);
    const answer = typeof entry === "function" ? entry(record) : entry;
    if (!answer) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: `no script for ${req.method} ${path}` } }));
      return;
    }
    if (answer.drop) {
      req.socket.destroy();
      return;
    }
    res.writeHead(answer.status ?? 200, answer.headers ?? {});
    if (answer.chunks) {
      for (const chunk of answer.chunks) {
        res.write(chunk);
        await new Promise((r) => setTimeout(r, 5));
      }
      res.end();
      return;
    }
    res.end(answer.body ?? "");
  };
  const server: Server = createServer((req, res) => void handle(req, res));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}/ui/api`,
    seen,
    script,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
};
