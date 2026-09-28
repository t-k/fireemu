import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { createLocalWireTransport } from "./local-wire-transport.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

// Run under portctl: this opt-in validator owns its listener and every accepted socket.
const port = Number(process.env.PORT);
if (!Number.isInteger(port) || port < 1024 || port > 65535 || !process.env.PORT_REGISTRY_TOKEN)
  throw new Error("a portctl claim is required");
const directory = mkdtempSync(join(tmpdir(), "storage-object-wire-"));
const keyPath = join(directory, "tls-key.pem"),
  certPath = join(directory, "tls-cert.pem");
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ],
  { stdio: "ignore" },
);
chmodSync(keyPath, 0o600);
chmodSync(certPath, 0o600);
const plan = buildStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["wireproofone", "wireprooftwo"],
});
const results = [];
const normal = Buffer.from(
  "HTTP/1.1 103 Early Hints\r\nLink: </example>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-Probe: one\r\nx-probe: two\r\n\r\n3;custom=yes\r\nabc\r\n0\r\nX-Trailer: synthetic\r\n\r\n",
);

async function runServer(secure, responses, run) {
  const sockets = new Set();
  const received = [];
  const accept = (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    const chunks = [];
    let bytes = 0;
    let sent = false;
    socket.on("data", (chunk) => {
      if (sent) return;
      bytes += chunk.length;
      if (bytes > 3 * 1024 * 1024) throw new Error("local receiver bound exceeded");
      chunks.push(chunk);
      const raw = Buffer.concat(chunks, bytes);
      const end = raw.indexOf("\r\n\r\n");
      if (end < 0) return;
      const length = /\r\nContent-Length: (\d+)\r\n/.exec(raw.toString("latin1", 0, end + 2));
      if (!length || raw.length < end + 4 + Number(length[1])) return;
      sent = true;
      received.push(raw);
      const response = responses[received.length - 1];
      if (response === null) return;
      if (!response) throw new Error("unexpected local request");
      if (Array.isArray(response)) {
        for (const part of response) socket.write(part);
        socket.end();
      } else socket.end(response);
    });
  };
  const server = secure
    ? tls.createServer(
        { key: readFileSync(keyPath), cert: readFileSync(certPath), ALPNProtocols: ["http/1.1"] },
        accept,
      )
    : net.createServer(accept);
  server.on("tlsClientError", () => {});
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  try {
    await run(`${secure ? "https" : "http"}://127.0.0.1:${port}`, received);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

for (const secure of [false, true]) {
  const root = join(directory, secure ? "tls" : "http");
  mkdirSync(root, { mode: 0o700 });
  await runServer(secure, [normal, normal, normal, normal, normal], async (origin, received) => {
    const client = createLocalWireTransport({
      origins: [origin],
      limits: plan,
      captureDirectory: root,
      localCa: readFileSync(certPath),
      onByteReserve: async () => {},
    });
    try {
      for (const [index, method] of ["GET", "POST", "PUT", "PATCH", "DELETE"].entries()) {
        const response = await client.fetch(`${origin}/encoded%2Fname?key=synthetic%2Fkey`, {
          method,
          headers: { "x-fixture": "synthetic-private-token" },
          ...(method === "GET" || method === "DELETE"
            ? {}
            : { body: index === 1 ? '{"value":"日本語"}' : Buffer.from([0, 255, 1]) }),
          operationId: `wire/${method.toLowerCase()}`,
          accountingPhase: index % 2 === 0 ? "subject" : "cleanup",
        });
        assert.equal(response.status, 200);
        assert.equal(Buffer.from(await response.arrayBuffer()).toString(), "abc");
        const stem = String(index + 1).padStart(6, "0");
        assert.deepEqual(readFileSync(join(root, `${stem}-request.bin`)), received[index]);
        assert.deepEqual(readFileSync(join(root, `${stem}-response.bin`)), normal);
      }
    } finally {
      await client.close();
    }
    assert.equal(client.snapshot().attempts, 5);
    assert.equal(client.snapshot().responseObservedBytes, normal.length * 5);
    assert.equal(client.snapshot().readAfterHaltBytes, 0);
    results.push({
      case: secure ? "TLS_FULL_RAW_CAPTURE" : "HTTP_FULL_RAW_CAPTURE",
      requests: 5,
      wire: client.snapshot(),
    });
  });
}

for (const secure of [false, true]) {
  const root = join(directory, secure ? "tls-overflow" : "http-overflow");
  mkdirSync(root, { mode: 0o700 });
  const header = Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Length: 20000\r\nConnection: close\r\n\r\n",
  );
  const overflow = Buffer.concat([header, Buffer.alloc(20000, 65)]);
  await runServer(secure, [overflow], async (origin, received) => {
    const client = createLocalWireTransport({
      origins: [origin],
      limits: { ...plan, maxPerResponseWireBytes: 8192 },
      captureDirectory: root,
      localCa: readFileSync(certPath),
      onByteReserve: async () => {},
    });
    try {
      await assert.rejects(
        client.fetch(`${origin}/overflow`, {
          operationId: "wire/overflow",
          accountingPhase: "subject",
        }),
        /WIRE_RESPONSE_CAP_EXCEEDED/,
      );
      await assert.rejects(
        client.fetch(`${origin}/no-retry`, {
          operationId: "wire/next",
          accountingPhase: "cleanup",
        }),
        /WIRE_BUDGET_HALTED/,
      );
    } finally {
      await client.close();
    }
    const state = client.snapshot();
    assert.equal(received.length, 1);
    assert.equal(state.halted, true);
    assert.ok(state.responseObservedBytes > 8192 && state.responseObservedBytes <= 16384);
    assert.ok(state.largestResponseReadBytes <= 8192);
    assert.equal(state.readAfterHaltBytes, 0);
    assert.equal(
      readFileSync(join(root, "000001-response.bin")).length,
      state.responseObservedBytes,
    );
    results.push({
      case: secure ? "TLS_OVERFLOW_STOP" : "HTTP_OVERFLOW_STOP",
      requests: 1,
      wire: state,
    });
  });
}

const errorRoot = join(directory, "http-errors");
mkdirSync(errorRoot, { mode: 0o700 });
const errorResponses = [
  Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc"),
  Buffer.from(
    "HTTP/1.1 302 Found\r\nLocation: https://example.invalid/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  ),
  Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
  ),
];
await runServer(false, errorResponses, async (origin, received) => {
  const client = createLocalWireTransport({
    origins: [origin],
    limits: plan,
    captureDirectory: errorRoot,
    onByteReserve: async () => {},
  });
  try {
    await assert.rejects(
      client.fetch(`${origin}/truncated`, {
        operationId: "wire/truncated",
        accountingPhase: "subject",
      }),
      /WIRE_TRUNCATED/,
    );
    const redirect = await client.fetch(`${origin}/redirect`, {
      operationId: "wire/redirect",
      accountingPhase: "cleanup",
    });
    assert.equal(redirect.status, 302);
    await assert.rejects(
      client.fetch(`${origin}/compressed`, {
        operationId: "wire/compressed",
        accountingPhase: "cleanup",
      }),
      /WIRE_UNSUPPORTED_ENCODING/,
    );
  } finally {
    await client.close();
  }
  assert.equal(received.length, 3);
  for (let index = 0; index < 3; index++)
    assert.deepEqual(
      readFileSync(join(errorRoot, `${String(index + 1).padStart(6, "0")}-response.bin`)),
      errorResponses[index],
    );
  results.push({ case: "NO_RETRY_OR_DECOMPRESSION", requests: 3, wire: client.snapshot() });
});
const untrustedRoot = join(directory, "tls-untrusted");
mkdirSync(untrustedRoot, { mode: 0o700 });
await runServer(true, [], async (origin, received) => {
  const client = createLocalWireTransport({
    origins: [origin],
    limits: plan,
    captureDirectory: untrustedRoot,
    onByteReserve: async () => {},
  });
  try {
    await assert.rejects(
      client.fetch(`${origin}/untrusted`, {
        operationId: "wire/untrusted-ca",
        accountingPhase: "subject",
      }),
      /WIRE_CONNECTION_FAILED|WIRE_REQUEST_FAILED/,
    );
  } finally {
    await client.close();
  }
  assert.equal(received.length, 0);
  assert.equal(client.snapshot().responseObservedBytes, 0);
  results.push({
    case: "TLS_UNTRUSTED_CA_REJECTED",
    requests: 1,
    peerRequests: 0,
    wire: client.snapshot(),
  });
});

const timeoutRoot = join(directory, "http-timeout");
mkdirSync(timeoutRoot, { mode: 0o700 });
await runServer(false, [null], async (origin, received) => {
  const client = createLocalWireTransport({
    origins: [origin],
    limits: plan,
    captureDirectory: timeoutRoot,
    timeoutMs: 50,
    onByteReserve: async () => {},
  });
  try {
    await assert.rejects(
      client.fetch(`${origin}/timeout`, {
        operationId: "wire/timeout",
        accountingPhase: "subject",
      }),
      /WIRE_TIMEOUT/,
    );
  } finally {
    await client.close();
  }
  assert.equal(received.length, 1);
  assert.equal(client.snapshot().attempts, 1);
  results.push({ case: "ABSOLUTE_DEADLINE_ABORT", requests: 1, wire: client.snapshot() });
});
unlinkSync(keyPath);
writeFileSync(join(directory, "summary.json"), `${JSON.stringify(results)}\n`, {
  flag: "wx",
  mode: 0o600,
});
process.stdout.write(
  `${JSON.stringify({ status: "LOCAL_WIRE_PROOF_COMPLETE", results, eventDirectory: directory })}\n`,
);
