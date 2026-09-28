import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import test from "node:test";
import { createLocalWireTransport } from "./storage-object/local-wire-transport.mjs";
import { createWireTransportCore } from "./storage-object/wire-transport-core.mjs";
import { serializeBoundedHttpRequest } from "./storage-object/wire-serialization.mjs";
import { createPrivateWireAttempt } from "./storage-object/private-wire-capture.mjs";

for (const policy of ["ALLOW", "REJECT"])
  for (const channel of ["103", "chunked-trailer", "chunked"])
    test(`the fixed auxiliary policy preserves local plaintext or rejects before publication (${policy}, ${channel})`, async () => {
      const directory = mkdtempSync(join(tmpdir(), "storage-object-local-auxiliary-"));
      const originalConnect = net.connect;
      const body = Buffer.from("SYNTHETIC_LOCAL_BODY");
      const final = Buffer.concat([
        Buffer.from(
          `HTTP/1.1 200 Synthetic\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
        ),
        body,
      ]);
      const responseWire =
        channel === "103"
          ? Buffer.concat([
              Buffer.from(
                "HTTP/1.1 103 Synthetic\r\nX-Synthetic-Capability: SYNTHETIC_LOCAL_AUXILIARY\r\n\r\n",
              ),
              final,
            ])
          : Buffer.concat([
              Buffer.from(
                `HTTP/1.1 200 Synthetic\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${body.length.toString(16)}\r\n`,
              ),
              body,
              Buffer.from(
                `\r\n0\r\n${channel === "chunked-trailer" ? "X-Synthetic-Capability: SYNTHETIC_LOCAL_AUXILIARY\r\n" : ""}\r\n`,
              ),
            ]);
      let calls = 0,
        responded = false,
        request = Buffer.alloc(0);
      net.connect = (options) => {
        calls++;
        const socket = new Duplex({
          read() {},
          write(bytes, encoding, done) {
            request = Buffer.concat([request, bytes]);
            socket.bytesWritten += bytes.length;
            const end = request.indexOf("\r\n\r\n"),
              length = /content-length: (\d+)/i.exec(request.toString())?.[1];
            if (!responded && end >= 0 && request.length === end + 4 + Number(length)) {
              responded = true;
              queueMicrotask(() => {
                for (let offset = 0; offset < responseWire.length; offset += 37)
                  options.onread.callback(
                    Math.min(37, responseWire.length - offset),
                    responseWire.subarray(offset, offset + 37),
                  );
                socket.push(null);
              });
            }
            done();
          },
        });
        Object.assign(socket, {
          bytesWritten: 0,
          setTimeout() {
            return this;
          },
          setNoDelay() {
            return this;
          },
          setKeepAlive() {
            return this;
          },
        });
        queueMicrotask(() => socket.emit("connect"));
        return socket;
      };
      const limits = {
        maxRequestBytes: 100000,
        maxResponseBytes: 100000,
        maxPerResponseWireBytes: 20000,
        responseReadUnitBytes: 8192,
      };
      const transport =
        policy === "ALLOW"
          ? createLocalWireTransport({
              origins: ["http://127.0.0.1:9999"],
              captureDirectory: directory,
              limits: {
                maxRequestBytes: 100000,
                maxResponseBytes: 100000,
                maxPerResponseWireBytes: 20000,
                responseReadUnitBytes: 8192,
              },
              onByteReserve: async () => {},
            })
          : createWireTransportCore({
              limits,
              onByteReserve: async () => {},
              auxiliaryResponsePolicy: "REJECT",
              serializeRequest: (url, init) =>
                serializeBoundedHttpRequest(url, init, ["http://127.0.0.1:9999"]),
              createCapture: ({ sequence, serialized, metadata }) =>
                createPrivateWireAttempt({
                  directory,
                  sequence,
                  request: serialized.wire,
                  metadata,
                }),
              tlsConnectionOptions: () => assert.fail("TLS is not used"),
            });
      try {
        const sending = transport.fetch("http://127.0.0.1:9999/object", {
          operationId: "local/auxiliary",
          accountingPhase: "subject",
        });
        const rejected = policy === "REJECT" && channel !== "chunked";
        if (rejected) await assert.rejects(sending, /^Error: WIRE_UNSUPPORTED_AUXILIARY_RESPONSE$/);
        else {
          const response = await sending;
          assert.equal(response.status, 200);
          assert.deepEqual(Buffer.from(await response.arrayBuffer()), body);
        }
        assert.equal(calls, 1);
        const observed = readFileSync(join(directory, "000001-response.bin"));
        assert.deepEqual(observed, responseWire.subarray(0, observed.length));
        if (!rejected) assert.deepEqual(observed, responseWire);
        const result = JSON.parse(readFileSync(join(directory, "000001-result.json")));
        assert.equal(result.complete, !rejected);
        assert.equal(result.reason, rejected ? "WIRE_UNSUPPORTED_AUXILIARY_RESPONSE" : null);
        assert.equal(
          createHash("sha256")
            .update(readFileSync(join(directory, "000001-response.bin")))
            .digest("hex"),
          createHash("sha256").update(responseWire.subarray(0, observed.length)).digest("hex"),
        );
        assert.equal(result.responseObservedBytes, observed.length);
      } finally {
        await transport.close();
        net.connect = originalConnect;
        rmSync(directory, { recursive: true, force: true });
      }
    });
