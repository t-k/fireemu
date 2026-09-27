import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import { webchannelSessionProgram } from "./webchannel-request-bytes.mjs";

const execFileAsync = promisify(execFile);
const GSESSIONID = "gsess-test-1";

const frame = (value) => `${JSON.stringify(value).length}\n${JSON.stringify(value)}`;

/**
 * What the fake channel does with each session, in corpus order: the session's control (RID=2)
 * and its measured body (RID=3). `drop` closes the socket before any response, `drop-late`
 * after the response head, `stall` sends the head and then nothing.
 */
const BEHAVIOUR = [
  { size: 12_582_912, control: "ack", body: "drop" },
  { size: 16_777_216, control: "ack", body: "drop-late" },
  { size: 33_554_432, control: "drop", body: "ack" },
  { size: 11_534_336, control: "stall", body: "ack" },
  { size: 11_534_337, control: "ack", body: "stall" },
];

function fakeChannel() {
  const seen = [];
  let opened = 0;
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const rid = url.searchParams.get("RID");
    const session = Number(/SIDtest(\d+)x/.exec(url.searchParams.get("SID") ?? "")?.[1]);
    request.on("data", () => {});
    const act = (behaviour) => {
      if (behaviour === "drop") request.socket.destroy();
      else if (behaviour === "drop-late") {
        response.writeHead(400, { "content-type": "application/json" });
        response.write('{"error":{"code":400,"message":"Request payload');
        setTimeout(() => request.socket.destroy(), 10);
      } else if (behaviour === "stall") {
        response.writeHead(200, { "content-type": "text/plain" });
        response.write("5\n[1,0");
      } else response.end(frame([1, 0, 0]));
    };
    request.on("end", () => {
      if (request.method === "DELETE") return response.end("{}");
      if (url.searchParams.get("TYPE") === "terminate") {
        seen.push(`terminate:${session}`);
        return response.end("ok");
      }
      if (rid === "1") {
        opened += 1;
        response.setHeader("x-http-session-id", GSESSIONID);
        return response.end(
          frame([[0, ["c", `SIDtest${opened - 1}xabcdefghij`, "", 8, 14, 30000]]]),
        );
      }
      seen.push(`rid${rid}:${session}`);
      return act(rid === "2" ? BEHAVIOUR[session].control : BEHAVIOUR[session].body);
    });
  });
  return { server, seen };
}

test("only a dropped measured body is a typed reset; timeouts while reading are no-response", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webchannel-reset-"));
  const { server, seen } = fakeChannel();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const input = join(dir, "corpus.json");
    const output = join(dir, "rest.json");
    const programs = BEHAVIOUR.map(({ size }) => webchannelSessionProgram(size));
    await writeFile(input, JSON.stringify({ schemaVersion: 1, restPrograms: programs }));
    await execFileAsync("node", [new URL("./sandbox-session.mjs", import.meta.url).pathname], {
      env: {
        ...process.env,
        FIRESTORE_PROBE_HOST: `127.0.0.1:${server.address().port}`,
        FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
        FIRESTORE_PROBE_IN: input,
        FIRESTORE_PROBE_OUT: output,
        FIRESTORE_PROBE_TOKEN: "owner",
        FIRESTORE_PROBE_TIMEOUT_MS: "1500",
        // Loopback only: the measured body's own, longer timeout, shortened for the test.
        FIRESTORE_PROBE_BOUNDARY_TIMEOUT_MS: "2500",
      },
      maxBuffer: 1024 * 1024,
    });
    const text = await readFile(output, "utf8");
    assert.ok(!/SIDtest\d+x/.test(text), "the SID must not be recorded");
    assert.ok(!text.includes(GSESSIONID), "the session header must not be recorded");
    const rows = JSON.parse(text);
    const steps = (size) => rows[`writes/limits/webchannel-request-bytes/${size}`].steps;
    const reset = (message) => ({ status: 0, code: "connection-reset", message });
    const noResponse = {
      status: 0,
      code: "no-response",
      message: "no response within the timeout",
    };
    assert.deepEqual(steps(12_582_912).boundary, reset("reset-before-response"));
    assert.deepEqual(steps(16_777_216).boundary, reset("reset-during-response"));
    // A dropped control stays an untyped failure, and the measured body is never sent.
    assert.equal(steps(33_554_432).control.code, "probe-error");
    assert.equal(steps(33_554_432).boundary.code, "not-run");
    assert.ok(!seen.includes("rid3:2"), "no measured body after a failed control");
    // A timeout while a response body is read is no-response, on the control and the body.
    assert.deepEqual(steps(11_534_336).control, noResponse);
    assert.equal(steps(11_534_336).boundary.code, "not-run");
    assert.deepEqual(steps(11_534_337).boundary, noResponse);
    for (const { size } of BEHAVIOUR) {
      assert.deepEqual(steps(size).terminate, {
        status: 200,
        code: "OK",
        body: "session-terminated",
      });
    }
    assert.equal(seen.filter((entry) => entry.startsWith("terminate:")).length, BEHAVIOUR.length);
  } finally {
    server.closeAllConnections();
    server.close();
    await rm(dir, { recursive: true, force: true });
  }
});
