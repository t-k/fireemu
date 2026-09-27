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
const SID = "SIDtestabcdefghij";
const GSESSIONID = "gsess-test-1";

const frame = (value) => `${JSON.stringify(value).length}\n${JSON.stringify(value)}`;

/**
 * A loopback WebChannel that opens every session, then answers each session's measured body
 * (RID=3) or control (RID=2) the way the program's size asks: the 12 MiB session's body is
 * dropped before any response, the 16 MiB one after the response head, and the 32 MiB
 * session's control is dropped. Terminates and the emulator wipe answer 200.
 */
function fakeChannel() {
  const seen = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    const rid = url.searchParams.get("RID");
    let bytes = 0;
    request.on("data", (chunk) => {
      bytes += chunk.length;
    });
    const drop = () => request.socket.destroy();
    if (request.method === "DELETE") {
      request.resume();
      request.on("end", () => response.end("{}"));
      return;
    }
    if (url.searchParams.get("TYPE") === "terminate") {
      seen.push(`terminate:${url.searchParams.get("SID")}`);
      response.end("ok");
      return;
    }
    if (rid === "1") {
      request.on("end", () => {
        response.setHeader("x-http-session-id", GSESSIONID);
        response.end(frame([[0, ["c", SID, "", 8, 14, 30000]]]));
      });
      return;
    }
    request.on("end", () => {
      const size = bytes;
      seen.push(`rid${rid}:${size}`);
      if (rid === "2" && seen.filter((entry) => entry.startsWith("rid2:")).length === 3) {
        drop();
      } else if (rid === "2") {
        response.end(frame([1, 0, 0]));
      } else if (size === 12_582_912) {
        drop();
      } else if (size === 16_777_216) {
        response.writeHead(400, { "content-type": "application/json" });
        response.write('{"error":{"code":400,"message":"Request payload');
        setTimeout(drop, 10);
      } else {
        response.end(frame([1, 0, 0]));
      }
    });
  });
  return { server, seen };
}

test("a reset on a WebChannel measured body is a typed answer; a reset elsewhere is not", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webchannel-reset-"));
  const { server, seen } = fakeChannel();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const input = join(dir, "corpus.json");
    const output = join(dir, "rest.json");
    const programs = [12_582_912, 16_777_216, 33_554_432].map(webchannelSessionProgram);
    await writeFile(input, JSON.stringify({ schemaVersion: 1, restPrograms: programs }));
    await execFileAsync("node", [new URL("./sandbox-session.mjs", import.meta.url).pathname], {
      env: {
        ...process.env,
        FIRESTORE_PROBE_HOST: `127.0.0.1:${server.address().port}`,
        FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
        FIRESTORE_PROBE_IN: input,
        FIRESTORE_PROBE_OUT: output,
        FIRESTORE_PROBE_TOKEN: "owner",
        FIRESTORE_PROBE_TIMEOUT_MS: "20000",
      },
      maxBuffer: 1024 * 1024,
    });
    const text = await readFile(output, "utf8");
    assert.ok(!text.includes(SID), "the SID must not be recorded");
    assert.ok(!text.includes(GSESSIONID), "the session header must not be recorded");
    const rows = JSON.parse(text);
    const steps = (size) => rows[`writes/limits/webchannel-request-bytes/${size}`].steps;
    assert.deepEqual(steps(12_582_912).boundary, {
      status: 0,
      code: "connection-reset",
      message: "reset-before-response",
    });
    assert.deepEqual(steps(16_777_216).boundary, {
      status: 0,
      code: "connection-reset",
      message: "reset-during-response",
    });
    // A dropped control stays an untyped failure, and the measured body is never sent.
    assert.equal(steps(33_554_432).control.code, "probe-error");
    assert.equal(steps(33_554_432).boundary.code, "not-run");
    for (const size of [12_582_912, 16_777_216, 33_554_432]) {
      assert.deepEqual(steps(size).terminate, {
        status: 200,
        code: "OK",
        body: "session-terminated",
      });
    }
    assert.equal(seen.filter((entry) => entry.startsWith("terminate:")).length, 3);
    assert.ok(!seen.includes("rid3:33554432"), "no measured body after a failed control");
  } finally {
    server.close();
    await rm(dir, { recursive: true, force: true });
  }
});
