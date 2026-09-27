// The request meter of the deployment subprocesses (issue auth-tenant-campaign-total-request-cap).

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { statSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { CLI_METER } from "./auth-tenant-blocking/deploy.mjs";

const { isExternal } = createRequire(import.meta.url)(CLI_METER);

test("only requests that leave the machine are external", () => {
  for (const host of ["localhost", "127.0.0.1", "127.0.0.1:8080", "[::1]:9000", "LOCALHOST"])
    assert.equal(isExternal(host), false, host);
  for (const host of [
    "cloudfunctions.googleapis.com",
    "localhost.example.com",
    "127.0.0.10",
    "",
    undefined,
  ])
    assert.equal(isExternal(host), true, String(host));
});

/** Runs `script` under the meter against a local server; the loopback counts for the test. */
async function metered(script, limit, file) {
  file ??= join(await mkdtemp(join(tmpdir(), "atb-meter-")), "requests");
  let served = 0;
  const server = createServer((request, response) => {
    served += 1;
    response.end("ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    const result = await new Promise((resolve) => {
      execFile(
        process.execPath,
        ["-e", script],
        {
          env: {
            PATH: process.env.PATH,
            NODE_OPTIONS: `--require=${CLI_METER}`,
            FIREEMU_CLI_METER_FILE: file,
            FIREEMU_CLI_METER_LIMIT: String(limit),
            FIREEMU_CLI_METER_COUNT_LOOPBACK: "1",
            URL: url,
          },
          timeout: 20_000,
        },
        (error, stdout, stderr) => resolve({ error, stdout, stderr }),
      );
    });
    let count = 0;
    try {
      count = statSync(file).size;
    } catch {
      /* nothing counted */
    }
    return { ...result, count, served };
  } finally {
    server.close();
  }
}

const FETCH_AND_HTTP = `
const http = require("node:http");
(async () => {
  await (await fetch(process.env.URL)).text();
  await new Promise((resolve, reject) =>
    http.get(process.env.URL, (r) => { r.resume(); r.on("end", resolve); }).on("error", reject));
  await (await fetch(process.env.URL)).text();
  console.log("done");
})();
`;

test("every fetch and http request of a metered process is counted", async () => {
  const run = await metered(FETCH_AND_HTTP, 3);
  assert.equal(run.error, null, run.stderr);
  assert.equal(run.stdout.trim(), "done");
  assert.equal(run.count, 3);
  assert.equal(run.served, 3);
});

test("a request past the allowance kills the process before it is sent", async () => {
  const run = await metered(FETCH_AND_HTTP, 2);
  assert.equal(run.error?.signal, "SIGKILL");
  assert.equal(run.stdout, "");
  assert.match(run.stderr, /request 3 would pass the allowance of 2/);
  assert.equal(run.served, 2);
});

test("an allowance of zero sends nothing", async () => {
  const run = await metered(FETCH_AND_HTTP, 0);
  assert.equal(run.error?.signal, "SIGKILL");
  assert.equal(run.served, 0);
});

test("the processes a metered process spawns count into the same allowance", async () => {
  const child = `require("node:child_process").execFileSync(process.execPath, ["-e", ${JSON.stringify(
    FETCH_AND_HTTP,
  )}], { stdio: "inherit" });`;
  const run = await metered(`${child}\n${FETCH_AND_HTTP}`, 5);
  assert.equal(run.error?.signal, "SIGKILL");
  assert.equal(run.served, 5);
  assert.equal(run.count, 6);
});

test("a meter that cannot record sends nothing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "atb-meter-"));
  const run = await metered(FETCH_AND_HTTP, 10, join(dir, "missing", "requests"));
  assert.equal(run.error?.signal, "SIGKILL");
  assert.equal(run.stdout, "");
  assert.match(run.stderr, /cannot record a request/);
  assert.equal(run.served, 0);
});
