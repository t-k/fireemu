import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";

import { captureFetch } from "./bearer-observation.mjs";
import { createBudget } from "./harness.mjs";
import { acquireToken, cli, createControl, createUser } from "./production.mjs";
import { createTransport } from "./callable-ingress/rerecord.mjs";
import { SEND_FLAG, assertProductionSend, guardedFetch, isLoopbackUrl } from "./send-guard.mjs";
import { runCases } from "./session.mjs";

// No test in this repository sets FIREEMU_PRODUCTION_SEND: these tests prove that, without it, every client
// that can reach a real service refuses before it sends anything.
const REFUSED = /refused; FIREEMU_PRODUCTION_SEND=1 is set by a launch script only/;

test("the flag is a launch script's alone: only the exact value 1 allows a send", () => {
  assert.equal(SEND_FLAG, "FIREEMU_PRODUCTION_SEND");
  assert.equal(process.env[SEND_FLAG], undefined, "the test run itself carries no send flag");
  assert.doesNotThrow(() => assertProductionSend("x", { FIREEMU_PRODUCTION_SEND: "1" }));
  for (const value of [undefined, "", "0", "true", "yes", " 1", "11"]) {
    assert.throws(() => assertProductionSend("x", { FIREEMU_PRODUCTION_SEND: value }), REFUSED);
  }
  assert.throws(() => assertProductionSend("x", {}), /^Error: x: refused/);
});

test("loopback URLs are this machine; anything else, and anything unparsable, is not", () => {
  for (const url of ["http://127.0.0.1:1/", "http://localhost/", "http://[::1]:8080/x"])
    assert.equal(isLoopbackUrl(url), true, url);
  for (const url of [
    "https://run.googleapis.com/",
    "http://127.0.0.1.example.com/",
    "http://localhost.example.com/",
    "http://10.0.0.1/",
    "not a url",
    "",
  ])
    assert.equal(isLoopbackUrl(url), false, url);
});

test("the guarded fetch refuses a real host without the flag, before any send, and names the host", async () => {
  await assert.rejects(
    guardedFetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp"),
    REFUSED,
  );
  await assert.rejects(
    guardedFetch("https://nonexistent.invalid/"),
    /fetch nonexistent\.invalid: refused/,
  );
});

test("the guarded fetch lets a loopback server through, and uses a fetch a test replaced", async () => {
  const server = http.createServer((req, res) => res.end("local"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  try {
    const response = await guardedFetch(`http://127.0.0.1:${server.address().port}/`);
    assert.equal(await response.text(), "local");
  } finally {
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
  const original = globalThis.fetch;
  try {
    const seen = [];
    globalThis.fetch = async (url, init) => {
      seen.push([url, init]);
      return new Response("stub");
    };
    const response = await guardedFetch("https://run.googleapis.com/", { method: "GET" });
    assert.equal(await response.text(), "stub");
    assert.deepEqual(seen, [["https://run.googleapis.com/", { method: "GET" }]]);
  } finally {
    globalThis.fetch = original;
  }
  await assert.rejects(
    guardedFetch("https://run.googleapis.com/"),
    REFUSED,
    "the stub is gone again",
  );
});

test("every production client refuses without the flag: ADC refresh, REST control, Auth sign-up, the Firebase CLI", async () => {
  const adc = { refresh_token: "r", client_id: "c", client_secret: "s" };
  const budget = createBudget();
  await assert.rejects(acquireToken(adc, budget, "token"), REFUSED);
  const control = createControl(adc, budget);
  await assert.rejects(
    control("GET", "https://cloudfunctions.googleapis.com/v2/projects/p"),
    REFUSED,
  );
  await assert.rejects(
    createUser("k".repeat(24), budget, "/nonexistent", "program-x"),
    /ENOENT|refused/,
  );
  // createUser journals first, then sends: with no run directory it stops at the journal, and with one it refuses.
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "send-guard-"));
  try {
    await assert.rejects(createUser("k".repeat(24), createBudget(), dir, "program-x"), REFUSED);
    await assert.rejects(
      cli(["deploy"], "/adc", createBudget(), "cliDeploy", dir, undefined),
      REFUSED,
    );
    // a harmless command is not the real CLI: it is not refused by the guard
    await assert.rejects(
      cli(["deploy"], "/adc", createBudget(), "cliDeploy", dir, undefined, [
        process.execPath,
        "-e",
        "process.exit(1)",
      ]),
      /failed or attempted API enablement/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the default fetch of the session and of the capture is the guarded one", async () => {
  const program = {
    id: "p",
    cases: [
      { id: "c", target: "http", request: { method: "GET", path: "/" }, capture: "complete" },
    ],
  };
  await assert.rejects(
    runCases(program, { http: "https://example.invalid/fn" }, {}, createBudget()),
    REFUSED,
  );
  await assert.rejects(
    captureFetch({ onCapture: () => {} })("https://example.invalid/", {
      method: "GET",
      headers: {},
    }),
    REFUSED,
  );
});

test("the invocation transport refuses a real host without the flag and serves this machine", async () => {
  const transport = createTransport({ delayMs: 0 });
  const init = { method: "POST", headers: { "content-type": "application/json" }, body: "{}" };
  await assert.rejects(
    transport.fetchImpl("https://fireemucallableprobe-abc-uc.a.run.app/", init),
    REFUSED,
  );
  const server = http.createServer((req, res) => res.end("ok"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  try {
    const response = await transport.fetchImpl(`http://127.0.0.1:${server.address().port}/`, init);
    assert.equal(await response.text(), "ok");
  } finally {
    transport.close();
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
});
