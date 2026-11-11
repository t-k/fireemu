// The guard that keeps tests, mutation passes and dry runs of the Hosting recorder away from
// production (send-guard.mjs). An unarmed process cannot read a credential, the private ledger or the
// run directories, nor reach a host other than loopback; and no test runs armed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { edgeRequest } from "./client.mjs";
import { productionDeps } from "./record.mjs";
import { assertMaySend, isArmed, isLoopback, SEND_FLAG } from "./send-guard.mjs";

const REFUSED = new RegExp(`${SEND_FLAG}=1 is not set`);

test("no test runs armed: the flag is unset, so an unarmed process is the only one under test", () => {
  assert.equal(SEND_FLAG, "FIREEMU_HOSTING_ALLOW_SEND");
  assert.equal(process.env[SEND_FLAG], undefined, "a test must never run with the send flag set");
  assert.equal(isArmed(), false);
});

test("the flag arms a send only when it is exactly 1, and the refusal names the effect", () => {
  assert.equal(isArmed({}), false);
  for (const value of ["", "0", "true", "yes", "1 ", " 1", "01", "2"]) {
    assert.equal(isArmed({ [SEND_FLAG]: value }), false, JSON.stringify(value));
    assert.throws(() => assertMaySend("a thing", { [SEND_FLAG]: value }), /a thing refused/);
  }
  assert.equal(isArmed({ [SEND_FLAG]: "1" }), true);
  assert.doesNotThrow(() => assertMaySend("a thing", { [SEND_FLAG]: "1" }));
  assert.throws(() => assertMaySend("reading the owner credentials", {}), REFUSED);
});

test("loopback is the only host an unarmed edge client reaches", () => {
  for (const host of ["localhost", "LOCALHOST", "127.0.0.1", "::1", "[::1]"]) {
    assert.equal(isLoopback(host), true, host);
  }
  for (const host of [
    "example.com",
    "127.0.0.1.example.com",
    "localhost.example.com",
    "0.0.0.0",
    "10.0.0.1",
    "fireemu-oracle-idp--hst-abc123-v11-abcdef12.web.app",
    "",
    undefined,
  ]) {
    assert.equal(isLoopback(host), false, String(host));
  }
});

/**
 * Runs `body` with every way out of this process stubbed: `fetch`, `http.request` and `https.request`
 * record the call and fail it. If a guard under test were missing, the call would land in a stub
 * and the test would fail: a broken guard can never reach a network from here.
 */
async function withNoNetwork(body) {
  const sent = [];
  const saved = { fetch: globalThis.fetch, http: http.request, https: https.request };
  globalThis.fetch = (...args) => {
    sent.push(["fetch", String(args[0])]);
    return Promise.reject(new Error("the test network is closed"));
  };
  for (const [name, module] of [
    ["http", http],
    ["https", https],
  ]) {
    module.request = (...args) => {
      sent.push([name, JSON.stringify(args[0]?.host ?? args[0])]);
      throw new Error("the test network is closed");
    };
  }
  try {
    await body(sent);
  } finally {
    globalThis.fetch = saved.fetch;
    http.request = saved.http;
    https.request = saved.https;
  }
}

test("an unarmed edge client refuses a host that is not loopback before it opens a connection", async () => {
  await withNoNetwork(async (sent) => {
    await assert.rejects(
      () => edgeRequest({ host: "refused.invalid", secure: true, method: "GET", target: "/" }),
      REFUSED,
    );
    await assert.rejects(
      () => edgeRequest({ host: "10.255.255.1", secure: false, method: "GET", target: "/" }),
      /edge request to 10\.255\.255\.1 refused/,
    );
    assert.deepEqual(sent, [], "nothing was sent");
  });
  // loopback is not refused by the guard: the request reaches the (stubbed) transport
  await withNoNetwork(async (sent) => {
    await edgeRequest({ host: "127.0.0.1", port: 9, secure: false, method: "GET", target: "/" });
    assert.deepEqual(sent, [["http", '"127.0.0.1"']]);
  });
});

test("every effect of the production deps that reaches a credential, the private files or the network refuses when unarmed", async () => {
  // the root is an empty directory of this test and the credentials path does not exist: a missing
  // guard could neither read nor write anything private, and the network is stubbed
  const root = mkdtempSync(join(tmpdir(), "guard-root-"));
  const savedAdc = process.env.FIREEMU_OWNER_ADC;
  process.env.FIREEMU_OWNER_ADC = join(root, "no-such-adc.json");
  try {
    await withNoNetwork(async (sent) => {
      const deps = await productionDeps({ root });
      const calls = {
        ownerAdc: () => deps.ownerAdc(),
        token: () => deps.token({ file: {} }),
        http: () =>
          deps.http({
            method: "GET",
            url: "https://firebasehosting.googleapis.com/v1beta1/projects/x/sites",
            headers: {},
          }),
        edge: () =>
          deps.edge({
            host: "refused.invalid",
            secure: true,
            method: "GET",
            target: "/",
            headers: {},
          }),
        webConfig: () => deps.webConfig(),
        readLedger: () => deps.readLedger(),
        appendLedger: () => deps.appendLedger("{}\n"),
        makeRunDir: () => deps.makeRunDir("never-made"),
        writeRunFile: () => deps.writeRunFile(root, "never", "x"),
        appendRunFile: () => deps.appendRunFile(root, "never", "x"),
      };
      for (const [name, call] of Object.entries(calls)) {
        await assert.rejects(async () => call(), REFUSED, name);
      }
      assert.deepEqual(sent, [], "nothing was sent");
      assert.deepEqual(readdirSync(root), [], "nothing was written under the root");
      // the effects that touch nothing private still work
      assert.equal(typeof deps.runTag(), "string");
      assert.equal(typeof deps.sleep, "function");
    });
  } finally {
    if (savedAdc === undefined) delete process.env.FIREEMU_OWNER_ADC;
    else process.env.FIREEMU_OWNER_ADC = savedAdc;
  }
});

test("the record and recover commands refuse to start unarmed, before any file or credential is read", () => {
  const record = fileURLToPath(new URL("./record.mjs", import.meta.url));
  for (const mode of ["record-production", "recover"]) {
    let message = "";
    try {
      execFileSync(process.execPath, [record, mode], {
        env: {
          PATH: process.env.PATH,
          HOME: "/nonexistent-home",
          FIREEMU_OWNER_ADC: "/nonexistent/adc.json",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      message = String(error.stderr);
    }
    assert.match(message, REFUSED, mode);
  }
});

// The mutation harnesses of the lane run every test with HOME set to an empty directory, no
// credential in the environment and a work copy of their own: FIREEMU_HOSTING_HERMETIC=1 says so,
// and this test checks that it is true. It is skipped in an ordinary run.
test(
  "a hermetic run has an empty home, no credential and no private root in reach",
  { skip: process.env.FIREEMU_HOSTING_HERMETIC === "1" ? false : "not a hermetic run" },
  () => {
    const home = homedir();
    assert.equal(existsSync(join(home, ".config")), false, "HOME holds a .config directory");
    assert.deepEqual(readdirSync(home), [], "HOME is not empty");
    for (const name of Object.keys(process.env)) {
      assert.doesNotMatch(
        name,
        /^(GOOGLE_|CLOUDSDK_|FIREBASE_TOKEN|FIREEMU_OWNER_ADC|FIREEMU_HOSTING_WEB_CONFIG|GCLOUD_)/,
        name,
      );
    }
    assert.equal(process.env[SEND_FLAG], undefined);
    // the repository the recorder resolves is this work copy: no private root above it
    const conformance = resolve(fileURLToPath(new URL("../..", import.meta.url)));
    const common = execFileSync(
      "git",
      ["rev-parse", "--path-format=absolute", "--git-common-dir"],
      { cwd: conformance },
    )
      .toString()
      .trim();
    const root = resolve(common, "..");
    assert.ok(conformance.startsWith(`${root}/`), `${conformance} is not inside ${root}`);
    assert.equal(existsSync(join(root, "docs.local")), false, "a private docs.local is in reach");
  },
);
