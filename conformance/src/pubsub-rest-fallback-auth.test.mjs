// Source-bound SDK probes: guards stop credential acquisition before any original method runs.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { once } from "node:events";
import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import fs from "node:fs";
import childProcess from "node:child_process";
import test from "node:test";

const require = createRequire(import.meta.url);
const sdkRequire = createRequire(require.resolve("@google-cloud/pubsub"));
const gaxRequire = createRequire(sdkRequire.resolve("google-gax"));
const authCopies = [sdkRequire("google-auth-library"), gaxRequire("google-auth-library")];
const sdk = require("@google-cloud/pubsub");
// Repo-pinned PubSub 4.11.0 / gax 4.6.1 calls auth.getClient() in build/src/fallback.js:214.
// PubSub 5.3.1 / gax 5.0.8 has the same credential acquisition at fallback.js:266-268.
assert.equal(sdkRequire("./../../package.json").version, "4.11.0");
assert.equal(gaxRequire("./../../package.json").version, "4.6.1");

async function probe(anonymous) {
  const requests = [];
  const sockets = new Set();
  const server = http.createServer((request, response) => {
    requests.push({ method: request.method, path: request.url, headers: request.headers });
    request.resume();
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ name: "projects/demo-task10/topics/a2-probe" }));
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  const restores = [];
  const calls = [];
  function replace(object, key, value) {
    const original = object[key];
    object[key] = value;
    restores.push(() => {
      object[key] = original;
    });
  }
  function deny(kind) {
    return () => {
      throw new Error(`TASK10_FORBIDDEN_${kind}`);
    };
  }
  for (const [index, auth] of authCopies.entries()) {
    for (const name of [
      "getClient",
      "getProjectId",
      "getApplicationDefault",
      "getApplicationDefaultAsync",
      "_getApplicationDefaultAsync",
      "_tryGetApplicationCredentialsFromEnvironmentVariable",
      "_tryGetApplicationCredentialsFromWellKnownFile",
      "_checkIsGCE",
    ]) {
      if (typeof auth.GoogleAuth.prototype[name] !== "function") continue;
      replace(auth.GoogleAuth.prototype, name, async function () {
        calls.push({ copy: index, method: name });
        throw new Error(`TASK10_AUTH_BLOCKED_${index}_${name}`);
      });
    }
  }
  const connect = net.Socket.prototype.connect;
  replace(net.Socket.prototype, "connect", function (...args) {
    let options = args[0];
    if (Array.isArray(options)) options = options[0];
    const targetPort = typeof options === "object" ? options.port : options;
    const host = typeof options === "object" ? options.host : args[1];
    assert.equal(host, "127.0.0.1", "only the allocated loopback host is allowed");
    assert.equal(Number(targetPort), port, "only the allocated collector port is allowed");
    return connect.apply(this, args);
  });
  replace(tls, "connect", deny("TLS"));
  replace(dns, "lookup", deny("DNS"));
  for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])
    replace(childProcess, name, deny("PROCESS"));
  for (const name of ["readFile", "readFileSync"]) {
    const original = fs[name];
    replace(fs, name, function (path, ...args) {
      assert.ok(
        !String(path).match(/application_default_credentials|[/.]config[/\\]gcloud/),
        "credential files are forbidden",
      );
      return original.call(this, path, ...args);
    });
  }
  const previousHost = process.env.PUBSUB_EMULATOR_HOST;
  process.env.PUBSUB_EMULATOR_HOST = `127.0.0.1:${port}`;
  let pubsub;
  let publisher;
  try {
    const options = { projectId: "demo-task10", fallback: "rest" };
    if (anonymous)
      Object.assign(options, { protocol: "http", auth: new authCopies[0].PassThroughClient() });
    pubsub = new sdk.PubSub(options);
    assert.equal(pubsub.isEmulator, true);
    if (anonymous) {
      const [topic] = await pubsub.createTopic("a2-probe", {
        gaxOpts: { timeout: 2000, retry: null },
      });
      assert.equal(topic.name, "projects/demo-task10/topics/a2-probe");
      assert.equal(
        calls.length,
        0,
        "explicit anonymous fallback performs no credential acquisition",
      );
      assert.equal(requests.length, 1);
      assert.equal(requests[0].method, "PUT");
      assert.equal(
        new URL(requests[0].path, "http://127.0.0.1").pathname,
        "/v1/projects/demo-task10/topics/a2-probe",
      );
      assert.equal(Object.hasOwn(requests[0].headers, "authorization"), false);
    } else {
      publisher = new sdk.v1.PublisherClient(await pubsub.getClientConfig());
      await assert.rejects(publisher.initialize(), /TASK10_AUTH_BLOCKED_1_getClient/);
      assert.deepEqual(
        calls,
        [{ copy: 1, method: "getClient" }],
        "default fallback attempts credential acquisition despite emulator mode",
      );
      assert.equal(requests.length, 0);
    }
    return {
      anonymous,
      attemptedAcquisition: calls,
      wireRequests: requests.length,
      actualCredentialLookups: 0,
    };
  } finally {
    await publisher?.close().catch(() => {});
    await pubsub?.close().catch(() => {});
    if (previousHost === undefined) delete process.env.PUBSUB_EMULATOR_HOST;
    else process.env.PUBSUB_EMULATOR_HOST = previousHost;
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    for (const restore of restores.reverse()) restore();
  }
}

test(
  "default emulator REST fallback credential acquisition is guarded before ADC",
  { timeout: 10000 },
  async () => {
    console.log(JSON.stringify(await probe(false)));
  },
);

test(
  "explicit anonymous REST fallback emits no Authorization with the real SDK",
  { timeout: 10000 },
  async () => {
    console.log(JSON.stringify(await probe(true)));
  },
);
