/** Real SDK and raw-target regressions for Hosting's offline boundary. */
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import vm from "node:vm";
import { noEgressProof, request } from "./run.mjs";
const require = createRequire(import.meta.url);
const destinations = [];
const originalFetch = globalThis.fetch;
let authOrigin;
// The pinned Node SDK captures fetch when its module is loaded.
globalThis.fetch = (input, options) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  assert.equal(url.origin, authOrigin, "SDK request must target the selected local Auth listener");
  destinations.push(url.origin);
  return originalFetch(input, options);
};
const firebase = require("firebase/compat/app");
require("firebase/compat/auth");
const binary = resolve(process.argv[2]);
const edges = JSON.parse(
  await readFile(new URL("../../fixtures/hosting/redirect-edges.json", import.meta.url)),
);
const failures = [];
async function check(name, run) {
  try {
    await run();
    console.log(JSON.stringify({ name, pass: true }));
  } catch (error) {
    failures.push(name);
    console.log(JSON.stringify({ name, pass: false, error: String(error) }));
  }
}
async function suite(only, hosting, hostingHost, run) {
  const dir = await mkdtemp(resolve(tmpdir(), "hosting-regression-"));
  await mkdir(resolve(dir, "home"));
  await mkdir(resolve(dir, "public"));
  const config = {
    hosting: { public: resolve(dir, "public"), ...hosting },
    emulators: {
      hosting: { host: hostingHost, port: 0 },
      auth: { port: 0 },
      ui: { enabled: false },
      hub: { port: 0 },
      logging: { port: 0 },
    },
  };
  await writeFile(resolve(dir, "firebase.json"), JSON.stringify(config));
  const ready = resolve(dir, "ready.json");
  const child = spawn(
    binary,
    [
      "up",
      "--only",
      only,
      "--project",
      "demo-hosting",
      "--firebase-json",
      resolve(dir, "firebase.json"),
      "--ready-file",
      ready,
      "--owner-stdin",
      "--log-verbosity",
      "quiet",
    ],
    {
      env: { PATH: process.env.PATH, HOME: resolve(dir, "home") },
      stdio: ["pipe", "ignore", "pipe"],
    },
  );
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c));
  try {
    let descriptor;
    for (let i = 0; i < 200; i++) {
      if (child.exitCode !== null) throw Error(`startup ${child.exitCode}: ${stderr}`);
      try {
        descriptor = JSON.parse(await readFile(ready));
        break;
      } catch {}
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(descriptor, "readiness deadline");
    await run(descriptor);
  } finally {
    child.stdin.end();
    if (child.exitCode === null)
      await Promise.race([
        new Promise((r) => child.once("exit", r)),
        new Promise((r) => setTimeout(r, 5000)),
      ]);
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await new Promise((r) => child.once("exit", r));
    }
    await rm(dir, { recursive: true, force: true });
  }
}
console.log(JSON.stringify({ noEgress: await noEgressProof() }));
for (const destination of [
  ...new Set(edges.rows.filter((r) => r.destination).map((r) => r.destination)),
]) {
  await check(`redirect ${destination}`, () =>
    suite(
      "hosting",
      { redirects: [{ source: "/go/:name", destination, type: 302 }] },
      "127.0.0.1",
      async (descriptor) => {
        const port = Number(new URL(descriptor.hostingUrl).port);
        for (const expected of edges.rows.filter((r) => r.destination === destination)) {
          const actual = await request(port, { id: expected.path, path: expected.path });
          console.log(JSON.stringify({ wireTarget: expected.path, actual }));
          assert.equal(actual.headers.location, expected.location, expected.path);
          assert.equal(
            new URL(actual.headers.location, "http://127.0.0.1").host,
            expected.authority,
          );
        }
        const malformed = await request(port, { path: edges.malformedQuery.path });
        assert.equal(malformed.status, 400);
        const alive = await request(port, { path: "/go/alive" });
        assert.equal(alive.status, 302);
      },
    ),
  );
}
await check("reserved priority", () =>
  suite(
    "hosting",
    { redirects: [{ source: "**", destination: "/maintenance", type: 302 }] },
    "127.0.0.1",
    async (descriptor) => {
      for (const [path, status] of [
        ["/__/firebase/init.json", 200],
        ["/__/firebase/init.js?useEmulator=true", 200],
        ["/__/firebase/12.18.0/firebase-app.js", 503],
        ["/ordinary", 302],
      ]) {
        const actual = await request(Number(new URL(descriptor.hostingUrl).port), { path });
        assert.equal(actual.status, status, path);
      }
    },
  ),
);
await check("excluded hosting", () =>
  suite("auth", {}, "0.0.0.0", async (descriptor) => {
    assert.ok(descriptor.environment.FIREBASE_AUTH_EMULATOR_HOST);
  }),
);
await check("selected hosting still rejects nonloopback", async () => {
  await assert.rejects(
    suite("hosting", {}, "0.0.0.0", async () => assert.fail("unsafe bind accepted")),
    /loopback/,
  );
});
await check("real compat Auth init and sign-in", () =>
  suite("hosting,auth", {}, "127.0.0.1", async (descriptor) => {
    assert.equal(firebase.apps.length, 0, "SDK must start empty");
    const port = Number(new URL(descriptor.hostingUrl).port);
    const config = await request(port, { path: "/__/firebase/init.json" });
    const script = await request(port, { path: "/__/firebase/init.js?useEmulator=true" });
    const target = new URL(`http://${descriptor.environment.FIREBASE_AUTH_EMULATOR_HOST}`);
    authOrigin = target.origin;
    destinations.length = 0;
    try {
      vm.runInNewContext(script.body, { firebase, console }, { timeout: 1000 });
      assert.deepEqual(JSON.parse(JSON.stringify(firebase.app().options)), JSON.parse(config.body));
      const auth = firebase.auth();
      assert.equal(auth.emulatorConfig.host, target.hostname);
      assert.equal(auth.emulatorConfig.port, Number(target.port));
      const result = await auth.signInAnonymously();
      assert.ok(result.user.uid);
      assert.ok(destinations.length > 0, "actual Auth request observed");
      console.log(JSON.stringify({ authDestinations: destinations }));
    } finally {
      await Promise.all(firebase.apps.map((app) => app.delete()));
    }
  }),
);
globalThis.fetch = originalFetch;
assert.deepEqual(failures, [], "Hosting regressions");
