import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { BLOCKING_PROGRAMS } from "./auth-tenant-blocking/blocking-corpus.mjs";
import {
  FIXTURE_FUNCTIONS,
  REQUIRED_APIS,
  createDeployer,
  isFixtureArtifact,
  isFixtureTrigger,
} from "./auth-tenant-blocking/deploy.mjs";
import { validateTenantCorpus } from "./auth-tenant-blocking/guard.mjs";

const PROJECT = "fireemu-oracle-idp";
const NUMBER = "637500000000";
const fn = (name) => ({ functionUri: `https://${name.toLowerCase()}-abc123-uc.a.run.app` });

/**
 * A fake of the REST surfaces the deployer calls. `state` is what exists; `calls` records every
 * request as `METHOD path`.
 */
function fakeCloud({
  apis = REQUIRED_APIS,
  functions = [],
  blocking = {},
  packages = [],
  sources = [],
  uploads = [],
} = {}) {
  const state = {
    functions: [...functions],
    blocking: structuredClone(blocking),
    packages: [...packages],
    sources: [...sources],
    uploads: [...uploads],
  };
  const calls = [];
  const json = (status, body) => new Response(JSON.stringify(body ?? {}), { status });
  const fetchImpl = async (url, init = {}) => {
    const { pathname, hostname } = new URL(url);
    const method = init.method ?? "GET";
    calls.push(`${method} ${hostname}${pathname}`);
    if (hostname === "serviceusage.googleapis.com")
      return json(200, {
        state: apis.includes(pathname.split("/").at(-1)) ? "ENABLED" : "DISABLED",
      });
    if (hostname === "cloudfunctions.googleapis.com")
      return json(200, {
        functions: state.functions.map((name) => ({ name: `x/functions/${name}` })),
      });
    if (pathname.endsWith("/config")) {
      if (method === "PATCH") state.blocking = JSON.parse(init.body).blockingFunctions;
      return json(200, { blockingFunctions: state.blocking });
    }
    if (hostname === "artifactregistry.googleapis.com") {
      if (method === "DELETE") {
        state.packages = state.packages.filter((p) => !pathname.endsWith(p));
        return json(200, {});
      }
      return json(200, {
        packages: state.packages.map((p) => ({ name: `projects/x/packages/${p}` })),
      });
    }
    if (hostname === "storage.googleapis.com") {
      const bucket = pathname.split("/b/")[1].split("/")[0];
      const key = bucket.startsWith("gcf-v2-uploads") ? "uploads" : "sources";
      if (method === "DELETE") {
        const name = decodeURIComponent(pathname.split("/o/")[1]);
        state[key] = state[key].filter((o) => o !== name);
        return new Response(null, { status: 204 });
      }
      return json(200, { items: state[key].map((name) => ({ name })) });
    }
    if (hostname === "run.googleapis.com")
      return json(200, { bindings: [{ role: "roles/run.invoker", members: ["allUsers"] }] });
    if (hostname.endsWith(".run.app")) return json(400, {});
    return json(404, {});
  };
  const runs = [];
  const run = async (file, args) => {
    runs.push([file.split("/").at(-1), ...args].join(" "));
    if (args[0] === "deploy") {
      state.functions.push(...Object.values(FIXTURE_FUNCTIONS));
      state.blocking = {
        triggers: Object.fromEntries(
          Object.entries(FIXTURE_FUNCTIONS).map(([event, name]) => [event, fn(name)]),
        ),
        forwardInboundCredentials: {},
      };
      state.packages.push("fireemu--oracle--idp__us--central1__atb_before_create");
      state.sources.push("atbBeforeCreate/function-source.zip");
      state.uploads.push("d6b1a2c3-random.zip");
    }
    if (args[0] === "functions:delete")
      state.functions = state.functions.filter((name) => !args.includes(name));
    return { stdout: "", stderr: "" };
  };
  const deployer = createDeployer({
    project: PROJECT,
    number: NUMBER,
    token: async () => "ya29.fake",
    fetchImpl,
    run,
    retryMs: 0,
  });
  return { state, calls, runs, deployer };
}

const buildDir = async () => join(await mkdtemp(join(tmpdir(), "atb-deploy-")), "build");
const source = new URL("./auth-tenant-blocking/function", import.meta.url).pathname;

test("the deployer refuses another project", () => {
  assert.throws(
    () => createDeployer({ project: "fireemu-35fe6", number: NUMBER, token: async () => "" }),
    /only to the sandbox/,
  );
});

test("the preflight refuses a missing API, an existing function or a registered trigger (MF-2)", async () => {
  await assert.rejects(
    fakeCloud({
      apis: REQUIRED_APIS.filter((api) => !api.startsWith("pubsub")),
    }).deployer.preflight(),
    /pubsub/,
  );
  await assert.rejects(fakeCloud({ functions: ["other"] }).deployer.preflight(), /functions exist/);
  await assert.rejects(
    fakeCloud({ blocking: { triggers: { beforeCreate: fn("other") } } }).deployer.preflight(),
    /already registered/,
  );
});

test("nothing is removed before a deployment started (MF-1)", async () => {
  const { deployer, calls, runs } = fakeCloud({
    blocking: { triggers: { beforeCreate: fn("other") } },
  });
  await assert.rejects(deployer.preflight());
  assert.deepEqual(await deployer.remove(await buildDir()), { removed: "nothing deployed" });
  assert.ok(!calls.some((c) => c.startsWith("PATCH") || c.startsWith("DELETE")));
  assert.deepEqual(runs, []);
});

test("a removal takes out exactly what the deployment created (MF-1, MF-3)", async () => {
  const { deployer, state, runs } = fakeCloud({
    packages: ["other-image"],
    sources: ["other/function-source.zip"],
    uploads: ["older-upload.zip"],
  });
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  assert.deepEqual(
    (await deployer.verifyRegistered()).functions,
    Object.values(FIXTURE_FUNCTIONS).toSorted(),
  );
  const removed = await deployer.remove(dir);
  assert.equal(removed.images, 1);
  assert.equal(removed.sources, 2);
  assert.deepEqual(state.functions, []);
  assert.deepEqual(state.blocking, {});
  assert.deepEqual(state.packages, ["other-image"]);
  assert.deepEqual(state.sources, ["other/function-source.zip"]);
  assert.deepEqual(state.uploads, ["older-upload.zip"]);
  assert.ok(runs.some((r) => r.startsWith("firebase deploy --only functions:atb-blocking")));
  assert.ok(runs.some((r) => r.startsWith("firebase functions:delete atbBeforeCreate")));
});

test("a trigger of another function stops the removal untouched (MF-1)", async () => {
  const { deployer, state } = fakeCloud();
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  state.blocking.triggers.beforeCreate = fn("someoneElse");
  await assert.rejects(deployer.remove(dir), /another function/);
  assert.deepEqual(state.blocking.triggers.beforeCreate, fn("someoneElse"));
});

test("fixture artifacts are recognised by function name only", () => {
  assert.ok(isFixtureArtifact("fireemu--oracle--idp__us--central1__atb_before_create"));
  assert.ok(isFixtureArtifact("fireemu--oracle--idp__us--central1__atb_before_send_sms/cache"));
  assert.ok(isFixtureArtifact("atbBeforeSignIn/function-source.zip"));
  assert.ok(!isFixtureArtifact("fireemu--oracle--idp__us--central1__hello"));
  assert.ok(isFixtureTrigger(fn("atbBeforeCreate")));
  assert.ok(!isFixtureTrigger(fn("hello")));
});

test("the blocking corpus is valid", () => {
  const requests = validateTenantCorpus(BLOCKING_PROGRAMS);
  assert.ok(requests > 50 && requests < 200, `${requests}`);
  for (const program of BLOCKING_PROGRAMS) {
    assert.match(program.id, /^atb\/blocking\//);
    assert.equal(program.functions, true);
  }
});
