// The App Engine app: created once, after every other check has passed, only when the project has none (owner ledger
// 2226), kept afterwards, never re-sent, and never closed on a guess.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { APP_ENGINE_LOCATION, PROJECT, TOPIC } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send, options = {}) {
  const world = createWorld({ runId: RUN, appEngine: false, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => (sleeps.push(ms), world.advance(ms)),
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;

test("the guard allows exactly one App Engine create: this project, this location, no other field", () => {
  const guard = createGuard(RUN, NUMBER);
  const post = (json) => ({
    method: "POST",
    url: "https://appengine.googleapis.com/v1/apps",
    json,
  });
  assert.equal(guard.allow(post({ id: PROJECT, locationId: APP_ENGINE_LOCATION })), true);
  assert.equal(guard.isMutation(post({ id: PROJECT, locationId: APP_ENGINE_LOCATION })), true);
  for (const bad of [
    { id: "other", locationId: APP_ENGINE_LOCATION },
    { id: PROJECT, locationId: "europe-west" },
    { id: PROJECT },
    { locationId: APP_ENGINE_LOCATION },
    { id: PROJECT, locationId: APP_ENGINE_LOCATION, authDomain: "x" },
    undefined,
    [],
  ])
    assert.equal(guard.allow(post(bad)), false, JSON.stringify(bad));
  const get = (path) => ({ method: "GET", url: "https://appengine.googleapis.com" + path });
  assert.equal(guard.allow(get(`/v1/apps/${PROJECT}`)), true);
  assert.equal(guard.allow(get(`/v1/apps/${PROJECT}/operations/abc-123`)), true);
  assert.equal(guard.isMutation(get(`/v1/apps/${PROJECT}/operations/abc-123`)), false);
  assert.equal(guard.allow(get(`/v1/apps/other/operations/abc`)), false);
  assert.equal(
    guard.allow({ method: "DELETE", url: `https://appengine.googleapis.com/v1/apps/${PROJECT}` }),
    false,
  );
  assert.equal(
    guard.allow({
      method: "PATCH",
      url: `https://appengine.googleapis.com/v1/apps/${PROJECT}`,
      json: {},
    }),
    false,
  );
  assert.equal(APP_ENGINE_LOCATION, "us-central");
});

test("a project without the app gets it after the dry run and before the topic, and keeps it", async () => {
  const { result, world, journal } = await go();
  assert.equal(result.outcome, "pycheck-recorded");
  assert.deepEqual(result.appEngine, {
    status: 404,
    missing: true,
    createClass: "2xx",
    created: true,
  });
  const order = ids(journal);
  const at = (id) => order.indexOf(id);
  assert.ok(at("appengine-app") < at("bucket") && at("bucket") < at("preflight-functions-v2"));
  assert.ok(at("preflight-topics") < at("create-appengine"), "after every preflight read");
  assert.ok(
    at("create-appengine") < at("appengine-operation-1") &&
      at("appengine-operation-1") < at("settle-appengine") &&
      at("settle-appengine") < at("create-topic"),
  );
  assert.equal(count(world, "POST appengine"), 1);
  assert.equal(count(world, "DELETE appengine"), 0, "the app is kept");
  assert.equal(world.app.locationId, "us-central");
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.closureReady, true);
});

test("the operation is read until it is done, at most thirty times, ten seconds apart", async () => {
  const quick = await go();
  assert.equal(ids(quick.journal).filter((id) => id.startsWith("appengine-operation-")).length, 2);
  assert.equal(quick.sleeps.filter((ms) => ms === 10_000).length, 2);
  const stuck = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("/operations/")
        ? reply(200, { name: "x", done: false })
        : send(request),
  );
  assert.equal(ids(stuck.journal).filter((id) => id.startsWith("appengine-operation-")).length, 30);
  assert.equal(stuck.result.outcome, "pycheck-recorded", "the app itself is what settles it");
  const noName = await go(
    {},
    (send) => async (request) =>
      request.method === "POST" && request.url.endsWith("/v1/apps")
        ? (await send(request), reply(200, {}))
        : send(request),
  );
  assert.equal(ids(noName.journal).filter((id) => id.startsWith("appengine-operation-")).length, 0);
  const done = await go(
    {},
    (send) => async (request) =>
      request.method === "POST" && request.url.endsWith("/v1/apps")
        ? (await send(request), reply(200, { name: "apps/x/operations/y", done: true }))
        : send(request),
  );
  assert.equal(ids(done.journal).filter((id) => id.startsWith("appengine-operation-")).length, 0);
  const waits = await go({}, (send) => send, { waits: { appEngine: 3, appEnginePolls: 1 } });
  assert.equal(waits.sleeps.filter((ms) => ms === 3000).length, 1);
});

test("a refused create is a clean stop before the topic and the deploy", async () => {
  for (const status of [400, 403, 409, 429]) {
    const { result, world } = await go(
      {},
      (send) => async (request) =>
        request.method === "POST" && request.url.endsWith("/v1/apps")
          ? error(status, "X")
          : send(request),
    );
    if (status === 403) {
      assert.equal(result.outcome, "pycheck-auth-stop");
      continue;
    }
    assert.equal(result.outcome, "pycheck-stopped-clean", String(status));
    assert.equal(result.stoppedBecause, "appengine");
    assert.equal(result.stage, "app-engine");
    assert.equal(result.closureReady, false);
    assert.deepEqual(world.cliRuns, ["dry-run"]);
    assert.equal(world.topics.has(TOPIC), false);
    assert.deepEqual(result.unconfirmedCreates, []);
  }
});

test("an unknown answer to the create is never re-sent; an own read that shows the app settles it, none does not", async () => {
  for (const unknown of ["throw", "503"]) {
    const applied = await go({}, (send) => async (request) => {
      if (request.method === "POST" && request.url.endsWith("/v1/apps")) {
        await send(request);
        if (unknown === "throw") throw new Error("reset");
        return error(503, "UNAVAILABLE");
      }
      return send(request);
    });
    assert.equal(count(applied.world, "POST appengine"), 1, unknown);
    assert.deepEqual(applied.result.unconfirmedCreates, [], "the own read showed the app");
    assert.equal(applied.result.unknownMutations, 1);
    assert.equal(applied.result.closureReady, false);
    assert.equal(applied.result.readBackRequired, true);
    assert.equal(applied.result.outcome, "pycheck-needs-review");
    assert.equal(applied.result.appEngine.created, true);
    const unseen = await go({}, (send) => async (request) => {
      if (request.method === "POST" && request.url.endsWith("/v1/apps")) {
        if (unknown === "throw") throw new Error("reset");
        return error(503, "UNAVAILABLE");
      }
      return send(request);
    });
    assert.equal(unseen.result.outcome, "pycheck-needs-review");
    assert.equal(unseen.result.stoppedBecause, "appengine");
    assert.deepEqual(
      unseen.result.unconfirmedCreates.map((c) => [c.label, c.id, c.name]),
      [["appengine", "create-appengine", `apps/${PROJECT}`]],
    );
    assert.deepEqual(unseen.world.cliRuns, ["dry-run"]);
    assert.equal(
      ids(unseen.journal).filter((id) => id === "create-appengine").length,
      1,
      "sent once",
    );
    assert.equal(unseen.result.closureReady, false);
  }
});

test("a create that answers 2xx but whose app cannot be read, or sits in another location, is not accepted", async () => {
  const hidden = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" &&
      request.url.endsWith(`/apps/${PROJECT}`) &&
      request.url.length &&
      (await send(request)).status === 200
        ? error(404, "NOT_FOUND")
        : send(request),
  );
  assert.notEqual(hidden.result.outcome, "pycheck-recorded");
  const elsewhere = await go({}, (send) => async (request) => {
    const answer = await send(request);
    if (
      request.method === "GET" &&
      request.url.endsWith(`/apps/${PROJECT}`) &&
      answer.status === 200
    )
      return reply(200, { name: "apps/x", locationId: "europe-west" });
    return answer;
  });
  assert.equal(elsewhere.result.stoppedBecause, "appengine");
  assert.deepEqual(elsewhere.world.cliRuns, ["dry-run"]);
  assert.equal(elsewhere.result.unconfirmedCreates.length, 1);
});

test("the app is not created when anything else in the preflight stops the run, nor when it exists", async () => {
  const dirty = await go({}, (send, world) => (world.topics.add(TOPIC), send));
  assert.equal(dirty.result.stoppedBecause, "namespace");
  assert.equal(count(dirty.world, "POST appengine"), 0);
  const exists = await go({ appEngine: true });
  assert.equal(count(exists.world, "POST appengine"), 0);
  assert.deepEqual(exists.result.appEngine, { status: 200 });
  assert.equal(ids(exists.journal).includes("create-appengine"), false);
  const forbidden = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith(`/apps/${PROJECT}`) && request.method === "GET"
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(forbidden.result.stoppedBecause, "appengine");
  assert.equal(
    count(forbidden.world, "POST appengine"),
    0,
    "only a clear not-found allows the create",
  );
  const unreadable = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith(`/apps/${PROJECT}`) && request.method === "GET"
        ? new Response("gone", { status: 404 })
        : send(request),
  );
  assert.equal(unreadable.result.stoppedBecause, "appengine");
  assert.equal(count(unreadable.world, "POST appengine"), 0);
});

test("a dry run that fails does not create the app", async () => {
  const world = createWorld({ runId: RUN, appEngine: false });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: async ({ action }) => (world.cliRuns.push(action), { action, exitCode: 1 }),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.stoppedBecause, "the CLI dry run failed");
  assert.equal(world.app, null);
});
