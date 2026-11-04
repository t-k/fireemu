// The read-back: reads only, absence judged only by a direct 404 NOT_FOUND (or an account lookup with no user), the lists
// checked, the configuration compared with the baseline the run recorded, and a leftover or an unreadable answer keeps it from
// saying everything is gone.
import assert from "node:assert/strict";
import test from "node:test";
import { PROJECT, functionName, packageIds } from "./plan.mjs";
import { READBACK_MAX_REQUESTS, SETTLE_MS, readbackAllow, readbackRun } from "./readback.mjs";
import { configDigest, record } from "./run.mjs";
import { deleteAccount, signUp } from "./script.mjs";
import { LOCAL_ID, NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const path = (request) => new URL(request.url).pathname;
async function afterRun(worldOptions = {}) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, result };
}
const baseline = (result) => ({
  localId: result.signUp.localId,
  accountsBefore: result.inventory.before.accounts,
  configBeforeDigest: result.configBefore.sha256,
});
const readback = (world, result, over = {}) =>
  readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: over.send ?? world.send,
    ...baseline(result),
    baseline: world.baseline,
    ...over.options,
  });

test("after a clean run everything reads absent and nothing is sent but reads", async () => {
  const { world, result } = await afterRun();
  const before = world.calls.length;
  const rb = await readback(world, result);
  assert.equal(rb.allAbsent, true);
  const calls = world.calls.slice(before);
  assert.ok(
    calls.every(
      (c) => c.startsWith("GET ") || c.endsWith("accounts:lookup") || c.endsWith("accounts:query"),
    ),
    calls.join("\n"),
  );
  assert.ok(rb.attempted <= READBACK_MAX_REQUESTS);
  assert.deepEqual(
    Object.keys(rb.names).toSorted(),
    ["account", "function", ...packageIds().map((id) => "package-" + id)].toSorted(),
  );
  assert.deepEqual(rb.lists, { functionAndService: true, packages: [] });
  assert.deepEqual(rb.config, { blockingEmpty: true, digestMatches: true });
  assert.deepEqual(rb.accounts, { before: 3, after: 3 });
  assert.equal(rb.unknown, 0);
  assert.deepEqual(rb.incompleteReads, []);
  assert.equal(SETTLE_MS, 600_000);
  assert.equal(READBACK_MAX_REQUESTS, 60);
});

test("without an account id, no account is read and the names are the function and its images", async () => {
  const { world, result } = await afterRun({ hooks: {} });
  const rb = await readback(world, result, { options: { localId: null } });
  assert.deepEqual(
    Object.keys(rb.names).toSorted(),
    ["function", ...packageIds().map((id) => "package-" + id)].toSorted(),
  );
  assert.equal(rb.allAbsent, true);
});

const LEFTOVERS = [
  [
    "the function",
    (w) => w.functions.set(functionName(), { name: functionName(), state: "ACTIVE" }),
  ],
  ["the service", (w) => w.runServices.add("pcblock")],
  ["an image", (w) => w.packages.add(packageIds()[1])],
  ["the account", (w) => w.accounts.set(LOCAL_ID, { localId: LOCAL_ID })],
];
for (const [what, seed] of LEFTOVERS)
  test(`${what} that is still there is not absent`, async () => {
    const { world, result } = await afterRun();
    seed(world);
    assert.equal((await readback(world, result)).allAbsent, false);
  });

test("a trigger still registered, another configuration change, an unreadable configuration and a different account count are not a clean read", async () => {
  const stillThere = await afterRun();
  stillThere.world.config.blockingFunctions = {
    triggers: { beforeCreate: { functionUri: "https://x.run.app" } },
  };
  const a = await readback(stillThere.world, stillThere.result);
  assert.equal(a.allAbsent, false);
  assert.equal(a.config.blockingEmpty, false);
  const changed = await afterRun();
  changed.world.config.mfa = { state: "ENABLED" };
  const b = await readback(changed.world, changed.result);
  assert.deepEqual(b.config, { blockingEmpty: true, digestMatches: false });
  assert.equal(b.allAbsent, false);
  const unreadable = await afterRun();
  const c = await readback(unreadable.world, unreadable.result, {
    send: (request) =>
      path(request).endsWith("/config")
        ? Promise.resolve(reply(500, { error: { status: "INTERNAL" } }))
        : unreadable.world.send(request),
  });
  assert.equal(c.config, null);
  assert.equal(c.allAbsent, false);
  assert.ok(c.incompleteReads.some((r) => r.id === "read-config"));
  const count = await afterRun();
  count.world.accounts.set("extra", { localId: "extra" });
  const d = await readback(count.world, count.result);
  assert.deepEqual(d.accounts, { before: 3, after: 4 });
  assert.equal(d.allAbsent, false);
  const noBaseline = await afterRun();
  const e = await readback(noBaseline.world, noBaseline.result, {
    options: { accountsBefore: null },
  });
  assert.equal(e.allAbsent, false, "without the recorded count there is nothing to compare with");
  const noDigest = await afterRun();
  const f = await readback(noDigest.world, noDigest.result, {
    options: { configBeforeDigest: null },
  });
  assert.equal(f.config.digestMatches, null);
  assert.equal(f.allAbsent, false);
});

test("a 404 that is not NOT_FOUND, an unreadable answer, a 5xx and a transport error are not absence", async () => {
  const { world, result } = await afterRun();
  const url = "GET cloudfunctions.googleapis.com/v2/" + functionName();
  for (const answer of [
    () => reply(404, { error: { status: "PERMISSION_DENIED", code: 404 } }),
    () => new Response("not json", { status: 404 }),
    () => reply(500, { error: { status: "INTERNAL", code: 500 } }),
    () => "throw",
  ]) {
    const rb = await readback(world, result, {
      send: async (request) => {
        const u = new URL(request.url);
        if (request.method + " " + u.hostname + u.pathname === url) {
          const out = answer();
          if (out === "throw") throw new Error("transport");
          return out;
        }
        return world.send(request);
      },
    });
    assert.equal(rb.allAbsent, false);
  }
});

test("an account lookup that answers with a user, or fails, is not absence", async () => {
  const { world, result } = await afterRun();
  for (const answer of [
    () => reply(200, { users: [{ localId: LOCAL_ID }] }),
    () => reply(500, { error: { status: "INTERNAL" } }),
    () => reply(400, { error: { message: "USER_NOT_FOUND" } }),
  ]) {
    const rb = await readback(world, result, {
      send: async (request) =>
        path(request).endsWith("accounts:lookup") ? answer() : world.send(request),
    });
    assert.equal(rb.names.account.absent, false);
    assert.equal(rb.allAbsent, false);
  }
});

test("a list that cannot be read, or runs past five pages, is incomplete and not allAbsent", async () => {
  const { world, result } = await afterRun();
  const broken = await readback(world, result, {
    send: async (request) =>
      request.url.includes("/packages?")
        ? reply(500, { error: { status: "INTERNAL" } })
        : world.send(request),
  });
  assert.equal(broken.allAbsent, false);
  assert.ok(broken.incompleteReads.some((r) => r.id === "list-packages"));
  assert.equal(broken.lists.packages, null);
  let pages = 0;
  const endless = await readback(world, result, {
    send: async (request) => {
      if (request.method === "GET" && /\/locations\/-\/functions(\?|$)/.test(request.url)) {
        pages++;
        return reply(200, { nextPageToken: "t" + pages });
      }
      return world.send(request);
    },
  });
  assert.equal(pages, 5, "a sixth page is never read");
  assert.ok(
    endless.incompleteReads.some(
      (r) => r.id === "list-functions-v2" && r.status === "more-than-five-pages",
    ),
  );
  assert.equal(endless.allAbsent, false);
});

test("a 401 stops the read-back and is recorded", async () => {
  const { world, result } = await afterRun();
  const rb = await readback(world, result, {
    send: async () => reply(401, { error: { status: "UNAUTHENTICATED" } }),
  });
  assert.equal(rb.allAbsent, false);
  assert.ok(rb.authStop);
});

test("an error that is not a stop is not swallowed", async () => {
  const { world, result } = await afterRun();
  await assert.rejects(
    readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {
        throw new Error("disk full");
      },
      clock: () => world.now,
      send: world.send,
      ...baseline(result),
    }),
    /private persistence failed/,
  );
});

test("the allowlist refuses every mutation, an account that was not adopted, and any read outside the run's names", () => {
  const { allow } = readbackAllow(RUN, NUMBER, LOCAL_ID);
  assert.equal(allow(deleteAccount(LOCAL_ID)), false);
  assert.equal(allow(signUp(RUN)), false);
  assert.equal(
    allow({ method: "DELETE", url: `https://cloudfunctions.googleapis.com/v2/${functionName()}` }),
    false,
  );
  assert.equal(
    allow({
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/${packageIds()[0]}`,
    }),
    false,
  );
  assert.equal(
    allow({ method: "GET", url: `https://cloudfunctions.googleapis.com/v2/${functionName()}` }),
    true,
  );
  assert.equal(
    allow({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`,
      json: { localId: [LOCAL_ID] },
    }),
    true,
  );
  assert.equal(
    readbackAllow(RUN, NUMBER, null).allow({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`,
      json: { localId: [LOCAL_ID] },
    }),
    false,
  );
  assert.equal(
    allow({
      method: "GET",
      url: `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions/other`,
    }),
    false,
  );
  assert.equal(configDigest({}).length, 64);
});
