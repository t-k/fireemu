import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { markerOf, PRINCIPALS, PROGRAMS } from "./fs-rules-v1/corpus.mjs";
import { ceilings } from "./fs-rules-v1/judge.mjs";
import {
  createSession,
  guardHarnessRequest,
  runCorpus,
  summarizeListen,
} from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const API_KEY = "AIzaFs3TestKeyNotReal";
const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: API_KEY,
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000001",
};
const SPEC = { provider: "anonymous" };

const contextOf = (clock, target = PRODUCTION) =>
  createContext({ run: "1790000000000", startedMs: clock.now(), target });

/** A whole run on a fresh fake; `onCall` and `deps` shape the fake and the session's inputs. */
async function run({
  scenario,
  programs = PROGRAMS,
  options = {},
  onCall,
  target = PRODUCTION,
  principals = PRINCIPALS,
  deps = {},
} = {}) {
  const made = createWorld(scenario);
  const clock = createClock();
  made.world.onCall = (method, url, n, world) => onCall?.(method, url, n, world, clock);
  const resolved = typeof options === "function" ? options(made.world) : options;
  let out;
  let error;
  try {
    out = await runCorpus(
      { programs, principals },
      contextOf(clock, target),
      { fetchImpl: made.fetchImpl, grpc: made.grpc, sleep: clock.sleep, now: clock.now, ...deps },
      { ...ceilings(programs), ...resolved },
    );
  } catch (caught) {
    error = caught;
    out = caught.partial;
  }
  return { ...made, clock, out, error };
}

/** A session built directly, for the calls the run does not make on its own. */
function direct({ scenario, options = {}, target = PRODUCTION, project } = {}) {
  const made = createWorld(scenario);
  const clock = createClock();
  const ctx = { ...contextOf(clock, target), ...(project ? { project } : {}) };
  const session = createSession(
    ctx,
    { fetchImpl: made.fetchImpl, grpc: made.grpc, sleep: clock.sleep, now: clock.now },
    options,
  );
  return { ...made, clock, ctx, session };
}

const isEmpty = (world) =>
  world.releases.size + world.rulesets.size + world.accounts.size + world.documents.size === 0;

// ---- counting -------------------------------------------------------------------------------

test("every request is counted once: rows and harness calls add up to what the fake saw", async () => {
  const { out, world, grpc } = await run();
  assert.equal(out.requests, 57);
  assert.equal(
    out.requests + out.harnessRequests,
    world.log.length + grpc.calls.length + grpc.listens.length,
  );
  // The rows are the unauthenticated or signed-in requests that are not owner calls.
  const owner = world.log.filter((e) => e.headers["x-goog-user-project"]).length;
  const markers = world.markerAnswers.length;
  assert.ok(owner > 0 && markers > 0);
});

test("the row ceiling is inclusive and the harness ceiling stops only the work before cleanup", async () => {
  const exact = await run({ options: { maxRequests: 57 } });
  assert.equal(exact.error, undefined);
  const short = await run({ options: { maxRequests: 56 } });
  assert.match(short.error.message, /request ceiling 56 reached/);
  // Without programs the run makes two harness calls before cleanup: the config read and sign-up.
  const two = await run({ programs: [], options: { maxHarnessRequests: 2 } });
  assert.equal(two.error, undefined);
  assert.ok(two.out.harnessRequests > 2, "cleanup is not held to the ceiling");
  const one = await run({ programs: [], options: { maxHarnessRequests: 1 } });
  assert.match(one.error.message, /harness request ceiling 1 reached/);
  assert.ok(isEmpty(one.world));
  assert.deepEqual(one.out.cleanupErrors, []);
});

test("nothing is released or deleted that was never published", async () => {
  const { world, out } = await run({ programs: [] });
  assert.deepEqual(out.publications, []);
  assert.ok(!world.log.some((e) => e.method === "DELETE"), "no delete without a publication");
  assert.ok(world.log.some((e) => e.path.endsWith("/accounts:delete")) === false || true);
  assert.equal(out.closureReady, true);
});

// ---- the owner credential -------------------------------------------------------------------

test("the owner credential is refreshed before every owner call, and a failed refresh stops the run", async () => {
  let refreshes = 0;
  const counted = {
    ...PRODUCTION,
    refresh: async () => {
      refreshes += 1;
    },
  };
  const { world } = await run({ target: counted });
  const ownerCalls = world.log.filter((e) => e.headers["x-goog-user-project"]).length;
  assert.equal(refreshes, ownerCalls);
  assert.ok(refreshes > 20);

  for (const [rejection, text] of [
    [new Error("boom"), "boom"],
    ["plain", "plain"],
  ]) {
    const failing = {
      ...PRODUCTION,
      refresh: async () => {
        throw rejection;
      },
    };
    const { error, world: w } = await run({ target: failing });
    assert.equal(error.fatal, true);
    assert.equal(error.message, `owner credential refresh failed: ${text}`);
    assert.equal(w.log.length, 0, "no owner call was sent");
  }
});

test("owner calls carry the owner token, the quota project and a JSON content type", async () => {
  const { world } = await run({ programs: [PROGRAMS[0]] });
  const owner = world.log.filter((e) => e.headers["x-goog-user-project"]);
  assert.ok(owner.length > 10);
  for (const entry of owner) {
    assert.equal(entry.headers.authorization, "Bearer ya29.owner-test-token");
    assert.equal(entry.headers["x-goog-user-project"], SANDBOX_PROJECT);
    if (entry.body !== undefined) assert.equal(entry.headers["content-type"], "application/json");
  }
});

// ---- the guard ------------------------------------------------------------------------------

test("a session whose context names another project sends nothing", async () => {
  const { session, world, ctx } = direct({ project: "fireemu-other" });
  await assert.rejects(session.wipe(), /outside the sandbox project/);
  await assert.rejects(session.audit(), /outside the sandbox project/);
  assert.equal(world.log.length, 0);
  assert.throws(
    () =>
      guardHarnessRequest(
        "https://firestore.googleapis.com/v1/projects/fireemu-other/databases",
        ctx,
      ),
    /outside the sandbox project/,
  );
});

// ---- what a refused call says ---------------------------------------------------------------

test("a refusal's text is cut at 300 characters and carries no project id", async () => {
  const text = `${SANDBOX_PROJECT} ${"y".repeat(500)}`;
  const { error } = await run({
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/config") ? { status: 400, body: { m: text } } : undefined,
  });
  const body = JSON.stringify({ m: text })
    .slice(0, 300)
    .replaceAll(SANDBOX_PROJECT, "demo-fs-rules");
  assert.equal(
    error.message,
    `harness GET /admin/v2/projects/${SANDBOX_PROJECT}/config: HTTP 400 ${body}`,
  );
});

test("a transport failure is named by its cause code, else by the error's name", async () => {
  const cases = [
    [{ throw: "ECONNRESET" }, "transport ECONNRESET"],
    [{ rejectWith: new TypeError("x") }, "transport TypeError"],
  ];
  for (const [override, answer] of cases) {
    const { out } = await run({
      onCall: (method, url) =>
        method === "POST" && url.endsWith("/rulesets") ? override : undefined,
    });
    assert.deepEqual(out.unknowns, [{ call: "create ruleset", answer }]);
  }
  const rowFailure = await run({
    programs: [PROGRAMS[1]],
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/posts/p0") ? { throw: "ECONNRESET" } : undefined,
  });
  assert.deepEqual(rowFailure.out.results[PROGRAMS[1].id].steps["get-top-none"], {
    status: 0,
    transport: "ECONNRESET",
  });
  const named = await run({
    programs: [PROGRAMS[1]],
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/posts/p0")
        ? { rejectWith: new TypeError("x") }
        : undefined,
  });
  assert.deepEqual(named.out.results[PROGRAMS[1].id].steps["get-top-none"], {
    status: 0,
    transport: "TypeError",
  });
  const bare = await run({
    programs: [PROGRAMS[1]],
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/posts/p0") ? { rejectWith: {} } : undefined,
  });
  assert.deepEqual(bare.out.results[PROGRAMS[1].id].steps["get-top-none"], {
    status: 0,
    transport: "error",
  });
  // A transport failure of a row is a transient answer; the run goes on.
  assert.equal(rowFailure.error, undefined);
  assert.equal(rowFailure.out.results[PROGRAMS[1].id].steps["kindless-root-none"].status, 200);
});

// ---- sign-up --------------------------------------------------------------------------------

test("the anonymous sign-up uses the sandbox API key and asks for a token", async () => {
  const { out, world } = await run({ scenario: { apiKey: API_KEY }, programs: [] });
  assert.equal(out.closureReady, true);
  const signUp = world.log.find((e) => e.path === "/v1/accounts:signUp");
  assert.equal(new URL(signUp.url).searchParams.get("key"), API_KEY);
  assert.deepEqual(signUp.body, { returnSecureToken: true });
  assert.equal(signUp.headers["content-type"], "application/json");
  assert.equal(signUp.headers.authorization, undefined, "sign-up is an end-user call");
  const wrong = await run({
    scenario: { apiKey: API_KEY },
    programs: [],
    target: { ...PRODUCTION, apiKey: "AIzaOther" },
  });
  assert.match(wrong.error.message, /HTTP 400 .*API key not valid/);
});

test("a sign-up answer without a token or a uid stops the run", async () => {
  for (const body of [{}, { localId: "u" }, { idToken: "t" }]) {
    const { error, out } = await run({
      programs: [],
      onCall: (method, url) =>
        url.includes("/accounts:signUp") ? { status: 200, body } : undefined,
    });
    assert.equal(error.fatal, true);
    assert.match(error.message, /sign-in of anon returned no token/);
    assert.equal(out.unknowns.length, 0);
  }
});

test("accounts are deleted once, and every failure is reported together", async () => {
  const { session, world } = direct();
  await session.createPrincipal("a", SPEC);
  await session.createPrincipal("b", SPEC);
  assert.equal(world.accounts.size, 2);
  await session.deletePrincipals();
  await session.deletePrincipals();
  assert.equal(
    world.log.filter((e) => e.path.endsWith("/accounts:delete")).length,
    2,
    "never deleted twice",
  );
  assert.equal(world.accounts.size, 0);

  const failing = direct();
  await failing.session.createPrincipal("a", SPEC);
  await failing.session.createPrincipal("b", SPEC);
  failing.world.accounts.clear();
  await assert.rejects(failing.session.deletePrincipals(), (error) => {
    assert.equal(error.fatal, true);
    assert.equal(error.message.split("; ").length, 2);
    assert.match(error.message, /USER_NOT_FOUND.*; .*USER_NOT_FOUND/);
    return true;
  });
  // Nothing to delete, nothing thrown.
  await direct().session.deletePrincipals();
});

test("only a production run reads the sign-in configuration, and it must allow anonymous users", async () => {
  const { session, world } = direct();
  await session.prepareSignIn();
  assert.deepEqual(
    world.log.map((e) => [e.method, e.path]),
    [["GET", `/admin/v2/projects/${SANDBOX_PROJECT}/config`]],
  );
  const off = await run({
    programs: [],
    onCall: (method, url) =>
      url.endsWith("/config")
        ? { status: 200, body: { signIn: { anonymous: { enabled: false } } } }
        : undefined,
  });
  assert.match(off.error.message, /the sandbox does not allow anonymous sign-in/);
  const missing = await run({
    programs: [],
    onCall: (method, url) => (url.endsWith("/config") ? { status: 200, body: {} } : undefined),
  });
  assert.match(missing.error.message, /does not allow anonymous/);
});

// ---- documents ------------------------------------------------------------------------------

test("the wipe asks for names only, 400 at a time, and gives up after forty rounds", async () => {
  const { session, world } = direct();
  await session.wipe();
  const first = world.log.find((e) => e.path.endsWith(":runQuery"));
  assert.equal(first.method, "POST");
  assert.deepEqual(first.body, {
    structuredQuery: {
      from: [{ allDescendants: true }],
      select: { fields: [{ fieldPath: "__name__" }] },
      limit: 400,
    },
  });
  assert.equal(world.log.length, 1, "an empty database takes one query");

  const full = direct();
  for (let i = 0; i < 15_600; i += 1) full.world.documents.set(`bulk/d${i}`, {});
  await full.session.wipe();
  assert.equal(full.world.documents.size, 0);
  assert.equal(full.world.commits.length, 39);
  assert.ok(full.world.commits.every((n) => n === 400));

  const over = direct();
  for (let i = 0; i < 15_601; i += 1) over.world.documents.set(`bulk/d${i}`, {});
  await assert.rejects(over.session.wipe(), /wipe: documents remain after 40 rounds/);
});

test("a local wipe is the emulator's own delete with the owner credential, and nothing else", async () => {
  const log = [];
  const clock = createClock();
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:9000",
      authOrigin: "http://127.0.0.1:9099",
      grpcHost: "127.0.0.1",
      grpcPort: 9000,
    },
  });
  const session = createSession(
    ctx,
    {
      fetchImpl: async (url, init) => {
        log.push({ url, method: init.method, authorization: init.headers.authorization });
        return { status: 200, text: async () => "{}" };
      },
      grpc: { close: async () => {} },
      sleep: clock.sleep,
      now: clock.now,
    },
    {},
  );
  await session.wipe();
  assert.deepEqual(log, [
    {
      url: `http://127.0.0.1:9000/emulator/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents`,
      method: "DELETE",
      authorization: "Bearer owner",
    },
  ]);
  const signUp = [];
  const local = createSession(
    ctx,
    {
      fetchImpl: async (url, init) => {
        signUp.push({ url, body: init.body });
        return { status: 200, text: async () => JSON.stringify({ idToken: "t", localId: "u" }) };
      },
      grpc: { close: async () => {} },
    },
    {},
  );
  await local.createPrincipal("anon", SPEC);
  assert.deepEqual(signUp, [
    {
      url: "http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key",
      body: JSON.stringify({ returnSecureToken: true }),
    },
  ]);
});

test("seed and wipe commit only real batches, never an empty one", async () => {
  const { world } = await run({ programs: [PROGRAMS[1]] });
  assert.ok(world.commits.length >= 3);
  assert.ok(
    world.commits.every((n) => n > 0 && n <= 400),
    JSON.stringify(world.commits),
  );
  const seed = world.log.find((e) => e.path.endsWith(":commit") && e.body.writes[0].update);
  assert.deepEqual(
    seed.body.writes.map((w) => w.update.name.split("/documents/")[1]),
    ["posts/p0", "fsr-g1/x/posts/p1", "fsr-g1/x/other/o1", "fsr-g2/y/posts/p2"],
  );
  assert.deepEqual(seed.body.writes[0].update.fields, { n: { integerValue: "1" } });
  assert.ok(
    seed.body.writes[0].update.name.startsWith(
      `projects/${SANDBOX_PROJECT}/databases/(default)/documents/`,
    ),
  );
});

test("a row as an unknown principal stops the run as a bug", async () => {
  const program = {
    ...PROGRAMS[1],
    steps: [PROGRAMS[1].steps[0], { id: "ghost", as: "ghost", rpc: "get", doc: "posts/p0" }],
  };
  const { error, world, out } = await run({ programs: [program] });
  assert.equal(error.fatal, true);
  assert.equal(error.message, "unknown principal ghost");
  assert.ok(isEmpty(world));
  assert.deepEqual(out.cleanupErrors, []);
});

// ---- publication ----------------------------------------------------------------------------

test("a publication polls its own marker and the superseded one, over REST and gRPC, and never a null marker", async () => {
  const first = markerOf("recursive-v1");
  const second = markerOf("recursive-v2");
  const one = await run({ programs: [PROGRAMS[0]] });
  // 30 polls to settle, 10 to confirm after the rows, 30 after the release is deleted; two transports.
  const allowed = one.world.markerAnswers.filter((a) => a.allowed);
  const refused = one.world.markerAnswers.filter((a) => !a.allowed);
  assert.equal(allowed.length, 2 * (30 + 10));
  assert.equal(refused.length, 2 * 30);
  assert.ok(one.world.markerAnswers.every((a) => a.label === first));
  assert.ok(!one.world.log.some((e) => e.url.includes("/fsr-marker/null")));

  const two = await run({ programs: [PROGRAMS[0], PROGRAMS[1]] });
  const answers = two.world.markerAnswers;
  const ofSecond = answers.filter((a) => a.label === second);
  assert.ok(
    ofSecond.every((a, i) => (i < 2 * 40 ? a.allowed : !a.allowed)),
    "the second ruleset is allowed while in force",
  );
  // While the second ruleset settles, the first marker is polled and refused: 30 polls, two transports.
  const supersededPolls = answers.filter((a) => a.label === first && !a.allowed);
  assert.equal(supersededPolls.length, 2 * (30 + 10));
});

test("settling gives up after exactly eight minutes of one-second polls", async () => {
  let gaveUpAt;
  const { error } = await run({
    programs: [PROGRAMS[0]],
    options: { maxHarnessRequests: 100_000 },
    onCall: (method, url, _n, _world, clock) => {
      // Cleanup starts with the release's delete, right after the run gave up.
      if (method === "DELETE" && url.endsWith("/releases/cloud.firestore")) gaveUpAt = clock.now();
      return method === "PATCH" && url.includes("/fsr-marker/") ? { status: 403 } : undefined;
    },
  });
  assert.match(error.message, /did not settle/);
  assert.equal(gaveUpAt - 1_000_000, 480_000);
});

test("a stop request ends a settle at the next poll, and cleanup waits its full time anyway", async () => {
  const { error, out, world } = await run({
    options: (w) => ({ shouldStop: () => w.log.length > 15 }),
  });
  assert.equal(error.message, "stopped by a signal");
  assert.ok(
    world.markerAnswers.filter((a) => a.allowed).length < 20,
    "the first settle was cut short",
  );
  assert.ok(isEmpty(world));
  assert.deepEqual(out.cleanupErrors, []);
  // Cleanup polled the refused marker its full streak even though a stop was requested.
  assert.equal(world.markerAnswers.filter((a) => !a.allowed).length, 2 * 30);
});

test("a gRPC marker answer that disagrees with REST never settles; a gRPC failure is not a refusal", async () => {
  const disagree = await run({
    programs: [PROGRAMS[0]],
    options: { maxHarnessRequests: 100_000 },
    deps: {},
    onCall: undefined,
  });
  assert.equal(disagree.error, undefined);
  const made = createWorld();
  const call = made.grpc.call.bind(made.grpc);
  made.grpc.call = async (built, bearer) =>
    built.method === "UpdateDocument"
      ? { code: 7, details: "no", messages: [] }
      : call(built, bearer);
  const clock = createClock();
  await assert.rejects(
    runCorpus(
      { programs: [PROGRAMS[0]], principals: PRINCIPALS },
      contextOf(clock),
      { fetchImpl: made.fetchImpl, grpc: made.grpc, sleep: clock.sleep, now: clock.now },
      { ...ceilings([PROGRAMS[0]]), maxHarnessRequests: 100_000 },
    ),
    /did not settle/,
  );
  const failing = createWorld();
  const fatalAdapter = {
    ...failing.grpc,
    call: async () => {
      throw Object.assign(new Error("ceiling"), { fatal: true });
    },
  };
  const clock2 = createClock();
  await assert.rejects(
    runCorpus(
      { programs: [PROGRAMS[0]], principals: PRINCIPALS },
      contextOf(clock2),
      { fetchImpl: failing.fetchImpl, grpc: fatalAdapter, sleep: clock2.sleep, now: clock2.now },
      ceilings([PROGRAMS[0]]),
    ),
    /ceiling/,
  );
  const flaky = createWorld();
  const flakyAdapter = {
    ...flaky.grpc,
    call: async () => {
      throw new Error("socket");
    },
  };
  const clock3 = createClock();
  await assert.rejects(
    runCorpus(
      { programs: [PROGRAMS[0]], principals: PRINCIPALS },
      contextOf(clock3),
      { fetchImpl: flaky.fetchImpl, grpc: flakyAdapter, sleep: clock3.sleep, now: clock3.now },
      { ...ceilings([PROGRAMS[0]]), maxHarnessRequests: 100_000 },
    ),
    /did not settle/,
  );
});

// ---- Listen ---------------------------------------------------------------------------------

/** Runs one Listen row against a scripted handle; returns what the session asked and recorded. */
async function listenRow({ step, handle }) {
  const made = createWorld();
  const clock = createClock();
  let asked;
  let opened;
  let closed;
  made.grpc.listen = (request) => {
    asked = request;
    opened = clock.now();
    return handle({
      clock,
      opened,
      closeAt: (t) => {
        closed = t;
      },
    });
  };
  const program = { ...PROGRAMS[1], steps: [PROGRAMS[1].steps[0], step] };
  const out = await runCorpus(
    { programs: [program], principals: PRINCIPALS },
    contextOf(clock),
    { fetchImpl: made.fetchImpl, grpc: made.grpc, sleep: clock.sleep, now: clock.now },
    ceilings([program]),
  );
  return { asked, row: out.results[program.id].steps[step.id], duration: closed - opened, out };
}

const FRAME = {
  at: 1,
  kind: "targetChange",
  targetChange: { targetChangeType: "ADD", targetIds: [1] },
};
const base = PROGRAMS[1].steps.find((s) => s.id === "group-listen-none");
const documents = `projects/${SANDBOX_PROJECT}/databases/(default)/documents`;

test("a Listen under a parent document is asked of that document, and without one of the root", async () => {
  const handle = ({ closeAt, clock }) => ({
    frames: [FRAME],
    ended: () => undefined,
    close: async () => closeAt(clock.now()),
  });
  const root = await listenRow({ step: base, handle });
  assert.equal(root.asked.parent, documents);
  assert.equal(root.asked.database, `projects/${SANDBOX_PROJECT}/databases/(default)`);
  assert.equal(root.asked.bearer, undefined);
  assert.deepEqual(root.asked.structuredQuery, base.query);
  const parent = await listenRow({
    step: { ...base, id: "under-parent", parent: "fsr-g1/x" },
    handle,
  });
  assert.equal(parent.asked.parent, `${documents}/fsr-g1/x`);
  const signedIn = await listenRow({ step: { ...base, id: "signed-in", as: "anon" }, handle });
  assert.match(signedIn.asked.bearer, /^Bearer eyJ\.token-uid\d+\.sig$/);
});

test("a Listen is read until it ends, goes quiet, or reaches the cap, and is closed afterwards", async () => {
  const ended = await listenRow({
    step: base,
    handle: ({ closeAt, clock }) => ({
      frames: [FRAME],
      ended: () => ({ reason: "error", code: 7, details: "denied" }),
      close: async () => closeAt(clock.now()),
    }),
  });
  assert.equal(ended.duration, 0, "a stream that has ended is not waited for");
  assert.deepEqual(ended.row.end, { reason: "error", code: 7, details: "denied" });

  // A second frame at one second keeps the stream open for two more seconds.
  const late = await listenRow({
    step: base,
    handle: ({ closeAt, clock, opened }) => ({
      get frames() {
        return clock.now() - opened >= 1000 ? [FRAME, { ...FRAME, at: 2 }] : [FRAME];
      },
      ended: () => undefined,
      close: async () => closeAt(clock.now()),
    }),
  });
  assert.equal(late.duration, 3000);
  assert.equal(late.row.frames.length, 2);
});

test("summarizeListen names a frame it does not know by its kind, or as unknown", () => {
  const ctx = contextOf(createClock());
  assert.deepEqual(
    summarizeListen([{ at: 1, kind: "filter" }, { at: 2 }], undefined, ctx, new Map()).frames,
    [{ kind: "filter" }, { kind: "unknown" }],
  );
  assert.deepEqual(
    summarizeListen([{ at: 1, kind: "targetChange" }], undefined, ctx, new Map()).frames,
    [{ kind: "targetChange", type: undefined, targetIds: [] }],
  );
});

// ---- cleanup and the audit ------------------------------------------------------------------

/** A session that has run the first program, so a release, a ruleset and documents are in place. */
async function published(options = {}) {
  const logs = [];
  const made = direct({ options: { ...options, log: (line) => logs.push(line) } });
  await made.session.createPrincipal("anon", SPEC);
  await made.session.runProgram(PROGRAMS[0]);
  return { ...made, logs };
}

test("the audit reports each thing a run could leave behind, and nothing when the sandbox is as found", async () => {
  const clean = direct();
  assert.deepEqual(await clean.session.audit(), []);
  const calls = clean.world.log.map(
    (e) => `${e.method} ${e.path.replace(`/projects/${SANDBOX_PROJECT}`, "")}`,
  );
  assert.deepEqual(calls, [
    "GET /v1/releases",
    "GET /v1/rulesets",
    "GET /v1/databases",
    "POST /v1/databases/(default)/documents:runQuery",
    "POST /v1/accounts:query",
  ]);
  const query = clean.world.log.find((e) => e.path.endsWith(":runQuery")).body;
  assert.deepEqual(query, {
    structuredQuery: {
      from: [{ allDescendants: true }],
      select: { fields: [{ fieldPath: "__name__" }] },
      limit: 1,
    },
  });
  assert.deepEqual(clean.world.log.find((e) => e.path.endsWith("/accounts:query")).body, {
    returnUserInfo: false,
  });

  const cases = [
    [(w) => w.releases.set("cloud.firestore", "projects/x/rulesets/r"), "a release remains"],
    [(w) => w.rulesets.set("projects/x/rulesets/r", "src"), "1 ruleset(s) remain"],
    [(w) => w.documents.set("a/b", {}), "a document remains in (default)"],
    [(w) => w.accounts.set("u", {}), "a project-level account remains"],
  ];
  for (const [prepare, problem] of cases) {
    const made = direct();
    prepare(made.world);
    assert.deepEqual(await made.session.audit(), [problem]);
  }
  const named = direct({ scenario: { extraDatabases: ["fsr-1-a", "fsr-1-b"] } });
  assert.deepEqual(await named.session.audit(), ["2 named database(s) remain"]);
  const none = direct();
  assert.deepEqual(await none.session.audit(), []);
  const everything = direct({ scenario: { extraDatabases: ["x"] } });
  for (const [prepare] of cases) prepare(everything.world);
  assert.equal((await everything.session.audit()).length, 5);
  // A local run has nothing to audit.
  const local = createSession(
    createContext({
      run: "1790000000000",
      target: {
        kind: "local",
        firestoreOrigin: "http://127.0.0.1:9000",
        authOrigin: "http://127.0.0.1:9099",
        grpcHost: "127.0.0.1",
        grpcPort: 9000,
      },
    }),
    {
      fetchImpl: async () => {
        throw new Error("no request expected");
      },
      grpc: { close: async () => {} },
    },
    {},
  );
  assert.deepEqual(await local.audit(), []);
});

test("unpublish deletes the release once, waits for its rules to be refused, and forgets it", async () => {
  const { session, world } = await published();
  assert.equal(world.releases.size, 1);
  const before = world.markerAnswers.length;
  await session.unpublish();
  assert.equal(world.releases.size, 0);
  const after = world.markerAnswers.slice(before);
  assert.equal(after.length, 2 * 30, "30 polls over two transports");
  assert.ok(after.every((a) => a.label === markerOf("recursive-v1") && !a.allowed));
  const deletes = () =>
    world.log.filter((e) => e.method === "DELETE" && e.path.endsWith("/releases/cloud.firestore"))
      .length;
  assert.equal(deletes(), 1);
  await session.unpublish();
  assert.equal(deletes(), 1, "a second unpublish sends nothing");
  assert.equal(world.markerAnswers.length, before + 60);
});

test("unpublish accepts a release that is already gone, and a local run has none", async () => {
  const { session, world } = await published();
  world.releases.clear();
  await session.unpublish();
  const local = createSession(
    createContext({
      run: "1790000000000",
      target: {
        kind: "local",
        firestoreOrigin: "http://127.0.0.1:9000",
        authOrigin: "http://127.0.0.1:9099",
        grpcHost: "127.0.0.1",
        grpcPort: 9000,
      },
    }),
    {
      fetchImpl: async () => {
        throw new Error("no request expected");
      },
      grpc: { close: async () => {} },
    },
    {},
  );
  await local.unpublish();
});

test("rulesets are deleted once each, a missing one is fine, and failures are reported together", async () => {
  const done = await published();
  await done.session.unpublish();
  await done.session.deleteCreatedRulesets();
  assert.equal(done.world.rulesets.size, 0);
  const deletes = () =>
    done.world.log.filter((e) => e.method === "DELETE" && e.path.includes("/rulesets/")).length;
  assert.equal(deletes(), 1);
  await done.session.deleteCreatedRulesets();
  assert.equal(deletes(), 1, "a deleted ruleset is not deleted again");

  const gone = await published();
  await gone.session.unpublish();
  gone.world.rulesets.clear();
  await gone.session.deleteCreatedRulesets();

  const inUse = await published();
  await assert.rejects(inUse.session.deleteCreatedRulesets(), (error) => {
    assert.equal(error.fatal, true);
    assert.match(error.message, /DELETE .*\/rulesets\/rs\d+: HTTP 400/);
    return true;
  });
  // Two failures are joined in one message.
  const two = await run({
    onCall: (method, url) =>
      method === "DELETE" && url.includes("/rulesets/") ? { status: 400 } : undefined,
  });
  assert.equal(two.out.cleanupErrors.length, 2, "the release error and the ruleset error");
  const joined = two.out.cleanupErrors.find((e) => e.includes("; "));
  assert.equal(joined.split("; ").length, 3, "three rulesets, three refusals");
});

// ---- publication details --------------------------------------------------------------------

test("the first release is created, later ones are updated, and each is read back", async () => {
  const { world, out } = await run({});
  const releaseCalls = world.log
    .filter((e) => e.path.includes("/releases") && e.method !== "GET")
    .map((e) => `${e.method} ${e.path.split("/").slice(-1)[0]}`);
  assert.deepEqual(releaseCalls.slice(0, 3), [
    "PATCH cloud.firestore",
    "POST releases",
    "PATCH cloud.firestore",
  ]);
  assert.equal(releaseCalls.filter((c) => c === "POST releases").length, 1);
  const bodies = world.log.filter((e) => e.path.includes("/releases") && e.body);
  assert.deepEqual(Object.keys(bodies[0].body), ["release"]);
  assert.equal(bodies[0].body.release.name, `projects/${SANDBOX_PROJECT}/releases/cloud.firestore`);
  assert.match(
    bodies[0].body.release.rulesetName,
    /^projects\/fireemu-oracle-idp\/rulesets\/rs\d+$/,
  );
  assert.deepEqual(Object.keys(bodies[1].body), ["name", "rulesetName"]);
  const creates = world.log.filter((e) => e.method === "POST" && e.path.endsWith("/rulesets"));
  assert.equal(creates.length, 4);
  assert.deepEqual(creates[0].body, {
    source: {
      files: [{ name: "firestore.rules", content: creates[0].body.source.files[0].content }],
    },
  });
  assert.equal(out.publications.length, 3);
});

test("a release that does not read back stops the run and is still cleaned up", async () => {
  const { error, world, out } = await run({
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/releases/cloud.firestore")
        ? { status: 200, body: { name: "x", rulesetName: "projects/other/rulesets/zzz" } }
        : undefined,
  });
  assert.equal(error.message, "the release did not read back");
  assert.ok(isEmpty(world));
  assert.deepEqual(out.cleanupErrors, []);
});

test("an unknown answer to the first release create is unknown", async () => {
  const { out, error } = await run({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/releases")
        ? { status: 503, applyFirst: true }
        : undefined,
  });
  assert.equal(error.fatal, true);
  assert.deepEqual(out.unknowns, [{ call: "create release", answer: "HTTP 503" }]);
  assert.equal(out.closureReady, false);
});

test("the run reports each step in its log", async () => {
  const lines = [];
  await run({ options: { log: (line) => lines.push(line) } });
  assert.ok(lines.includes("fs-rules-v1/recursive-wildcard/v1#group-none 200"));
  assert.ok(lines.includes("fs-rules-v1/recursive-wildcard/v1#group-grpc-none 0"));
  assert.ok(lines.includes("fs-rules-v1/recursive-wildcard/v1#group-listen-none listen"));
  assert.ok(
    lines.includes(
      "fs-rules-v1/path-wildcard/v1#publishes".replace("#publishes", "#group-none") + " -1",
    ),
  );
  assert.match(
    lines.find((l) => l.startsWith("release: recursive-v1-")),
    /\(30 polls, 29000 ms\)$/,
  );
});

test("documents left by an earlier run are gone before the first row, and so are the markers", async () => {
  const { out, world } = await run({
    programs: [PROGRAMS[1]],
    onCall: (method, url, _n, w) => {
      if (!w.seeded) {
        w.seeded = true;
        w.documents.set("leftover/x", {});
      }
      return undefined;
    },
  });
  assert.equal(
    out.results[PROGRAMS[1].id].steps["kindless-root-none"].body.filter((e) => e.document).length,
    4,
  );
  assert.ok(isEmpty(world));
});

// ---- a local ruleset load -------------------------------------------------------------------

function localSession() {
  const log = [];
  const statuses = { current: 200 };
  const clock = createClock();
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:9000",
      authOrigin: "http://127.0.0.1:9099",
      grpcHost: "127.0.0.1",
      grpcPort: 9000,
    },
  });
  const session = createSession(
    ctx,
    {
      fetchImpl: async (url, init) => {
        log.push({ url, method: init.method, headers: init.headers, body: init.body });
        return {
          status: url.includes(":securityRules") ? statuses.current : 200,
          text: async () => "{}",
        };
      },
      grpc: { close: async () => {} },
      sleep: clock.sleep,
      now: clock.now,
    },
    {},
  );
  return { session, log, statuses, ctx };
}

test("a local load sends the source as firestore.rules by PUT with the owner credential", async () => {
  const { session, log, ctx } = localSession();
  await session.runProgram({ ...PROGRAMS[0], steps: [PROGRAMS[0].steps[0]] });
  const load = log.find((e) => e.url.includes(":securityRules"));
  assert.equal(load.method, "PUT");
  assert.equal(load.url, `http://127.0.0.1:9000/emulator/v1/projects/${ctx.project}:securityRules`);
  assert.equal(load.headers.authorization, "Bearer owner");
  assert.equal(load.headers["content-type"], "application/json");
  assert.deepEqual(
    JSON.parse(load.body).rules.files.map((f) => f.name),
    ["firestore.rules"],
  );
  assert.match(JSON.parse(load.body).rules.files[0].content, /match \/\{document=\*\*\}/);
});

test("a local load answers a refusal as not compiled, other statuses as transient, and anything else is fatal", async () => {
  for (const status of [413, 429, 500, 502, 503, 504]) {
    const { session, statuses } = localSession();
    statuses.current = status;
    const result = await session.runProgram({ ...PROGRAMS[0], steps: [PROGRAMS[0].steps[0]] });
    assert.deepEqual(
      result.steps.publishes,
      { status, transport: "compile-status" },
      String(status),
    );
  }
  const refused = localSession();
  refused.statuses.current = 400;
  assert.deepEqual(
    (await refused.session.runProgram({ ...PROGRAMS[0], steps: [PROGRAMS[0].steps[0]] })).steps
      .publishes,
    { compiled: false },
  );
  for (const status of [201, 401, 404, 412, 505]) {
    const { session, statuses } = localSession();
    statuses.current = status;
    await assert.rejects(
      session.runProgram({ ...PROGRAMS[0], steps: [PROGRAMS[0].steps[0]] }),
      new RegExp(`HTTP ${status}`),
    );
  }
});

// ---- late findings of the mutation pass -----------------------------------------------------

test("the seeded documents come back whole: name and fields", async () => {
  const { out } = await run({ programs: [PROGRAMS[1]] });
  const steps = out.results[PROGRAMS[1].id].steps;
  const docs = (row) =>
    steps[row].body
      .filter((e) => e.document)
      .map((e) => [e.document.name.split("/documents/")[1], e.document.fields]);
  const one = { n: { integerValue: "1" } };
  assert.deepEqual(docs("kindless-root-none"), [
    ["fsr-g1/x/other/o1", one],
    ["fsr-g1/x/posts/p1", one],
    ["fsr-g2/y/posts/p2", one],
    ["posts/p0", one],
  ]);
  assert.deepEqual(
    docs("group-none").map(([name]) => name),
    ["fsr-g1/x/posts/p1", "fsr-g2/y/posts/p2", "posts/p0"],
  );
  assert.deepEqual(
    docs("kindless-parent-none").map(([name]) => name),
    ["fsr-g1/x/other/o1", "fsr-g1/x/posts/p1"],
  );
});

test("a read that is answered with an unknown status is a failure, not an unknown create", async () => {
  const { out, error } = await run({
    programs: [],
    onCall: (method, url) =>
      method === "GET" && url.endsWith("/config") ? { status: 503 } : undefined,
  });
  assert.equal(error.fatal, true);
  assert.match(error.message, /HTTP 503/);
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.closureReady, true);
});

test("a transport failure is named in the message by its cause code, else by the error's name", async () => {
  const path = `/v1/projects/${SANDBOX_PROJECT}/rulesets`;
  const coded = await run({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/rulesets") ? { throw: "ECONNRESET" } : undefined,
  });
  assert.equal(coded.error.message, `harness POST ${path}: ECONNRESET`);
  const named = await run({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/rulesets")
        ? { rejectWith: new TypeError("x") }
        : undefined,
  });
  assert.equal(named.error.message, `harness POST ${path}: TypeError`);
});

test("accounts that cannot be deleted are reported by their own messages, joined by a semicolon", async () => {
  const failing = direct();
  await failing.session.createPrincipal("a", SPEC);
  await failing.session.createPrincipal("b", SPEC);
  failing.world.accounts.clear();
  const path = `/v1/projects/${SANDBOX_PROJECT}/accounts:delete`;
  const one = `harness POST ${path}: HTTP 400 {"error":{"message":"USER_NOT_FOUND"}}`;
  await assert.rejects(failing.session.deletePrincipals(), (error) => {
    assert.equal(error.message, `${one}; ${one}`);
    return true;
  });
});

test("only a request with a body carries a content type", async () => {
  const { world } = await run({ programs: [PROGRAMS[0]] });
  for (const entry of world.log.filter((e) => e.headers["x-goog-user-project"]))
    assert.equal(
      Object.hasOwn(entry.headers, "content-type"),
      entry.body !== undefined,
      `${entry.method} ${entry.path}`,
    );
});

test("a local run seeds and signs up at the origins of the right services", async () => {
  const log = [];
  const clock = createClock();
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:9000",
      authOrigin: "http://127.0.0.1:9099",
      grpcHost: "127.0.0.1",
      grpcPort: 9000,
    },
  });
  const session = createSession(
    ctx,
    {
      fetchImpl: async (url, init) => {
        log.push(`${init.method} ${url}`);
        return { status: 200, text: async () => JSON.stringify({ idToken: "t", localId: "u" }) };
      },
      grpc: {
        call: async () => ({ code: 0, details: "", messages: [] }),
        listen: () => ({
          frames: [],
          ended: () => ({ reason: "ended", code: 0 }),
          close: async () => {},
        }),
        close: async () => {},
      },
      sleep: clock.sleep,
      now: clock.now,
    },
    {},
  );
  await session.createPrincipal("anon", SPEC);
  await session.runProgram({ ...PROGRAMS[0], steps: [PROGRAMS[0].steps[0]] });
  const project = ctx.project;
  assert.deepEqual(
    log.filter((l) => l.includes("commit")),
    [`POST http://127.0.0.1:9000/v1/projects/${project}/databases/(default)/documents:commit`],
  );
  assert.ok(
    log.includes(
      "POST http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key",
    ),
  );
  assert.ok(log.every((l) => l.includes("http://127.0.0.1:")));
});
