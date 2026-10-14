import assert from "node:assert/strict";
import { test } from "node:test";

import { scanFixture } from "./auth-account/fixture-scan.mjs";
import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  HARNESS_CAP,
  markerOf,
  PRINCIPALS,
  PROGRAMS,
  REQUEST_CAP,
  rulesetSource,
} from "./fs-rules-v1/corpus.mjs";
import { ceilings, fixtureText, mockToken } from "./fs-rules-v1/judge.mjs";
import {
  guardHarnessRequest,
  isUnknownStatus,
  LISTEN_CAP_MS,
  LISTEN_IDLE_MS,
  runCorpus,
  SETTLE_STREAK,
  summarizeListen,
} from "./fs-rules-v1/session.mjs";
import { brief } from "./fs-rules-v1/judge.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const API_KEY = "AIzaFs3TestKeyNotReal";
const NUMBER = "555500000001";
const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: API_KEY,
  quotaProject: SANDBOX_PROJECT,
  projectNumber: NUMBER,
};

async function record({
  scenario,
  options = {},
  programs = PROGRAMS,
  onCall,
  target = PRODUCTION,
} = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  world.onCall = (method, url, n) => onCall?.(method, url, n, world);
  const resolved = typeof options === "function" ? options(world) : options;
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target });
  let out;
  let error;
  try {
    out = await runCorpus(
      { programs, principals: PRINCIPALS },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      { ...ceilings(programs), ...resolved },
    );
  } catch (caught) {
    error = caught;
    out = caught.partial;
  }
  return { out, error, world, grpc, clock };
}

const isMarker = (url) => url.includes("/fsr-marker/");
const isEmpty = (world) =>
  world.releases.size === 0 &&
  world.rulesets.size === 0 &&
  world.accounts.size === 0 &&
  world.documents.size === 0;

// ---- a whole recording ----------------------------------------------------------------------

test("a recording leaves the sandbox as it found it and stays inside its ceilings", async () => {
  const { out, error, world } = await record();
  assert.equal(error, undefined);
  assert.deepEqual(out.failures, []);
  assert.deepEqual(out.cleanupErrors, []);
  assert.equal(out.closureReady, true);
  assert.ok(isEmpty(world), "no release, ruleset, account or document remains");
  assert.ok(out.requests <= REQUEST_CAP);
  assert.equal(out.requests, 3 * 19, "three published rulesets, 19 rows each");
  assert.ok(out.harnessRequests <= HARNESS_CAP, `harness requests ${out.harnessRequests}`);
});

test("every request addresses the sandbox project and nothing else", async () => {
  const { world } = await record();
  const hosts = new Set([
    "firestore.googleapis.com",
    "firebaserules.googleapis.com",
    "identitytoolkit.googleapis.com",
  ]);
  for (const { host, path, url } of world.log) {
    assert.ok(hosts.has(host), `unexpected host ${host}`);
    assert.ok(
      path.startsWith(`/v1/projects/${SANDBOX_PROJECT}/`) ||
        path.startsWith(`/admin/v2/projects/${SANDBOX_PROJECT}/`) ||
        path === "/v1/accounts:signUp",
      `unexpected path ${path}`,
    );
    assert.ok(!/databases\/(?!\(default\))/.test(path), `another database: ${path}`);
    if (!path.includes("/documents/") || path.endsWith(":commit"))
      guardHarnessRequest(url, createContext({ run: "1790000000000", target: PRODUCTION }));
  }
  assert.ok(world.log.length > 100);
});

test("the default scenario records the finding: v1 lets a group query through", async () => {
  const { out } = await record();
  const v1 = out.results["fs-rules-v1/recursive-wildcard/v1"].steps;
  assert.deepEqual(v1.publishes, { compiled: true });
  assert.equal(v1["group-none"].status, 200);
  assert.equal(v1["group-count-none"].status, 200);
  assert.equal(v1["group-grpc-none"].grpc, 0);
  assert.equal(v1["group-listen-none"].frames.at(-1).type, "CURRENT");
  // The path form does not compile under v1 in this scenario: nothing else of that program ran.
  const path = out.results["fs-rules-v1/path-wildcard/v1"].steps;
  assert.deepEqual(path.publishes, { compiled: false });
  assert.deepEqual(path["group-none"], {
    status: -1,
    unresolved: "ruleset path-v1 did not compile",
  });
  assert.equal(out.diagnostics["path-v1"].status, 400);
  assert.equal(out.diagnostics["path-v1"].stage, "ruleset");
  assert.ok(!out.diagnostics["path-v1"].message.includes(SANDBOX_PROJECT));
});

test("a ruleset whose release is refused (400) is recorded as not compiled and deleted at the end", async () => {
  const { out, world, error } = await record({ scenario: { pathV1: "release-refused" } });
  assert.equal(error, undefined);
  const v1 = out.results["fs-rules-v1/path-wildcard/v1"].steps;
  assert.deepEqual(v1.publishes, { compiled: false });
  assert.equal(v1["group-none"].unresolved, "ruleset path-v1 did not compile");
  assert.equal(out.diagnostics["path-v1"].stage, "release");
  assert.ok(!out.diagnostics["path-v1"].message.includes(SANDBOX_PROJECT));
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.closureReady, true);
  assert.ok(isEmpty(world), "the refused release's ruleset was deleted");
  assert.equal(out.requests, 3 * 19);
});

test("an unknown answer to a release update is unknown, and the run does not read it as a refusal", async () => {
  const { out, error } = await record({
    onCall: (method, url) =>
      method === "PATCH" && url.endsWith("/releases/cloud.firestore") ? { status: 503 } : undefined,
  });
  assert.equal(error.fatal, true);
  assert.deepEqual(out.unknowns, [{ call: "update release", answer: "HTTP 503" }]);
  assert.equal(out.closureReady, false);
});

test("a principal that is not an anonymous sign-up is refused before it is created", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  await assert.rejects(
    runCorpus(
      { programs: [], principals: { x: { provider: "password" } } },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      ceilings([]),
    ),
    /only anonymous sign-up is supported, not password/,
  );
  assert.ok(!world.log.some((e) => e.path.endsWith("/accounts:signUp")));
  assert.equal(world.accounts.size, 0);
});

test("a production that refuses group queries under v1 is recorded as it answers", async () => {
  const { out } = await record({ scenario: { v1Group: "deny" } });
  const v1 = out.results["fs-rules-v1/recursive-wildcard/v1"].steps;
  const v2 = out.results["fs-rules-v1/recursive-wildcard/v2"].steps;
  for (const row of ["group-none", "group-anon", "group-count-none", "kindless-root-none"])
    assert.equal(v1[row].status, 403, row);
  assert.equal(v1["group-grpc-none"].grpc, 7);
  assert.equal(v1["group-listen-none"].frames[0].cause.code, 7);
  // The controls and the v2 ruleset are unaffected.
  for (const row of ["single-none", "nested-none", "get-top-none"])
    assert.equal(v1[row].status, 200, row);
  for (const row of ["group-none", "group-count-none", "kindless-root-none"])
    assert.equal(v2[row].status, 200, row);
});

test("no secret, token, project id or number is recorded", async () => {
  const { out } = await record();
  const text = JSON.stringify(out);
  for (const secret of [API_KEY, "ya29.", "eyJ", SANDBOX_PROJECT, NUMBER, "AIza"])
    assert.ok(!text.includes(secret), `recorded ${secret}`);
  const meta = { startedAt: "2026-10-14T00:00:00.000Z", sha: "0".repeat(40), harness: "h" };
  const fixture = fixtureText({ programs: PROGRAMS, recordings: [out, out], meta });
  scanFixture(fixture, [API_KEY, SANDBOX_PROJECT, NUMBER]);
  assert.ok(!fixture.includes("diagnostics") || !fixture.includes(SANDBOX_PROJECT));
});

// ---- publication ----------------------------------------------------------------------------

test("a publication settles only after a streak of agreeing marker polls on REST and gRPC", async () => {
  const { out, world, grpc } = await record();
  assert.equal(out.publications.length, 3);
  for (const publication of out.publications) assert.equal(publication.polls, SETTLE_STREAK);
  assert.equal(out.publications[1].previous, out.publications[0].label);
  assert.equal(out.publications[0].previous, null);
  const first = markerOf("recursive-v1");
  const markerWrites = world.log.filter((e) => e.method === "PATCH" && isMarker(e.url));
  assert.ok(markerWrites.filter((e) => e.url.includes(first)).length >= SETTLE_STREAK);
  assert.ok(grpc.calls.some((c) => c.method === "UpdateDocument"));
  // The superseded marker is checked refused once a second ruleset is in force.
  assert.ok(markerWrites.some((e) => e.url.includes(markerOf("recursive-v1"))));
});

test("a ruleset that production refuses to compile is recorded, with the next one still polled against the last in force", async () => {
  const { out } = await record();
  const labels = out.publications.map((p) => p.label);
  assert.deepEqual(labels, [
    markerOf("recursive-v1"),
    markerOf("recursive-v2"),
    markerOf("path-v2"),
  ]);
  // path-v1 was refused, so path-v2 supersedes recursive-v2.
  assert.equal(out.publications[2].previous, markerOf("recursive-v2"));
});

test("a publication that never settles stops the run, and cleanup still empties the sandbox", async () => {
  const { error, world, out } = await record({
    options: { maxHarnessRequests: 100_000 },
    onCall: (method, url) => (method === "PATCH" && isMarker(url) ? { status: 403 } : undefined),
  });
  assert.equal(error.fatal, true);
  assert.match(error.message, /did not settle/);
  assert.ok(isEmpty(world));
  assert.equal(out.cleanupErrors.length, 0);
});

test("rows count only while their ruleset stays in force", async () => {
  let swapped = false;
  const { out } = await record({
    programs: [PROGRAMS[0]],
    onCall: (method, url, _n, world) => {
      if (!swapped && method === "GET" && url.includes("/fsr-g1/x/posts/p1")) {
        swapped = true;
        world.rulesets.set(
          "projects/fireemu-oracle-idp/rulesets/other",
          rulesetSource("recursive-v2"),
        );
        world.releases.set("cloud.firestore", "projects/fireemu-oracle-idp/rulesets/other");
      }
      return undefined;
    },
  });
  const steps = out.results[PROGRAMS[0].id].steps;
  assert.ok(Object.values(steps).every((row) => row.publication === "unsettled"));
});

test("a request ceiling stops the run with cleanup done; the harness ceiling too", async () => {
  const rows = await record({ options: { maxRequests: 5 } });
  assert.match(rows.error.message, /request ceiling 5 reached/);
  assert.ok(isEmpty(rows.world));
  const harness = await record({ options: { maxHarnessRequests: 40 } });
  assert.match(harness.error.message, /harness request ceiling 40 reached/);
  assert.ok(isEmpty(harness.world));
  assert.deepEqual(harness.out.cleanupErrors, []);
});

test("a stop request ends the run at the next step and cleans up", async () => {
  const { error, out, world } = await record({
    options: (w) => ({ shouldStop: () => w.log.length > 120 }),
  });
  assert.equal(error.fatal, true);
  assert.match(error.message, /stopped by a signal/);
  assert.ok(isEmpty(world));
  assert.deepEqual(out.cleanupErrors, []);
  assert.equal(out.closureReady, true);
});

test("a request the guards refuse stops the run as a bug, not as a program failure", async () => {
  const bad = {
    ...PROGRAMS[0],
    steps: [PROGRAMS[0].steps[0], { id: "escape", as: "none", rpc: "get", doc: "a/../b" }],
  };
  const { error, world } = await record({ programs: [bad] });
  assert.equal(error.fatal, true);
  assert.match(error.message, /not canonical/);
  assert.ok(isEmpty(world));
});

test("production runs address the sandbox project only", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const ctx = {
    ...createContext({ run: "1790000000000", target: PRODUCTION }),
    project: "fireemu-other",
  };
  await assert.rejects(
    runCorpus({ programs: PROGRAMS, principals: PRINCIPALS }, ctx, { fetchImpl, grpc }),
    /sandbox project only/,
  );
  assert.equal(world.log.length, 0);
});

// ---- unknown and ambiguous answers (checklist section 3) ------------------------------------

test("isUnknownStatus: below 200, 3xx and 5xx are unknown; 2xx and 4xx are answers", () => {
  const unknown = [0, 100, 199, 300, 301, 304, 399, 500, 503, 599];
  const known = [200, 201, 204, 299, 400, 403, 404, 409, 429, 499];
  for (const status of unknown) assert.equal(isUnknownStatus(status), true, String(status));
  for (const status of known) assert.equal(isUnknownStatus(status), false, String(status));
});

test("an unknown create is never retried, never settled by a 404, and keeps the run not closure-ready", async () => {
  for (const status of [199, 301, 500, 503]) {
    const { out, error, world } = await record({
      onCall: (method, url) =>
        method === "POST" && url.endsWith("/rulesets") ? { status, applyFirst: true } : undefined,
    });
    assert.equal(error.fatal, true, `status ${status}`);
    assert.deepEqual(out.unknowns, [{ call: "create ruleset", answer: `HTTP ${status}` }]);
    assert.equal(out.closureReady, false);
    assert.equal(
      world.log.filter((e) => e.method === "POST" && e.url.endsWith("/rulesets")).length,
      1,
    );
    // The ruleset the lost answer hid is found by the audit, not assumed gone.
    assert.ok(
      out.cleanupErrors.some((e) => /ruleset\(s\) remain/.test(e)),
      `status ${status}`,
    );
  }
});

test("an unknown create that took no effect is still unconfirmed; a later 404 settles nothing", async () => {
  const { out, world } = await record({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/rulesets") ? { throw: "ETIMEDOUT" } : undefined,
  });
  assert.deepEqual(out.unknowns, [{ call: "create ruleset", answer: "transport ETIMEDOUT" }]);
  assert.equal(out.closureReady, false);
  assert.ok(isEmpty(world));
  // Cleanup read the empty lists, which does not turn the unknown create into a confirmed absence.
  assert.deepEqual(out.cleanupErrors, []);
});

test("an unknown release delete is sent once and keeps the run not closure-ready", async () => {
  const { out, world } = await record({
    onCall: (method, url) =>
      method === "DELETE" && url.endsWith("/releases/cloud.firestore")
        ? { status: 503 }
        : undefined,
  });
  const deletes = world.log.filter(
    (e) => e.method === "DELETE" && e.url.endsWith("/releases/cloud.firestore"),
  );
  assert.equal(deletes.length, 1);
  assert.deepEqual(out.unknowns, [{ call: "delete release", answer: "HTTP 503" }]);
  assert.equal(out.closureReady, false);
  assert.ok(out.cleanupErrors.length > 0);
  assert.equal(
    world.releases.size,
    1,
    "the release is still there; the run does not claim otherwise",
  );
});

test("a confirmed create whose read-back is a 404 is deleted by its own delete, not assumed gone", async () => {
  let first = true;
  const { out, error, world } = await record({
    onCall: (method, url) => {
      if (method === "GET" && url.endsWith("/releases/cloud.firestore") && first) {
        first = false;
        return { status: 404 };
      }
      return undefined;
    },
  });
  assert.equal(error.fatal, true);
  assert.match(error.message, /HTTP 404/);
  assert.deepEqual(out.unknowns, []);
  assert.ok(isEmpty(world), "the release and the ruleset were deleted by their own requests");
  assert.deepEqual(out.cleanupErrors, []);
});

test("an unknown account delete or sign-up is reported and leaves the audit to find the account", async () => {
  const del = await record({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/accounts:delete") ? { status: 502 } : undefined,
  });
  assert.deepEqual(del.out.unknowns, [{ call: "delete account", answer: "HTTP 502" }]);
  assert.ok(del.out.cleanupErrors.some((e) => /account/.test(e)));
  assert.equal(del.out.closureReady, false);

  const signUp = await record({
    onCall: (method, url) =>
      method === "POST" && url.includes("/accounts:signUp")
        ? { status: 500, applyFirst: true }
        : undefined,
  });
  assert.equal(signUp.error.fatal, true);
  assert.deepEqual(signUp.out.unknowns, [{ call: "sign-up", answer: "HTTP 500" }]);
  assert.ok(signUp.out.cleanupErrors.some((e) => /account/.test(e)));
});

test("a definite refusal of a create (429) stops the run but is not an unknown answer", async () => {
  const { out, error, world } = await record({
    onCall: (method, url) =>
      method === "POST" && url.endsWith("/rulesets") ? { status: 429 } : undefined,
  });
  assert.equal(error.fatal, true);
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.closureReady, true);
  assert.ok(isEmpty(world));
});

// ---- request shapes -------------------------------------------------------------------------

test("the fake refuses write bodies that miss a required field, as production does", async () => {
  const { fetchImpl } = createWorld();
  const owner = {
    authorization: "Bearer ya29.x",
    "content-type": "application/json",
    "x-goog-user-project": SANDBOX_PROJECT,
  };
  const base = `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}`;
  const post = (url, body) =>
    fetchImpl(url, { method: "POST", headers: owner, body: JSON.stringify(body) });
  assert.equal((await post(`${base}/rulesets`, {})).status, 400);
  assert.equal(
    (await post(`${base}/rulesets`, { source: { files: [{ name: "firestore.rules" }] } })).status,
    400,
  );
  assert.equal((await post(`${base}/releases`, { name: "x" })).status, 400);
  const documents = `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents`;
  assert.equal((await post(`${documents}:commit`, {})).status, 400);
  assert.equal(
    (
      await post(`${documents}:runAggregationQuery`, {
        structuredAggregationQuery: { structuredQuery: { from: [{}] } },
      })
    ).status,
    400,
  );
});

test("the bodies the session sends carry every field the API requires", async () => {
  const { world } = await record({ programs: [PROGRAMS[0]] });
  // Every write call succeeded against a fake that refuses missing fields (a 400 would be fatal).
  const writes = world.log.filter(
    (e) => e.method !== "GET" && e.host === "firebaserules.googleapis.com",
  );
  assert.ok(writes.length >= 4);
  assert.equal(
    world.log.filter((e) => e.url.endsWith("/accounts:signUp?key=" + API_KEY)).length,
    1,
  );
});

// ---- Listen ---------------------------------------------------------------------------------

const ctxFor = () => createContext({ run: "1790000000000", target: PRODUCTION });

test("summarizeListen keeps what is behaviour and drops times, tokens and arrival order", () => {
  const name = (id) => `projects/${SANDBOX_PROJECT}/databases/(default)/documents/posts/${id}`;
  const frames = [
    {
      at: 5,
      kind: "targetChange",
      targetChange: { targetChangeType: "ADD", targetIds: [1], resumeToken: "AAAA", readTime: "t" },
    },
    { at: 7, kind: "documentChange", documentChange: { document: { name: name("b") } } },
    { at: 8, kind: "documentChange", documentChange: { document: { name: name("a") } } },
    {
      at: 9,
      kind: "targetChange",
      targetChange: { targetChangeType: "CURRENT", targetIds: [1], resumeToken: "BBBB" },
    },
  ];
  const summary = summarizeListen(
    frames,
    { reason: "closed-by-harness", at: 99 },
    ctxFor(),
    new Map(),
  );
  assert.deepEqual(summary, {
    listen: true,
    frames: [
      { kind: "targetChange", type: "ADD", targetIds: [1] },
      {
        kind: "documentChange",
        names: [
          "projects/demo-fs-rules/databases/(default)/documents/posts/a",
          "projects/demo-fs-rules/databases/(default)/documents/posts/b",
        ],
      },
      { kind: "targetChange", type: "CURRENT", targetIds: [1] },
    ],
    end: "open",
  });
  assert.ok(!JSON.stringify(summary).includes("AAAA"));
});

test("summarizeListen records a refusal as a cause or as a stream end, and silence as silence", () => {
  const refused = [
    {
      at: 1,
      kind: "targetChange",
      targetChange: {
        targetChangeType: "REMOVE",
        targetIds: [1],
        cause: { code: 7, message: `denied for ${SANDBOX_PROJECT}` },
      },
    },
  ];
  assert.deepEqual(summarizeListen(refused, undefined, ctxFor(), new Map()).frames, [
    {
      kind: "targetChange",
      type: "REMOVE",
      targetIds: [1],
      cause: { code: 7, message: "denied for demo-fs-rules" },
    },
  ]);
  const errored = summarizeListen(
    [],
    { reason: "error", code: 7, details: "no access" },
    ctxFor(),
    new Map(),
  );
  assert.deepEqual(errored.end, { reason: "error", code: 7, details: "no access" });
  assert.equal(errored.silent, undefined);
  const silent = summarizeListen([], undefined, ctxFor(), new Map());
  assert.equal(silent.silent, true);
  assert.equal(silent.end, "open");
  const other = summarizeListen(
    [{ at: 1, kind: "filter", filter: { count: 1 } }],
    undefined,
    ctxFor(),
    new Map(),
  );
  assert.deepEqual(other.frames, [{ kind: "filter" }]);
});

test("summarizeListen: the order documents arrive in never changes the record (property)", () => {
  let seed = 7;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) % 2 ** 32;
    return seed / 2 ** 32;
  };
  for (let round = 0; round < 200; round += 1) {
    const ids = Array.from({ length: 1 + Math.floor(random() * 6) }, (_, i) => `d${i}`);
    const shuffled = ids.toSorted(() => random() - 0.5);
    const frame = (id) => ({
      at: 1,
      kind: "documentChange",
      documentChange: { document: { name: `projects/x/databases/(default)/documents/p/${id}` } },
    });
    const a = summarizeListen(ids.map(frame), undefined, ctxFor(), new Map());
    const b = summarizeListen(shuffled.map(frame), undefined, ctxFor(), new Map());
    assert.deepEqual(a, b);
  }
});

test("a Listen that never answers is capped, not waited out", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  grpc.listen = () => ({ frames: [], ended: () => undefined, close: async () => {} });
  const program = {
    ...PROGRAMS[1],
    steps: [PROGRAMS[1].steps[0], PROGRAMS[1].steps.find((s) => s.id === "group-listen-none")],
  };
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  const start = clock.now();
  const out = await runCorpus(
    { programs: [program], principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings([program]),
  );
  const row = out.results[program.id].steps["group-listen-none"];
  assert.equal(row.silent, true);
  assert.ok(clock.now() - start >= LISTEN_CAP_MS);
  assert.ok(isEmpty(world));
});

// ---- local targets --------------------------------------------------------------------------

function localFake({ compileStatus = () => 200 } = {}) {
  const log = [];
  const fetchImpl = async (url, init = {}) => {
    log.push({ method: init.method ?? "GET", url, authorization: init.headers?.authorization });
    const response = (status, body = {}) => ({ status, text: async () => JSON.stringify(body) });
    if (url.includes(":securityRules")) {
      const content = JSON.parse(init.body).rules.files[0].content;
      return response(compileStatus(content));
    }
    if (init.method === "DELETE" && url.includes("/emulator/v1/")) return response(200);
    if (url.includes("documents:commit")) return response(200, { writeResults: [{}] });
    if (url.includes("accounts:signUp"))
      return response(200, { idToken: "eyJ.local.sig", localId: "local1" });
    if (url.includes(":runQuery")) return response(200, [{}]);
    return response(200, {});
  };
  const grpcCalls = [];
  const grpc = {
    call: async (built, bearer) => {
      grpcCalls.push({ method: built.method, bearer });
      return { code: 0, details: "", messages: [] };
    },
    listen: () => ({
      frames: [
        {
          at: 1,
          kind: "targetChange",
          targetChange: { targetChangeType: "CURRENT", targetIds: [1] },
        },
      ],
      ended: () => undefined,
      close: async () => {},
    }),
    close: async () => {},
  };
  return { log, fetchImpl, grpc, grpcCalls };
}

const LOCAL = {
  kind: "local",
  firestoreOrigin: "http://127.0.0.1:9000",
  authOrigin: "http://127.0.0.1:9099",
  grpcHost: "127.0.0.1",
  grpcPort: 9000,
};

test("a local run loads rules by the emulator endpoint and records a refused ruleset as not compiled", async () => {
  const fake = localFake({
    compileStatus: (source) =>
      source.includes("{path=**}") && !source.startsWith("rules_version") ? 400 : 200,
  });
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", target: LOCAL });
  const out = await runCorpus(
    { programs: PROGRAMS, principals: PRINCIPALS },
    ctx,
    { ...fake, sleep: clock.sleep, now: clock.now },
    ceilings(PROGRAMS),
  );
  assert.deepEqual(out.results["fs-rules-v1/path-wildcard/v1"].steps.publishes, {
    compiled: false,
  });
  assert.deepEqual(out.results["fs-rules-v1/path-wildcard/v2"].steps.publishes, { compiled: true });
  // No marker polls, no release, no account deletion: those are production-only.
  assert.equal(
    out.publications.every((p) => p.polls === 0),
    true,
  );
  assert.ok(fake.log.every((e) => e.url.startsWith("http://127.0.0.1:")));
  assert.ok(
    !fake.log.some((e) => e.url.includes("firebaserules") || e.url.includes("accounts:delete")),
  );
  assert.equal(out.closureReady, true);
});

test("a compile answer other than 200 or 400 is recorded as a transient status, not as a refusal", async () => {
  const fake = localFake({ compileStatus: () => 503 });
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", target: LOCAL });
  const out = await runCorpus(
    { programs: [PROGRAMS[0]], principals: PRINCIPALS },
    ctx,
    { ...fake, sleep: clock.sleep, now: clock.now },
    ceilings([PROGRAMS[0]]),
  );
  assert.deepEqual(out.results[PROGRAMS[0].id].steps.publishes, {
    status: 503,
    transport: "compile-status",
  });
});

test("the official emulator run signs the principal with a mock token and makes no sign-up call", async () => {
  const fake = localFake();
  const clock = createClock();
  const ctx = {
    ...createContext({
      run: "1790000000000",
      target: {
        ...LOCAL,
        authOrigin: "http://127.0.0.1:1",
        mockToken: (uid) => mockToken(uid, "demo-fs3-v1", 1_800_000_000),
      },
    }),
    project: "demo-fs3-v1",
  };
  await runCorpus(
    { programs: [PROGRAMS[0]], principals: PRINCIPALS },
    ctx,
    { ...fake, sleep: clock.sleep, now: clock.now },
    ceilings([PROGRAMS[0]]),
  );
  assert.ok(!fake.log.some((e) => e.url.includes("signUp")));
  const withBearer = fake.log.find(
    (e) => e.authorization?.startsWith("Bearer ") && e.authorization !== "Bearer owner",
  );
  const [, payload] = withBearer.authorization.slice(7).split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  assert.equal(claims.firebase.sign_in_provider, "anonymous");
  assert.equal(claims.aud, "demo-fs3-v1");
  assert.equal(claims.sub, "fsr-1790000000000-anon");
});

test("a local run cannot leave loopback", async () => {
  const fake = localFake();
  const ctx = createContext({ run: "1790000000000", target: LOCAL });
  assert.throws(
    () => guardHarnessRequest("https://firestore.googleapis.com/v1/projects/x", ctx),
    /left loopback/,
  );
  assert.throws(() => guardHarnessRequest("http://127.0.0.1:9100/v1/x", ctx), /left loopback/);
  guardHarnessRequest("http://127.0.0.1:9000/v1/x", ctx);
  void fake;
});

// ---- the guard ------------------------------------------------------------------------------

test("guardHarnessRequest refuses everything but the sandbox project's own resources", () => {
  const ctx = ctxFor();
  const ok = [
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:runQuery`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:commit`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/rulesets`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/rulesets/abc-123`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/releases`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/releases/cloud.firestore`,
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:delete`,
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:query`,
    `https://identitytoolkit.googleapis.com/admin/v2/projects/${SANDBOX_PROJECT}/config`,
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
  ];
  for (const url of ok) guardHarnessRequest(url, ctx);
  const refused = [
    "https://firestore.googleapis.com/v1/projects/fireemu-35fe6/databases",
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}-x/databases`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/other/documents:commit`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/indexes`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/releases/cloud.storage`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/rulesets/../x`,
    `https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-sbx/rulesets`,
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:batchDelete`,
    `https://identitytoolkit.googleapis.com/v2/projects/${SANDBOX_PROJECT}/tenants`,
    `https://identitytoolkit.googleapis.com/admin/v2/projects/${SANDBOX_PROJECT}/config/x`,
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp/x",
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/x:signJwt",
    "https://securetoken.googleapis.com/v1/token",
    "https://example.com/v1/accounts:signUp",
    `http://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases`,
  ];
  for (const url of refused)
    assert.throws(() => guardHarnessRequest(url, ctx), /outside the sandbox project/, url);
});

// ---- what each row asks, through a fake that evaluates the request it gets -------------------

const table = (out) =>
  PROGRAMS.flatMap((p) =>
    p.steps.map(
      (s) => `${p.id.replace("fs-rules-v1/", "")}#${s.id} ${brief(out.results[p.id].steps[s.id])}`,
    ),
  );

const GOLDEN_ALLOW = `
recursive-wildcard/v1#publishes compiled=true
recursive-wildcard/v1#group-none 200 docs=3
recursive-wildcard/v1#group-anon 200 docs=3
recursive-wildcard/v1#group-count-none 200 count=3
recursive-wildcard/v1#group-count-anon 200 count=3
recursive-wildcard/v1#group-grpc-none grpc0 msgs=3
recursive-wildcard/v1#group-count-grpc-none grpc0 msgs=1
recursive-wildcard/v1#group-listen-none listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v1#group-listen-anon listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v1#single-none 200 docs=1
recursive-wildcard/v1#single-anon 200 docs=1
recursive-wildcard/v1#single-count-none 200 count=1
recursive-wildcard/v1#nested-none 200 docs=1
recursive-wildcard/v1#single-listen-none listen[ADD,documentChangex1,CURRENT]
recursive-wildcard/v1#get-top-none 200
recursive-wildcard/v1#get-nested-none 200
recursive-wildcard/v1#kindless-parent-none 200 docs=2
recursive-wildcard/v1#kindless-parent-anon 200 docs=2
recursive-wildcard/v1#kindless-root-none 200 docs=4
recursive-wildcard/v1#kindless-count-parent-none 200 count=2
recursive-wildcard/v2#publishes compiled=true
recursive-wildcard/v2#group-none 200 docs=3
recursive-wildcard/v2#group-anon 200 docs=3
recursive-wildcard/v2#group-count-none 200 count=3
recursive-wildcard/v2#group-count-anon 200 count=3
recursive-wildcard/v2#group-grpc-none grpc0 msgs=3
recursive-wildcard/v2#group-count-grpc-none grpc0 msgs=1
recursive-wildcard/v2#group-listen-none listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v2#group-listen-anon listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v2#single-none 200 docs=1
recursive-wildcard/v2#single-anon 200 docs=1
recursive-wildcard/v2#single-count-none 200 count=1
recursive-wildcard/v2#nested-none 200 docs=1
recursive-wildcard/v2#single-listen-none listen[ADD,documentChangex1,CURRENT]
recursive-wildcard/v2#get-top-none 200
recursive-wildcard/v2#get-nested-none 200
recursive-wildcard/v2#kindless-parent-none 200 docs=2
recursive-wildcard/v2#kindless-parent-anon 200 docs=2
recursive-wildcard/v2#kindless-root-none 200 docs=4
recursive-wildcard/v2#kindless-count-parent-none 200 count=2
path-wildcard/v1#publishes compiled=false
path-wildcard/v1#group-none not-published
path-wildcard/v1#group-anon not-published
path-wildcard/v1#group-count-none not-published
path-wildcard/v1#group-count-anon not-published
path-wildcard/v1#group-grpc-none not-published
path-wildcard/v1#group-count-grpc-none not-published
path-wildcard/v1#group-listen-none not-published
path-wildcard/v1#group-listen-anon not-published
path-wildcard/v1#single-none not-published
path-wildcard/v1#single-anon not-published
path-wildcard/v1#single-count-none not-published
path-wildcard/v1#nested-none not-published
path-wildcard/v1#single-listen-none not-published
path-wildcard/v1#get-top-none not-published
path-wildcard/v1#get-nested-none not-published
path-wildcard/v1#kindless-parent-none not-published
path-wildcard/v1#kindless-parent-anon not-published
path-wildcard/v1#kindless-root-none not-published
path-wildcard/v1#kindless-count-parent-none not-published
path-wildcard/v2#publishes compiled=true
path-wildcard/v2#group-none 200 docs=3
path-wildcard/v2#group-anon 200 docs=3
path-wildcard/v2#group-count-none 200 count=3
path-wildcard/v2#group-count-anon 200 count=3
path-wildcard/v2#group-grpc-none grpc0 msgs=3
path-wildcard/v2#group-count-grpc-none grpc0 msgs=1
path-wildcard/v2#group-listen-none listen[ADD,documentChangex3,CURRENT]
path-wildcard/v2#group-listen-anon listen[ADD,documentChangex3,CURRENT]
path-wildcard/v2#single-none 403 PERMISSION_DENIED
path-wildcard/v2#single-anon 403 PERMISSION_DENIED
path-wildcard/v2#single-count-none 403 PERMISSION_DENIED
path-wildcard/v2#nested-none 403 PERMISSION_DENIED
path-wildcard/v2#single-listen-none listen[REMOVE:cause7]
path-wildcard/v2#get-top-none 403 PERMISSION_DENIED
path-wildcard/v2#get-nested-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-parent-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-parent-anon 403 PERMISSION_DENIED
path-wildcard/v2#kindless-root-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-count-parent-none 403 PERMISSION_DENIED
`
  .trim()
  .split("\n");

const GOLDEN_DENY = `
recursive-wildcard/v1#publishes compiled=true
recursive-wildcard/v1#group-none 403 PERMISSION_DENIED
recursive-wildcard/v1#group-anon 403 PERMISSION_DENIED
recursive-wildcard/v1#group-count-none 403 PERMISSION_DENIED
recursive-wildcard/v1#group-count-anon 403 PERMISSION_DENIED
recursive-wildcard/v1#group-grpc-none grpc7
recursive-wildcard/v1#group-count-grpc-none grpc7
recursive-wildcard/v1#group-listen-none listen[REMOVE:cause7]
recursive-wildcard/v1#group-listen-anon listen[REMOVE:cause7]
recursive-wildcard/v1#single-none 200 docs=1
recursive-wildcard/v1#single-anon 200 docs=1
recursive-wildcard/v1#single-count-none 200 count=1
recursive-wildcard/v1#nested-none 200 docs=1
recursive-wildcard/v1#single-listen-none listen[ADD,documentChangex1,CURRENT]
recursive-wildcard/v1#get-top-none 200
recursive-wildcard/v1#get-nested-none 200
recursive-wildcard/v1#kindless-parent-none 403 PERMISSION_DENIED
recursive-wildcard/v1#kindless-parent-anon 403 PERMISSION_DENIED
recursive-wildcard/v1#kindless-root-none 403 PERMISSION_DENIED
recursive-wildcard/v1#kindless-count-parent-none 403 PERMISSION_DENIED
recursive-wildcard/v2#publishes compiled=true
recursive-wildcard/v2#group-none 200 docs=3
recursive-wildcard/v2#group-anon 200 docs=3
recursive-wildcard/v2#group-count-none 200 count=3
recursive-wildcard/v2#group-count-anon 200 count=3
recursive-wildcard/v2#group-grpc-none grpc0 msgs=3
recursive-wildcard/v2#group-count-grpc-none grpc0 msgs=1
recursive-wildcard/v2#group-listen-none listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v2#group-listen-anon listen[ADD,documentChangex3,CURRENT]
recursive-wildcard/v2#single-none 200 docs=1
recursive-wildcard/v2#single-anon 200 docs=1
recursive-wildcard/v2#single-count-none 200 count=1
recursive-wildcard/v2#nested-none 200 docs=1
recursive-wildcard/v2#single-listen-none listen[ADD,documentChangex1,CURRENT]
recursive-wildcard/v2#get-top-none 200
recursive-wildcard/v2#get-nested-none 200
recursive-wildcard/v2#kindless-parent-none 200 docs=2
recursive-wildcard/v2#kindless-parent-anon 200 docs=2
recursive-wildcard/v2#kindless-root-none 200 docs=4
recursive-wildcard/v2#kindless-count-parent-none 200 count=2
path-wildcard/v1#publishes compiled=false
path-wildcard/v1#group-none not-published
path-wildcard/v1#group-anon not-published
path-wildcard/v1#group-count-none not-published
path-wildcard/v1#group-count-anon not-published
path-wildcard/v1#group-grpc-none not-published
path-wildcard/v1#group-count-grpc-none not-published
path-wildcard/v1#group-listen-none not-published
path-wildcard/v1#group-listen-anon not-published
path-wildcard/v1#single-none not-published
path-wildcard/v1#single-anon not-published
path-wildcard/v1#single-count-none not-published
path-wildcard/v1#nested-none not-published
path-wildcard/v1#single-listen-none not-published
path-wildcard/v1#get-top-none not-published
path-wildcard/v1#get-nested-none not-published
path-wildcard/v1#kindless-parent-none not-published
path-wildcard/v1#kindless-parent-anon not-published
path-wildcard/v1#kindless-root-none not-published
path-wildcard/v1#kindless-count-parent-none not-published
path-wildcard/v2#publishes compiled=true
path-wildcard/v2#group-none 200 docs=3
path-wildcard/v2#group-anon 200 docs=3
path-wildcard/v2#group-count-none 200 count=3
path-wildcard/v2#group-count-anon 200 count=3
path-wildcard/v2#group-grpc-none grpc0 msgs=3
path-wildcard/v2#group-count-grpc-none grpc0 msgs=1
path-wildcard/v2#group-listen-none listen[ADD,documentChangex3,CURRENT]
path-wildcard/v2#group-listen-anon listen[ADD,documentChangex3,CURRENT]
path-wildcard/v2#single-none 403 PERMISSION_DENIED
path-wildcard/v2#single-anon 403 PERMISSION_DENIED
path-wildcard/v2#single-count-none 403 PERMISSION_DENIED
path-wildcard/v2#nested-none 403 PERMISSION_DENIED
path-wildcard/v2#single-listen-none listen[REMOVE:cause7]
path-wildcard/v2#get-top-none 403 PERMISSION_DENIED
path-wildcard/v2#get-nested-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-parent-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-parent-anon 403 PERMISSION_DENIED
path-wildcard/v2#kindless-root-none 403 PERMISSION_DENIED
path-wildcard/v2#kindless-count-parent-none 403 PERMISSION_DENIED
`
  .trim()
  .split("\n");

test("the rows ask what they claim: every row's effect under a permissive and a refusing v1", async () => {
  assert.deepEqual(table((await record()).out), GOLDEN_ALLOW);
  assert.deepEqual(table((await record({ scenario: { v1Group: "deny" } })).out), GOLDEN_DENY);
});

test("the constants that bound a recording are the ones the presend packet states", () => {
  assert.equal(SETTLE_STREAK, 30);
  assert.equal(LISTEN_IDLE_MS, 2000);
  assert.equal(LISTEN_CAP_MS, 20_000);
});

/** How long the session reads a Listen whose frames are `frames` from the start, in clock ms. */
async function listenDuration(frames) {
  const { fetchImpl, grpc } = createWorld();
  const clock = createClock();
  let opened;
  let closed;
  grpc.listen = () => {
    opened = clock.now();
    return {
      frames,
      ended: () => undefined,
      close: async () => {
        await new Promise((resolve) => setImmediate(resolve));
        closed = clock.now();
      },
    };
  };
  const program = {
    ...PROGRAMS[1],
    steps: [PROGRAMS[1].steps[0], PROGRAMS[1].steps.find((s) => s.id === "group-listen-none")],
  };
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  await runCorpus(
    { programs: [program], principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings([program]),
  );
  return closed - opened;
}

test("a Listen is read until it has been quiet for two seconds, and a silent one for twenty", async () => {
  const frame = { at: 1, kind: "targetChange", targetChange: { targetChangeType: "ADD" } };
  assert.equal(await listenDuration([frame]), 2000);
  assert.equal(await listenDuration([]), 20_000);
});

test("a wipe and a seed never send more than 400 writes in one commit", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  for (let i = 0; i < 1000; i += 1) world.documents.set(`leftover/d${i}`, {});
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  const program = { ...PROGRAMS[1], steps: [PROGRAMS[1].steps[0]] };
  const out = await runCorpus(
    { programs: [program], principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings([program]),
  );
  assert.equal(out.closureReady, true);
  assert.equal(world.documents.size, 0);
  assert.ok(world.commits.length >= 3);
  assert.ok(
    Math.max(...world.commits) <= 400,
    `a commit held ${Math.max(...world.commits)} writes`,
  );
  assert.ok(world.commits.filter((n) => n === 400).length >= 2, "and fills the batches it can");
  const queries = world.log.filter((e) => e.path.endsWith(":runQuery"));
  assert.ok(queries.length >= 3);
});
