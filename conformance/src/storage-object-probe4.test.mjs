// probe-v4: the "not match" refusals, the accepted PUTs and the Firebase wrong-offset session it asks
// for, the values it asks them with, and above all that its cleanup finds and removes everything it
// can have created even when production accepts what it should have refused. The production is a
// stateful fake (storage-object-probe4-fake.mjs).

import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLeanWire } from "./storage-object/lean-wire.mjs";
import {
  buildProbe4Plan,
  PROBE4_ESTIMATE_USD,
  PROBE4_MAX_REQUESTS,
  PROBE4_RESERVE_USD,
  probe4ClosingRow,
  sendProbe4,
} from "./storage-object/probe4.mjs";
import { BUCKET, production } from "./storage-object-probe4-fake.mjs";

const PROJECT = "fireemu-oracle-query";
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";
const ORIGINS = {
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
};
const plan = buildProbe4Plan({ projectId: PROJECT, bucket: BUCKET, runId: RUN, otherRunId: OTHER });

function makeWire(fake, { capture } = {}) {
  return createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: plan.prefix,
    origins: ORIGINS,
    adminToken: async () => TOKEN,
    authApiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    readRules: async () => ({ source: "x" }),
    fetchImpl: fake.fetchImpl,
    capture: capture ?? (async () => {}),
    pacer: { dispatch: (_name, attempt) => attempt() },
  });
}

async function run(options = {}, wireOptions = {}) {
  const fake = production(options);
  const result = await sendProbe4({ wire: makeWire(fake, wireOptions), plan, origins: ORIGINS });
  return { fake, ...result };
}

const ids = (answers) => answers.map((row) => row.id);
const status = (answers, id) => answers.find((row) => row.id === id)?.status;
const at = (fake, predicate) => fake.calls.find(predicate);
const q = (call) => new URL(call.href).searchParams;
const decoded = (call) => decodeURIComponent(new URL(call.href).pathname);
const respond = (body, code = 200) =>
  new Response(JSON.stringify(body), {
    status: code,
    headers: { "content-type": "application/json" },
  });
const isTarget = (call) => decoded(call).endsWith(`/o/${plan.names.target}`);
const isGcsList = (call) => new URL(call.href).pathname === `/storage/v1/b/${BUCKET}/o`;

// ---- the plan --------------------------------------------------------------------------------------------

test("the plan is two fixed names under the probe's own prefix, whatever the answers", () => {
  assert.equal(plan.scope, `storage-object/${RUN}/probe4/`);
  assert.deepEqual(plan.objects, [
    `${plan.scope}pre/target.bin`,
    `${plan.scope}firebase/resumable-wrong-offset.bin`,
  ]);
  for (const name of Object.values(plan.names)) assert.ok(name.startsWith(plan.scope), name);
  const again = buildProbe4Plan({
    projectId: PROJECT,
    bucket: BUCKET,
    runId: RUN,
    otherRunId: OTHER,
  });
  assert.deepEqual(again.objects, plan.objects);
  assert.equal(PROBE4_MAX_REQUESTS, 60);
  assert.equal(PROBE4_RESERVE_USD, 0.05);
  assert.equal(PROBE4_ESTIMATE_USD, 0.02);
});

// ---- an honest production -----------------------------------------------------------------------------------

test("an honest run asks for every shape, gets the answers, removes its objects, and closes on an empty prefix", async () => {
  const { fake, answers, interrupted } = await run();
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0);
  const closing = probe4ClosingRow(answers);
  assert.equal(closing.id, "final-list");
  assert.equal(closing.prefixEmpty, true);
  assert.equal(fake.calls.length, 24);
  assert.deepEqual(
    answers.filter((row) => row.skipped),
    [],
  );
  const expected = {
    "target-create": 200,
    "target-metadata": 200,
    "patch-generation-not-match": 412,
    "patch-metageneration-not-match": 412,
    "put-generation-not-match": 412,
    "put-metageneration-not-match": 412,
    "upload-generation-not-match": 412,
    "upload-metageneration-not-match": 412,
    "put-metageneration-match": 200,
    "put-metageneration-not-match-stale": 200,
    "target-metadata-again": 200,
    "delete-generation-not-match": 412,
    "delete-metageneration-not-match": 412,
    "firebase-session-start": 200,
    "firebase-session-query": 200,
    "firebase-session-wrong-offset": 400,
    "firebase-session-query-after": 200,
    "firebase-session-cancel": 200,
    "firebase-session-query-after-cancel": 200,
  };
  assert.deepEqual(
    answers.slice(0, 19).map((row) => row.id),
    Object.keys(expected),
  );
  for (const [id, wanted] of Object.entries(expected))
    assert.equal(status(answers, id), wanted, id);
});

test("every GCS create of the target carries ifGenerationMatch=0, or the guard it tests", async () => {
  const { fake } = await run();
  const creates = fake.calls.filter(
    (c) => c.method === "POST" && c.href.includes("/upload/storage/v1/b/"),
  );
  assert.equal(creates.length, 3);
  for (const call of creates) assert.equal(q(call).get("name"), plan.names.target);
  assert.equal(q(creates[0]).get("ifGenerationMatch"), "0");
  assert.equal(q(creates[0]).has("ifGenerationNotMatch"), false);
  const target = fake.history.find((row) => row.name === plan.names.target);
  assert.equal(q(creates[1]).get("ifGenerationNotMatch"), target.generation);
  assert.equal(q(creates[1]).has("ifGenerationMatch"), false);
  assert.equal(q(creates[2]).get("ifMetagenerationNotMatch"), "1");
  assert.equal(q(creates[2]).has("ifGenerationMatch"), false);
  for (const call of creates) assert.equal(q(call).get("uploadType"), "media");
});

test("the guards are the target's own current values, on each of POST, PATCH, PUT and DELETE", async () => {
  const { fake } = await run();
  const target = fake.history.find((row) => row.name === plan.names.target);
  const guards = (call) =>
    [
      "ifGenerationMatch",
      "ifGenerationNotMatch",
      "ifMetagenerationMatch",
      "ifMetagenerationNotMatch",
    ]
      .filter((key) => q(call).has(key))
      .map((key) => `${key}=${q(call).get(key)}`);
  const patches = fake.calls.filter((c) => c.method === "PATCH");
  assert.deepEqual(patches.map(guards), [
    [`ifGenerationNotMatch=${target.generation}`],
    [`ifGenerationMatch=${target.generation}`, "ifMetagenerationNotMatch=1"],
  ]);
  const puts = fake.calls.filter((c) => c.method === "PUT");
  assert.deepEqual(puts.map(guards), [
    [`ifGenerationNotMatch=${target.generation}`],
    [`ifGenerationMatch=${target.generation}`, "ifMetagenerationNotMatch=1"],
    [`ifGenerationMatch=${target.generation}`, "ifMetagenerationMatch=1"],
    [`ifGenerationMatch=${target.generation}`, "ifMetagenerationNotMatch=1"],
  ]);
  // The metageneration is 1 until an accepted PUT raises it: the deletes carry the fresh value, 3.
  const deletes = fake.calls.filter((c) => c.method === "DELETE" && isTarget(c));
  assert.deepEqual(deletes.slice(0, 2).map(guards), [
    [`ifGenerationNotMatch=${target.generation}`],
    ["ifMetagenerationNotMatch=3"],
  ]);
});

test("the deletes and the accepted PUTs come after every refusal test, and the deletes come last on the target", async () => {
  const { fake } = await run();
  const writes = fake.calls.filter(
    (c) =>
      ["POST", "PATCH", "PUT", "DELETE"].includes(c.method) &&
      (isTarget(c) || q(c).get("name") === plan.names.target),
  );
  assert.deepEqual(
    writes.map((c) => c.method),
    [
      "POST",
      "PATCH",
      "PATCH",
      "PUT",
      "PUT",
      "POST",
      "POST",
      "PUT",
      "PUT",
      "DELETE",
      "DELETE",
      "DELETE",
    ],
  );
  // A metadata read of the target sits between the last PUT and the first delete, and gives the deletes their value.
  const order = fake.calls.filter(isTarget).map((c) => c.method);
  const lastPut = order.lastIndexOf("PUT");
  assert.equal(order[lastPut + 1], "GET");
  assert.equal(order[lastPut + 2], "DELETE");
});

test("the requests have the corpus's methods, headers and bodies", async () => {
  const { fake } = await run();
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.scope });
  const step = (recipe, id) =>
    corpus.recipes.find((r) => r.id === recipe).steps.find((s) => s.id === id);
  const meta = "storage-object/gcs/metageneration-preconditions";
  const patchStep = step(meta, "patch-ifMetagenerationMatch-stale");
  const patch = at(fake, (c) => c.method === "PATCH");
  assert.equal(patch.headers.get("content-type"), patchStep.headers["content-type"]);
  assert.deepEqual(JSON.parse(patch.body), patchStep.body.json);
  const putStep = step(meta, "put-ifMetagenerationMatch-stale");
  for (const put of fake.calls.filter((c) => c.method === "PUT")) {
    assert.equal(put.headers.get("content-type"), putStep.headers["content-type"]);
    assert.deepEqual(JSON.parse(put.body), putStep.body.json);
  }
  const createStep = step(
    "storage-object/gcs/generation-preconditions",
    "upload-ifGenerationMatch-zero-present",
  );
  for (const post of fake.calls.filter(
    (c) => c.method === "POST" && c.href.includes("uploadType=media"),
  )) {
    assert.equal(post.body.toString("base64"), createStep.body.base64);
    assert.equal(post.headers.get("content-type"), createStep.headers["content-type"]);
  }
  for (const row of fake.calls) {
    assert.equal(row.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(row.headers.get("x-goog-user-project"), PROJECT);
  }
});

test("the Firebase session is the recipe's own sequence: start, query, a chunk at the wrong offset, query, cancel, query", async () => {
  const { fake } = await run();
  const session = fake.calls.filter((c) => c.href.includes("/v0/b/"));
  assert.deepEqual(
    session.map((c) => c.headers.get("x-goog-upload-command")),
    ["start", "query", "upload", "query", "cancel", "query"],
  );
  assert.equal(q(session[0]).get("name"), plan.names.firebaseSession);
  const chunk = session[2];
  assert.equal(chunk.headers.get("x-goog-upload-offset"), "1");
  assert.equal(chunk.body.length, 1);
  for (const call of session.slice(1)) assert.match(q(call).get("upload_id"), /^f/);
});

// ---- production that accepts what it should refuse --------------------------------------------------------------------

test("when production accepts every write it should refuse, cleanup still ends prefix-empty within the budget", async () => {
  const { fake, answers } = await run({ acceptRefused: true });
  assert.equal(fake.store.size, 0, "what the accepted writes made is removed");
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  assert.equal(fake.calls.length, 22);
  assert.equal(status(answers, "upload-generation-not-match"), 200);
  // The accepted delete removed the target: what follows it is a 404, and cleanup finds it absent.
  assert.equal(status(answers, "delete-generation-not-match"), 204);
});

test("the deletes carry the values of a fresh read, so an accepted create that replaced the target changes them", async () => {
  const { fake } = await run({ acceptRefused: true });
  const generations = fake.history.filter((row) => row.name === plan.names.target);
  assert.equal(generations.length, 3);
  const latest = generations.at(-1).generation;
  assert.notEqual(latest, generations[0].generation);
  const remove = at(fake, (c) => c.method === "DELETE" && q(c).has("ifGenerationNotMatch"));
  assert.equal(q(remove).get("ifGenerationNotMatch"), latest);
});

test("when every recording step answers something unexpected, the run still ends prefix-empty", async () => {
  const { fake, answers, interrupted } = await run({ odd: true });
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  const skipped = answers.filter((row) => row.skipped);
  for (const row of skipped) assert.match(row.skipped, /no session URL|no target metadata/);
  assert.equal(skipped.length, 8 + 2 + 5);
  for (const name of plan.objects)
    assert.ok(
      fake.calls.some((c) => c.method === "GET" && decoded(c).endsWith(`/o/${name}`)),
      name,
    );
});

test("a target whose metadata is unusable skips the guarded requests with the reason, and cleanup goes on", async () => {
  for (const drop of ["generation", "metageneration", "both"]) {
    const fake = production({});
    const original = fake.fetchImpl;
    fake.fetchImpl = async (url, init) => {
      const response = await original(url, init);
      if (
        init.method === "GET" &&
        decoded({ href: String(url) }).endsWith(`/o/${plan.names.target}`) &&
        !fake.calls.some((c) => c.method === "DELETE")
      ) {
        const body = await response.json();
        if (drop !== "metageneration") delete body.generation;
        if (drop !== "generation") delete body.metageneration;
        return respond(body);
      }
      return response;
    };
    const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    const skipped = answers
      .filter((row) => row.skipped === "no target metadata")
      .map((row) => row.id);
    assert.equal(skipped.length, 10, drop);
    assert.ok(skipped.includes("put-metageneration-match"), drop);
    assert.ok(skipped.includes("delete-metageneration-not-match"), drop);
    assert.ok(!fake.calls.some((c) => c.method === "PATCH" || c.method === "PUT"), drop);
    assert.equal(fake.store.size, 0, drop);
  }
});

test("a session start without a URL skips its follow-ups with the reason", async () => {
  const { answers, fake } = await run({ odd: true });
  for (const id of [
    "firebase-session-query",
    "firebase-session-wrong-offset",
    "firebase-session-query-after",
    "firebase-session-cancel",
    "firebase-session-query-after-cancel",
  ])
    assert.deepEqual(
      answers.find((row) => row.id === id),
      { id, skipped: "no session URL" },
    );
  assert.equal(fake.store.size, 0);
});

// ---- cleanup does not depend on an answer --------------------------------------------------------------------------

test("a metadata read that gives no generation is followed by a delete by name", async () => {
  const { fake, answers } = await run({ noGeneration: true });
  assert.equal(fake.store.size, 0);
  const deletes = fake.calls.filter((c) => c.method === "DELETE" && isTarget(c));
  assert.equal(deletes.length, 3);
  assert.equal(q(deletes[2]).has("ifGenerationMatch"), false);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
});

test("an object that cannot be removed leaves the closing row not empty, and no more than ten are tried by name", async () => {
  const stuck = plan.objects[0];
  const { fake, answers } = await run({ deleteFails: stuck });
  assert.ok(fake.store.has(stuck));
  const closing = probe4ClosingRow(answers);
  assert.equal(closing.prefixEmpty, false);
  assert.equal(closing.id, "final-list-again");
  assert.ok(ids(answers).filter((id) => id.startsWith("cleanup-extra-delete-")).length <= 10);
});

test("at most ten leftovers are removed by name, and the worst case stays inside the budget", async () => {
  const strayPrefix = `${plan.scope}stray/`;
  const { fake, answers } = await run({ strays: 15, strayPrefix, acceptRefused: true });
  assert.equal(ids(answers).filter((id) => id.startsWith("cleanup-extra-delete-")).length, 10);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, false);
  assert.equal(fake.calls.length, 33);
  assert.ok(fake.calls.length + 4 <= PROBE4_MAX_REQUESTS);
});

test("a connection lost at any request ends in a clean prefix or in an error, never in a leftover with a clean row", async () => {
  const total = (await run()).fake.calls.length;
  for (let failAt = 1; failAt <= total; failAt++) {
    const fake = production({ failAt });
    let result;
    try {
      result = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    } catch (error) {
      assert.equal(typeof error.probeStep, "string", `failAt ${failAt}`);
      assert.ok(Array.isArray(error.answered), `failAt ${failAt}`);
      continue;
    }
    const closing = probe4ClosingRow(result.answers);
    if (closing?.prefixEmpty === true)
      assert.equal(
        fake.store.size,
        0,
        `failAt ${failAt}: a clean row over ${fake.store.size} objects`,
      );
  }
});

test("a connection lost during the recording ends the recording, and the objects made so far are removed", async () => {
  const { fake, answers, interrupted } = await run({ failAt: 8 });
  assert.ok(interrupted);
  assert.match(interrupted.reason, /fetch failed/);
  assert.equal(interrupted.step, "upload-metageneration-not-match");
  assert.equal(fake.store.size, 0);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  assert.ok(!ids(answers).includes("firebase-session-start"));
});

test("a capture failure halts the wire, and cleanup cannot go on either: the run stops", async () => {
  let count = 0;
  const fake = production();
  const wire = makeWire(fake, {
    capture: async () => {
      if (++count === 6) throw new Error("disk full");
    },
  });
  await assert.rejects(sendProbe4({ wire, plan, origins: ORIGINS }), /LEAN_WIRE|CAPTURE/);
});

test("a request the route table refuses is recorded as skipped and the run goes on", async () => {
  const fake = production();
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (init.method === "DELETE" && String(href).includes("ifMetagenerationNotMatch=")) {
        const error = new Error("route is not in the table");
        error.routeRefused = true;
        throw error;
      }
      return wire.fetch(href, init);
    },
    snapshot: () => wire.snapshot(),
  };
  const result = await sendProbe4({ wire: refusing, plan, origins: ORIGINS });
  assert.deepEqual(
    result.answers.find((row) => row.id === "delete-metageneration-not-match"),
    { id: "delete-metageneration-not-match", skipped: "route is not in the table" },
  );
  assert.equal(result.interrupted, null);
  assert.equal(fake.store.size, 0);
});

test("only an error marked routeRefused=true is a refusal by the route table; any other error ends the recording", async () => {
  for (const marker of [false, undefined, "yes"]) {
    const fake = production({});
    const wire = makeWire(fake);
    const failing = {
      fetch: async (href, init) => {
        if (init.method === "DELETE" && String(href).includes("ifMetagenerationNotMatch=")) {
          const error = new Error("boom");
          if (marker !== undefined) error.routeRefused = marker;
          throw error;
        }
        return wire.fetch(href, init);
      },
      snapshot: () => wire.snapshot(),
    };
    const { answers, interrupted } = await sendProbe4({ wire: failing, plan, origins: ORIGINS });
    assert.equal(interrupted?.step, "delete-metageneration-not-match", String(marker));
    assert.ok(
      !answers.some((row) => row.id === "delete-metageneration-not-match" && row.skipped),
      String(marker),
    );
    assert.equal(fake.store.size, 0);
  }
});

test("a session start the route table refused skips the session's follow-ups, with the reason", async () => {
  const fake = production({});
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (init.headers["x-goog-upload-command"] === "start") {
        const error = new Error("route is not in the table");
        error.routeRefused = true;
        throw error;
      }
      return wire.fetch(href, init);
    },
    snapshot: () => wire.snapshot(),
  };
  const { answers, interrupted } = await sendProbe4({ wire: refusing, plan, origins: ORIGINS });
  assert.equal(interrupted, null);
  assert.deepEqual(
    answers.find((row) => row.id === "firebase-session-start"),
    { id: "firebase-session-start", skipped: "route is not in the table" },
  );
  assert.deepEqual(
    answers.find((row) => row.id === "firebase-session-cancel"),
    { id: "firebase-session-cancel", skipped: "no session URL" },
  );
});

test("a multi-line error message ends the recording with its first line only, cut at 200 characters", async () => {
  for (const [message, wanted] of [
    ["connection reset\nsecond line with detail", "connection reset"],
    ["x".repeat(500), "x".repeat(200)],
  ]) {
    const fake = production();
    const original = fake.fetchImpl;
    let count = 0;
    fake.fetchImpl = async (url, init) => {
      if (++count === 5) throw new TypeError(message);
      return original(url, init);
    };
    const result = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    assert.equal(result.interrupted.reason, wanted);
  }
});

test("the request count: an honest run is 24, and the worst case, with ten leftovers, 37 at most", async () => {
  const honest = await run();
  assert.equal(honest.fake.calls.length, 24);
  const worst = await run({
    acceptRefused: true,
    deleteFails: plan.objects[0],
    strays: 15,
    strayPrefix: `${plan.scope}stray/`,
  });
  assert.ok(worst.fake.calls.length <= 37, `${worst.fake.calls.length}`);
});

// ---- the shared cleanup, judged through this probe ----------------------------------------------------------------

test("a generation that is not a plain number of at most twenty digits is not a precondition: the object is deleted by name", async () => {
  for (const generation of ["1234567890123456789012", "12x4", "0", "abc1"]) {
    const fake = production({});
    const original = fake.fetchImpl;
    fake.fetchImpl = async (url, init) => {
      const response = await original(url, init);
      if (
        init.method === "GET" &&
        decoded({ href: String(url) }).endsWith(`/o/${plan.names.firebaseSession}`) &&
        fake.calls.some((c) => c.method === "DELETE")
      ) {
        return respond({ kind: "storage#object", name: plan.names.firebaseSession, generation });
      }
      return response;
    };
    const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    const deletes = fake.calls.filter(
      (c) => c.method === "DELETE" && decoded(c).endsWith(`/o/${plan.names.firebaseSession}`),
    );
    assert.equal(deletes.length, 1, generation);
    assert.equal(q(deletes[0]).has("ifGenerationMatch"), false, generation);
    assert.equal(probe4ClosingRow(answers).prefixEmpty, true, generation);
  }
});

test("what the final list holds is removed by name only when it is a string under the probe's own scope", async () => {
  const fake = production({});
  const original = fake.fetchImpl;
  const outside = `${plan.prefix}other-probe/foreign.bin`;
  fake.fetchImpl = async (url, init) => {
    const response = await original(url, init);
    if (
      isGcsList({ href: String(url) }) &&
      new URL(String(url)).searchParams.get("maxResults") === "1000"
    )
      return respond({
        items: [
          { name: outside },
          { id: "no-name" },
          { name: 7 },
          null,
          { name: `${plan.scope}left.bin` },
        ],
      });
    return response;
  };
  const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
  const extra = fake.calls.filter(
    (c) => c.method === "DELETE" && /(left|foreign)\.bin$/.test(decoded(c)),
  );
  assert.deepEqual(
    extra.map((c) => decoded(c).split("/o/")[1]),
    [`${plan.scope}left.bin`],
  );
  assert.ok(answers.some((row) => row.id === "final-list-again"));
});
