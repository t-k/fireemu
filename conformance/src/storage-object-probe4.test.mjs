// probe-v4: the refusals it asks for, the values it asks them with, and above all that its cleanup
// finds and removes everything it can have created even when production accepts what it should have
// refused. The production is a stateful fake (storage-object-probe4-fake.mjs).

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

// ---- the plan --------------------------------------------------------------------------------------------

test("the plan is three fixed names under the probe's own prefix, whatever the answers", () => {
  assert.equal(plan.scope, `storage-object/${RUN}/probe4/`);
  assert.deepEqual(plan.objects, [
    `${plan.scope}pre/target.bin`,
    `${plan.scope}copy/source.bin`,
    `${plan.scope}copy/refused-copy.bin`,
  ]);
  for (const name of Object.values(plan.names)) assert.ok(name.startsWith(plan.scope), name);
  assert.equal(new Set(Object.values(plan.names)).size, Object.keys(plan.names).length);
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

test("an honest run asks for every refusal, gets them, removes its three objects, and closes on an empty prefix", async () => {
  const { fake, answers, interrupted } = await run();
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0);
  const closing = probe4ClosingRow(answers);
  assert.equal(closing.id, "final-list");
  assert.equal(closing.prefixEmpty, true);
  assert.ok(fake.calls.length <= 40, `${fake.calls.length} requests`);
  assert.deepEqual(
    answers.filter((row) => row.skipped),
    [],
  );
  const expected = {
    "target-create": 200,
    "target-metadata": 200,
    "upload-zero-present": 412,
    "upload-generation-stale": 412,
    "patch-generation-stale": 412,
    "patch-metageneration-stale": 412,
    "patch-metageneration-empty": 400,
    "patch-metageneration-text": 400,
    "put-metageneration-stale": 412,
    "firebase-patch-generation-stale": 200,
    "firebase-upload-zero-present": 200,
    "delete-generation-stale": 412,
    "delete-generation-not-match-current": 412,
    "copy-source-create": 200,
    "copy-live-create": 200,
    "copy-missing-source": 404,
    "rewrite-missing-source": 404,
    "copy-live-destination": 412,
    "rewrite-live-destination": 412,
    "gcs-session-start": 200,
    "gcs-session-wrong-offset": 400,
    "gcs-session-cancel": 499,
    "gcs-session-invalid": 404,
    "firebase-session-start": 200,
    "firebase-session-wrong-offset": 400,
    "firebase-session-cancel": 200,
    "list-start-offset": 200,
    "list-match-glob": 200,
    "firebase-list-page-1": 200,
    "firebase-list-page-2": 200,
  };
  for (const [id, wanted] of Object.entries(expected))
    assert.equal(status(answers, id), wanted, id);
  assert.equal(
    ids(answers).filter(
      (id) => !(id in expected) && !id.startsWith("cleanup-") && !id.startsWith("final-"),
    ).length,
    0,
  );
});

test("every GCS create carries ifGenerationMatch=0: the target, the source, the destination, the session", async () => {
  const { fake } = await run();
  const creates = fake.calls.filter(
    (call) =>
      call.method === "POST" &&
      call.href.includes("/upload/storage/v1/b/") &&
      !q(call).has("upload_id") &&
      (q(call).get("name") === plan.names.target
        ? call === fake.calls.find((c) => q(c).get("name") === plan.names.target)
        : true),
  );
  const names = creates.map((call) => q(call).get("name"));
  assert.deepEqual(
    names.toSorted(),
    [plan.names.gcsSession, plan.names.live, plan.names.source, plan.names.target].toSorted(),
  );
  for (const call of creates) assert.equal(q(call).get("ifGenerationMatch"), "0", call.href);
});

test("the preconditions are the target's own values, made stale by one: the generation and the metageneration", async () => {
  const { fake } = await run();
  const target = fake.history.find((row) => row.name === plan.names.target);
  const later = (BigInt(target.generation) + 1n).toString();
  const patch = fake.calls.filter((c) => c.method === "PATCH" && c.href.includes("/storage/v1/"));
  assert.equal(patch.length, 4);
  assert.deepEqual(
    patch.map((c) => [q(c).get("ifGenerationMatch"), q(c).get("ifMetagenerationMatch")]),
    [
      [later, null],
      [target.generation, "2"],
      [target.generation, ""],
      [target.generation, "abc"],
    ],
  );
  const put = at(fake, (c) => c.method === "PUT" && c.href.includes("/storage/v1/"));
  assert.deepEqual(
    [q(put).get("ifGenerationMatch"), q(put).get("ifMetagenerationMatch")],
    [target.generation, "2"],
  );
  const deletes = fake.calls.filter(
    (c) => c.method === "DELETE" && decodeURIComponent(c.href).includes(`/o/${plan.names.target}?`),
  );
  assert.deepEqual(
    deletes
      .slice(0, 2)
      .map((c) => [q(c).get("ifGenerationMatch"), q(c).get("ifGenerationNotMatch")]),
    [
      [later, null],
      [null, target.generation],
    ],
  );
  // The v0 routes get the same stale generation, and a create-only precondition on the live object.
  const v0Patch = at(fake, (c) => c.method === "PATCH" && c.href.includes("/v0/"));
  assert.equal(q(v0Patch).get("ifGenerationMatch"), later);
  const v0Upload = at(
    fake,
    (c) =>
      c.href.includes("/v0/b/") && c.method === "POST" && q(c).get("ifGenerationMatch") === "0",
  );
  assert.equal(q(v0Upload).get("name"), plan.names.target);
});

test("the two deletes of the target come after every other write to it", async () => {
  const { fake } = await run();
  const writes = fake.calls.filter(
    (c) =>
      ["POST", "PATCH", "PUT", "DELETE"].includes(c.method) &&
      (decodeURIComponent(c.href).includes(`/${plan.names.target}`) ||
        q(c).get("name") === plan.names.target),
  );
  const firstDelete = writes.findIndex((c) => c.method === "DELETE");
  assert.ok(firstDelete > 0);
  for (const call of writes.slice(firstDelete).slice(0, 2)) assert.equal(call.method, "DELETE");
});

test("the requests have the corpus's methods, headers and bodies", async () => {
  const { fake } = await run();
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.scope });
  const step = (recipe, id) =>
    corpus.recipes.find((r) => r.id === recipe).steps.find((s) => s.id === id);
  const patchStep = step(
    "storage-object/gcs/metageneration-preconditions",
    "patch-ifMetagenerationMatch-stale",
  );
  const patch = at(fake, (c) => c.method === "PATCH" && c.href.includes("/storage/v1/"));
  assert.equal(patch.headers.get("content-type"), patchStep.headers["content-type"]);
  assert.deepEqual(JSON.parse(patch.body), patchStep.body.json);
  const create = step(
    "storage-object/gcs/generation-preconditions",
    "upload-ifGenerationMatch-zero-present",
  );
  const post = at(fake, (c) => c.method === "POST" && c.href.includes("uploadType=media"));
  assert.equal(post.body.toString("base64"), create.body.base64);
  assert.equal(post.headers.get("content-type"), "application/octet-stream");
  const copy = at(fake, (c) => c.href.includes("/copyTo/") && c.href.includes("missing-source"));
  assert.deepEqual(JSON.parse(copy.body), {});
  assert.equal(q(copy).get("ifGenerationMatch"), "0");
  const rewriteMissing = at(
    fake,
    (c) => c.href.includes("/rewriteTo/") && c.href.includes("rewrite-missing-source"),
  );
  assert.equal(rewriteMissing.headers.get("content-type"), "application/json");
  const live = at(fake, (c) => c.href.includes("/copyTo/") && c.href.includes("refused-copy"));
  assert.ok(decodeURIComponent(live.href).includes(`/${plan.names.source}/copyTo/`));
  assert.equal(q(live).get("ifGenerationMatch"), "0");
  for (const row of fake.calls) {
    assert.equal(row.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(row.headers.get("x-goog-user-project"), PROJECT);
  }
});

test("the sessions get a chunk at a wrong offset, a cancel, and (GCS) an invalid session", async () => {
  const { fake } = await run();
  const wrong = at(
    fake,
    (c) => c.method === "PUT" && c.headers.get("content-range") === "bytes 100-262143/262147",
  );
  assert.equal(wrong.body.length, 262044);
  const cancel = at(fake, (c) => c.method === "DELETE" && q(c).has("upload_id"));
  assert.match(q(cancel).get("upload_id"), /^s/);
  const invalid = at(fake, (c) => q(c).get("upload_id") === "invalid-session-id");
  assert.equal(invalid.method, "PUT");
  assert.equal(invalid.headers.get("content-range"), "bytes */262147");
  const firebase = fake.calls.filter((c) => q(c).get("upload_id")?.startsWith("f"));
  assert.deepEqual(
    firebase.map((c) => c.headers.get("x-goog-upload-command")),
    ["upload", "cancel"],
  );
  assert.equal(firebase[0].headers.get("x-goog-upload-offset"), "1");
  assert.equal(firebase[0].body.length, 1);
});

test("the list filters and Firebase paging are asked for while the prefix holds objects", async () => {
  const { fake } = await run();
  const offset = at(fake, (c) => q(c).has("startOffset"));
  assert.equal(q(offset).get("prefix"), plan.scope);
  assert.equal(q(offset).get("startOffset"), `${plan.scope}copy/`);
  assert.equal(q(offset).get("endOffset"), `${plan.scope}pre/`);
  const glob = at(fake, (c) => q(c).has("matchGlob"));
  assert.equal(q(glob).get("matchGlob"), `${plan.scope}copy/*`);
  const page1 = at(
    fake,
    (c) =>
      c.href.includes("/v0/b/") &&
      c.method === "GET" &&
      q(c).get("maxResults") === "1" &&
      !q(c).has("pageToken"),
  );
  const page2 = at(fake, (c) => c.href.includes("/v0/b/") && q(c).has("pageToken"));
  assert.equal(q(page1).get("prefix"), plan.scope);
  assert.equal(q(page2).get("pageToken"), "1");
});

// ---- production that accepts what it should refuse --------------------------------------------------------------------

test("when production accepts every write it should refuse, cleanup still ends prefix-empty within the budget", async () => {
  const { fake, answers } = await run({ acceptRefused: true });
  assert.equal(fake.store.size, 0, "what the accepted writes made is removed");
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  assert.ok(fake.calls.length <= PROBE4_MAX_REQUESTS, `${fake.calls.length}`);
  // The accepted copies of a missing source made objects the plan does not name: removed by name.
  assert.ok(ids(answers).some((id) => id.startsWith("cleanup-extra-delete-")));
  assert.equal(status(answers, "copy-missing-source"), 200);
});

test("when every recording step answers something unexpected, the run still ends prefix-empty", async () => {
  const { fake, answers, interrupted } = await run({ odd: true });
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  const skipped = answers.filter((row) => row.skipped);
  for (const row of skipped)
    assert.match(row.skipped, /no session URL|no target metadata|no next page token/);
  assert.ok(skipped.length >= 5);
  for (const name of plan.objects)
    assert.ok(
      fake.calls.some(
        (c) => c.method === "GET" && decodeURIComponent(c.href).endsWith(`/o/${name}`),
      ),
      name,
    );
});

test("a target whose metadata is unusable skips the precondition refusals, with the reason, and cleanup goes on", async () => {
  const fake = production({});
  const original = fake.fetchImpl;
  fake.fetchImpl = async (url, init) => {
    if (
      init.method === "GET" &&
      String(url).endsWith(`/o/${encodeURIComponent(plan.names.target)}`) &&
      !fake.calls.some((c) => c.method === "DELETE")
    )
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    return original(url, init);
  };
  const result = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
  const skipped = result.answers
    .filter((row) => row.skipped === "no target metadata")
    .map((row) => row.id);
  assert.equal(skipped.length, 11);
  assert.ok(skipped.includes("delete-generation-not-match-current"));
  assert.equal(fake.store.size, 0);
  assert.ok(!fake.calls.some((c) => c.method === "PATCH"));
});

test("a session start without a URL skips its follow-ups with the reason", async () => {
  const { answers, fake } = await run({ odd: true });
  for (const id of [
    "gcs-session-wrong-offset",
    "gcs-session-cancel",
    "gcs-session-invalid",
    "firebase-session-wrong-offset",
    "firebase-session-cancel",
  ])
    assert.deepEqual(
      answers.find((row) => row.id === id),
      { id, skipped: "no session URL" },
    );
  assert.equal(fake.store.size, 0);
});

test("a Firebase list without a next-page token skips its second page", async () => {
  const { answers } = await run({ noToken: true });
  assert.deepEqual(
    answers.find((row) => row.id === "firebase-list-page-2"),
    {
      id: "firebase-list-page-2",
      skipped: "no next page token",
    },
  );
});

// ---- cleanup does not depend on an answer --------------------------------------------------------------------------

test("a metadata read that gives no generation is followed by a delete by name", async () => {
  const { fake, answers } = await run({ noGeneration: true });
  assert.equal(fake.store.size, 0);
  const deletes = fake.calls.filter((c) => c.method === "DELETE" && !q(c).has("upload_id"));
  assert.ok(deletes.length >= 3);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
});

test("an object that cannot be removed leaves the closing row not empty, and no more than ten are tried by name", async () => {
  const stuck = plan.objects[1];
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
  assert.ok(fake.calls.length <= PROBE4_MAX_REQUESTS, `${fake.calls.length}`);
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
  const { fake, answers, interrupted } = await run({ failAt: 12 });
  assert.ok(interrupted);
  assert.match(interrupted.reason, /fetch failed/);
  assert.equal(typeof interrupted.step, "string");
  assert.equal(fake.store.size, 0);
  assert.equal(probe4ClosingRow(answers).prefixEmpty, true);
  assert.ok(!ids(answers).includes("list-match-glob"));
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
      if (String(href).includes("matchGlob=")) {
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
    result.answers.find((row) => row.id === "list-match-glob"),
    {
      id: "list-match-glob",
      skipped: "route is not in the table",
    },
  );
  assert.equal(fake.store.size, 0);
});

test("a multi-line error message ends the recording with its first line only", async () => {
  const fake = production();
  const original = fake.fetchImpl;
  let count = 0;
  fake.fetchImpl = async (url, init) => {
    if (++count === 5) throw new TypeError("connection reset\nsecond line with detail");
    return original(url, init);
  };
  const result = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
  assert.equal(result.interrupted.reason, "connection reset");
});

test("the request count: an honest run is at most 40, and the worst case at most 51", async () => {
  const honest = await run();
  assert.ok(honest.fake.calls.length <= 40, `${honest.fake.calls.length}`);
  const worst = await run({ acceptRefused: true, deleteFails: plan.objects[0] });
  assert.ok(worst.fake.calls.length <= 51, `${worst.fake.calls.length}`);
});

// ---- what each request is, one by one -----------------------------------------------------------------------------------

const decoded = (call) => decodeURIComponent(new URL(call.href).pathname);

test("each refused create, copy and rewrite carries ifGenerationMatch=0 and the names the plan fixes", async () => {
  const { fake } = await run();
  const target = fake.calls.filter(
    (c) =>
      c.method === "POST" &&
      q(c).get("name") === plan.names.target &&
      c.href.includes("/upload/storage/"),
  );
  assert.deepEqual(
    target.map((c) => q(c).get("ifGenerationMatch")),
    ["0", "0", `${BigInt(fake.history.find((h) => h.name === plan.names.target).generation) + 1n}`],
  );
  const transfers = fake.calls
    .filter((c) => /\/(copyTo|rewriteTo)\//.test(c.href))
    .map((c) => {
      const [, from, verb, to] = /\/o\/(.+)\/(copyTo|rewriteTo)\/b\/[^/]+\/o\/(.+)$/.exec(
        decoded(c),
      );
      return [from, verb, to, q(c).get("ifGenerationMatch")];
    });
  assert.deepEqual(transfers, [
    [plan.names.missingSource, "copyTo", plan.names.missingDestination, "0"],
    [plan.names.rewriteMissingSource, "rewriteTo", plan.names.rewriteMissingDestination, "0"],
    [plan.names.source, "copyTo", plan.names.live, "0"],
    [plan.names.source, "rewriteTo", plan.names.live, "0"],
  ]);
});

test("the PUT is the corpus's put step, the v0 upload is a binary create on the target, the v0 patch is the patch step", async () => {
  const { fake } = await run();
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.scope });
  const step = (id) =>
    corpus.recipes
      .find((r) => r.id === "storage-object/gcs/metageneration-preconditions")
      .steps.find((s) => s.id === id);
  const put = at(fake, (c) => c.method === "PUT" && c.href.includes("/storage/v1/"));
  assert.equal(
    put.headers.get("content-type"),
    step("put-ifMetagenerationMatch-stale").headers["content-type"],
  );
  assert.deepEqual(JSON.parse(put.body), step("put-ifMetagenerationMatch-stale").body.json);
  const v0 = at(
    fake,
    (c) =>
      c.method === "POST" &&
      c.href.includes("/v0/b/") &&
      !q(c).has("upload_id") &&
      !c.headers.has("x-goog-upload-command"),
  );
  assert.equal(v0.headers.get("content-type"), "application/octet-stream");
  assert.equal(q(v0).get("name"), plan.names.target);
  assert.equal(q(v0).get("ifGenerationMatch"), "0");
  const v0Patch = at(fake, (c) => c.method === "PATCH" && c.href.includes("/v0/"));
  assert.equal(v0Patch.headers.get("authorization"), `Bearer ${TOKEN}`);
  assert.equal(decoded(v0Patch), `/v0/b/${BUCKET}/o/${plan.names.target}`);
});

test("the sessions are opened for their own fixed names and the GCS lists use the GCS route", async () => {
  const { fake } = await run();
  const starts = fake.calls.filter(
    (c) =>
      !q(c).has("upload_id") &&
      (q(c).get("uploadType") === "resumable" ||
        c.headers.get("x-goog-upload-command") === "start"),
  );
  assert.deepEqual(
    starts.map((c) => q(c).get("name")),
    [plan.names.gcsSession, plan.names.firebaseSession],
  );
  const gcsLists = fake.calls.filter((c) => q(c).has("startOffset") || q(c).has("matchGlob"));
  for (const call of gcsLists)
    assert.equal(new URL(call.href).pathname, `/storage/v1/b/${BUCKET}/o`);
  const pages = fake.calls.filter(
    (c) =>
      new URL(c.href).pathname === `/v0/b/${BUCKET}/o` &&
      c.method === "GET" &&
      q(c).get("maxResults") === "1",
  );
  assert.equal(pages.length, 2);
});

test("metadata with only a generation, or only a metageneration, is not enough to make the refusals", async () => {
  for (const drop of ["generation", "metageneration"]) {
    const fake = production({});
    const original = fake.fetchImpl;
    fake.fetchImpl = async (url, init) => {
      const response = await original(url, init);
      if (
        init.method === "GET" &&
        String(url).endsWith(`/o/${encodeURIComponent(plan.names.target)}`) &&
        !fake.calls.some((c) => c.method === "DELETE")
      ) {
        const body = await response.json();
        delete body[drop];
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return response;
    };
    const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    assert.equal(answers.filter((row) => row.skipped === "no target metadata").length, 11, drop);
    assert.ok(!fake.calls.some((c) => c.method === "PATCH"), drop);
    assert.equal(fake.store.size, 0);
  }
});

test("an empty next-page token is no token: the second page is skipped", async () => {
  const fake = production({});
  const original = fake.fetchImpl;
  fake.fetchImpl = async (url, init) => {
    const response = await original(url, init);
    if (
      new URL(String(url)).pathname === `/v0/b/${BUCKET}/o` &&
      init.method === "GET" &&
      !new URL(String(url)).searchParams.has("pageToken")
    )
      return new Response(JSON.stringify({ items: [], nextPageToken: "" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    return response;
  };
  const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
  assert.deepEqual(
    answers.find((row) => row.id === "firebase-list-page-2"),
    { id: "firebase-list-page-2", skipped: "no next page token" },
  );
  assert.ok(!fake.calls.some((c) => new URL(c.href).searchParams.has("pageToken")));
});

// ---- the shared cleanup, judged through this probe ----------------------------------------------------------------

const respond = (body, code = 200) =>
  new Response(JSON.stringify(body), {
    status: code,
    headers: { "content-type": "application/json" },
  });

test("a generation that is not a plain number of at most twenty digits is not a precondition: the object is deleted by name", async () => {
  for (const generation of ["1234567890123456789012", "12x4", "0", "abc1"]) {
    const fake = production({});
    const original = fake.fetchImpl;
    fake.fetchImpl = async (url, init) => {
      const response = await original(url, init);
      const path = new URL(String(url)).pathname;
      if (
        init.method === "GET" &&
        path === `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(plan.names.source)}` &&
        fake.calls.some((c) => c.method === "DELETE")
      ) {
        const body = await response.json();
        return respond({ ...body, generation });
      }
      return response;
    };
    const { answers } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
    const deletes = fake.calls.filter(
      (c) => c.method === "DELETE" && decoded(c).endsWith(`/o/${plan.names.source}`),
    );
    assert.equal(deletes.length, 1, generation);
    assert.equal(q(deletes[0]).has("ifGenerationMatch"), false, generation);
    assert.equal(fake.store.size, 0, generation);
    assert.equal(probe4ClosingRow(answers).prefixEmpty, true, generation);
  }
});

test("an error message longer than 200 characters is cut in the record", async () => {
  const fake = production({});
  const original = fake.fetchImpl;
  let count = 0;
  fake.fetchImpl = async (url, init) => {
    if (++count === 5) throw new TypeError("x".repeat(500));
    return original(url, init);
  };
  const { interrupted } = await sendProbe4({ wire: makeWire(fake), plan, origins: ORIGINS });
  assert.equal(interrupted.reason.length, 200);
});

test("only an error marked routeRefused=true is a refusal by the route table; any other error ends the recording", async () => {
  for (const marker of [false, undefined, "yes"]) {
    const fake = production({});
    const wire = makeWire(fake);
    const failing = {
      fetch: async (href, init) => {
        if (String(href).includes("matchGlob=")) {
          const error = new Error("boom");
          if (marker !== undefined) error.routeRefused = marker;
          throw error;
        }
        return wire.fetch(href, init);
      },
      snapshot: () => wire.snapshot(),
    };
    const { answers, interrupted } = await sendProbe4({ wire: failing, plan, origins: ORIGINS });
    assert.equal(interrupted?.step, "list-match-glob", String(marker));
    assert.ok(!answers.some((row) => row.id === "list-match-glob" && row.skipped), String(marker));
    assert.equal(fake.store.size, 0);
  }
});

test("a session start the route table refused skips the session's follow-ups, with the reason", async () => {
  const fake = production({});
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (String(href).includes("uploadType=resumable")) {
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
    answers.find((row) => row.id === "gcs-session-start"),
    {
      id: "gcs-session-start",
      skipped: "route is not in the table",
    },
  );
  for (const id of ["gcs-session-wrong-offset", "gcs-session-cancel", "gcs-session-invalid"])
    assert.deepEqual(
      answers.find((row) => row.id === id),
      { id, skipped: "no session URL" },
    );
});

test("what the final list holds is removed by name only when it is a string under the probe's own scope", async () => {
  const fake = production({});
  const original = fake.fetchImpl;
  const outside = `${plan.prefix}other-probe/foreign.bin`;
  fake.fetchImpl = async (url, init) => {
    const response = await original(url, init);
    const u = new URL(String(url));
    if (u.pathname === `/storage/v1/b/${BUCKET}/o` && u.searchParams.get("maxResults") === "1000")
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
    (c) =>
      (c.method === "DELETE" && decoded(c).includes("/o/") && decoded(c).endsWith("left.bin")) ||
      decoded(c).endsWith("foreign.bin"),
  );
  assert.deepEqual(
    extra.map((c) => decoded(c).split("/o/")[1]),
    [`${plan.scope}left.bin`],
  );
  assert.ok(answers.some((row) => row.id === "final-list-again"));
});
