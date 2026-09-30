// probe-v3: the plan, the requests it sends through the real lean wire, and above all that its
// cleanup finds and removes every object it can have created, whatever any answer of the recording
// says. The production is a small stateful fake that answers in the shapes production has recorded.

import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { BUCKET, json, production } from "./storage-object-probe3-fake.mjs";
import { createLeanWire } from "./storage-object/lean-wire.mjs";
import {
  buildProbe3Plan,
  PROBE3_ESTIMATE_USD,
  PROBE3_MAX_REQUESTS,
  PROBE3_RESERVE_USD,
  probe3ClosingRow,
  sendProbe3,
} from "./storage-object/probe3.mjs";

const PROJECT = "fireemu-oracle-query";
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";
const ORIGINS = {
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
};

const plan = buildProbe3Plan({ projectId: PROJECT, bucket: BUCKET, runId: RUN, otherRunId: OTHER });

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
  const wire = makeWire(fake, wireOptions);
  const result = await sendProbe3({ wire, plan, origins: ORIGINS });
  return { fake, wire, ...result };
}

const ids = (answers) => answers.map((row) => row.id);

// ---- the plan ------------------------------------------------------------------------------------

test("the plan is seven fixed names under the probe's own prefix, whatever the answers", () => {
  assert.equal(plan.scope, `storage-object/${RUN}/probe3/`);
  assert.equal(plan.objects.length, 7);
  assert.equal(new Set(plan.objects).size, 7);
  for (const name of plan.objects) assert.ok(name.startsWith(plan.scope), name);
  const again = buildProbe3Plan({
    projectId: PROJECT,
    bucket: BUCKET,
    runId: RUN,
    otherRunId: OTHER,
  });
  assert.deepEqual(again.objects, plan.objects);
  const other = buildProbe3Plan({
    projectId: PROJECT,
    bucket: BUCKET,
    runId: OTHER,
    otherRunId: RUN,
  });
  assert.ok(other.objects.every((name) => name.startsWith(`storage-object/${OTHER}/probe3/`)));
});

test("the request budget of the envelope covers the worst case the plan can send", () => {
  // The recording is at most 24 requests (multipart 1, GCS resumable 4, Firebase resumable 5,
  // source 2, copy 1, rewrite 3, tokens 3, lists 4 + 1); cleanup is 3 per object (21), the final
  // list, and at most 10 removals by name and one more list: 24 + 21 + 1 + 11 = 57, inside 60.
  assert.equal(PROBE3_MAX_REQUESTS, 60);
  assert.equal(PROBE3_RESERVE_USD, 0.05);
  assert.equal(PROBE3_ESTIMATE_USD, 0.02);
});

// ---- an honest production ---------------------------------------------------------------------

test("an honest run records every step, removes all seven objects, and closes on an empty prefix", async () => {
  const { fake, answers, interrupted } = await run();
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0, "nothing is left under the prefix");
  const closing = probe3ClosingRow(answers);
  assert.equal(closing.id, "final-list");
  assert.equal(closing.prefixEmpty, true);
  assert.ok(fake.calls.length <= 46, `${fake.calls.length} requests`);
  for (const wanted of [
    "multipart-create",
    "gcs-resumable-start",
    "gcs-resumable-chunk",
    "gcs-resumable-status",
    "gcs-resumable-finish",
    "firebase-resumable-start",
    "firebase-resumable-query",
    "firebase-resumable-chunk",
    "firebase-resumable-query-after-chunk",
    "firebase-resumable-finish",
    "copy-source-create",
    "copy-source-metadata",
    "copy-to",
    "rewrite-0",
    "token-upload",
    "token-create",
    "token-delete",
    "list-page-1",
    "list-delimiter",
  ])
    assert.ok(ids(answers).includes(wanted), wanted);
  assert.equal(answers.filter((row) => row.skipped).length, 0);
});

test("every GCS create carries ifGenerationMatch=0, the source, copy and rewrite destinations included", async () => {
  const { fake } = await run();
  const creates = fake.calls.filter((call) => {
    const u = new URL(call.href);
    return (
      (call.method === "POST" &&
        u.pathname.startsWith("/upload/storage/v1/b/") &&
        u.searchParams.get("uploadType") !== null &&
        !u.searchParams.has("upload_id")) ||
      (call.method === "POST" && /\/(copyTo|rewriteTo)\//.test(u.pathname))
    );
  });
  // multipart, GCS resumable start, the source, copyTo, rewriteTo.
  assert.equal(creates.length, 5);
  for (const call of creates)
    assert.equal(new URL(call.href).searchParams.get("ifGenerationMatch"), "0", call.href);
});

test("the copy and rewrite carry the source's generation and metageneration when its metadata gave them", async () => {
  const { fake } = await run();
  const copy = fake.calls.find((call) => call.href.includes("/copyTo/"));
  const query = new URL(copy.href).searchParams;
  const source = fake.history.find((row) => row.name === plan.objects[3]);
  assert.equal(query.get("ifSourceGenerationMatch"), source.generation);
  assert.equal(query.get("ifSourceMetagenerationMatch"), "2");
  // The rewrite's first call carries the same preconditions.
  const rewrite = fake.calls.find((call) => call.href.includes("/rewriteTo/"));
  const rq = new URL(rewrite.href).searchParams;
  assert.equal(rq.get("ifSourceGenerationMatch"), source.generation);
  assert.equal(rq.get("ifSourceMetagenerationMatch"), "2");
  assert.equal(rq.get("ifGenerationMatch"), "0");
  const odd = await run({ odd: true });
  const oddCopy = odd.fake.calls.find((call) => call.href.includes("/copyTo/"));
  assert.equal(new URL(oddCopy.href).searchParams.has("ifSourceGenerationMatch"), false);
});

test("the requests have the shapes the corpus declares for them", async () => {
  const { fake } = await run();
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.scope });
  const recipe = (id) => corpus.recipes.find((row) => row.id === id);
  const multipart = recipe("storage-object/gcs/simple-multipart-upload").steps.find(
    (row) => row.id === "valid",
  );
  const call = fake.calls.find((row) => row.href.includes("uploadType=multipart"));
  assert.equal(call.headers.get("content-type"), multipart.headers["content-type"]);
  assert.equal(Buffer.from(call.body).toString("base64"), multipart.body.base64);
  const chunk = recipe("storage-object/gcs/resumable-upload").steps.find(
    (row) => row.id === "chunk-0",
  );
  const put = fake.calls.find((row) => row.method === "PUT" && row.body?.length === 262144);
  assert.equal(put.headers.get("content-range"), chunk.headers["content-range"]);
  const finalize = fake.calls.find(
    (row) => row.headers.get("x-goog-upload-command") === "upload, finalize",
  );
  assert.equal(finalize.headers.get("x-goog-upload-offset"), "262144");
  assert.equal(finalize.body.length, 3);
  const create = fake.calls.find((row) => row.href.includes("create_token=true"));
  assert.equal(create.method, "POST");
  const del = fake.calls.find((row) => row.href.includes("delete_token="));
  assert.equal(new URL(del.href).searchParams.get("delete_token"), "t2");
  for (const row of fake.calls) {
    assert.equal(row.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(row.headers.get("x-goog-user-project"), PROJECT);
  }
});

test("a rewrite that takes several calls is followed with the token it gave, and no further than three calls", async () => {
  const two = await run({ rewriteCalls: 2 });
  assert.deepEqual(
    ids(two.answers).filter((id) => id.startsWith("rewrite-")),
    ["rewrite-0", "rewrite-1"],
  );
  const second = two.fake.calls.find((row) => row.href.includes("rewriteToken="));
  assert.equal(new URL(second.href).searchParams.get("rewriteToken"), "rt1");
  const many = await run({ rewriteCalls: 9 });
  assert.deepEqual(
    ids(many.answers).filter((id) => id.startsWith("rewrite-")),
    ["rewrite-0", "rewrite-1", "rewrite-2"],
  );
  assert.equal(many.fake.store.size, 0);
});

test("the lists are read while the prefix holds objects, in pages of two, and once with a delimiter", async () => {
  const { fake, answers } = await run();
  const pages = ids(answers).filter((id) => id.startsWith("list-page-"));
  assert.ok(pages.length >= 2 && pages.length <= 4, pages.join());
  const first = fake.calls.find((row) => row.href.includes("maxResults=2"));
  assert.equal(new URL(first.href).searchParams.get("prefix"), plan.scope);
  assert.ok(fake.calls.some((row) => row.href.includes("pageToken=")));
  assert.ok(fake.calls.some((row) => row.href.includes("delimiter=")));
});

test("a token that is not a single new one is not deleted", async () => {
  const wire = { calls: 0 };
  const fake = production();
  const original = fake.fetchImpl;
  fake.fetchImpl = async (url, init) => {
    const response = await original(url, init);
    if (String(url).includes("create_token=true")) {
      wire.calls++;
      return json(200, { name: "x", bucket: BUCKET, downloadTokens: "t1" });
    }
    return response;
  };
  const result = await sendProbe3({ wire: makeWire(fake), plan, origins: ORIGINS });
  const row = result.answers.find((r) => r.id === "token-delete");
  assert.deepEqual(row, { id: "token-delete", skipped: "no single new token" });
  assert.equal(fake.store.size, 0);
});

// ---- cleanup does not depend on any answer of the recording -------------------------------------------

test("when every recording step answers something unexpected, the run still ends prefix-empty", async () => {
  const { fake, answers, interrupted } = await run({ odd: true });
  assert.equal(interrupted, null);
  assert.equal(fake.store.size, 0, "the objects the odd answers hid are removed");
  assert.equal(probe3ClosingRow(answers).prefixEmpty, true);
  // The steps that needed an earlier answer say why they were skipped.
  const skipped = answers.filter((row) => row.skipped);
  assert.ok(skipped.length >= 8);
  for (const row of skipped)
    assert.match(row.skipped, /no session URL|no single new token|no rewrite token/);
  // Every one of the seven names was looked up by its own metadata read.
  for (const name of plan.objects)
    assert.ok(
      fake.calls.some(
        (call) =>
          call.method === "GET" &&
          call.href.endsWith(`/o/${encodeURIComponent(name)}`) &&
          call.headers.get("x-goog-user-project") === PROJECT,
      ),
      name,
    );
});

test("a metadata read that gives no generation is followed by a delete by name", async () => {
  const { fake, answers } = await run({ noGeneration: true });
  assert.equal(fake.store.size, 0);
  const deletes = fake.calls.filter((call) => call.method === "DELETE");
  assert.ok(deletes.length >= 7);
  for (const call of deletes)
    assert.equal(new URL(call.href).searchParams.has("ifGenerationMatch"), false, call.href);
  assert.equal(probe3ClosingRow(answers).prefixEmpty, true);
});

test("a conditional delete that is refused is followed, once the list shows the object, by a delete by name", async () => {
  const { fake, answers } = await run({ conditionalDeleteFails: true });
  assert.equal(fake.store.size, 0);
  assert.deepEqual(
    ids(answers).filter((id) => id.startsWith("final-list")),
    ["final-list", "final-list-again"],
  );
  assert.equal(probe3ClosingRow(answers).id, "final-list-again");
  assert.equal(probe3ClosingRow(answers).prefixEmpty, true);
  assert.ok(ids(answers).some((id) => id.startsWith("cleanup-extra-delete-")));
});

test("an object that cannot be removed leaves the closing row not empty, and no more than ten are tried by name", async () => {
  const stuck = plan.objects[1];
  const { fake, answers } = await run({ deleteFails: stuck });
  assert.ok(fake.store.has(stuck));
  const closing = probe3ClosingRow(answers);
  assert.equal(closing.prefixEmpty, false);
  assert.equal(closing.id, "final-list-again");
  assert.ok(ids(answers).filter((id) => id.startsWith("cleanup-extra-delete-")).length <= 10);
});

test("a connection lost during the recording ends the recording, and the objects made so far are removed", async () => {
  // Request 16 is in the middle of the recording (the GCS multipart and both sessions are done).
  const { fake, answers, interrupted } = await run({ failAt: 16 });
  assert.ok(interrupted);
  assert.match(interrupted.reason, /fetch failed/);
  assert.equal(typeof interrupted.step, "string");
  assert.equal(fake.store.size, 0, "what the recording made is removed");
  assert.equal(probe3ClosingRow(answers).prefixEmpty, true);
  assert.ok(!ids(answers).includes("list-delimiter"), "the recording did not go on");
});

test("a connection lost at any request ends in a clean prefix or in an error, never in a leftover with a clean row", async () => {
  const total = (await run()).fake.calls.length;
  for (let failAt = 1; failAt <= total; failAt++) {
    const fake = production({ failAt });
    let result;
    try {
      result = await sendProbe3({ wire: makeWire(fake), plan, origins: ORIGINS });
    } catch (error) {
      // Cleanup itself could not finish: the error says where, and what was answered.
      assert.equal(typeof error.probeStep, "string", `failAt ${failAt}`);
      assert.ok(Array.isArray(error.answered), `failAt ${failAt}`);
      continue;
    }
    const closing = probe3ClosingRow(result.answers);
    if (closing?.prefixEmpty === true)
      assert.equal(
        fake.store.size,
        0,
        `failAt ${failAt}: a clean row over ${fake.store.size} objects`,
      );
  }
});

test("a connection lost during cleanup stops with what was answered, so the run is needs-recovery", async () => {
  const total = (await run()).fake.calls.length;
  const fake = production({ failAt: total - 2 });
  await assert.rejects(sendProbe3({ wire: makeWire(fake), plan, origins: ORIGINS }), (error) => {
    assert.match(error.probeStep, /^(cleanup|final)/);
    assert.ok(error.answered.length > 20);
    return true;
  });
});

test("a capture failure halts the wire, and cleanup cannot go on either: the run stops", async () => {
  let count = 0;
  const fake = production();
  const wire = makeWire(fake, {
    capture: async () => {
      if (++count === 6) throw new Error("disk full");
    },
  });
  await assert.rejects(sendProbe3({ wire, plan, origins: ORIGINS }), /LEAN_WIRE|CAPTURE/);
});

// ---- the number of requests ------------------------------------------------------------------------

test("the most the plan can send stays inside the envelope's 60 requests", async () => {
  // Three rewrite calls, four list pages, one object that stays, and the removals by name.
  const stuck = plan.objects[0];
  const { fake } = await run({ rewriteCalls: 9, deleteFails: stuck });
  assert.ok(fake.calls.length <= PROBE3_MAX_REQUESTS, `${fake.calls.length}`);
  const honest = await run();
  assert.ok(honest.fake.calls.length <= 46, `${honest.fake.calls.length}`);
});

// ---- what the wire's route table refuses -----------------------------------------------------------

test("a request the route table refuses is recorded as skipped and the run goes on", async () => {
  const fake = production();
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (String(href).includes("delimiter=")) {
        const error = new Error("route is not in the table");
        error.routeRefused = true;
        throw error;
      }
      return wire.fetch(href, init);
    },
    snapshot: () => wire.snapshot(),
  };
  const result = await sendProbe3({ wire: refusing, plan, origins: ORIGINS });
  assert.deepEqual(
    result.answers.find((row) => row.id === "list-delimiter"),
    {
      id: "list-delimiter",
      skipped: "route is not in the table",
    },
  );
  assert.equal(fake.store.size, 0);
});

// ---- the exact requests ---------------------------------------------------------------------------

const commandOf = (call) => call.headers.get("x-goog-upload-command");

test("the two sessions send their requests in the corpus's order, each to the session URL", async () => {
  const { fake } = await run();
  const gcs = fake.calls.filter((call) =>
    new URL(call.href).searchParams.get("upload_id")?.startsWith("s"),
  );
  assert.deepEqual(
    gcs.map((call) => [call.method, call.headers.get("content-range"), call.body?.length ?? 0]),
    [
      ["PUT", "bytes 0-262143/262147", 262144],
      ["PUT", "bytes */262147", 0],
      ["PUT", "bytes 262144-262146/262147", 3],
    ],
  );
  const firebase = fake.calls.filter((call) =>
    new URL(call.href).searchParams.get("upload_id")?.startsWith("f"),
  );
  assert.deepEqual(
    firebase.map((call) => [
      call.method,
      commandOf(call),
      call.headers.get("x-goog-upload-offset"),
      call.body?.length ?? 0,
    ]),
    [
      ["POST", "query", null, 0],
      ["POST", "upload", "0", 262144],
      ["POST", "query", null, 0],
      ["POST", "upload, finalize", "262144", 3],
    ],
  );
  const starts = fake.calls.filter((call) => ["start"].includes(commandOf(call)));
  assert.equal(starts.length, 1);
  assert.equal(starts[0].headers.get("x-goog-upload-header-content-length"), "262147");
});

test("the request bodies are the corpus's JSON and bytes", async () => {
  const { fake } = await run();
  const corpus = buildCorpus({ bucket: BUCKET, prefix: plan.scope });
  const step = (recipe, id) =>
    corpus.recipes.find((row) => row.id === recipe).steps.find((row) => row.id === id);
  const bodyOf = (predicate) => fake.calls.find(predicate).body;
  assert.deepEqual(
    JSON.parse(bodyOf((c) => c.href.includes("/rewriteTo/"))),
    step("storage-object/gcs/copy-rewrite", "rewrite-0").body.json,
  );
  assert.deepEqual(
    JSON.parse(bodyOf((c) => c.href.includes("/copyTo/"))),
    step("storage-object/gcs/copy-rewrite", "copy").body.json,
  );
  assert.deepEqual(
    JSON.parse(bodyOf((c) => c.href.includes("uploadType=resumable") && c.method === "POST")),
    step("storage-object/gcs/resumable-upload", "initiate").body.json,
  );
  assert.deepEqual(
    JSON.parse(bodyOf((c) => commandOf(c) === "start")),
    step("storage-object/firebase/resumable-upload", "initiate").body.json,
  );
});

test("a rewrite call after the first has the token and nothing else, and no body", async () => {
  const { fake } = await run({ rewriteCalls: 2 });
  const calls = fake.calls.filter((call) => call.href.includes("/rewriteTo/"));
  assert.equal(calls.length, 2);
  const [first, second] = calls;
  assert.ok(first.body !== undefined);
  assert.equal(second.body, undefined);
  assert.deepEqual([...new URL(second.href).searchParams.keys()], ["rewriteToken"]);
});

test("the final list asks for the whole prefix, at most a thousand", async () => {
  const { fake } = await run();
  const final = fake.calls.findLast(
    (call) => call.method === "GET" && new URL(call.href).searchParams.get("maxResults") === "1000",
  );
  const query = new URL(final.href).searchParams;
  assert.equal(query.get("prefix"), plan.scope);
  assert.equal(new URL(final.href).pathname, `/storage/v1/b/${BUCKET}/o`);
});

test("cleanup reads each object, deletes it, and reads it absent: three requests for each of the seven", async () => {
  const { fake, answers } = await run();
  for (const index of plan.objects.keys())
    for (const kind of ["metadata", "delete", "absent"])
      assert.ok(ids(answers).includes(`cleanup-${kind}-${index}`), `${kind} ${index}`);
  assert.equal(fake.calls.filter((call) => call.method === "DELETE").length, 7);
});

// ---- what an odd answer must not do ------------------------------------------------------------------

test("a multi-line error message ends the recording with its first line only", async () => {
  const fake = production();
  const original = fake.fetchImpl;
  let count = 0;
  fake.fetchImpl = async (url, init) => {
    if (++count === 5) throw new TypeError("connection reset\nsecond line with detail");
    return original(url, init);
  };
  const result = await sendProbe3({ wire: makeWire(fake), plan, origins: ORIGINS });
  assert.equal(result.interrupted.reason, "connection reset");
});

test("a session start that answers with a URL that is not on the wire's origin, or with a failure, gets no follow-up", async () => {
  for (const change of [
    { status: 500, headers: { location: "http://127.0.0.1:19199/upload/x?upload_id=s1" } },
    { status: 200, headers: { location: "https://elsewhere.example/upload?upload_id=s1" } },
    {
      status: 200,
      headers: { location: "http://127.0.0.1:19199.example.com/upload?upload_id=s1" },
    },
    { status: 300, headers: { location: "http://127.0.0.1:19199/upload/x?upload_id=s1" } },
  ]) {
    const fake = production();
    const wire = makeWire(fake);
    // Stand in for a wire that hands back this answer to the session starts.
    const odd = {
      fetch: async (href, init) => {
        const response = await wire.fetch(href, init);
        if (new URL(href).searchParams.get("uploadType") !== "resumable" || init.method !== "POST")
          return response;
        const headers = new Headers(response.headers);
        for (const [key, value] of Object.entries(change.headers)) headers.set(key, value);
        return new Response("", { status: change.status, headers });
      },
      snapshot: () => wire.snapshot(),
    };
    const result = await sendProbe3({ wire: odd, plan, origins: ORIGINS });
    for (const id of ["gcs-resumable-chunk", "gcs-resumable-status", "gcs-resumable-finish"])
      assert.deepEqual(
        result.answers.find((row) => row.id === id),
        {
          id,
          skipped: "no session URL",
        },
      );
    assert.equal(fake.store.size, 0);
  }
});

test("a token step with two new tokens, or none, deletes nothing", async () => {
  const many = await run({ manyTokens: true });
  assert.deepEqual(
    many.answers.find((row) => row.id === "token-delete"),
    {
      id: "token-delete",
      skipped: "no single new token",
    },
  );
  assert.ok(!many.fake.calls.some((call) => call.href.includes("delete_token=")));
});

test("a rewrite that is not done and gives no token, or an empty one, stops the rewrite there", async () => {
  for (const options of [{ rewriteNoToken: true }, { rewriteEmptyToken: true }]) {
    const { answers, fake } = await run({ rewriteCalls: 3, ...options });
    assert.deepEqual(
      answers.find((row) => row.id === "rewrite-1"),
      {
        id: "rewrite-1",
        skipped: "no rewrite token",
      },
    );
    assert.ok(!ids(answers).includes("rewrite-2"));
    assert.equal(fake.calls.filter((call) => call.href.includes("/rewriteTo/")).length, 1);
    assert.equal(fake.store.size, 0);
  }
});

test("the list pages stop after four, and where no token says there is another", async () => {
  const endless = await run({ endlessPages: true });
  assert.equal(ids(endless.answers).filter((id) => id.startsWith("list-page-")).length, 4);
  const empty = await run({ endlessPages: true, emptyToken: true });
  assert.equal(ids(empty.answers).filter((id) => id.startsWith("list-page-")).length, 1);
  const odd = await run({ odd: true });
  assert.equal(ids(odd.answers).filter((id) => id.startsWith("list-page-")).length, 1);
});

test("a metadata read that is not a 200 is followed by a delete by name, whatever it says about a generation", async () => {
  const { fake } = await run({ cleanupMetadata: { status: 403, body: '{"generation":"5"}' } });
  const deletes = fake.calls.filter((call) => call.method === "DELETE");
  assert.ok(deletes.length >= 7);
  for (const call of deletes)
    assert.equal(new URL(call.href).searchParams.has("ifGenerationMatch"), false, call.href);
});

test("an object that was never made is not deleted, and is not read again", async () => {
  // The recording is cut at the third request: only the multipart object exists.
  const { fake, answers } = await run({ failAt: 3 });
  const made = new Set(fake.history.map((row) => row.name));
  const deletes = fake.calls.filter((call) => call.method === "DELETE");
  assert.equal(deletes.length, made.size);
  const absentReads = ids(answers).filter((id) => id.startsWith("cleanup-absent-"));
  assert.equal(absentReads.length, made.size);
});

test("a cleanup metadata read the route table refuses does not stop the run, and the object is removed by name", async () => {
  const fake = production();
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (
        init.method === "GET" &&
        String(href).endsWith(`/o/${encodeURIComponent(plan.objects[0])}`) &&
        fake.calls.some((call) => call.href.includes("maxResults=2"))
      ) {
        const error = new Error("route is not in the table");
        error.routeRefused = true;
        throw error;
      }
      return wire.fetch(href, init);
    },
    snapshot: () => wire.snapshot(),
  };
  const { answers } = await sendProbe3({ wire: refusing, plan, origins: ORIGINS });
  assert.deepEqual(
    answers.find((row) => row.id === "cleanup-metadata-0"),
    {
      id: "cleanup-metadata-0",
      skipped: "route is not in the table",
    },
  );
  // The list still shows that object, and the second chance removes it by name.
  assert.equal(fake.store.size, 0);
  assert.ok(ids(answers).includes("cleanup-extra-delete-0"));
});

test("a final list the route table refuses leaves no clean row, and does not crash", async () => {
  const fake = production();
  const wire = makeWire(fake);
  const refusing = {
    fetch: async (href, init) => {
      if (new URL(href).searchParams.get("maxResults") === "1000") {
        const error = new Error("route is not in the table");
        error.routeRefused = true;
        throw error;
      }
      return wire.fetch(href, init);
    },
    snapshot: () => wire.snapshot(),
  };
  const { answers } = await sendProbe3({ wire: refusing, plan, origins: ORIGINS });
  const closing = probe3ClosingRow(answers);
  assert.deepEqual(closing, { id: "final-list", skipped: "route is not in the table" });
  assert.notEqual(closing.prefixEmpty, true);
  assert.ok(!ids(answers).includes("final-list-again"));
});

// ---- the second chance ---------------------------------------------------------------------------------

test("at most ten leftovers are removed by name, and only those under the prefix", async () => {
  const strayPrefix = `${plan.scope}stray/`;
  const { fake, answers } = await run({ strays: 15, strayPrefix });
  assert.equal(ids(answers).filter((id) => id.startsWith("cleanup-extra-delete-")).length, 10);
  assert.equal(fake.store.size, 5);
  assert.equal(probe3ClosingRow(answers).prefixEmpty, false);
});

test("a name the final list gives from outside the prefix is not deleted, whatever else the list holds", async () => {
  const strayPrefix = `${plan.scope}stray/`;
  const { fake, answers } = await run({ strays: 2, strayPrefix, listLeaksOutside: true });
  assert.ok(!fake.calls.some((call) => call.href.includes("storage-object%2Fother%2F")));
  assert.equal(ids(answers).filter((id) => id.startsWith("cleanup-extra-delete-")).length, 2);
  assert.equal(fake.store.size, 0, "the two strays under the prefix are gone");
  assert.equal(probe3ClosingRow(answers).id, "final-list-again");
});

test("a final list that names only something outside the prefix removes nothing and is not read again", async () => {
  const { fake, answers } = await run({ listOnlyOutside: true });
  assert.ok(!fake.calls.some((call) => call.href.includes("storage-object%2Fother%2F")));
  assert.ok(!ids(answers).some((id) => id.startsWith("cleanup-extra-delete-")));
  assert.ok(!ids(answers).includes("final-list-again"));
  const closing = probe3ClosingRow(answers);
  assert.equal(closing.id, "final-list");
  assert.equal(closing.prefixEmpty, false);
});

test("a final list whose items are not a list does not crash the cleanup, and is not a clean row", async () => {
  for (const listItemsOdd of ["x", { name: "a" }, 5, null]) {
    const { answers } = await run({ listItemsOdd });
    const closing = probe3ClosingRow(answers);
    assert.equal(closing.id, "final-list", JSON.stringify(listItemsOdd));
    assert.equal(closing.prefixEmpty, false, JSON.stringify(listItemsOdd));
  }
});
