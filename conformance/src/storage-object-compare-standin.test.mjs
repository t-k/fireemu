// The rehearsal stand-in answers only a PUT that fireemu answers 501 to, in the recorded production
// shape, and marks its answer. These tests run it as a `--import` preload in a child process
// against a small fake fireemu.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { tempDir } from "./test-tmpdir.mjs";

const STANDIN = fileURLToPath(
  new URL("./storage-object-compare/rehearsal-standin.mjs", import.meta.url),
);
const RECORDED_KEYS = [
  "bucket",
  "contentType",
  "crc32c",
  "etag",
  "generation",
  "id",
  "kind",
  "md5Hash",
  "mediaLink",
  "metadata",
  "metageneration",
  "name",
  "selfLink",
  "size",
  "storageClass",
  "timeCreated",
  "timeFinalized",
  "timeStorageClassUpdated",
  "updated",
];

function fixtureDirectory({ withPut = true } = {}) {
  const directory = tempDir("compare-standin-");
  const exchange = {
    n: 1,
    method: "PUT",
    route: "PUT /storage/v1/b/<BUCKET>/o/<NAME>",
    status: 200,
    body: { type: "json", value: Object.fromEntries(RECORDED_KEYS.map((key) => [key, "x"])) },
  };
  writeFileSync(
    join(directory, "index.json"),
    JSON.stringify({ recipes: [{ recipeId: "storage-object/gcs/a", file: "a.json" }] }),
  );
  const body = (value) => ({ type: "json", value });
  // Rows that look like the PUT but are not: another method, another route, another status, another body type.
  const decoys = [
    {
      ...exchange,
      method: "GET",
      route: "GET /storage/v1/b/<BUCKET>/o/<NAME>",
      body: body({ decoy: "get" }),
    },
    { ...exchange, route: "PUT /v0/b/<BUCKET>/o/<NAME>", body: body({ decoy: "route" }) },
    { ...exchange, status: 404, body: body({ decoy: "status" }) },
    { ...exchange, body: { type: "text", value: "decoy" } },
  ];
  writeFileSync(
    join(directory, "a.json"),
    JSON.stringify({ exchanges: withPut ? [...decoys, exchange] : decoys }),
  );
  return directory;
}

/** A fake fireemu: one object, GET and PATCH (short spelling only unless `longPatch`), PUT is 501 unless `servePut`. */
function fakeFireemu({ longPatch = false, servePut = false, metageneration = "1" } = {}) {
  const log = [];
  let object = {
    kind: "storage#object",
    bucket: "b",
    name: "o/a.bin",
    generation: "1000",
    metageneration,
    contentType: "application/octet-stream",
    storageClass: "STANDARD",
    size: "5",
    md5Hash: "m",
    crc32c: "c",
    etag: "e",
    timeCreated: "t",
    updated: "t",
    timeStorageClassUpdated: "t",
    metadata: { keep: "1", drop: "2" },
  };
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      log.push({ method: request.method, url: request.url, body });
      const send = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(value === undefined ? undefined : JSON.stringify(value));
      };
      const path = request.url.split("?")[0];
      if (request.method === "PUT") return servePut ? send(200, { served: true }) : send(501);
      if (path === "/storage/v1/b/b/o/o%2Fmissing.bin" || path === "/b/b/o/o%2Fmissing.bin")
        return send(404, { error: { code: 404 } });
      if (request.method === "GET") return send(200, object);
      if (request.method === "PATCH") {
        if (path.startsWith("/storage/v1/") && !longPatch) return send(501);
        const patch = JSON.parse(body);
        const metadata = { ...object.metadata };
        for (const [key, value] of Object.entries(patch.metadata ?? {}))
          if (value === null) delete metadata[key];
          else metadata[key] = value;
        object = {
          ...object,
          ...(patch.contentType ? { contentType: patch.contentType } : {}),
          metadata,
          metageneration: String(Number(object.metageneration) + 1),
        };
        return send(200, object);
      }
      return send(400);
    });
  });
  return { server, log };
}

async function run({ fireemu, fixture, requests }) {
  await new Promise((resolve) => fireemu.server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${fireemu.server.address().port}`;
  const script = `
    const origin = ${JSON.stringify(origin)};
    const out = [];
    for (const [method, path, body, base] of ${JSON.stringify(requests)}) {
      const response = await fetch((base ?? origin) + path, { method, headers: { "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      out.push({ status: response.status, standin: response.headers.get("x-compare-standin"), contentType: response.headers.get("content-type"), text: await response.text() });
    }
    console.log(JSON.stringify(out));`;
  const child = spawn(
    process.execPath,
    ["--import", STANDIN, "--input-type=module", "--eval", script],
    {
      env: {
        ...process.env,
        STANDIN_STORAGE_ORIGIN: origin,
        ...(fixture ? { STANDIN_FIXTURE: fixture } : {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const code = await new Promise((resolve) => child.on("close", resolve));
  await new Promise((resolve) => fireemu.server.close(resolve));
  return {
    code,
    stderr,
    results: code === 0 ? JSON.parse(stdout.trim().split("\n").at(-1)) : null,
  };
}

const PUT_URL = "/storage/v1/b/b/o/o%2Fa.bin";

test("a PUT fireemu answers 501 to is answered in the recorded shape, marked, and applied as a PATCH that nulls the keys the body lacks", async () => {
  const fireemu = fakeFireemu();
  const { code, stderr, results } = await run({
    fireemu,
    fixture: fixtureDirectory(),
    requests: [
      [
        "PUT",
        `${PUT_URL}?ifGenerationMatch=1000&ifMetagenerationMatch=1`,
        { contentType: "text/plain", metadata: { keep: "9" } },
      ],
    ],
  });
  assert.equal(code, 0, stderr);
  const [answer] = results;
  assert.equal(answer.status, 200);
  assert.equal(answer.standin, "1");
  assert.equal(answer.contentType, "application/json; charset=UTF-8");
  const body = JSON.parse(answer.text);
  assert.deepEqual(Object.keys(body).toSorted(), RECORDED_KEYS);
  assert.equal(body.metageneration, "2");
  assert.deepEqual(body.metadata, { keep: "9" });
  assert.equal(body.contentType, "text/plain");
  assert.equal(
    body.timeFinalized,
    "t",
    "a key fireemu lacks is filled from the object's creation time",
  );
  assert.equal(body.id, "b/o/a.bin/1000");
  assert.match(body.mediaLink, /alt=media$/);
  const patch = fireemu.log.find(
    (entry) => entry.method === "PATCH" && !entry.url.startsWith("/storage/v1/"),
  );
  assert.deepEqual(JSON.parse(patch.body), {
    contentType: "text/plain",
    metadata: { keep: "9", drop: null },
  });
  // The PUT was tried first, and the long PATCH before the short one.
  assert.deepEqual(
    fireemu.log.map((entry) => entry.method),
    ["PUT", "GET", "PATCH", "PATCH"],
  );
  assert.ok(fireemu.log[2].url.startsWith("/storage/v1/"));
});

test("when fireemu serves the PATCH on the long spelling, the stand-in uses it", async () => {
  const fireemu = fakeFireemu({ longPatch: true });
  const { results } = await run({
    fireemu,
    fixture: fixtureDirectory(),
    requests: [["PUT", PUT_URL, { metadata: {} }]],
  });
  assert.equal(results[0].status, 200);
  assert.deepEqual(
    fireemu.log.map((entry) => entry.method),
    ["PUT", "GET", "PATCH"],
  );
});

test("a metadata that ends up empty has no metadata member", async () => {
  const fireemu = fakeFireemu();
  const { results } = await run({
    fireemu,
    fixture: fixtureDirectory(),
    requests: [["PUT", PUT_URL, { metadata: {} }]],
  });
  assert.equal("metadata" in JSON.parse(results[0].text), false);
});

test("the guards are evaluated as production does: 304 for not-match naming the current value, 412 for a match that does not hold, 400 for a malformed value", async () => {
  const fireemu = fakeFireemu();
  const { results } = await run({
    fireemu,
    fixture: fixtureDirectory(),
    requests: [
      ["PUT", `${PUT_URL}?ifGenerationNotMatch=1000`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationNotMatch=1`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifGenerationMatch=999`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationMatch=7`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationMatch=-1`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationNotMatch=-1`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationMatch=`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationMatch=1.5`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifMetagenerationNotMatch=abc`, { metadata: {} }],
      ["PUT", `${PUT_URL}?ifGenerationNotMatch=999`, { metadata: {} }],
    ],
  });
  assert.deepEqual(
    results.map((row) => row.status),
    [304, 304, 412, 412, 412, 200, 400, 400, 400, 200],
  );
  for (const row of results) assert.equal(row.standin, "1");
  assert.equal(results[0].text, "");
  assert.equal(JSON.parse(results[2].text).error.errors[0].reason, "conditionNotMet");
  assert.equal(JSON.parse(results[4].text).error.errors[0].reason, "conditionNotMet");
  assert.equal(JSON.parse(results[6].text).error.errors[0].reason, "invalid");
  // Only the accepted ones changed the object: -1 is a number that matches nothing, so the not-match
  // guard holds and the update is applied; the last request then applies a second one.
  assert.equal(JSON.parse(results[5].text).metageneration, "2");
  assert.equal(JSON.parse(results[9].text).metageneration, "3");
});

test("a PUT to an object that does not exist is the 404 fireemu gives, marked", async () => {
  const { results } = await run({
    fireemu: fakeFireemu(),
    fixture: fixtureDirectory(),
    requests: [["PUT", "/storage/v1/b/b/o/o%2Fmissing.bin", { metadata: {} }]],
  });
  assert.equal(results[0].status, 404);
  assert.equal(results[0].standin, "1");
});

test("a PUT fireemu serves is not replaced, and is not marked", async () => {
  const { results } = await run({
    fireemu: fakeFireemu({ servePut: true }),
    fixture: fixtureDirectory(),
    requests: [["PUT", PUT_URL, { metadata: {} }]],
  });
  assert.equal(results[0].status, 200);
  assert.equal(results[0].standin, null);
  assert.deepEqual(JSON.parse(results[0].text), { served: true });
});

test("everything else goes through untouched: other methods, other spellings, other origins", async () => {
  const fireemu = fakeFireemu();
  const other = fakeFireemu();
  await new Promise((resolve) => other.server.listen(0, "127.0.0.1", resolve));
  const otherOrigin = `http://127.0.0.1:${other.server.address().port}`;
  const { results } = await run({
    fireemu,
    fixture: fixtureDirectory(),
    requests: [
      ["GET", PUT_URL],
      ["PUT", "/b/b/o/o%2Fa.bin", { metadata: {} }],
      ["PUT", "/upload/storage/v1/b/b/o", { metadata: {} }],
      ["POST", PUT_URL, {}],
      ["PUT", PUT_URL, { metadata: {} }, otherOrigin],
    ],
  });
  assert.deepEqual(
    results.map((row) => [row.status, row.standin]),
    [
      [200, null],
      [501, null],
      [501, null],
      [400, null],
      [501, null],
    ],
  );
  assert.equal(other.log.length, 1, "the other origin got the request itself");
  await new Promise((resolve) => other.server.close(resolve));
});

test("without its environment the stand-in does nothing, and a fixture without an accepted PUT is refused", async () => {
  const { results } = await run({
    fireemu: fakeFireemu(),
    requests: [["PUT", PUT_URL, { metadata: {} }]],
  });
  assert.equal(results[0].status, 501);
  assert.equal(results[0].standin, null);
  const refused = await run({
    fireemu: fakeFireemu(),
    fixture: fixtureDirectory({ withPut: false }),
    requests: [],
  });
  assert.notEqual(refused.code, 0);
  assert.match(refused.stderr, /no accepted PUT/);
});

test("the stand-in takes a URL object or a Request as well as a string", async () => {
  const fireemu = fakeFireemu();
  await new Promise((resolve) => fireemu.server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${fireemu.server.address().port}`;
  const script = `
    const origin = ${JSON.stringify(origin)};
    const asUrl = await fetch(new URL(origin + ${JSON.stringify(PUT_URL)}), { method: "PUT", body: "{}" });
    const asRequest = await fetch(new Request(origin + ${JSON.stringify(PUT_URL)}, { method: "PUT", body: "{}" }));
    console.log(JSON.stringify([asUrl.status, asUrl.headers.get("x-compare-standin"), asRequest.status]));`;
  const child = spawn(
    process.execPath,
    ["--import", STANDIN, "--input-type=module", "--eval", script],
    {
      env: { ...process.env, STANDIN_STORAGE_ORIGIN: origin, STANDIN_FIXTURE: fixtureDirectory() },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  await new Promise((resolve) => child.on("close", resolve));
  await new Promise((resolve) => fireemu.server.close(resolve));
  const [urlStatus, urlMarked] = JSON.parse(stdout.trim().split("\n").at(-1));
  assert.equal(urlStatus, 200);
  assert.equal(urlMarked, "1");
});

// ---- the stand-in against production's own rows ---------------------------------------------------

test("for every PUT the fixture records in gcs/metageneration-preconditions, the stand-in answers the recorded status", async () => {
  const rows = JSON.parse(
    readFileSync(
      fileURLToPath(
        new URL(
          "../fixtures/storage-object-production/gcs--metageneration-preconditions.json",
          import.meta.url,
        ),
      ),
      "utf8",
    ),
  ).exchanges.filter(
    (row) =>
      row.method === "PUT" &&
      row.query.some(
        ([key]) => key === "ifMetagenerationMatch" || key === "ifMetagenerationNotMatch",
      ),
  );
  assert.ok(rows.length >= 12);
  const cases = [];
  for (const row of rows) {
    const [key, value] = row.query.find(
      ([name]) => name === "ifMetagenerationMatch" || name === "ifMetagenerationNotMatch",
    );
    // The object's metageneration that makes the guard behave as production's recorded status says.
    const holds =
      (key === "ifMetagenerationMatch" && row.status === 200) ||
      (key === "ifMetagenerationNotMatch" && row.status === 304);
    const current = holds ? value : value === "5" ? "6" : "5";
    cases.push({ row, key, value, current });
  }
  for (const { row, key, value, current } of cases) {
    const fireemu = fakeFireemu({ metageneration: current });
    const { results } = await run({
      fireemu,
      fixture: fixtureDirectory(),
      requests: [
        [
          "PUT",
          `${PUT_URL}?ifGenerationMatch=1000&${key}=${encodeURIComponent(value)}`,
          { metadata: { x: "1" } },
        ],
      ],
    });
    assert.equal(results[0].status, row.status, `#${row.n} ${key}=${JSON.stringify(value)}`);
  }
  // The two the review named.
  assert.ok(
    cases.some(
      ({ row, key, value }) =>
        row.status === 412 && key === "ifMetagenerationMatch" && value === "-1",
    ),
  );
  assert.ok(
    cases.some(
      ({ row, key, value }) =>
        row.status === 200 && key === "ifMetagenerationNotMatch" && value === "-1",
    ),
  );
});
