import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  classifyAnswer,
  compareRecordings,
  compileRecord,
  mask,
  normalizeAnswer,
  parseCreated,
  parseObjectList,
  parseRelease,
  parseRulesetList,
  renderLoads,
  renderTable,
  rowRecord,
  rowsAgree,
  sameRulesetList,
} from "./storage-rules-s9/judge.mjs";
import { PRODUCTION } from "./storage-rules-production-fixtures.mjs";

const answer = (fixture) => ({
  status: fixture.status,
  headers: { "content-type": fixture.contentType },
  body: Buffer.from(fixture.body),
});
const meta = { op: "meta", program: "s9", id: "r", plan: "allow" };
const media = { op: "media", program: "s9", id: "r", plan: "allow" };
const list = { op: "list", program: "s9", id: "r", plan: "allow" };
const releaseName =
  "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app";

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

describe("storage rules s9 judges on recorded production answers", () => {
  it("reads the recorded v0 refusals, the missing release and the missing object", () => {
    assert.equal(classifyAnswer(meta, answer(PRODUCTION.settleDenied)), "deny");
    assert.equal(classifyAnswer(meta, answer(PRODUCTION.noRelease)), "no-release");
    assert.equal(classifyAnswer(meta, answer(PRODUCTION.objectMetadataAbsent)), "not-found");
    assert.equal(classifyAnswer(media, answer(PRODUCTION.objectMediaAbsent)), "not-found");
  });

  it("reads a 200 as an allow only for the body of its operation", () => {
    const resource = answer(PRODUCTION.objectCreated);
    assert.equal(classifyAnswer(meta, resource), "allow");
    assert.equal(classifyAnswer(list, answer(PRODUCTION.objectListed)), "allow");
    assert.equal(
      classifyAnswer(media, { status: 200, headers: {}, body: Buffer.from("plain bytes") }),
      "allow",
    );
    // Near misses: a 200 with a body that is not JSON is no metadata and no list.
    assert.equal(
      classifyAnswer(meta, { status: 200, headers: {}, body: Buffer.from("plain bytes") }),
      "other",
    );
    assert.equal(
      classifyAnswer(list, { status: 200, headers: {}, body: Buffer.from("[]") }),
      "other",
    );
  });

  it("does not take a refusal of another shape for the recorded one", () => {
    const body = (value) => Buffer.from(JSON.stringify(value));
    assert.equal(
      classifyAnswer(meta, {
        status: 403,
        headers: {},
        body: body({ error: { code: 403, message: "Forbidden" } }),
      }),
      "other",
    );
    assert.equal(
      classifyAnswer(meta, {
        status: 403,
        headers: {},
        body: body({ error: { code: 401, message: "Permission denied." } }),
      }),
      "other",
    );
    assert.equal(
      classifyAnswer(meta, { status: 403, headers: {}, body: Buffer.from("Permission denied.") }),
      "other",
    );
    assert.equal(
      classifyAnswer(meta, {
        status: 400,
        headers: {},
        body: body({ error: { code: 400, message: "Bad Request" } }),
      }),
      "other",
    );
    assert.equal(classifyAnswer(meta, { status: 401, headers: {}, body: body({}) }), "other");
    assert.equal(classifyAnswer(meta, { status: 429, headers: {}, body: body({}) }), "other");
  });

  it("calls below 200, 3xx, 5xx and no answer unknown", () => {
    for (const status of [0, 100, 199, 301, 302, 304, 500, 502, 503, Number.NaN, undefined])
      assert.equal(
        classifyAnswer(meta, { status, headers: {}, body: Buffer.alloc(0) }),
        "unknown",
        `${status}`,
      );
  });

  it("parses the recorded release, ruleset list, created object and object list", () => {
    assert.deepEqual(parseRelease(answer(PRODUCTION.releasePresent), releaseName), {
      state: "present",
      rulesetName: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8",
    });
    assert.deepEqual(parseRelease(answer(PRODUCTION.releaseAbsent), releaseName), {
      state: "absent",
    });
    assert.equal(parseRelease(answer(PRODUCTION.releasePresent), `${releaseName}x`), null);
    assert.equal(parseRelease({ status: 500, body: Buffer.alloc(0) }, releaseName), null);
    assert.equal(parseRelease({ status: 404, body: Buffer.from("{}") }, releaseName), null);
    const rulesets = parseRulesetList(answer(PRODUCTION.rulesetList));
    assert.ok(Array.isArray(rulesets) && rulesets.length >= 2);
    assert.deepEqual(
      rulesets
        .map((r) => r.services)
        .flat()
        .sort()
        .slice(0, 1),
      ["cloud.firestore"],
    );
    assert.equal(sameRulesetList(rulesets, parseRulesetList(answer(PRODUCTION.rulesetList))), true);
    assert.equal(sameRulesetList(rulesets, rulesets.slice(1)), false);
    assert.equal(
      parseRulesetList({
        status: 200,
        body: Buffer.from(JSON.stringify({ rulesets: [], nextPageToken: "t" })),
      }),
      null,
    );
    assert.equal(
      parseRulesetList({
        status: 200,
        body: Buffer.from(JSON.stringify({ rulesets: [{ name: "x" }] })),
      }),
      null,
    );
    const created = parseCreated(answer(PRODUCTION.objectCreated));
    assert.equal(created.name, "STORAGE-RULES/probe-2f/object.bin");
    assert.match(created.generation, /^\d+$/);
    assert.equal(parseCreated({ status: 200, body: Buffer.from("{}") }), null);
    assert.equal(parseCreated({ status: 412, body: answer(PRODUCTION.objectCreated).body }), null);
    const listed = parseObjectList(answer(PRODUCTION.objectListed));
    assert.equal(listed.length, 1);
    assert.deepEqual(parseObjectList(answer(PRODUCTION.prefixEmpty)), []);
    assert.equal(
      parseObjectList({
        status: 200,
        body: Buffer.from(JSON.stringify({ kind: "storage#objects", nextPageToken: "t" })),
      }),
      null,
    );
    assert.equal(parseObjectList({ status: 500, body: Buffer.alloc(0) }), null);
  });

  it("records a ruleset create as loaded, refused or unread", () => {
    const masks = [["fireemu-oracle-query", "<project>"]];
    assert.deepEqual(
      compileRecord({ recording: 1, id: "a", response: answer(PRODUCTION.rulesetCreated), masks }),
      { recording: 1, id: "a", compiled: true, status: 200 },
    );
    const refused = compileRecord({
      recording: 1,
      id: "a",
      response: {
        status: 400,
        body: Buffer.from(JSON.stringify({ error: { message: "fireemu-oracle-query: bad" } })),
      },
      masks,
    });
    assert.equal(refused.compiled, false);
    assert.equal(refused.message, "<project>: bad");
    assert.equal(
      compileRecord({
        recording: 1,
        id: "a",
        response: { status: 403, body: Buffer.from("no") },
        masks,
      }).compiled,
      null,
    );
    assert.equal(
      compileRecord({
        recording: 1,
        id: "a",
        response: { status: 200, body: Buffer.from("{}") },
        masks,
      }).compiled,
      null,
    );
    // A local emulator answers a rules load with a bare 200; production never does.
    const bare = { status: 200, body: Buffer.alloc(0) };
    assert.equal(
      compileRecord({ recording: 1, id: "a", response: bare, masks, local: true }).compiled,
      true,
    );
    assert.equal(compileRecord({ recording: 1, id: "a", response: bare, masks }).compiled, null);
    assert.equal(
      compileRecord({
        recording: 1,
        id: "a",
        response: { status: 400, body: Buffer.from("{}") },
        masks,
        local: true,
      }).compiled,
      false,
    );
  });

  it("drops what differs between runs and keeps the shape", () => {
    const masks = [
      ["storage-rules-s9/sr-0123abcd/rec1", "<P>"],
      ["fireemu-oracle-query.firebasestorage.app", "<bucket>"],
    ];
    const resource = {
      kind: "storage#object",
      name: "storage-rules-s9/sr-0123abcd/rec1/pub/x",
      bucket: "fireemu-oracle-query.firebasestorage.app",
      generation: "1790000000000001",
      etag: "CAE=",
      downloadTokens: "t",
      metadata: { k: "v" },
    };
    const normalized = normalizeAnswer(
      meta,
      {
        status: 200,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify(resource)),
      },
      masks,
    );
    assert.deepEqual(normalized.resource, {
      kind: "storage#object",
      name: "<P>/pub/x",
      bucket: "<bucket>",
      metadata: { k: "v" },
    });
    const denied = normalizeAnswer(meta, answer(PRODUCTION.settleDenied), masks);
    assert.deepEqual(denied.error, { code: 403, status: null, message: "Permission denied." });
    assert.equal(denied.bodyBytes, PRODUCTION.settleDenied.body.length);
    const listing = normalizeAnswer(
      list,
      {
        status: 200,
        headers: {},
        body: Buffer.from(
          JSON.stringify({
            prefixes: ["storage-rules-s9/sr-0123abcd/rec1/pub/"],
            items: [
              { name: "storage-rules-s9/sr-0123abcd/rec1/pub/x" },
              { name: "storage-rules-s9/sr-0123abcd/rec1/pub/a" },
            ],
          }),
        ),
      },
      masks,
    );
    assert.deepEqual(listing.list.items, ["<P>/pub/a", "<P>/pub/x"]);
    assert.deepEqual(listing.list.prefixes, ["<P>/pub/"]);
    assert.equal(
      normalizeAnswer(media, { status: 200, headers: {}, body: Buffer.from("rec1") }, masks).text,
      "rec1",
    );
    assert.equal(
      mask("aXb", [
        ["X", "-"],
        ["", "!"],
      ]),
      "a-b",
    );
  });

  it("agrees across recordings on class and shape, and on layout only for refusals", () => {
    const masks = [];
    const record = (response, row = meta) =>
      rowRecord({ recording: 1, row, request: {}, response, masks });
    const deny1 = record(answer(PRODUCTION.settleDenied));
    const deny2 = record(answer(PRODUCTION.settleDenied));
    assert.equal(rowsAgree(deny1, deny2), true);
    const padded = record({
      ...answer(PRODUCTION.settleDenied),
      body: Buffer.from(`${PRODUCTION.settleDenied.body}\n`),
    });
    assert.equal(
      rowsAgree(deny1, padded),
      false,
      "a refusal that grew by one byte is a different layout",
    );
    const allowA = record({
      status: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ name: "x", generation: "1" })),
    });
    const allowB = record({
      status: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ name: "x", generation: "12345" })),
    });
    assert.equal(rowsAgree(allowA, allowB), true, "digits of a generation do not matter");
    const allowC = record({
      status: 200,
      headers: {},
      body: Buffer.from(JSON.stringify({ name: "y", generation: "1" })),
    });
    assert.equal(rowsAgree(allowA, allowC), false);
    assert.equal(rowsAgree(allowA, deny1), false);
    const a = [
      { ...deny1, id: "one" },
      { ...allowA, id: "two" },
    ];
    const b = [
      { ...deny2, id: "one" },
      { ...allowC, id: "two" },
    ];
    assert.deepEqual(
      compareRecordings(a, b).map((r) => r.agree),
      [true, false],
    );
    assert.deepEqual(
      compareRecordings(a, b.slice(0, 1)).map((r) => r.agree),
      [true, false],
      "a row missing from the second recording disagrees",
    );
  });

  it("renders one line per row with a star for a recording that disagrees", () => {
    const rowFor = (id, response, recording = 1) =>
      rowRecord({ recording, row: { ...meta, id }, request: {}, response, masks: [] });
    const denied = answer(PRODUCTION.settleDenied);
    const ok = { status: 200, headers: {}, body: Buffer.from("{}") };
    const production = {
      label: "production",
      rows: [rowFor("a", denied), rowFor("a", ok, 2), rowFor("b", ok)],
      loads: [{ id: "l", compiled: true, status: 200 }],
    };
    const emulator = {
      label: "emulator",
      rows: [rowFor("a", denied), rowFor("a", denied, 2)],
      loads: [{ id: "l", compiled: false, status: 400 }],
    };
    const table = renderTable([production, emulator]).split("\n");
    assert.equal(table[0], "row\tplan\tproduction\temulator");
    assert.equal(table[1], "a\tallow\tdeny/403*\t=", "the emulator agrees with the first cell");
    assert.equal(table[2], "b\tallow\tallow/200\t-");
    const loads = renderLoads([production, emulator]).split("\n");
    assert.equal(loads[1], "l\tloads/200\trefused/400");
  });

  it("holds its invariants over random answers (seeded)", () => {
    const next = prng(20261108);
    const statuses = [
      0,
      100,
      199,
      200,
      201,
      204,
      301,
      400,
      401,
      403,
      404,
      409,
      412,
      429,
      500,
      503,
      Number.NaN,
    ];
    const bodies = [
      Buffer.alloc(0),
      Buffer.from("{}"),
      Buffer.from("[]"),
      Buffer.from("text"),
      answer(PRODUCTION.settleDenied).body,
      answer(PRODUCTION.noRelease).body,
      answer(PRODUCTION.objectCreated).body,
    ];
    const rows = [meta, media, list];
    for (let i = 0; i < 2000; i += 1) {
      const response = {
        status: statuses[Math.floor(next() * statuses.length)],
        headers: {},
        body: bodies[Math.floor(next() * bodies.length)],
      };
      const row = rows[Math.floor(next() * rows.length)];
      const cls = classifyAnswer(row, response);
      // Never an allow or a refusal unless the status says so.
      if (cls === "allow") assert.equal(response.status, 200);
      if (cls === "deny") assert.equal(response.status, 403);
      if (cls === "no-release") assert.equal(response.status, 400);
      if (cls === "not-found") assert.equal(response.status, 404);
      if (response.status >= 500 || response.status < 200 || Number.isNaN(response.status))
        assert.equal(cls, "unknown");
      const record = rowRecord({ recording: 1, row, request: {}, response, masks: [] });
      assert.equal(rowsAgree(record, record), true);
      assert.equal(record.class, cls);
    }
  });
});
