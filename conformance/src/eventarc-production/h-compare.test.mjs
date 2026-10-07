import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { compareDelivery, compareDeclaredAnswer, loadHRecording, replayH } from "./h-compare.mjs";

const native = JSON.parse(
  readFileSync(new URL("./fixtures/h-fe/h-readiness.json", import.meta.url)),
);
const object = native.find((r) => r.run === "H1-v5" && r.case === "object");
const frames = object.handlerFrames;
const observation = {
  case: "object",
  known: true,
  status: 200,
  body: { events: frames.map(({ frame }) => ({ id: frame.event.id, source: frame.event.source })) },
};
const capture = { complete: true, finalRead: true, frames };

test("H replay refuses a remote HTTP origin before invoking transport", async () => {
  await assert.rejects(
    replayH(
      {},
      {
        base: "http://example.org:9999",
        fetchImpl: () => {
          throw Error("must not send");
        },
      },
    ),
    /loopback/,
  );
});

test("H1 native frames compare generated tracing and member order by their declared classes", () => {
  const local = structuredClone(frames);
  for (const { frame } of local) {
    frame.event.traceparent = "00-" + "1".repeat(32) + "-" + "2".repeat(16) + "-01";
    frame.event = Object.fromEntries(Object.entries(frame.event).reverse());
    frame.eventKeys = Object.keys(frame.event);
  }
  const result = compareDelivery(observation, capture, { ...capture, frames: local });
  assert.equal(result.verdict, "MATCH");
  assert.ok(result.declaredDifferences.includes("generated-traceparent"));
  assert.ok(result.declaredDifferences.includes("cloudevent-member-order"));
  for (const mutation of ["trace", "keys", "data", "correlation", "handler"]) {
    const bad = structuredClone(local);
    const f = bad[0].frame;
    if (mutation === "trace") delete f.event.traceparent;
    if (mutation === "keys") f.eventKeys.pop();
    if (mutation === "data") f.event.data = { a: 2 };
    if (mutation === "correlation") f.correlation.id = "other";
    if (mutation === "handler") f.handler = "other";
    assert.equal(
      compareDelivery(observation, capture, { ...capture, frames: bad }).verdict,
      "DIVERGES",
      mutation,
    );
  }
});

test("unbracketed absence and incomplete captures cannot establish delivery equality", () => {
  assert.equal(
    compareDelivery(observation, { ...capture, frames: [] }, capture).verdict,
    "NOT_COMPARABLE",
  );
  assert.equal(
    compareDelivery(observation, capture, { ...capture, finalRead: false }).verdict,
    "NOT_COMPARABLE",
  );
  const refused = {
    ...observation,
    refused: true,
    before: true,
    after: true,
    windowMs: 120000,
    sentAt: 0,
    endedAt: 120000,
  };
  assert.equal(
    compareDelivery(refused, { ...capture, frames: [] }, { ...capture, frames: [] }).verdict,
    "NOT_COMPARABLE",
    "controls must be observed",
  );
});

test("declared channel order retains membership, cardinality and envelope", () => {
  const row = {
    op: "listChannels",
    request: { path: "/v1/projects/demo-h/locations/us-central1/channels" },
    response: { status: 200, body: { channels: [{ name: "a" }, { name: "b" }] } },
  };
  assert.equal(
    compareDeclaredAnswer(row, { status: 200, body: { channels: [{ name: "b" }, { name: "a" }] } })
      .verdict,
    "MATCH",
  );
  for (const channels of [
    [{ name: "a" }],
    [{ name: "a" }, { name: "a" }],
    [{ name: "a" }, { name: "c" }],
  ])
    assert.equal(
      compareDeclaredAnswer(row, { status: 200, body: { channels } }).verdict,
      "DIVERGES",
    );
  assert.equal(
    compareDeclaredAnswer(row, {
      status: 200,
      body: { channels: row.response.body.channels, extra: true },
    }).verdict,
    "DIVERGES",
  );
  const auth = { ...row, tokenMode: "expired", response: { status: 401, body: {} } };
  assert.equal(compareDeclaredAnswer(auth, { status: 200, body: {} }).verdict, "NOT_COMPARABLE");
  assert.equal(
    compareDeclaredAnswer({ ...auth, tokenMode: "none" }, { status: 200, body: {} }).verdict,
    "DIVERGES",
  );
});

const recordings = process.env.EVENTARC_RECORDINGS_ROOT;
test(
  "closed H1 v5 journals replay all actual SDK bodies and preserve the two delivery gaps",
  { skip: !recordings },
  async () => {
    const h = loadHRecording(join(recordings, "eventarc-packet-h-20261006-h1v5"));
    assert.equal(h.production.closed, true);
    assert.equal(h.observations.length, 48);
    assert.equal(h.capture.frames.length, 69);
    const sent = [];
    const result = await replayH(h, {
      base: "http://127.0.0.1:9999",
      fetchImpl: async (url, init) => {
        sent.push(JSON.parse(init.body));
        const row = h.publications[sent.length - 1];
        return new Response(JSON.stringify(row.response.body), { status: row.response.status });
      },
      localCapture: h.capture,
    });
    assert.equal(sent.length, 48);
    assert.deepEqual(
      sent,
      h.publications.map((r) => r.request.body),
    );
    assert.deepEqual(result.counts, { MATCH: 46, DIVERGES: 0, NOT_COMPARABLE: 2 });
    assert.deepEqual(
      result.rows.filter((r) => r.verdict === "NOT_COMPARABLE").map((r) => r.case),
      ["scalar", "null"],
    );
    await assert.rejects(
      replayH(h, {
        base: "https://eventarcpublishing.googleapis.com",
        fetchImpl: () => {
          throw Error("must not send");
        },
      }),
      /loopback/,
    );
  },
);
