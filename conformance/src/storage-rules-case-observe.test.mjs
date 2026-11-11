import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { observe, readback } from "./storage-rules-s9/observe.mjs";
import { CANDIDATES, CASE_PLAN, CASE_ROWS } from "./storage-rules-s9/plan-case.mjs";
import { readCase } from "./storage-rules-s9/reading.mjs";
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const project = "fireemu-oracle-query";
const bucket = "fireemu-oracle-query.firebasestorage.app";
const runId = "sr-0123abcd";
const baselineName = `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`;
const target = { name: "production", bucket, project };
const owner = { authorization: "Bearer t", "x-goog-user-project": project };
const memoryOut = () => {
  const saved = {};
  return { saved, journal() {}, save: (name, data) => (saved[name] = data) };
};
const noSleep = async () => {};
const urlOf = (call) => new URL(call.url);

async function run({ baseline = baselineName, candidate = "ascii", faults = [], recordings } = {}) {
  const fake = createWorld({
    plan: CASE_PLAN,
    project,
    bucket,
    baseline: baseline === "absent" ? null : baseline,
    lag: 0,
    faults,
    allow: (row) => row.candidates[candidate],
  });
  const out = memoryOut();
  const { report } = await observe({
    plan: CASE_PLAN,
    target,
    runId,
    baseline,
    deps: { net: fake.net, adminHeaders: () => owner, sleep: noSleep },
    out,
    recordings,
  });
  return { ...fake, report, out };
}

describe("the case family in the fake world", () => {
  it("runs both recordings with one ruleset, leaves the sandbox as it found it, and reads the planned class on every row", async () => {
    const { report, world } = await run();
    assert.equal(report.stopped, null);
    assert.equal(report.mode, "record");
    assert.equal(report.plan, "case");
    assert.equal(report.complete, true);
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(report.requests, CASE_PLAN.expectedRequests(2));
    assert.equal(report.rows.length, CASE_ROWS.length * 2);
    assert.deepEqual(report.loads, []);
    assert.equal(report.publications.filter((p) => p.program).length, 2);
    assert.equal(world.objects.size, 0);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.deepEqual([...world.rulesets.keys()].toSorted(), [
      `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`,
      `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
    ]);
    assert.equal(world.sources.length, 2);
  });

  for (const candidate of CANDIDATES) {
    it(`gives a run whose answers are ${candidate}'s the verdict ${candidate}`, async () => {
      const { report } = await run({ candidate });
      assert.equal(readCase(report.rows, CASE_PLAN).verdict, candidate);
    });
  }

  it("publishes by POST and restores by DELETE when the bucket has no release at entry", async () => {
    const { report, world } = await run({ baseline: "absent" });
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(world.release, null);
    const methods = world.calls
      .filter((c) => urlOf(c).pathname.includes("/releases"))
      .map((c) => `${c.method} ${urlOf(c).pathname.split("/releases")[1]}`);
    assert.ok(methods.includes("POST "));
    assert.ok(methods.includes(`DELETE /firebase.storage/${bucket}`));
  });

  it("sends the probes as UTF-8 and nothing normalized: the rule source raw, object names percent-encoded", async () => {
    const { world } = await run({ recordings: 1 });
    const source = world.sources[0];
    const bytes = Buffer.from(source, "utf8");
    assert.ok(source.includes("'É'.lower()"));
    // E + combining acute stays two characters; the composed letter is a different probe.
    assert.ok(
      bytes.includes(Buffer.from([0x27, 0x65, 0xcc, 0x81, 0x27, 0x2e, 0x75])),
      "decomposed e",
    );
    assert.ok(bytes.includes(Buffer.from([0xf0, 0x9f, 0x94, 0xa5])), "fire");
    const sent = world.calls.filter((c) => c.method === "POST" && c.url.includes("/rulesets"));
    assert.equal(sent.length, 1);
    const content = JSON.parse(Buffer.from(sent[0].body).toString("utf8")).source.files[0].content;
    assert.equal(content, source);
    assert.ok(!content.includes("\\u"));
    const creates = world.calls.filter((c) => c.url.includes("/upload/storage/"));
    assert.equal(creates.length, Object.keys(CASE_PLAN.objects).length);
    const names = creates.map((c) => new URL(c.url).searchParams.get("name"));
    assert.ok(names.some((n) => n.endsWith("/rt-lower-same/É")));
    assert.ok(
      creates.every((c) => !/[^\x20-\x7e]/.test(c.url)),
      "every URL is ASCII (percent-encoded)",
    );
    assert.ok(creates.some((c) => c.url.includes("%C3%89")));
  });

  it("marks every row not evaluated and still cleans up when the ruleset does not compile", async () => {
    const { report, world } = await run({
      faults: [
        {
          match: (r) => r.method === "POST" && r.path.endsWith("/rulesets"),
          answer: {
            status: 400,
            headers: { "content-type": "application/json" },
            body: Buffer.from('{"error":{"code":400,"message":"x","status":"INVALID_ARGUMENT"}}'),
          },
        },
      ],
    });
    assert.equal(world.objects.size, 0);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.ok(report.rows.some((r) => r.class === "not-evaluated"));
    assert.equal(readCase(report.rows, CASE_PLAN).verdict, "incomplete");
    assert.ok(report.loads.some((l) => l.compiled === false));
  });

  it("refuses a request outside its own prefix, and the s9 prefix is not its own", async () => {
    const { classifyRequest } = await import("./storage-rules-s9/guard.mjs");
    const state = {
      runId,
      root: CASE_PLAN.runRoot(runId),
      prefixRoot: CASE_PLAN.prefixRoot,
      ownRulesets: new Set(),
      baseline: baselineName,
    };
    const get = (name) => ({
      method: "GET",
      url: `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(name)}`,
    });
    assert.equal(
      classifyRequest(target, get(`${CASE_PLAN.runRoot(runId)}rec1/mk/a`), state),
      "v0-meta",
    );
    assert.throws(
      () => classifyRequest(target, get(`storage-rules-s9/${runId}/rec1/mk/a`), state),
      /outside the run root/,
    );
    assert.throws(
      () => classifyRequest(target, get("other/x"), { ...state, root: "other/" }),
      /bad run root/,
    );
  });

  it("reads back with a cap that covers every planned name, and closes only when everything is absent", async () => {
    const fake = createWorld({ plan: CASE_PLAN, project, bucket, baseline: baselineName, lag: 0 });
    const entry = [
      {
        name: `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`,
        services: ["firebase.storage"],
      },
      {
        name: `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
        services: ["cloud.firestore"],
      },
    ];
    const out = memoryOut();
    const report = await readback({
      plan: CASE_PLAN,
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net: fake.net, adminHeaders: () => owner },
      out,
    });
    assert.equal(report.closed, true, JSON.stringify(report.problems));
    assert.equal(report.requests, 2 + 2 + 2 * Object.keys(CASE_PLAN.objects).length);
    assert.ok(report.requests <= CASE_PLAN.readbackCap(2));
  });
});

describe("a recording that cannot put the release back (S9 review SF2)", () => {
  const refuseFirstBaselinePatch = () => {
    let refused = false;
    return {
      match: (r) =>
        !refused &&
        r.method === "PATCH" &&
        r.path.includes("/releases/") &&
        Buffer.from(r.body ?? [])
          .toString("utf8")
          .includes(baselineName) &&
        (refused = true),
      answer: {
        status: 400,
        headers: { "content-type": "application/json" },
        body: Buffer.from('{"error":{"code":400,"message":"refused","status":"INVALID_ARGUMENT"}}'),
      },
    };
  };

  it("does not start the second recording, restores in the cleanup, and does not close", async () => {
    const { report, world } = await run({ faults: [refuseFirstBaselinePatch()] });
    assert.match(report.stopped, /rec1\/restore/);
    assert.equal(report.closureReady, false);
    assert.equal(report.complete, false);
    assert.equal(world.sources.length, 1, "only the first recording's ruleset was created");
    assert.deepEqual(world.release, { rulesetName: baselineName }, "the cleanup put it back");
    assert.equal(world.objects.size, 0);
    assert.equal(report.rows.filter((r) => r.recording === 2).length, 0);
    const toBaseline = world.calls.filter(
      (c) =>
        c.method === "PATCH" &&
        Buffer.from(c.body ?? [])
          .toString("utf8")
          .includes(baselineName),
    );
    assert.equal(toBaseline.length, 2, "refused once in the recording, once more in the cleanup");
  });

  it("goes on to the second recording when the restore reads back as the baseline", async () => {
    const { report } = await run();
    assert.equal(report.rows.filter((r) => r.recording === 2).length, CASE_ROWS.length);
  });
});
