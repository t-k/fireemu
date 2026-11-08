import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { observe, readback } from "./storage-rules-s9/observe.mjs";
import {
  LOCAL_BUCKET,
  OBJECTS,
  PROGRAMS,
  ROWS,
  SETTLE_MAX_POLLS,
  expectedRequests,
  objectName,
  recordingPrefix,
} from "./storage-rules-s9/plan.mjs";
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const project = "fireemu-oracle-query";
const bucket = "fireemu-oracle-query.firebasestorage.app";
const runId = "sr-0123abcd";
const baselineName = `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`;
const target = { name: "production", bucket, project };
const P1 = recordingPrefix(runId, 1);
const P2 = recordingPrefix(runId, 2);
const owner = { authorization: "Bearer t", "x-goog-user-project": project };
const memoryOut = () => {
  const saved = {};
  return { saved, journal() {}, save: (name, data) => (saved[name] = data) };
};
const noSleep = async () => {};

async function run({
  baseline = baselineName,
  lag = 0,
  faults = [],
  allow,
  refuseNames,
  recordings,
  rowFilter,
  caps,
} = {}) {
  const fake = createWorld({
    project,
    bucket,
    baseline: baseline === "absent" ? null : baseline,
    lag,
    faults,
    allow,
    refuseNames,
  });
  const out = memoryOut();
  const { report } = await observe({
    target,
    runId,
    baseline,
    deps: { net: fake.net, adminHeaders: () => owner, sleep: noSleep },
    out,
    recordings,
    rowFilter,
    caps,
  });
  return { ...fake, report, out };
}

const urlOf = (call) => new URL(call.url);
const on = (method, test) => ({ match: (req) => req.method === method && test(req) });

describe("storage rules s9 observation in the fake world", () => {
  it("runs both recordings, leaves the sandbox as it found it, and reads the planned class on every row", async () => {
    const { report, world } = await run();
    assert.equal(report.stopped, null);
    assert.equal(report.complete, true);
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(report.requests, expectedRequests());
    assert.equal(report.rows.length, ROWS.length * 2);
    assert.equal(report.loads.filter((l) => l.stage === "load-only").length, 6);
    assert.ok(report.loads.every((l) => l.compiled === true));
    for (const row of report.rows)
      assert.equal(
        row.class,
        row.plan === "allow" ? "allow" : "deny",
        `${row.recording}/${row.id}`,
      );
    assert.deepEqual(report.disagreeing, []);
    assert.equal(world.objects.size, 0);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.deepEqual([...world.rulesets.keys()].sort(), [
      `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`,
      `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
    ]);
    assert.equal(report.publications.filter((p) => p.program).length, 6);
  });

  it("publishes by POST and restores by DELETE when the bucket has no release at entry", async () => {
    const { report, world } = await run({ baseline: "absent" });
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(world.release, null);
    const methods = world.calls
      .filter((c) => urlOf(c).pathname.includes("/releases"))
      .map((c) => `${c.method} ${urlOf(c).pathname.split("/releases")[1]}`);
    assert.ok(methods.includes("POST "));
    assert.ok(methods.includes("DELETE /firebase.storage/" + bucket));
    // After the first POST the release exists, so the next program patches it.
    assert.ok(methods.includes("PATCH /firebase.storage/" + bucket));
    assert.equal(report.requests, expectedRequests() + 0);
  });

  it("waits out a release that reaches the serving plane late, and counts the polls", async () => {
    const { report } = await run({ lag: 5 });
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.ok(report.requests > expectedRequests());
    assert.ok(report.publications.some((p) => p.polls > 3));
    assert.ok(report.publications.some((p) => p.restoreSettlePolls > 3));
  });

  it("stops, restores and cleans up when a release never settles", async () => {
    const { report, world } = await run({ lag: 100000 });
    assert.match(report.stopped, /did not settle/);
    assert.equal(report.closureReady, false);
    assert.equal(world.objects.size, 0);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.ok(report.requests < 600);
    assert.ok(
      world.calls.filter((c) => c.method === "GET" && urlOf(c).pathname.includes("/v0/")).length >=
        SETTLE_MAX_POLLS,
    );
  });

  it("stops before the first program when a marker is readable at setup", async () => {
    const { report, world } = await run({
      baseline: baselineName,
      faults: [
        on(
          "GET",
          (r) =>
            r.url.pathname.includes("/v0/") && r.url.pathname.includes(encodeURIComponent("/mk/b")),
        ),
      ].map((f) => ({ ...f, answer: { status: 200, headers: {}, body: Buffer.from("{}") } })),
    });
    assert.match(report.stopped, /marker mkB is readable before its program/);
    assert.equal(world.objects.size, 0);
    assert.equal(report.rows.length, 0);
    assert.equal(report.closureReady, false);
  });

  it("keeps an unknown create out of the retry path and finds the object by listing", async () => {
    const lost = {
      ...on(
        "POST",
        (r) =>
          r.url.pathname.startsWith("/upload/") &&
          r.url.searchParams.get("name") === objectName("pubInterior", P1),
      ),
      afterReal: true,
      answer: "transport",
    };
    const { report, world } = await run({ faults: [lost] });
    assert.deepEqual(report.unknowns, ["create/pubInterior"]);
    assert.equal(report.closureReady, false);
    assert.equal(world.objects.size, 0, "the cleanup list found it and deleted it");
    assert.equal(
      world.calls.filter(
        (c) =>
          c.method === "POST" &&
          urlOf(c).searchParams.get("name") === objectName("pubInterior", P1),
      ).length,
      1,
      "sent once",
    );
  });

  it("never retries a ruleset create whose answer is unknown", async () => {
    const lost = {
      ...on("POST", (r) => r.url.pathname.endsWith("/rulesets")),
      answer: { status: 503, headers: {}, body: Buffer.from("{}") },
    };
    const { report, world } = await run({ faults: [lost] });
    assert.equal(report.unknowns.length, 1);
    assert.match(report.stopped, /ruleset/);
    assert.equal(
      world.calls.filter((c) => c.method === "POST" && c.url.endsWith("/rulesets")).length,
      1,
    );
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.equal(report.closureReady, false);
  });

  it("settles an unknown release patch by reading the release, then restores once", async () => {
    // The first program's PATCH takes effect and its answer is lost.
    const lost = {
      ...on("PATCH", (r) => r.url.pathname.includes("/releases/")),
      afterReal: true,
      answer: "transport",
    };
    const { report, world } = await run({ faults: [lost] });
    assert.equal(report.unknowns.length, 1);
    assert.equal(report.closureReady, false);
    assert.deepEqual(
      world.release,
      { rulesetName: baselineName },
      "the cleanup restored the baseline",
    );
    const patches = world.calls.filter(
      (c) => c.method === "PATCH" && urlOf(c).pathname.includes("/releases/"),
    );
    assert.equal(patches.length, 2, "one lost patch and one restore, no blind resend");
    assert.equal(JSON.parse(Buffer.from(patches[1].body)).release.rulesetName, baselineName);
    assert.equal(world.objects.size, 0);
  });

  it("does not resend a release delete whose answer is unknown", async () => {
    const lost = {
      ...on("DELETE", (r) => r.url.pathname.includes("/releases/")),
      answer: "transport",
    };
    const { report, world } = await run({ baseline: "absent", faults: [lost] });
    assert.equal(report.unknowns.length, 1);
    assert.equal(report.closureReady, false);
    assert.equal(
      world.calls.filter((c) => c.method === "DELETE" && urlOf(c).pathname.includes("/releases/"))
        .length,
      1,
    );
    assert.ok(report.problems.some((p) => /not re-sent|did not read back/.test(p)));
  });

  it("records a ruleset the service refuses and goes on with the other programs", async () => {
    const refuse = {
      ...on("POST", (r) => r.url.pathname.endsWith("/rulesets")),
      answer: {
        status: 400,
        headers: {},
        body: Buffer.from(
          JSON.stringify({ error: { code: 400, message: "bad", status: "INVALID_ARGUMENT" } }),
        ),
      },
    };
    const { report } = await run({ faults: [refuse] });
    assert.equal(report.stopped, null);
    const s9 = report.rows.filter((r) => r.program === "s9" && r.recording === 1);
    assert.ok(s9.length > 0 && s9.every((r) => r.class === "not-evaluated"));
    assert.ok(
      report.rows
        .filter((r) => r.program === "units" && r.recording === 1)
        .every((r) => r.class !== "not-evaluated"),
    );
    assert.ok(
      report.loads.some(
        (l) => l.compiled === false && l.stage === "released-program" && l.id === "s9",
      ),
    );
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
  });

  it("records a load-only ruleset the service refuses", async () => {
    const world = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = world.net;
    const net = async (req) => {
      if (
        req.method === "POST" &&
        req.url.endsWith("/rulesets") &&
        Buffer.from(req.body).toString().includes("ud83d")
      ) {
        return {
          status: 400,
          headers: {},
          body: Buffer.from(
            JSON.stringify({
              error: { code: 400, message: "Invalid escape", status: "INVALID_ARGUMENT" },
            }),
          ),
        };
      }
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
    });
    const s7 = report.loads.filter((l) => l.id === "s7-lone-surrogate");
    assert.equal(s7.length, 2);
    assert.ok(s7.every((l) => l.compiled === false && l.message === "Invalid escape"));
    assert.ok(report.loads.filter((l) => l.id.startsWith("s8")).every((l) => l.compiled === true));
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
  });

  it("marks the rows of an object that could not be created and reads the rest", async () => {
    const { report, world } = await run({ refuseNames: new Set([objectName("pubLeading", P1)]) });
    const leading = report.rows.filter((r) => r.recording === 1 && r.id.startsWith("pub-leading"));
    assert.equal(leading.length, 2);
    assert.ok(leading.every((r) => r.class === "not-evaluated"));
    assert.ok(
      report.rows
        .filter((r) => r.recording === 2 && r.id.startsWith("pub-leading"))
        .every((r) => r.class !== "not-evaluated"),
    );
    assert.equal(world.objects.size, 0);
    assert.ok(report.problems.some((p) => /create of pubLeading refused with 400/.test(p)));
    assert.equal(report.closureReady, false, "a refused create is reported, not hidden");
  });

  it("does not stop on a create refused with 412, and does not evaluate the rows of that name", async () => {
    const collide = {
      ...on(
        "POST",
        (r) =>
          r.url.pathname.startsWith("/upload/") &&
          r.url.searchParams.get("name") === objectName("pubLeading", P1),
      ),
      answer: {
        status: 412,
        headers: {},
        body: Buffer.from(JSON.stringify({ error: { code: 412, message: "Precondition Failed" } })),
      },
    };
    const { report, world } = await run({ faults: [collide], recordings: 1 });
    assert.equal(report.stopped, null);
    assert.ok(
      report.rows
        .filter((r) => r.id.startsWith("pub-leading"))
        .every((r) => r.class === "not-evaluated"),
    );
    assert.ok(report.problems.some((p) => /create of pubLeading refused with 412/.test(p)));
    assert.equal(world.objects.size, 0);
  });

  it("does not evaluate the rows of an object the server stored under another name, and deletes what it stored", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    const leading = objectName("pubLeading", P1);
    const net = async (req) => {
      const url = new URL(req.url);
      // A server that drops the leading slash: the object is stored as `x` and reported as `x`.
      if (req.method === "POST" && url.searchParams.get("name") === leading) {
        const rewritten = {
          ...req,
          url: req.url.replace(
            encodeURIComponent(leading),
            encodeURIComponent(leading.slice(1) + "-renamed"),
          ),
        };
        const res = await inner(rewritten);
        return res;
      }
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
      recordings: 1,
    });
    assert.equal(report.stopped, null);
    assert.ok(
      report.rows
        .filter((r) => r.id.startsWith("pub-leading"))
        .every((r) => r.class === "not-evaluated"),
    );
    assert.ok(report.problems.some((p) => /stored under another name/.test(p)));
    assert.equal(fake.world.objects.size, 0);
  });

  it("stops when the server drops the custom metadata of an upload", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    const net = async (req) => {
      const res = await inner(req);
      if (
        req.method === "POST" &&
        new URL(req.url).searchParams.get("uploadType") === "multipart"
      ) {
        const body = JSON.parse(res.body.toString("utf8"));
        delete body.metadata;
        return { ...res, body: Buffer.from(JSON.stringify(body)) };
      }
      return res;
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
      recordings: 1,
    });
    assert.match(report.stopped, /did not keep the custom metadata/);
    assert.equal(fake.world.objects.size, 0, "the object it did create is deleted");
  });

  it("stops on an unauthorized or forbidden create", async () => {
    for (const status of [401, 403, 429]) {
      const refuse = {
        ...on("POST", (r) => r.url.pathname.startsWith("/upload/")),
        answer: { status, headers: {}, body: Buffer.from("{}") },
      };
      const { report } = await run({ faults: [refuse], recordings: 1 });
      assert.match(report.stopped, new RegExp(`refused with ${status}`));
      assert.equal(report.rows.length, 0);
    }
  });

  it("reports a baseline that does not come back", async () => {
    // The programs go through; the restore patches (to the baseline ruleset) are refused.
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    const net = async (req) => {
      if (
        req.method === "PATCH" &&
        req.url.includes("/releases/") &&
        JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName
      )
        return { status: 400, headers: {}, body: Buffer.from("{}") };
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
    });
    assert.equal(report.closureReady, false);
    assert.ok(
      report.problems.some((p) =>
        /baseline release was refused|did not read back as the baseline/.test(p),
      ),
    );
    assert.equal(fake.world.objects.size, 0);
  });

  it("notes a marker that stops answering 200 while the rows were read", async () => {
    // Program one has no superseded marker: reads 1-3 settle it, reads 4-6 are the still-in-force reads.
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    let markerReads = 0;
    const net = async (req) => {
      const path = decodeURIComponent(new URL(req.url).pathname);
      if (req.method === "GET" && path.includes("/v0/") && path.endsWith(`${P1}/mk/a`)) {
        markerReads += 1;
        // Reads 1 is the setup pre-read; 2-4 settle; 5-7 are the still-in-force reads.
        if (markerReads >= 6)
          return {
            status: 403,
            headers: {},
            body: Buffer.from(
              JSON.stringify({ error: { code: 403, message: "Permission denied." } }),
            ),
          };
      }
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
      recordings: 1,
    });
    assert.ok(
      report.problems.some((p) => /marker stopped answering 200/.test(p)),
      JSON.stringify(report.problems),
    );
    assert.equal(report.publications.find((p) => p.program === "s9").inForce, false);
    assert.equal(report.closureReady, false);
  });

  it("sends anonymous v0 reads without credentials and owner requests with both headers, and deletes only what it made", async () => {
    const { world } = await run();
    for (const call of world.calls) {
      const url = urlOf(call);
      const headers = Object.fromEntries(
        Object.entries(call.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
      );
      // The fake world is handed the request headers before the owner headers are added by the wire.
      assert.ok(
        !url.pathname.startsWith("/v0/") || !headers.authorization,
        `${call.method} ${call.url}`,
      );
    }
    const deletes = world.calls.filter((c) => c.method === "DELETE");
    for (const call of deletes) {
      const url = urlOf(call);
      if (url.pathname.includes("/rulesets/"))
        assert.ok(!url.pathname.includes("22b746af") && !url.pathname.includes("d0abf7c6"));
      else assert.match(url.search, /ifGenerationMatch=\d+/);
    }
  });

  it("sends the rule sources and object names to production as UTF-8, with the escape left as text", async () => {
    const { world } = await run({ recordings: 1 });
    const created = world.calls.filter((c) => c.method === "POST" && c.url.endsWith("/rulesets"));
    assert.equal(created.length, 6);
    const sources = created.map(
      (c) => JSON.parse(Buffer.from(c.body).toString("utf8")).source.files[0].content,
    );
    // U+00E9 and U+1F525 reach the service as their UTF-8 bytes.
    const units = created.find((c) => Buffer.from(c.body).includes(Buffer.from([0xc3, 0xa9])));
    assert.ok(units && Buffer.from(units.body).includes(Buffer.from([0xf0, 0x9f, 0x94, 0xa5])));
    // The lone surrogate stays a six-character escape in the source text.
    const s7 = sources.find((source) => source.includes("ud83d"));
    assert.ok(s7.includes('"\\ud83d".size() == 1'));
    assert.ok(
      !sources.some((source) =>
        /[\ud800-\udfff]/.test(source.replace(/[\ud800-\udbff][\udc00-\udfff]/g, "")),
      ),
      "no lone surrogate in any source",
    );
    // Object names are percent-encoded UTF-8 in every URL, and the empty segments survive.
    const gets = world.calls.filter(
      (c) => c.method === "GET" && c.url.includes("/v0/") && c.url.includes("%2F%2Fx"),
    );
    assert.ok(gets.some((c) => c.url.includes("pub%2F%2Fx")));
    assert.ok(world.calls.some((c) => c.url.includes("s1a%2F%C3%A9%F0%9F%94%A5x")));
    assert.ok(
      world.calls.some((c) => c.url.includes("/o/%2Fstorage-rules-s9%2F")),
      "the leading slash is encoded, not dropped",
    );
  });

  it("reads only the filtered rows (dry runs)", async () => {
    const { report } = await run({
      rowFilter: new Set(["pub-plain-meta", "c1-true"]),
      recordings: 1,
    });
    assert.deepEqual(report.rows.map((r) => r.id).sort(), ["c1-true", "pub-plain-meta"]);
    assert.equal(report.complete, true);
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
  });

  it("stops at the request cap instead of sending more", async () => {
    const { report, world } = await run({ caps: { main: 40, total: 400 } });
    assert.match(report.stopped, /request budget exhausted/);
    assert.ok(world.calls.length <= 400);
    assert.equal(world.objects.size, 0);
    assert.equal(report.closureReady, false);
  });

  it("refuses to start when the release is not the baseline the packet names", async () => {
    const other = `projects/${project}/rulesets/ffffffff-0000-4000-8000-000000000003`;
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const out = memoryOut();
    const { report } = await observe({
      target,
      runId,
      baseline: other,
      deps: { net: fake.net, adminHeaders: () => owner, sleep: noSleep },
      out,
    });
    assert.match(report.stopped, /not the baseline the packet names|not in the ruleset list/);
    assert.equal(
      fake.world.calls.filter((c) => c.method !== "GET").length,
      0,
      "nothing was written",
    );
  });
});

describe("storage rules s9 observation details", () => {
  const deps = (fake) => ({ net: fake.net, adminHeaders: () => owner, sleep: noSleep });

  it("refuses a baseline that is not a ruleset name before sending anything", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    await assert.rejects(
      observe({ target, runId, baseline: "present", deps: deps(fake), out: memoryOut() }),
      /baseline is neither/,
    );
    assert.equal(fake.world.calls.length, 0);
  });

  it("reports a failing journal or save sink instead of ending the run, keeping at most twenty notes", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const out = {
      journal() {
        throw new Error("disk full");
      },
      save() {
        throw new Error("read-only");
      },
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: deps(fake),
      out,
    });
    assert.equal(report.complete, true, "the run itself went on");
    assert.equal(
      report.reportingErrors.length,
      3,
      "one note per distinct failure, not one per call",
    );
    assert.deepEqual(report.reportingErrors.sort(), [
      "entry.json: read-only",
      "journal: disk full",
      "results.json: read-only",
    ]);
    assert.equal(report.closureReady, false);
    assert.equal(fake.world.objects.size, 0);
    // Each failing call with a new message adds a note, up to twenty.
    let n = 0;
    const noisy = {
      journal() {
        throw new Error(`journal ${n++}`);
      },
      save() {
        throw new Error("save");
      },
    };
    const second = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const result = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: deps(second),
      out: noisy,
    });
    assert.equal(result.report.reportingErrors.length, 20);
    assert.equal(result.report.reportingErrors[0], "journal: journal 0");
  });

  it("sends no more than the total cap, cleanup included", async () => {
    const { report, world } = await run({ caps: { main: 40, total: 60 } });
    assert.match(report.stopped, /request budget exhausted/);
    assert.ok(world.calls.length <= 60, `${world.calls.length}`);
    assert.equal(report.requests, world.calls.length);
    assert.equal(report.closureReady, false);
  });

  it("does not count an object as unconfirmed when its create was refused before it was sent", async () => {
    // Preflight takes 6 requests; four creates fit in a main cap of 10, the fifth is refused by the budget.
    const { world, report } = await run({ caps: { main: 10, total: 200 } });
    assert.match(report.stopped, /request budget exhausted/);
    const names = Object.keys(OBJECTS).map((id) => objectName(id, P1));
    const fifth = names[4];
    assert.ok(
      !world.calls.some((c) => c.url.includes(encodeURIComponent(fifth))),
      "nothing was sent for the refused create, and no cleanup read follows",
    );
    assert.ok(
      world.calls.some((c) => c.url.includes(encodeURIComponent(names[3]))),
      "the fourth object was created, so it is read in cleanup",
    );
  });

  it("stops on a 200 answer that is not JSON where the recorded one is", async () => {
    const asText = (match) => ({
      ...on("GET", match),
      answer: { status: 200, headers: {}, body: Buffer.from("<html>") },
    });
    const bucketFault = asText((r) => r.url.pathname.endsWith(`/b/${bucket}`));
    const first = await run({ faults: [bucketFault] });
    assert.match(first.report.stopped, /the bucket is not the expected one/);
    assert.equal(
      first.world.calls.filter((c) => c.method !== "GET").length,
      0,
      "nothing was written",
    );
    const rulesetFault = {
      ...on("POST", (r) => r.url.pathname.endsWith("/rulesets")),
      answer: { status: 200, headers: {}, body: Buffer.from("not json") },
    };
    const second = await run({ faults: [rulesetFault] });
    assert.match(second.report.stopped, /the created ruleset has an unrecorded name/);
    assert.deepEqual(second.world.release, { rulesetName: baselineName });
  });

  it("keeps each problem once", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    // Every create except the markers is refused, in both recordings: the same text is reported twice.
    const inner = fake.net;
    const net = async (req) => {
      const name = new URL(req.url).searchParams.get("name") ?? "";
      if (req.method === "POST" && req.url.includes("/upload/") && !/\/mk\/[abc]$/.test(name))
        return { status: 400, headers: {}, body: Buffer.from("{}") };
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
    });
    assert.equal(report.rows.length, ROWS.length * 2, "both recordings ran");
    const creates = report.problems.filter((p) => p.startsWith("create of "));
    assert.equal(
      creates.length,
      24,
      "24 objects, each noted once although two recordings refuse it",
    );
    assert.equal(new Set(report.problems).size, report.problems.length);
  });

  it("sends the content types of the recorded requests", async () => {
    const { world } = await run({ recordings: 1 });
    const types = (test) =>
      world.calls
        .filter(test)
        .map(
          (c) =>
            Object.fromEntries(
              Object.entries(c.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
            )["content-type"],
        );
    assert.ok(
      types((c) => c.method === "POST" && c.url.includes("uploadType=media")).every(
        (t) => t === "text/plain",
      ),
    );
    assert.ok(
      types((c) => c.method === "POST" && c.url.includes("uploadType=multipart")).every((t) =>
        /^multipart\/related; boundary=s9boundary0123$/.test(t),
      ),
    );
    assert.ok(
      types((c) => c.method === "POST" && c.url.endsWith("/rulesets")).every(
        (t) => t === "application/json",
      ),
    );
    assert.ok(types((c) => c.method === "PATCH").every((t) => t === "application/json"));
    assert.equal(
      types((c) => c.method === "GET").every((t) => t === undefined),
      true,
    );
  });

  it("stops and later deletes an object whose create answered 200 with a body it does not know", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    const net = async (req) => {
      const res = await inner(req);
      if (
        req.method === "POST" &&
        req.url.includes("/upload/") &&
        new URL(req.url).searchParams.get("name") === objectName("mkB", P1)
      )
        return { ...res, body: Buffer.from("{}") };
      return res;
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
    });
    assert.match(report.stopped, /create of mkB answered 200 with an unrecorded body/);
    assert.equal(fake.world.objects.size, 0, "the object is found by the cleanup list and deleted");
    assert.equal(report.closureReady, false);
  });

  it("keeps an object it stored under another name in the cleanup", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    const leading = objectName("pubLeading", P1);
    const net = async (req) => {
      const url = new URL(req.url);
      if (req.method === "POST" && url.searchParams.get("name") === leading) {
        const res = await inner({
          ...req,
          url: req.url.replace(
            encodeURIComponent(leading),
            encodeURIComponent("renamed-by-server"),
          ),
        });
        const body = JSON.parse(res.body.toString("utf8"));
        // The server reports a name outside the run root; the cleanup list (by prefix) cannot see it.
        body.name = objectName("pubPlain", P1) + "-stored";
        fake.world.objects.set(body.name, fake.world.objects.get("renamed-by-server"));
        fake.world.objects.delete("renamed-by-server");
        return { ...res, body: Buffer.from(JSON.stringify(body)) };
      }
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
      recordings: 1,
    });
    assert.ok(report.problems.some((p) => /stored under another name/.test(p)));
    assert.equal(fake.world.objects.size, 0, "the reported name is deleted by its generation");
  });

  it("reads the markers as reads: a lost answer does not end the run", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 0 });
    const inner = fake.net;
    let lost = 0;
    const net = async (req) => {
      const path = decodeURIComponent(new URL(req.url).pathname);
      if (
        req.method === "GET" &&
        path.includes("/v0/") &&
        path.endsWith(`${P1}/mk/a`) &&
        lost < 1
      ) {
        lost += 1;
        throw new Error("reset");
      }
      return inner(req);
    };
    const { report } = await observe({
      target,
      runId,
      baseline: baselineName,
      deps: { net, adminHeaders: () => owner, sleep: noSleep },
      out: memoryOut(),
      recordings: 1,
    });
    // The setup pre-read was lost: not a 200, so the run goes on and the program settles later.
    assert.equal(report.stopped, null);
    assert.equal(report.unknownReads, 1);
    assert.deepEqual(report.unknowns, []);
  });
});

describe("storage rules s9 local target", () => {
  const origin = "http://127.0.0.1:9199";
  it("loads rules with setRules and never touches the Rules API", async () => {
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    // The local emulator starts with rules that deny, and serves them at once.
    const out = memoryOut();
    const { report } = await observe({
      target: { name: "local", bucket: LOCAL_BUCKET, origin },
      runId,
      baseline: "local",
      deps: {
        net: fake.net,
        adminHeaders: () => ({ authorization: "Bearer owner" }),
        sleep: noSleep,
      },
      out,
    });
    assert.equal(report.stopped, null, JSON.stringify(report.problems));
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(fake.world.calls.filter((c) => urlOf(c).pathname.startsWith("/v1/")).length, 0);
    assert.ok(fake.world.calls.some((c) => urlOf(c).pathname === "/internal/setRules"));
    assert.equal(report.rows.length, ROWS.length * 2);
    assert.equal(report.loads.filter((l) => l.stage === "load-only").length, 6);
  });
});

describe("storage rules s9 read-back", () => {
  async function finished() {
    const result = await run();
    return result;
  }
  const deps = (fake) => ({ net: fake.net, adminHeaders: () => owner });

  it("closes after a clean run, and names what is left", async () => {
    const { world, net, out } = await finished();
    const entry = out.saved["entry.json"].entryRulesets;
    const closed = await readback({
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net, adminHeaders: () => owner },
      out: memoryOut(),
    });
    assert.equal(closed.closed, true, JSON.stringify(closed.problems));
    assert.ok(closed.requests <= 70);
    // A leftover object, a different release and an extra ruleset each keep it open.
    world.objects.set(objectName("pubPlain", P2), {
      generation: 7,
      body: Buffer.from("x"),
      metadata: null,
    });
    const open1 = await readback({
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net, adminHeaders: () => owner },
      out: memoryOut(),
    });
    assert.equal(open1.closed, false);
    assert.ok(open1.problems.length >= 1);
    world.objects.clear();
    world.release = {
      rulesetName: `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
    };
    const open2 = await readback({
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net, adminHeaders: () => owner },
      out: memoryOut(),
    });
    assert.ok(open2.problems.includes("the bucket release is not the baseline"));
    world.release = { rulesetName: baselineName };
    world.rulesets.set(`projects/${project}/rulesets/99999999-0000-4000-8000-000000000000`, {
      services: ["firebase.storage"],
      source: "",
    });
    const open3 = await readback({
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net, adminHeaders: () => owner },
      out: memoryOut(),
    });
    assert.ok(open3.problems.includes("the ruleset list is not the list at entry"));
    assert.ok(deps);
  });

  it("covers every planned object name", async () => {
    const { world, net, out } = await finished();
    const entry = out.saved["entry.json"].entryRulesets;
    const before = world.calls.length;
    await readback({
      target,
      runId,
      baseline: baselineName,
      entry,
      deps: { net, adminHeaders: () => owner },
      out: memoryOut(),
    });
    const reads = world.calls
      .slice(before)
      .map((c) => decodeURIComponent(urlOf(c).pathname.split("/o/")[1] ?? ""));
    for (const P of [P1, P2])
      for (const id of Object.keys(OBJECTS))
        assert.ok(reads.includes(objectName(id, P)), `${P} ${id}`);
    assert.ok(PROGRAMS.length === 3);
  });
});
