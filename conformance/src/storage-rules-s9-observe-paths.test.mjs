import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { observe } from "./storage-rules-s9/observe.mjs";
import {
  LOCAL_BASELINE_RULES,
  LOCAL_BUCKET,
  OBJECTS,
  ROWS,
  SETTLE_MAX_POLLS,
  SETTLE_POLL_MS,
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
const reply = (status, body = {}) => ({
  status,
  headers: {},
  body: Buffer.from(typeof body === "string" ? body : JSON.stringify(body)),
});
const denied = reply(403, { error: { code: 403, message: "Permission denied." } });
const pathOf = (req) => decodeURIComponent(new URL(req.url).pathname);

function sinks() {
  const entries = [];
  const saved = {};
  return {
    entries,
    saved,
    journal: (entry) => entries.push(entry),
    save: (name, data) => (saved[name] = data),
  };
}

/**
 * Runs the observation against a fake world. `intercept(req, inner)` may answer a request itself
 * (return an answer), let it through (return undefined) or run it and change the answer.
 */
async function go({
  baseline = baselineName,
  lag = 0,
  intercept,
  recordings,
  rowFilter,
  caps,
  worldBaseline,
  seed,
} = {}) {
  const fake = createWorld({
    project,
    bucket,
    baseline: worldBaseline !== undefined ? worldBaseline : baseline === "absent" ? null : baseline,
    lag,
  });
  seed?.(fake.world);
  const out = sinks();
  const sleeps = [];
  // The recorder sends one request at a time and waits for each pause: a request that starts while
  // another is in flight, or while a pause is running, is a missing await.
  let inflight = 0;
  let maxInflight = 0;
  let sleeping = 0;
  let overlaps = 0;
  const later = () => new Promise((resolve) => setImmediate(resolve));
  const net = async (req) => {
    if (sleeping > 0) overlaps += 1;
    inflight += 1;
    maxInflight = Math.max(maxInflight, inflight);
    try {
      await later();
      if (intercept) {
        const answered = await intercept(req, fake.net);
        if (answered !== undefined) return answered;
      }
      return await fake.net(req);
    } finally {
      inflight -= 1;
    }
  };
  const sleep = async (ms) => {
    sleeping += 1;
    sleeps.push(ms);
    await later();
    sleeping -= 1;
  };
  const { report } = await observe({
    target,
    runId,
    baseline,
    deps: { net, adminHeaders: () => owner, sleep },
    out,
    recordings,
    rowFilter,
    caps,
  });
  assert.equal(maxInflight <= 1, true, "two requests were in flight at once");
  assert.equal(overlaps, 0, "a request was sent while a pause was running");
  return { ...fake, report, out, sleeps };
}

/** The number of the request (1-based, in sending order) that carries `label` in a clean run with these options. */
async function requestNumber(label, options = {}) {
  const { out } = await go(options);
  const entry = out.entries.find((e) => e.phase === "before" && e.label === label);
  assert.ok(entry, `no request labelled ${label}`);
  return entry.n;
}

/** An intercept that answers the nth request of the run with `answer` (or throws a transport failure when it is "transport"). */
function atRequest(n, answer) {
  let seen = 0;
  return async (req, inner) => {
    seen += 1;
    if (seen !== n) return undefined;
    if (answer === "transport") throw new Error("reset");
    if (answer === "after") {
      await inner(req);
      throw new Error("lost");
    }
    return answer;
  };
}

const rootPrefix = `storage-rules-s9/${runId}/`;
const prefixOf = (req) => new URL(req.url).searchParams.get("prefix");
const isGcsList = (req) =>
  req.method === "GET" && req.url.includes("/storage/v1/") && prefixOf(req) !== null;
const isGet = (req) => req.method === "GET";
const isV0 = (req) => req.url.includes("/v0/");
const markerRead = (req, P, marker) =>
  isGet(req) && isV0(req) && pathOf(req).endsWith(`${P}/mk/${marker}`);

describe("storage rules s9 journal labels", () => {
  const labelsOf = (out) =>
    [
      ...new Set(
        out.entries
          .filter((e) => e.phase === "before")
          .map((e) =>
            e.label
              .replace(/\/poll\d+(?=\/|$)/, "/pollN")
              .replace(/^cleanup\/ruleset\/.+$/, "cleanup/ruleset/ID"),
          ),
      ),
    ].sort();

  it("pins the labels of a clean production run", async () => {
    const { out, report } = await go({ recordings: 1 });
    assert.equal(report.closureReady, true);
    const labels = labelsOf(out).filter(
      (label) =>
        !label.startsWith("create/") &&
        !label.startsWith("cleanup/delete/") &&
        !label.startsWith("cleanup/absent/") &&
        !label.startsWith("row/"),
    );
    assert.deepEqual(
      labels,
      [
        "cleanup/final-list",
        "cleanup/final-list-slash",
        "cleanup/list",
        "cleanup/list-slash",
        "cleanup/ruleset/ID",
        "final/release",
        "final/rulesets",
        "preflight/bucket",
        "preflight/empty",
        "preflight/empty-slash",
        "preflight/release",
        "preflight/release-bucketless",
        "preflight/rulesets",
        "rec1/lists/release/patch",
        "rec1/lists/release-readback",
        "rec1/lists/ruleset",
        "rec1/lists/still1",
        "rec1/lists/still2",
        "rec1/lists/still3",
        "rec1/lists/pollN/new",
        "rec1/lists/pollN/old",
        "rec1/load/s7-lone-surrogate",
        "rec1/load/s7-lone-surrogate/delete",
        "rec1/load/s8-function-after",
        "rec1/load/s8-function-after/delete",
        "rec1/load/s8-function-before",
        "rec1/load/s8-function-before/delete",
        "rec1/restore/patch/patch",
        "rec1/restore/pollN",
        "rec1/restore/read",
        "rec1/restore/readback",
        "rec1/s9/release/patch",
        "rec1/s9/release-readback",
        "rec1/s9/ruleset",
        "rec1/s9/still1",
        "rec1/s9/still2",
        "rec1/s9/still3",
        "rec1/s9/pollN/new",
        "rec1/units/release/patch",
        "rec1/units/release-readback",
        "rec1/units/ruleset",
        "rec1/units/still1",
        "rec1/units/still2",
        "rec1/units/still3",
        "rec1/units/pollN/new",
        "rec1/units/pollN/old",
        "setup/marker/lists",
        "setup/marker/s9",
        "setup/marker/units",
      ].sort(),
    );
    assert.equal(
      new Set(out.entries.filter((e) => e.label?.startsWith("create/")).map((e) => e.label)).size,
      Object.keys(OBJECTS).length,
    );
    assert.equal(out.entries.filter((e) => e.label?.startsWith("row/1/")).length / 2, ROWS.length);
    assert.ok(out.entries.some((e) => e.label === "row/1/pub-plain-meta"));
  });

  it("labels the post, the delete and the cleanup of a run that starts without a release", async () => {
    const { out } = await go({ baseline: "absent", recordings: 1 });
    const labels = labelsOf(out);
    for (const label of [
      "rec1/s9/release/post",
      "rec1/units/release/patch",
      "rec1/restore/delete",
      "rec1/restore/readback",
      "rec1/restore/read",
    ]) {
      assert.ok(labels.includes(label), label);
    }
    assert.ok(!labels.includes("rec1/restore/patch/patch"));
  });

  it("labels the steps of a local run", async () => {
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    const out = sinks();
    await observe({
      target: { name: "local", bucket: LOCAL_BUCKET, origin: "http://127.0.0.1:9199" },
      runId,
      baseline: "local",
      deps: {
        net: fake.net,
        adminHeaders: () => ({ authorization: "Bearer owner" }),
        sleep: async () => {},
      },
      out,
      recordings: 1,
    });
    const labels = labelsOf(out);
    for (const label of [
      "preflight/local-baseline",
      "rec1/s9/set-rules",
      "rec1/s9/marker",
      "rec1/units/set-rules",
      "rec1/lists/set-rules",
      "rec1/load/s7-lone-surrogate",
      "rec1/restore/local-baseline",
      "setup/marker/s9",
    ]) {
      assert.ok(labels.includes(label), label);
    }
    // Every local rules load is an owner request with the PUT body the emulators read.
    const puts = fake.world.calls.filter((c) => c.method === "PUT");
    assert.ok(puts.length >= 8);
    for (const put of puts) {
      assert.equal(put.headers.authorization, "Bearer owner");
      assert.equal(put.headers["content-type"], "application/json");
      const body = JSON.parse(Buffer.from(put.body).toString("utf8"));
      assert.deepEqual(Object.keys(body), ["rules"]);
      assert.equal(body.rules.files.length, 1);
      assert.equal(body.rules.files[0].name, "storage.rules");
    }
    assert.equal(
      fake.world.local.rulesSource,
      LOCAL_BASELINE_RULES,
      "the local rules end as the closed baseline",
    );
  });
});

describe("storage rules s9 settle", () => {
  it("settles on the sixtieth poll and not on the sixty-first", async () => {
    const last = await go({
      lag: SETTLE_MAX_POLLS - 2,
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta"]),
    });
    assert.equal(last.report.stopped, null, "settled at poll 60");
    assert.equal(last.report.publications.find((p) => p.program === "s9").polls, SETTLE_MAX_POLLS);
    const late = await go({
      lag: SETTLE_MAX_POLLS - 1,
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta"]),
    });
    assert.match(late.report.stopped, /rec1\/s9: did not settle in 60 polls/);
    assert.equal(late.report.publications.length, 0);
  });

  it("starts at poll one, and sleeps the poll interval between polls only", async () => {
    const { report, sleeps, out } = await go({
      lag: 4,
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta"]),
    });
    const s9 = report.publications.find((p) => p.program === "s9");
    assert.equal(s9.polls, 6, "three stale polls, then three good ones");
    const polls = out.entries
      .filter((e) => e.phase === "before" && /^rec1\/s9\/poll\d+\/new$/.test(e.label))
      .map((e) => e.label);
    assert.equal(polls[0], "rec1/s9/poll1/new");
    assert.equal(polls.length, 6);
    assert.ok(sleeps.every((ms) => ms === SETTLE_POLL_MS));
    // No sleep before the first poll or after the last: five between the six polls of s9, five between those of the restore.
    assert.equal(sleeps.length, 5 + 5);
    assert.equal(report.publications.find((p) => p.restoreSettlePolls).restoreSettlePolls, 6);
  });

  it("restarts the streak after a bad poll", async () => {
    let reads = 0;
    const script = [200, 200, 403, 200, 200, 200];
    const { report } = await go({
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta"]),
      intercept: (req) => {
        if (markerRead(req, P1, "a") && reads < script.length + 1) {
          reads += 1;
          if (reads === 1) return undefined; // the setup pre-read
          return script[reads - 2] === 200 ? reply(200, { name: "mk" }) : denied;
        }
        return undefined;
      },
    });
    assert.equal(report.publications.find((p) => p.program === "s9").polls, 6);
  });

  it("does not settle while the superseded marker can still be read", async () => {
    let seen = 0;
    let patches = 0;
    const { report } = await go({
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta", "c1-true"]),
      intercept: (req) => {
        // After the second release, the old marker stays readable for the first three polls.
        if (markerRead(req, P1, "a") && patches >= 2 && (seen += 1) <= 3)
          return reply(200, { name: "mk" });
        if (
          req.method === "PATCH" &&
          JSON.parse(Buffer.from(req.body)).release.rulesetName !== baselineName
        )
          patches += 1;
        return undefined;
      },
    });
    assert.equal(report.publications.find((p) => p.program === "units").polls, 6);
  });

  it("treats an unknown answer for the superseded marker as not settled", async () => {
    let seen = 0;
    let patches = 0;
    const { report } = await go({
      recordings: 1,
      rowFilter: new Set(["pub-plain-meta", "c1-true"]),
      intercept: (req) => {
        if (markerRead(req, P1, "a") && patches >= 2 && (seen += 1) <= 2) return reply(503, "down");
        if (
          req.method === "PATCH" &&
          JSON.parse(Buffer.from(req.body)).release.rulesetName !== baselineName
        )
          patches += 1;
        return undefined;
      },
    });
    assert.equal(report.publications.find((p) => p.program === "units").polls, 5);
  });

  it("stops a local run whose marker cannot be read after the rules load, and records one poll when it can", async () => {
    const origin = "http://127.0.0.1:9199";
    const mk = () =>
      createWorld({ project: "demo-storage-s9", bucket: LOCAL_BUCKET, baseline: null, lag: 0 });
    const local = { name: "local", bucket: LOCAL_BUCKET, origin };
    const deps = (fake, intercept) => ({
      net: async (req) => (intercept && (await intercept(req))) || fake.net(req),
      adminHeaders: () => ({ authorization: "Bearer owner" }),
      sleep: async () => {},
    });
    const fake = mk();
    const bad = await observe({
      target: local,
      runId,
      baseline: "local",
      deps: deps(fake, (req) =>
        markerRead(req, P1, "a") && fake.world.local.rulesSource?.includes("mk/a")
          ? denied
          : undefined,
      ),
      out: sinks(),
      recordings: 1,
    });
    assert.match(bad.report.stopped, /rec1\/s9: the marker is not readable \(403\)/);
    const good = await observe({
      target: local,
      runId,
      baseline: "local",
      deps: deps(mk()),
      out: sinks(),
      recordings: 1,
    });
    assert.deepEqual(
      good.report.publications.map((p) => p.polls),
      [1, 1, 1],
    );
  });
});

const writes = (world) => world.calls.filter((c) => c.method !== "GET");
const only = (...ids) => new Set(ids);
const releaseUrl = (req) => req.url.includes("/releases/");
const rulesetsUrl = (req) => req.url.endsWith("/rulesets") || req.url.includes("/rulesets?");

describe("storage rules s9 preflight", () => {
  const stopsWith = async (message, options) => {
    const result = await go({ recordings: 1, ...options });
    assert.match(result.report.stopped, message);
    assert.equal(writes(result.world).length, 0, "nothing was written");
    assert.equal(result.report.rows.length, 0);
    assert.equal(result.report.closureReady, false);
    return result;
  };

  it("stops when the bucket is not the expected one", async () => {
    await stopsWith(/preflight: the bucket is not the expected one/, {
      intercept: (req) =>
        req.url.endsWith(`/b/${bucket}`) ? reply(200, { name: "other" }) : undefined,
    });
    await stopsWith(/the bucket is not the expected one/, {
      intercept: (req) => (req.url.endsWith(`/b/${bucket}`) ? reply(404, {}) : undefined),
    });
    await stopsWith(/the bucket is not the expected one/, {
      intercept: (req) =>
        req.url.endsWith(`/b/${bucket}`)
          ? reply(200, { name: bucket, extra: 1 }) && reply(200, [])
          : undefined,
    });
  });

  it("stops when the release cannot be read in a recorded shape", async () => {
    await stopsWith(/preflight: unknown answer: preflight\/release \(500\)/, {
      intercept: (req) =>
        isGet(req) && releaseUrl(req) && req.url.endsWith(bucket) ? reply(500, {}) : undefined,
    });
    await stopsWith(/the bucket release read is not a recorded shape/, {
      intercept: (req) =>
        isGet(req) && releaseUrl(req) && req.url.endsWith(bucket)
          ? reply(200, { name: "other", rulesetName: baselineName })
          : undefined,
    });
  });

  it("stops when the release is not the baseline the packet names", async () => {
    const other = `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`;
    await stopsWith(/the bucket release is not the baseline the packet names/, {
      baseline: other,
      worldBaseline: baselineName,
    });
    await stopsWith(/the bucket release is not the baseline the packet names/, {
      baseline: "absent",
      worldBaseline: baselineName,
    });
    await stopsWith(/the bucket release is not the baseline the packet names/, {
      baseline: baselineName,
      worldBaseline: null,
    });
  });

  it("stops when the bucketless release is not absent", async () => {
    await stopsWith(/preflight: the bucketless release is not absent/, {
      intercept: (req) =>
        isGet(req) && req.url.endsWith("/releases/firebase.storage")
          ? reply(200, { name: "x" })
          : undefined,
    });
  });

  it("stops when the ruleset list is not one recorded page, or lacks the baseline", async () => {
    await stopsWith(/preflight: unknown answer: preflight\/rulesets \(500\)/, {
      intercept: (req) => (isGet(req) && rulesetsUrl(req) ? reply(500, {}) : undefined),
    });
    await stopsWith(/preflight: the ruleset list is not a recorded single page/, {
      intercept: (req) =>
        isGet(req) && rulesetsUrl(req)
          ? reply(200, { rulesets: [], nextPageToken: "t" })
          : undefined,
    });
    const missing = `projects/${project}/rulesets/ffffffff-0000-4000-8000-000000000009`;
    await stopsWith(/preflight: the baseline ruleset is not in the ruleset list/, {
      baseline: missing,
    });
    // With no baseline release the list needs no baseline ruleset.
    const empty = await go({
      baseline: "absent",
      recordings: 1,
      intercept: (req) =>
        isGet(req) && rulesetsUrl(req) ? reply(200, { rulesets: [] }) : undefined,
      rowFilter: only("pub-plain-meta"),
    });
    assert.equal(empty.report.stopped, null);
  });

  it("stops when the run root is not empty, with or without the leading slash, and leaves what it did not create", async () => {
    const seed = (name) => (world) =>
      world.objects.set(name, { generation: 5, body: Buffer.from("x"), metadata: null });
    for (const name of [`storage-rules-s9/${runId}/old`, `/storage-rules-s9/${runId}/old`]) {
      const result = await stopsWith(/preflight: the run root is not empty/, { seed: seed(name) });
      assert.deepEqual(
        [...result.world.objects.keys()],
        [name],
        "an object it did not create is not deleted",
      );
      assert.ok(
        result.report.problems.includes("an unexpected object is listed under the run root"),
      );
    }
    await stopsWith(/preflight: unknown answer: preflight\/empty \(500\)/, {
      intercept: (req) =>
        isGcsList(req) && prefixOf(req) === rootPrefix ? reply(500, {}) : undefined,
    });
  });

  it("stops a local run whose baseline rules are refused or unanswered", async () => {
    const local = { name: "local", bucket: LOCAL_BUCKET, origin: "http://127.0.0.1:9199" };
    for (const [answer, text] of [
      [reply(400, {}), "400"],
      [reply(500, {}), "500"],
    ]) {
      const fake = createWorld({
        project: "demo-storage-s9",
        bucket: LOCAL_BUCKET,
        baseline: null,
        lag: 0,
      });
      const { report } = await observe({
        target: local,
        runId,
        baseline: "local",
        deps: {
          net: async (req) => (req.url.endsWith("/internal/setRules") ? answer : fake.net(req)),
          adminHeaders: () => ({ authorization: "Bearer owner" }),
          sleep: async () => {},
        },
        out: sinks(),
        recordings: 1,
      });
      assert.match(report.stopped, new RegExp(`preflight: local baseline rules answered ${text}`));
      assert.equal(report.rows.length, 0);
    }
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    const { report } = await observe({
      target: local,
      runId,
      baseline: "local",
      deps: {
        net: async (req) => {
          if (req.url.endsWith("/internal/setRules")) throw new Error("reset");
          return fake.net(req);
        },
        adminHeaders: () => ({ authorization: "Bearer owner" }),
        sleep: async () => {},
      },
      out: sinks(),
      recordings: 1,
    });
    assert.match(
      report.stopped,
      /preflight: local baseline rules answered NaN/,
      "a lost setRules answer is a read, not an unknown write",
    );
    assert.deepEqual(report.unknowns, []);
  });
});

describe("storage rules s9 publication", () => {
  it("stops on a ruleset create refused for any reason but a compile error", async () => {
    for (const status of [401, 403, 404, 409, 429]) {
      const { report, world } = await go({
        recordings: 1,
        intercept: (req) =>
          req.method === "POST" && rulesetsUrl(req) ? reply(status, {}) : undefined,
      });
      assert.match(
        report.stopped,
        new RegExp(`rec1/s9: rec1/s9/ruleset: ruleset create answered ${status}`),
      );
      assert.deepEqual(world.release, { rulesetName: baselineName });
    }
  });

  it("records a ruleset refused at create as a compile answer and skips its rows", async () => {
    const { report } = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "POST" && rulesetsUrl(req) && Buffer.from(req.body).includes("mk/b")
          ? reply(400, {
              error: { code: 400, message: "Compilation failed", status: "INVALID_ARGUMENT" },
            })
          : undefined,
    });
    const refused = report.loads.find((l) => l.stage === "released-program");
    assert.deepEqual(refused, {
      recording: 1,
      id: "units",
      compiled: false,
      status: 400,
      message: "Compilation failed",
      stage: "released-program",
    });
    const units = report.rows.filter((r) => r.program === "units");
    assert.ok(
      units.length > 0 &&
        units.every(
          (r) =>
            r.class === "not-evaluated" &&
            r.why === "ruleset refused at create" &&
            r.answer.status === null,
        ),
    );
    assert.equal(
      report.publications.filter((p) => p.program).length,
      2,
      "the other programs were published",
    );
  });

  it("records a release refused with 400 and skips the rows of that program", async () => {
    let patches = 0;
    const { report, world } = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "PATCH" && releaseUrl(req) && (patches += 1) === 1
          ? reply(400, {})
          : undefined,
    });
    assert.equal(report.stopped, null);
    const refused = report.loads.find((l) => l.stage === "release");
    assert.deepEqual(refused, {
      recording: 1,
      id: "s9",
      stage: "release",
      compiled: false,
      status: 400,
    });
    const s9 = report.rows.filter((r) => r.program === "s9");
    assert.ok(
      s9.length > 0 && s9.every((r) => r.class === "not-evaluated" && r.why === "release refused"),
    );
    assert.deepEqual(world.release, { rulesetName: baselineName });
  });

  it("stops on a release write refused for another reason", async () => {
    for (const status of [401, 403, 409]) {
      const { report, world } = await go({
        recordings: 1,
        intercept: (req) =>
          req.method === "PATCH" &&
          releaseUrl(req) &&
          JSON.parse(Buffer.from(req.body)).release.rulesetName !== baselineName
            ? reply(status, {})
            : undefined,
      });
      assert.match(report.stopped, new RegExp(`rec1/s9/release: release write answered ${status}`));
      assert.deepEqual(world.release, { rulesetName: baselineName });
      assert.equal(world.objects.size, 0);
    }
  });

  it("falls back to a create when the patch finds no release, and stops when that is refused", async () => {
    const missing = (req) =>
      req.method === "PATCH" && releaseUrl(req) ? reply(404, {}) : undefined;
    const { report, world } = await go({ recordings: 1, intercept: missing });
    // The fake refuses a release create over an existing release with 409.
    assert.match(report.stopped, /rec1\/s9\/release: release write answered 409/);
    assert.ok(world.calls.some((c) => c.method === "POST" && c.url.endsWith("/releases")));
  });

  it("stops when the release does not read back as the ruleset it just wrote", async () => {
    let wrote = false;
    const { report, world } = await go({
      recordings: 1,
      intercept: (req) => {
        if (req.method === "PATCH" && releaseUrl(req)) wrote = true;
        if (wrote && isGet(req) && releaseUrl(req) && req.url.endsWith(bucket))
          return reply(200, {
            name: `projects/${project}/releases/firebase.storage/${bucket}`,
            rulesetName: baselineName,
          });
        return undefined;
      },
    });
    assert.match(
      report.stopped,
      /rec1\/s9: rec1\/s9: the release did not read back|the release did not read back/,
    );
    assert.equal(world.objects.size, 0);
  });

  it("publishes no program when no row of it is read", async () => {
    const { report, world } = await go({ recordings: 1, rowFilter: only("c1-true") });
    assert.equal(report.stopped, null);
    assert.deepEqual(
      report.publications.filter((p) => p.program).map((p) => p.program),
      ["units"],
    );
    assert.equal(
      world.calls.filter((c) => c.method === "POST" && rulesetsUrl(c)).length,
      1 + 3,
      "one program ruleset and three load-only ones",
    );
    assert.deepEqual(
      report.rows.map((r) => r.id),
      ["c1-true"],
    );
  });

  it("deletes each load-only ruleset right after it is created, and says what it did with a ruleset that is already gone", async () => {
    const { world, report } = await go({ recordings: 1 });
    const seq = world.calls.map(
      (c) => `${c.method} ${new URL(c.url).pathname.split("/").slice(-2).join("/")}`,
    );
    const creates = world.calls
      .map((c, i) => [c, i])
      .filter(
        ([c]) =>
          (c.method === "POST" && rulesetsUrl(c) && Buffer.from(c.body).includes("function ok")) ||
          (c.method === "POST" && rulesetsUrl(c) && Buffer.from(c.body).includes("ud83d")),
      );
    assert.equal(creates.length, 3);
    for (const [, index] of creates)
      assert.equal(world.calls[index + 1].method, "DELETE", "the delete follows the create");
    assert.ok(seq.length > 0);
    assert.equal(report.closureReady, true);
    const gone = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "DELETE" && req.url.includes("/rulesets/") ? reply(404, {}) : undefined,
    });
    assert.ok(
      gone.report.problems.some((p) =>
        /rec1\/load\/s7-lone-surrogate\/delete: the ruleset was already gone/.test(p),
      ),
    );
    const refused = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "DELETE" && req.url.includes("/rulesets/") ? reply(400, {}) : undefined,
    });
    assert.ok(
      refused.report.problems.some((p) =>
        /rec1\/load\/s8-function-before\/delete: ruleset delete answered 400/.test(p),
      ),
    );
    assert.equal(refused.report.closureReady, false);
  });
});

describe("storage rules s9 restore and cleanup", () => {
  it("writes nothing to restore when the release is already the baseline, and settles by markers", async () => {
    // A lost patch that never took effect: the release still reads as the baseline when the restore looks.
    let sent = 0;
    const lost = (req) => {
      if (req.method === "PATCH" && releaseUrl(req)) {
        sent += 1;
        throw new Error("reset");
      }
      return undefined;
    };
    const { report, world } = await go({ recordings: 1, intercept: lost });
    assert.equal(report.unknowns.length, 1);
    assert.equal(sent, 1, "no second patch");
    assert.equal(world.calls.filter((c) => c.method === "PATCH").length, 0);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.ok(!report.problems.some((p) => /restore/.test(p)));
  });

  it("notes a release delete that answers 404 as fine and one that answers 403 as a problem", async () => {
    const del = (status) => (req) =>
      req.method === "DELETE" && releaseUrl(req) ? reply(status, {}) : undefined;
    const fine = await go({ baseline: "absent", recordings: 1, intercept: del(404) });
    assert.ok(!fine.report.problems.some((p) => /release delete/.test(p)));
    const refused = await go({ baseline: "absent", recordings: 1, intercept: del(403) });
    assert.ok(refused.report.problems.includes("rec1/restore: release delete answered 403"));
    assert.ok(refused.report.problems.some((p) => /did not read back as the baseline/.test(p)));
  });

  it("reports a baseline patch that is refused, and one that does not read back", async () => {
    const toBaseline = (req) =>
      req.method === "PATCH" &&
      releaseUrl(req) &&
      JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName;
    const refused = await go({
      recordings: 1,
      intercept: (req) => (toBaseline(req) ? reply(400, {}) : undefined),
    });
    assert.ok(refused.report.problems.includes("rec1/restore: the baseline release was refused"));
    assert.ok(
      refused.report.problems.includes(
        "rec1/restore: the release did not read back as the baseline",
      ),
    );
    const silent = await go({
      recordings: 1,
      intercept: (req) => (toBaseline(req) ? reply(200, {}) : undefined),
    });
    assert.ok(
      silent.report.problems.includes(
        "rec1/restore: the release did not read back as the baseline",
      ),
    );
    assert.ok(!silent.report.problems.includes("rec1/restore: the baseline release was refused"));
  });

  it("reports a marker that still answers 200 after the restore, after exactly sixty polls", async () => {
    let restoring = false;
    const { report, sleeps } = await go({
      recordings: 1,
      rowFilter: only("c1-true"),
      intercept: (req) => {
        if (
          req.method === "PATCH" &&
          releaseUrl(req) &&
          JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName
        )
          restoring = true;
        if (restoring && markerRead(req, P1, "b")) return reply(200, { name: "mk" });
        return undefined;
      },
    });
    assert.ok(
      report.problems.includes("rec1/restore: the last marker still answers 200 or unknown"),
    );
    assert.equal(sleeps.length >= SETTLE_MAX_POLLS, true);
    assert.equal(
      report.publications.some((p) => p.restoreSettlePolls),
      false,
    );
  });

  it("leaves the cleanup restore to say so when the recording's restore did not work", async () => {
    const toBaseline = (req) =>
      req.method === "PATCH" &&
      releaseUrl(req) &&
      JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName;
    let refusals = 0;
    const { report, world } = await go({
      recordings: 1,
      intercept: (req) => (toBaseline(req) && (refusals += 1) === 1 ? reply(400, {}) : undefined),
    });
    assert.ok(report.problems.includes("rec1/restore: the baseline release was refused"));
    assert.deepEqual(
      world.release,
      { rulesetName: baselineName },
      "the cleanup restore (second attempt) worked",
    );
    assert.equal(refusals, 2, "the cleanup restored once more");
  });

  it("keeps the first reason a run stopped for", async () => {
    // The release never settles, and the baseline patch of the cleanup is refused with 403 (a stop-class error).
    const { report } = await go({
      lag: 100000,
      recordings: 1,
      intercept: (req) =>
        req.method === "PATCH" &&
        releaseUrl(req) &&
        JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName
          ? reply(403, {})
          : undefined,
    });
    assert.match(report.stopped, /^rec1\/s9: rec1\/s9: did not settle|did not settle in 60 polls/);
    assert.ok(
      report.problems.some((p) => /cleanup\/restore: .*release write answered 403/.test(p)),
    );
  });

  it("propagates an error that is not one of the run's own, after the cleanup", async () => {
    const fake = createWorld({ project, bucket, baseline: baselineName, lag: 5 });
    let calls = 0;
    const deps = {
      net: fake.net,
      adminHeaders: () => owner,
      sleep: async () => {
        calls += 1;
        if (calls === 1) throw new TypeError("boom");
      },
    };
    await assert.rejects(
      observe({ target, runId, baseline: baselineName, deps, out: sinks(), recordings: 1 }),
      TypeError,
    );
    assert.equal(fake.world.objects.size, 0, "the cleanup ran");
    assert.deepEqual(fake.world.release, { rulesetName: baselineName });
  });
});

describe("storage rules s9 cleanup details", () => {
  /** Answers the nth GCS list of the root prefix (1: preflight, 2: cleanup list, 3: final list) with `answer`. */
  const nthRootList = (n, answer) => {
    let seen = 0;
    return (req) =>
      isGcsList(req) && prefixOf(req) === rootPrefix && (seen += 1) === n ? answer : undefined;
  };
  const emptyList = reply(200, { kind: "storage#objects" });

  it("deletes by the generation it was told when the cleanup list is stale", async () => {
    const { report, world } = await go({ recordings: 1, intercept: nthRootList(2, emptyList) });
    assert.equal(world.objects.size, 0);
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    const deletes = world.calls.filter(
      (c) =>
        c.method === "DELETE" && !c.url.includes("/rulesets/") && !c.url.includes("/releases/"),
    );
    assert.equal(deletes.length, Object.keys(OBJECTS).length);
    for (const call of deletes)
      assert.match(new URL(call.url).search, /^\?ifGenerationMatch=\d{16}$/);
  });

  it("flags a create it never saw an answer to when the cleanup list does not show it", async () => {
    const stale = nthRootList(2, emptyList);
    const target1 = objectName("pubInterior", P1);
    const { report, world } = await go({
      recordings: 1,
      intercept: async (req, inner) => {
        if (
          req.method === "POST" &&
          req.url.includes("/upload/") &&
          new URL(req.url).searchParams.get("name") === target1
        ) {
          await inner(req);
          throw new Error("lost");
        }
        return stale(req);
      },
    });
    assert.deepEqual(report.unknowns, ["create/pubInterior"]);
    assert.ok(report.problems.includes("an object still reads 200 after cleanup"));
    assert.deepEqual([...world.objects.keys()], [target1]);
    assert.equal(report.closureReady, false);
  });

  it("notes a cleanup list that is not one recorded page, and still deletes what it created", async () => {
    const { report, world } = await go({
      recordings: 1,
      intercept: nthRootList(2, reply(500, {})),
    });
    assert.ok(report.problems.includes("cleanup list is not a recorded single page"));
    assert.equal(world.objects.size, 0);
    const paged = await go({
      recordings: 1,
      intercept: nthRootList(2, reply(200, { kind: "storage#objects", nextPageToken: "t" })),
    });
    assert.ok(paged.report.problems.includes("cleanup list is not a recorded single page"));
  });

  it("notes an object delete that is refused, treats a 404 as gone, and does not read an unknown delete back", async () => {
    const victim = objectName("pubPlain", P1);
    const isVictim = (req) => req.method === "DELETE" && pathOf(req).split("/o/")[1] === victim;
    const refused = await go({
      recordings: 1,
      intercept: (req) => (isVictim(req) ? reply(403, {}) : undefined),
    });
    assert.ok(refused.report.problems.includes("cleanup delete of an object answered 403"));
    assert.ok(refused.report.problems.includes("an object still reads 200 after cleanup"));
    assert.deepEqual([...refused.world.objects.keys()], [victim]);
    const gone = await go({
      recordings: 1,
      intercept: async (req, inner) =>
        isVictim(req) ? (await inner(req), reply(404, {})) : undefined,
    });
    assert.deepEqual(gone.report.problems, []);
    assert.equal(gone.report.closureReady, true);
    const unknown = await go({
      recordings: 1,
      intercept: async (req, inner) => {
        if (isVictim(req)) {
          await inner(req);
          throw new Error("reset");
        }
        return undefined;
      },
    });
    assert.equal(unknown.report.unknowns.length, 1);
    assert.match(unknown.report.unknowns[0], /^cleanup\/delete\//);
    assert.equal(unknown.report.closureReady, false);
    assert.equal(
      unknown.world.calls.filter((c) => isVictim(c)).length,
      1,
      "the delete was sent once",
    );
    const absentReads = (result) =>
      result.world.calls.filter(
        (c) =>
          isGet(c) &&
          c.url.includes("/storage/v1/") &&
          c.url.includes(`/o/${encodeURIComponent(rootPrefix)}`),
      ).length;
    assert.equal(
      absentReads(unknown),
      Object.keys(OBJECTS).length - 2,
      "no read-back for the object whose delete is unknown (the leading-slash name is read under another path)",
    );
    assert.equal(absentReads(gone), Object.keys(OBJECTS).length - 1);
  });

  it("notes a run root that is not empty at the end", async () => {
    const leftover = reply(200, {
      kind: "storage#objects",
      items: [{ name: `${rootPrefix}x`, generation: "7" }],
    });
    const full = await go({ recordings: 1, intercept: nthRootList(3, leftover) });
    assert.ok(full.report.problems.includes("the run root is not empty after cleanup"));
    const unreadable = await go({ recordings: 1, intercept: nthRootList(3, reply(500, {})) });
    assert.ok(unreadable.report.problems.includes("the run root is not empty after cleanup"));
    const slash = (n, answer) => {
      let seen = 0;
      return (req) =>
        isGcsList(req) && prefixOf(req) === `/${rootPrefix}` && (seen += 1) === n
          ? answer
          : undefined;
    };
    const other = await go({ recordings: 1, intercept: slash(3, leftover) });
    assert.ok(other.report.problems.includes("the run root is not empty after cleanup"));
  });

  it("checks the release and the ruleset list again at the end", async () => {
    const counted = await go({ recordings: 1 });
    const releaseGets = counted.world.calls.filter(
      (c) => isGet(c) && releaseUrl(c) && c.url.endsWith(bucket),
    ).length;
    let gets = 0;
    const drifted = await go({
      recordings: 1,
      intercept: (req) =>
        isGet(req) && releaseUrl(req) && req.url.endsWith(bucket) && (gets += 1) === releaseGets
          ? reply(200, {
              name: `projects/${project}/releases/firebase.storage/${bucket}`,
              rulesetName: `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
            })
          : undefined,
    });
    assert.ok(
      drifted.report.problems.includes("the bucket release is not the baseline at the end"),
    );
    assert.equal(counted.report.problems.length, 0);
    const extra = {
      rulesets: [
        {
          name: `projects/${project}/rulesets/99999999-0000-4000-8000-000000000000`,
          metadata: { services: ["firebase.storage"] },
        },
      ],
    };
    let lists = 0;
    const listed = await go({
      recordings: 1,
      intercept: (req) =>
        isGet(req) && rulesetsUrl(req) && (lists += 1) === 2 ? reply(200, extra) : undefined,
    });
    assert.ok(listed.report.problems.includes("the ruleset list is not what it was at entry"));
    let lists2 = 0;
    const unreadable = await go({
      recordings: 1,
      intercept: (req) =>
        isGet(req) && rulesetsUrl(req) && (lists2 += 1) === 2 ? reply(500, {}) : undefined,
    });
    assert.ok(unreadable.report.problems.includes("the ruleset list is not what it was at entry"));
    const entry = counted.out.saved["entry.json"];
    assert.equal(entry.baseline, baselineName);
    assert.equal(entry.entryRulesets.length, 2);
    assert.deepEqual(counted.out.saved["results.json"].agreement, []);
  });

  it("skips the final audit on a local target and records the masked requests of the rows", async () => {
    const { report } = await go({
      recordings: 1,
      rowFilter: only("list-pub-delim", "pub-plain-media", "pub-plain-meta"),
    });
    const byId = Object.fromEntries(report.rows.map((r) => [r.id, r]));
    assert.deepEqual(byId["list-pub-delim"].request, {
      method: "GET",
      kind: "v0-list",
      prefix: "<P>/pub/",
      delimiter: "/",
    });
    assert.deepEqual(byId["pub-plain-media"].request, {
      method: "GET",
      kind: "v0-media",
      name: "<P>/pub/x",
    });
    assert.deepEqual(byId["pub-plain-meta"].request, {
      method: "GET",
      kind: "v0-meta",
      name: "<P>/pub/x",
    });
    assert.equal(byId["pub-plain-meta"].answer.resource.bucket, "<bucket>");
    assert.equal(byId["pub-plain-meta"].answer.resource.name, "<P>/pub/x");
    const noDelimiter = await go({ recordings: 1, rowFilter: only("list-pub") });
    assert.equal(noDelimiter.report.rows[0].request.delimiter, null);
    const url = noDelimiter.world.calls.find(
      (c) => c.url.includes("/v0/") && c.url.includes("prefix="),
    );
    assert.ok(!url.url.includes("delimiter"));
  });

  it("reports the rows two recordings disagree on", async () => {
    let metaReads = 0;
    const { report } = await go({
      intercept: (req) =>
        isGet(req) &&
        isV0(req) &&
        pathOf(req).endsWith(`${P2}/pub/x`) &&
        !req.url.includes("alt=media") &&
        (metaReads += 1) === 1
          ? denied
          : undefined,
    });
    assert.deepEqual(report.disagreeing, ["pub-plain-meta"]);
    assert.equal(report.agreement.length, ROWS.length);
    assert.equal(report.agreement.filter((a) => !a.agree).length, 1);
    assert.equal(
      report.closureReady,
      true,
      "a disagreement is a finding, not a failure of the run",
    );
    const one = await go({ recordings: 1 });
    assert.deepEqual(one.report.agreement, []);
  });
});

const enc = encodeURIComponent;
const toBaselinePatch = (req) =>
  req.method === "PATCH" &&
  req.url.includes("/releases/") &&
  JSON.parse(Buffer.from(req.body)).release.rulesetName === baselineName;
/** A fresh intercept that refuses the first patch back to the baseline with 400. */
const refuseFirstBaselinePatch = () => {
  let refused = 0;
  return (req) => (toBaselinePatch(req) && (refused += 1) === 1 ? reply(400, {}) : undefined);
};
/** Total cap that lets everything before the request labelled `label` through and refuses that one. */
async function capBefore(label, options = {}) {
  const n = await requestNumber(label, options);
  return { main: 100_000, total: n - 1 };
}

describe("storage rules s9 local programs", () => {
  const local = { name: "local", bucket: LOCAL_BUCKET, origin: "http://127.0.0.1:9199" };
  const localDeps = (fake, intercept) => ({
    net: async (req) => (intercept && (await intercept(req))) || fake.net(req),
    adminHeaders: () => ({ authorization: "Bearer owner" }),
    sleep: async () => {},
  });

  it("records a program the emulator refuses to load and goes on with the others", async () => {
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    const out = sinks();
    const { report } = await observe({
      target: local,
      runId,
      baseline: "local",
      deps: localDeps(fake, (req) =>
        req.url.endsWith("/internal/setRules") && Buffer.from(req.body).includes("mk/b")
          ? reply(400, {})
          : undefined,
      ),
      out,
      recordings: 1,
    });
    assert.equal(report.stopped, null);
    assert.deepEqual(
      report.loads.find((l) => l.stage === "released-program"),
      {
        recording: 1,
        id: "units",
        stage: "released-program",
        compiled: false,
        status: 400,
      },
    );
    const units = report.rows.filter((r) => r.program === "units");
    assert.ok(
      units.length > 0 &&
        units.every(
          (r) =>
            r.class === "not-evaluated" &&
            r.why === "setRules answered 400" &&
            r.answer.status === null,
        ),
    );
    assert.deepEqual(
      report.publications.filter((p) => p.program).map((p) => p.program),
      ["s9", "lists"],
    );
    // A local run has no still-in-force reads and no Rules API.
    assert.ok(!out.entries.some((e) => /\/still\d/.test(e.label ?? "")));
    assert.ok(report.publications.filter((p) => p.program).every((p) => p.inForce === true));
  });
});

describe("storage rules s9 which marker a program supersedes", () => {
  const labels = (out) => out.entries.filter((e) => e.phase === "before").map((e) => e.label);

  it("reads the marker of the last program that was published, not of one that was skipped or refused", async () => {
    const skipped = await go({ recordings: 1, rowFilter: only("pub-plain-meta", "l0-true") });
    const skippedLabels = labels(skipped.out);
    assert.ok(
      skippedLabels.includes("rec1/lists/poll1/old"),
      "the lists program supersedes s9 although units was skipped",
    );
    assert.ok(!skippedLabels.includes("rec1/s9/poll1/old"));
    const refused = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "POST" && rulesetsUrl(req) && Buffer.from(req.body).includes("mk/b")
          ? reply(400, {})
          : undefined,
    });
    const refusedLabels = labels(refused.out);
    assert.ok(
      refusedLabels.includes("rec1/lists/poll1/old"),
      "a refused program leaves the earlier marker to be superseded",
    );
    assert.ok(!refusedLabels.includes("rec1/units/poll1/old"));
    const first = await go({
      recordings: 1,
      intercept: (req) =>
        req.method === "POST" && rulesetsUrl(req) && Buffer.from(req.body).includes("mk/a")
          ? reply(400, {})
          : undefined,
    });
    const firstLabels = labels(first.out);
    assert.ok(
      !firstLabels.some((l) => /^rec1\/units\/poll\d+\/old$/.test(l)),
      "nothing was published before units",
    );
    assert.ok(firstLabels.includes("rec1/lists/poll1/old"));
  });

  it("does not touch the release when no program has rows", async () => {
    const { world, report } = await go({ recordings: 1, rowFilter: only("no-such-row") });
    assert.equal(report.stopped, null);
    assert.equal(report.rows.length, 0);
    assert.equal(
      world.calls.filter(
        (c) => c.method === "PATCH" || (c.method === "POST" && c.url.endsWith("/releases")),
      ).length,
      0,
    );
    assert.equal(
      world.calls.filter((c) => isGet(c) && releaseUrl(c) && c.url.endsWith(bucket)).length,
      2,
      "the preflight read and the final audit only",
    );
  });
});

describe("storage rules s9 restore reads", () => {
  it("writes the baseline back when the release cannot be read at the restore", async () => {
    const n = await requestNumber("rec1/restore/read", { recordings: 1 });
    const { report, world } = await go({ recordings: 1, intercept: atRequest(n, reply(503, {})) });
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.equal(report.unknownReads, 1);
    assert.deepEqual(report.problems, []);
    assert.equal(world.calls.filter(toBaselinePatch).length, 1);
  });

  it("restores once more when the read-back of the restore cannot be read", async () => {
    const n = await requestNumber("rec1/restore/readback", { recordings: 1 });
    const { report, world } = await go({ recordings: 1, intercept: atRequest(n, reply(503, {})) });
    assert.deepEqual(report.problems, [
      "rec1/restore: the release did not read back as the baseline",
    ]);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.equal(report.unknownReads, 1);
    assert.equal(
      world.calls.filter(toBaselinePatch).length,
      1,
      "the cleanup read it, found the baseline and wrote nothing",
    );
  });

  it("settles the restore on the sixtieth poll and not on the sixty-first", async () => {
    const last = await go({
      recordings: 1,
      lag: SETTLE_MAX_POLLS - 2,
      rowFilter: only("pub-plain-meta"),
    });
    assert.equal(
      last.report.publications.find((p) => p.restoreSettlePolls).restoreSettlePolls,
      SETTLE_MAX_POLLS,
    );
    assert.deepEqual(last.report.problems, []);
  });

  it("says that an unknown release delete was not sent again, in the cleanup's words", async () => {
    const del = (req) =>
      req.method === "DELETE" && releaseUrl(req)
        ? (() => {
            throw new Error("reset");
          })()
        : undefined;
    const { report } = await go({ baseline: "absent", recordings: 1, intercept: del });
    assert.ok(
      report.problems.includes(
        "cleanup/restore: the release delete was unknown and is not re-sent",
      ),
      JSON.stringify(report.problems),
    );
    assert.ok(
      report.problems.includes("rec1/restore: unknown answer: rec1/restore/delete (transport)"),
    );
    assert.ok(
      report.problems.includes("cleanup/restore: the release did not read back as the baseline"),
    );
    assert.deepEqual(report.unknowns, ["rec1/restore/delete"]);
  });

  it("names the cleanup restore and the step in a failure of the cleanup restore", async () => {
    const { report } = await go({
      lag: 100000,
      recordings: 1,
      intercept: (req) => (toBaselinePatch(req) ? reply(403, {}) : undefined),
    });
    assert.ok(
      report.problems.includes(
        "cleanup/restore: cleanup/restore/patch: release write answered 403",
      ),
      JSON.stringify(report.problems),
    );
    assert.match(
      report.stopped,
      /^rec1\/s9: rec1\/s9: did not settle in 60 polls|did not settle in 60 polls/,
    );
  });

  it("restores and settles on the recording's prefix in the cleanup, after the first restore failed", async () => {
    const options = { recordings: 1, intercept: refuseFirstBaselinePatch() };
    const { report, world } = await go(options);
    assert.deepEqual(world.release, { rulesetName: baselineName });
    assert.ok(
      report.publications.some((p) => p.label === "cleanup/restore" && p.restoreSettlePolls === 3),
    );
    assert.deepEqual(
      report.problems,
      [
        "rec1/restore: the baseline release was refused",
        "rec1/restore: the release did not read back as the baseline",
        "rec1/restore: the last marker still answers 200 or unknown",
      ],
      "no ruleset delete was refused as in use: the rulesets are deleted after the restore",
    );
  });
});

describe("storage rules s9 cleanup order and labels", () => {
  it("names each cleanup delete and read by the end of the encoded object name", async () => {
    const { out } = await go({ recordings: 1 });
    const labels = new Set(out.entries.filter((e) => e.phase === "before").map((e) => e.label));
    for (const id of Object.keys(OBJECTS)) {
      const tail = enc(objectName(id, P1)).slice(-24);
      assert.ok(labels.has(`cleanup/delete/${tail}`), `delete ${id}`);
      assert.ok(labels.has(`cleanup/absent/${tail}`), `absent ${id}`);
    }
    for (const id of [1, 2, 3])
      assert.ok(
        labels.has(`cleanup/ruleset/0000000${id}-0000-4000-8000-000000000000`),
        `ruleset ${id}`,
      );
  });

  it("goes on after an unknown ruleset delete and after an unreadable absent read", async () => {
    const n = await requestNumber("cleanup/ruleset/00000001-0000-4000-8000-000000000000", {
      recordings: 1,
    });
    const unknown = await go({ recordings: 1, intercept: atRequest(n, "transport") });
    assert.deepEqual(unknown.report.unknowns, [
      "cleanup/ruleset/00000001-0000-4000-8000-000000000000",
    ]);
    assert.equal(unknown.report.closureReady, false);
    assert.deepEqual(
      [...unknown.world.rulesets.keys()].filter((k) => /\/0000000\d-/.test(k)),
      [`projects/${project}/rulesets/00000001-0000-4000-8000-000000000000`],
    );
    const m = await requestNumber(`cleanup/absent/${enc(objectName("pubPlain", P1)).slice(-24)}`, {
      recordings: 1,
    });
    const lost = await go({ recordings: 1, intercept: atRequest(m, reply(503, {})) });
    assert.deepEqual(lost.report.problems, ["an object still reads 503 after cleanup"]);
    assert.equal(lost.report.unknownReads, 1);
    assert.equal(
      lost.world.calls.filter(
        (c) =>
          isGet(c) &&
          c.url.includes("/storage/v1/") &&
          c.url.includes("/o/") &&
          !c.url.includes("prefix"),
      ).length,
      Object.keys(OBJECTS).length - 1,
      "every other name is read (the unreadable one never reached the world)",
    );
  });

  it("names the cleanup step that ran out of requests, and calls the run incomplete", async () => {
    for (const [label, step] of [
      ["cleanup/ruleset/00000001-0000-4000-8000-000000000000", "cleanup/rulesets"],
      ["cleanup/list", "cleanup/objects"],
      ["cleanup/delete/" + enc(objectName("mkA", P1)).slice(-24), "cleanup/objects"],
      ["final/release", "cleanup/audit"],
    ]) {
      const caps = await capBefore(label, { recordings: 1 });
      const { report } = await go({ recordings: 1, caps });
      assert.ok(
        report.problems.includes(`${step}: request budget exhausted`),
        `${step}: ${JSON.stringify(report.problems)}`,
      );
      assert.equal(report.stopped, `${step}: request budget exhausted`);
      assert.equal(report.rows.length, ROWS.length, "every row was read");
      assert.equal(report.complete, false, "a run that stopped is not complete, whatever it read");
      assert.equal(report.closureReady, false);
    }
    const n = await requestNumber("cleanup/restore/read", {
      recordings: 1,
      intercept: refuseFirstBaselinePatch(),
    });
    const { report } = await go({
      recordings: 1,
      intercept: refuseFirstBaselinePatch(),
      caps: { main: 100_000, total: n - 1 },
    });
    assert.ok(
      report.problems.includes("cleanup/restore: request budget exhausted"),
      JSON.stringify(report.problems),
    );
  });

  it("keeps an object that it created although the create answered with a body it could not read", async () => {
    const stale = nthRootList(2, reply(200, { kind: "storage#objects" }));
    const unreadable = await go({
      recordings: 1,
      intercept: async (req, inner) => {
        if (
          req.method === "POST" &&
          req.url.includes("/upload/") &&
          new URL(req.url).searchParams.get("name") === objectName("mkB", P1)
        ) {
          await inner(req);
          return reply(200, "{}");
        }
        return stale(req);
      },
    });
    assert.match(unreadable.report.stopped, /create of mkB answered 200 with an unrecorded body/);
    assert.ok(
      unreadable.report.problems.includes("an object still reads 200 after cleanup"),
      "the unconfirmed name is read back and found",
    );
    assert.deepEqual([...unreadable.world.objects.keys()], [objectName("mkB", P1)]);
    const dropped = await go({
      recordings: 1,
      intercept: async (req, inner) => {
        const name = new URL(req.url).searchParams.get("name");
        if (req.method === "POST" && name === objectName("s4a", P1)) {
          const res = await inner(req);
          const body = JSON.parse(res.body.toString("utf8"));
          delete body.metadata;
          return { ...res, body: Buffer.from(JSON.stringify(body)) };
        }
        return stale(req);
      },
    });
    assert.match(dropped.report.stopped, /did not keep the custom metadata/);
    assert.equal(
      dropped.world.objects.size,
      0,
      "the generation of the object it stopped on was known, so the stale list does not matter",
    );
  });
});

describe("storage rules s9 rows and masks", () => {
  it("records a row whose answer is unknown and goes on", async () => {
    const n = await requestNumber("row/1/pub-plain-meta", { recordings: 1 });
    const { report } = await go({ recordings: 1, intercept: atRequest(n, reply(503, "down")) });
    assert.equal(report.stopped, null);
    const row = report.rows.find((r) => r.id === "pub-plain-meta");
    assert.equal(row.class, "unknown");
    assert.equal(row.answer.status, 503);
    assert.equal(report.unknownReads, 1);
    assert.equal(report.rows.length, ROWS.length);
    const lostRow = await go({ recordings: 1, intercept: atRequest(n, "transport") });
    assert.equal(lostRow.report.rows.find((r) => r.id === "pub-plain-meta").class, "unknown");
    assert.equal(lostRow.report.stopped, null);
  });

  it("puts the delimiter in the list URL, and masks the run, the bucket and the project in answers", async () => {
    const n = await requestNumber("row/1/pub-plain-meta", {
      recordings: 1,
      rowFilter: only("pub-plain-meta", "list-pub-delim"),
    });
    const text = `${bucket} ${project} ${runId} ${P1}/x`;
    const { report, world } = await go({
      recordings: 1,
      rowFilter: only("pub-plain-meta", "list-pub-delim"),
      intercept: atRequest(n, reply(400, { error: { code: 400, message: text } })),
    });
    assert.equal(
      report.rows.find((r) => r.id === "pub-plain-meta").answer.error.message,
      "<bucket> <project> <run> <P>/x",
    );
    const list = world.calls.find((c) => c.url.includes("/v0/") && c.url.includes("delimiter"));
    assert.ok(list.url.endsWith("&delimiter=%2F"), list.url);
  });

  it("computes the agreement of two recordings from one row each, and counts the entry rulesets", async () => {
    const { report } = await go({ rowFilter: only("pub-plain-meta") });
    assert.equal(report.agreement.length, 1);
    assert.equal(report.entryRulesets, 2);
    assert.equal(report.complete, true);
    assert.equal(report.runId, runId);
    assert.equal(report.target, "production");
    assert.equal(report.baseline, baselineName);
    assert.equal(report.requests, report.out?.requests ?? report.requests);
  });

  it("gives a row of an object it could not create the reason", async () => {
    const collide = (req) =>
      req.method === "POST" &&
      req.url.includes("/upload/") &&
      new URL(req.url).searchParams.get("name") === objectName("pubTrailing", P1)
        ? reply(412, {})
        : undefined;
    const { report } = await go({ recordings: 1, intercept: collide });
    const row = report.rows.find((r) => r.id === "pub-trailing-meta");
    assert.equal(row.why, "the object could not be created");
    assert.equal(row.class, "not-evaluated");
  });

  it("does not read a bucket whose answer is not a 200", async () => {
    const fault = (req) =>
      isGet(req) && req.url.endsWith(`/b/${bucket}`) ? reply(404, { name: bucket }) : undefined;
    const { report, world } = await go({ recordings: 1, intercept: fault });
    assert.match(report.stopped, /the bucket is not the expected one/);
    assert.equal(world.calls.filter((c) => c.method !== "GET").length, 0);
  });

  it("reads the final release as a read: an unreadable answer is a finding, and the ruleset list is still checked", async () => {
    const n = await requestNumber("final/release", { recordings: 1 });
    const { report, out } = await go({ recordings: 1, intercept: atRequest(n, reply(503, {})) });
    assert.deepEqual(report.problems, ["the bucket release is not the baseline at the end"]);
    assert.ok(out.entries.some((e) => e.label === "final/rulesets"));
    const m = await requestNumber("final/rulesets", { recordings: 1 });
    const second = await go({ recordings: 1, intercept: atRequest(m, reply(503, {})) });
    assert.deepEqual(second.report.problems, ["the ruleset list is not what it was at entry"]);
  });
});

/** Answers the nth GCS list of the root prefix. */
function nthRootList(n, answer) {
  let seen = 0;
  return (req) =>
    isGcsList(req) && prefixOf(req) === rootPrefix && (seen += 1) === n ? answer : undefined;
}
