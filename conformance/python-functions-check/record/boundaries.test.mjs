// Boundaries and exact values the other tests did not pin: the allowlist's limits, the filter window forms, the names and
// waits, the read-back's paging and settle time, and the deploy helpers that touch the disk. Found by mutation testing
// the first version of the suite; each test names what its mutant would have changed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { discover, prepareSource, sourceProblems, summarize } from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { errorFilter, frameFilter } from "./logs.mjs";
import {
  CHANNEL,
  DELIVERY_WINDOW_SECONDS,
  LOG_DELAY_SECONDS,
  PROPAGATION_WAIT_SECONDS,
  STEP_GAP_SECONDS,
  jobName,
  queueName,
  topicName,
  triggerSubscriptionPrefix,
} from "./plan.mjs";
import { READBACK_MAX_REQUESTS, SETTLE_MS, readbackRun } from "./readback.mjs";
import { operations } from "./script.mjs";
import { READY_MAX_POLLS, READY_POLL_SECONDS } from "./deploy.mjs";
import { PRODUCTION_FRAMES, BUCKET, NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const P = "fireemu-oracle-events";
const guard = createGuard(RUN, NUMBER);
const ok = (spec) => guard.allow(spec);

// ---- plan and script: exact names and waits ------------------------------------------------------------

test("names are exact strings", () => {
  assert.equal(jobName("j"), `projects/${P}/locations/us-central1/jobs/j`);
  assert.equal(queueName("q"), `projects/${P}/locations/us-central1/queues/q`);
  assert.equal(topicName("t"), `projects/${P}/topics/t`);
  assert.equal(triggerSubscriptionPrefix, "eventarc-us-central1-");
  assert.equal(CHANNEL, "firebase");
});

test("the waits and the read-back limits are the packet's stated values", () => {
  assert.deepEqual(
    [PROPAGATION_WAIT_SECONDS, DELIVERY_WINDOW_SECONDS, LOG_DELAY_SECONDS, STEP_GAP_SECONDS],
    [90, 180, 120, 5],
  );
  assert.deepEqual([READY_POLL_SECONDS, READY_MAX_POLLS], [30, 40]);
  assert.equal(SETTLE_MS, 600_000);
  assert.equal(READBACK_MAX_REQUESTS, 130);
});

test("the document the check writes holds the run marker and n, then n 2", () => {
  const ops = operations({ runId: RUN, bucket: BUCKET, targets: {} });
  assert.deepEqual(ops[0].request.json.fields, {
    run: { stringValue: "pcrun-" + RUN },
    n: { integerValue: "1" },
  });
  assert.deepEqual(ops[1].request.json.fields, { n: { integerValue: "2" } });
});

// ---- the allowlist's limits --------------------------------------------------------------------------

const BUILD = (id) => ({
  method: "GET",
  url: `https://cloudbuild.googleapis.com/v1/projects/${NUMBER}/locations/us-central1/builds/${id}`,
});
test("a Cloud Build read needs a UUID build id, exactly", () => {
  assert.equal(ok(BUILD("01234567-89ab-cdef-0123-456789abcdef")), true);
  assert.equal(
    ok(BUILD("00000000-0000-0000-0000-000000000000")),
    true,
    "zero is a digit in every group",
  );
  assert.equal(ok(BUILD("ffffffff-ffff-ffff-ffff-ffffffffffff")), true);
  for (const bad of [
    "0123456-89ab-cdef-0123-456789abcdef",
    "012345678-89ab-cdef-0123-456789abcdef",
    "01234567-89a-cdef-0123-456789abcdef",
    "01234567-89abc-cdef-0123-456789abcdef",
    "01234567-89ab-cde-0123-456789abcdef",
    "01234567-89ab-cdefg-0123-456789abcdef",
    "01234567-89ab-cdef-012-456789abcdef",
    "01234567-89ab-cdef-01234-456789abcdef",
    "01234567-89ab-cdef-0123-456789abcde",
    "01234567-89ab-cdef-0123-456789abcdef0",
  ])
    assert.equal(ok(BUILD(bad)), false, bad);
});

test("a page token may be 2048 characters and no more, and only URL-safe ones", () => {
  const list = (token) => ({
    method: "GET",
    url: `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/-/functions?pageToken=${token}`,
  });
  assert.equal(ok(list("a".repeat(2048))), true);
  assert.equal(ok(list("a".repeat(2049))), false);
  assert.equal(ok(list("a b")), false);
  assert.equal(ok(list("")), false);
});

test("list page sizes are limited to the ones the check asks for", () => {
  const url = (host, path, size) => ({
    method: "GET",
    url: `https://${host}${path}?pageSize=${size}`,
  });
  const pkgs = `/v1/projects/${P}/locations/us-central1/repositories/gcf-artifacts/packages`;
  assert.equal(ok(url("artifactregistry.googleapis.com", pkgs, 100)), true);
  assert.equal(ok(url("artifactregistry.googleapis.com", pkgs, 101)), false);
  const repos = `/v1/projects/${P}/locations/us-central1/repositories`;
  assert.equal(ok(url("artifactregistry.googleapis.com", repos, 100)), true);
  assert.equal(ok(url("artifactregistry.googleapis.com", repos, 101)), false);
  assert.equal(
    ok(url("cloudscheduler.googleapis.com", `/v1/projects/${P}/locations/us-central1/jobs`, 500)),
    true,
  );
  assert.equal(
    ok(url("cloudscheduler.googleapis.com", `/v1/projects/${P}/locations/us-central1/jobs`, 501)),
    false,
  );
});

test("an IAM policy read takes no body or an empty one, and a body must be a plain object", () => {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getIamPolicy`;
  assert.equal(ok({ method: "POST", url }), true);
  assert.equal(ok({ method: "POST", url, json: {} }), true);
  assert.equal(ok({ method: "POST", url, json: { a: 1 } }), false);
  assert.equal(ok({ method: "POST", url, json: [] }), false);
  assert.equal(ok({ method: "POST", url, json: null }), false);
  assert.equal(ok({ method: "POST", url, json: "x" }), false);
});

test("the source writes take exactly their own fields", () => {
  const doc = `https://firestore.googleapis.com/v1/projects/${P}/databases/(default)/documents/pycheck-src`;
  const id = `pcrun-${RUN}-a`;
  const create = (json) => ({ method: "POST", url: `${doc}?documentId=${id}`, json });
  assert.equal(ok(create({ fields: { run: { stringValue: "pcrun-" + RUN } } })), true);
  assert.equal(ok(create({ fields: { run: { stringValue: "other" } } })), false);
  assert.equal(ok(create({ fields: {}, extra: 1 })), false);
  assert.equal(ok(create({ extra: 1, fields: { run: { stringValue: "pcrun-" + RUN } } })), false);
  assert.equal(ok(create([])), false);
  const patch = (json) => ({
    method: "PATCH",
    url: `${doc}/${id}?updateMask.fieldPaths=n&currentDocument.exists=true`,
    json,
  });
  assert.equal(ok(patch({ fields: { n: { integerValue: "2" } } })), true);
  assert.equal(ok(patch({ fields: { n: { integerValue: "2" }, other: 1 } })), false);
  assert.equal(ok(patch({ fields: { n: 1 }, extra: 1 })), false);
  assert.equal(ok(patch({ extra: 1 })), false);
  const upload = (json) => ({
    method: "POST",
    url: `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=pycheck%2Fpcrun-${RUN}-a.json`,
    json,
  });
  assert.equal(ok(upload({ run: "pcrun-" + RUN })), true);
  assert.equal(ok(upload({ run: "other" })), false);
  assert.equal(ok(upload({ run: "pcrun-" + RUN, extra: 1 })), false);
  assert.equal(ok(upload({ extra: 1 })), false);
  assert.equal(ok(upload([])), false);
});

test("the log read has a size limit on the filter and the page", () => {
  const read = (over) => ({
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    json: {
      resourceNames: ["projects/" + P],
      filter: "x",
      orderBy: "timestamp asc",
      pageSize: 200,
      ...over,
    },
  });
  assert.equal(ok(read({})), true);
  assert.equal(ok(read({ filter: "x".repeat(5999) })), true);
  assert.equal(ok(read({ filter: "x".repeat(6000) })), false);
  assert.equal(ok(read({ pageSize: 201 })), false);
  assert.equal(ok(read({ pageSize: 1 })), true);
  assert.equal(ok(read({ orderBy: "timestamp desc" })), false);
});

test("a URL with only a user name, only a password, or a fragment is refused on its own", () => {
  const path = `/v2/projects/${P}/locations/us-central1/functions`;
  assert.equal(ok({ method: "GET", url: `https://cloudfunctions.googleapis.com${path}` }), true);
  assert.equal(
    ok({ method: "GET", url: `https://user@cloudfunctions.googleapis.com${path}` }),
    false,
  );
  assert.equal(
    ok({ method: "GET", url: `https://:pw@cloudfunctions.googleapis.com${path}` }),
    false,
  );
  assert.equal(ok({ method: "GET", url: `https://cloudfunctions.googleapis.com${path}#f` }), false);
  assert.equal(ok({ method: "GET", url: `http://cloudfunctions.googleapis.com${path}` }), false);
});

// ---- the log filters ---------------------------------------------------------------------------------

test("a window time may carry one to nine fraction digits, not ten, and the error filter has both bounds", () => {
  const at = (start) => () => frameFilter({ start, end: "2026-11-05T00:05:00Z" });
  assert.doesNotThrow(at("2026-11-05T00:00:00.1Z"));
  assert.doesNotThrow(at("2026-11-05T00:00:00.123456789Z"));
  assert.throws(at("2026-11-05T00:00:00.1234567890Z"), /RFC 3339/);
  assert.throws(at("2026-11-05T00:00:00.Z"), /RFC 3339/);
  const window = { start: "2026-11-05T00:00:00Z", end: "2026-11-05T00:05:00Z" };
  const filter = errorFilter(window);
  assert.ok(
    filter.includes('timestamp>="2026-11-05T00:00:00Z"') &&
      filter.includes('timestamp<="2026-11-05T00:05:00Z"'),
  );
  assert.ok(filter.includes("severity>=ERROR"));
  assert.ok(
    frameFilter(window).includes('timestamp<="2026-11-05T00:05:00Z"') &&
      frameFilter(window).includes('timestamp>="2026-11-05T00:00:00Z"'),
  );
});

// ---- the judge: what it records beside the verdict ------------------------------------------------------

const SENT = Object.fromEntries(
  [
    "fs-create",
    "fs-update",
    "ps-plain",
    "ps-ordered",
    "st-upload",
    "ea-fraction",
    "ea-whole",
    "sched-pcsch",
    "sched-pcschraw",
    "task-pctask",
    "task-pctaskraw",
  ].map((k) => [k, {}]),
);
const base = () =>
  JSON.parse(JSON.stringify(PRODUCTION_FRAMES).replaceAll("pcrun-RUNID", "pcrun-" + RUN)).map(
    (frame) => ({ frame }),
  );
const judged = (frames, sent = SENT) => judge({ runId: RUN, frames, sent });

test("a not-sent case names the operations that were not sent", () => {
  const { "fs-create": _a, "fs-update": _b, ...rest } = SENT;
  const r = judged(base(), rest);
  assert.deepEqual(r.cases["firestore-protobuf"].notes, ["fs-create"]);
  assert.deepEqual(r.cases["firestore-sdk"].notes, ["fs-create", "fs-update"]);
});

test("the verdicts keep what they observed and what they expected", () => {
  const r = judged(base());
  assert.deepEqual(r.cases["firestore-sdk"].expected, {
    created: { n: 1 },
    before: { n: 1 },
    after: { n: 2 },
  });
  assert.deepEqual(r.cases["firestore-sdk"].observed, {
    created: { n: 1, run: "pcrun-" + RUN },
    before: { n: 1, run: "pcrun-" + RUN },
    after: { n: 2, run: "pcrun-" + RUN },
  });
  assert.deepEqual(
    r.cases["firestore-attributes"].observed.extra.toSorted(),
    ["datacontenttype", "traceparent"].filter((n) => n !== "datacontenttype"),
  );
  assert.deepEqual(r.cases["storage-time"].expected, { fractionDigits: ">0" });
  assert.equal(r.cases["storage-time"].observed.sdkFrames, 1);
  assert.equal(r.cases["eventarc-time-fraction"].observed.sdkRan, true);
  assert.equal(
    r.cases["eventarc-time-whole"].observed.sdkRan,
    false,
    "the SDK function printed nothing for the whole-second time",
  );
  assert.equal(r.cases["scheduler-request"].observed.sdkJob, "firebase-schedule-pcsch-us-central1");
  assert.match(r.cases["scheduler-request"].observed.sdkTime, /^2026-/);
  assert.equal(r.cases["scheduler-request"].observed.sdkFrames, 1);
  assert.equal(r.cases["sdk-versions"].observed.versions["firebase-functions"], "0.6.0");
  assert.deepEqual(r.cases["sdk-versions"].observed.sdkVersionsSeen, ["0.6.0"]);
});

test("one fraction digit counts as a fraction, and an SDK function that did not run is a difference", () => {
  const frames = base();
  frames.find((e) => e.frame.function === "pcstraw").frame.attributes.time =
    "2026-11-05T00:00:00.5Z";
  assert.equal(judged(frames).cases["storage-time"].status, "as-expected");
  const noSdk = base().filter((e) => e.frame.function !== "pcst");
  assert.deepEqual(judged(noSdk).cases["storage-time"].notes, ["sdk-ran"]);
});

test("scheduler frames are found by their request, whether or not they carry a run marker", () => {
  const frames = base();
  for (const e of frames) if (e.frame.function.startsWith("pcsch")) delete e.frame.run;
  const r = judged(frames);
  assert.equal(r.cases["scheduler-request"].status, "as-expected");
  assert.equal(r.cases["scheduler-request"].observed.sdkFrames, 1);
  const stray = base();
  stray.unshift({
    frame: {
      function: "pcschraw",
      kind: "raw-event",
      run: null,
      request: { headers: { "x-cloudscheduler": "true" } },
      versions: {},
    },
  });
  stray.unshift({
    frame: {
      function: "pcschraw",
      kind: "raw-request",
      run: null,
      request: { headers: {} },
      versions: {},
    },
  });
  assert.equal(
    judged(stray).cases["scheduler-request"].status,
    "as-expected",
    "only a raw request that carries the scheduler header is the delivery",
  );
});

// ---- the read-back: paging, ids, errors -------------------------------------------------------------------

async function pagedReadback(pages) {
  const world = createWorld({ runId: RUN });
  const urls = [];
  const rows = [];
  let jobPages = 0;
  const result = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async (row) => rows.push(row),
    clock: () => world.now,
    send: async (request) => {
      if (
        /\/jobs(\?|$)/.test(request.url) &&
        request.method === "GET" &&
        !/\/jobs\/[^/]/.test(request.url)
      ) {
        urls.push(request.url);
        jobPages++;
        return reply(200, jobPages < pages ? { nextPageToken: "tok" + jobPages } : {});
      }
      return world.send(request);
    },
  });
  return { result, urls, rows };
}

test("a list may span five pages and no more, and each page after the first is asked for by token", async () => {
  const five = await pagedReadback(5);
  assert.equal(five.result.incompleteReads.length, 0);
  assert.equal(five.urls.length, 5);
  const six = await pagedReadback(6);
  assert.equal(six.urls.length, 5, "a sixth page is never read");
  assert.ok(
    six.result.incompleteReads.some(
      (r) => r.id === "list-jobs" && r.status === "more-than-five-pages",
    ),
  );
  assert.equal(six.result.allAbsent, false);
  assert.match(five.urls[0], /\/jobs\?pageSize=500$/);
  assert.match(
    five.urls[1],
    /\/jobs\?pageSize=500&pageToken=tok1$/,
    "a list that has a query takes the token with &",
  );
  const ids = five.rows
    .filter((r) => r.state === "before-send" && r.id.startsWith("list-jobs"))
    .map((r) => r.id);
  assert.deepEqual(ids, [
    "list-jobs",
    "list-jobs-page-2",
    "list-jobs-page-3",
    "list-jobs-page-4",
    "list-jobs-page-5",
  ]);
  assert.ok(five.rows.some((r) => r.id === "readback-function-pcps" && r.state === "before-send"));
  assert.ok(five.rows.some((r) => r.id === "readback-topic"));
});

test("a list without a query takes the page token with a question mark", async () => {
  const world = createWorld({ runId: RUN });
  const seen = [];
  let first = true;
  await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: async (request) => {
      if (request.url.includes("/v2/projects/") && request.url.includes("/locations/-/functions")) {
        seen.push(request.url);
        if (first) {
          first = false;
          return reply(200, { nextPageToken: "abc" });
        }
      }
      return world.send(request);
    },
  });
  assert.ok(
    seen.some((u) => u.endsWith("/functions?pageToken=abc")),
    seen.join("\n"),
  );
});

test("the lists are judged on their own: the topic in the topics list alone keeps the read-back from saying all gone", async () => {
  const world = createWorld({ runId: RUN });
  world.topics.add("pycheck-orders");
  const direct = `GET pubsub.googleapis.com/v1/projects/${P}/topics/pycheck-orders`;
  const result = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: async (request) => {
      const u = new URL(request.url);
      if (request.method + " " + u.hostname + u.pathname === direct)
        return reply(404, { error: { code: 404, status: "NOT_FOUND" } });
      return world.send(request);
    },
  });
  assert.deepEqual(result.lists.topics, ["pycheck-orders"]);
  assert.equal(result.allAbsent, false);
  const other = createWorld({ runId: RUN });
  other.topics.add("someone-elses");
  const clean = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => other.now,
    send: other.send,
  });
  assert.deepEqual(clean.lists.topics, []);
  assert.equal(clean.allAbsent, true);
});

test("the functions and the Cloud Run services must both be listed", async () => {
  for (const host of ["cloudfunctions.googleapis.com", "run.googleapis.com"]) {
    const world = createWorld({ runId: RUN });
    const result = await readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      bucket: BUCKET,
      accessToken: "tok-abcdefgh",
      save: async () => {},
      clock: () => world.now,
      send: async (request) =>
        new URL(request.url).hostname === host && request.url.includes("/locations/-/")
          ? reply(500, { error: { status: "INTERNAL" } })
          : world.send(request),
    });
    assert.equal(result.lists.functionsAndServices, false, host);
    assert.equal(result.allAbsent, false);
  }
});

test("an unknown answer is counted, and an error that is not a stop is not swallowed", async () => {
  const world = createWorld({ runId: RUN });
  const result = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: async (request) => {
      if (new URL(request.url).pathname.endsWith("/queues/pctask") && request.method === "GET")
        throw new Error("reset");
      return world.send(request);
    },
  });
  assert.equal(result.unknown, 1);
  assert.equal(result.allAbsent, false);
  await assert.rejects(
    readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      bucket: BUCKET,
      accessToken: "tok-abcdefgh",
      save: async () => {
        throw new Error("disk full");
      },
      clock: () => world.now,
      send: world.send,
    }),
    /private persistence failed/,
  );
});

// ---- deploy: what touches the disk -------------------------------------------------------------------

function repoWithFixture() {
  const repo = mkdtempSync(join(tmpdir(), "pc-repo-"));
  const env = {
    PATH: process.env.PATH,
    HOME: repo,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_AUTHOR_NAME: "t",
    GIT_AUTHOR_EMAIL: "t@example.com",
    GIT_COMMITTER_NAME: "t",
    GIT_COMMITTER_EMAIL: "t@example.com",
  };
  const git = (...args) =>
    execFileSync("git", ["-C", repo, ...args], { env, encoding: "utf8" }).trim();
  mkdirSync(join(repo, "conformance/python-functions-check/fixture"), { recursive: true });
  mkdirSync(join(repo, "conformance/other"), { recursive: true });
  writeFileSync(join(repo, "conformance/python-functions-check/firebase.json"), "{}");
  writeFileSync(join(repo, "conformance/python-functions-check/fixture/main.py"), "x = 1\n");
  writeFileSync(join(repo, "conformance/other/file"), "no");
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", "c");
  writeFileSync(join(repo, "conformance/python-functions-check/untracked.txt"), "u");
  return { repo, sha: git("rev-parse", "HEAD") };
}

test("the source copy takes the tracked files of the check at the commit, links the venv, and nothing else", () => {
  const { repo, sha } = repoWithFixture();
  const target = join(mkdtempSync(join(tmpdir(), "pc-target-")), "nested", "source");
  const venv = mkdtempSync(join(tmpdir(), "pc-venv-"));
  const { configPath, fixtureDir } = prepareSource({
    repoRoot: repo,
    commit: sha,
    target,
    venvDir: venv,
  });
  assert.equal(configPath, join(target, "conformance/python-functions-check/firebase.json"));
  assert.equal(readFileSync(join(fixtureDir, "main.py"), "utf8"), "x = 1\n");
  assert.equal(existsSync(join(target, "conformance/other")), false);
  assert.equal(
    existsSync(join(target, "conformance/python-functions-check/untracked.txt")),
    false,
    "untracked files do not come along",
  );
  assert.equal(lstatSync(join(fixtureDir, "venv")).isSymbolicLink(), true);
  assert.equal(lstatSync(target).mode & 0o777, 0o700);
  const none = prepareSource({
    repoRoot: repo,
    commit: sha,
    target: join(target, "again"),
    venvDir: undefined,
  });
  assert.equal(existsSync(join(none.fixtureDir, "venv")), false);
});

test("a forty-character hexadecimal commit passes the shape check, and forty-one does not", () => {
  const target = mkdtempSync(join(tmpdir(), "pc-sha-"));
  assert.throws(
    () => prepareSource({ repoRoot: "/nonexistent-repo", commit: "a".repeat(40), target }),
    (e) => !/full SHA/.test(e.message),
  );
  assert.throws(
    () => prepareSource({ repoRoot: "/nonexistent-repo", commit: "a".repeat(41), target }),
    /full SHA/,
  );
  assert.throws(
    () => prepareSource({ repoRoot: "/nonexistent-repo", commit: "a".repeat(39), target }),
    /full SHA/,
  );
});

function fakeVenv(script) {
  const fixture = mkdtempSync(join(tmpdir(), "pc-fixture-"));
  mkdirSync(join(fixture, "venv/bin"), { recursive: true });
  writeFileSync(join(fixture, "venv/bin/python"), script);
  chmodSync(join(fixture, "venv/bin/python"), 0o755);
  return fixture;
}

test("the discovery runs the venv's Python isolated, in the fixture, with the project settings only", () => {
  const fixture = fakeVenv(
    `#!/bin/sh\nprintf '{"first":"%s","pp":"%s","cwd":"%s","fc":%s,"gp":"%s","home":"%s"}' "$1" "$PYTHONPATH" "$(pwd -P)" "$FIREBASE_CONFIG" "$GCLOUD_PROJECT" "$HOME"\n`,
  );
  const directory = join(mkdtempSync(join(tmpdir(), "pc-dir-")), "made", "here");
  const out = discover({ fixtureDir: fixture, directory });
  assert.equal(out.first, "-I");
  assert.equal(out.pp, fixture);
  assert.equal(
    out.cwd,
    execFileSync("sh", ["-c", `cd ${fixture} && pwd -P`], { encoding: "utf8" }).trim(),
  );
  assert.deepEqual(out.fc, { projectId: P, storageBucket: P + ".firebasestorage.app" });
  assert.equal(out.gp, P);
  assert.equal(out.home, directory);
  assert.equal(lstatSync(directory).mode & 0o777, 0o700);
});

test("an offline discovery failure keeps only the first 300 characters of the error", () => {
  const fixture = fakeVenv(`#!/bin/sh\nprintf '%s' "${"E".repeat(400)}" >&2\nexit 3\n`);
  const [problem] = sourceProblems({
    fixtureDir: fixture,
    directory: mkdtempSync(join(tmpdir(), "pc-dir-")),
  });
  assert.equal(problem.length, "the SDK discovery of the fixture failed: ".length + 300);
});

test("another function is not a stray of this one", () => {
  const other = {
    v2: {
      functions: [{ name: `projects/${P}/locations/us-central1/functions/pcst`, state: "ACTIVE" }],
    },
    run: { services: [] },
  };
  const summary = summarize(other);
  assert.equal(summary.pcps.stray, false);
  assert.equal(summary.pcst.present, true);
  assert.equal(summary.pcst.stray, false);
});

test("a commit hash with zeros in it passes the shape check", () => {
  const target = mkdtempSync(join(tmpdir(), "pc-sha0-"));
  for (const sha of ["0123456789abcdef0123456789abcdef01234567", "0".repeat(40)])
    assert.throws(
      () => prepareSource({ repoRoot: "/nonexistent-repo", commit: sha, target }),
      (e) => !/full SHA/.test(e.message),
      sha,
    );
});
