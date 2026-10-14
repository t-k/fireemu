// Properties of the FS-3 recorder's pure decisions, over seeded random inputs (the repository has
// no property-testing library for Node, and the owner's rule is to add none without a decision).
// Every generator is deterministic: a failing case is reproduced by its seed and round.

import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext, isTransient, sameRecording, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { countRequests, PROGRAMS, REQUEST_CAP, validateCorpus } from "./fs-rules-v1/corpus.mjs";
import {
  brief,
  classify,
  estimatedUsd,
  fixtureText,
  harnessDigest,
  HARNESS_FILES,
  openRuns,
  otherLanesRecently,
  preflightProblems,
  recentAbort,
  TASK_ID,
} from "./fs-rules-v1/judge.mjs";
import { guardHarnessRequest, summarizeListen } from "./fs-rules-v1/session.mjs";

const ROUNDS = 300;

/** mulberry32: a small seeded generator. */
function generator(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n) => Math.floor(next() * n);
  const pick = (items) => items[int(items.length)];
  const bool = (p = 0.5) => next() < p;
  return { next, int, pick, bool };
}

const forEachRound = (seed, body) => {
  const random = generator(seed);
  for (let round = 0; round < ROUNDS; round += 1) {
    try {
      body(random, round);
    } catch (error) {
      error.message = `seed ${seed} round ${round}: ${error.message}`;
      throw error;
    }
  }
};

// ---- recordings ----------------------------------------------------------------------------

/** A random JSON value shaped like a recorded body. */
function value(random, depth = 0) {
  const kind = depth > 2 ? random.int(3) : random.int(6);
  switch (kind) {
    case 0:
      return random.pick(["a", "b", "PERMISSION_DENIED", "projects/p/x", ""]);
    case 1:
      return random.int(5);
    case 2:
      return random.bool();
    case 3:
      return Array.from({ length: random.int(4) }, () => value(random, depth + 1));
    default:
      return Object.fromEntries(
        Array.from({ length: random.int(4) }, () => [
          random.pick(["name", "fields", "n", "error", "document", "status"]),
          value(random, depth + 1),
        ]),
      );
  }
}

/** A recorded row that is neither transient nor unresolved. */
const row = (random) => ({
  status: random.pick([200, 200, 403, 404]),
  body: value(random),
});

/** The same value with every object's keys in another order. */
function shuffled(random, v) {
  if (Array.isArray(v)) return v.map((item) => shuffled(random, item));
  if (v && typeof v === "object") {
    const keys = Object.keys(v).toSorted(() => random.next() - 0.5);
    return Object.fromEntries(keys.map((key) => [key, shuffled(random, v[key])]));
  }
  return v;
}

const TRANSIENT = [
  { status: 0, transport: "ETIMEDOUT" },
  { status: 429, body: {} },
  { status: 500, body: {} },
  { status: 503, body: {} },
  { grpc: 14 },
  { grpc: 13 },
  { grpc: 8 },
  { grpc: 4 },
  { status: 200, body: [], publication: "unsettled" },
  { status: -1, unresolved: "x", dependencyTransient: true },
];

test("a row equals itself in any key order, and differs from a different row (property)", () => {
  forEachRound(1, (random) => {
    const x = row(random);
    assert.equal(classify({ row: "p#s", production: x, fireemu: shuffled(random, x) }), "MATCH");
    const y = row(random);
    const expected = sameRecording(x, y) ? "MATCH" : "MISMATCH";
    assert.equal(classify({ row: "p#s", production: x, fireemu: y }), expected);
  });
});

test("a transient answer on any side makes a row indeterminate, and staleness comes first (property)", () => {
  forEachRound(2, (random) => {
    const t = random.pick(TRANSIENT);
    assert.ok(isTransient(t), JSON.stringify(t));
    const x = row(random);
    for (const [production, alternative, fireemu] of [
      [t, undefined, x],
      [x, undefined, t],
      [x, t, x],
    ])
      assert.equal(classify({ row: "p#s", production, alternative, fireemu }), "INDETERMINATE");
    assert.equal(classify({ row: "p#s", stale: true, production: t, fireemu: x }), "STALE_FIXTURE");
    assert.equal(classify({ row: "p#s", production: undefined, fireemu: t }), "MISSING_FIXTURE");
    assert.equal(classify({ row: "p#s", production: x, fireemu: undefined }), "MISSING");
  });
});

test("two production recordings that differ are never a match unless the row is listed (property)", () => {
  forEachRound(3, (random) => {
    const x = row(random);
    const y = row(random);
    const fireemu = random.pick([x, y]);
    // A second recording equal to the first is the same answer; a different one is not.
    const same = sameRecording(x, y);
    assert.equal(
      classify({ row: "p#s", production: x, alternative: y, fireemu }),
      same ? "MATCH" : "INDETERMINATE",
    );
    const listed = classify(
      { row: "p#s", production: x, alternative: y, fireemu },
      { "p#s": "why" },
    );
    // The row is listed and fireemu equals one of the two recordings.
    assert.equal(listed, same ? "MATCH" : "MATCH_NONDETERMINISTIC");
    const neither = row(random);
    if (!sameRecording(neither, x) && !sameRecording(neither, y))
      assert.equal(
        classify({ row: "p#s", production: x, alternative: y, fireemu: neither }, { "p#s": "why" }),
        "MISMATCH",
      );
  });
});

test("brief never throws and always says something, whatever shape it is given (property)", () => {
  forEachRound(4, (random) => {
    const recorded = random.pick([
      row(random),
      random.pick(TRANSIENT),
      { grpc: random.int(16), messages: value(random) },
      { compiled: random.bool() },
      { status: -1, unresolved: "x" },
      {
        listen: true,
        frames: [
          {
            kind: random.pick(["targetChange", "documentChange", "boundary", "filter"]),
            type: "ADD",
          },
        ],
        end: "open",
      },
    ]);
    const text = brief(recorded);
    assert.equal(typeof text, "string");
    assert.ok(text.length > 0);
  });
});

// ---- Listen rows ---------------------------------------------------------------------------

const ctx = createContext({
  run: "1790000000000",
  target: {
    kind: "production",
    adminToken: "ya29.t",
    apiKey: "k",
    quotaProject: SANDBOX_PROJECT,
    projectNumber: "555500000001",
  },
});
const ROOT = `projects/${SANDBOX_PROJECT}/databases/(default)/documents`;

function frames(random) {
  return Array.from({ length: random.int(12) }, (_, i) => {
    const kind = random.pick([
      "add",
      "current",
      "heartbeat",
      "heartbeat",
      "doc",
      "doc",
      "doc",
      "remove",
      "filter",
    ]);
    switch (kind) {
      case "add":
        return {
          at: i,
          kind: "targetChange",
          targetChange: { targetChangeType: "ADD", targetIds: [1], resumeToken: "a" },
        };
      case "current":
        return {
          at: i,
          kind: "targetChange",
          targetChange: { targetChangeType: "CURRENT", targetIds: [1], resumeToken: "c" },
        };
      case "heartbeat":
        return {
          at: i,
          kind: "targetChange",
          targetChange: { targetChangeType: "NO_CHANGE", resumeToken: random.bool() ? "h" : "" },
        };
      case "doc":
        return {
          at: i,
          kind: "documentChange",
          documentChange: {
            document: {
              name: `${ROOT}/p/d${random.int(9)}`,
              fields: { n: { integerValue: String(random.int(3)) } },
            },
            targetIds: [1],
          },
        };
      case "remove":
        return {
          at: i,
          kind: "targetChange",
          targetChange: {
            targetChangeType: "REMOVE",
            targetIds: [1],
            cause: { code: 7, message: "denied" },
          },
        };
      default:
        return { at: i, kind: "filter", filter: { targetId: 1, count: random.int(4) } };
    }
  });
}

test("Listen rows: arrival order kept, heartbeats collapsed, nothing else dropped or merged (property)", () => {
  forEachRound(5, (random) => {
    const input = frames(random);
    const rows = summarizeListen(input, undefined, ctx, new Map()).frames;
    for (let i = 1; i < rows.length; i += 1)
      assert.ok(
        !(rows[i].kind === "boundary" && rows[i - 1].kind === "boundary"),
        "adjacent boundaries",
      );
    const isBeat = (f) =>
      f.kind === "targetChange" && f.targetChange.targetChangeType === "NO_CHANGE";
    const kept = input.filter((f) => !isBeat(f));
    assert.deepEqual(
      rows.filter((r) => r.kind !== "boundary").map((r) => r.kind),
      kept.map((f) => f.kind),
    );
    assert.deepEqual(
      rows.filter((r) => r.kind === "documentChange").map((r) => `${ROOT}/${r.doc}`),
      kept.filter((f) => f.kind === "documentChange").map((f) => f.documentChange.document.name),
    );
    // A run of heartbeats is one boundary; it carries the last heartbeat's token.
    const runs = [];
    for (const f of input) {
      if (isBeat(f)) {
        if (runs.at(-1)?.beat)
          runs[runs.length - 1] = { beat: true, token: Boolean(f.targetChange.resumeToken) };
        else runs.push({ beat: true, token: Boolean(f.targetChange.resumeToken) });
      } else runs.push({ beat: false });
    }
    assert.deepEqual(
      rows.filter((r) => r.kind === "boundary").map((r) => r.resumeToken),
      runs.filter((r) => r.beat).map((r) => r.token),
    );
    // A beat repeated any number of times records as the same rows.
    const doubled = input.flatMap((f) => (isBeat(f) ? [f, f] : [f]));
    assert.deepEqual(summarizeListen(doubled, undefined, ctx, new Map()).frames, rows);
  });
});

// ---- the corpus bound and the ledger windows ------------------------------------------------

test("a corpus passes the static guard exactly when its rows fit the cap (property)", () => {
  forEachRound(6, (random) => {
    const programs = Array.from({ length: 1 + random.int(10) }, (_, i) => ({
      ...structuredClone(PROGRAMS[0]),
      id: `fs-rules-v1/many/p${i}`,
      steps: PROGRAMS[0].steps.slice(0, 1 + random.int(PROGRAMS[0].steps.length)),
    }));
    const rows = countRequests(programs);
    if (rows <= REQUEST_CAP) assert.equal(validateCorpus(programs), rows);
    else
      assert.throws(
        () => validateCorpus(programs),
        new RegExp(`request cap \\(${rows} > ${REQUEST_CAP}\\)`),
      );
  });
});

test("ledger windows include a line exactly when it is younger than the window (property)", () => {
  const NOW = Date.parse("2026-10-14T12:00:00Z");
  const MIN = 60_000;
  forEachRound(7, (random) => {
    const age = random.int(8 * 60 * MIN);
    const stamp = new Date(NOW - age).toISOString();
    const other = JSON.stringify({ project: SANDBOX_PROJECT, ts: stamp, taskId: "A" });
    assert.equal(otherLanesRecently(other, NOW).length === 1, age < 30 * MIN);
    const started = JSON.stringify({
      project: SANDBOX_PROJECT,
      ts: stamp,
      taskId: "A",
      event: "started",
    });
    assert.equal(openRuns(started, NOW).length === 1, age < 6 * 60 * MIN);
    const abort = JSON.stringify({
      project: SANDBOX_PROJECT,
      ts: stamp,
      taskId: TASK_ID,
      outcome: "aborted",
    });
    assert.equal(recentAbort(abort, NOW) !== undefined, age < 60 * MIN);
    // A line for another project never counts.
    const elsewhere = JSON.stringify({
      project: "fireemu-oracle-sbx",
      ts: stamp,
      taskId: "A",
      event: "started",
    });
    assert.deepEqual(otherLanesRecently(elsewhere, NOW), []);
    assert.deepEqual(openRuns(elsewhere, NOW), []);
  });
});

test("each way the sandbox can be unfit adds exactly one problem, and read failures one each (property)", () => {
  forEachRound(8, (random) => {
    const deviations = [];
    const report = {
      failedReads: Array.from({ length: random.int(3) }, (_, i) => `read${i} (HTTP 403)`),
      projectAccounts: 0,
      anonymousEnabled: true,
      rulesets: 0,
      otherLanesRecently: [],
      openRuns: [],
      releases: [],
      databases: ["(default)"],
      defaultHasDocuments: false,
    };
    const apply = (name, change) => {
      if (random.bool()) {
        change();
        deviations.push(name);
      }
    };
    apply("accounts", () => (report.projectAccounts = 1 + random.int(5)));
    apply("anonymous", () => (report.anonymousEnabled = false));
    apply("rulesets", () => (report.rulesets = 1 + random.int(5)));
    apply("lanes", () => (report.otherLanesRecently = ["X", "Y"].slice(0, 1 + random.int(2))));
    apply("open", () => (report.openRuns = ["R"]));
    apply("release", () => (report.releases = ["cloud.firestore"]));
    apply("database", () => (report.databases = ["(default)", "extra"]));
    apply("documents", () => (report.defaultHasDocuments = true));
    assert.equal(preflightProblems(report).length, report.failedReads.length + deviations.length);
  });
});

test("the cost estimate rises with the requests and stays under its stated bound (property)", () => {
  forEachRound(9, (random) => {
    const a = random.int(4000);
    const b = a + 1 + random.int(4000);
    assert.ok(estimatedUsd(a) <= estimatedUsd(b));
    assert.ok(estimatedUsd(a) >= 0.01);
    assert.ok(estimatedUsd(a) <= a * 0.000002 + 0.0101);
  });
  assert.ok(estimatedUsd(2 * (76 + 1500)) < 0.05);
});

// ---- the request guard ---------------------------------------------------------------------

const GOOD = [
  `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases`,
  `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:runQuery`,
  `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:commit`,
  `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/rulesets`,
  `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/releases/cloud.firestore`,
  `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:query`,
  `https://identitytoolkit.googleapis.com/admin/v2/projects/${SANDBOX_PROJECT}/config`,
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
];

test("the guard allows each sandbox URL with any query string and refuses every corruption of it (property)", () => {
  forEachRound(10, (random) => {
    const url = random.pick(GOOD);
    guardHarnessRequest(url, ctx);
    guardHarnessRequest(`${url}?key=${random.int(1e6)}`, ctx);
    const parsed = new URL(url);
    const corruptions = [
      url.replace(SANDBOX_PROJECT, `${SANDBOX_PROJECT}${random.pick(["x", "-1", "2"])}`),
      url.replace(SANDBOX_PROJECT, random.pick(["fireemu-oracle-sbx", "fireemu-35fe6", "other"])),
      `${url}/${random.pick(url.endsWith("/rulesets") ? ["..", "y/z"] : ["x", "..", "y/z"])}`,
      url.replace(
        parsed.host,
        random.pick(["example.com", `${parsed.host}.evil.test`, `evil.${parsed.host}`]),
      ),
      url.replace("https://", "http://"),
    ].filter((corrupted) => corrupted !== url);
    for (const corrupted of corruptions)
      assert.throws(
        () => guardHarnessRequest(corrupted, ctx),
        /outside the sandbox project/,
        corrupted,
      );
  });
});

// ---- the fixture ----------------------------------------------------------------------------

test("a saved program keeps exactly the rows whose second recording differs (property)", () => {
  forEachRound(11, (random) => {
    const program = PROGRAMS[random.int(PROGRAMS.length)];
    const ids = program.steps.map((s) => s.id);
    const first = Object.fromEntries(ids.map((id) => [id, row(random)]));
    const second = Object.fromEntries(
      ids.map((id) => [id, random.bool(0.3) ? row(random) : shuffled(random, first[id])]),
    );
    const make = (steps) => ({ results: { [program.id]: { steps } }, diagnostics: {} });
    const meta = { startedAt: "t", sha: "s", harness: "h" };
    const text = fixtureText({
      programs: [program],
      recordings: [make(first), make(second)],
      meta,
    });
    const saved = JSON.parse(text).programs[program.id];
    const differing = ids.filter((id) => !sameRecording(first[id], second[id]));
    assert.deepEqual(Object.keys(saved.second ?? {}).toSorted(), differing.toSorted());
    for (const id of differing) assert.deepEqual(saved.second[id], second[id]);
    assert.deepEqual(saved.steps, first);
  });
});

test("the harness digest changes with any one covered file and with nothing else (property)", () => {
  forEachRound(12, (random) => {
    const files = Object.fromEntries(HARNESS_FILES.map((f) => [f, `${f}:${random.int(1e9)}`]));
    const reader = (overrides) => (file) => overrides[file] ?? files[file];
    const base = harnessDigest(reader({}));
    const changed = random.pick(HARNESS_FILES);
    assert.notEqual(harnessDigest(reader({ [changed]: `${files[changed]}!` })), base);
    assert.equal(harnessDigest(reader({ "unrelated.mjs": "x" })), base);
  });
});
