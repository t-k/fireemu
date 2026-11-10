import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import test from "node:test";

import { createWorld } from "./world.mjs";

const root = "https://firebasehosting.googleapis.com/v1beta1";
const site = "fireemu-oracle-idp";
const request = (world, method, url, body) =>
  world.http({ method, url, body: body === undefined ? undefined : JSON.stringify(body) });

test("the fake API deploys and deletes a channel and version", async () => {
  const world = createWorld({ run: "123abc", secrets: { apiKey: "private-value" } });
  const channels = `${root}/projects/${site}/sites/${site}/channels`;
  const channelId = "hst-123abc-v01";
  const channel = JSON.parse(
    (
      await request(world, "POST", `${channels}?channelId=${channelId}`, {
        labels: { "fireemu-run": "123abc" },
      })
    ).text,
  );
  const version = JSON.parse(
    (
      await request(world, "POST", `${root}/projects/-/sites/${site}/versions`, {
        labels: { "fireemu-run": "123abc" },
      })
    ).text,
  );
  const population = JSON.parse(
    (
      await request(world, "POST", `${root}/${version.name}:populateFiles`, {
        files: { "/ready.txt": "hash" },
      })
    ).text,
  );
  assert.deepEqual(population.uploadRequiredHashes, ["hash"]);
  await world.http({
    method: "POST",
    url: `${population.uploadUrl}/hash`,
    body: gzipSync("ready"),
  });
  assert.equal(
    (
      await request(world, "PATCH", `${root}/${version.name}?updateMask=status,config`, {
        status: "FINALIZED",
        config: {},
      })
    ).status,
    200,
  );
  await request(
    world,
    "POST",
    `${channels}/${channelId}/releases?versionName=${encodeURIComponent(version.name)}`,
    {},
  );
  const answer = await world.edge({
    method: "GET",
    host: new URL(channel.url).host,
    target: "/ready.txt",
  });
  assert.equal(answer.status, 200);
  assert.equal(answer.body.toString(), "ready");
  const info = JSON.parse((await request(world, "GET", `${root}/${version.name}`)).text);
  assert.equal(info.fileCount, "3");
  await request(world, "DELETE", `${channels}/${channelId}`);
  await request(world, "DELETE", `${root}/${version.name}`);
  assert.equal(
    (await world.edge({ method: "GET", host: new URL(channel.url).host, target: "/ready.txt" }))
      .status,
    404,
  );
});

test("fault overrides apply to their selected call only", async () => {
  const world = createWorld({
    run: "123abc",
    secrets: {},
    overrides: [{ match: "GET /channels/", nth: 2, answer: "timeout" }],
  });
  const url = `${root}/projects/-/sites/${site}/channels`;
  assert.equal((await request(world, "GET", url)).status, 200);
  assert.equal((await request(world, "GET", url)).status, 0);
  assert.equal((await request(world, "GET", url)).status, 200);
});

import { buildCorpus } from "./corpus.mjs";
import { CORPUS_SHA256 } from "./pins.mjs";
import {
  admit,
  CAPS,
  checkReport,
  classify,
  PROJECT,
  READINESS_ATTEMPTS,
  READINESS_FIRST_WAIT_MS,
  READINESS_GAP_MS,
  recordHosting,
  recoverHosting,
  secretsFromWebConfig,
  TASK_ID,
} from "./record.mjs";

const now = Date.parse("2026-11-10T12:00:00Z");
const fakeSecrets = { apiKey: "AIzaFAKEFAKEFAKEFAKEFAKEFAKE12345", projectNumber: "123456789012" };
const ENVELOPE = "HOSTING-PRODUCTION-V5-20261111";
const closed = {
  ts: "2026-11-10T00:00:00Z",
  project: PROJECT,
  taskId: "other",
  event: "finished",
  outcome: "recorded",
};
const reply = (status, value = {}) => ({ status, text: JSON.stringify(value) });
const answer = (status, headers = []) => ({
  outcome: "answered",
  status,
  headers,
  body: Buffer.alloc(0),
});
const rowsOf = (run) => JSON.parse(run.files["rows.json"]).rows;
const resultOf = (run) => JSON.parse(run.files["result.json"]);
const deployOf = (run) => JSON.parse(run.files["deploy.json"]).versions;
const terminal = (run) => JSON.parse(run.ledger.at(-1));
const edgeCalls = (run) => run.world.log.filter((call) => call.kind === "edge");
const noSecrets = (run, secrets = fakeSecrets) => {
  const retained = JSON.stringify([run.files, run.ledger]);
  for (const value of Object.values(secrets)) assert.equal(retained.includes(value), false);
};

async function run(options = {}) {
  const secrets = options.secrets ?? fakeSecrets;
  const world = createWorld({
    run: "abc123",
    secrets,
    overrides: options.overrides ?? [],
    ...options.world,
  });
  const ledger = [JSON.stringify(closed)];
  const files = {};
  const sleeps = [];
  const deps = {
    now: () => now,
    assertCleanTree: async () => {},
    gitSha: async () => "a".repeat(40),
    readSources: async () => ({ corpus: buildCorpus() }),
    readLedger: async () => ledger.join("\n"),
    appendLedger: async (text) => {
      ledger.push(text.trim());
    },
    ownerAdc: async () => ({}),
    webConfig: async () => ({
      projectId: PROJECT,
      ...secrets,
      messagingSenderId: secrets.projectNumber,
      appId: `1:${secrets.projectNumber}:web:deadbeef1234`,
    }),
    makeRunDir: async (name) => `/run/${name}`,
    writeRunFile: async (_dir, name, text) => {
      files[name] = text;
    },
    appendRunFile: async (_dir, name, text) => {
      files[name] = (files[name] ?? "") + text;
    },
    runTag: () => "abc123",
    token: async () => ({ value: "fake-bearer", expiresAt: now + 1e9 }),
    http: world.http,
    edge: world.edge,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    installSignals: () => {},
    log() {},
    warn() {},
    ...options.deps,
  };
  options.setup?.(world, deps, ledger);
  const result = await recordHosting({ FIREEMU_HOSTING_ENVELOPE: ENVELOPE, ...options.env }, deps);
  return { result, world, ledger, files, sleeps, deps };
}

const fault = (match, answerValue, nth = 1) => ({ match, nth, answer: answerValue });
const channelCreate = "POST /channels\\?channelId=/";
const versionCreate = "POST /projects/-/sites/[^/]+/versions$/";
const channelDelete = "DELETE /channels/hst-/";
const finalize = "PATCH /versions/";

test("records and cleans the full corpus with bounded, counted requests", async () => {
  const r = await run();
  const rows = rowsOf(r);
  const corpus = buildCorpus();
  assert.deepEqual(
    rows.map((row) => row.id),
    corpus.versions.flatMap((version) => version.requests.map((spec) => spec.id)),
  );
  assert.equal(rows.length, 201);
  assert.deepEqual(
    rows.filter((row) => row.outcome !== "answered").map((row) => [row.id, row.reason]),
    [["v01.cond-etag-rewrite", "dependency"]],
  );
  assert.equal(r.result.outcome, "observed-unknown");
  assert.equal(terminal(r).closureReady, true);
  assert.equal(r.world.state.versions.size, 10);
  assert.equal(r.world.state.channels.size, 10);
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.ok([...r.world.state.versions.values()].every((version) => version.status === "DELETED"));
  assert.equal(r.world.state.releasedVersions.size, 10);
  const counts = { token: 1, control: 0, cleanup: 0, upload: 0, edge: 0 };
  // The first five calls are the read-only prechecks (service, site, channels, versions, config);
  // the deletes and the final listings are cleanup.
  r.world.log.forEach((call, index) => {
    if (call.kind === "edge" || call.kind === "upload") counts[call.kind]++;
    else if (
      index >= 5 &&
      (call.method === "DELETE" ||
        (call.method === "GET" &&
          (call.url.includes("/sites/fireemu-oracle-idp/versions?") ||
            call.url.includes("/channels?") ||
            call.url.includes("identitytoolkit"))))
    )
      counts.cleanup++;
    else counts.control++;
  });
  assert.deepEqual(resultOf(r).requests, counts);
  for (const kind of Object.keys(CAPS)) assert.ok(counts[kind] <= CAPS[kind]);
  for (const name of ["rows.json", "deploy.json", "result.json", "journal.jsonl"])
    assert.ok(r.files[name]);
  const v01 = deployOf(r).v01;
  assert.equal(typeof v01.fileCount, "string");
  assert.equal(v01.fileCountType, "string");
  assert.deepEqual(v01.reservedFiles, ["/__/firebase/init.json", "/__/firebase/init.js"]);
  noSecrets(r);
  for (const row of rows.filter((item) => item.bodyKind?.startsWith("init-"))) {
    assert.ok(row.layout);
    assert.equal("bodyText" in row, false);
  }
});

test("unknown channel creates are probed once and halt", async () => {
  for (const value of ["network-error", reply(500), reply(302)]) {
    const r = await run({ overrides: [fault(channelCreate, value)] });
    assert.equal(r.result.outcome, "needs-recovery");
    assert.equal(terminal(r).event, "needs-recovery");
    assert.equal(
      r.world.log.filter(
        (call) => call.method === "GET" && call.url?.includes("/channels/hst-abc123-v01"),
      ).length,
      1,
    );
    assert.equal(r.world.state.versions.size, 0);
    assert.ok(rowsOf(r).every((row) => row.outcome === "unknown"));
  }
});

test("refused channel creates are not deleted", async () => {
  for (const status of [409, 400, 403]) {
    const r = await run({ overrides: [fault(channelCreate, reply(status))] });
    assert.equal(r.result.outcome, "failed-cleaned");
    assert.equal(
      r.world.log.filter((call) => call.method === "DELETE" && call.url.includes("/channels/"))
        .length,
      0,
    );
    assert.equal(r.world.state.versions.size, 0);
  }
});

test("an unknown version create is reported by the final listing", async () => {
  const r = await run({
    overrides: [
      fault(versionCreate, (_call, state) => {
        const name = `sites/${PROJECT}/versions/0000000000000001`;
        state.versions.set(name, { name, labels: { "fireemu-run": "abc123" }, status: "CREATED" });
        return reply(500);
      }),
    ],
  });
  assert.equal(r.result.outcome, "needs-recovery");
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.equal(resultOf(r).readback.versionsLeft.length, 1);
});

test("optional finalize config is dropped once, while other 400s halt", async () => {
  const r = await run({
    setup: (world) => {
      world.state.rejectAppAssociation = true;
    },
  });
  assert.deepEqual(deployOf(r).v02.droppedConfig, ["appAssociation"]);
  assert.equal(
    r.world.log.filter((call) => call.method === "PATCH" && call.url.includes("0000000000000002"))
      .length,
    2,
  );
  assert.equal(r.result.closureReady, true);
  const failed = await run({ overrides: [fault(finalize, reply(400))] });
  assert.equal(failed.result.outcome, "failed-cleaned");
  assert.equal(failed.world.log.filter((call) => call.method === "PATCH").length, 1);
});

test("upload failure skips finalization and cleans up", async () => {
  const r = await run({ overrides: [fault("POST /upload/", reply(500))] });
  assert.equal(r.result.outcome, "failed-cleaned");
  assert.equal(r.world.log.filter((call) => call.method === "PATCH").length, 0);
  assert.ok([...r.world.state.versions.values()].every((version) => version.deleted));
});

test("unknown deletes are not retried and successful deletes are read back", async () => {
  for (const value of [reply(500), reply(200)]) {
    const r = await run({ overrides: [fault(channelDelete, value)] });
    const deletes = r.world.log.filter(
      (call) =>
        call.kind === "http" &&
        call.method === "DELETE" &&
        call.url.includes("/channels/hst-abc123-v01"),
    );
    assert.equal(deletes.length, 1);
    assert.equal(r.result.outcome, "needs-recovery");
    assert.ok(resultOf(r).readback.channelsLeft.length);
  }
});

test("readiness polls the whole window, cleans the version and continues", async () => {
  const r = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
      },
    ],
  });
  assert.equal(r.sleeps.filter((ms) => ms === READINESS_GAP_MS).length, READINESS_ATTEMPTS - 1);
  assert.equal(deployOf(r).v01.readiness.length, READINESS_ATTEMPTS);
  assert.ok(
    rowsOf(r)
      .filter((row) => row.version === "v01")
      .every((row) => row.reason === "not-ready"),
  );
  assert.equal(r.world.state.versions.size, 10);
  assert.ok([...r.world.state.versions.values()].every((version) => version.deleted));
});

// Run bba4c0 (attempt 2): v05, v06, v09 and v10 answered 404 to /ready.txt three times, 10 s apart,
// and were given up on, while v01-v04, v07 and v08 were served at once. The 404 came for v09 too,
// whose `**` redirect would have answered 302 for any path, so the release was not live at the edge
// yet (not a missing file). The window has to outlast a slow release.
const SLOW_RELEASES = ["v05", "v06", "v09", "v10"];
const slowRelease = (probes) => {
  const seen = new Map();
  return {
    match: "GET /ready.txt/",
    answer: (call) => {
      const version = SLOW_RELEASES.find((id) => call.host.includes(`-${id}-`));
      if (!version) return undefined;
      seen.set(version, (seen.get(version) ?? 0) + 1);
      return seen.get(version) <= probes ? answer(404) : undefined;
    },
  };
};

test("a release that is live only after the recorded 404s is still observed", async () => {
  const r = await run({ overrides: [slowRelease(3)] });
  const rows = rowsOf(r);
  assert.equal(r.result.outcome, "observed-unknown");
  assert.deepEqual(
    rows.filter((row) => row.outcome !== "answered").map((row) => [row.id, row.reason]),
    [["v01.cond-etag-rewrite", "dependency"]],
  );
  for (const id of SLOW_RELEASES) {
    assert.deepEqual(deployOf(r)[id].readiness, [404, 404, 404, deployOf(r)[id].readiness[3]]);
    assert.equal(deployOf(r)[id].readiness.at(-1), id === "v09" ? 302 : 200);
    assert.equal(deployOf(r)[id].failure, undefined);
  }
  assert.equal(r.sleeps.filter((ms) => ms === READINESS_GAP_MS).length, 4 * 3);
});

test("the readiness window is at least three times the 20 s a recorded release stayed dark", () => {
  assert.ok(READINESS_ATTEMPTS * READINESS_GAP_MS >= 60_000);
});

test("the worst slow-release window still fits every budget", async () => {
  const r = await run({ overrides: [slowRelease(READINESS_ATTEMPTS - 1)] });
  assert.equal(r.result.outcome, "observed-unknown");
  assert.equal(rowsOf(r).filter((row) => row.reason === "not-ready").length, 0);
  for (const [kind, count] of Object.entries(resultOf(r).requests)) assert.ok(count <= CAPS[kind]);
  // 200 requests are sent (one has no dependency answer), 6 versions need 1 probe, 4 need all
  assert.equal(resultOf(r).requests.edge, 200 + 6 + 4 * READINESS_ATTEMPTS);
});

test("a version that never becomes ready keeps what the last probe and the channel showed", async () => {
  const notFound = Buffer.from("Site Not Found");
  const r = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) =>
          call.host.includes("-v01-")
            ? {
                outcome: "answered",
                status: 404,
                headers: [
                  ["Content-Type", "text/html; charset=utf-8"],
                  ["X-Served-By", "cache-nrt-1"],
                  ["X-Cache", "MISS"],
                  ["X-Private", fakeSecrets.apiKey],
                ],
                body: notFound,
              }
            : undefined,
      },
    ],
  });
  const v01 = deployOf(r).v01;
  assert.equal(v01.failure, "not-ready");
  assert.deepEqual(v01.lastProbe, {
    status: 404,
    contentType: "text/html; charset=utf-8",
    xCache: "MISS",
    xServedBy: "cache-nrt-1",
    bodyBytes: notFound.length,
    bodyHead: "Site Not Found",
  });
  // the channel read says whether the API still held this version as the channel's release
  assert.equal(v01.releaseOnChannel, true);
  assert.equal(
    r.world.log.filter(
      (call) => call.method === "GET" && call.url?.endsWith("/channels/hst-abc123-v01"),
    ).length,
    1,
  );
  noSecrets(r);
  // a ready version carries neither
  assert.equal("lastProbe" in deployOf(r).v02, false);
  assert.equal("releaseOnChannel" in deployOf(r).v02, false);
});

test("a channel read that does not show this release, or fails, is recorded as such", async () => {
  const gone = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
      },
      fault("GET /channels/hst-abc123-v01$/", (_call, state) => {
        const channel = state.channels.get("hst-abc123-v01");
        return reply(200, { ...channel, release: { version: { name: "sites/x/versions/other" } } });
      }),
    ],
  });
  assert.equal(deployOf(gone).v01.releaseOnChannel, false);
  const failed = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
      },
      fault("GET /channels/hst-abc123-v01$/", reply(500)),
    ],
  });
  assert.equal(deployOf(failed).v01.releaseOnChannel, "unread");
  assert.equal(failed.result.outcome, "failed-cleaned");
});

test("edge timeout, 503 and redirect are retained without retries", async () => {
  for (const [injected, outcome, reason] of [
    ["timeout", "unknown", "network-error"],
    [answer(503), "unknown", "http-503"],
    [answer(302), "answered", undefined],
  ]) {
    const r = await run({ overrides: [fault("GET /data.json$/", injected)] });
    const row = rowsOf(r).find((item) => item.id === "v01.static");
    assert.equal(row.outcome, outcome);
    assert.equal(row.reason, reason);
    assert.equal(
      edgeCalls(r).filter(
        (call) =>
          call.host.includes("-v01-") &&
          call.target === "/data.json" &&
          !call.headers["if-none-match"] &&
          !call.headers["if-modified-since"] &&
          !call.headers.range &&
          call.method === "GET",
      ).length,
      1,
    );
  }
});

test("foreign channel and upload hosts fail before any edge request", async () => {
  const cases = [
    fault(channelCreate, (_call, state) => {
      const id = "hst-abc123-v01";
      const channel = {
        name: `projects/${PROJECT}/sites/${PROJECT}/channels/${id}`,
        url: "https://foreign.example",
        deleted: false,
      };
      state.channels.set(id, channel);
      return reply(200, channel);
    }),
    fault(
      "POST /:populateFiles/",
      reply(200, { uploadUrl: "https://foreign.example/upload", uploadRequiredHashes: [] }),
    ),
  ];
  for (const rule of cases) {
    const r = await run({ overrides: [rule] });
    assert.equal(r.result.outcome, "failed-cleaned");
    assert.equal(edgeCalls(r).length, 0);
    assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  }
});

test("control cap preserves cleanup capacity", async () => {
  const caps = { ...CAPS, control: 5 };
  const r = await run({ deps: { caps } });
  assert.equal(r.result.outcome, "failed-cleaned");
  for (const [kind, count] of Object.entries(resultOf(r).requests)) assert.ok(count <= caps[kind]);
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
});

test("seeded faults respect budgets, host boundaries and closure", async () => {
  let seed = 1234567;
  const random = (n) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % n;
  };
  const matches = [
    channelCreate,
    versionCreate,
    "POST /:populateFiles/",
    "POST /upload/",
    finalize,
    "POST /releases/",
    channelDelete,
    "DELETE /sites/",
    "GET /ready.txt/",
    "GET /data.json/",
  ];
  const faults = ["network-error", reply(500), reply(400), reply(302), "timeout"];
  for (let iteration = 0; iteration < 200; iteration++) {
    const overrides = Array.from({ length: 1 + random(4) }, () =>
      fault(matches[random(matches.length)], faults[random(faults.length)], 1 + random(4)),
    );
    const r = await run({ overrides });
    const result = resultOf(r);
    for (const [kind, count] of Object.entries(result.requests)) assert.ok(count <= CAPS[kind]);
    const hosts = new Set(
      [...r.world.state.channels.values()].map((channel) => new URL(channel.url).host),
    );
    for (const call of r.world.log) {
      if (call.kind === "edge") assert.ok(hosts.has(call.host));
      else
        assert.ok(
          [
            "firebasehosting.googleapis.com",
            "upload-firebasehosting.googleapis.com",
            "serviceusage.googleapis.com",
            "identitytoolkit.googleapis.com",
          ].includes(new URL(call.url).host),
        );
    }
    const remaining =
      [...r.world.state.channels.values()].some((channel) => !channel.deleted) ||
      [...r.world.state.versions.values()].some((version) => version.status !== "DELETED");
    if (remaining) assert.equal(r.result.closureReady, false);
    if (r.result.closureReady) assert.deepEqual(r.world.state.authorizedDomains, ["localhost"]);
    noSecrets(r);
  }
});

test("stop during the second version leaves later rows unknown and cleans up", async () => {
  let stop;
  const r = await run({
    setup: (world, deps) => {
      deps.installSignals = (handler) => {
        stop = handler;
      };
      deps.edge = async (call) => {
        const value = await world.edge(call);
        if (call.host.includes("-v02-") && !call.target.startsWith("/ready.txt?fireemu-ready="))
          stop();
        return value;
      };
    },
  });
  assert.ok(
    rowsOf(r)
      .filter((row) => row.version === "v03")
      .every((row) => ["stopped", "not-run"].includes(row.reason)),
  );
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.ok([...r.world.state.versions.values()].every((version) => version.deleted));
});

test("admission checks closure, age, unfinished attempts and project scope", () => {
  const check = (lines, env = {}) =>
    admit({
      ledgerText: lines.map((line) => JSON.stringify(line)).join("\n"),
      now,
      env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE, ...env },
    });
  assert.equal(check([closed]).attempt, 1);
  assert.throws(() => check([{ ...closed, event: "needs-recovery" }]));
  const recent = { ...closed, ts: new Date(now).toISOString() };
  assert.throws(() => check([recent]));
  assert.equal(check([recent], { FIREEMU_HOSTING_SOLE_SENDER: "1" }).attempt, 1);
  const started = { ...closed, taskId: TASK_ID, event: "started", envelopeId: ENVELOPE };
  assert.throws(() => check([started, closed]));
  const done = { ...closed, taskId: TASK_ID };
  assert.equal(check([started, done, { ...started, project: "other" }]).attempt, 2);
  assert.throws(() => check([started, done, started, done, started, done]));
});

// Attempts 1 and 2 (runs 03d922 and bba4c0) were started under earlier envelopes; their started rows
// carry no envelope id. The V4 envelope allows 3 launches of its own, so the first V4 launch is its
// attempt 1, while the money already reserved still counts (US$2.00 before the first V4 launch).
const priorAttempt = (attempt, extra = {}) => [
  { ...closed, taskId: TASK_ID, event: "started", attempt, ...extra },
  { ...closed, taskId: TASK_ID, event: "finished", outcome: "failed-cleaned", attempt },
  { ...closed, taskId: TASK_ID, event: "cleanup-verified", outcome: "failed-cleaned", attempt },
];
const v4Attempt = (attempt, extra = {}) =>
  priorAttempt(attempt, { envelopeId: ENVELOPE, ...extra });

test("a new envelope counts its own attempts from 1 and the reserved money from all rows", () => {
  const check = (lines, env = {}) =>
    admit({
      ledgerText: lines.map((line) => JSON.stringify(line)).join("\n"),
      now,
      env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE, ...env },
    });
  const old = [
    ...priorAttempt(1),
    ...priorAttempt(2, { envelopeId: "HOSTING-PRODUCTION-V3-20261111" }),
  ];
  assert.deepEqual(check(old), { attempt: 1, cumulativeReservedUsd: 3 });
  const one = [...old, ...v4Attempt(1)];
  assert.deepEqual(check(one), { attempt: 2, cumulativeReservedUsd: 4 });
  const two = [...one, ...v4Attempt(2)];
  assert.deepEqual(check(two), { attempt: 3, cumulativeReservedUsd: 5 });
  assert.throws(() => check([...two, ...v4Attempt(3)]), /attempt 4 exceeds 3 attempts/);
  // another envelope's rows do not use this envelope's three launches
  const other = [...old, ...v4Attempt(1, { envelopeId: "HOSTING-PRODUCTION-V6-20261111" })];
  assert.equal(check(other).attempt, 1);
  // the envelope is the one named by the caller, not the latest one in the ledger
  assert.equal(
    check(one, { FIREEMU_HOSTING_ENVELOPE: "HOSTING-PRODUCTION-V6-20261111" }).attempt,
    1,
  );
});

test("the cumulative reservation of the parent never passes US$6.00", () => {
  const rows = (n) =>
    Array.from({ length: n }, (_, i) =>
      priorAttempt(i + 1, { envelopeId: `HOSTING-PRODUCTION-V${i + 10}-20261111` }),
    ).flat();
  const check = (n) =>
    admit({
      ledgerText: rows(n)
        .map((line) => JSON.stringify(line))
        .join("\n"),
      now,
      env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE },
    });
  assert.equal(check(5).cumulativeReservedUsd, 6);
  assert.throws(() => check(6), /US\$6\.00/);
});

test("admission needs the envelope id, in the form of a HOSTING envelope", () => {
  for (const value of [
    undefined,
    "",
    "V4",
    "HOSTING-PRODUCTION-V4 20261111",
    "OTHER-V4-20261111",
    "HOSTING-PRODUCTION-",
    "HOSTING-PRODUCTION-V4-20261111 extra",
    "xHOSTING-PRODUCTION-V4-20261111",
  ])
    assert.throws(
      () =>
        admit({
          ledgerText: JSON.stringify(closed),
          now,
          env: value === undefined ? {} : { FIREEMU_HOSTING_ENVELOPE: value },
        }),
      /FIREEMU_HOSTING_ENVELOPE/,
      String(value),
    );
});

test("the started row carries the envelope and the attempt of that envelope", async () => {
  const old = [...priorAttempt(1), ...priorAttempt(2)];
  const r = await run({
    setup: (_world, _deps, ledger) => {
      ledger.splice(0, ledger.length, ...old.map((line) => JSON.stringify(line)));
    },
  });
  const started = r.ledger
    .map((line) => JSON.parse(line))
    .find((line) => line.event === "started" && line.run === "abc123");
  assert.equal(started.attempt, 1);
  assert.equal(started.envelopeId, ENVELOPE);
  assert.equal(started.reservedUsd, 1);
  assert.equal(started.cumulativeReservedUsd, 3);
  assert.equal(terminal(r).attempt, 1);
  assert.equal(terminal(r).cumulativeReservedUsd, 3);
});

test("a run without an envelope id sends nothing", async () => {
  await assert.rejects(
    run({ env: { FIREEMU_HOSTING_ENVELOPE: undefined } }),
    /FIREEMU_HOSTING_ENVELOPE/,
  );
});

test("dependent etags are forwarded or cause an unsent dependency row", async () => {
  const normal = await run();
  const sent = edgeCalls(normal).find(
    (call) => call.host.includes("-v01-") && call.headers["if-none-match"] === '"fake-etag"',
  );
  assert.equal(sent.target, "/data.json");
  const missing = await run({ overrides: [fault("GET /data.json$/", answer(200))] });
  assert.equal(rowsOf(missing).find((row) => row.id === "v01.cond-etag").reason, "dependency");
  assert.equal(
    edgeCalls(missing).filter(
      (call) => call.host.includes("-v01-") && call.headers["if-none-match"] === '"fake-etag"',
    ).length,
    0,
  );
});

const startedRow = {
  ...closed,
  taskId: TASK_ID,
  event: "started",
  envelopeId: ENVELOPE,
  run: "abc123",
  authorizedDomainsBefore: ["localhost"],
};
const endedRow = (extra = {}) => ({
  ...closed,
  taskId: TASK_ID,
  event: "needs-recovery",
  outcome: "needs-recovery",
  run: "abc123",
  openUnknownCreates: [],
  residualEntries: [],
  ...extra,
});
/** A finished run whose first channel and version are still live, as the recovery finds them. */
async function leftover(extraEnded) {
  const r = await run();
  const channel = [...r.world.state.channels.values()][0];
  channel.deleted = false;
  const version = [...r.world.state.versions.values()][0];
  version.deleted = false;
  version.status = "CREATED";
  r.ledger.push(JSON.stringify(startedRow), JSON.stringify(endedRow(extraEnded)));
  return { r, channel, version };
}
const lastRow = (r) => JSON.parse(r.ledger.at(-1));
const admitFor = (r, env = {}) =>
  admit({
    ledgerText: r.ledger.join("\n"),
    now: now + 3 * 3600_000,
    env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE, ...env },
  });

test("recovery deletes leftovers and reads back, but never writes a closing row", async () => {
  const { r, channel, version } = await leftover();
  const start = r.world.log.length;
  const recovered = await recoverHosting({}, r.deps);
  assert.equal(recovered.outcome, "recovery-read-clean");
  assert.equal(channel.deleted, true);
  assert.equal(version.deleted, true);
  const row = lastRow(r);
  assert.equal(row.event, "recovery-read");
  assert.equal(row.outcome, "recovery-read-clean");
  assert.equal(row.a2ReadNotBefore, new Date(now + 600_000).toISOString());
  assert.deepEqual(row.openUnknownCreates, []);
  assert.ok(row.deleted.every((entry) => entry.kind === "ok"));
  assert.ok(
    r.world.log.slice(start).every((call) => call.method !== "POST" && call.kind !== "edge"),
  );
  // Even a clean recovery is not a close: the coordinator writes it after the A2 read-back.
  assert.throws(() => admitFor(r), /does not close its run/);
  r.ledger.push(
    JSON.stringify({
      ts: new Date(now + 3600_000).toISOString(),
      project: PROJECT,
      taskId: TASK_ID,
      run: "abc123",
      event: "cleanup-verified",
      outcome: "recorded",
    }),
  );
  // The recorded run and the started row this test adds are two attempts, so the next is the third.
  assert.equal(admitFor(r).attempt, 3, "only the coordinator's close row admits the next attempt");
});

test("a recovery DELETE that answers 503, times out or is refused stays residual and open", async () => {
  for (const value of [reply(503), reply(404), reply(403), "timeout"]) {
    const { r } = await leftover();
    const http = r.deps.http;
    r.deps.http = async (call) =>
      call.method === "DELETE"
        ? value === "timeout"
          ? { status: 0, text: "" }
          : value
        : http(call);
    const recovered = await recoverHosting({}, r.deps);
    assert.equal(recovered.outcome, "needs-recovery", JSON.stringify(value));
    const row = lastRow(r);
    assert.equal(row.event, "recovery-read");
    assert.ok(row.residual.length >= 1);
    assert.ok(row.deleted.some((entry) => entry.kind !== "ok"));
    assert.throws(() => admitFor(r), /does not close its run/);
  }
});

test("an unknown create stays open through a recovery that lists nothing; admission refuses attempt 2", async () => {
  const r = await run({ overrides: [fault(channelsPost, "network-error")] });
  assert.equal(r.result.outcome, "needs-recovery");
  const ended = terminal(r);
  assert.deepEqual(ended.openUnknownCreates, ["channel:hst-abc123-v01"]);
  assert.equal(r.world.state.channels.size, 0, "the world applied nothing");
  const recovered = await recoverHosting({}, r.deps);
  assert.equal(recovered.outcome, "needs-recovery");
  assert.deepEqual(recovered.openUnknownCreates, ["channel:hst-abc123-v01"]);
  const row = lastRow(r);
  assert.equal(row.event, "recovery-read");
  assert.deepEqual(row.openUnknownCreates, ["channel:hst-abc123-v01"]);
  assert.equal(row.outcome, "needs-recovery");
  assert.throws(() => admitFor(r), /does not close its run/);
  // A second recovery reads the same open create from the first.
  assert.deepEqual((await recoverHosting({}, r.deps)).openUnknownCreates, [
    "channel:hst-abc123-v01",
  ]);
});

test("a create that an own read shows and a 2xx delete removes is settled; one never shown is not", async () => {
  const r = await run();
  const channel = [...r.world.state.channels.values()][0];
  channel.deleted = false;
  const version = [...r.world.state.versions.values()][0];
  version.deleted = false;
  version.status = "CREATED";
  r.ledger.push(
    JSON.stringify(startedRow),
    JSON.stringify(
      endedRow({
        openUnknownCreates: [
          "channel:hst-abc123-v01",
          "version:v01",
          "channel:hst-abc123-v09",
          "version:v05",
        ],
      }),
    ),
  );
  const recovered = await recoverHosting({}, r.deps);
  assert.deepEqual(
    recovered.openUnknownCreates,
    ["channel:hst-abc123-v09", "version:v05"],
    "v09 and v05 were never listed",
  );
  assert.equal(recovered.outcome, "needs-recovery");
});

test("a run with no terminal row, or with unknown deletes, cannot be recovered clean", async () => {
  const r = await run();
  r.ledger.push(JSON.stringify(startedRow));
  const none = await recoverHosting({}, r.deps);
  assert.deepEqual(none.openUnknownCreates, ["run-ended-without-a-terminal-row"]);
  const { r: again } = await leftover({
    residualEntries: ["hst-abc123-v01: channel delete unknown (500)"],
  });
  const carried = await recoverHosting({}, again.deps);
  assert.equal(carried.outcome, "needs-recovery");
  assert.deepEqual(lastRow(again).carriedResidual, [
    "hst-abc123-v01: channel delete unknown (500)",
  ]);
  const closedRun = await run();
  await assert.rejects(recoverHosting({}, closedRun.deps), /no run of this task to recover/);
});

test("recovery also takes a needs-recovery run and leaves another run's channel alone", async () => {
  const { r, channel } = await leftover();
  const other = {
    ...channel,
    name: "projects/p/sites/s/channels/hst-ffffff-v01",
    url: `https://${hostOf("hst-ffffff-v01")}`,
    deleted: false,
  };
  r.world.state.channels.set("hst-ffffff-v01", other);
  const recovered = await recoverHosting({}, r.deps);
  assert.equal(recovered.outcome, "recovery-read-clean");
  assert.equal(other.deleted, false);
  assert.equal(channel.deleted, true);
});

test("web config validates project, number and key and includes the app hash", () => {
  const valid = {
    projectId: PROJECT,
    ...fakeSecrets,
    messagingSenderId: fakeSecrets.projectNumber,
    appId: `1:${fakeSecrets.projectNumber}:web:deadbeef1234`,
  };
  for (const patch of [
    { projectId: "other" },
    { projectNumber: "abc" },
    { messagingSenderId: "1" },
    { apiKey: "" },
    { apiKey: "short" },
  ])
    assert.throws(() => secretsFromWebConfig({ ...valid, ...patch }));
  assert.ok(secretsFromWebConfig(valid).includes("deadbeef1234"));
});

test("API replies are classified and the report pins the budget and corpus", () => {
  assert.equal(classify(reply(200, { ok: true })).kind, "ok");
  assert.equal(classify({ status: 200, text: "bad" }).kind, "unknown");
  for (const status of [0, 302, 500]) assert.equal(classify(reply(status)).kind, "unknown");
  assert.equal(classify(reply(403)).kind, "refused");
  const report = checkReport();
  assert.equal(report.corpusSha256, CORPUS_SHA256);
  assert.equal(
    report.worstCaseTotal,
    Object.values(CAPS).reduce((a, b) => a + b, 0),
  );
});

test("a private value in a header name is withheld and requires review", async () => {
  const secrets = { ...fakeSecrets, apiKey: "aizafakefakefakefakefakefake12345" };
  const r = await run({
    secrets,
    overrides: [fault("GET /data.json$/", answer(200, [[secrets.apiKey, "echo"]]))],
  });
  assert.equal(rowsOf(r).find((row) => row.id === "v01.static").reason, "private-value-withheld");
  assert.equal(r.result.outcome, "observed-unknown");
  assert.equal(terminal(r).needsReview, true);
  noSecrets(r, secrets);
});

test("a paged channel list or an earlier run's channel stops the run before any write or ledger row", async () => {
  for (const [what, listing] of [
    ["paged", { channels: [], nextPageToken: "more" }],
    ["earlier", { channels: [{ name: "projects/p/sites/s/channels/hst-ffffff-v01" }] }],
  ]) {
    const ledger = [JSON.stringify(closed)];
    await assert.rejects(
      run({
        overrides: [fault("GET /channels\\?pageSize=100/", reply(200, listing), 1)],
        setup: (_world, _deps, rows) => rows.splice(0, rows.length, ...ledger),
      }),
      /paged|earlier run/,
      what,
    );
  }
});

import { createBudget, makeApi } from "./record.mjs";

const channelsPost = "POST /channels\\?channelId=/";
const hostOf = (id) => `fireemu-oracle-idp--${id}-abcdef12.web.app`;

test("the REST client refuses an unreviewed host or scheme before it sends or spends", async () => {
  let sent = 0;
  const budget = createBudget();
  const api = makeApi({
    deps: {
      now: () => 0,
      token: async () => ({ value: "t", expiresAt: 1e12 }),
      http: async () => {
        sent += 1;
        return reply(200);
      },
      appendRunFile: async () => {},
    },
    budget,
    adc: {},
    runDir: "/r",
  });
  await assert.rejects(api.call("control", "GET", "https://evil.example/x"), /not reviewed/);
  await assert.rejects(
    api.call("control", "GET", "http://firebasehosting.googleapis.com/x"),
    /not reviewed/,
  );
  assert.equal(sent, 0);
  assert.deepEqual(budget.snapshot(), { token: 0, control: 0, cleanup: 0, upload: 0, edge: 0 });
});

test("a channel url that only looks like the run's host, or is not https, sends no edge request", async () => {
  const urls = [
    `https://${hostOf("hst-abc123-extra")}`,
    `https://${hostOf("hst-abc123-vzz")}`,
    `https://${hostOf("hst-ffffff-v01")}`,
    `http://${hostOf("hst-abc123-v01")}`,
  ];
  for (const url of urls) {
    const r = await run({
      overrides: [
        fault(
          channelsPost,
          reply(200, { name: "projects/p/sites/s/channels/hst-abc123-v01", url }),
        ),
      ],
    });
    assert.equal(edgeCalls(r).length, 0, url);
    assert.match(deployOf(r).v01.failure, /channel host/);
    // The injected answer created nothing in the fake world, so the run's DELETE reads 404 for a
    // create it saw answered 2xx: not settled in the run.
    assert.equal(r.result.outcome, "needs-recovery");
  }
});

test("the channel is created with a 24 hour ttl and the run label, the version with its labels", async () => {
  const r = await run();
  const body = (call) => JSON.parse(call.body);
  const channel = r.world.log.find(
    (call) => call.method === "POST" && call.url.includes("channelId="),
  );
  assert.deepEqual(body(channel), { ttl: "86400s", labels: { "fireemu-run": "abc123" } });
  const version = r.world.log.find(
    (call) => call.method === "POST" && call.url.endsWith("/versions"),
  );
  assert.deepEqual(body(version), {
    labels: { "fireemu-run": "abc123", "fireemu-version": "v01" },
  });
  for (const call of r.world.log.filter((c) => c.kind !== "edge")) {
    assert.equal(call.headers["x-goog-user-project"], PROJECT, call.url);
    assert.equal(call.headers.authorization, "Bearer fake-bearer");
  }
});

test("only a 400 on a version with optional keys is resent; any other refusal fails the version", async () => {
  const r = await run({ overrides: [fault(finalize, reply(403), 2)] });
  assert.equal(r.world.log.filter((call) => call.method === "PATCH").length, 2);
  assert.equal(deployOf(r).v02.droppedConfig, undefined);
  assert.match(deployOf(r).v02.failure, /finalize failed \(403\)/);
  assert.equal(r.result.outcome, "failed-cleaned");
});

test("an edge answer of 500 or 429 is an unknown row", async () => {
  const r = await run({
    overrides: [
      fault("GET /data.json$/", answer(500), 1),
      fault("GET /data.json\\?q=1$/", answer(429), 1),
    ],
  });
  const byId = Object.fromEntries(rowsOf(r).map((row) => [row.id, row]));
  assert.deepEqual(
    [byId["v01.static"].outcome, byId["v01.static"].reason],
    ["unknown", "http-500"],
  );
  assert.deepEqual([byId["v01.query"].outcome, byId["v01.query"].reason], ["unknown", "http-429"]);
});

test("a refused delete is residual, and an unknown delete that took effect still needs recovery", async () => {
  const refused = await run({ overrides: [fault(channelDelete, reply(403))] });
  assert.ok(
    resultOf(refused).residual.some((entry) => /channel delete refused \(403\)/.test(entry)),
  );
  assert.equal(refused.result.outcome, "needs-recovery");
  const took = await run({
    overrides: [
      fault(channelDelete, (_call, state) => {
        state.channels.get("hst-abc123-v01").deleted = true;
        return reply(500);
      }),
    ],
  });
  assert.equal(resultOf(took).readback.clean, true, "the read-back alone would pass");
  assert.equal(took.result.outcome, "needs-recovery");
  assert.equal(terminal(took).event, "needs-recovery");
  assert.equal(terminal(took).closureReady, false);
});

test("authorized domains that change during the run leave the run needing recovery", async () => {
  const r = await run({
    overrides: [
      fault(
        "GET /admin/v2/projects/fireemu-oracle-idp/config/",
        reply(200, { authorizedDomains: ["other.example"] }),
        2,
      ),
    ],
  });
  assert.equal(r.result.outcome, "needs-recovery");
  assert.equal(resultOf(r).readback.domainsUnchanged, false);
});

test("a thrown effect with a private value in its message reaches no file and no ledger row", async () => {
  const r = await run({
    setup: (_world, deps) => {
      deps.edge = async () => {
        throw new Error(`boom ${fakeSecrets.apiKey}`);
      };
    },
  });
  assert.equal(r.result.outcome, "failed-cleaned");
  assert.match(terminal(r).reason, /exception: boom #+/);
  noSecrets(r);
});

test("a disabled Hosting API stops the run before any write", async () => {
  await assert.rejects(
    run({
      overrides: [
        fault("GET /v1/projects/fireemu-oracle-idp/services/", reply(200, { state: "DISABLED" })),
      ],
    }),
    /DISABLED/,
  );
});

test("the ledger row says whether the lock stays", async () => {
  const served = {
    outcome: "answered",
    status: 200,
    headers: [
      ["etag", '"x"'],
      ["content-type", "text/html"],
    ],
    body: Buffer.from("first\n"),
  };
  const clean = await run({ overrides: [fault("GET /rewrite/a$/", served, undefined)] });
  assert.equal(clean.result.outcome, "recorded");
  assert.equal(terminal(clean).lockKept, false);
  const unknown = await run();
  assert.equal(terminal(unknown).lockKept, true);
  const broken = await run({ overrides: [fault(channelDelete, reply(500))] });
  assert.equal(terminal(broken).lockKept, true);
});

test("a stop during a version's requests ends its serving at once", async () => {
  let stop;
  const r = await run({
    setup: (world, deps) => {
      deps.installSignals = (handler) => {
        stop = handler;
      };
      deps.edge = async (call) => {
        const value = await world.edge(call);
        if (call.host.includes("-v02-") && !call.target.startsWith("/ready.txt?fireemu-ready="))
          stop();
        return value;
      };
    },
  });
  const v02 = rowsOf(r).filter((row) => row.version === "v02");
  assert.equal(v02[0].outcome, "answered");
  assert.ok(v02.slice(1).every((row) => row.reason === "stopped"));
  assert.equal(edgeCalls(r).filter((call) => call.host.includes("-v02-")).length, 2);
});

test("a hash the version does not hold, an unfinalized version and an endless listing fail safe", async () => {
  const hash = await run({
    overrides: [
      fault(
        "POST /:populateFiles/",
        reply(200, {
          uploadRequiredHashes: ["deadbeef"],
          uploadUrl: "https://upload-firebasehosting.googleapis.com/upload/x",
        }),
      ),
    ],
  });
  assert.match(deployOf(hash).v01.failure, /hash the version does not hold/);
  assert.equal(hash.world.log.filter((call) => call.kind === "upload").length, 0);
  const created = await run({
    overrides: [
      fault(
        "GET /sites/fireemu-oracle-idp/versions/[0-9]+$/",
        reply(200, { status: "CREATED", fileCount: "1" }),
        1,
      ),
    ],
  });
  assert.match(deployOf(created).v01.failure, /version is CREATED/);
  const endless = await run({
    overrides: [
      {
        match: "GET /versions\\?pageSize=100/",
        answer: (() => {
          let calls = 0;
          // The precheck reads one page; every later listing (the read-back) never ends.
          return () =>
            ++calls <= 1 ? undefined : reply(200, { versions: [], nextPageToken: "more" });
        })(),
      },
    ],
  });
  assert.equal(endless.result.outcome, "needs-recovery");
  assert.equal(resultOf(endless).readback.versionsTruncated, true);
});

test("a version create that was never applied is still unknown: absence does not settle it", async () => {
  for (const injected of ["network-error", reply(500), reply(302)]) {
    const r = await run({ overrides: [fault(versionCreate, injected)] });
    assert.equal(r.world.state.versions.size, 0, "the world applied nothing");
    assert.equal(r.result.outcome, "needs-recovery");
    assert.equal(terminal(r).closureReady, false);
    assert.ok(resultOf(r).needsRecovery.some((entry) => /version create unknown/.test(entry)));
    assert.deepEqual(terminal(r).openUnknownCreates, ["version:v01"]);
  }
});

test("a dependent header whose source request got no answer is an unsent dependency row", async () => {
  const r = await run({ overrides: [fault("GET /data.json$/", "timeout", 1)] });
  const byId = Object.fromEntries(rowsOf(r).map((row) => [row.id, row]));
  assert.equal(byId["v01.static"].reason, "network-error");
  assert.deepEqual(
    [byId["v01.cond-etag"].outcome, byId["v01.cond-etag"].reason],
    ["unknown", "dependency"],
  );
  assert.equal(r.result.outcome, "observed-unknown");
});

test("a delete that answers 404 for a confirmed create settles nothing in the run", async () => {
  for (const [what, match] of [
    ["channel", channelDelete],
    ["version", "DELETE /versions/"],
  ]) {
    const r = await run({ overrides: [fault(match, reply(404))] });
    assert.equal(r.result.outcome, "needs-recovery", what);
    assert.equal(terminal(r).closureReady, false, what);
    assert.ok(
      resultOf(r).residual.some((entry) =>
        new RegExp(`${what} delete refused \\(404\\)`).test(entry),
      ),
    );
  }
});

test("an unknown channel create that an own read then shows lets the run go on and clean up", async () => {
  let world;
  const r = await run({
    overrides: [
      fault(
        channelsPost,
        async (call) => {
          await world.http(call);
          return reply(500);
        },
        1,
      ),
    ],
    setup: (created) => {
      world = created;
    },
  });
  assert.equal(r.result.outcome, "observed-unknown", "the dependency row is the only unknown");
  assert.equal(deployOf(r).v01.channelCreate, "unknown");
  assert.equal(deployOf(r).v01.channelCreated, true);
  assert.ok(
    rowsOf(r)
      .filter((row) => row.version === "v01")
      .some((row) => row.outcome === "answered"),
  );
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.equal(terminal(r).closureReady, true);
});

test("an answer below 200 is unknown", () => {
  assert.equal(classify({ status: 199, text: "{}" }).kind, "unknown");
  assert.equal(classify({ status: 100, text: "" }).kind, "unknown");
  assert.equal(classify({ status: 399, text: "{}" }).kind, "unknown");
  assert.equal(classify({ status: 400, text: "{}" }).kind, "refused");
});

test("the channel is created under the project id, as every recorded create was", async () => {
  const r = await run();
  const create = r.world.log.find(
    (call) => call.method === "POST" && call.url.includes("channelId="),
  );
  assert.ok(
    create.url.startsWith(
      "https://firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp/channels?channelId=",
    ),
  );
  // The wildcard is recorded for version creates and releases, and the fake refuses it for a channel.
  const wildcard = await r.world.http({
    method: "POST",
    url: `${root}/projects/-/sites/${site}/channels?channelId=hst-abc123-v99`,
    body: "{}",
  });
  assert.equal(wildcard.status, 404);
  const versionCreate = r.world.log.find((call) =>
    call.url.endsWith("/projects/-/sites/fireemu-oracle-idp/versions"),
  );
  assert.ok(versionCreate);
});

test("a site whose version list already runs past two pages stops the run before any write", async () => {
  for (const [pages, refused] of [
    [1, false],
    [2, false],
    [3, true],
  ]) {
    let reads = 0;
    const attempt = run({
      overrides: [
        {
          match: "GET /versions\\?pageSize=100/",
          answer: () => {
            reads += 1;
            // Only the precheck's own reads are shaped; the read-back's reads are the world's.
            if (reads > 2) return undefined;
            return reads < pages
              ? reply(200, { versions: [], nextPageToken: `t${reads}` })
              : undefined;
          },
        },
      ],
    });
    if (refused) await assert.rejects(attempt, /runs past 2 pages/);
    else assert.equal((await attempt).result.closureReady, true, `${pages} pages`);
  }
});

test("an unknown delete is carried in the terminal row for the recovery and the coordinator", async () => {
  const r = await run({ overrides: [fault(channelDelete, reply(500))] });
  assert.equal(r.result.outcome, "needs-recovery");
  assert.ok(
    terminal(r).residualEntries.some((entry) => /channel delete unknown \(500\)/.test(entry)),
  );
  assert.deepEqual(terminal(r).openUnknownCreates, []);
});

test("the version name production returned (the project number in front) is accepted, masked in every file, and cleaned", async () => {
  const r = await run({ world: { versionNameForm: "number" } });
  assert.equal(r.result.outcome, "observed-unknown", "only the fake's dependency row is unknown");
  assert.equal(terminal(r).closureReady, true);
  assert.ok([...r.world.state.versions.values()].every((version) => version.status === "DELETED"));
  // The in-run calls use the returned name, so the number is in the URLs and must not be in any file.
  assert.ok(
    r.world.log.some((call) => call.url.includes(`/projects/${fakeSecrets.projectNumber}/sites/`)),
  );
  noSecrets(r);
  assert.match(r.files["journal.jsonl"], /projects\/#{12}\/sites\//);
  assert.match(deployOf(r).v01.version, /^projects\/#{12}\/sites\/fireemu-oracle-idp\/versions\//);
  const projectId = await run({ world: { versionNameForm: "projectId" } });
  assert.equal(terminal(projectId).closureReady, true);
  assert.equal(deployOf(projectId).v01.failure, undefined, "the project-id form is accepted too");
  assert.equal(projectId.result.outcome, "observed-unknown");
});

test("a version create that succeeded and then fails the name check is deleted before the run ends", async () => {
  const foreign = [
    ["another site", (name) => `projects/999/sites/other-site/versions/${name.split("/").at(-1)}`],
    ["another project number", (name) => `projects/555555555555/${name}`],
    ["another project id", (name) => `projects/other-project/${name}`],
  ];
  for (const [what, form] of foreign) {
    const r = await run({ world: { versionNameForm: form } });
    assert.match(deployOf(r).v01.failure, /version name is not the site's/, what);
    assert.equal(r.result.outcome, "failed-cleaned", what);
    assert.equal(terminal(r).closureReady, true, what);
    assert.ok(
      [...r.world.state.versions.values()].every((version) => version.status === "DELETED"),
      what,
    );
    assert.ok(
      [...r.world.state.channels.values()].every((channel) => channel.deleted),
      what,
    );
    const deletes = r.world.log.filter(
      (call) => call.method === "DELETE" && call.url.includes("/versions/"),
    );
    assert.equal(deletes.length, 1, what);
    assert.ok(deletes[0].url.endsWith(`/sites/fireemu-oracle-idp/versions/0000000000000001`), what);
    assert.equal(r.world.log.filter((call) => call.kind === "edge").length, 0, what);
  }
});

test("a version name with no usable id cannot be deleted by the run and stays for recovery", async () => {
  const r = await run({ world: { versionNameForm: () => "x" } });
  assert.match(deployOf(r).v01.failure, /version name is not the site's/);
  assert.equal(r.result.outcome, "needs-recovery");
  assert.deepEqual(resultOf(r).readback.versionsLeft, [
    "sites/fireemu-oracle-idp/versions/0000000000000001",
  ]);
  assert.equal(
    r.world.log.filter((call) => call.method === "DELETE" && call.url.includes("/versions/"))
      .length,
    0,
  );
});

test("the kept head of a probe body is bounded, and an unanswered last probe keeps none", async () => {
  const big = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) =>
          call.host.includes("-v01-")
            ? { ...answer(404), body: Buffer.alloc(500, "x") }
            : undefined,
      },
    ],
  });
  assert.equal(deployOf(big).v01.lastProbe.bodyBytes, 500);
  assert.equal(deployOf(big).v01.lastProbe.bodyHead, "x".repeat(200));
  const silent = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call, state) => {
          if (!call.host.includes("-v01-")) return undefined;
          state.silent = (state.silent ?? 0) + 1;
          return state.silent < READINESS_ATTEMPTS ? answer(404) : { status: 0 };
        },
      },
    ],
  });
  assert.equal(deployOf(silent).v01.readiness.at(-1), "network-error");
  assert.equal("lastProbe" in deployOf(silent).v01, false);
  assert.equal(deployOf(silent).v01.releaseOnChannel, true);
});

test("the channel's release is matched to the version whatever form its name has", async () => {
  const r = await run({
    world: { versionNameForm: "number" },
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
      },
    ],
  });
  assert.equal(deployOf(r).v01.releaseOnChannel, true);
});

test("a stop during the readiness window reads no channel and keeps no release verdict", async () => {
  let stop;
  const r = await run({
    setup: (_world, deps) => {
      deps.installSignals = (handler) => {
        stop = handler;
      };
    },
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => {
          if (!call.host.includes("-v01-")) return undefined;
          stop();
          return answer(404);
        },
      },
    ],
  });
  assert.equal(deployOf(r).v01.failure, "stopped");
  assert.equal("releaseOnChannel" in deployOf(r).v01, false);
  assert.equal(
    r.world.log.filter(
      (call) => call.method === "GET" && call.url?.endsWith("/channels/hst-abc123-v01"),
    ).length,
    0,
  );
});

// ---- V5: run ab8b85 (V4 launch 2): v02, v03 and v07 answered the "Site Not Found" page, X-Cache: HIT, to
// all 12 probes of the same URL while the channel held the release: the CDN had cached a negative
// answer from an early probe, so more probes of the same URL could not help. Run 658bb2 (launch 1)
// had every version ready on the first probe.

/** The log of the world with the waits in it, in order. */
const withSleepsInLog = (world, deps) => {
  deps.sleep = async (ms) => {
    world.log.push({ kind: "sleep", ms });
  };
};

test("the first readiness probe comes only after a wait that follows the release", async () => {
  const r = await run({ setup: (world, deps) => withSleepsInLog(world, deps) });
  for (const id of ["v01", "v05", "v10"]) {
    const host = `-${id}-`;
    const log = r.world.log;
    const release = log.findIndex(
      (c) => c.method === "POST" && c.url?.includes(`hst-abc123-${id}/releases`),
    );
    const first = log.findIndex((c) => c.kind === "edge" && c.host.includes(host));
    const wait = log.findIndex(
      (c, i) => c.kind === "sleep" && c.ms === READINESS_FIRST_WAIT_MS && i > release,
    );
    assert.ok(release >= 0 && wait > release && first > wait, id);
  }
  assert.equal(
    r.world.log.filter((c) => c.kind === "sleep" && c.ms === READINESS_FIRST_WAIT_MS).length,
    10,
  );
  assert.ok(READINESS_FIRST_WAIT_MS >= 30_000);
});

test("a stop during the first wait sends no probe", async () => {
  let stop;
  const r = await run({
    setup: (_world, deps) => {
      deps.installSignals = (handler) => {
        stop = handler;
      };
      deps.sleep = async (ms) => {
        if (ms === READINESS_FIRST_WAIT_MS) stop();
      };
    },
  });
  assert.equal(edgeCalls(r).length, 0);
  assert.equal(deployOf(r).v01.failure, "stopped");
});

test("every readiness probe has its own cache-busting query and no recorded request is changed", async () => {
  const r = await run({ overrides: [slowRelease(READINESS_ATTEMPTS - 1)] });
  const corpus = buildCorpus();
  const probes = edgeCalls(r).filter((call) => call.target.includes("fireemu-ready"));
  const others = edgeCalls(r).filter((call) => !call.target.includes("fireemu-ready"));
  // a version that is ready on the first probe is probed once; the slow ones 12 times
  assert.equal(probes.length, 6 + 4 * READINESS_ATTEMPTS);
  assert.equal(new Set(probes.map((call) => `${call.host}${call.target}`)).size, probes.length);
  for (const version of corpus.versions) {
    const mine = probes.filter((call) => call.host.includes(`-${version.id}-`));
    mine.forEach((call, index) =>
      assert.equal(call.target, `${version.readiness.path}?fireemu-ready=abc123-${index + 1}`),
    );
  }
  // the recorded requests go out exactly as the corpus has them
  assert.deepEqual(
    others.map((call) => `${call.method} ${call.target}`),
    corpus.versions.flatMap((version) =>
      version.requests
        .filter((spec) => spec.id !== "v01.cond-etag-rewrite")
        .map((spec) => `${spec.method} ${spec.target}`),
    ),
  );
  assert.ok(others.every((call) => !call.target.startsWith("/ready.txt?fireemu-ready=")));
});

test("a probe is judged by its status, whatever the query", async () => {
  // v09 expects 302: a `**` redirect answers the probe with its query too
  const r = await run();
  assert.equal(deployOf(r).v09.readiness.at(-1), 302);
  assert.equal(deployOf(r).v09.failure, undefined);
});

test("the x-cache of every probe is kept next to its status", async () => {
  let seen = 0;
  const r = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => {
          if (!call.host.includes("-v01-")) return undefined;
          seen += 1;
          if (seen === 1) return { ...answer(404, [["X-Cache", "HIT"]]) };
          if (seen === 2) return answer(404);
          if (seen === 3) return { status: 0 };
          return { ...answer(200, [["x-cache", "MISS, MISS"]]), body: Buffer.from("ready") };
        },
      },
    ],
  });
  assert.deepEqual(deployOf(r).v01.readiness, [404, 404, "network-error", 200]);
  assert.deepEqual(deployOf(r).v01.readinessXCache, ["HIT", null, null, "MISS, MISS"]);
});

test("a secret that straddles the cut of the kept body head never reaches a file, even in part", async () => {
  const secret = fakeSecrets.apiKey;
  const body = Buffer.from(`${"x".repeat(200 - 10)}${secret}${"y".repeat(50)}`);
  const r = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? { ...answer(404), body } : undefined),
      },
    ],
  });
  const head = deployOf(r).v01.lastProbe.bodyHead;
  assert.equal(head.length, 200);
  assert.equal(head.startsWith("x".repeat(190)), true);
  assert.equal(head.slice(190), "#".repeat(10));
  assert.equal(deployOf(r).v01.lastProbe.bodyBytes, body.length);
  const retained = JSON.stringify([r.files, r.ledger]);
  for (let i = 0; i + 6 <= secret.length; i += 1)
    assert.equal(retained.includes(secret.slice(i, i + 6)), false, String(i));
});

test("the channel's release is true, false for another version, absent when there is none, or unread", async () => {
  const dark = {
    match: "GET /ready.txt/",
    answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
  };
  const channelRead = (value) => fault("GET /channels/hst-abc123-v01$/", value);
  const withRelease = (release) => (_call, state) =>
    reply(200, { ...state.channels.get("hst-abc123-v01"), ...(release ? { release } : {}) });
  const cases = [
    [undefined, "absent", undefined],
    [{ version: { name: "sites/x/versions/other" }, type: "DEPLOY" }, false, ["type", "version"]],
    [{ type: "DEPLOY" }, "absent", ["type"]],
    [{ version: {} }, "absent", ["version"]],
    ["oops", "absent", undefined],
    [{ version: { name: "" } }, "absent", ["version"]],
  ];
  for (const [release, expected, keys] of cases) {
    const r = await run({ overrides: [dark, channelRead(withRelease(release))] });
    assert.equal(deployOf(r).v01.releaseOnChannel, expected, JSON.stringify(release));
    assert.deepEqual(deployOf(r).v01.releaseKeys, keys);
  }
  const ok = await run({ overrides: [dark] });
  assert.equal(deployOf(ok).v01.releaseOnChannel, true);
  assert.deepEqual(deployOf(ok).v01.releaseKeys, ["version"]);
  const unread = await run({ overrides: [dark, channelRead(reply(500))] });
  assert.equal(deployOf(unread).v01.releaseOnChannel, "unread");
  assert.equal("releaseKeys" in deployOf(unread).v01, false);
});

test("the launch's attempt number must be the recorder's count; two launches fit under US$6.00", () => {
  const four = [
    ...priorAttempt(1),
    ...priorAttempt(2),
    ...v4Attempt(1, { envelopeId: "HOSTING-PRODUCTION-V4-20261111" }),
    ...v4Attempt(2, { envelopeId: "HOSTING-PRODUCTION-V4-20261111" }),
  ];
  const check = (lines, env = {}) =>
    admit({
      ledgerText: lines.map((line) => JSON.stringify(line)).join("\n"),
      now,
      env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE, ...env },
    });
  assert.deepEqual(check(four, { FIREEMU_HOSTING_ATTEMPT: "1" }), {
    attempt: 1,
    cumulativeReservedUsd: 5,
  });
  const five = [...four, ...v4Attempt(1)];
  assert.deepEqual(check(five, { FIREEMU_HOSTING_ATTEMPT: "2" }), {
    attempt: 2,
    cumulativeReservedUsd: 6,
  });
  assert.throws(
    () => check([...five, ...v4Attempt(2)], { FIREEMU_HOSTING_ATTEMPT: "3" }),
    /US\$6\.00/,
  );
  // a number that is not the count of the envelope is refused, before anything is sent
  assert.throws(() => check(four, { FIREEMU_HOSTING_ATTEMPT: "2" }), /FIREEMU_HOSTING_ATTEMPT/);
  assert.throws(() => check(five, { FIREEMU_HOSTING_ATTEMPT: "1" }), /FIREEMU_HOSTING_ATTEMPT/);
  assert.throws(() => check(four, { FIREEMU_HOSTING_ATTEMPT: "1.0" }), /FIREEMU_HOSTING_ATTEMPT/);
  assert.throws(() => check(four, { FIREEMU_HOSTING_ATTEMPT: "" }), /FIREEMU_HOSTING_ATTEMPT/);
  // not set: the count alone decides (the older callers)
  assert.equal(check(four).attempt, 1);
});

test("a run whose launch names the wrong attempt sends nothing", async () => {
  await assert.rejects(run({ env: { FIREEMU_HOSTING_ATTEMPT: "2" } }), /FIREEMU_HOSTING_ATTEMPT/);
});
