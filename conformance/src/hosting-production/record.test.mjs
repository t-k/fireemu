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
  const channels = `${root}/projects/-/sites/${site}/channels`;
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
  recordHosting,
  recoverHosting,
  secretsFromWebConfig,
  TASK_ID,
} from "./record.mjs";

const now = Date.parse("2026-11-10T12:00:00Z");
const fakeSecrets = { apiKey: "AIzaFAKEFAKEFAKEFAKEFAKEFAKE12345", projectNumber: "123456789012" };
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
  const world = createWorld({ run: "abc123", secrets, overrides: options.overrides ?? [] });
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
  const result = await recordHosting({}, deps);
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
  for (const call of r.world.log) {
    if (call.kind === "edge" || call.kind === "upload") counts[call.kind]++;
    else if (
      call.method === "DELETE" ||
      (call.method === "GET" &&
        (call.url.includes("/sites/fireemu-oracle-idp/versions?") ||
          (call.url.includes("/channels?") && counts.control >= 4) ||
          (call.url.includes("identitytoolkit") && counts.control >= 4)))
    )
      counts.cleanup++;
    else counts.control++;
  }
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

test("readiness retries twice, cleans the version and continues", async () => {
  const r = await run({
    overrides: [
      {
        match: "GET /ready.txt/",
        answer: (call) => (call.host.includes("-v01-") ? answer(404) : undefined),
      },
    ],
  });
  assert.equal(r.sleeps.filter((ms) => ms === 10000).length, 2);
  assert.ok(
    rowsOf(r)
      .filter((row) => row.version === "v01")
      .every((row) => row.reason === "not-ready"),
  );
  assert.equal(r.world.state.versions.size, 10);
  assert.ok([...r.world.state.versions.values()].every((version) => version.deleted));
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
        if (call.host.includes("-v02-") && call.target !== "/ready.txt") stop();
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
    admit({ ledgerText: lines.map((line) => JSON.stringify(line)).join("\n"), now, env });
  assert.equal(check([closed]).attempt, 1);
  assert.throws(() => check([{ ...closed, event: "needs-recovery" }]));
  const recent = { ...closed, ts: new Date(now).toISOString() };
  assert.throws(() => check([recent]));
  assert.equal(check([recent], { FIREEMU_HOSTING_SOLE_SENDER: "1" }).attempt, 1);
  const started = { ...closed, taskId: TASK_ID, event: "started" };
  assert.throws(() => check([started, closed]));
  const done = { ...closed, taskId: TASK_ID };
  assert.equal(check([started, done, { ...started, project: "other" }]).attempt, 2);
  assert.throws(() => check([started, done, started, done, started, done]));
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

test("recovery deletes leftovers, reports failures and rejects closed runs", async () => {
  for (const fail of [false, true]) {
    const r = await run();
    const channel = [...r.world.state.channels.values()][0];
    channel.deleted = false;
    const version = [...r.world.state.versions.values()][0];
    version.deleted = false;
    version.status = "CREATED";
    r.ledger.push(
      JSON.stringify({
        ...closed,
        taskId: TASK_ID,
        event: "started",
        run: "abc123",
        authorizedDomainsBefore: ["localhost"],
      }),
    );
    if (fail) {
      const http = r.deps.http;
      r.deps.http = (call) => (call.method === "DELETE" ? reply(500) : http(call));
    }
    const start = r.world.log.length;
    const recovered = await recoverHosting({}, r.deps);
    assert.equal(recovered.outcome, fail ? "needs-recovery" : "recovered");
    assert.equal(terminal(r).event, fail ? "needs-recovery" : "cleanup-verified");
    assert.ok(
      r.world.log.slice(start).every((call) => call.method !== "POST" && call.kind !== "edge"),
    );
  }
  const r = await run();
  await assert.rejects(recoverHosting({}, r.deps));
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
