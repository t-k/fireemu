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
    assert.equal(r.result.outcome, "failed-cleaned", "the channel is deleted by its id");
    assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
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

test("recovery also takes a needs-recovery run and leaves another run's channel alone", async () => {
  const r = await run();
  const channel = [...r.world.state.channels.values()][0];
  channel.deleted = false;
  const other = {
    ...channel,
    name: "projects/p/sites/s/channels/hst-ffffff-v01",
    url: `https://${hostOf("hst-ffffff-v01")}`,
    deleted: false,
  };
  r.world.state.channels.set("hst-ffffff-v01", other);
  r.ledger.push(
    JSON.stringify({
      ...closed,
      taskId: TASK_ID,
      event: "started",
      run: "abc123",
      authorizedDomainsBefore: ["localhost"],
    }),
    JSON.stringify({
      ...closed,
      taskId: TASK_ID,
      event: "needs-recovery",
      outcome: "needs-recovery",
      run: "abc123",
    }),
  );
  const recovered = await recoverHosting({}, r.deps);
  assert.equal(recovered.outcome, "recovered", "another run's channel is not this run's to judge");
  assert.equal(other.deleted, false);
  assert.equal(channel.deleted, true);
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
        if (call.host.includes("-v02-") && call.target !== "/ready.txt") stop();
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
        answer: reply(200, { versions: [], nextPageToken: "more" }),
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
