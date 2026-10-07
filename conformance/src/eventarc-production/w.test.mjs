import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { wManifest, wBody, wAcceptance, recordW, wAdmission, W_A2_RULING } from "./w.mjs";
import { hProductionAnswer } from "./h-production.mjs";
import { readWJournal, main } from "./w-run.mjs";

const manifest = (stage = "w0", prerequisite) =>
  wManifest({
    project: "fireemu-oracle-events",
    runId: "adbcfeadbcfe",
    stage,
    prerequisite,
  });
const native = (status, body, host) => {
  const text = JSON.stringify(body, null, 2);
  const bytes = Buffer.from(
    `${host === "usage" ? text.replace(/[<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) : text}\n`,
  );
  return { status, body, bodyBase64: bytes.toString("base64"), bodyBytes: bytes.length };
};
const corpus = ["stage-c-replay", "h1-preflight", "h-readiness", "h-lists", "v7-replay"].flatMap(
  (name) => JSON.parse(readFileSync(new URL(`./fixtures/h-fe/${name}.json`, import.meta.url))),
);
const template = (predicate) => structuredClone(corpus.find(predicate).body);

test("W family reaches every ladder point and adjacent bytes below the ceiling", () => {
  const m = manifest();
  for (const size of [65536, ...m.ladder, m.ceiling]) {
    const a = wBody(m, 1, size);
    assert.equal(Buffer.byteLength(a.raw), size);
    assert.equal(a.body.events.length, 100);
    assert.ok(a.anyBytes.every((n) => n < 450000));
    assert.equal(new Set(a.body.events.map((e) => e.id)).size, 100);
    assert.ok(a.body.events.every((e) => typeof JSON.parse(e.textData) === "string"));
    assert.equal(wBody(m, 2, size).requestBytes, a.requestBytes);
  }
  const a = wBody(m, 3, 65536),
    b = wBody(m, 3, 65536, 2);
  assert.deepEqual(JSON.parse(a.raw), JSON.parse(b.raw));
  assert.equal(b.httpBytes, a.httpBytes + 2);
  assert.equal(b.requestBytes, a.requestBytes);
  assert.throws(() => wBody(m, 1, m.ceiling + 1), /ceiling/);
  assert.throws(() => wBody(m, 1, m.ceiling, 1), /ceiling/);
  assert.throws(() => wBody(m, 21, 65536), /recipe/);
  assert.throws(
    () => wBody({ ...m, ceiling: 60 * 1024 * 1024 }, 1, 45 * 1024 * 1024),
    /individual Any/,
  );
});

test("W refusals require native request-size attribution and exclude per-event errors", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
    recipe: { httpBytes: 1000000, requestBytes: 990000 },
  };
  const body = template((r) => r.status === 400 && r.body.error?.message === "No events provided.");
  body.error.message =
    "The request size (1000000 bytes) is too large. The maximum size is 999999 bytes.";
  body.error.details[0].fieldViolations[0].description = body.error.message;
  assert.equal(wAcceptance(native(400, body), spec), false);
  for (const message of [
    "The event size (1000000 bytes) is too large. The maximum size is 999999 bytes.",
    "Too many events.",
    "Quota exceeded.",
    "Request too large.",
  ]) {
    const changed = structuredClone(body);
    changed.error.message = message;
    changed.error.details[0].fieldViolations[0].description = message;
    assert.equal(wAcceptance(native(400, changed), spec), null);
  }
  const badLayout = native(400, body);
  badLayout.bodyBase64 = Buffer.from(
    Buffer.from(badLayout.bodyBase64, "base64").toString().replace("  ", "\t "),
  ).toString("base64");
  assert.equal(wAcceptance(badLayout, spec), null);
  assert.equal(wAcceptance({ ...native(400, body), bodyBytes: 1 }, spec), null);
  assert.equal(
    wAcceptance(native(400, body), {
      ...spec,
      recipe: { httpBytes: 2000000, requestBytes: 1900000 },
    }),
    null,
  );
  assert.equal(wAcceptance(native(200, {}), spec), true);
  assert.equal(wAcceptance({ ...native(200, {}), bodyBytes: 2 }, spec), null);
  assert.equal(wAcceptance(native(503, body), spec), null);
  assert.equal(wAcceptance(native(429, body), spec), null);
  assert.equal(
    wAcceptance(native(400, body), { ...spec, path: "/v1/foreign:publishEvents" }),
    null,
  );
});

// Resource answers use recorded bodies and the real production judge; only instance values change.
async function replay(stage = "w0", mode = "normal", prerequisite, defer = false) {
  const m = manifest(stage, prerequisite),
    calls = [],
    notes = [];
  let clock = 0,
    present = false,
    topicPresent = false;
  const topic = `projects/${m.project}/topics/w-managed`,
    operations = new Map();
  const operation = (action) => {
    const body = template((r) => r.sequence === (action === "create" ? 4 : 11) && r.path);
    body.name = `${m.parent}/operations/w-${action}`;
    body.metadata.target = m.channel;
    operations.set(body.name, { action, body });
    return body;
  };
  const transports = Object.fromEntries(
    ["usage", "eventarc", "pubsub", "publishing"].map((host) => [
      host,
      {
        request: async (spec) => {
          calls.push({ host, ...spec });
          let status = 200,
            body;
          if (host === "publishing") {
            if (mode === "unknown-publish") return { unknown: true, status: 503, body: {} };
            const size = Buffer.byteLength(spec.rawBody);
            const accepted =
              mode === "all-accepted" ||
              (mode === "logical" ? spec.recipe.httpBytes - spec.recipe.whitespace : size) <=
                1500000;
            if (accepted) body = {};
            else {
              status = 400;
              body = template(
                (r) => r.status === 400 && r.body.error?.message === "No events provided.",
              );
              body.error.message = `The request size (${size} bytes) is too large. The maximum size is 1500000 bytes.`;
              body.error.details[0].fieldViolations[0].description = body.error.message;
            }
          } else if (host === "usage") {
            body = template(
              (r) =>
                Array.isArray(r.body.services) &&
                r.body.services.some((s) => s.config?.name === "eventarcpublishing.googleapis.com"),
            );
            if (mode === "api-disabled")
              body.services = body.services.filter(
                (s) => s.config.name !== "eventarcpublishing.googleapis.com",
              );
          } else if (spec.path.includes("/topics?"))
            body = topicPresent ? { topics: [{ name: topic }] } : {};
          else if (spec.path.endsWith("/triggers"))
            body =
              mode === "dependent" && present
                ? { triggers: [{ name: `${m.parent}/triggers/foreign`, channel: m.channel }] }
                : {};
          else if (spec.path.includes("/operations/")) {
            const own = operations.get(spec.path.slice(4));
            if (mode === "pending-delete" && own.action === "delete") {
              body = template((r) => r.case === "channel-operation-not-done");
              body.name = own.body.name;
              body.metadata.target = m.channel;
            } else {
              body = template((r) => r.sequence === 13 && r.path);
              body.name = own.body.name;
              body.metadata.target = m.channel;
              body.metadata.verb = own.action;
              if (own.action === "delete") {
                present = false;
                topicPresent = mode === "topic-left";
              }
              if (mode === "wrong-target") body.metadata.target += "-foreign";
            }
          } else if (spec.method === "POST") {
            present = true;
            topicPresent = true;
            if (mode === "unknown-create") return { unknown: true, status: 503, body: {} };
            body = operation("create");
          } else if (spec.method === "DELETE") {
            if (mode === "unknown-delete") return { unknown: true, status: 503, body: {} };
            body = operation("delete");
          } else if (present && mode !== "unknown-create") {
            body = template(
              (r) =>
                r.status === 200 &&
                r.method === "GET" &&
                (r.path ?? r.url).includes("/channels/") &&
                r.body.pubsubTopic,
            );
            body.name = m.channel;
            body.pubsubTopic = topic;
          } else {
            status = 404;
            body = template(
              (r) =>
                r.status === 404 && r.method === "GET" && (r.path ?? r.url).includes("/channels/"),
            );
          }
          const answer = native(status, body, host);
          if (host !== "publishing")
            assert.equal(
              hProductionAnswer(answer, { ...spec, host }),
              true,
              `${host} ${spec.method} ${spec.path}`,
            );
          return answer;
        },
      },
    ]),
  );
  if (defer) return { transports, calls };
  const result = await recordW({
    manifest: m,
    transports,
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    note: (kind, value) => notes.push({ kind, value: structuredClone(value) }),
  });
  return { result, calls, notes };
}

test("W0 discovers an interval through real resource judges and cleans its exact channel", async () => {
  const { result, calls } = await replay();
  assert.equal(result.stopped, null);
  assert.equal(result.cleanupReady, true);
  assert.ok(result.boundary.refused - result.boundary.accepted <= 4096);
  assert.equal(calls.filter((c) => c.method === "DELETE").length, 1);
  assert.ok(result.counts.publish <= 20);
  assert.equal(result.publishes[0].accepted, true);
});

test("W1 and W2 confirm adjacent bytes and distinguish HTTP and logical dependence", async () => {
  const prerequisite = { accepted: 1499900, refused: 1500100 };
  for (const mode of ["normal", "logical"]) {
    const one = await replay("w1", mode, prerequisite);
    assert.equal(one.result.stopped, null);
    assert.deepEqual(one.result.boundary, { accepted: 1500000, refused: 1500001 });
    assert.equal(
      one.result.layer,
      mode === "normal" ? "http-body-dependent" : "logical-request-dependent",
    );
    assert.ok(one.result.counts.publish <= 18);
    const confirmed = one.calls.find((c) => c.recipe?.purpose === "accepted-confirmation");
    for (const variant of one.calls.filter((c) => c.recipe?.whitespace)) {
      assert.deepEqual(JSON.parse(variant.rawBody), JSON.parse(confirmed.rawBody));
      assert.equal(variant.recipe.requestBytes, confirmed.recipe.requestBytes);
    }
    const two = await replay("w2", mode, one.result.boundary);
    assert.equal(two.result.stopped, null);
    assert.equal(two.result.counts.publish, 6);
    assert.equal(two.result.cleanupReady, true);
  }
});

test("W A2 polls only its own prior DELETE and preserves unknown CREATE and topic obligations", async () => {
  for (const outcome of [
    "done",
    "pending",
    "foreign-target",
    "foreign-name",
    "channel-present",
    "topic-present",
    "unknown-create",
    "unknown-delete",
  ]) {
    const m = manifest(),
      channel = m.channel,
      topic = `projects/${m.project}/topics/managed-w`,
      operation = `${m.parent}/operations/own-delete`;
    const recording = {
      manifest: m,
      startedAt: 0,
      lastRequestAt: 0,
      baselineAbsent: true,
      baselineTopics: [],
      baselineTriggers: [],
      topic,
      stopped: null,
      evidenceComplete: true,
      cleanupReady: false,
      writes: [
        {
          name: channel,
          action: "create",
          state: outcome === "unknown-create" ? "unknown" : "confirmed",
        },
        {
          name: channel,
          action: "delete",
          state: "pending",
          ...(outcome === "unknown-delete" ? {} : { operation }),
        },
      ],
    };
    const calls = [];
    let clock = 600_000;
    const result = await recordW({
      manifest: m,
      recording,
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      },
      note: () => {},
      transports: Object.fromEntries(
        ["eventarc", "pubsub"].map((host) => [
          host,
          {
            request: async (spec) => {
              calls.push(spec);
              assert.equal(spec.method, "GET");
              let body,
                status = 200;
              if (spec.path.includes("/operations/")) {
                body = template((r) =>
                  outcome === "pending"
                    ? r.case === "channel-operation-not-done"
                    : r.sequence === 13 && r.path,
                );
                body.name = outcome === "foreign-name" ? operation + "-foreign" : operation;
                body.metadata.target =
                  outcome === "foreign-target" ? channel + "-foreign" : channel;
              } else if (spec.path.includes("/channels/")) {
                status = outcome === "channel-present" ? 200 : 404;
                body = template(
                  (r) =>
                    r.status === status &&
                    r.method === "GET" &&
                    (r.path ?? r.url).includes("/channels/") &&
                    (status === 404 || r.body.pubsubTopic),
                );
                if (status === 200) {
                  body.name = channel;
                  body.pubsubTopic = topic;
                }
              } else
                body =
                  outcome === "topic-present" && spec.path.includes("/topics?")
                    ? { topics: [{ name: topic }] }
                    : {};
              const answer = native(status, body);
              assert.equal(hProductionAnswer(answer, { ...spec, host }), true);
              return answer;
            },
          },
        ]),
      ),
    });
    assert.equal(result.cleanupReady, outcome === "done", outcome);
    assert.ok(result.counts.cleanup <= 38);
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
    if (outcome === "unknown-create") assert.equal(calls.length, 1);
  }
});

test("W A2 requires spacing, exhaustive pages and the original wall cap", async () => {
  const m = manifest();
  const recording = {
    manifest: m,
    startedAt: 0,
    lastRequestAt: 0,
    baselineAbsent: true,
    baselineTopics: [],
    baselineTriggers: [],
    topic: `projects/${m.project}/topics/managed`,
    writes: [{ action: "create", name: m.channel, state: "confirmed" }],
    publishes: [],
    stopped: null,
    evidenceComplete: true,
  };
  await assert.rejects(
    recordW({ manifest: m, recording, now: () => 599_999, note: () => {} }),
    /ten minutes/,
  );
  let calls = 0;
  const late = await recordW({
    manifest: m,
    recording,
    now: () => m.wallMs,
    note: () => {},
    sleep: async () => {},
    transports: {},
  });
  assert.equal(late.cleanupReady, false);
  assert.match(late.cleanupError, /wall/);
  const spent = await recordW({
    manifest: m,
    recording: { ...recording, a2Requests: 38 },
    now: () => 600_000,
    note: () => {},
    sleep: async () => {},
    transports: {},
  });
  assert.equal(spent.cleanupReady, false);
  assert.match(spent.cleanupError, /ceiling/);
  assert.equal(spent.counts.cleanup, 0);
  const incomplete = await recordW({
    manifest: m,
    now: () => 0,
    note: () => {},
    sleep: async () => {},
    transports: {
      usage: {
        request: async () => {
          calls++;
          return native(200, { services: [], nextPageToken: "still-more" });
        },
      },
    },
  });
  assert.equal(calls, 1);
  assert.match(incomplete.stopped, /needs-review/);
  assert.equal(incomplete.writes.length, 0);
});

test("W refuses changed W2 boundaries and inconsistent whitespace layers", async () => {
  const moved = await replay("w2", "normal", {
    accepted: 1500001,
    refused: 1500002,
    layer: "http-body-dependent",
  });
  assert.match(moved.result.stopped, /boundary changed/);
  const layer = await replay("w2", "logical", {
    accepted: 1500000,
    refused: 1500001,
    layer: "http-body-dependent",
  });
  assert.match(layer.result.stopped, /layer changed/);
  assert.equal(layer.result.evidenceComplete, false);
});

test("W journal recovery keeps unanswered intents and latest A2 spacing", () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "journal-"));
  try {
    const runId = manifest().runId,
      state = {
        manifest: manifest(),
        writes: [{ name: manifest().channel, action: "delete", state: "unknown" }],
      };
    const own = join(dir, `issued-${runId}.jsonl`);
    writeFileSync(
      own,
      JSON.stringify({ at: 0, kind: "w-state", value: state }) +
        "\n" +
        JSON.stringify({ at: 100, kind: "request" }) +
        "\n{",
    );
    writeFileSync(
      join(dir, `issued-${runId}-a2-20261007T010000Z.jsonl`),
      JSON.stringify({ at: 200, kind: "answer" }) + "\n",
    );
    const recovered = readWJournal(own);
    assert.equal(recovered.writes[0].state, "unknown");
    assert.equal(recovered.lastRequestAt, 200);
    assert.throws(() => readWJournal(join(dir, "other.jsonl")), /original/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("W entry fails before credentials or writes for unfrozen and wrongly pinned input", async () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "entry-"));
  try {
    const config = {
      project: manifest().project,
      stage: "w0",
      runId: manifest().runId,
      sourceCommit: "a".repeat(40),
      reserveUsd: 0.05,
      packetReserveUsd: 0.15,
      parentBudgetUsd: 14,
      out: join(dir, "out"),
      sandboxLedger: join(dir, "ledger.jsonl"),
      lockDir: join(dir, "locks"),
      ownerLedger: join(dir, "owner.md"),
      packetDir: dir,
    };
    const input = join(dir, "input.json");
    writeFileSync(input, JSON.stringify(config));
    const descriptor = {
      status: "ready",
      sourceCommit: config.sourceCommit,
      executions: [{ stage: "w0", runId: config.runId }],
      sourceHashes: {},
      artifactHashes: {},
    };
    writeFileSync(join(dir, "w-descriptor.json"), JSON.stringify(descriptor));
    const env = {
        PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin`,
      },
      errors = [];
    const io = { stdout: { write: () => {} }, stderr: { write: (text) => errors.push(text) } };
    const deps = {
      head: () => config.sourceCommit,
      execToken: () => {
        throw new Error("credentials must not run");
      },
    };
    assert.equal(await main(["--config", input], env, io, deps), 2);
    assert.match(errors.pop(), /not coordinator-frozen/);
    descriptor.status = "frozen";
    descriptor.sourceHashes[input] = "b".repeat(64);
    writeFileSync(join(dir, "w-descriptor.json"), JSON.stringify(descriptor));
    assert.equal(await main(["--config", input], env, io, deps), 2);
    assert.match(errors.pop(), /source changed/);
    assert.equal(await main(["--config", input], { PATH: "/usr/bin" }, io, deps), 2);
    assert.match(errors.pop(), /Node 24/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("W entry records exact emitted bytes with real judges and gates E, V, ruling and revocation", async () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  for (const failure of [
    null,
    "missing-e",
    "duplicate-v",
    "ruling-changed",
    "revoked",
    "artifact-changed",
  ]) {
    const dir = mkdtempSync(join(root, "entry-replay-"));
    try {
      const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
      const config = {
        project: manifest().project,
        stage: "w0",
        runId: manifest().runId,
        sourceCommit: "a".repeat(40),
        reserveUsd: 0.05,
        packetReserveUsd: 0.15,
        parentBudgetUsd: 14,
        out: join(dir, "out"),
        sandboxLedger: join(dir, "ledger.jsonl"),
        lockDir: join(dir, "locks"),
        ownerLedger: join(dir, "owner.md"),
        packetDir: dir,
      };
      const artifacts = Object.fromEntries(
        ["eventarc-packet-w.md", "w-checklist.md", "w-mutation-report.md"].map((name) => {
          writeFileSync(join(dir, name), name);
          return [name, hash(name)];
        }),
      );
      const source = new URL("./w.mjs", import.meta.url).pathname;
      const descriptor = {
        status: "frozen",
        sourceCommit: config.sourceCommit,
        executions: [{ stage: config.stage, runId: config.runId }],
        sourceHashes: { [source]: hash(readFileSync(source)) },
        artifactHashes: artifacts,
        envelopeBodies: { w0: `envelopeId=EVENTARC-W-${config.runId}; reserveUsd=0.05` },
      };
      const descriptorBytes = JSON.stringify(descriptor);
      writeFileSync(join(dir, "w-descriptor.json"), descriptorBytes);
      const vBody = `decision=APPROVE; envelopeId=EVENTARC-W-${config.runId}; packetSha256=${artifacts["eventarc-packet-w.md"]}; checklistSha256=${artifacts["w-checklist.md"]}; mutationSha256=${artifacts["w-mutation-report.md"]}; descriptorSha256=${hash(descriptorBytes)}; sourceCommit=${config.sourceCommit}`;
      const e = `- 2026-10-07 | EVENTARC-PACKET-W envelope | ${descriptor.envelopeBodies.w0} | coordinator | private-review.md`;
      const v = `- 2026-10-07 | EVENTARC-PACKET-W | ${vBody} | coordinator | private-review.md`;
      const lines = [
        failure === "ruling-changed" ? W_A2_RULING + "changed" : W_A2_RULING,
        ...(failure === "missing-e" ? [] : [e]),
        v,
        ...(failure === "duplicate-v" ? [v] : []),
        ...(failure === "revoked"
          ? [
              `- 2026-10-07 | EVENTARC-PACKET-W envelope | REVOKED envelopeId=EVENTARC-W-${config.runId} | coordinator | private-review.md`,
            ]
          : []),
      ];
      writeFileSync(config.ownerLedger, lines.join("\n") + "\n");
      if (failure === "artifact-changed") writeFileSync(join(dir, "w-checklist.md"), "changed");
      const input = join(dir, "input.json");
      writeFileSync(input, JSON.stringify(config));
      const world = await replay("w0", "normal", undefined, true);
      let credentials = 0,
        requests = 0;
      const output = [],
        errors = [],
        io = {
          stdout: { write: (text) => output.push(text) },
          stderr: { write: (text) => errors.push(text) },
        };
      const code = await main(
        ["--config", input],
        { PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin` },
        io,
        {
          head: () => config.sourceCommit,
          now: () => 0,
          sleep: async () => {},
          execToken: async () => {
            credentials++;
            return "offline-not-a-real-credential";
          },
          fetchImpl: async (address, options) => {
            requests++;
            assert.equal(options.redirect, "manual");
            assert.equal(options.headers["accept-encoding"], "identity");
            assert.equal(options.headers["x-goog-user-project"], config.project);
            const url = new URL(address),
              host = {
                "serviceusage.googleapis.com": "usage",
                "eventarc.googleapis.com": "eventarc",
                "pubsub.googleapis.com": "pubsub",
                "eventarcpublishing.googleapis.com": "publishing",
              }[url.hostname];
            const spec = {
              method: options.method,
              path: url.pathname + url.search,
              ...(options.body === undefined ? {} : { body: JSON.parse(options.body) }),
              ...(host === "publishing"
                ? {
                    rawBody: options.body,
                    recipe: { httpBytes: Buffer.byteLength(options.body), whitespace: 0 },
                  }
                : {}),
            };
            const answer = await world.transports[host].request(spec);
            return new Response(Buffer.from(answer.bodyBase64, "base64"), {
              status: answer.status,
              headers: { "content-type": "application/json" },
            });
          },
        },
      );
      assert.equal(code, failure === null ? 0 : 2, errors.join(""));
      assert.equal(credentials, failure === null ? 1 : 0);
      if (failure === null) {
        assert.ok(requests <= 86);
        const recovered = readWJournal(join(config.out, `issued-${config.runId}.jsonl`));
        assert.equal(recovered.cleanupReady, true);
        const captures = readFileSync(join(config.out, `capture-${config.runId}.jsonl`), "utf8");
        assert.doesNotMatch(captures, /offline-not-a-real-credential|authorization/i);
        const entries = captures
          .trim()
          .split("\n")
          .map(JSON.parse)
          .filter((r) => r.case === "w-publish");
        assert.equal(entries.length, recovered.publishes.length);
        for (let i = 0; i < entries.length; i++) {
          assert.equal(entries[i].requestBytes, recovered.publishes[i].httpBytes);
          assert.equal(entries[i].requestSha256, recovered.publishes[i].sha256);
        }
      } else assert.equal(requests, 0);
    } finally {
      rmSync(dir, { recursive: true });
    }
  }
});

test("W stops on unknowns, unavailable APIs, incomplete cleanup and unobserved boundaries", async () => {
  for (const mode of [
    "unknown-publish",
    "api-disabled",
    "unknown-create",
    "unknown-delete",
    "pending-delete",
    "wrong-target",
    "dependent",
    "topic-left",
    "all-accepted",
  ]) {
    const { result, calls } = await replay("w0", mode);
    assert.equal(
      result.cleanupReady,
      ["unknown-publish", "all-accepted", "api-disabled"].includes(mode),
      mode,
    );
    assert.ok(calls.filter((c) => c.method === "DELETE").length <= 1);
    if (mode === "api-disabled") assert.equal(calls.filter((c) => c.method === "POST").length, 0);
    if (mode === "unknown-publish") assert.equal(result.counts.publish, 1);
    if (mode === "all-accepted") {
      assert.equal(result.boundary, null);
      assert.equal(result.counts.publish, 8);
    }
    if (mode === "unknown-create")
      assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
  }
});

test("W prerequisites and admission bind the checkpoint with a ledger-compatible line", () => {
  assert.throws(() => manifest("w1"), /prerequisite/);
  assert.throws(() => manifest("w1", { accepted: 1048576, refused: 2097152 }), /interval/);
  assert.throws(() => manifest("w2", { accepted: 1048576, refused: 1048578 }), /adjacent/);
  const line = wAdmission({
    stage: "w1",
    runId: "adbcfeadbcfe",
    sourceCommit: "a".repeat(40),
    checkpointSha256: "b".repeat(64),
    date: "2026-10-07",
  });
  assert.equal(line.split(" | ").length, 5);
  assert.match(line, /checkpoint=b{64}; decision=APPROVE/);
});
