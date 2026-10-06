import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { hProductionAnswer, hProductionEvidence } from "./eventarc-production/h-production.mjs";
import { hReadList, hReady, hCliFailed } from "./eventarc-production/h-deploy.mjs";
import { parseHEntries, hCapture, judgeH } from "./eventarc-production/h-capture.mjs";
import { recordH, hA2 } from "./eventarc-production/h-record.mjs";
import { hManifest } from "./eventarc-production/h-script.mjs";

const fe = JSON.parse(
  readFileSync(
    new URL("./eventarc-production/fixtures/h-fe/v7-replay.json", import.meta.url),
    "utf8",
  ),
);
const stageC = JSON.parse(
  readFileSync(
    new URL("./eventarc-production/fixtures/h-fe/stage-c-replay.json", import.meta.url),
    "utf8",
  ),
);
const m = hManifest({ project: "fireemu-oracle-events", runId: "cafe60000001" });

for (const recorded of [...fe, ...stageC]) {
  test(`H production judges replay ${recorded.run} ${recorded.sequence ?? `${recorded.file}:${recorded.line}`}`, () => {
    const url = new URL(
      recorded.url ?? recorded.path,
      `https://${recorded.sequence === 1 ? "serviceusage" : [184, 190].includes(recorded.sequence) ? "eventarcpublishing" : "eventarc"}.googleapis.com`,
    );
    const host = {
      "serviceusage.googleapis.com": "usage",
      "firestore.googleapis.com": "firestore",
      "cloudfunctions.googleapis.com": "functions",
      "run.googleapis.com": "run",
      "eventarc.googleapis.com": "eventarc",
      "logging.googleapis.com": "logging",
      "artifactregistry.googleapis.com": "artifact",
      "eventarcpublishing.googleapis.com": "publishing",
      "pubsub.googleapis.com": "pubsub",
    }[url.hostname];
    const spec = { host, method: recorded.method, path: url.pathname + url.search };
    assert.equal(hProductionAnswer(recorded, spec), true);
    const judges = [
      hProductionAnswer,
      ...(recorded.method === "GET" ? [hProductionEvidence.preflight] : []),
      ...(["GET", "DELETE"].includes(recorded.method) ? [hProductionEvidence.readiness] : []),
      ...(recorded.body.metadata?.target ? [hProductionEvidence.operation] : []),
      ...(host === "logging" ? [hProductionEvidence.logging] : []),
    ];
    for (const judge of judges) {
      assert.equal(judge(recorded, spec), true);
      assert.equal(
        judge({ ...recorded, body: { ...recorded.body, unrecorded: true } }, spec),
        false,
      );
      assert.equal(judge(recorded, { ...spec, method: "PATCH" }), false);
      assert.equal(judge(recorded, { ...spec, path: "/unobserved" }), false);
      assert.equal(judge(recorded, { ...spec, host: "unobserved" }), false);
      assert.equal(judge({ ...recorded, unknown: true }, spec), false);
    }
    assert.equal(hProductionEvidence.notFound(recorded, spec), recorded.status === 404);
    assert.equal(hProductionAnswer(recorded), false);
    if (Object.keys(recorded.body).length > 1) {
      assert.equal(
        hProductionAnswer(
          { ...recorded, body: Object.fromEntries(Object.entries(recorded.body).toReversed()) },
          spec,
        ),
        false,
      );
    }
    if (recorded.bodyBase64) {
      const raw = Buffer.from(recorded.bodyBase64, "base64");
      assert.equal(raw.length, recorded.recordedBodyBytes);
      assert.equal(raw.length, recorded.bodyBytes);
      assert.deepEqual(JSON.parse(raw), recorded.body);
      assert.notEqual(raw.length, Buffer.byteLength(JSON.stringify(recorded.body)));
    }
  });
}

test("H preflight, readiness and cleanup lists replay FE v7 regional and all-region bodies", async () => {
  for (const recorded of fe.filter(
    (r) => r.method === "GET" && /\/(functions|services|triggers)(?:\?|$)/.test(r.url),
  )) {
    const path = new URL(recorded.url).pathname;
    const key = path.split("/").at(-1);
    for (const phase of ["preflight", "readiness", "cleanup"]) {
      let calls = 0;
      assert.deepEqual(
        await hReadList(
          {
            request: async (spec) => {
              calls++;
              assert.equal(spec.path, path);
              return recorded;
            },
          },
          { path, key, phase },
          () => {},
        ),
        recorded.body[key] ?? [],
      );
      assert.equal(calls, 1);
    }
  }
  const functions = fe.find((r) => r.sequence === 30).body.functions;
  assert.ok(functions.some((f) => f.environment === "GEN_1"));
  assert.ok(functions.some((f) => f.name.endsWith("/functions/fsCreatedV2")));
  const input = {
    manifest: m,
    functions,
    services: fe.find((r) => r.sequence === 31).body.services,
    triggers: fe.find((r) => r.sequence === 32).body.triggers,
    channel: stageC.find((r) => r.sequence === 8).body,
  };
  assert.equal(hReady(input).ready, false, "FE handlers do not prove H custom-event readiness");
  const nativeFunction = functions.find((f) => f.environment === "GEN_2");
  const native = {
    ...m,
    project: nativeFunction.name.split("/")[1],
    observe: nativeFunction.name.split("/").at(-1),
    type: nativeFunction.eventTrigger.eventType,
  };
  assert.equal(
    hReady({ ...input, manifest: native, names: [native.observe] }).ready,
    false,
    "FE's non-channel trigger is not an observed H trigger",
  );
});

test("H Logging capture and handler judge reject recorded FE frames as H evidence", async () => {
  const recorded = fe.find((r) => r.sequence === 46);
  assert.ok(recorded.body.entries.length > 0);
  const parsed = parseHEntries(recorded.body, {
    manifest: m,
    origins: [],
    readAt: "2026-10-06T00:00:00Z",
  });
  assert.equal(parsed.incomplete, true);
  assert.deepEqual(parsed.frames, []);
  const capture = hCapture({
    manifest: m,
    origins: [],
    startedAt: 0,
    now: () => 1000,
    saveFrame: () => {},
    transport: { request: async () => recorded },
  });
  await capture.poll();
  await capture.finish();
  assert.equal(capture.result().complete, false);
  assert.equal(
    judgeH({ manifest: m, observations: [], capture: capture.result() }).complete,
    false,
  );
});

test("H CLI summary replay does not imply observed H write inventory or retention", async () => {
  for (const command of ["deploy", "delete"]) {
    const stdout = readFileSync(
      new URL(`./eventarc-production/fixtures/h-fe/v7-cli-${command}-tail.txt`, import.meta.url),
      "utf8",
    );
    const result = { exitCode: 0, stdout };
    assert.equal(hCliFailed(result), false);
    assert.deepEqual(hProductionEvidence.cliWrites(result), {
      complete: false,
      resources: [],
      reason: "needs-review: H CLI write inventory is unobserved",
    });
  }
  assert.equal((await hProductionEvidence.retention({})).complete, false);
  assert.equal((await hProductionEvidence.retention({})).atBaseline, false);
});

test("H unobserved preflight stops before CLI writes even on plausible successful answers", async () => {
  const result = await recordH({
    manifest: m,
    evidence: hProductionEvidence,
    transports: {
      usage: {
        request: async () => ({
          status: 200,
          body: { state: "ENABLED", config: { name: "artifactregistry.googleapis.com" } },
        }),
      },
    },
    cli: () => assert.fail("unobserved preflight must not deploy"),
    now: () => 0,
    sleep: async () => {},
    note: () => {},
    saveFrame: () => {},
  });
  assert.equal(result.stopped, "needs-review: H preflight answer");
  assert.equal(result.closureReady, false);
  assert.deepEqual(result.writes, []);
});

test("H A2 cannot accept an unobserved function 404 or clear retention with an empty inventory", async () => {
  const name = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
  const result = await hA2({
    recording: {
      manifest: m,
      lastRequestAt: 0,
      writes: [
        { name, host: "functions", action: "create", state: "confirmed" },
        { name, host: "functions", action: "delete", state: "unknown" },
      ],
      identities: [],
      cleanup: {},
      evidence: { complete: true },
      stopped: null,
    },
    transports: {
      functions: {
        request: async () => ({ status: 404, body: { error: { code: 404, status: "NOT_FOUND" } } }),
      },
    },
    evidence: hProductionEvidence,
    now: () => 600000,
    note: () => {},
  });
  assert.equal(result.facts[0].read, "unknown");
  assert.equal(result.cleanupReady, false);
  assert.equal(result.closureReady, false);
});

test("H production judges reject every unobserved exact-name cleanup route", () => {
  for (const [host, version, collection] of [
    ["functions", "v2", "functions"],
    ["run", "v2", "services"],
    ["eventarc", "v1", "triggers"],
    ["pubsub", "v1", "subscriptions"],
  ]) {
    const path = `/${version}/projects/${m.project}/${host === "pubsub" ? "" : "locations/us-central1/"}${collection}/owned`;
    for (const reply of [
      { status: 200, body: { name: path.slice(4) } },
      { status: 404, body: { error: { code: 404, status: "NOT_FOUND" } } },
    ]) {
      assert.equal(hProductionEvidence.readiness(reply, { host, method: "GET", path }), false);
      assert.equal(hProductionEvidence.notFound(reply, { host, method: "GET", path }), false);
    }
  }
  const publishing = stageC.find((r) => r.sequence === 190);
  assert.equal(
    hProductionAnswer(publishing, {
      host: "publishing",
      method: "POST",
      path: publishing.path.replace(":publishEvents", ""),
    }),
    false,
  );
  const service = stageC.find((r) => r.sequence === 1);
  for (const api of [
    "artifactregistry",
    "cloudbuild",
    "cloudfunctions",
    "cloudresourcemanager",
    "eventarc",
    "firestore",
    "logging",
    "pubsub",
    "run",
    "storage",
  ]) {
    assert.equal(
      hProductionEvidence.preflight(service, {
        host: "usage",
        method: "GET",
        path: service.path.replace("eventarcpublishing.googleapis.com", `${api}.googleapis.com`),
      }),
      false,
    );
  }
});

test("H A2 replays stage C channel absence with its route and still refuses unobserved retention", async () => {
  const recorded = stageC.find((r) => r.sequence === 2);
  const name = recorded.path.slice(4);
  const result = await hA2({
    recording: {
      manifest: m,
      lastRequestAt: 0,
      writes: [
        { name, host: "eventarc", action: "create", state: "confirmed" },
        { name, host: "eventarc", action: "delete", state: "unknown" },
      ],
      identities: [],
      cleanup: {},
      evidence: { complete: true },
      stopped: null,
    },
    transports: {
      eventarc: {
        request: async (spec) => {
          assert.equal(spec.path, recorded.path);
          return recorded;
        },
      },
    },
    evidence: hProductionEvidence,
    now: () => 600000,
    note: () => {},
  });
  assert.equal(result.facts[0].read, "absent");
  assert.equal(result.facts[0].closed, true);
  assert.equal(result.cleanupReady, false);
  assert.equal(result.closureReady, false);
});

// Scan both alphabets for ASCII numbers and nested protobuf varints, including suffix offsets.
function hasUnmaskedToken(text) {
  const readVarint = (bytes, cursor) => {
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      if (cursor.at >= bytes.length) return null;
      const byte = bytes[cursor.at++];
      value |= BigInt(byte & 127) << shift;
      if (!(byte & 128)) return value;
    }
    return null;
  };
  const parse = (bytes, depth, found) => {
    const cursor = { at: 0 };
    while (cursor.at < bytes.length) {
      const before = cursor.at;
      const tag = readVarint(bytes, cursor);
      if (tag === null || tag >> 3n === 0n || tag >> 3n > 1000n) return before;
      switch (Number(tag & 7n)) {
        case 0: {
          const value = readVarint(bytes, cursor);
          if (value === null) return before;
          found.push(value);
          break;
        }
        case 1:
          cursor.at += 8;
          break;
        case 5:
          cursor.at += 4;
          break;
        case 2: {
          const length = readVarint(bytes, cursor);
          if (length === null || length > BigInt(bytes.length - cursor.at)) return before;
          const end = cursor.at + Number(length);
          if (depth < 4) parse(bytes.subarray(cursor.at, end), depth + 1, found);
          cursor.at = end;
          break;
        }
        default:
          return before;
      }
      if (cursor.at > bytes.length) return before;
    }
    return cursor.at;
  };
  for (const [run] of text.matchAll(/[A-Za-z0-9_+\/-]{14,}/g)) {
    if (
      /(?<![0-9])(?!123456789012(?:[^0-9]|$))[0-9]{10,13}(?![0-9])/.test(
        Buffer.from(run, "base64").toString("latin1"),
      )
    )
      return true;
    const offsets = run.length <= 512 ? run.length - 24 : 3;
    for (let offset = 0; offset <= offsets; offset++) {
      const bytes = Buffer.from(run.slice(offset), "base64");
      const found = [];
      const parsed = parse(bytes, 0, found);
      if (
        bytes.length - parsed <= 2 &&
        parsed * 10 >= bytes.length * 9 &&
        found.some(
          (value) => value >= 100000000000n && value < 1000000000000n && value !== 123456789012n,
        )
      )
        return true;
    }
  }
  return false;
}

test("H fixture mask check rejects unmasked opaque protobuf tokens", () => {
  const token = (masked) => {
    let value = 123456789012n + (masked ? 0n : 1n);
    const inner = [0x18, 1, 0x20];
    do {
      const byte = Number(value & 127n);
      value >>= 7n;
      inner.push(byte | (value ? 128 : 0));
    } while (value);
    inner.push(0x2a, 8, ...Buffer.from("channels"));
    return Buffer.from([
      0x0a,
      inner.length,
      ...inner,
      0x21,
      255,
      255,
      255,
      255,
      255,
      255,
      255,
      255,
    ]);
  };
  for (const alphabet of ["base64", "base64url"]) {
    const unmasked = token(false).toString(alphabet);
    for (const text of [
      unmasked,
      JSON.stringify({ nextPageToken: unmasked }),
      `?pageToken=${unmasked}&x=1`,
      `pageToken/${unmasked}`,
    ]) {
      assert.equal(hasUnmaskedToken(text), true, "unmasked token must be rejected");
    }
    assert.equal(hasUnmaskedToken(token(true).toString(alphabet)), false);
  }
  assert.equal(hasUnmaskedToken("ordinary text d41d8cd98f00b204e9800998ecf8427e"), false);
});

test("H fixture mask check rejects ASCII project numbers in encoded tokens", () => {
  for (const alphabet of ["base64", "base64url"]) {
    for (const number of ["1234567890", "12345678901", "123456789013", "1234567890123"]) {
      const encoded = Buffer.from(number).toString(alphabet);
      assert.equal(hasUnmaskedToken(encoded), true, "unmasked ASCII token must be rejected");
      assert.equal(hasUnmaskedToken(JSON.stringify({ sourceToken: encoded })), true);
      assert.equal(hasUnmaskedToken(Buffer.from(`projects/${number}/builds/example`).toString(alphabet)), true);
    }
    assert.equal(hasUnmaskedToken(Buffer.from("projects/123456789012/builds/example").toString(alphabet)), false);
    assert.equal(hasUnmaskedToken(Buffer.from("12345678901234").toString(alphabet)), false);
  }
});

test("every H FE fixture masks project numbers in plain text and opaque tokens", () => {
  const dir = new URL("./eventarc-production/fixtures/h-fe/", import.meta.url);
  for (const name of readdirSync(dir)) {
    const text = readFileSync(new URL(name, dir), "utf8");
    assert.equal(
      /(?<!\d)(?!123456789012(?:\D|$))\d{12}(?!\d)/.test(text),
      false,
      `${name}: unmasked plain number`,
    );
    assert.equal(hasUnmaskedToken(text), false, `${name}: unmasked opaque token`);
  }
});
