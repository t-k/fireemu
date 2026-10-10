import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const sha = (b) => createHash("sha256").update(b).digest("hex");
async function subject() {
  const m = await import("./project-native-inputs.mjs").catch(() => null);
  assert.ok(m, "native projection entrypoint must exist");
  return m;
}
const old = "111111111111",
  alias = "123456789012";
function token(number) {
  let n = BigInt(number),
    out = [0x0a, 0x01, 0x61, 0x18, 0x01, 0x20];
  do {
    let b = Number(n & 127n);
    n >>= 7n;
    if (n) b |= 128;
    out.push(b);
  } while (n);
  out.push(0x28, 0x07);
  return Buffer.from(out).toString("base64url");
}
function journal(rows) {
  return Buffer.from(rows.map((x) => JSON.stringify(x)).join("\n") + "\n");
}
function row(n = 1) {
  const raw = Buffer.from('{\n  "channels": [],\n  "nextPageToken": "' + token(old) + '"\n}\n');
  return {
    n,
    op: "listChannels",
    case: "page",
    at: "2026-10-05T11:11:27.052Z",
    ms: 12,
    tokenMode: "default",
    request: {
      method: "GET",
      path: `/v1/projects/${old}/locations/us-central1/channels?pageSize=1&pageToken=${token(old)}`,
    },
    response: {
      status: 200,
      body: JSON.parse(raw),
      bodyBase64: raw.toString("base64"),
      bodyBytes: raw.length,
      bodySha256: sha(raw),
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "content-length": String(raw.length),
      },
    },
  };
}
async function project(rows, extra = {}) {
  const { projectJournal } = await subject(),
    bytes = journal(rows);
  return projectJournal({ bytes, expectedSha256: sha(bytes), numericProjectNumber: old, ...extra });
}
test("parsed-only input preserves absent native bytes, headers and optional token metadata", async () => {
  const r = row();
  r.response = { status: 404, body: { error: { code: 404 } } };
  delete r.tokenMode;
  delete r.at;
  delete r.ms;
  const p = await project([r]);
  const got = p.rows[0];
  assert.deepEqual(got.response, r.response);
  assert.equal(Object.hasOwn(got, "tokenMode"), false);
  assert.equal(Object.hasOwn(got, "at"), false);
  assert.equal(Object.hasOwn(got, "ms"), false);
  assert.equal(got.projectionSource.originalResponseBytesPresent, false);
  assert.ok(got.projectionSource.absentFields.includes("response.headers"));
  assert.ok(got.projectionSource.absentFields.includes("response.bodyBase64"));
});
test("native bytes retain layout and separate original and sanitized digest identities", async () => {
  const original = row(),
    p = await project([original]);
  const got = p.rows[0],
    raw = Buffer.from(got.response.bodyBase64, "base64");
  assert.equal(raw.length, original.response.bodyBytes);
  assert.equal(got.response.bodyBytes, raw.length);
  assert.equal(got.response.bodySha256, sha(raw));
  assert.equal(got.response.originalBodySha256, original.response.bodySha256);
  assert.notEqual(got.response.bodySha256, got.response.originalBodySha256);
  assert.equal(
    raw.toString(),
    Buffer.from(original.response.bodyBase64, "base64")
      .toString()
      .replace(token(old), token(alias)),
  );
  assert.ok(got.request.path.includes(`/projects/${alias}/`));
  assert.ok(got.request.path.endsWith(token(alias)));
  assert.equal(got.response.headers["content-length"], String(raw.length));
  assert.equal(got.at, original.at);
  assert.equal(got.ms, original.ms);
});
test("joined native chunks are verified before projection", async () => {
  const r = row(),
    text = r.response.bodyBase64;
  delete r.response.bodyBase64;
  r.response.bodyBase64Parts = [text.slice(0, 20), text.slice(20)];
  const p = await project([r]);
  assert.equal(p.rows[0].projectionSource.originalRawEncoding, "bodyBase64Parts");
  assert.equal(p.rows[0].response.bodyBytes, r.response.bodyBytes);
});
test("original journal digest mismatch refuses all output", async () => {
  await assert.rejects(
    () => project([row()], { expectedSha256: "0".repeat(64) }),
    /journal digest/,
  );
});
test("original native body digest mismatch refuses all output", async () => {
  const r = row();
  r.response.bodySha256 = "0".repeat(64);
  await assert.rejects(() => project([r]), /native body digest/);
});
test("native byte count mismatch refuses all output", async () => {
  const r = row();
  r.response.bodyBytes++;
  await assert.rejects(() => project([r]), /native body length/);
});
test("duplicate ordinals and nonfinite latency refuse all output", async () => {
  await assert.rejects(() => project([row(), row()]), /duplicate ordinal/);
  const r = row();
  r.ms = "Infinity";
  await assert.rejects(() => project([r]), /latency/);
});
test("credential material in decoded native text is rejected", async () => {
  const r = row(),
    raw = Buffer.from('{"message":"ya29.real-access-token-value"}');
  r.response = {
    status: 400,
    body: JSON.parse(raw),
    bodyBase64: raw.toString("base64"),
    bodyBytes: raw.length,
    bodySha256: sha(raw),
  };
  await assert.rejects(() => project([r]), /credential/);
});
test("a project alias with another decimal or varint width is rejected", async () => {
  await assert.rejects(() => project([row()], { numericProjectNumber: "1" }), /width/);
});
test("fixed property corpus preserves protobuf surroundings and widths for every project alias", async () => {
  const { sanitizePageToken } = await subject();
  for (let n = 0; n < 64; n++) {
    const number = String(111111111111n + BigInt(n) * 100003n),
      input = token(number),
      actual = sanitizePageToken(input, number);
    assert.equal(actual, token(alias));
    assert.equal(actual.length, input.length);
    const a = Buffer.from(actual, "base64url"),
      b = Buffer.from(input, "base64url");
    assert.deepEqual(a.subarray(0, 6), b.subarray(0, 6));
    assert.deepEqual(a.subarray(-2), b.subarray(-2));
  }
  assert.equal(sanitizePageToken("not-a-protobuf-page-token", old), "not-a-protobuf-page-token");
});
test("unknown token mode and partial native envelope cannot be silently normalized", async () => {
  const r = row();
  r.tokenMode = "credential-file";
  await assert.rejects(() => project([r]), /credential mode/);
  const partial = row();
  delete partial.response.bodySha256;
  await assert.rejects(() => project([partial]), /native body digest/);
});
test("native notes never manufacture a request but preserve run and service-state authority", async () => {
  const p = await project([
    {
      note: "run-start",
      runId: "example",
      at: "2026-10-05T00:00:00Z",
      project: "demo",
      target: "production",
    },
    row(),
    { note: "sdk-zero-wire", private: "unused" },
    { note: "service-state", before: { state: "DISABLED" } },
  ]);
  assert.equal(p.rows.length, 1);
  assert.equal(p.summary.omittedNotes, 1);
  const lines = p.bytes.toString().trim().split("\n").map(JSON.parse);
  assert.deepEqual(lines[0], { note: "run-start", runId: "example" });
  assert.equal(lines.at(-1).before.state, "DISABLED");
  assert.equal(Object.hasOwn(lines[0], "target"), false);
});
test("witness plan refuses absent selectors and preserves exact logical phases", async () => {
  const { buildWitnessPlan } = await subject();
  const roots = {
    B: [16, 20, 26, 27, 202],
    C: [16, 20, 26, 27, 41, 46, 64, 76, 80, 84, 88, 92, 96, 101, 102, 110, 115, 398],
    D: [16, 19, 23, 27, 31, 35, 40, 41, 47, 50, 61, 66, 87, 186],
  };
  const corpora = Object.fromEntries(
    Object.entries(roots).map(([l, ns]) => [l, ns.map((n) => ({ n }))]),
  );
  const p = buildWitnessPlan(corpora);
  assert.deepEqual(p.corpora.D.independentLifecycleSlices, [
    { createN: 61, deleteN: 66, overlap: true },
    { createN: 87, deleteN: 186, overlap: false },
  ]);
  assert.equal(p.corpora.C.walks[0].setupThroughN, 20);
  assert.equal(p.corpora.C.walks[1].setupThroughN, 96);
  assert.equal(p.corpora.C.walks[1].inventoryN, 101);
  corpora.C = corpora.C.filter((r) => r.n !== 110);
  assert.throws(() => buildWitnessPlan(corpora), /missing witness selector/);
});
test("original parsed A2 event identities and individual timestamps survive the distinct compact fixture binding", async () => {
  const { bindExistingPublicFixture } = await subject();
  const r = row(59);
  r.op = "publishEvents";
  r.request = {
    method: "POST",
    path: "/v1/projects/demo/channels/x:publishEvents",
    body: {
      events: [
        { id: "event-32", time: "2026-10-05T06:17:46.176Z" },
        { id: "event-33", time: "2026-10-05T06:17:46.177Z" },
      ],
    },
  };
  r.response = { status: 200, body: {} };
  const projected = await project([r]);
  assert.deepEqual(projected.rows[0].request, r.request);
  assert.equal(projected.rows[0].at, r.at);
  assert.equal(projected.rows[0].ms, r.ms);
  const fixture = [
    {
      ...r,
      request: {
        ...r.request,
        body: { events: { $repeat: { count: 2, template: r.request.body.events[0] } } },
      },
    },
  ];
  const binding = bindExistingPublicFixture({
    label: "A2",
    projected: projected.rows,
    fixtureBytes: Buffer.from(JSON.stringify(fixture)),
    path: "legacy-a.json",
  });
  assert.equal(
    binding.legacyPublicFixture.relationship,
    "distinct compact parsed input; not equality authority",
  );
  assert.deepEqual(binding.legacyPublicFixture.differentRequestOrdinals, [59]);
  assert.equal(Object.hasOwn(binding, "existingPublicFixture"), false);
  assert.equal(Object.hasOwn(projected.rows[0].response, "bodyBase64"), false);
});
test("B and C exact-public guards reject changed identity, timestamp, path, count, status and raw bytes", async () => {
  const { bindExistingPublicFixture } = await subject();
  for (const label of ["B", "C"]) {
    const r = row();
    r.request.body = { events: [{ id: "one", time: "2026-10-05T00:00:00Z" }] };
    const p = await project([r]);
    const before = {
      ...p.rows[0],
      response: {
        status: 200,
        rawBody: Buffer.from(p.rows[0].response.bodyBase64, "base64").toString(),
        bodyBytes: p.rows[0].response.bodyBytes,
        contentType: "application/json; charset=UTF-8",
      },
    };
    const bind = (existing) =>
      bindExistingPublicFixture({
        label,
        projected: p.rows,
        fixtureBytes: Buffer.from(JSON.stringify([existing])),
        path: "public.json",
      });
    assert.ok(bind(before).existingPublicFixture);
    for (const change of [
      (x) => (x.request.body.events[0].id = "two"),
      (x) => (x.request.body.events[0].time = "2026-10-05T00:00:01Z"),
      (x) => (x.request.path += "&changed=1"),
      (x) => x.request.body.events.push({ id: "extra" }),
      (x) => (x.response.status = 403),
      (x) => (x.response.rawBody += " "),
    ]) {
      const changed = structuredClone(before);
      change(changed);
      assert.throws(() => bind(changed), /existing public/);
    }
  }
});
test("encoded private numbers and credential signatures cannot escape the publication scan", async () => {
  for (const text of [`projects/${old}`, "ya29.real-access-token-value"]) {
    const r = row();
    r.response = { status: 400, body: { payload: Buffer.from(text).toString("base64") } };
    await assert.rejects(() => project([r]), /private project number|credential/);
  }
  const r = row();
  r.response = { status: 400, body: { payload: token(old) } };
  await assert.rejects(() => project([r]), /private project number/);
});
test("committed projections bind all1043 original selectors through the existing native loader with explicit parsed-only absence", async () => {
  const { loadNativeRequests } = await import("./lifecycle-evidence.mjs");
  const provenance = JSON.parse(
      readFileSync(new URL("./fixtures/ad/provenance.json", import.meta.url)),
    ),
    plan = JSON.parse(readFileSync(new URL("./fixtures/ad/witness-plan.json", import.meta.url)));
  let count = 0,
    native = 0,
    parsed = 0;
  const loaded = {};
  for (const corpus of provenance.corpora) {
    const path = new URL(`./fixtures/ad/${corpus.projection.file}`, import.meta.url);
    assert.equal(sha(readFileSync(path)), corpus.projection.sha256);
    const rows = loadNativeRequests({
      path,
      sha256: corpus.projection.sha256,
      ordinals: corpus.projection.ordinals,
    });
    assert.equal(rows.size, corpus.projection.rows);
    loaded[corpus.label] = rows;
    count += rows.size;
    for (const row of rows.values()) {
      if (corpus.projection.nativeRows === 0) {
        parsed++;
        assert.equal(Object.hasOwn(row.recorded, "bodyBase64"), false);
        assert.equal(Object.hasOwn(row.recorded, "bodySha256"), false);
        assert.equal(Object.hasOwn(row.recorded, "headers"), false);
      } else {
        native++;
        const bytes = Buffer.from(row.recorded.bodyBase64, "base64");
        assert.equal(bytes.length, row.recorded.bodyBytes);
        assert.equal(sha(bytes), row.recorded.bodySha256);
        assert.match(row.recorded.originalBodySha256, /^[a-f0-9]{64}$/);
      }
    }
  }
  assert.equal(count, 1043);
  assert.equal(native, 856);
  assert.equal(parsed, 187);
  for (const n of [59, 60]) {
    const events = loaded.A2.get(n).request.body.events;
    assert.notEqual(events[0].id, events[1].id);
  }
  assert.ok(
    new Set(loaded.A2.get(61).request.body.events.map((e) => e.attributes.time.ceTimestamp)).size >
      1,
  );
  assert.deepEqual(
    provenance.corpora.find((c) => c.label === "A2").legacyPublicFixture.differentRequestOrdinals,
    [59, 60, 61],
  );
  for (const [label, spec] of Object.entries(plan.corpora)) {
    assert.equal(
      spec.projectionSha256,
      provenance.corpora.find((c) => c.label === label).projection.sha256,
    );
    for (const w of spec.walks) {
      assert.ok(loaded[label].has(w.rootN));
      assert.ok(loaded[label].has(w.inventoryN));
    }
  }
});
test("parsed-only absence contract explicitly names all four byte fields and headers without synthesizing them", async () => {
  const r = row();
  r.response = { status: 404, body: { error: { code: 404, message: "original" } } };
  const p = await project([r]);
  const actual = p.rows[0];
  assert.deepEqual(actual.response, r.response);
  for (const key of ["bodyBase64", "bodyBytes", "bodySha256", "originalBodySha256", "headers"]) {
    assert.equal(Object.hasOwn(actual.response, key), false);
    assert.ok(
      actual.projectionSource.absentFields.includes(`response.${key}`),
      `missing explicit absence ${key}`,
    );
  }
});
