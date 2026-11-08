import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { compare, families, validate } from "./functions-python/compare.mjs";
const record = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/FUNCTIONS-PYTHON.json", import.meta.url)),
);
const fixture = JSON.parse(
  readFileSync(new URL("../functions-python/fixtures/observations.json", import.meta.url)),
);

test("complete projections reject value, presence, extra fields, type and array-length differences", () => {
  for (const [expected, actual] of [
    [{ n: 1 }, { n: 2 }],
    [{ n: 1 }, {}],
    [{}, { n: 1 }],
    [{ n: 1 }, { n: "1" }],
    [[], [1]],
    [[1], []],
    [null, {}],
  ]) {
    assert.ok(compare(expected, actual, "strict").length);
  }
  assert.deepEqual(
    compare({ n: 1, nested: [null, true] }, { n: 1, nested: [null, true] }, "strict"),
    [],
  );
  assert.throws(() => compare({}, {}, "other"), /known profile/);
});
const corpus = JSON.parse(
  readFileSync(new URL("../functions-python/corpus.json", import.meta.url)),
);
for (const observed of corpus.replayDifferences) {
  for (const path of observed.fields) {
    test(`${observed.id}/${path}: exact replay field stays pending and neighbors remain DIFF`, () => {
      for (const profile of observed.profiles) {
        assert.deepEqual(
          compare({ [path]: 1 }, { [path]: 2 }, profile, record.declaredDifferences),
          [{ path, status: "PENDING_DIFFERENCE" }],
        );
        assert.deepEqual(
          compare(
            { [`${path}-neighbor`]: 1 },
            { [`${path}-neighbor`]: 2 },
            profile,
            record.declaredDifferences,
          ),
          [{ path: `${path}-neighbor`, status: "DIFF" }],
        );
      }
      const otherProfile = ["strict", "emulator"].find((p) => !observed.profiles.includes(p));
      if (otherProfile)
        assert.equal(
          compare({ [path]: 1 }, { [path]: 2 }, otherProfile, record.declaredDifferences)[0].status,
          "DIFF",
        );
    });
  }
}
test("masked task body remains bytes, not JSON equality", () => {
  const body = fixture.observations
    .find((r) => r.condition === "tasks-events")
    .frames.find((f) => f.bodyText).bodyText;
  const value = JSON.parse(body);
  const reordered = JSON.stringify({
    data: Object.fromEntries(Object.entries(value.data).toReversed()),
  });
  assert.notEqual(body, reordered);
  assert.deepEqual(compare({ body }, { body: reordered }, "strict"), [
    { path: "body", status: "DIFF" },
  ]);
});
if (process.env.PYTHON_PARENT_PICT) {
  const [head, ...rows] = readFileSync(process.env.PYTHON_PARENT_PICT, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((r) => r.split("\t"));
  for (const [i, row] of rows.entries()) {
    const c = Object.fromEntries(head.map((k, n) => [k, row[n]]));
    test(`PICT ${i}: ${row.join("/")}`, () => {
      assert.ok(families.includes(c.Family));
      const observation = fixture.observations.find((r) => r.condition === c.Family);
      const expected = { frames: observation.frames.length, pass: observation.observedPasses };
      const actual = structuredClone(expected);
      if (c.Alteration === "missing") delete actual.frames;
      if (c.Alteration === "wrong") actual.frames += 1;
      if (c.Alteration === "extra") actual.extra = true;
      assert.equal(compare(expected, actual, c.Profile).length > 0, c.Alteration !== "exact");
      const candidate = structuredClone(record);
      if (c.Decision === "pending") {
        candidate.scopeDecisions[0].status = "PENDING";
        candidate.scopeDecisions[0].answer = null;
      }
      const corpus = JSON.parse(
        readFileSync(new URL("../functions-python/corpus.json", import.meta.url)),
      );
      const bytes = readFileSync(
        new URL("../functions-python/fixtures/observations.json", import.meta.url),
      );
      validate(
        candidate,
        corpus,
        bytes,
        readFileSync(
          new URL("../functions-python/fixtures/observations-pass2.json", import.meta.url),
        ),
      );
      if (c.Decision === "answered") candidate.scopeDecisions[0].authority = "";
      else candidate.scopeDecisions[0].answer = "unapproved";
      assert.throws(() => validate(candidate, corpus, bytes), /PY1/);
    });
  }
}

test("seeded projection properties preserve equality and detect every single-leaf change", () => {
  let state = 1729;
  const next = () => (state = (Math.imul(state, 1664525) + 1013904223) >>> 0);
  for (let i = 0; i < 128; i += 1) {
    const value = {
      nested: { count: next(), present: Boolean(next() & 1) },
      values: [next(), null],
    };
    assert.deepEqual(compare(value, structuredClone(value), "strict"), []);
    const changed = structuredClone(value);
    changed.nested.count += 1;
    assert.deepEqual(compare(value, changed, "strict"), [{ path: "nested.count", status: "DIFF" }]);
    assert.deepEqual(compare(changed, value, "emulator"), [
      { path: "nested.count", status: "DIFF" },
    ]);
  }
});

test("recording accounting counts CLI attempts rather than aggregated write rows", async () => {
  const { accountRecording } = await import("./functions-python/recordings.mjs");
  const rows = [
    { state: "before-send" },
    { state: "response-persisted" },
    { state: "cli-write", requests: 3 },
  ];
  assert.deepEqual(accountRecording(rows, { attempted: 1, completed: 1 }), {
    recorderRequests: 1,
    cliWriteRows: 1,
    cliWriteAttempts: 3,
    accountedRequests: 4,
  });
});

test("pair comparison exposes missing Tasks instead of manufacturing a second pass", async () => {
  const { compareRecordings } = await import("./functions-python/recordings.mjs");
  const a = {
    recording: { alias: "pass-1" },
    observations: [
      {
        condition: "tasks-events",
        coverage: "RECORDED",
        frames: [{ kind: "sdk-event" }],
        sdkCases: [{ expected: { n: 1 } }],
      },
    ],
  };
  const b = {
    recording: { alias: "pass-2" },
    observations: [{ condition: "tasks-events", coverage: "UNOBSERVED", frames: [], sdkCases: [] }],
  };
  assert.deepEqual(compareRecordings(a, b), [
    { condition: "tasks-events", status: "UNOBSERVED", observedPasses: 1, differences: [] },
  ]);
  assert.throws(() => compareRecordings(a, a), /distinct aliases/);
});

function syntheticRecording() {
  const functions = {
    "firestore-events": ["pcfsc", "pcfsu", "pcfscraw"],
    "pubsub-events": ["pcps", "pcpsraw"],
    "storage-events": ["pcst", "pcstraw"],
    "eventarc-custom-events": ["pcea", "pcearaw"],
    "scheduler-events": ["pcsch", "pcschraw"],
    "tasks-events": ["pctask", "pctaskraw"],
  };
  const frames = [];
  for (const row of fixture.observations.slice(0, 6)) {
    for (const c of row.sdkCases) {
      const f = {
        kind: "sdk-event",
        function: functions[row.condition][c.variant === "updated" ? 1 : 0],
        ...c.expected,
      };
      if (c.event?.type) Object.assign(f, { type: c.event.type, time: c.event.time });
      if (c.trigger === "firestore")
        for (const key of Object.keys(c.expected)) f[key] = { data: c.expected[key] };
      frames.push(f);
    }
    for (const raw of row.frames.filter((f) => f.kind !== "sdk-event")) {
      const f = { kind: raw.kind, function: functions[row.condition].at(-1) };
      if (raw.request)
        f.request = {
          method: raw.request.method,
          path: raw.request.path,
          header_names: raw.request.headerNames,
          headers: { ...raw.request.headers, authorization: "DO-NOT-PROJECT" },
        };
      if (raw.attributes)
        f.attributes = {
          ...raw.attributes,
          time: raw.fractionalTime ? "2026-01-01T00:00:02.555555Z" : "2026-01-01T00:00:02Z",
        };
      if (raw.bodyText)
        Object.assign(f.request, {
          body_text: raw.bodyText,
          body_length: Buffer.byteLength(raw.bodyText),
        });
      frames.push(f);
    }
  }
  const entries = frames.map((f, i) => ({
    insertId: `synthetic-${i}`,
    textPayload: "PYCHECK_FRAME " + JSON.stringify(f),
  }));
  const count = Object.fromEntries(
    [...new Set(frames.map((f) => f.function))].map((name) => [
      name,
      frames.filter((f) => f.function === name).length,
    ]),
  );
  const rows = [
    { state: "before-send" },
    {
      state: "response-persisted",
      id: "logs-final-frames",
      bodyBase64: Buffer.from(JSON.stringify({ entries })).toString("base64"),
    },
    { state: "cli-write", requests: 3 },
  ];
  return { rows, result: { attempted: 1, completed: 1, frames: count } };
}

test("offline extraction deduplicates repeated polls and never projects authorization values", async () => {
  const { extractRecording, extractPair } = await import("./functions-python/recordings.mjs");
  const { rows, result } = syntheticRecording();
  const extract = (r = rows, value = result, alias = "pass-1") =>
    extractRecording(r.map((x) => JSON.stringify(x)).join("\n"), JSON.stringify(value), alias);
  const first = extract();
  assert.equal(first.fixture.recording.eventFrames, 16);
  assert.ok(!JSON.stringify(first.fixture).includes("DO-NOT-PROJECT"));
  const repeated = extract([...rows, rows[0], rows[1]], { ...result, attempted: 2, completed: 2 });
  assert.deepEqual(repeated.fixture.observations, first.fixture.observations);
  assert.throws(
    () => extractPair(first, extract(rows, result, "pass-2")),
    /same original recording/,
  );
  assert.throws(() => extract(rows, { ...result, completed: 0 }), /counters disagree/);
  const missing = structuredClone(rows);
  const response = JSON.parse(Buffer.from(missing[1].bodyBase64, "base64"));
  response.entries.pop();
  missing[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
  assert.throws(() => extract(missing), /count disagreement/);
});

test("the two actual fixtures compare finite common projections and retain Tasks UNOBSERVED", async () => {
  const { compareRecordings } = await import("./functions-python/recordings.mjs");
  const second = JSON.parse(
    readFileSync(new URL("../functions-python/fixtures/observations-pass2.json", import.meta.url)),
  );
  const first = { ...fixture, observations: fixture.observations.slice(0, 6) };
  const result = compareRecordings(first, second);
  assert.deepEqual(
    result.map((x) => x.status),
    ["MATCH", "MATCH", "MATCH", "MATCH", "MATCH", "UNOBSERVED"],
  );
  for (let index = 0; index < 5; index += 1) {
    const changed = structuredClone(second);
    changed.observations[index].sdkCases[0].expected.extra = true;
    assert.equal(compareRecordings(first, changed)[index].status, "DIFF");
    const reversed = structuredClone(second);
    reversed.observations[index].sdkCases.reverse();
    reversed.observations[index].frames.reverse();
    assert.equal(compareRecordings(first, reversed)[index].status, "MATCH");
  }
});

if (process.env.PYTHON_RECORDINGS_PICT) {
  const [head, ...rows] = readFileSync(process.env.PYTHON_RECORDINGS_PICT, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((line) => line.split("\t"));
  for (const [i, values] of rows.entries()) {
    const c = Object.fromEntries(head.map((key, n) => [key, values[n]]));
    test(`recordings PICT ${i}: ${values.join("/")}`, async () => {
      const { compareRecordings } = await import("./functions-python/recordings.mjs");
      const second = JSON.parse(
        readFileSync(
          new URL("../functions-python/fixtures/observations-pass2.json", import.meta.url),
        ),
      );
      const source = c.Pass === "pass-1" ? fixture : second;
      const row = source.observations.find((x) => x.condition === c.Family);
      assert.ok(row);
      const expected = { coverage: row.coverage, frames: row.frames, sdkCases: row.sdkCases };
      const actual = structuredClone(expected);
      if (c.Alteration === "wrong") actual.coverage = "fabricated";
      if (c.Alteration === "missing") delete actual.frames;
      if (c.Alteration === "duplicate") actual.frames.push(row.frames[0] ?? { fabricated: true });
      assert.equal(compare(expected, actual, c.Profile).length > 0, c.Alteration !== "exact");
      const pair = compareRecordings(fixture, second).find((x) => x.condition === c.Family);
      assert.equal(pair.observedPasses, c.Family === "tasks-events" ? 1 : 2);
      assert.equal(pair.status, c.Family === "tasks-events" ? "UNOBSERVED" : "MATCH");
    });
  }
}

test("accounting properties keep aggregated rows distinct from attempted requests", async () => {
  const { accountRecording } = await import("./functions-python/recordings.mjs");
  for (let n = 1; n <= 32; n += 1) {
    const rows = [
      { state: "before-send" },
      { state: "response-persisted" },
      { state: "cli-write", requests: n },
    ];
    assert.equal(accountRecording(rows, { attempted: 1, completed: 1 }).accountedRequests, n + 1);
    assert.equal(
      accountRecording(rows.toReversed(), { attempted: 1, completed: 1 }).cliWriteRows,
      1,
    );
  }
  for (const requests of [0, -1, 1.5, "2", null]) {
    assert.throws(
      () => accountRecording([{ state: "cli-write", requests }], { attempted: 0, completed: 0 }),
      /CLI attempt counter/,
    );
  }
});

test("extractor rejects unknown request shapes and contradictory duplicate events", async () => {
  const { extractRecording } = await import("./functions-python/recordings.mjs");
  for (const mutate of [
    (frames) => {
      frames.find((f) => f.request).request.method = "DELETE";
    },
    (frames) => {
      frames.find((f) => f.request).request.header_names.push("unknown-header");
    },
    (frames) => {
      frames.find((f) => f.request).request.headers["user-agent"] = "unknown-agent";
    },
    (frames) => {
      frames.find((f) => f.snapshot).snapshot.data.unrecorded = true;
    },
  ]) {
    const { rows, result } = syntheticRecording();
    const response = JSON.parse(Buffer.from(rows[1].bodyBase64, "base64"));
    const frames = response.entries.map((e) =>
      JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length)),
    );
    mutate(frames);
    response.entries.forEach((entry, i) => {
      entry.textPayload = "PYCHECK_FRAME " + JSON.stringify(frames[i]);
    });
    rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
    assert.throws(
      () =>
        extractRecording(
          rows.map((r) => JSON.stringify(r)).join("\n"),
          JSON.stringify(result),
          "pass-1",
        ),
      /unrecorded/,
    );
  }
  const { rows, result } = syntheticRecording();
  const response = JSON.parse(Buffer.from(rows[1].bodyBase64, "base64"));
  response.entries.push({
    ...response.entries[0],
    textPayload: response.entries[0].textPayload + " ",
  });
  rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
  assert.throws(
    () =>
      extractRecording(
        rows.map((r) => JSON.stringify(r)).join("\n"),
        JSON.stringify(result),
        "pass-1",
      ),
    /contradictory duplicate/,
  );
});

test("same original frame identities cannot become independent by changing journal whitespace or notes", async () => {
  const { extractRecording, extractPair } = await import("./functions-python/recordings.mjs");
  const { rows, result } = syntheticRecording();
  const first = extractRecording(
    rows.map((r) => JSON.stringify(r)).join("\n"),
    JSON.stringify(result),
    "pass-1",
  );
  const changed = [...rows, { state: "synthetic-note" }];
  const second = extractRecording(
    changed.map((r) => JSON.stringify(r)).join("\n"),
    JSON.stringify(result),
    "pass-2",
  );
  assert.throws(() => extractPair(first, second), /same original recording/);
});
