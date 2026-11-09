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
        readFileSync(
          new URL("../functions-python/fixtures/observations-tasks-pass2.json", import.meta.url),
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
        readFileSync(
          new URL("../functions-python/fixtures/observations-tasks-pass2.json", import.meta.url),
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

test("frame and case arrival normalization never sorts a semantic payload array with the same key", async () => {
  const { compareRecordings } = await import("./functions-python/recordings.mjs");
  const first = {
    recording: { alias: "pass-1" },
    observations: [
      {
        condition: "firestore-events",
        coverage: "RECORDED",
        frames: [],
        sdkCases: [{ expected: { frames: [1, 2] } }],
      },
    ],
  };
  const second = structuredClone(first);
  second.recording.alias = "pass-2";
  second.observations[0].sdkCases[0].expected.frames.reverse();
  assert.equal(compareRecordings(first, second)[0].status, "DIFF");
});

function editSyntheticRecording(change) {
  const input = syntheticRecording();
  const response = JSON.parse(Buffer.from(input.rows[1].bodyBase64, "base64"));
  change(response.entries);
  input.rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
  input.result.frames = {};
  for (const e of response.entries) {
    const f = JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length));
    input.result.frames[f.function] = (input.result.frames[f.function] ?? 0) + 1;
  }
  return input;
}
async function extractSynthetic(input, alias) {
  const { extractRecording } = await import("./functions-python/recordings.mjs");
  return extractRecording(
    input.rows.map((r) => JSON.stringify(r)).join("\n"),
    JSON.stringify(input.result),
    alias,
  );
}

test("a second recording derived by dropping Tasks still overlaps its original", async () => {
  const { extractPair } = await import("./functions-python/recordings.mjs");
  const first = await extractSynthetic(syntheticRecording(), "pass-1");
  const subset = editSyntheticRecording((entries) => {
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const f = JSON.parse(entries[i].textPayload.slice("PYCHECK_FRAME ".length));
      if (["pctask", "pctaskraw"].includes(f.function)) entries.splice(i, 1);
    }
  });
  const second = await extractSynthetic(subset, "pass-2");
  assert.equal(second.fixture.recording.eventFrames, 14);
  assert.throws(() => extractPair(first, second), /overlapping original/);
});

function syntheticTaskBody(body) {
  return editSyntheticRecording((entries) => {
    const entry = entries.find(
      (e) => JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length)).function === "pctaskraw",
    );
    const frame = JSON.parse(entry.textPayload.slice("PYCHECK_FRAME ".length));
    frame.request.body_text = body;
    frame.request.body_length = Buffer.byteLength(body);
    entry.textPayload = "PYCHECK_FRAME " + JSON.stringify(frame);
  });
}

test("task masking rejects Unicode escapes and duplicate identifiers before publication", async () => {
  for (const body of [
    '{"data":{"run":"private-\\u006fwner","label":"label"}}',
    '{"data":{"run":"private-original","run":"selected","label":"label"}}',
    '{"data":{"run":"run","label":"private-original","label":"selected"}}',
    '{"data":{"run":"private-original","label":"old"},"data":{"run":"selected","label":"label"}}',
  ])
    await assert.rejects(
      extractSynthetic(syntheticTaskBody(body), "pass-1"),
      /unsupported task body lexical shape/,
    );
});

test("equal task identifiers are masked by field and retain only intended layout", async () => {
  for (const body of [
    '{"data":{"run":"same-original","label":"same-original"}}',
    '{ "data" : { "label" : "same-original", "run" : "same-original" } }',
  ]) {
    const extracted = await extractSynthetic(syntheticTaskBody(body), "pass-1");
    const row = extracted.fixture.observations.find((r) => r.condition === "tasks-events");
    const frame = row.frames.find((f) => f.bodyText);
    assert.deepEqual(JSON.parse(frame.bodyText), {
      data: { run: "fixture-run", label: "fixture-label" },
    });
    assert.ok(!frame.bodyText.includes("same-original"));
    assert.equal(frame.originalBodyBytes, Buffer.byteLength(body));
  }
});

function syntheticTasksPass(rename = { pctask: "pc3task", pctaskraw: "pc3taskraw" }) {
  return editSyntheticRecording((entries) => {
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const f = JSON.parse(entries[i].textPayload.slice("PYCHECK_FRAME ".length));
      if (!Object.hasOwn(rename, f.function)) entries.splice(i, 1);
      else {
        f.function = rename[f.function];
        entries[i] = {
          insertId: "tasks-" + entries[i].insertId,
          textPayload: "PYCHECK_FRAME " + JSON.stringify(f),
        };
      }
    }
  });
}

test("a Tasks-only pass under fresh queue names projects only the Tasks family", async () => {
  const tasks = await extractSynthetic(syntheticTasksPass(), "tasks-pass-2");
  assert.equal(tasks.fixture.recording.profile, "tasks");
  assert.equal(tasks.fixture.recording.eventFrames, 2);
  assert.deepEqual(
    tasks.fixture.observations.map((r) => [r.condition, r.coverage, r.observedPasses]),
    [["tasks-events", "RECORDED", 1]],
  );
  const pass1 = await extractSynthetic(syntheticRecording(), "pass-1");
  const expected = pass1.fixture.observations.find((r) => r.condition === "tasks-events");
  assert.deepEqual(tasks.fixture.observations[0], expected);
  assert.ok(!JSON.stringify(tasks.fixture).includes("DO-NOT-PROJECT"));
});

test("Tasks-pass names and events-pass names cannot cross profiles", async () => {
  await assert.rejects(
    extractSynthetic(
      syntheticTasksPass({ pctask: "pctask", pctaskraw: "pctaskraw" }),
      "tasks-pass-2",
    ),
    /unrecorded function/,
  );
  const events = editSyntheticRecording((entries) => {
    for (const [i, e] of entries.entries()) {
      const f = JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length));
      if (f.function === "pctask") f.function = "pc3task";
      entries[i] = { ...e, textPayload: "PYCHECK_FRAME " + JSON.stringify(f) };
    }
  });
  await assert.rejects(extractSynthetic(events, "pass-1"), /unrecorded function/);
  await assert.rejects(
    extractSynthetic(syntheticTasksPass({ pctask: "pc3task" }), "tasks-pass-2"),
    /incomplete recorded family/,
  );
  await assert.rejects(
    extractSynthetic(syntheticTasksPass(), "pass-2"),
    /incomplete recorded family|unrecorded function/,
  );
});

test("a Tasks pass must not share original log entries with pass 1", async () => {
  const { extractTasksPass } = await import("./functions-python/recordings.mjs");
  const first = await extractSynthetic(syntheticRecording(), "pass-1");
  const tasks = await extractSynthetic(syntheticTasksPass(), "tasks-pass-2");
  assert.equal(extractTasksPass(first, tasks), tasks.fixture);
  const shared = syntheticTasksPass();
  const response = JSON.parse(Buffer.from(shared.rows[1].bodyBase64, "base64"));
  const original = JSON.parse(Buffer.from(syntheticRecording().rows[1].bodyBase64, "base64"));
  const source = original.entries.find((e) => e.textPayload.includes('"pctask"'));
  response.entries[0].insertId = source.insertId;
  shared.rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
  const overlapping = await extractSynthetic(shared, "tasks-pass-2");
  assert.throws(() => extractTasksPass(first, overlapping), /overlapping original/);
  assert.throws(() => extractTasksPass(tasks, first), /ordered independent aliases/);
});

test("a Tasks pass compares only Tasks with pass 1, by masked bytes and recorded length", async () => {
  const { compareRecordings } = await import("./functions-python/recordings.mjs");
  const first = await extractSynthetic(syntheticRecording(), "pass-1");
  const tasks = await extractSynthetic(syntheticTasksPass(), "tasks-pass-2");
  assert.deepEqual(compareRecordings(first.fixture, tasks.fixture), [
    { condition: "tasks-events", status: "MATCH", observedPasses: 2, differences: [] },
  ]);
  for (const alter of [
    (f) => {
      f.originalBodyBytes += 1;
    },
    (f) => {
      f.bodyText = f.bodyText.replace("{", "{ ");
    },
    (f) => {
      f.request.headerNames.pop();
    },
  ]) {
    const changed = structuredClone(tasks.fixture);
    alter(changed.observations[0].frames.find((x) => x.bodyText));
    assert.equal(compareRecordings(first.fixture, changed)[0].status, "DIFF");
  }
  const unknown = structuredClone(tasks.fixture);
  unknown.recording.profile = "storage";
  assert.throws(() => compareRecordings(first.fixture, unknown), /known recording profile/);
  const extra = structuredClone(tasks.fixture);
  extra.observations.push(structuredClone(first.fixture.observations[0]));
  assert.throws(() => compareRecordings(first.fixture, extra), /same family inventory/);
});

test("masked task values keep their recorded byte lengths, and only those may explain a body length change", async () => {
  const { compareRecordings } = await import("./functions-python/recordings.mjs");
  const body = '{"data":{"run":"run-value","label":"pctaskraw"}}';
  const first = await extractSynthetic(syntheticTaskBody(body), "pass-1");
  const raw = (f) =>
    f.observations.find((r) => r.condition === "tasks-events").frames.find((x) => x.bodyText);
  assert.deepEqual(raw(first.fixture).originalValueBytes, { run: 9, label: 9 });
  const renamed = syntheticTasksPass();
  const response = JSON.parse(Buffer.from(renamed.rows[1].bodyBase64, "base64"));
  for (const e of response.entries) {
    const f = JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length));
    if (f.function === "pc3taskraw") {
      f.request.body_text = body.replace("pctaskraw", "pc3taskraw");
      f.request.body_length = Buffer.byteLength(f.request.body_text);
      e.textPayload = "PYCHECK_FRAME " + JSON.stringify(f);
    }
  }
  renamed.rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
  const tasks = await extractSynthetic(renamed, "tasks-pass-2");
  assert.deepEqual(raw(tasks.fixture).originalValueBytes, { run: 9, label: 10 });
  const [pair] = compareRecordings(first.fixture, tasks.fixture);
  assert.equal(pair.status, "MATCH_LAYOUT");
  assert.deepEqual(pair.differences.map((d) => d.path).sort(), [
    "frames.0.originalBodyBytes",
    "frames.0.originalValueBytes.label",
  ]);
  for (const alter of [
    (f) => {
      f.originalBodyBytes += 1;
    },
    (f) => {
      f.originalValueBytes.run += 1;
    },
    (f) => {
      f.originalValueBytes.label -= 1;
      f.originalBodyBytes -= 2;
    },
    (f) => {
      f.bodyText = f.bodyText.replace(":", ": ");
    },
    (f) => {
      delete f.originalValueBytes.run;
    },
    (f) => {
      f.originalBodyBytes -= f.originalValueBytes.run;
      delete f.originalValueBytes.run;
    },
  ]) {
    const changed = structuredClone(tasks.fixture);
    alter(raw(changed));
    assert.equal(compareRecordings(first.fixture, changed)[0].status, "DIFF");
  }
});

if (process.env.PYTHON_CUSTODY_PICT) {
  const [head, ...rows] = readFileSync(process.env.PYTHON_CUSTODY_PICT, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((line) => line.split("\t"));
  for (const [index, values] of rows.entries()) {
    const c = Object.fromEntries(head.map((key, i) => [key, values[i]]));
    test(`custody PICT ${index}: ${values.join("/")}`, async () => {
      const { extractPair } = await import("./functions-python/recordings.mjs");
      const first = await extractSynthetic(syntheticRecording(), "pass-1");
      const fields = c.Order === "run-first" ? ["run", "label"] : ["label", "run"];
      const value = c.Body === "equal" ? "same-private" : "private-value";
      let members = fields.map((key) => JSON.stringify(key) + ":" + JSON.stringify(value));
      if (c.Body === "escape") members[0] = JSON.stringify(fields[0]) + ':"private-\\u006fwner"';
      if (c.Body === "duplicate") members.push(JSON.stringify(fields[0]) + ':"second-private"');
      const input = syntheticTaskBody('{"data":{' + members.join(", ") + "}}");
      const response = JSON.parse(Buffer.from(input.rows[1].bodyBase64, "base64"));
      response.entries.forEach((e, i) => {
        if (c.Overlap === "none" || (c.Overlap === "one" && i > 0))
          e.insertId = "second-" + e.insertId;
      });
      input.rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
      if (["escape", "duplicate"].includes(c.Body)) {
        await assert.rejects(
          extractSynthetic(input, "pass-2"),
          /unsupported task body lexical shape/,
        );
        return;
      }
      const second = await extractSynthetic(input, "pass-2");
      if (c.Overlap === "none") assert.equal(extractPair(first, second).length, 2);
      else
        assert.throws(
          () => extractPair(first, second),
          /same original recording|overlapping original/,
        );
      const body = second.fixture.observations
        .find((r) => r.condition === "tasks-events")
        .frames.find((f) => f.bodyText).bodyText;
      assert.deepEqual(JSON.parse(body), { data: { run: "fixture-run", label: "fixture-label" } });
      assert.ok(!body.includes("private"));
      assert.equal(body.indexOf('"' + fields[0] + '"') < body.indexOf('"' + fields[1] + '"'), true);
    });
  }
}

if (process.env.PYTHON_TASKS_PASS_PICT) {
  const [head, ...rows] = readFileSync(process.env.PYTHON_TASKS_PASS_PICT, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((line) => line.split("\t"));
  for (const [index, values] of rows.entries()) {
    const c = Object.fromEntries(head.map((key, i) => [key, values[i]]));
    test(`tasks pass PICT ${index}: ${values.join("/")}`, async () => {
      const { compareRecordings, extractTasksPass } =
        await import("./functions-python/recordings.mjs");
      const firstBody = '{"data":{"run":"run-value","label":"pctaskraw"}}';
      const bodies = {
        equal: firstBody,
        "label-longer": '{"data":{"run":"run-value","label":"pc3taskraw"}}',
        "swapped-lengths": '{"data":{"run":"run-valu","label":"pc3taskraw"}}',
        "layout-change": '{"data":{"run":"run-value", "label":"pctaskraw"}}',
      };
      const first = await extractSynthetic(syntheticTaskBody(firstBody), "pass-1");
      const names = {
        new: { pctask: "pc3task", pctaskraw: "pc3taskraw" },
        old: { pctask: "pctask", pctaskraw: "pctaskraw" },
        mixed: { pctask: "pc3task", pctaskraw: "pctaskraw" },
      }[c.Names];
      const input = syntheticTasksPass(names);
      const response = JSON.parse(Buffer.from(input.rows[1].bodyBase64, "base64"));
      const original = JSON.parse(Buffer.from(syntheticRecording().rows[1].bodyBase64, "base64"));
      for (const e of response.entries) {
        const f = JSON.parse(e.textPayload.slice("PYCHECK_FRAME ".length));
        if (f.request) {
          f.request.body_text = bodies[c.Body];
          f.request.body_length = Buffer.byteLength(f.request.body_text);
          e.textPayload = "PYCHECK_FRAME " + JSON.stringify(f);
        }
      }
      if (c.Overlap === "one") response.entries[0].insertId = original.entries[0].insertId;
      input.rows[1].bodyBase64 = Buffer.from(JSON.stringify(response)).toString("base64");
      if (c.Names !== "new" || c.Alias !== "tasks-pass-2") {
        await assert.rejects(
          extractSynthetic(input, c.Alias),
          /unrecorded function|incomplete recorded family|coverage incomplete/,
        );
        return;
      }
      const tasks = await extractSynthetic(input, c.Alias);
      if (c.Overlap === "one") {
        assert.throws(() => extractTasksPass(first, tasks), /overlapping original/);
        return;
      }
      assert.equal(extractTasksPass(first, tasks), tasks.fixture);
      const [pair] = compareRecordings(first.fixture, tasks.fixture);
      assert.equal(
        pair.status,
        { equal: "MATCH", "label-longer": "MATCH_LAYOUT", "swapped-lengths": "MATCH_LAYOUT" }[
          c.Body
        ] ?? "DIFF",
      );
    });
  }
}
