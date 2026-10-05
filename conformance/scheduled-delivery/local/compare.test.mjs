// The comparison rows against synthetic recordings and local timelines built to match, then broken one field at a
// time: each row must say MATCH for the matching pair and DIVERGES for its own near miss, and nothing else.
import assert from "node:assert/strict";
import test from "node:test";
import {
  FORM,
  compareProfiles,
  localChains,
  productionChains,
  rows,
  secondsOf,
} from "./compare.mjs";
import { parseTimeline } from "./local-run.mjs";

const T0 = Date.parse("2026-10-05T08:41:00Z");
const instant = (ms) => new Date(ms).toISOString().replace(".000Z", "Z");
const la = (ms, fraction = "") => {
  const d = new Date(ms - 7 * 3600_000).toISOString().slice(0, 19);
  return `${d}${fraction}-07:00`;
};
const NAMES = [
  "accept-encoding",
  "authorization",
  "content-length",
  "host",
  "user-agent",
  "x-cloudscheduler",
  "x-cloudscheduler-jobname",
  "x-cloudscheduler-scheduletime",
];
const jobId = (fn) => `firebase-schedule-${fn}-us-central1`;

function prodV2(handler, atMs, scheduleTime, job = jobId(handler)) {
  return {
    handler,
    generation: 2,
    at: atMs,
    method: "POST",
    url: "/",
    headers: {
      "x-cloudscheduler": "true",
      "user-agent": "Google-Cloud-Scheduler",
      "content-length": "0",
      "x-cloudscheduler-jobname": job,
      "x-cloudscheduler-scheduletime": scheduleTime,
    },
    headerNames: NAMES,
    rawBodyLength: null,
    event: { jobName: job, scheduleTime },
    eventKeys: ["jobName", "scheduleTime"],
    contextProperty: { enumerable: false, configurable: false, hasGetter: true },
    context: {
      eventId: job,
      timestamp: scheduleTime,
      eventType: "google.pubsub.topic.publish",
      resource: { service: "pubsub.googleapis.com", name: `projects/p/topics/${job}` },
      params: {},
    },
  };
}
const prodV1 = (handler, atMs, id, timestamp) => ({
  handler,
  generation: 1,
  at: atMs,
  argumentCount: 1,
  arguments: [],
  context: {
    eventId: id,
    eventType: "google.pubsub.topic.publish",
    resource: {
      name: `projects/p/topics/${jobId(handler)}`,
      service: "pubsub.googleapis.com",
      type: "type.googleapis.com/google.pubsub.v1.PubsubMessage",
    },
    timestamp,
    params: {},
  },
});

const CHAINS = {
  retryFour: [0, 4.6, 13.2, 29.7, 48.2],
  retryFive: [0, 5.6, 16.3, 36.8, 77.3, 157.8],
  retryZero: [0],
  retryDuration: [0, 4.6, 13.2, 23.7],
};
function production() {
  const frames = [];
  // schedOkV2: every 60 s with a fractional anchor
  for (let i = 0; i < 5; i++)
    frames.push(prodV2("schedOkV2", i * 60_000, la(T0 + i * 60_000, ".416739")));
  // five-minute job, two occurrences off the boundary
  frames.push(
    prodV2(
      "schedRetryV2",
      1000 + 420_000,
      la(T0 + 15 * 60_000 + 1751, ".751605"),
      jobId("schedRetryV2"),
    ),
  );
  const keys = {
    retryFour: ["schedRetryV2", jobId("schedRetryV2")],
    retryFive: ["schedRetryV2", "fe-sd-0123456789abcdef-retry5"],
    retryZero: ["schedRetryV2", "fe-sd-0123456789abcdef-zero"],
    retryDuration: ["schedRetryV2", "fe-sd-0123456789abcdef-duration"],
  };
  let base = 10_000_000;
  for (const [name, offsets] of Object.entries(CHAINS)) {
    base += 1_000_000;
    const scheduleTime =
      name === "retryFour" ? la(T0 + 8 * 60_000 + 1751, ".751605") : "2026-12-31T16:00:00-08:00";
    for (const o of offsets)
      frames.push(prodV2(keys[name][0], base + Math.round(o * 1000), scheduleTime, keys[name][1]));
  }
  frames.push(prodV1("schedOkV1", 2000, "22257109111563907", "2026-10-05T08:41:01.359Z"));
  frames.push(prodV1("schedFailV1", 4000, "22256732696405721", "2026-10-05T08:42:50.384Z"));
  frames.push(prodV1("schedFailV1", 300_000, "22256732696405722", "2026-10-05T08:47:05.447Z"));
  return { run: { id: "x" }, frames };
}

const localV2 = (handler, at, scheduleTime, over = {}) => ({
  at,
  kind: "SCHED_DELIVERY_FRAME",
  value: {
    handler,
    generation: 2,
    request: {
      method: "POST",
      url: "/",
      headers: Object.fromEntries(
        NAMES.map((n) => [
          n,
          n === "content-length"
            ? "0"
            : n === "user-agent"
              ? "Google-Cloud-Scheduler"
              : n === "x-cloudscheduler"
                ? "true"
                : n === "x-cloudscheduler-jobname"
                  ? jobId(handler)
                  : n === "x-cloudscheduler-scheduletime"
                    ? scheduleTime
                    : "x",
        ]),
      ),
      rawBodyLength: null,
    },
    event: { jobName: jobId(handler), scheduleTime },
    eventKeys: ["jobName", "scheduleTime"],
    contextProperty: { enumerable: false, configurable: false, hasGetter: true },
    context: {
      eventId: jobId(handler),
      timestamp: scheduleTime,
      eventType: "google.pubsub.topic.publish",
      resource: {
        service: "pubsub.googleapis.com",
        name: `projects/demo/topics/${jobId(handler)}`,
      },
      params: {},
    },
    ...over,
  },
});
const localV1 = (handler, at, id, timestamp, over = {}) => ({
  at,
  kind: "SCHED_DELIVERY_FRAME",
  value: {
    handler,
    generation: 1,
    argumentCount: 1,
    arguments: [],
    context: {
      eventId: id,
      eventType: "google.pubsub.topic.publish",
      resource: {
        name: `projects/demo/topics/${jobId(handler)}`,
        service: "pubsub.googleapis.com",
        type: "type.googleapis.com/google.pubsub.v1.PubsubMessage",
      },
      timestamp,
      params: {},
    },
    ...over,
  },
});
function local(over = {}) {
  const lines = [];
  for (let i = 0; i < 5; i++)
    lines.push(localV2("schedOkV2", instant(T0 + i * 60_000), la(T0 + i * 60_000, ".416739")));
  lines.push(
    localV2("schedRetryV2", instant(T0 + 8 * 60_000), la(T0 + 8 * 60_000 + 1751, ".751605")),
  );
  lines.push(
    localV2("schedRetryV2", instant(T0 + 15 * 60_000), la(T0 + 15 * 60_000 + 1751, ".751605")),
  );
  lines.push(localV1("schedOkV1", instant(T0), "21060470636220959", "2026-10-05T08:41:01.359Z"));
  lines.push(
    localV1("schedFailV1", instant(T0 + 1000), "27203228007418468", "2026-10-05T08:42:50.384Z"),
  );
  lines.push(
    localV1("schedFailV1", instant(T0 + 300_000), "27777684328644704", "2026-10-05T08:47:05.447Z"),
  );
  const probe = [];
  const local = {
    retryFour: [0, 4, 12, 28, 48],
    retryFive: [0, 5, 15, 35, 75, 155],
    retryZero: [0],
    retryDuration: [0, 4, 12, 22],
  };
  for (const [name, offsets] of Object.entries(local))
    for (const o of offsets)
      probe.push({ at: instant(T0 + o * 1000), kind: "PROBE", value: { handler: name } });
  return {
    natural: { lines: over.lines ?? lines, unplaced: 0, state: null },
    probe: { lines: over.probe ?? probe, unplaced: 0, state: null },
  };
}
const byId = (list) => Object.fromEntries(list.map((r) => [r.id, r]));
const verdicts = (p, l) => Object.fromEntries(rows(p, l).map((r) => [r.id, r.verdict]));

test("a local run built like the recording matches every comparable row, and a forced run is not comparable", () => {
  const v = verdicts(production(), local());
  const notMatching = Object.entries(v).filter(
    ([id, verdict]) => verdict !== "MATCH" && id !== "forced-run",
  );
  assert.deepEqual(notMatching, []);
  assert.equal(v["forced-run"], "NOT_COMPARABLE");
  assert.equal(Object.keys(v).length, 24);
});

test("FORM keeps the shape of a time and drops its fraction", () => {
  assert.equal(FORM("2026-10-05T01:42:01.416739-07:00"), "dddd-dd-ddTdd:dd:dd-dd:dd");
  assert.equal(FORM("2026-10-05T01:42:01-07:00"), "dddd-dd-ddTdd:dd:dd-dd:dd");
  assert.equal(FORM("2026-10-05T08:41:00Z"), "dddd-dd-ddTdd:dd:ddZ");
});

const breaking = [
  [
    "v2.request.method",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? { ...x, value: { ...x.value, request: { ...x.value.request, method: "GET" } } }
          : x,
      ),
  ],
  [
    "v2.request.url",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? { ...x, value: { ...x.value, request: { ...x.value.request, url: "/x" } } }
          : x,
      ),
  ],
  [
    "v2.request.headers",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? {
              ...x,
              value: {
                ...x.value,
                request: {
                  ...x.value.request,
                  headers: { ...x.value.request.headers, "content-length": "5" },
                },
              },
            }
          : x,
      ),
  ],
  [
    "v2.request.header-names",
    (l) =>
      l.natural.lines.map((x) => {
        if (x.value.generation !== 2) return x;
        const headers = Object.fromEntries(
          Object.entries(x.value.request.headers).filter(([name]) => name !== "authorization"),
        );
        return { ...x, value: { ...x.value, request: { ...x.value.request, headers } } };
      }),
  ],
  [
    "v2.request.body",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? { ...x, value: { ...x.value, request: { ...x.value.request, rawBodyLength: 12 } } }
          : x,
      ),
  ],
  [
    "v2.event.keys",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? { ...x, value: { ...x.value, eventKeys: ["jobName", "scheduleTime", "extra"] } }
          : x,
      ),
  ],
  [
    "v2.event.jobName",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? {
              ...x,
              value: {
                ...x.value,
                event: {
                  ...x.value.event,
                  jobName: "projects/p/locations/us-central1/jobs/" + x.value.event.jobName,
                },
              },
            }
          : x,
      ),
  ],
  [
    "v2.event.scheduleTime-form",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? {
              ...x,
              value: {
                ...x.value,
                event: {
                  ...x.value.event,
                  scheduleTime: x.value.event.scheduleTime.replace("-07:00", "Z"),
                },
              },
            }
          : x,
      ),
  ],
  [
    "v2.event.context",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 2
          ? { ...x, value: { ...x.value, contextProperty: null, context: null } }
          : x,
      ),
  ],
  [
    "v1.argumentCount",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 1 ? { ...x, value: { ...x.value, argumentCount: 2 } } : x,
      ),
  ],
  [
    "v1.context.eventId",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 1
          ? { ...x, value: { ...x.value, context: { ...x.value.context, eventId: "42-3" } } }
          : x,
      ),
  ],
  [
    "v1.context.resource",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 1
          ? {
              ...x,
              value: {
                ...x.value,
                context: {
                  ...x.value.context,
                  resource: {
                    service: "pubsub.googleapis.com",
                    name: "projects/demo/locations/us-central1/jobs/x",
                  },
                },
              },
            }
          : x,
      ),
  ],
  [
    "v1.context.timestamp",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 1
          ? {
              ...x,
              value: {
                ...x.value,
                context: { ...x.value.context, timestamp: "2026-10-05T08:41:00.000000000Z" },
              },
            }
          : x,
      ),
  ],
  [
    "v1.context.keys",
    (l) =>
      l.natural.lines.map((x) =>
        x.value.generation === 1
          ? { ...x, value: { ...x.value, context: { ...x.value.context, extra: 1 } } }
          : x,
      ),
  ],
];
for (const [id, change] of breaking) {
  test(`${id}: its own near miss diverges and no other row does`, () => {
    const broken = local();
    broken.natural.lines = change(broken);
    const v = verdicts(production(), broken);
    assert.equal(v[id], "DIVERGES", id);
    // Rows that read the same field move together: the job name is also the context's event id, the context also
    // carries the parameters.
    const coupled =
      { "v2.event.jobName": ["v2.event.context"], "v2.event.context": ["v2.event.context-values"] }[
        id
      ] ?? [];
    const others = Object.entries(v).filter(
      ([k, verdict]) =>
        k !== id && !coupled.includes(k) && verdict !== "MATCH" && k !== "forced-run",
    );
    assert.deepEqual(others, [], "only the broken row moves");
  });
}

test("v1.failure-no-retry: a second attempt of the same occurrence diverges", () => {
  const l = local();
  l.natural.lines.push(
    localV1("schedFailV1", instant(T0 + 1000), "27203228007418469", "2026-10-05T08:42:50.384Z"),
  );
  assert.equal(verdicts(production(), l)["v1.failure-no-retry"], "DIVERGES");
});

test("cadence: a different spacing, whole-minute phase and a five-minute boundary diverge, each by itself", () => {
  const l = local();
  l.natural.lines = l.natural.lines.map((x) =>
    x.value.handler === "schedOkV2"
      ? {
          ...x,
          value: {
            ...x.value,
            event: {
              ...x.value.event,
              scheduleTime: x.value.event.scheduleTime.replace(".416739", ""),
            },
          },
        }
      : x,
  );
  const v = verdicts(production(), l);
  assert.equal(v["cadence.every-1-minutes.phase"], "DIVERGES");
  assert.equal(v["cadence.every-1-minutes.spacing"], "MATCH");
  const spaced = local();
  let n = 0;
  spaced.natural.lines = spaced.natural.lines.map((x) =>
    x.value.handler === "schedOkV2"
      ? {
          ...x,
          value: {
            ...x.value,
            event: { ...x.value.event, scheduleTime: la(T0 + n++ * 120_000, ".416739") },
          },
        }
      : x,
  );
  assert.equal(verdicts(production(), spaced)["cadence.every-1-minutes.spacing"], "DIVERGES");
  const aligned = local();
  aligned.natural.lines = aligned.natural.lines.map((x) =>
    x.value.handler === "schedRetryV2"
      ? {
          ...x,
          value: {
            ...x.value,
            event: { ...x.value.event, scheduleTime: "2026-10-05T01:45:00-07:00" },
          },
        }
      : x,
  );
  assert.equal(verdicts(production(), aligned)["cadence.every-5-minutes.alignment"], "DIVERGES");
});

test("retry chains: a different attempt count, a gap beyond the tolerance, and a missing chain diverge; latency within tolerance matches", () => {
  const withProbe = (probe) => verdicts(production(), local({ probe }));
  const chain = (name, offsets) =>
    offsets.map((o) => ({ at: instant(T0 + o * 1000), kind: "PROBE", value: { handler: name } }));
  const good = () => [
    ...chain("retryFour", [0, 4, 12, 28, 48]),
    ...chain("retryFive", [0, 5, 15, 35, 75, 155]),
    ...chain("retryZero", [0]),
    ...chain("retryDuration", [0, 4, 12, 22]),
  ];
  assert.equal(withProbe(good())["retry.retryFour"], "MATCH");
  // the fourth gap of 32 s instead of the recorded ~18 s (the divergence found in run 156715222b86ea44)
  const wide = good()
    .filter((x) => x.value.handler !== "retryFour")
    .concat(chain("retryFour", [0, 4, 12, 28, 60]));
  assert.equal(withProbe(wide)["retry.retryFour"], "DIVERGES");
  const single = good()
    .filter((x) => x.value.handler !== "retryDuration")
    .concat(chain("retryDuration", [0]));
  assert.equal(withProbe(single)["retry.retryDuration"], "DIVERGES");
  const missing = good().filter((x) => x.value.handler !== "retryFive");
  assert.equal(withProbe(missing)["retry.retryFive"], "DIVERGES");
  const early = good()
    .filter((x) => x.value.handler !== "retryZero")
    .concat(chain("retryZero", [0, 1]));
  assert.equal(withProbe(early)["retry.retryZero"], "DIVERGES");
});

test("productionChains groups attempts by job and schedule time, and localChains reads offsets from the first attempt", () => {
  const chains = productionChains(production());
  assert.deepEqual(Object.keys(chains).toSorted(), [
    "retryDuration",
    "retryFive",
    "retryFour",
    "retryZero",
  ]);
  assert.deepEqual(chains.retryDuration, CHAINS.retryDuration);
  const probe = local().probe;
  assert.deepEqual(localChains(probe).retryFour, [0, 4, 12, 28, 48]);
  assert.deepEqual(localChains({ lines: [] }), {});
  // two occurrences of one handler: only the first is its chain, and occurrences are told apart by schedule time
  const two = [
    { at: instant(T0 + 300_000), kind: "PROBE", value: { handler: "h", scheduleTime: "B" } },
    { at: instant(T0), kind: "PROBE", value: { handler: "h", scheduleTime: "A" } },
    { at: instant(T0 + 4000), kind: "PROBE", value: { handler: "h", scheduleTime: "A" } },
    { at: instant(T0 + 304_000), kind: "PROBE", value: { handler: "h", scheduleTime: "B" } },
    { at: instant(T0 + 1000), kind: "SCHED_DELIVERY_FRAME", value: { handler: "h" } },
  ];
  assert.deepEqual(localChains({ lines: two }), { h: [0, 4] });
});

test("compareProfiles puts each profile's verdict beside the other's", () => {
  const strict = local();
  const emulator = local();
  emulator.natural.lines = emulator.natural.lines.map((x) =>
    x.value.generation === 1 ? { ...x, value: { ...x.value, argumentCount: 2 } } : x,
  );
  const table = byId(compareProfiles(production(), strict, emulator));
  assert.equal(table["v1.argumentCount"].strict.verdict, "MATCH");
  assert.equal(table["v1.argumentCount"].emulator.verdict, "DIVERGES");
  assert.equal(table["forced-run"].strict.verdict, "NOT_COMPARABLE");
});

test("parseTimeline places a handler line on the step that follows it and keeps the last state", () => {
  const output = [
    "noise",
    'PROBE {"handler":"a"}',
    "STEP 2026-10-05T08:41:01Z",
    'SCHED_DELIVERY_FRAME {"handler":"b","generation":2}',
    "SCHED_DELIVERY_FRAME {broken",
    "STEP 2026-10-05T08:41:02Z",
    'PROBE {"handler":"c"}',
    'STATE {"pending":0}',
  ].join("\n");
  const t = parseTimeline(output);
  assert.deepEqual(
    t.lines.map((l) => [l.at, l.kind, l.value.handler]),
    [
      ["2026-10-05T08:41:01Z", "PROBE", "a"],
      ["2026-10-05T08:41:02Z", "SCHED_DELIVERY_FRAME", "b"],
    ],
  );
  assert.equal(t.unplaced, 1);
  assert.deepEqual(t.state, { pending: 0 });
  assert.deepEqual(parseTimeline("").lines, []);
  assert.equal(parseTimeline("").state, null);
});

test("secondsOf reads an instant with an offset and a fraction of up to nine digits, exactly", () => {
  assert.equal(secondsOf("2026-10-05T08:41:00Z"), Date.parse("2026-10-05T08:41:00Z") / 1000);
  assert.equal(secondsOf("2026-10-05T01:41:00-07:00"), Date.parse("2026-10-05T08:41:00Z") / 1000);
  assert.ok(
    Math.abs(
      secondsOf("2026-10-05T01:42:01.416739-07:00") -
        (Date.parse("2026-10-05T08:42:01Z") / 1000 + 0.416739),
    ) < 1e-6,
  );
  assert.ok(
    Math.abs(
      secondsOf("2026-10-05T08:42:01.5Z") - (Date.parse("2026-10-05T08:42:01Z") / 1000 + 0.5),
    ) < 1e-9,
  );
  assert.ok(
    Math.abs(
      secondsOf("2026-10-05T08:42:01.000000123Z") -
        (Date.parse("2026-10-05T08:42:01Z") / 1000 + 1.23e-7),
    ) < 1e-9,
  );
  assert.equal(secondsOf("2026-10-05T08:42:01.000Z"), Date.parse("2026-10-05T08:42:01Z") / 1000);
});

test("productionChains sorts the attempts, keeps the longest chain of a job and the first of equal length", () => {
  const frame = (job, at, scheduleTime) => ({
    handler: "schedRetryV2",
    generation: 2,
    at,
    headers: { "x-cloudscheduler-jobname": job, "x-cloudscheduler-scheduletime": scheduleTime },
  });
  const digest = {
    frames: [
      frame("fe-sd-0123456789abcdef-zero", 9000, "A"),
      frame("fe-sd-0123456789abcdef-zero", 3000, "A"),
      frame("fe-sd-0123456789abcdef-zero", 6000, "A"),
      frame("fe-sd-0123456789abcdef-zero", 100, "B"),
      frame("fe-sd-0123456789abcdef-zero", 4100, "B"),
      frame("fe-sd-0123456789abcdef-zero", 8100, "B"),
      frame("fe-sd-0123456789abcdef-duration", 1000, "A"),
      frame("fe-sd-0123456789abcdef-duration", 2000, "A"),
      frame("fe-sd-0123456789abcdef-duration", 500, "B"),
      frame("unknown-job", 1, "A"),
    ],
  };
  const chains = productionChains(digest);
  assert.deepEqual(
    chains.retryZero,
    [0, 3, 6],
    "unsorted frames are sorted, and of two chains of three the first wins",
  );
  assert.deepEqual(chains.retryDuration, [0, 1], "the longest of two chains");
  assert.deepEqual(Object.keys(chains).toSorted(), ["retryDuration", "retryZero"]);
  // a chain must not be replaced by an equal-length one
  const equal = {
    frames: [
      frame("fe-sd-0123456789abcdef-zero", 0, "A"),
      frame("fe-sd-0123456789abcdef-zero", 1000, "A"),
      frame("fe-sd-0123456789abcdef-zero", 5000, "B"),
      frame("fe-sd-0123456789abcdef-zero", 9000, "B"),
    ],
  };
  assert.deepEqual(productionChains(equal).retryZero, [0, 1]);
});

test("the row forms: a message id of another length, a timestamp with a trailing zero or four digits, and the first of equal chains", () => {
  const eighteen = local();
  eighteen.natural.lines = eighteen.natural.lines.map((x) =>
    x.value.generation === 1
      ? {
          ...x,
          value: { ...x.value, context: { ...x.value.context, eventId: "210604706362209599" } },
        }
      : x,
  );
  assert.equal(verdicts(production(), eighteen)["v1.context.eventId"], "DIVERGES");
  for (const bad of [
    "2026-10-05T08:41:01.3590Z",
    "2026-10-05T08:41:01.3591Z",
    "2026-10-05T08:41:01.350Z",
    "2026-10-05T08:41:01.0Z",
  ]) {
    const l = local();
    l.natural.lines = l.natural.lines.map((x) =>
      x.value.generation === 1
        ? { ...x, value: { ...x.value, context: { ...x.value.context, timestamp: bad } } }
        : x,
    );
    assert.equal(verdicts(production(), l)["v1.context.timestamp"], "DIVERGES", bad);
  }
  for (const good of [
    "2026-10-05T08:41:01.359Z",
    "2026-10-05T08:41:01.5Z",
    "2026-10-05T08:41:01Z",
    "2026-10-05T08:41:01.05Z",
  ]) {
    const l = local();
    l.natural.lines = l.natural.lines.map((x) =>
      x.value.generation === 1
        ? { ...x, value: { ...x.value, context: { ...x.value.context, timestamp: good } } }
        : x,
    );
    assert.equal(verdicts(production(), l)["v1.context.timestamp"], "MATCH", good);
  }
});

test("the retry tolerance: latency of a second per attempt is allowed, earlier or much later is not", () => {
  const chain = (offsets) =>
    offsets.map((o) => ({
      at: instant(T0 + o * 1000),
      kind: "PROBE",
      value: { handler: "retryFour" },
    }));
  const withFour = (offsets) => {
    const l = local();
    l.probe.lines = [
      ...l.probe.lines.filter((x) => x.value.handler !== "retryFour"),
      ...chain(offsets),
    ];
    return verdicts(production(), l)["retry.retryFour"];
  };
  // production 0, 4.6, 13.2, 29.7, 48.2: the first offset must be zero and later ones may trail by up to 1.2 s per attempt plus 1 s
  assert.equal(withFour([0, 4, 12, 28, 48]), "MATCH");
  assert.equal(withFour([0, 4.6, 13.2, 29.7, 48.2]), "MATCH");
  assert.equal(withFour([0, 4.2, 12.4, 28.9, 47.9]), "MATCH");
  assert.equal(
    withFour([0, 5, 13.5, 30, 48.5]),
    "MATCH",
    "production may be earlier than local by half a second",
  );
  assert.equal(
    withFour([0, 6, 13.2, 29.7, 48.2]),
    "DIVERGES",
    "local later than production by more than half a second",
  );
  assert.equal(
    withFour([0, 2, 12, 28, 48]),
    "DIVERGES",
    "more than 1.2 s per attempt plus 1 s later",
  );
  assert.equal(
    withFour([0, 3, 12, 28, 48]),
    "MATCH",
    "1.6 s later on the first retry is within 2.2 s",
  );
  assert.equal(
    withFour([0, 4, 12, 28, 40]),
    "DIVERGES",
    "the last attempt: production 8 s later than local, beyond 5.8 s",
  );
  assert.equal(withFour([0, 4, 12, 28, 43]), "MATCH", "5.2 s later is inside 5.8 s");
});

const value = (rowsList, id) => rowsList.find((r) => r.id === id);

test("the values the matching rows compare are the recorded ones, not only equal to each other", () => {
  const table = rows(production(), local());
  assert.deepEqual(
    [value(table, "v1.failure-no-retry").production, value(table, "v1.failure-no-retry").local],
    [[1], [1]],
  );
  assert.deepEqual(
    [
      value(table, "cadence.every-1-minutes.spacing").production,
      value(table, "cadence.every-1-minutes.spacing").local,
    ],
    [60, 60],
  );
  assert.deepEqual(value(table, "cadence.every-1-minutes.phase").production, ["fractional second"]);
  assert.deepEqual(value(table, "cadence.every-5-minutes.alignment").production, [
    "off the boundary",
  ]);
  assert.deepEqual(value(table, "v2.request.method").production, ["POST"]);
  assert.deepEqual(value(table, "v2.request.url").local, ["/"]);
  assert.deepEqual(value(table, "v2.request.body").production, [null]);
  assert.deepEqual(value(table, "v1.argumentCount").production, [1]);
  assert.deepEqual(value(table, "v1.context.eventId").production, ["<17 digits>"]);
  assert.deepEqual(value(table, "v1.context.keys").production, [
    ["eventId", "eventType", "params", "resource", "timestamp"],
  ]);
  assert.deepEqual(value(table, "retry.retryFive").production, CHAINS.retryFive);
  assert.deepEqual(value(table, "retry.retryZero").local, [0]);
  assert.equal(value(table, "forced-run").verdict, "NOT_COMPARABLE");
  const headers = value(table, "v2.request.headers").production[0];
  assert.equal(headers["x-cloudscheduler-jobname"], "<job id>");
  assert.equal(headers["x-cloudscheduler-scheduletime"], "dddd-dd-ddTdd:dd:dd-dd:dd");
  assert.equal(headers["content-length"], "0");
});

test("a recording with no frames of a generation is refused, not matched vacuously", () => {
  const p = production();
  assert.throws(
    () => rows({ ...p, frames: p.frames.filter((f) => f.generation === 2) }, local()),
    /nothing to compare/,
  );
  assert.throws(
    () => rows({ ...p, frames: p.frames.filter((f) => f.generation === 1) }, local()),
    /nothing to compare/,
  );
});

test("a missing header and a context that disagrees with the job id each diverge on their own row", () => {
  const noAgent = local();
  noAgent.natural.lines = noAgent.natural.lines.map((x) => {
    if (x.value.generation !== 2) return x;
    const headers = Object.fromEntries(
      Object.entries(x.value.request.headers).filter(([name]) => name !== "user-agent"),
    );
    return { ...x, value: { ...x.value, request: { ...x.value.request, headers } } };
  });
  assert.equal(verdicts(production(), noAgent)["v2.request.headers"], "DIVERGES");
  const eventId = local();
  eventId.natural.lines = eventId.natural.lines.map((x) =>
    x.value.generation === 2
      ? { ...x, value: { ...x.value, context: { ...x.value.context, eventId: "other" } } }
      : x,
  );
  assert.equal(verdicts(production(), eventId)["v2.event.context"], "DIVERGES");
  const topic = local();
  topic.natural.lines = topic.natural.lines.map((x) =>
    x.value.generation === 2
      ? {
          ...x,
          value: {
            ...x.value,
            context: {
              ...x.value.context,
              resource: { ...x.value.context.resource, name: "projects/demo/topics/other" },
            },
          },
        }
      : x,
  );
  assert.equal(verdicts(production(), topic)["v2.event.context"], "DIVERGES");
  const job = local();
  job.natural.lines = job.natural.lines.map((x) =>
    x.value.generation === 1
      ? {
          ...x,
          value: {
            ...x.value,
            context: {
              ...x.value.context,
              resource: {
                ...x.value.context.resource,
                name: x.value.context.resource.name.replace("/topics/", "/jobs/"),
              },
            },
          },
        }
      : x,
  );
  assert.equal(
    verdicts(production(), job)["v1.context.resource"],
    "DIVERGES",
    "a job path with the right keys is still not the topic",
  );
});

test("the phase of a time: a fraction beyond half a millisecond is a fraction, a smaller one is not", () => {
  const phase = (fraction) => {
    const l = local();
    l.natural.lines = l.natural.lines.map((x) =>
      x.value.handler === "schedOkV2"
        ? {
            ...x,
            value: {
              ...x.value,
              event: {
                ...x.value.event,
                scheduleTime: x.value.event.scheduleTime.replace(".416739", fraction),
              },
            },
          }
        : x,
    );
    return value(rows(production(), l), "cadence.every-1-minutes.phase").local;
  };
  assert.deepEqual(phase(".0006"), ["fractional second"]);
  assert.deepEqual(phase(".0004"), ["whole minute"]);
  assert.deepEqual(phase(""), ["whole minute"]);
  assert.deepEqual(phase(".5"), ["fractional second"]);
});
