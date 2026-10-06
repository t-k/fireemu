// The comparison rows against synthetic recordings and local timelines built to match, then broken one field at a
// time: each row must say MATCH for the matching pair and DIVERGES for its own near miss, and nothing else.
import assert from "node:assert/strict";
import test from "node:test";
import {
  FORM,
  compareProfiles,
  inFlightFacts,
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
  "x-forwarded-proto",
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
      "accept-encoding": "gzip, deflate, br",
      "x-forwarded-proto": "https",
      host: "us-central1-fireemu-oracle-sbx.cloudfunctions.net",
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
  // schedOkV2: every 60 s with a fractional anchor, the first occurrence on the minute (as recorded)
  for (let i = 0; i < 5; i++)
    frames.push(prodV2("schedOkV2", i * 60_000, la(T0 + i * 60_000, i === 0 ? "" : ".416739")));
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
  // a forced run between two natural ones, and two Gen1 handlers at the same instant
  frames.push(prodV2("schedOkV2", 30_000, la(T0 + 30_000, ".416739")));
  frames.push(prodV1("schedOkV1", 2000, "22257109111563907", "2026-10-05T08:41:01.359Z"));
  frames.push(prodV1("schedOkV1", 2000, "22257109111563908", "2026-10-05T08:41:01.359Z"));
  frames.push(prodV1("schedFailV1", 4000, "22256732696405721", "2026-10-05T08:42:50.384Z"));
  frames.push(prodV1("schedFailV1", 300_000, "22256732696405722", "2026-10-05T08:47:05.447Z"));
  // `every 1 minutes` with a 100 s handler: natural runs at 0, 120, 300 and 420 s (the occurrences between never
  // started), and a forced run at 150 s inside the one that began at 120 s; the occurrence at 240 s fell inside the
  // forced run, so the next natural run is at 300 s.
  for (const [start, forced] of [
    [0, false],
    [120, false],
    [150, true],
    [300, false],
    [420, false],
  ]) {
    const scheduleTime = la(T0 + (forced ? 360 : start) * 1000, ".352477");
    frames.push({ ...prodV2("schedSlowV2", start * 1000, scheduleTime), phase: "start" });
    frames.push({ ...prodV2("schedSlowV2", (start + 100) * 1000, scheduleTime), phase: "end" });
  }
  return {
    run: { id: "x" },
    frames,
    // the forced requests: one of the slow job (a second before its frame), one of another job
    forced: [
      { pass: 1, job: jobId("schedSlowV2"), atMs: 149_000 },
      { pass: 1, job: jobId("schedOkV2"), atMs: 29_000 },
    ],
  };
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
                    : n === "accept-encoding"
                      ? "gzip, deflate, br"
                      : n === "x-forwarded-proto"
                        ? "https"
                        : n === "host"
                          ? "us-central1-demo-app.cloudfunctions.net"
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
  lines.push(localV2("schedSlowV2", instant(T0), la(T0, ".352477")));
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
  // the in-flight scenario: the same runs as the recording's slow job, the forced one placed by a manual run
  const inflight = [];
  for (const [start, scheduleTime] of [
    [0, 0],
    [120, 120],
    [150, 150],
    [300, 300],
    [420, 420],
  ]) {
    for (const [phase, at] of [
      ["start", start],
      ["end", start + 100],
    ])
      inflight.push(
        localV2("schedSlowV2", instant(T0 + at * 1000), la(T0 + scheduleTime * 1000), { phase }),
      );
  }
  return {
    natural: { lines: over.lines ?? lines, unplaced: 0, state: null },
    probe: { lines: over.probe ?? probe, unplaced: 0, state: null },
    inflight: {
      lines: over.inflight ?? inflight,
      manual: over.manual ?? [{ name: "schedSlowV2", at: instant(T0 + 149_000) }],
      unplaced: 0,
      state: null,
    },
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
  assert.equal(Object.keys(v).length, 25);
});

test("FORM keeps the shape of a time, its fraction's length and a trailing zero, and masks the digits", () => {
  assert.equal(FORM("2026-10-05T01:42:01.416739-07:00"), "dddd-dd-ddTdd:dd:dd.dddddd-dd:dd");
  assert.equal(FORM("2026-10-05T01:42:01-07:00"), "dddd-dd-ddTdd:dd:dd-dd:dd");
  assert.equal(FORM("2026-10-05T08:41:00Z"), "dddd-dd-ddTdd:dd:ddZ");
  assert.equal(FORM("2026-10-05T01:42:01.4167390-07:00"), "dddd-dd-ddTdd:dd:dd.ddddddz-dd:dd");
  assert.equal(FORM("2026-10-05T01:42:01.416739123-07:00"), "dddd-dd-ddTdd:dd:dd.ddddddddd-dd:dd");
  assert.equal(FORM("2026-10-05T01:42:01.5Z"), "dddd-dd-ddTdd:dd:dd.dZ");
  assert.equal(FORM("2026-10-05T01:42:01.0Z"), "dddd-dd-ddTdd:dd:dd.zZ");
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
      {
        "v2.event.jobName": ["v2.event.context"],
        "v2.event.context": ["v2.event.context-values"],
        // every Gen1 frame given one message id reads as a retry of one occurrence
        "v1.context.eventId": ["v1.failure-no-retry"],
      }[id] ?? [];
    const others = Object.entries(v).filter(
      ([k, verdict]) =>
        k !== id && !coupled.includes(k) && verdict !== "MATCH" && k !== "forced-run",
    );
    assert.deepEqual(others, [], "only the broken row moves");
  });
}

test("v1.failure-no-retry: a second attempt of the same occurrence diverges, at the same instant or some seconds later", () => {
  for (const seconds of [0, 6, 90]) {
    const l = local();
    l.natural.lines.push(
      localV1(
        "schedFailV1",
        instant(T0 + 1000 + seconds * 1000),
        "27203228007418468",
        "2026-10-05T08:42:50.384Z",
      ),
    );
    assert.equal(verdicts(production(), l)["v1.failure-no-retry"], "DIVERGES", `+${seconds}s`);
  }
  // another occurrence (its own message id) is not a retry, whenever it comes
  const other = local();
  other.natural.lines.push(
    localV1("schedFailV1", instant(T0 + 1000), "27203228007418469", "2026-10-05T08:42:50.384Z"),
  );
  assert.equal(verdicts(production(), other)["v1.failure-no-retry"], "MATCH");
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
  assert.deepEqual(parseTimeline("").manual, []);
});

test("parseTimeline keeps each manual run with the logical instant it was made at, and ignores a line it cannot read", () => {
  const output = [
    'MANUAL schedSlowV2 2026-10-05T08:40:30Z {"status":200,"json":{}}',
    "STEP 2026-10-05T08:40:31Z",
    'MANUAL other 2026-10-05T08:43:50Z {"status":400}',
    "MANUAL",
    "MANUAL onlyaname",
    "STEP 2026-10-05T08:43:51Z",
  ].join("\n");
  assert.deepEqual(parseTimeline(output).manual, [
    { name: "schedSlowV2", at: "2026-10-05T08:40:30Z", status: 200 },
    { name: "other", at: "2026-10-05T08:43:50Z", status: 400 },
  ]);
  // a manual run is not a handler line and does not become one
  assert.deepEqual(parseTimeline(output).lines, []);
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
  const forms = value(table, "v2.request.headers").production;
  assert.deepEqual([...new Set(forms.map((f) => f["x-cloudscheduler-jobname"]))].toSorted(), [
    "firebase-schedule-schedOkV2-us-central1",
    "firebase-schedule-schedRetryV2-us-central1",
    "firebase-schedule-schedSlowV2-us-central1",
  ]);
  assert.deepEqual([...new Set(forms.map((f) => f["x-cloudscheduler-scheduletime"]))].toSorted(), [
    "dddd-dd-ddTdd:dd:dd-dd:dd",
    "dddd-dd-ddTdd:dd:dd.dddddd-dd:dd",
  ]);
  assert.ok(forms.every((f) => f["content-length"] === "0"));
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

test("the production gaps are a mode, not the first gap: a forced run between two natural ones does not set the spacing", () => {
  const table = rows(production(), local());
  assert.equal(value(table, "cadence.every-1-minutes.spacing").production, 60);
});

test("a Gen1 failure is counted for schedFailV1 only: two other Gen1 frames with one message id do not change it", () => {
  const table = rows(production(), local());
  assert.deepEqual(value(table, "v1.failure-no-retry").production, [1]);
  // schedOkV1 delivered twice with one id (a redelivery of a handler that does not fail) is not a failure retried
  const p = production();
  p.frames.push(prodV1("schedOkV1", 3000, "22257109111563907", "2026-10-05T08:41:01.359Z"));
  const l = local();
  l.natural.lines.push(
    localV1("schedOkV1", instant(T0 + 3000), "21060470636220959", "2026-10-05T08:41:01.359Z"),
  );
  const row = value(rows(p, l), "v1.failure-no-retry");
  assert.deepEqual(row.production, [1]);
  assert.deepEqual(row.local, [1]);
  assert.equal(row.verdict, "MATCH");
});

test("the phase compares every occurrence after the first: a second one on the minute is a whole-minute phase", () => {
  const p = production();
  p.frames = p.frames.map((f) =>
    f.handler === "schedOkV2" && f.at === 60_000
      ? {
          ...f,
          event: { ...f.event, scheduleTime: la(T0 + 60_000) },
          headers: { ...f.headers, "x-cloudscheduler-scheduletime": la(T0 + 60_000) },
        }
      : f,
  );
  assert.deepEqual(value(rows(p, local()), "cadence.every-1-minutes.phase").production, [
    "fractional second",
    "whole minute",
  ]);
});

test("the v2 context row's values are the recorded ones", () => {
  const row = value(rows(production(), local()), "v2.event.context");
  assert.deepEqual(row.production, [
    {
      property: { enumerable: false, configurable: false, hasGetter: true },
      eventIdIsJobId: true,
      topic: true,
      type: "google.pubsub.topic.publish",
    },
  ]);
  assert.deepEqual(row.local, row.production);
});

test("frames and lines may arrive in any order: the rows do not change", () => {
  const p = production();
  const l = local();
  const reversedProduction = {
    ...p,
    frames: [...p.frames].reverse(),
    forced: [...p.forced].reverse(),
  };
  const reversedLocal = {
    natural: { ...l.natural, lines: [...l.natural.lines].reverse() },
    probe: { ...l.probe, lines: [...l.probe.lines].reverse() },
    inflight: { ...l.inflight, lines: [...l.inflight.lines].reverse() },
  };
  assert.deepEqual(rows(reversedProduction, reversedLocal), rows(p, l));
});

test("the five-minute alignment reads the schedRetryV2 times only, whatever the other handlers' times are", () => {
  const p = production();
  // every schedRetryV2 time on a five-minute boundary (two of them), while the other handlers' times stay off it
  const boundaries = ["2026-10-05T01:45:00-07:00", "2026-10-05T01:50:00-07:00"];
  let n = 0;
  const onBoundary = {
    ...p,
    frames: p.frames.map((f) => {
      if (
        f.handler !== "schedRetryV2" ||
        !f.headers["x-cloudscheduler-jobname"].startsWith("firebase-schedule-")
      )
        return f;
      const scheduleTime = boundaries[n++ % 2];
      return {
        ...f,
        event: { ...f.event, scheduleTime },
        headers: { ...f.headers, "x-cloudscheduler-scheduletime": scheduleTime },
      };
    }),
  };
  const l = local();
  let m = 0;
  l.natural.lines = l.natural.lines.map((x) =>
    x.value.handler === "schedRetryV2"
      ? {
          ...x,
          value: { ...x.value, event: { ...x.value.event, scheduleTime: boundaries[m++ % 2] } },
        }
      : x,
  );
  l.natural.lines.push(localV2("schedRetryV2", instant(T0 + 600_000), "2026-10-05T01:55:00-07:00"));
  const aligned = value(rows(onBoundary, l), "cadence.every-5-minutes.alignment");
  assert.deepEqual(aligned.production, ["five-minute boundary"]);
  assert.deepEqual(aligned.local, ["five-minute boundary"]);
  assert.equal(aligned.verdict, "MATCH");
});

test("localChains keeps the earliest occurrence, the first of equal starts, and sorts a descending occurrence", () => {
  const line = (handler, scheduleTime, seconds) => ({
    at: instant(T0 + seconds * 1000),
    kind: "PROBE",
    value: { handler, scheduleTime },
  });
  // later occurrence first, then an earlier one that starts before it but ends after it
  const both = [line("h", "A", 10), line("h", "A", 20), line("h", "B", 5), line("h", "B", 30)];
  assert.deepEqual(localChains({ lines: both }).h, [0, 25]);
  assert.deepEqual(localChains({ lines: [...both].reverse() }).h, [0, 25]);
  // equal starts: the first one met wins
  const tie = [line("h", "A", 0), line("h", "A", 4), line("h", "B", 0), line("h", "B", 9)];
  assert.deepEqual(localChains({ lines: tie }).h, [0, 4]);
  // an occurrence listed in descending time order is read ascending
  assert.deepEqual(
    localChains({ lines: [line("h", "A", 12), line("h", "A", 4), line("h", "A", 0)] }).h,
    [0, 4, 12],
  );
});

test("the lower edge of the retry tolerance is inclusive: half a second earlier than local still matches", () => {
  const p = production();
  // retryDuration in production: 0, 4.6, 13.2, 23.7; give it offsets exactly half a second earlier than local
  p.frames = p.frames.filter(
    (f) => !f.headers?.["x-cloudscheduler-jobname"]?.endsWith("-duration"),
  );
  const base = 90_000_000;
  for (const o of [0, 4.5, 13.5, 24.5])
    p.frames.push(
      prodV2(
        "schedRetryV2",
        base + o * 1000,
        "2026-12-31T16:00:00-08:00",
        "fe-sd-0123456789abcdef-duration",
      ),
    );
  const l = local();
  l.probe.lines = l.probe.lines.filter((x) => x.value.handler !== "retryDuration");
  for (const o of [0, 5, 14, 25])
    l.probe.lines.push({
      at: instant(T0 + o * 1000),
      kind: "PROBE",
      value: { handler: "retryDuration" },
    });
  assert.equal(value(rows(p, l), "retry.retryDuration").verdict, "MATCH");
  p.frames = p.frames.filter(
    (f) => !f.headers?.["x-cloudscheduler-jobname"]?.endsWith("-duration"),
  );
  for (const o of [0, 4.4, 13.5, 24.5])
    p.frames.push(
      prodV2(
        "schedRetryV2",
        base + o * 1000,
        "2026-12-31T16:00:00-08:00",
        "fe-sd-0123456789abcdef-duration",
      ),
    );
  assert.equal(value(rows(p, l), "retry.retryDuration").verdict, "DIVERGES");
});

// ---- cadence.in-flight-skip (production: run 156715222b86ea44, schedSlowV2) ----

const slowLocal = (runs) =>
  runs.flatMap(([start, end]) => [
    localV2("schedSlowV2", instant(T0 + start * 1000), la(T0 + start * 1000), { phase: "start" }),
    localV2("schedSlowV2", instant(T0 + end * 1000), la(T0 + start * 1000), { phase: "end" }),
  ]);
const inflightRow = (l, p = production()) => value(rows(p, l), "cadence.in-flight-skip");
const recorded = {
  naturalStartsInFlight: 0,
  occurrencesSkipped: true,
  forcedStartsInFlight: true,
  startsOnTime: true,
};

test("cadence.in-flight-skip: production's runs skip occurrences, never start a natural one in flight, and let a forced one start inside", () => {
  const row = inflightRow(local());
  assert.deepEqual(row.production, recorded);
  assert.deepEqual(row.local, recorded);
  assert.equal(row.verdict, "MATCH");
});

test("cadence.in-flight-skip: a local run that starts every occurrence overlaps itself and diverges", () => {
  // a 100 s handler started every 60 s: each natural start is inside the previous run
  const l = local({
    inflight: slowLocal([
      [0, 100],
      [60, 160],
      [120, 220],
      [180, 280],
    ]),
    manual: [],
  });
  const row = inflightRow(l);
  assert.deepEqual(row.local, {
    naturalStartsInFlight: 3,
    occurrencesSkipped: false,
    forcedStartsInFlight: false,
    startsOnTime: true,
  });
  assert.equal(row.verdict, "DIVERGES");
});

test("cadence.in-flight-skip: one natural start inside a run diverges, and so does a run that never skips an occurrence", () => {
  // the skipping is right but the third natural run starts 30 s before the second ends
  const inside = local({
    inflight: slowLocal([
      [0, 100],
      [120, 220],
      [150, 250],
      [200, 300],
      [420, 520],
    ]),
    manual: [{ name: "schedSlowV2", at: instant(T0 + 149_000) }],
  });
  assert.equal(inflightRow(inside).local.naturalStartsInFlight, 1);
  assert.equal(inflightRow(inside).verdict, "DIVERGES");
  // a short handler: every occurrence starts, none is skipped (the near miss of "skipped")
  const quick = local({
    inflight: slowLocal([
      [0, 10],
      [60, 70],
      [120, 130],
      [180, 190],
    ]),
    manual: [],
  });
  assert.equal(inflightRow(quick).local.occurrencesSkipped, false);
  assert.equal(inflightRow(quick).verdict, "DIVERGES");
});

test("cadence.in-flight-skip: a forced run is told from a natural one by its request, and a forced run refused or not started diverges", () => {
  // without the manual run recorded the run at 150 s is a natural start inside a run
  const unrecorded = local({ manual: [] });
  assert.equal(inflightRow(unrecorded).local.naturalStartsInFlight, 1);
  assert.equal(inflightRow(unrecorded).verdict, "DIVERGES");
  // a request claims a start from one second before it to five seconds after it: the run at 150 s is claimed by a
  // request between 145 s and 151 s, and not by one at 144 s or 152 s
  for (const [at, claimed] of [
    [149_000, true],
    [150_000, true],
    [151_000, true],
    [145_000, true],
    [144_000, false],
    [152_000, false],
  ]) {
    const l = local({ manual: [{ name: "schedSlowV2", at: instant(T0 + at) }] });
    assert.equal(inflightRow(l).local.forcedStartsInFlight, claimed, `manual at ${at}`);
  }
  // another job's manual run does not claim the slow job's start
  const other = local({ manual: [{ name: "schedOkV2", at: instant(T0 + 149_000) }] });
  assert.equal(inflightRow(other).verdict, "DIVERGES");
  // production: the forced request of another job does not claim a slow start, so the run at 150 s is natural
  const p = production();
  p.forced = p.forced.filter((f) => !f.job.includes("schedSlowV2"));
  assert.equal(inflightRow(local(), p).production.naturalStartsInFlight, 1);
});

test("cadence.in-flight-skip: no local frames, a run that never ends, and an unfinished first run are not a match", () => {
  const none = local({ inflight: [], manual: [] });
  assert.equal(inflightRow(none).verdict, "DIVERGES");
  const withoutInflight = local();
  delete withoutInflight.inflight;
  assert.equal(inflightRow(withoutInflight).verdict, "DIVERGES");
  // the first run never ends: every later natural start is inside it
  const endless = local({
    inflight: slowLocal([[0, 100]])
      .filter((l) => l.value.phase === "start")
      .concat(slowLocal([[120, 220]])),
    manual: [],
  });
  assert.ok(inflightRow(endless).local.naturalStartsInFlight >= 1);
});

test("inFlightFacts: edges of the in-flight interval, the cadence factor and the end pairing", () => {
  const f = (start, end) => [
    { phase: "start", at: start, scheduled: start },
    { phase: "end", at: end, scheduled: start },
  ];
  // a start exactly at the end of a run is not inside it
  assert.equal(inFlightFacts([...f(0, 100), ...f(100, 200)], [], 60).naturalStartsInFlight, 0);
  // a start exactly at the start of another is not inside it either (both begin together)
  assert.equal(inFlightFacts([...f(0, 100), ...f(0, 100)], [], 60).naturalStartsInFlight, 0);
  // one second inside
  assert.equal(inFlightFacts([...f(0, 100), ...f(99, 199)], [], 60).naturalStartsInFlight, 1);
  // a gap of exactly one and a half cadences is not a skip; one second more is
  assert.equal(inFlightFacts([...f(0, 10), ...f(90, 100)], [], 60).occurrencesSkipped, false);
  assert.equal(inFlightFacts([...f(0, 10), ...f(91, 100)], [], 60).occurrencesSkipped, true);
  // frames in any order: ends close the oldest start
  const shuffled = [...f(120, 220), ...f(0, 100)].reverse();
  assert.equal(inFlightFacts(shuffled, [], 60).naturalStartsInFlight, 0);
  assert.equal(inFlightFacts(shuffled, [], 60).occurrencesSkipped, true);
  // a forced request claims the first start inside its window, once
  const runs = [...f(0, 100), ...f(50, 150)];
  assert.deepEqual(inFlightFacts(runs, [49], 60), {
    naturalStartsInFlight: 0,
    occurrencesSkipped: false,
    forcedStartsInFlight: true,
    startsOnTime: true,
  });
  // the same starts with the request outside the window of both: the second start is a natural one inside a run
  assert.equal(inFlightFacts(runs, [20], 60).naturalStartsInFlight, 1);
  // two requests claim two starts
  assert.equal(
    inFlightFacts([...f(0, 100), ...f(50, 150), ...f(60, 160)], [49, 59], 60).naturalStartsInFlight,
    0,
  );
  // one request claims one start only
  assert.equal(
    inFlightFacts([...f(0, 100), ...f(50, 150), ...f(51, 151)], [49], 60).naturalStartsInFlight,
    1,
  );
  // no frames: nothing in flight, nothing skipped
  assert.deepEqual(inFlightFacts([], [], 60), {
    naturalStartsInFlight: 0,
    occurrencesSkipped: false,
    forcedStartsInFlight: false,
    startsOnTime: true,
  });
});

// ---- the header rows (strict must send exactly the recorded headers, and the recorded forms) ----

const headerRows = (l) => {
  const table = rows(production(), l);
  return {
    names: value(table, "v2.request.header-names"),
    headers: value(table, "v2.request.headers"),
    time: value(table, "v2.event.scheduleTime-form"),
    job: value(table, "v2.event.jobName"),
  };
};
const mapV2 = (l, change) => {
  const copy = local();
  copy.natural.lines = l.natural.lines.map((x) => (x.value.generation === 2 ? change(x) : x));
  return copy;
};

test("v2.request.header-names: an extra header fails, a missing one beyond the unreproducible ones fails, and only the declared missing set is excused", () => {
  const base = local();
  assert.equal(headerRows(base).names.verdict, "MATCH");
  assert.equal(headerRows(base).names.note, "");
  const extra = mapV2(base, (x) => ({
    ...x,
    value: {
      ...x.value,
      request: {
        ...x.value.request,
        headers: { ...x.value.request.headers, "x-extra": "1" },
      },
    },
  }));
  const extraRow = headerRows(extra).names;
  assert.equal(extraRow.verdict, "DIVERGES");
  assert.match(extraRow.note, /^UNEXPECTED: missing none; extra x-extra$/);
  // only the OIDC, trace and forwarding headers missing: declared
  const without = (names) =>
    mapV2(base, (x) => ({
      ...x,
      value: {
        ...x.value,
        request: {
          ...x.value.request,
          headers: Object.fromEntries(
            Object.entries(x.value.request.headers).filter(([name]) => !names.includes(name)),
          ),
        },
      },
    }));
  const declared = headerRows(without(["authorization"])).names;
  assert.equal(declared.verdict, "DIVERGES");
  assert.match(declared.note, /^declared: not reproduced authorization /);
  // a header production sends that is not one of the unreproducible ones: unexpected
  const unexpected = headerRows(without(["user-agent"])).names;
  assert.equal(unexpected.verdict, "DIVERGES");
  assert.match(unexpected.note, /^UNEXPECTED: missing user-agent; extra none$/);
  // missing the declared one and carrying an extra one is unexpected, not declared
  const both = headerRows(
    mapV2(without(["authorization"]), (x) => ({
      ...x,
      value: {
        ...x.value,
        request: {
          ...x.value.request,
          headers: { ...x.value.request.headers, "x-extra": "1" },
        },
      },
    })),
  ).names;
  assert.match(both.note, /^UNEXPECTED: missing authorization; extra x-extra$/);
  // no local request at all is unexpected, not declared
  const none = headerRows(mapV2(base, (x) => ({ ...x, value: { ...x.value, request: null } })));
  assert.equal(none.names.verdict, "DIVERGES");
  assert.match(none.names.note, /^UNEXPECTED/);
});

test("v2.request.header-names: every distinct recorded name set counts, not the first", () => {
  const p = production();
  // a frame of another job that carried one more header: the union is what a handler could see
  p.frames.push({
    ...prodV2("schedOkV2", 5_000_000, la(T0, ".416739")),
    headerNames: [...NAMES, "x-late"],
  });
  const table = rows(p, local());
  const row = value(table, "v2.request.header-names");
  assert.ok(row.production.includes("x-late"));
  assert.equal(row.verdict, "DIVERGES");
  assert.match(row.note, /missing x-late/);
});

test("the schedule time keeps its precision: nine digits and a trailing zero diverge, no fraction still matches", () => {
  const withTime = (time) =>
    mapV2(local(), (x) =>
      x.value.handler === "schedOkV2"
        ? {
            ...x,
            value: {
              ...x.value,
              event: { ...x.value.event, scheduleTime: time },
              request: {
                ...x.value.request,
                headers: { ...x.value.request.headers, "x-cloudscheduler-scheduletime": time },
              },
            },
          }
        : x,
    );
  for (const [time, verdict] of [
    ["2026-10-05T01:41:00-07:00", "MATCH"],
    ["2026-10-05T01:41:00.416739-07:00", "MATCH"],
    ["2026-10-05T01:41:00.416739123-07:00", "DIVERGES"],
    ["2026-10-05T01:41:00.4167390-07:00", "DIVERGES"],
    ["2026-10-05T01:41:00.4-07:00", "DIVERGES"],
    ["2026-10-05T01:41:00Z", "DIVERGES"],
  ]) {
    const r = headerRows(withTime(time));
    assert.equal(r.time.verdict, verdict, `event ${time}`);
    assert.equal(r.headers.verdict, verdict, `header ${time}`);
  }
});

test("the job id is compared by value, with only the project masked", () => {
  const renamed = (name) =>
    mapV2(local(), (x) =>
      x.value.handler === "schedOkV2"
        ? {
            ...x,
            value: {
              ...x.value,
              event: { ...x.value.event, jobName: name },
              request: {
                ...x.value.request,
                headers: { ...x.value.request.headers, "x-cloudscheduler-jobname": name },
              },
            },
          }
        : x,
    );
  assert.equal(headerRows(renamed("firebase-schedule-schedOkV2-us-central1")).job.verdict, "MATCH");
  for (const name of [
    "firebase-schedule-schedOkV2-europe-west1",
    "schedOkV2",
    "projects/demo/locations/us-central1/jobs/firebase-schedule-schedOkV2-us-central1",
  ]) {
    const r = headerRows(renamed(name));
    assert.equal(r.job.verdict, "DIVERGES", name);
    assert.equal(r.headers.verdict, "DIVERGES", name);
  }
});

// ---- daylight-saving changes: the times are ordered by the instant they name, not by their text ----

test("the cadence rows order times across the November change: -07:00 and -08:00 times sort by instant", () => {
  // 2026-11-01 01:59 PDT (08:59Z) is followed by 01:00 PST (09:00Z); their text sorts the other way round
  const crossing = (handler) =>
    [
      ["2026-11-01T01:59:00-07:00", 0],
      ["2026-11-01T01:00:00-08:00", 60_000],
    ].map(([time, at]) => prodV2(handler, at, time));
  const p = production();
  p.frames = p.frames.filter((f) => f.handler !== "schedOkV2").concat(crossing("schedOkV2"));
  const l = local();
  l.natural.lines = l.natural.lines
    .filter((x) => x.value.handler !== "schedOkV2")
    .concat(
      [
        ["2026-11-01T01:59:00-07:00", 0],
        ["2026-11-01T01:00:00-08:00", 60_000],
      ].map(([time, at]) => localV2("schedOkV2", instant(T0 + at), time)),
    );
  const spacing = value(rows(p, l), "cadence.every-1-minutes.spacing");
  assert.equal(spacing.production, 60);
  assert.equal(spacing.local, 60);
  assert.equal(spacing.verdict, "MATCH");
  // the five-minute alignment drops the first occurrence by instant: the one at 01:59 PDT is off the boundary and
  // the two after it are on it, and text order would drop an on-boundary one instead
  const five = (times) =>
    times.map((time, i) => prodV2("schedRetryV2", i * 1000, time, jobId("schedRetryV2")));
  const times = [
    "2026-11-01T01:00:00-08:00",
    "2026-11-01T01:59:00-07:00",
    "2026-11-01T01:05:00-08:00",
  ];
  const q = production();
  q.frames = q.frames
    .filter(
      (f) =>
        !(
          f.handler === "schedRetryV2" &&
          f.headers["x-cloudscheduler-jobname"].startsWith("firebase-schedule-")
        ),
    )
    .concat(five(times));
  const m = local();
  m.natural.lines = m.natural.lines
    .filter((x) => x.value.handler !== "schedRetryV2")
    .concat(
      ["2026-11-01T01:00:00-08:00", "2026-11-01T01:05:00-08:00"].map((time, i) =>
        localV2("schedRetryV2", instant(T0 + i * 1000), time),
      ),
    );
  const alignment = value(rows(q, m), "cadence.every-5-minutes.alignment");
  assert.deepEqual(alignment.production, ["five-minute boundary"]);
  assert.equal(alignment.verdict, "MATCH");
});

// ---- what the in-flight row reads, and how: the survivors of the first mutation pass ----

/** `production()` with its slow job's frames and forced requests replaced. */
const withSlow = (runs, forced) => {
  const p = production();
  p.frames = p.frames.filter((f) => f.handler !== "schedSlowV2");
  for (const [start, end] of runs) {
    const scheduleTime = la(T0 + start * 1000, ".352477");
    p.frames.push({ ...prodV2("schedSlowV2", start * 1000, scheduleTime), phase: "start" });
    p.frames.push({ ...prodV2("schedSlowV2", end * 1000, scheduleTime), phase: "end" });
  }
  p.forced = forced.map((atMs) => ({ pass: 1, job: jobId("schedSlowV2"), atMs }));
  return p;
};
const slowFacts = (p, runs, manual = []) => {
  const l = local({
    inflight: slowLocal(runs),
    manual: manual.map((at) => ({ name: "schedSlowV2", at: instant(T0 + at * 1000) })),
  });
  return value(rows(p, l), "cadence.in-flight-skip");
};

test("inFlightFacts: the forced requests are matched in time order, whatever order they come in", () => {
  const f = (start, end) => [
    { phase: "start", at: start, scheduled: start },
    { phase: "end", at: end, scheduled: start },
  ];
  // requests at 6 and 11 each claim a start inside their window; the one at 11 could take the start at 10 that the
  // one at 6 needs, so the order they are matched in decides whether both runs are forced
  const runs = [...f(10, 100), ...f(16, 110)];
  const both = {
    naturalStartsInFlight: 0,
    occurrencesSkipped: false,
    forcedStartsInFlight: true,
    startsOnTime: true,
  };
  assert.deepEqual(inFlightFacts(runs, [11, 6], 60), both);
  assert.deepEqual(inFlightFacts(runs, [6, 11], 60), both);
});

test("cadence.in-flight-skip: times are read in seconds, to the edge of the forced-request window", () => {
  // a start 1 s before its request (the window's lower edge) and 5 s after it (the upper edge) are both claimed
  // a long first run, so that a start at startS that is not claimed as forced is a natural start inside it
  const naturalCount = (requestMs, startS) =>
    slowFacts(
      withSlow(
        [
          [0, 300],
          [startS, startS + 100],
        ],
        [requestMs],
      ),
      [],
    ).production.naturalStartsInFlight;
  assert.equal(naturalCount(151_000, 150), 0, "request 1 s after the start: claimed");
  assert.equal(naturalCount(145_000, 150), 0, "request 5 s before the start: claimed");
  assert.equal(naturalCount(151_100, 150), 1, "request 1.1 s after the start: not claimed");
  assert.equal(naturalCount(144_900, 150), 1, "request 5.1 s before the start: not claimed");
});

test("cadence.in-flight-skip: a skipped occurrence is a gap beyond one and a half cadences of 60 s, on both sides", () => {
  // production 91 s apart (skipped), local 89 s apart (not): the row sees the difference only at a cadence of 60 s
  const p = withSlow(
    [
      [0, 10],
      [91, 101],
    ],
    [],
  );
  const row = slowFacts(p, [
    [0, 10],
    [89, 99],
  ]);
  assert.equal(row.production.occurrencesSkipped, true);
  assert.equal(row.local.occurrencesSkipped, false);
  assert.equal(row.verdict, "DIVERGES");
  // and the reverse: production 89 s apart, local 91 s apart
  const q = withSlow(
    [
      [0, 10],
      [89, 99],
    ],
    [],
  );
  const reverse = slowFacts(q, [
    [0, 10],
    [91, 101],
  ]);
  assert.equal(reverse.production.occurrencesSkipped, false);
  assert.equal(reverse.local.occurrencesSkipped, true);
  assert.equal(reverse.verdict, "DIVERGES");
});

test("cadence.in-flight-skip reads the slow job's start and end frames only, from production and from the local run", () => {
  const base = slowFacts(
    production(),
    [
      [0, 100],
      [120, 220],
      [150, 250],
      [300, 400],
      [420, 520],
    ],
    [149],
  );
  assert.equal(base.verdict, "MATCH");
  // another handler's frame carrying a phase does not become a run of the slow job
  const p = production();
  p.frames.push({ ...prodV2("schedOkV2", 130_000, la(T0 + 130_000, ".416739")), phase: "start" });
  const noisy = local();
  noisy.inflight.lines.push(
    localV2("schedOkV2", instant(T0 + 130_000), la(T0 + 130_000, ".416739"), { phase: "start" }),
  );
  const row = value(rows(p, noisy), "cadence.in-flight-skip");
  assert.deepEqual(row.production, recorded);
  assert.deepEqual(row.local, recorded);
  // nor does a line of another kind with the slow job's name
  const probe = local();
  probe.inflight.lines.push({
    at: instant(T0 + 130_000),
    kind: "PROBE",
    value: { handler: "schedSlowV2", phase: "start" },
  });
  assert.deepEqual(value(rows(production(), probe), "cadence.in-flight-skip").local, recorded);
});

// ---- the forms and names rows with one form, one name, or none ----

test("one recorded form against one produced form matches, and a recording with no deployed job's frame matches nothing", () => {
  const onlyOk = (list, pick) => list.filter(pick);
  const p = production();
  p.frames = onlyOk(p.frames, (f) => f.generation === 1 || f.handler === "schedOkV2");
  const l = local();
  l.natural.lines = l.natural.lines.filter(
    (x) => x.value.generation === 1 || x.value.handler === "schedOkV2",
  );
  const table = rows(p, l);
  assert.equal(value(table, "v2.request.headers").verdict, "MATCH");
  assert.equal(value(table, "v2.event.scheduleTime-form").verdict, "MATCH");
  assert.equal(value(table, "v2.request.headers").local.length, 1);
  assert.equal(value(table, "v2.event.scheduleTime-form").local.length, 1);
  // only the probe jobs in the recording (no deployed job) and nothing local: no row compares nothing and matches
  const probeOnly = production();
  probeOnly.frames = probeOnly.frames.filter(
    (f) =>
      f.generation === 1 || !f.headers["x-cloudscheduler-jobname"].startsWith("firebase-schedule-"),
  );
  const empty = local();
  empty.natural.lines = empty.natural.lines.filter((x) => x.value.generation === 1);
  const none = rows(probeOnly, empty);
  assert.equal(value(none, "v2.request.headers").verdict, "DIVERGES");
  assert.equal(value(none, "v2.event.scheduleTime-form").verdict, "DIVERGES");
});

test("header names: one name each matches, and neither side having any is not a match; nothing local is unexpected even when production's set is all unreproducible", () => {
  const names = (productionNames, localNames) => {
    const p = production();
    p.frames = p.frames.map((f) =>
      f.generation === 2 ? { ...f, headerNames: productionNames } : f,
    );
    const l = local();
    l.natural.lines = l.natural.lines.map((x) =>
      x.value.generation === 2
        ? {
            ...x,
            value: {
              ...x.value,
              request: {
                ...x.value.request,
                headers: Object.fromEntries(localNames.map((n) => [n, "x"])),
              },
            },
          }
        : x,
    );
    return value(rows(p, l), "v2.request.header-names");
  };
  const one = names(["host"], ["host"]);
  assert.equal(one.verdict, "MATCH");
  assert.equal(one.note, "");
  // no name on either side: nothing was compared
  const empty = names([], []);
  assert.equal(empty.verdict, "DIVERGES");
  assert.match(empty.note, /^UNEXPECTED: missing none; extra none$/);
  // production sent only a header nothing here can reproduce, and local sent none: the difference is the declared
  // one in size, but with no local request at all it is not excused
  const nothing = names(["authorization"], []);
  assert.equal(nothing.verdict, "DIVERGES");
  assert.match(nothing.note, /^UNEXPECTED/);
  // with one local name and only the declared one missing: declared
  const declared = names(["authorization", "host"], ["host"]);
  assert.match(declared.note, /^declared: not reproduced authorization /);
});

// ---- the three headers production sent in every frame: compared by value ----

test("the accept-encoding, x-forwarded-proto and host values are compared; the host with only its project masked", () => {
  const withHeader = (name, value) =>
    mapV2(local(), (x) => ({
      ...x,
      value: {
        ...x.value,
        request: {
          ...x.value.request,
          headers: Object.fromEntries(
            Object.entries(x.value.request.headers)
              .filter(([k]) => value !== undefined || k !== name)
              .map(([k, v]) => [k, k === name ? value : v]),
          ),
        },
      },
    }));
  const verdict = (name, value) => headerRows(withHeader(name, value)).headers.verdict;
  assert.equal(verdict("host", "us-central1-other-project.cloudfunctions.net"), "MATCH");
  assert.equal(verdict("host", "europe-west1-demo-app.cloudfunctions.net"), "DIVERGES");
  assert.equal(verdict("host", "us-central1-demo-app.example.com"), "DIVERGES");
  assert.equal(verdict("host", "demo-app.cloudfunctions.net"), "DIVERGES");
  assert.equal(verdict("host", undefined), "DIVERGES");
  assert.equal(verdict("accept-encoding", "gzip"), "DIVERGES");
  assert.equal(verdict("accept-encoding", undefined), "DIVERGES");
  assert.equal(verdict("x-forwarded-proto", "http"), "DIVERGES");
  assert.equal(verdict("x-forwarded-proto", undefined), "DIVERGES");
  const forms = headerRows(local()).headers.production;
  assert.ok(forms.every((f) => f["accept-encoding"] === "gzip, deflate, br"));
  assert.ok(forms.every((f) => f["x-forwarded-proto"] === "https"));
  assert.ok(forms.every((f) => f.host === "us-central1-<project>.cloudfunctions.net"));
});

// ---- cadence.in-flight-skip tells a skip from a queue ----

test("cadence.in-flight-skip: a queueing model that starts each due occurrence when the running ones end diverges", () => {
  // the reviewer's queue: nothing dropped, each occurrence waits and then starts at once (100.01 for the one due at
  // 60 s, ...), so the starts keep their runs apart exactly as a skip does, but late against their own schedule time
  const runs = [
    [0, 100],
    [100.01, 200.01],
    [250.01, 350.01],
    [420.01, 520.01],
  ];
  const due = [0, 60, 120, 180];
  const lines = runs.flatMap(([start, end], i) => [
    localV2("schedSlowV2", instant(T0 + start * 1000), la(T0 + due[i] * 1000), { phase: "start" }),
    localV2("schedSlowV2", instant(T0 + end * 1000), la(T0 + due[i] * 1000), { phase: "end" }),
  ]);
  // the forced run [150, 250] in the middle, claimed by a manual run at 149
  lines.push(
    localV2("schedSlowV2", instant(T0 + 150_000), la(T0 + 150_000), { phase: "start" }),
    localV2("schedSlowV2", instant(T0 + 250_000), la(T0 + 150_000), { phase: "end" }),
  );
  const row = inflightRow(
    local({ inflight: lines, manual: [{ name: "schedSlowV2", at: instant(T0 + 149_000) }] }),
  );
  assert.equal(row.local.naturalStartsInFlight, 0);
  assert.equal(row.local.occurrencesSkipped, true);
  assert.equal(row.local.forcedStartsInFlight, true);
  assert.equal(
    row.local.startsOnTime,
    false,
    "every start after the first is late against its schedule time",
  );
  assert.equal(row.verdict, "DIVERGES");
  assert.equal(row.production.startsOnTime, true);
});

test("inFlightFacts: starts are on time when their lag against their own schedule time varies by 20 seconds or less", () => {
  const f = (start, end, sched) => [
    { phase: "start", at: start, scheduled: sched },
    { phase: "end", at: end, scheduled: sched },
  ];
  const on = (frames) => inFlightFacts(frames, [], 60).startsOnTime;
  // a constant lag of any size is on time (the timeline's origin is not the schedule's)
  assert.equal(on([...f(10, 110, 0), ...f(130, 230, 120), ...f(250, 350, 240)]), true);
  assert.equal(on([...f(10, 110, 0), ...f(134, 234, 120)]), true, "4 s of jitter");
  // run f123d4fa2d61c5f5's slow job lagged by up to about 12.6 s from one start to another (cold starts)
  assert.equal(on([...f(10, 110, 0), ...f(142.6, 242.6, 120)]), true, "12.6 s");
  assert.equal(on([...f(10, 110, 0), ...f(150, 250, 120)]), true, "exactly 20 s");
  assert.equal(on([...f(10, 110, 0), ...f(150.01, 250, 120)]), false, "just over 20 s");
  assert.equal(on([...f(10, 110, 0), ...f(110, 210, 120)]), true, "early by 20 s");
  assert.equal(on([...f(10, 110, 0), ...f(109.9, 209.9, 120)]), false, "early by over 20 s");
  // one late start among on-time ones
  assert.equal(on([...f(10, 110, 0), ...f(130, 230, 120), ...f(300, 400, 240)]), false);
  // a start with no schedule time is not on time; no starts, or one, is vacuously on time
  assert.equal(on([...f(10, 110, undefined), ...f(130, 230, 120)]), false);
  assert.equal(on([]), true);
  assert.equal(on(f(10, 110, 0)), true);
  // a forced run is not judged: its schedule time is the next one, in the future
  const forced = [...f(10, 110, 0), ...f(50, 150, 500), ...f(130, 230, 120)];
  assert.equal(inFlightFacts(forced, [49], 60).startsOnTime, true);
});

test("cadence.in-flight-skip: a forced run in flight suppresses a natural occurrence too; one that starts inside it and inside no natural run diverges", () => {
  // production's 01:51:03 occurrence fell inside the forced run only and was skipped; a local run that starts it
  // (the forced run does not count as in flight) has a natural start inside a forced run and inside no natural one
  const runs = [
    [0, 100],
    [150, 250],
    [200, 300],
  ];
  const l = local({
    inflight: slowLocal(runs),
    manual: [{ name: "schedSlowV2", at: instant(T0 + 149_000) }],
  });
  const row = inflightRow(l);
  assert.equal(row.local.naturalStartsInFlight, 1);
  assert.equal(row.local.forcedStartsInFlight, false, "the forced run began inside no run");
  assert.equal(row.verdict, "DIVERGES");
  // the same frames at the facts level: the natural start at 200 is inside the forced run [150, 250] alone
  const f = (start, end) => [
    { phase: "start", at: start, scheduled: start },
    { phase: "end", at: end, scheduled: start },
  ];
  assert.equal(
    inFlightFacts([...f(0, 100), ...f(150, 250), ...f(200, 300)], [149], 60).naturalStartsInFlight,
    1,
  );
  // and a forced run that ended before the next natural start suppresses nothing
  assert.equal(
    inFlightFacts([...f(0, 100), ...f(150, 250), ...f(260, 360)], [149], 60).naturalStartsInFlight,
    0,
  );
});

// ---- Gen1: the message published to the job's topic (run f123d4fa2d61c5f5) ----

const msg = (fn, id, publishTime, over = {}) => ({
  function: fn,
  messageId: id,
  publishTime,
  atMs: Date.parse(publishTime) - T0,
  attributes: { scheduled: "true" },
  hasData: false,
  ...over,
});
/** A recording of the Gen1 handlers and of the messages pulled from their topics: ids and times agree. */
function productionWithMessages() {
  const p = production();
  // two schedOkV1 occurrences (the first two frames), one schedFailV1 pair, and a schedRetryV1 pair
  const frames = [
    prodV1("schedOkV1", 5000, "22257109111563910", "2026-10-05T08:41:02.5Z"),
    prodV1("schedRetryV1", 6000, "21339796619509982", "2026-10-05T08:41:03.993Z"),
    prodV1("schedRetryV1", 306_000, "21339949440159039", "2026-10-05T08:46:03.319Z"),
  ];
  return {
    ...p,
    frames: [...p.frames, ...frames],
    published: [
      msg("schedOkV1", "22257109111563910", "2026-10-05T08:41:02.5Z"),
      msg("schedOkV1", "22257109111563907", "2026-10-05T08:41:01.359Z"),
      msg("schedFailV1", "22256732696405721", "2026-10-05T08:42:50.384Z"),
      msg("schedRetryV1", "21339796619509982", "2026-10-05T08:41:03.993Z"),
      msg("schedRetryV1", "21339949440159039", "2026-10-05T08:46:03.319Z"),
    ],
  };
}
/** The local run: the same Gen1 frames, and the messages a pull subscription held on each topic. */
function localWithMessages(over = {}) {
  const l = local();
  const lines = [
    ...l.natural.lines,
    localV1("schedOkV1", instant(T0 + 5000), "27440000000000001", "2026-10-05T08:41:02.5Z"),
    localV1("schedRetryV1", instant(T0 + 6000), "27440000000000002", "2026-10-05T08:41:03.993Z"),
    localV1("schedRetryV1", instant(T0 + 306_000), "27440000000000003", "2026-10-05T08:46:03.319Z"),
  ];
  const message = (id, publishTime, extra = {}) => ({
    messageId: id,
    publishTime,
    attributes: { scheduled: "true" },
    ...extra,
  });
  const pulled = over.pulled ?? [
    {
      topic: jobId("schedOkV1"),
      status: 200,
      messages: [
        message("21060470636220959", "2026-10-05T08:41:01.359Z"),
        message("27440000000000001", "2026-10-05T08:41:02.5Z"),
      ],
    },
    {
      topic: jobId("schedFailV1"),
      status: 200,
      messages: [
        message("27203228007418468", "2026-10-05T08:42:50.384Z"),
        message("27777684328644704", "2026-10-05T08:47:05.447Z"),
      ],
    },
    {
      topic: jobId("schedRetryV1"),
      status: 200,
      messages: [
        message("27440000000000002", "2026-10-05T08:41:03.993Z"),
        message("27440000000000003", "2026-10-05T08:46:03.319Z"),
      ],
    },
  ];
  return { ...l, natural: { ...l.natural, lines: over.lines ?? lines, pulled } };
}
const PUBLISHED_ROWS = [
  "v1.published.topic",
  "v1.published.data",
  "v1.published.attributes",
  "v1.published.messageId",
  "v1.published.publishTime",
];

test("v1.published.messageId: every local handler needs exactly one publication", () => {
  const p = productionWithMessages();
  const base = localWithMessages();
  for (const messages of [
    base.natural.pulled[0].messages.slice(0, 1),
    [...base.natural.pulled[0].messages, base.natural.pulled[0].messages[0]],
  ]) {
    const pulled = base.natural.pulled.map((t, i) => (i === 0 ? { ...t, messages } : t));
    assert.equal(verdicts(p, localWithMessages({ pulled }))["v1.published.messageId"], "DIVERGES");
  }
});

test("v1.published.messageId: every local publication needs its handler", () => {
  const base = localWithMessages();
  const lines = base.natural.lines.filter((l) => l.value?.context?.eventId !== "27440000000000001");
  assert.equal(
    verdicts(productionWithMessages(), localWithMessages({ lines }))["v1.published.messageId"],
    "DIVERGES",
  );
});

test("the published-message rows exist only for a recording that pulled messages, and match a local run built like it", () => {
  assert.equal(
    Object.keys(verdicts(production(), local())).some((id) => id.startsWith("v1.published.")),
    false,
    "run 2's digest holds no messages",
  );
  const v = verdicts(productionWithMessages(), localWithMessages());
  for (const id of PUBLISHED_ROWS) assert.equal(v[id], "MATCH", id);
  assert.equal(v["v1.retry-declaration-no-retry"], "MATCH");
});

test("v1.published.topic: a topic the local broker has no subscription for, or that held nothing, diverges", () => {
  const p = productionWithMessages();
  for (const pulled of [
    // no such topic (the subscribe was refused)
    localWithMessages().natural.pulled.map((t) =>
      t.topic === jobId("schedRetryV1") ? { ...t, status: 404, messages: [] } : t,
    ),
    // the topic exists and holds nothing
    localWithMessages().natural.pulled.map((t) =>
      t.topic === jobId("schedRetryV1") ? { ...t, messages: [] } : t,
    ),
    // no pulled topic at all
    [],
  ]) {
    const v = verdicts(p, localWithMessages({ pulled }));
    assert.equal(v["v1.published.topic"], "DIVERGES");
  }
  // a topic named like the official emulator's (no region) is not the job's topic
  const official = localWithMessages().natural.pulled.map((t) => ({
    ...t,
    topic: t.topic.replace("-us-central1", ""),
  }));
  assert.equal(
    verdicts(p, localWithMessages({ pulled: official }))["v1.published.topic"],
    "DIVERGES",
  );
});

test("v1.published.data and .attributes: data on a message, or another attribute set, diverges", () => {
  const p = productionWithMessages();
  const change = (edit) =>
    localWithMessages().natural.pulled.map((t, i) =>
      i === 0 ? { ...t, messages: t.messages.map((m) => edit(m)) } : t,
    );
  const withData = verdicts(
    p,
    localWithMessages({ pulled: change((m) => ({ ...m, data: "YQ==" })) }),
  );
  assert.equal(withData["v1.published.data"], "DIVERGES");
  assert.equal(withData["v1.published.attributes"], "MATCH");
  for (const attributes of [{}, { scheduled: "false" }, { scheduled: "true", extra: "1" }]) {
    const v = verdicts(p, localWithMessages({ pulled: change((m) => ({ ...m, attributes })) }));
    assert.equal(v["v1.published.attributes"], "DIVERGES", JSON.stringify(attributes));
    assert.equal(v["v1.published.data"], "MATCH");
  }
});

test("v1.published.messageId: an id of another form, or one no handler frame carries, diverges", () => {
  const p = productionWithMessages();
  const one = (id) =>
    localWithMessages().natural.pulled.map((t, i) =>
      i === 0
        ? { ...t, messages: t.messages.map((m, j) => (j === 0 ? { ...m, messageId: id } : m)) }
        : t,
    );
  // another form: a counter (what the broker numbers an ordinary publish with)
  assert.equal(
    verdicts(p, localWithMessages({ pulled: one("1") }))["v1.published.messageId"],
    "DIVERGES",
  );
  // 17 digits, but the handler's context named another message
  assert.equal(
    verdicts(p, localWithMessages({ pulled: one("29999999999999999") }))["v1.published.messageId"],
    "DIVERGES",
  );
});

test("v1.published.publishTime: a publish time that is not the handler's context time diverges, at any digit", () => {
  const p = productionWithMessages();
  const shifted = (time) =>
    localWithMessages().natural.pulled.map((t, i) =>
      i === 2
        ? { ...t, messages: t.messages.map((m, j) => (j === 0 ? { ...m, publishTime: time } : m)) }
        : t,
    );
  for (const time of [
    "2026-10-05T08:41:03.994Z",
    "2026-10-05T08:41:04.993Z",
    "2026-10-05T08:41:03.993001Z",
  ])
    assert.equal(
      verdicts(p, localWithMessages({ pulled: shifted(time) }))["v1.published.publishTime"],
      "DIVERGES",
      time,
    );
  // the same instant written with more digits is the same time
  assert.equal(
    verdicts(p, localWithMessages({ pulled: shifted("2026-10-05T08:41:03.993000000Z") }))[
      "v1.published.publishTime"
    ],
    "MATCH",
  );
});

test("v1.retry-declaration-no-retry: a second attempt of a schedRetryV1 occurrence diverges, and so does a run without any", () => {
  const p = productionWithMessages();
  const l = localWithMessages();
  const dup = [
    ...l.natural.lines,
    localV1("schedRetryV1", instant(T0 + 12_000), "27440000000000002", "2026-10-05T08:41:03.993Z"),
  ];
  assert.equal(
    verdicts(p, localWithMessages({ lines: dup }))["v1.retry-declaration-no-retry"],
    "DIVERGES",
  );
  const without = l.natural.lines.filter((x) => x.value.handler !== "schedRetryV1");
  assert.equal(
    verdicts(p, localWithMessages({ lines: without, pulled: l.natural.pulled.slice(0, 2) }))[
      "v1.retry-declaration-no-retry"
    ],
    "DIVERGES",
  );
});

test("the emulator profile has no job topic: every published-message row diverges there, and the strict row is its own", () => {
  const table = compareProfiles(productionWithMessages(), localWithMessages(), {
    ...localWithMessages(),
    natural: {
      ...localWithMessages().natural,
      pulled: localWithMessages().natural.pulled.map((t) => ({ ...t, status: 404, messages: [] })),
    },
  });
  for (const id of PUBLISHED_ROWS) {
    const row = table.find((r) => r.id === id);
    assert.equal(row.strict.verdict, "MATCH", id);
    assert.equal(row.emulator.verdict, "DIVERGES", id);
  }
});

// ---- the published-message rows: the values they compare, and what they ignore ----

const rowOf = (p, l, id) => rows(p, l).find((r) => r.id === id);

test("the published-message rows compare the recorded values, not only equal ones", () => {
  const p = productionWithMessages();
  const l = localWithMessages();
  assert.deepEqual(rowOf(p, l, "v1.published.topic").production, [
    "schedFailV1",
    "schedOkV1",
    "schedRetryV1",
  ]);
  assert.deepEqual(rowOf(p, l, "v1.published.topic").local, [
    "schedFailV1",
    "schedOkV1",
    "schedRetryV1",
  ]);
  assert.deepEqual(rowOf(p, l, "v1.published.data").production, [false]);
  assert.deepEqual(rowOf(p, l, "v1.published.attributes").production, [{ scheduled: "true" }]);
  assert.deepEqual(rowOf(p, l, "v1.published.messageId").production, [
    { form: "<17 digits>", namedByAHandler: true },
  ]);
  assert.deepEqual(rowOf(p, l, "v1.published.messageId").local, [
    { form: "<17 digits>", namedByAHandler: true },
  ]);
  assert.deepEqual(rowOf(p, l, "v1.published.publishTime").production, [true]);
  assert.deepEqual(rowOf(p, l, "v1.published.publishTime").local, [true]);
  assert.deepEqual(rowOf(p, l, "v1.retry-declaration-no-retry").production, [1]);
  assert.deepEqual(rowOf(p, l, "v1.retry-declaration-no-retry").local, [1]);
});

test("a recording with a single pulled message still has the rows", () => {
  const p = productionWithMessages();
  const one = { ...p, published: [p.published[0]] };
  const base = localWithMessages();
  const l = localWithMessages({
    lines: base.natural.lines.filter(
      (l) => l.value?.generation !== 1 || l.value.context.eventId === "27440000000000001",
    ),
    pulled: [{ ...base.natural.pulled[0], messages: [base.natural.pulled[0].messages[1]] }],
  });
  const v = verdicts(one, l);
  for (const id of PUBLISHED_ROWS) assert.equal(v[id], "MATCH", id);
});

test("a topic that is not the job's, or that did not answer 200, adds nothing to what the local run published", () => {
  const p = productionWithMessages();
  const good = localWithMessages().natural.pulled;
  const message = {
    messageId: "27999999999999999",
    publishTime: "2026-10-05T08:41:09Z",
    attributes: { other: "1" },
    data: "YQ==",
  };
  const extra = [
    { topic: "firebase-schedule-schedOkV1", status: 200, messages: [message] }, // the official emulator's name
    {
      topic: jobId("schedFailV1").replace("schedFailV1", "ghost"),
      status: 404,
      messages: [message],
    }, // refused
  ];
  const v = verdicts(p, localWithMessages({ pulled: [...good, ...extra] }));
  for (const id of PUBLISHED_ROWS) assert.equal(v[id], "MATCH", id);
});

test("v1.published.messageId: an id of 16 or 18 digits is another form even when a handler reports it", () => {
  const p = productionWithMessages();
  for (const id of ["2744000000000001", "274400000000000001"]) {
    const base = localWithMessages();
    const lines = base.natural.lines.map((line) =>
      line.value.handler === "schedRetryV1" && line.value.context.eventId === "27440000000000002"
        ? { ...line, value: { ...line.value, context: { ...line.value.context, eventId: id } } }
        : line,
    );
    const pulled = base.natural.pulled.map((t) => ({
      ...t,
      messages: t.messages.map((m) =>
        m.messageId === "27440000000000002" ? { ...m, messageId: id } : m,
      ),
    }));
    assert.equal(
      verdicts(p, localWithMessages({ lines, pulled }))["v1.published.messageId"],
      "DIVERGES",
      id,
    );
  }
});

test("v1.retry-declaration-no-retry counts schedRetryV1 only: another Gen1 handler's repeated message id does not change it", () => {
  const p = productionWithMessages();
  const twice = {
    ...p,
    frames: [...p.frames, prodV1("schedOkV1", 9000, "22257109111563910", "2026-10-05T08:41:02.5Z")],
  };
  assert.deepEqual(
    rowOf(twice, localWithMessages(), "v1.retry-declaration-no-retry").production,
    [1],
  );
});

test("the recording has no schedRetryV1 frame: that row is not made", () => {
  const p = productionWithMessages();
  const without = { ...p, frames: p.frames.filter((f) => f.handler !== "schedRetryV1") };
  assert.equal(rowOf(without, localWithMessages(), "v1.retry-declaration-no-retry"), undefined);
});

// ---- run f123d4fa2d61c5f5's count-and-window and zero-backoff chains ----

/** The synthetic recording with the two chains run 3 added (frames of the REST jobs `count` and `zerobackoff`). */
function productionWithRun3Chains() {
  const p = production();
  let base = 40_000_000;
  const frames = [];
  for (const [key, offsets] of [
    ["count", [0, 4.65, 13.26, 23.88]],
    ["zerobackoff", [0, 5.62]],
  ]) {
    base += 1_000_000;
    for (const o of offsets)
      frames.push(
        prodV2(
          "schedRetryV2",
          base + Math.round(o * 1000),
          "2026-12-31T16:00:00-08:00",
          `fe-sd-0123456789abcdef-${key}`,
        ),
      );
  }
  return { ...p, frames: [...p.frames, ...frames] };
}
function localWithRun3Chains(over = {}) {
  const l = local();
  const chains = { retryCountWindow: [0, 4, 12, 22], retryZeroBackoff: [0, 5], ...over };
  const probe = [...l.probe.lines];
  let at = 5_000_000;
  for (const [name, offsets] of Object.entries(chains)) {
    at += 100_000;
    for (const o of offsets)
      probe.push({ at: instant(T0 + at + o * 1000), kind: "PROBE", value: { handler: name } });
  }
  return { ...l, probe: { ...l.probe, lines: probe } };
}

test("the count-and-window and zero-backoff chains match a local chain of the recorded attempts, and diverge from any other", () => {
  const p = productionWithRun3Chains();
  const v = verdicts(p, localWithRun3Chains());
  assert.equal(v["retry.retryCountWindow"], "MATCH");
  assert.equal(v["retry.retryZeroBackoff"], "MATCH");
  // the first-limit model stopped the count job at three attempts
  assert.equal(
    verdicts(p, localWithRun3Chains({ retryCountWindow: [0, 4, 12] }))["retry.retryCountWindow"],
    "DIVERGES",
  );
  // a fifth attempt
  assert.equal(
    verdicts(p, localWithRun3Chains({ retryCountWindow: [0, 4, 12, 22, 32] }))[
      "retry.retryCountWindow"
    ],
    "DIVERGES",
  );
  // zero backoff as a hot loop (a retry every clock move), or no retry at all
  assert.equal(
    verdicts(p, localWithRun3Chains({ retryZeroBackoff: [0, 1, 2, 3, 4, 5] }))[
      "retry.retryZeroBackoff"
    ],
    "DIVERGES",
  );
  assert.equal(
    verdicts(p, localWithRun3Chains({ retryZeroBackoff: [0] }))["retry.retryZeroBackoff"],
    "DIVERGES",
  );
  // a gap the recording does not allow: the second attempt of the zero-backoff chain 9 s after the first
  assert.equal(
    verdicts(p, localWithRun3Chains({ retryZeroBackoff: [0, 9] }))["retry.retryZeroBackoff"],
    "DIVERGES",
  );
  // a local run without the probe functions has no chain: it diverges, it does not match vacuously
  assert.equal(verdicts(p, local())["retry.retryCountWindow"], "DIVERGES");
});

test("the run 3 chain rows exist only for a recording that has those chains", () => {
  const v = verdicts(production(), local());
  assert.equal("retry.retryCountWindow" in v, false);
  assert.equal("retry.retryZeroBackoff" in v, false);
  assert.deepEqual(
    productionChains(productionWithRun3Chains()).retryCountWindow,
    [0, 4.65, 13.26, 23.88],
  );
  assert.deepEqual(productionChains(productionWithRun3Chains()).retryZeroBackoff, [0, 5.62]);
});

// ---- run ecef353d18975246's double chains ----

const cumulative = (gaps) =>
  gaps.reduce((offsets, gap) => [...offsets, +(offsets.at(-1) + gap).toFixed(2)], [0]);
const DOUBLES = {
  double0: cumulative([3.69, 6.53, 12.67, 24.52, 48.57]),
  double1: cumulative([4.64, 8.63, 10.91, 12.63, 14.69]),
  double3: cumulative([2.54, 4.64, 8.54, 16.48, 18.62]),
};
function productionWithDoubles() {
  const p = production();
  let base = 60_000_000;
  const frames = [];
  for (const [key, offsets] of Object.entries(DOUBLES)) {
    base += 1_000_000;
    for (const o of offsets)
      frames.push(
        prodV2(
          "schedRetryV2",
          base + Math.round(o * 1000),
          "2026-12-31T16:00:00-08:00",
          `fe-sd-0123456789abcdef-${key}`,
        ),
      );
  }
  return { ...p, frames: [...p.frames, ...frames] };
}
function localWithDoubles(over = {}) {
  const l = local();
  const chains = {
    retryDouble0: [0, 3, 9, 21, 45, 93],
    retryDouble1: [0, 4, 12, 22, 34, 48],
    retryDouble3: [0, 2, 6, 14, 30, 48],
    ...over,
  };
  const probe = [...l.probe.lines];
  let at = 7_000_000;
  for (const [name, offsets] of Object.entries(chains)) {
    at += 100_000;
    for (const o of offsets)
      probe.push({ at: instant(T0 + at + o * 1000), kind: "PROBE", value: { handler: name } });
  }
  return { ...l, probe: { ...l.probe, lines: probe } };
}

test("the double chains match the local chains of the recorded gaps, and diverge from the old linear step", () => {
  const p = productionWithDoubles();
  const v = verdicts(p, localWithDoubles());
  for (const id of ["retry.retryDouble0", "retry.retryDouble1", "retry.retryDouble3"])
    assert.equal(v[id], "MATCH", id);
  // the documented step (min * 2^doublings after the doublings) instead of 2 s
  assert.equal(
    verdicts(p, localWithDoubles({ retryDouble1: [0, 4, 12, 28, 52, 84] }))["retry.retryDouble1"],
    "DIVERGES",
  );
  assert.equal(
    verdicts(p, localWithDoubles({ retryDouble3: [0, 2, 6, 14, 30, 62] }))["retry.retryDouble3"],
    "DIVERGES",
  );
  // a zero doubling count taken as zero doublings (the step from the first gap on) instead of the stored 5
  assert.equal(
    verdicts(p, localWithDoubles({ retryDouble0: [0, 3, 6, 9, 12, 15] }))["retry.retryDouble0"],
    "DIVERGES",
  );
  // a chain of another length
  assert.equal(
    verdicts(p, localWithDoubles({ retryDouble1: [0, 4, 12, 22, 34] }))["retry.retryDouble1"],
    "DIVERGES",
  );
  // no chain locally: not a vacuous match
  assert.equal(verdicts(p, local())["retry.retryDouble0"], "DIVERGES");
});

test("the double rows exist only for a recording that has those chains", () => {
  const v = verdicts(production(), local());
  for (const id of ["retry.retryDouble0", "retry.retryDouble1", "retry.retryDouble3"])
    assert.equal(id in v, false, id);
  const chains = productionChains(productionWithDoubles());
  assert.deepEqual(chains.retryDouble1, DOUBLES.double1);
  assert.deepEqual(chains.retryDouble3, DOUBLES.double3);
  assert.deepEqual(chains.retryDouble0, DOUBLES.double0);
});

test("another recording's extra chains join the rows when the main recording has none of its own", () => {
  const main = production();
  const also = productionWithDoubles();
  const v = Object.fromEntries(
    rows(main, localWithDoubles(), [also]).map((r) => [r.id, r.verdict]),
  );
  for (const id of ["retry.retryDouble0", "retry.retryDouble1", "retry.retryDouble3"])
    assert.equal(v[id], "MATCH", id);
  // the other recording's deployed job and cadence are not joined: the main recording's rows are unchanged
  const without = Object.fromEntries(rows(main, localWithDoubles()).map((r) => [r.id, r.verdict]));
  for (const [id, verdict] of Object.entries(without)) assert.equal(v[id], verdict, id);
  // a chain the main recording has is not replaced by the other's
  const both = productionWithRun3Chains();
  const rowsBoth = rows(both, localWithRun3Chains(), [{ ...also, frames: [...also.frames] }]);
  assert.equal(rowsBoth.find((r) => r.id === "retry.retryCountWindow").verdict, "MATCH");
  // compareProfiles passes them on
  const table = compareProfiles(main, localWithDoubles(), localWithDoubles(), [also]);
  assert.equal(table.find((r) => r.id === "retry.retryDouble1").strict.verdict, "MATCH");
});

test("another recording's chain never replaces the main recording's own, and its non-optional chains are not joined", () => {
  const main = productionWithRun3Chains();
  // a second recording with a different `count` chain (a gap of 20 s: it would diverge) and its own deployed retry job
  const frame = (job, at) => prodV2("schedRetryV2", at, "2026-12-31T16:00:00-08:00", job);
  const other = {
    ...production(),
    frames: [
      ...production().frames,
      ...[0, 20_000].map((o) => frame("fe-sd-fedcba9876543210-count", 80_000_000 + o)),
      ...[0, 90_000].map((o) =>
        frame("firebase-schedule-schedRetryV2-us-central1", 90_000_000 + o),
      ),
    ],
  };
  const withOther = Object.fromEntries(
    rows(main, localWithRun3Chains(), [other]).map((r) => [r.id, r.verdict]),
  );
  const alone = Object.fromEntries(rows(main, localWithRun3Chains()).map((r) => [r.id, r.verdict]));
  assert.deepEqual(withOther, alone);
  assert.equal(withOther["retry.retryCountWindow"], "MATCH");
});
