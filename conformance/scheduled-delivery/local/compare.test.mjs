// The comparison rows against synthetic recordings and local timelines built to match, then broken one field at a
// time: each row must say MATCH for the matching pair and DIVERGES for its own near miss, and nothing else.
import assert from "node:assert/strict";
import test from "node:test";
import { FORM, compareProfiles, localChains, productionChains, rows } from "./compare.mjs";
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
