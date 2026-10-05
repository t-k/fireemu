// The reading of the third delivery run (packet r6.2) from its public digest: the answers of the extra REST jobs, the
// retry chains read against the retryConfig each job's own create answer carries (condition C4), the count/window
// readings with the same run's `duration` chain as the control, the zero-backoff chain, the Gen1 retry probe.
import assert from "node:assert/strict";
import test from "node:test";
import { analyzeRun3, chainsOf } from "./run3-analysis.mjs";

const RUN = "0123456789abcdef";
const NANOS = "retryConfig.max_retry_duration.nanos cannot be set: invalid argument";
const frame = (key, atS, scheduleTime = "2027-01-01T00:00:00Z") => ({
  handler: "schedRetryV2",
  generation: 2,
  at: Math.round(atS * 1000),
  headers: {
    "x-cloudscheduler-jobname": `fe-sd-${RUN}-${key}`,
    "x-cloudscheduler-scheduletime": scheduleTime,
  },
});
const chain = (key, start, offsets) => offsets.map((o) => frame(key, start + o));
const v1 = (id, atS) => ({
  handler: "schedRetryV1",
  generation: 1,
  at: Math.round(atS * 1000),
  context: { eventId: id },
});
const effective = (over = {}) => ({
  maxRetryDuration: "0s",
  minBackoffDuration: "5s",
  maxBackoffDuration: "3600s",
  maxDoublings: 5,
  ...over,
});
const DURATION = [0, 4.6, 13.2, 23.7];
function digest(over = {}) {
  const frames = [
    ...chain("duration", 100, DURATION),
    ...chain("duration", 700, [0, 4.6, 13.2, 23.9]),
    ...(over.count ?? chain("count", 200, [0, 4.6, 13.2])),
    ...(over.count2 ?? chain("count", 800, [0, 4.6, 13.2])),
    ...(over.zero ?? chain("zerobackoff", 300, [0, 0.4, 0.8, 1.2, 1.6])),
    ...(over.v1 ?? [v1("1", 10), v1("2", 20), v1("3", 600)]),
  ];
  return {
    run: { id: RUN },
    frames,
    attempts: {
      "firebase-schedule-schedRetryV1-us-central1": [
        { kind: "AttemptStarted", at: 10_000 },
        { kind: "AttemptFinished", at: 10_900, status: null },
        { kind: "AttemptStarted", at: 20_000 },
        { kind: "AttemptFinished", at: 20_800, status: null },
        { kind: "AttemptStarted", at: 600_000 },
        { kind: "AttemptFinished", at: 600_800, status: null },
      ],
    },
    extraJobs: {
      zero: { status: 200, message: null, requested: { retryCount: 0 }, effective: effective() },
      duration: {
        status: 200,
        message: null,
        requested: { maxRetryDuration: "30s", minBackoffDuration: "4s", maxBackoffDuration: "10s" },
        effective: effective({
          maxRetryDuration: "30s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        }),
      },
      count: {
        status: 200,
        message: null,
        requested: {
          retryCount: 3,
          maxRetryDuration: "20s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        },
        effective: effective({
          retryCount: 3,
          maxRetryDuration: "20s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        }),
      },
      fraction: {
        status: 400,
        message: NANOS,
        requested: { maxRetryDuration: "20.5s" },
        effective: null,
      },
      zerobackoff: {
        status: 200,
        message: null,
        requested: { maxRetryDuration: "10s", minBackoffDuration: "0s", maxBackoffDuration: "0s" },
        effective: effective({
          maxRetryDuration: "10s",
          minBackoffDuration: "0s",
          maxBackoffDuration: "0s",
        }),
      },
      retry5: {
        status: 200,
        message: null,
        requested: { retryCount: 5 },
        effective: effective({ retryCount: 5 }),
      },
      ...over.extraJobs,
    },
  };
}

test("chains: a job's attempts are split where the gap is over two and a half minutes, and offsets are from each chain's first attempt", () => {
  const chains = chainsOf(digest());
  assert.deepEqual(chains.duration, [DURATION, [0, 4.6, 13.2, 23.9]]);
  assert.deepEqual(chains.count, [
    [0, 4.6, 13.2],
    [0, 4.6, 13.2],
  ]);
  assert.equal(chains.zerobackoff.length, 1);
  // the long gaps inside one chain (the 80 s of run 2's retryCount 5 chain) do not split it, a gap of two and a half minutes does
  const long = digest({
    zero: [
      ...chain("zerobackoff", 300, [0, 5.6, 16.3, 36.8, 77.3, 157.8]),
      ...chain("zerobackoff", 900, [0]),
    ],
  });
  assert.deepEqual(chainsOf(long).zerobackoff, [[0, 5.6, 16.3, 36.8, 77.3, 157.8], [0]]);
  const edge = digest({
    zero: [...chain("zerobackoff", 300, [0]), ...chain("zerobackoff", 450, [0])],
  });
  assert.equal(chainsOf(edge).zerobackoff.length, 1, "exactly 150 s apart is one chain");
  assert.equal(
    chainsOf(
      digest({ zero: [...chain("zerobackoff", 300, [0]), ...chain("zerobackoff", 450.01, [0])] }),
    ).zerobackoff.length,
    2,
  );
  // two chains of one job at the same schedule time (the forced run of each pass) are still two chains
  assert.equal(chainsOf(digest()).duration.length, 2);
  // a frame of another handler or of a deployed job is not a chain of an extra job
  const d = digest();
  d.frames.push({
    handler: "schedOkV2",
    generation: 2,
    at: 5,
    headers: { "x-cloudscheduler-jobname": "firebase-schedule-schedOkV2-us-central1" },
  });
  assert.deepEqual(Object.keys(chainsOf(d)).toSorted(), ["count", "duration", "zerobackoff"]);
});

test("the fraction answer is the second observation of the nanos refusal only with exactly that text", () => {
  assert.deepEqual(analyzeRun3(digest()).fraction, {
    status: 400,
    text: NANOS,
    secondObservation: true,
  });
  for (const [status, message] of [
    [400, NANOS + "."],
    [400, "retryConfig.max_retry_duration.nanos cannot be set"],
    [400, "something else"],
    [200, null],
  ]) {
    const d = digest({
      extraJobs: { fraction: { status, message, requested: {}, effective: null } },
    });
    const f = analyzeRun3(d).fraction;
    assert.equal(f.secondObservation, false, `${status} ${message}`);
    assert.equal(f.status, status);
  }
});

test("count and window: three attempts is the first limit, four is both limits used up, anything else is new data", () => {
  const reading = (offsets, offsets2 = offsets) =>
    analyzeRun3(
      digest({ count: chain("count", 200, offsets), count2: chain("count", 800, offsets2) }),
    ).count;
  // the control (the same run's duration chain) reproduces 0, 4.6, 13.2, 23.7: the window of 20 s allows three
  assert.equal(reading([0, 4.6, 13.2]).reading, "first-limit (window binds)");
  assert.equal(
    reading([0, 4.6, 13.2, 23.7]).reading,
    "both-limits (retries continue until count and window are used up)",
  );
  assert.equal(reading([0, 4.6]).reading, "other");
  assert.equal(reading([0, 4.6, 13.2, 23.7, 33.0]).reading, "other");
  assert.equal(
    reading([0, 4.6, 13.2], [0, 4.6, 13.2, 23.9]).reading,
    "other",
    "the two passes disagree",
  );
  const r = reading([0, 4.6, 13.2]);
  assert.deepEqual(r.predicted, { firstLimit: 3, bothLimits: 4 });
  assert.deepEqual(r.attempts, [3, 3]);
  assert.equal(r.controlReproduced, true);
});

test("count and window: the retryConfig read is the one the create answer carries, not the request", () => {
  // the answer says a window of 30 s (as if 20 s were rounded up): three attempts is then neither limit
  const d = digest({
    extraJobs: {
      count: {
        status: 200,
        message: null,
        requested: {
          retryCount: 3,
          maxRetryDuration: "20s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        },
        effective: effective({
          retryCount: 3,
          maxRetryDuration: "30s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        }),
      },
    },
  });
  const r = analyzeRun3(d).count;
  assert.equal(r.normalised, true);
  assert.equal(r.effective.maxRetryDuration, "30s");
  assert.deepEqual(r.predicted, { firstLimit: 4, bothLimits: 4 });
  // a missing retryCount in the answer is zero (proto3 default), as `zero`'s answer shows
  const zero = digest({
    extraJobs: {
      count: {
        status: 200,
        message: null,
        requested: {},
        effective: effective({
          maxRetryDuration: "20s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        }),
      },
    },
  });
  assert.equal(analyzeRun3(zero).count.effective.retryCount, 0);
});

test("count and window: a control chain that does not reproduce makes the reading inconclusive", () => {
  const d = digest();
  d.frames = d.frames.filter(
    (f) => !f.headers?.["x-cloudscheduler-jobname"]?.endsWith("-duration"),
  );
  d.frames.push(...chain("duration", 100, [0, 5, 30]));
  const r = analyzeRun3(d).count;
  assert.equal(r.controlReproduced, false);
  assert.equal(r.reading, "inconclusive (the control chain did not reproduce)");
  // no duration chain at all
  const none = digest();
  none.frames = none.frames.filter(
    (f) => !f.headers?.["x-cloudscheduler-jobname"]?.endsWith("-duration"),
  );
  assert.equal(
    analyzeRun3(none).count.reading,
    "inconclusive (the control chain did not reproduce)",
  );
});

test("count and window: a refused or missing count job has no reading", () => {
  const refused = digest({
    extraJobs: { count: { status: 400, message: "new text", requested: {}, effective: null } },
  });
  assert.deepEqual(analyzeRun3(refused).count, {
    status: 400,
    text: "new text",
    reading: "refused",
  });
  const missing = digest();
  delete missing.extraJobs.count;
  assert.equal(analyzeRun3(missing).count.reading, "absent");
});

test("zero backoff: the effective config says if 0s was kept or normalised, and the chain is read against it", () => {
  const kept = analyzeRun3(digest()).zerobackoff;
  assert.equal(kept.normalised, false);
  assert.equal(kept.attempts.length, 1);
  assert.deepEqual(kept.attempts, [5]);
  assert.equal(kept.minGapSeconds, 0.4);
  assert.equal(kept.lastOffsetSeconds, 1.6);
  assert.equal(kept.withinWindow, true);
  // normalised to the default 5 s: said so, and the chain is judged against 5 s
  const normalised = digest({
    extraJobs: {
      zerobackoff: {
        status: 200,
        message: null,
        requested: { maxRetryDuration: "10s", minBackoffDuration: "0s", maxBackoffDuration: "0s" },
        effective: effective({ maxRetryDuration: "10s" }),
      },
    },
    zero: chain("zerobackoff", 300, [0, 5.4]),
  });
  const n = analyzeRun3(normalised).zerobackoff;
  assert.equal(n.normalised, true);
  assert.deepEqual(n.normalisedTo, { minBackoffDuration: "5s", maxBackoffDuration: "3600s" });
  assert.equal(n.minGapSeconds, 5.4);
  // a chain past its window is flagged
  const long = analyzeRun3(
    digest({ zero: chain("zerobackoff", 300, [0, 3, 6, 9, 12, 15]) }),
  ).zerobackoff;
  assert.equal(long.withinWindow, false);
  // a refusal is a recorded answer with its text
  const refused = analyzeRun3(
    digest({
      extraJobs: {
        zerobackoff: { status: 400, message: "positive please", requested: {}, effective: null },
      },
    }),
  ).zerobackoff;
  assert.deepEqual(refused, {
    status: 400,
    text: "positive please",
    normalised: null,
    attempts: [],
  });
});

test("the Gen1 probe: one invocation per message id is the expected shape, a repeated id is new data", () => {
  const ok = analyzeRun3(digest()).gen1Probe;
  assert.deepEqual(ok, {
    invocations: 3,
    messageIds: 3,
    maxPerMessageId: 1,
    repeatedMessage: false,
    schedulerAttempts: 3,
    finishedWithError: 0,
  });
  const repeated = analyzeRun3(digest({ v1: [v1("1", 10), v1("1", 40), v1("2", 600)] })).gen1Probe;
  assert.equal(repeated.repeatedMessage, true);
  assert.equal(repeated.maxPerMessageId, 2);
  // an attempt that finished with an error status is counted
  const d = digest();
  d.attempts["firebase-schedule-schedRetryV1-us-central1"][1].status = "INTERNAL";
  assert.equal(analyzeRun3(d).gen1Probe.finishedWithError, 1);
  // no frames of the probe: said so, not zero-by-default
  assert.deepEqual(analyzeRun3(digest({ v1: [] })).gen1Probe, {
    invocations: 0,
    messageIds: 0,
    maxPerMessageId: 0,
    repeatedMessage: false,
    schedulerAttempts: 3,
    finishedWithError: 0,
  });
});

test("retry5 and the control answers are reported with their status", () => {
  const a = analyzeRun3(digest());
  assert.equal(a.retry5.status, 200);
  assert.deepEqual(a.retry5.expected, "2xx");
  assert.equal(a.retry5.contradictsRun2, false);
  const d = digest({
    extraJobs: { retry5: { status: 400, message: "x", requested: {}, effective: null } },
  });
  assert.equal(analyzeRun3(d).retry5.contradictsRun2, true);
});
