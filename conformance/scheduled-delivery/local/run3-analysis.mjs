// The reading of the third SCHEDULED-FUNCTIONS delivery run (packet r6.2) from its public digest (see
// `extract-production.mjs`; the digest's `extraJobs` holds, per extra REST job, what was asked and the retryConfig the
// create answer carries). Pure: it judges nothing about the run's safety, it says what the recording shows.
//
// - The retry chains of the extra jobs are read against the retryConfig in each job's own create answer, not against the
//   request (a zero or an omitted value may be stored as a default): condition C4 of the r6.2 review.
// - `-count` (retryCount 3, window 20 s, backoff 4 s to 10 s) is read with the same run's `-duration` chain (window 30 s,
//   same backoff) as the control: it must reproduce about 0, 4.6, 13.2 and 23.7 s, as both chains of run
//   156715222b86ea44 did. Three attempts then means the chain stops at the first limit reached (the window), four that
//   retries continue until both limits are used up; anything else is new data.
export const NANOS_REFUSAL = "retryConfig.max_retry_duration.nanos cannot be set: invalid argument";
/** Run 156715222b86ea44's `duration` chain (min 4 s, max 10 s): the gaps are about 4, 8 and 10 s, then held at 10 s. */
const RECORDED_OFFSETS = [0, 4.6, 13.2, 23.7, 34.2, 44.7];
const CONTROL_TOLERANCE = 1;
// the longest gap inside a chain is the 80 s of the retryCount 5 chain (run 156715222b86ea44); the passes are minutes apart
const CHAIN_GAP_SECONDS = 150;
const round2 = (n) => Math.round(n * 100) / 100;
const seconds = (duration) => (duration == null ? 0 : Number.parseFloat(String(duration)));

/** The attempt offsets (seconds from each chain's first attempt) of each extra REST job, one list per chain. */
export function chainsOf(digest) {
  const times = new Map();
  for (const f of digest.frames ?? []) {
    if (f.handler !== "schedRetryV2") continue;
    const job = /^fe-sd-[0-9a-f]{16}-(.+)$/.exec(
      f.headers?.["x-cloudscheduler-jobname"] ?? "",
    )?.[1];
    if (!job) continue;
    if (!times.has(job)) times.set(job, []);
    times.get(job).push(f.at / 1000);
  }
  const chains = {};
  for (const [job, list] of times) {
    const sorted = list.toSorted((a, b) => a - b);
    const groups = [];
    for (const t of sorted) {
      const last = groups.at(-1);
      if (last && t - last.at(-1) <= CHAIN_GAP_SECONDS) last.push(t);
      else groups.push([t]);
    }
    chains[job] = groups.map((g) => g.map((t) => round2(t - g[0])));
  }
  return chains;
}

const effectiveOf = (job) =>
  job?.effective ? { ...job.effective, retryCount: job.effective.retryCount ?? 0 } : null;

function controlOf(chains) {
  const control = chains.duration ?? [];
  const reproduced =
    control.length > 0 &&
    control.every(
      (offsets) =>
        offsets.length === 4 &&
        offsets.every((o, i) => Math.abs(o - RECORDED_OFFSETS[i]) <= CONTROL_TOLERANCE),
    );
  return { reproduced, offsets: reproduced ? control[0] : RECORDED_OFFSETS };
}

function countReading(digest, chains) {
  const job = digest.extraJobs?.count;
  if (!job) return { reading: "absent" };
  if (job.status !== 200) return { status: job.status, text: job.message, reading: "refused" };
  const effective = effectiveOf(job);
  const asked = { retryCount: 0, ...job.requested };
  const normalised = [
    "retryCount",
    "maxRetryDuration",
    "minBackoffDuration",
    "maxBackoffDuration",
  ].some((k) => String(asked[k] ?? "") !== String(effective[k] ?? ""));
  const control = controlOf(chains);
  const window = seconds(effective.maxRetryDuration);
  const byCount = effective.retryCount + 1;
  const byWindow =
    window > 0 ? control.offsets.filter((o) => o <= window).length : Number.POSITIVE_INFINITY;
  const predicted = {
    firstLimit: Math.min(byCount, byWindow),
    bothLimits: byWindow === Infinity ? byCount : Math.max(byCount, byWindow),
  };
  const attempts = (chains.count ?? []).map((offsets) => offsets.length);
  let reading;
  if (!control.reproduced) reading = "inconclusive (the control chain did not reproduce)";
  else if (attempts.length === 0) reading = "no chain recorded";
  else if (!attempts.every((n) => n === attempts[0])) reading = "other";
  else if (predicted.firstLimit === predicted.bothLimits && attempts[0] === predicted.firstLimit)
    reading = "limits coincide (first-limit and both-limits agree)";
  else if (attempts[0] === predicted.firstLimit) reading = "first-limit (window binds)";
  else if (attempts[0] === predicted.bothLimits)
    reading = "both-limits (retries continue until count and window are used up)";
  else reading = "other";
  return {
    status: 200,
    effective,
    normalised,
    controlReproduced: control.reproduced,
    predicted,
    attempts,
    chains: chains.count ?? [],
    reading,
  };
}

function zeroBackoffReading(digest, chains) {
  const job = digest.extraJobs?.zerobackoff;
  if (!job) return { status: null, text: null, normalised: null, attempts: [] };
  if (job.status !== 200)
    return { status: job.status, text: job.message, normalised: null, attempts: [] };
  const effective = effectiveOf(job);
  const normalised = effective.minBackoffDuration !== "0s" || effective.maxBackoffDuration !== "0s";
  const list = chains.zerobackoff ?? [];
  const gaps = list.flatMap((offsets) => offsets.slice(1).map((o, i) => round2(o - offsets[i])));
  const last = list.length ? Math.max(...list.map((o) => o.at(-1))) : null;
  const window = seconds(effective.maxRetryDuration);
  return {
    status: 200,
    effective,
    normalised,
    ...(normalised
      ? {
          normalisedTo: {
            minBackoffDuration: effective.minBackoffDuration,
            maxBackoffDuration: effective.maxBackoffDuration,
          },
        }
      : {}),
    attempts: list.map((offsets) => offsets.length),
    minGapSeconds: gaps.length ? Math.min(...gaps) : null,
    lastOffsetSeconds: last,
    withinWindow: last === null || window === 0 ? null : last <= window + 1,
    chains: list,
  };
}

function gen1Probe(digest) {
  const frames = (digest.frames ?? []).filter((f) => f.handler === "schedRetryV1");
  const perId = new Map();
  for (const f of frames) perId.set(f.context?.eventId, (perId.get(f.context?.eventId) ?? 0) + 1);
  const entries = digest.attempts?.["firebase-schedule-schedRetryV1-us-central1"] ?? [];
  const max = perId.size ? Math.max(...perId.values()) : 0;
  return {
    invocations: frames.length,
    messageIds: perId.size,
    maxPerMessageId: max,
    repeatedMessage: max > 1,
    schedulerAttempts: entries.filter((e) => e.kind === "AttemptStarted").length,
    finishedWithError: entries.filter((e) => e.kind === "AttemptFinished" && e.status != null)
      .length,
  };
}

/** What run 3 shows, one section per question the packet asked. */
export function analyzeRun3(digest) {
  const chains = chainsOf(digest);
  const fraction = digest.extraJobs?.fraction;
  const retry5 = digest.extraJobs?.retry5;
  return {
    fraction: {
      status: fraction?.status ?? null,
      text: fraction?.message ?? null,
      secondObservation: fraction?.status === 400 && fraction.message === NANOS_REFUSAL,
    },
    retry5: {
      status: retry5?.status ?? null,
      expected: "2xx",
      contradictsRun2: retry5?.status !== 200,
    },
    chains,
    count: countReading(digest, chains),
    zerobackoff: zeroBackoffReading(digest, chains),
    gen1Probe: gen1Probe(digest),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync } = await import("node:fs");
  console.log(
    JSON.stringify(analyzeRun3(JSON.parse(readFileSync(process.argv[2], "utf8"))), null, 1),
  );
}
