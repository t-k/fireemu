// Case table and static bounds of the signed XML PUT observation (owner ledger 2215).
//
// One signed URL per case: the Admin SDK's `File#getSignedUrl({version: "v4", action: "write"})`
// signs it, a PUT sends it, and a JSON API read checks whether an object appeared. Every case runs
// in two recordings under `<prefix>rec1/` and `<prefix>rec2/`.

export const PROJECT = "fireemu-oracle-query";
export const BUCKET = "fireemu-oracle-query.firebasestorage.app";
export const SIGNER = "firebase-adminsdk-fbsvc@fireemu-oracle-query.iam.gserviceaccount.com";
export const PREFIX_ROOT = "storage-signed-put";
export const RECORDINGS = 2;

/** The range header value of the assigned flow, and the narrow range of the size cases. */
export const ASSIGNED_RANGE = "0,10485760";
export const NARROW_RANGE = "5,8";
export const RANGE_HEADER = "x-goog-content-length-range";
export const PNG_MAGIC = Uint8Array.from([137, 80, 78, 71]);

/** Request caps: the main phase (setup and both recordings) and the whole run with cleanup. */
export const MAIN_CAP = 130;
export const TOTAL_CAP = 200;
/** A2 read-back (a separate command, at least 10 minutes after the last request). */
export const READBACK_CAP = 40;
/** Per-request timeout, from the 30000 ms of the existing Storage recorders (no signed-PUT latency is recorded yet). */
export const REQUEST_TIMEOUT_MS = 30_000;
/** The shortest lifetime the SDK can sign is 1 s; the PUT waits this long past it. */
export const EXPIRY_MARGIN_MS = 2500;
/** The local clock may differ from the server's by at most this much. */
export const MAX_CLOCK_SKEW_MS = 5000;
export const ESTIMATED_USD = 0.05;

/**
 * A case: what is signed, what is sent. `signed.contentType` / `signed.range` of null leave the
 * header out of the signature; `sent.*` of null leaves it out of the request. `mutate` edits the
 * signed URL before it is sent. `expect` is the planning expectation (used for the static
 * bound), never a verdict.
 */
function bytes(length) {
  return Uint8Array.from({ length }, (_, i) => 65 + (i % 26));
}

const png = (range, sent = {}) => ({
  signed: { contentType: "image/png", range },
  sent: { contentType: "image/png", range, ...sent },
});

export const CASES = [
  {
    id: "ok",
    control: true,
    expect: "create",
    followUps: "full",
    ...png(ASSIGNED_RANGE),
    body: PNG_MAGIC,
  },
  {
    id: "ok-origin",
    expect: "create",
    preflight: true,
    ...png(ASSIGNED_RANGE, { origin: "http://localhost:3000" }),
    body: PNG_MAGIC,
  },
  {
    id: "wrong-content-type",
    expect: "refuse",
    ...png(ASSIGNED_RANGE, { contentType: "text/plain" }),
    body: PNG_MAGIC,
  },
  {
    id: "missing-content-type",
    expect: "refuse",
    ...png(ASSIGNED_RANGE, { contentType: null }),
    body: PNG_MAGIC,
  },
  { id: "over-range", expect: "refuse", ...png(NARROW_RANGE), body: bytes(9) },
  { id: "under-range", expect: "refuse", ...png(NARROW_RANGE), body: bytes(4) },
  { id: "range-min-ok", expect: "create", ...png(NARROW_RANGE), body: bytes(5) },
  { id: "range-max-ok", expect: "create", ...png(NARROW_RANGE), body: bytes(8) },
  {
    id: "range-header-missing",
    expect: "refuse",
    ...png(ASSIGNED_RANGE, { range: null }),
    body: PNG_MAGIC,
  },
  {
    id: "range-header-mismatch",
    expect: "refuse",
    ...png(ASSIGNED_RANGE, { range: "0,3" }),
    body: bytes(2),
  },
  {
    id: "range-header-unsigned",
    expect: "refuse",
    signed: { contentType: "image/png", range: null },
    sent: { contentType: "image/png", range: "0,10" },
    body: PNG_MAGIC,
  },
  {
    id: "no-range",
    expect: "create",
    signed: { contentType: "image/png", range: null },
    sent: { contentType: "image/png", range: null },
    body: PNG_MAGIC,
  },
  {
    id: "tampered-signature",
    expect: "refuse",
    mutate: "tamper",
    ...png(ASSIGNED_RANGE),
    body: PNG_MAGIC,
  },
  {
    id: "signature-missing",
    expect: "refuse",
    mutate: "drop-signature",
    ...png(ASSIGNED_RANGE),
    body: PNG_MAGIC,
  },
  { id: "expired", expect: "refuse", short: true, ...png(ASSIGNED_RANGE), body: PNG_MAGIC },
  {
    id: "other-object",
    expect: "refuse",
    sentObject: "other-sent.png",
    ...png(ASSIGNED_RANGE),
    body: PNG_MAGIC,
  },
];

export function newRunId(random = () => Math.random()) {
  let id = "";
  while (id.length < 8) id += Math.floor(random() * 16).toString(16);
  return `sp-${id}`;
}

export const runPrefix = (runId) => `${PREFIX_ROOT}/${runId}/`;
export const recordingPrefix = (runId, recording) => `${runPrefix(runId)}rec${recording}/`;

/** Names a case can write to in one recording (signed name, and the name actually sent). */
export function caseObjects(testCase) {
  const signed = `${testCase.object ?? testCase.id}.png`;
  return { signed, sent: testCase.sentObject ?? signed };
}

/** Every object name the plan can create, for cleanup and the guard. */
export function plannedNames(runId, cases = CASES, recordings = RECORDINGS) {
  const names = new Set();
  for (let recording = 1; recording <= recordings; recording += 1) {
    for (const testCase of cases) {
      const { sent } = caseObjects(testCase);
      names.add(`${recordingPrefix(runId, recording)}${sent}`);
    }
  }
  return [...names];
}

/**
 * Worst-case request counts. Setup: bucket read, signer read, empty-prefix list. Per case: one
 * signBlob, one PUT, one follow-up read (the positive control adds a media read; `exists()` is the metadata read), the
 * preflight case adds one OPTIONS. Cleanup, when every planned name exists: one list, a DELETE and
 * a read-back per name, a final list.
 */
export function staticBounds(cases = CASES, recordings = RECORDINGS) {
  const setup = 3;
  let perRecording = 0;
  for (const testCase of cases) {
    perRecording += 3;
    if (testCase.followUps === "full") perRecording += 1;
    if (testCase.preflight) perRecording += 1;
  }
  const main = setup + perRecording * recordings;
  const names = new Set(cases.map((c) => caseObjects(c).sent)).size * recordings;
  const cleanup = 2 + 2 * names;
  return { setup, perRecording, main, cleanup, total: main + cleanup };
}

/**
 * The request count of a run in which every case behaves as planned. Production adds the bucket
 * and signer reads and one signBlob per case; the local dry run signs with a local key.
 */
export function expectedRequests(
  cases = CASES,
  recordings = RECORDINGS,
  targetName = "production",
) {
  const production = targetName === "production";
  const setup = production ? 3 : 1;
  let perRecording = 0;
  let created = 0;
  for (const testCase of cases) {
    perRecording += production ? 3 : 2;
    if (testCase.followUps === "full") perRecording += 1;
    if (testCase.preflight) perRecording += 1;
    if (testCase.expect === "create") created += 1;
  }
  return setup + perRecording * recordings + 2 + 2 * created * recordings;
}
