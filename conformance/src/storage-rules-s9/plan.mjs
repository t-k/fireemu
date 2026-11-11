// Case table, rule sources and static bounds of the Storage Rules observation of the 2026-11-08
// sibling audit (S1-S4, S7-S10). Everything a run sends is derived from the tables below.
//
// Per recording, under a fresh prefix `storage-rules-s9/<runId>/rec<N>`:
//   - objects are created with the owner credential (rules never apply to it),
//   - three rulesets are released one after the other on the bucket's `firebase.storage` release
//     (`s9`, `units`, `lists`), each settled by a marker object that only that ruleset lets an
//     anonymous Firebase v0 request read, and each read by the rows below,
//   - three more rulesets are only loaded (`rulesets.create`, never released) and deleted,
//   - the release goes back to what it was, and every object this run created is deleted.

export const PROJECT = "fireemu-oracle-query";
export const BUCKET = "fireemu-oracle-query.firebasestorage.app";
export const LOCAL_BUCKET = "demo-storage-s9.appspot.com";
export const PREFIX_ROOT = "storage-rules-s9";
export const RECORDINGS = 2;
export const ESTIMATED_USD = 0.05;

/** Per-request timeout: the 30000 ms of the existing Storage recorders (no latency recorded for these routes). */
export const REQUEST_TIMEOUT_MS = 30_000;
/** A release is settled after this many consecutive polls that see it in force. */
export const SETTLE_STREAK = 3;
export const SETTLE_POLL_MS = 6000;
/** A release that is not settled after this many polls (about 6 minutes) stops the run; the release is restored. */
export const SETTLE_MAX_POLLS = 60;
/** After a restore, the last marker must stop answering 200 for this many polls in a row. */
export const STILL_IN_FORCE_READS = 3;

export const newRunId = (random = () => Math.random()) => {
  let id = "";
  while (id.length < 8) id += Math.floor(random() * 16).toString(16);
  return `sr-${id}`;
};

export const runRoot = (runId) => `${PREFIX_ROOT}/${runId}/`;
/** `P`: the prefix every rule and object of one recording lives under (no trailing slash). */
export const recordingPrefix = (runId, recording) => `${PREFIX_ROOT}/${runId}/rec${recording}`;

const FIRE = "\u{1F525}"; // U+1F525, one code point, two UTF-16 units
const E_ACUTE = "é";
export const FIRE_NAME = `${E_ACUTE}${FIRE}x`; // 4 UTF-16 units, 3 code points
export const FIRE_META = `${FIRE}x`; // 3 UTF-16 units, 2 code points

/**
 * Objects. `name(P)` is the full object name. Names with an empty path segment are the point of the
 * S9 rows: the interior one (`P/pub//x`), the leading one (`/P/pub/x`) and the trailing one (`P/pub/x/`).
 */
export const OBJECTS = {
  mkA: { name: (P) => `${P}/mk/a`, body: "a" },
  mkB: { name: (P) => `${P}/mk/b`, body: "b" },
  mkC: { name: (P) => `${P}/mk/c`, body: "c" },
  pubPlain: { name: (P) => `${P}/pub/x`, body: "plain" },
  pubInterior: { name: (P) => `${P}/pub//x`, body: "interior" },
  pubLeading: { name: (P) => `/${P}/pub/x`, body: "leading" },
  pubTrailing: { name: (P) => `${P}/pub/x/`, body: "trailing" },
  denPlain: { name: (P) => `${P}/den/x`, body: "denied" },
  c1: { name: (P) => `${P}/c1/abc`, body: "c1" },
  c2: { name: (P) => `${P}/c2/abc`, body: "c2" },
  s1a: { name: (P) => `${P}/s1a/${FIRE_NAME}`, body: "s1a" },
  s1b: { name: (P) => `${P}/s1b/${FIRE_NAME}`, body: "s1b" },
  s1r: { name: (P) => `${P}/s1r/${FIRE_NAME}`, body: "s1r" },
  s1p: { name: (P) => `${P}/s1p/${FIRE_NAME}`, body: "s1p" },
  s2a: { name: (P) => `${P}/s2a/${FIRE_NAME}`, body: "s2a" },
  s2b: { name: (P) => `${P}/s2b/${FIRE_NAME}`, body: "s2b" },
  s3a: { name: (P) => `${P}/s3a/${FIRE_NAME}`, body: "s3a" },
  s3b: { name: (P) => `${P}/s3b/${FIRE_NAME}`, body: "s3b" },
  s4a: { name: (P) => `${P}/s4a/o`, body: "s4a", metadata: { k: FIRE_META } },
  s4b: { name: (P) => `${P}/s4b/o`, body: "s4b", metadata: { k: FIRE_META } },
  s4c: { name: (P) => `${P}/s4c/o`, body: "s4c", metadata: { k: "ab" } },
  l0: { name: (P) => `${P}/l0/o1`, body: "l0" },
  l1: { name: (P) => `${P}/l1/o1`, body: "l1" },
  l2: { name: (P) => `${P}/l2/o1`, body: "l2" },
  l3: { name: (P) => `${P}/l3/o1`, body: "l3" },
  l4: { name: (P) => `${P}/l4/o1`, body: "l4" },
  l5: { name: (P) => `${P}/l5/o1`, body: "l5" },
};

const wrap = (body, version = "2") =>
  `rules_version = '${version}';\nservice firebase.storage {\n  match /b/{bucket}/o {\n${body}  }\n}\n`;
const allow = (path, grant, condition) =>
  `    match /${path} {\n      allow ${grant}: if ${condition};\n    }\n`;

const unitsOf = (text) => text.length; // UTF-16 units: what JavaScript counts
const pointsOf = (text) => [...text].length;

/** The released programs: marker object, rule source, objects and rows. */
export const PROGRAMS = [
  {
    id: "s9",
    marker: "mkA",
    objects: ["mkA", "pubPlain", "pubInterior", "pubLeading", "pubTrailing", "denPlain"],
    source: (P) => wrap(allow(`${P}/mk/a`, "read", "true") + allow(`${P}/pub/{f}`, "read", "true")),
  },
  {
    id: "units",
    marker: "mkB",
    objects: [
      "mkB",
      "c1",
      "c2",
      "s1a",
      "s1b",
      "s1r",
      "s1p",
      "s2a",
      "s2b",
      "s3a",
      "s3b",
      "s4a",
      "s4b",
      "s4c",
    ],
    source: (P) => {
      const full = `${P}/s1r/${FIRE_NAME}`;
      const fullPoints = pointsOf(full);
      return wrap(
        allow(`${P}/mk/b`, "read", "true") +
          allow(`${P}/c1/{n}`, "read", "n.size() == 3") +
          allow(`${P}/c2/{n}`, "read", "n.size() == 4") +
          allow(`${P}/s1a/{n}`, "read", "n.size() == 4") +
          allow(`${P}/s1b/{n}`, "read", "n.size() == 3") +
          allow(`${P}/s1r/{n}`, "read", `resource.name.size() == ${unitsOf(full)}`) +
          allow(`${P}/s1p/{n}`, "read", `resource.name.size() == ${fullPoints}`) +
          allow(`${P}/s2a/{n}`, "read", "n[3] == 'x'") +
          allow(`${P}/s2b/{n}`, "read", "n[2] == 'x'") +
          allow(`${P}/s3a/{n}`, "read", `n[0:3] == '${E_ACUTE}${FIRE}'`) +
          allow(`${P}/s3b/{n}`, "read", `n[0:2] == '${E_ACUTE}${FIRE}'`) +
          allow(`${P}/s4a/{n}`, "read", "resource.metadata.k.size() == 3") +
          allow(`${P}/s4b/{n}`, "read", "resource.metadata.k.size() == 2") +
          allow(`${P}/s4c/{n}`, "read", "resource.metadata.k.size() == 2"),
      );
    },
  },
  {
    id: "lists",
    marker: "mkC",
    objects: ["mkC", "l0", "l1", "l2", "l3", "l4", "l5"],
    source: (P) =>
      wrap(
        allow(`${P}/mk/c`, "read", "true") +
          allow(`${P}/l0/{file=**}`, "list", "true") +
          allow(`${P}/l1/{file=**}`, "list", "[file] != null") +
          allow(`${P}/l2/{file=**}`, "list", "false") +
          allow(`${P}/l3/{file=**}`, "list", `request.path == /b/$(bucket)/o/${P}/l3`) +
          allow(`${P}/l4/{file}`, "list", "true") +
          allow(`${P}/l5/{file=**}`, "list", "file == ''"),
      ),
  },
];

/** Rulesets that are only loaded (never released): `rulesets.create`, then deleted. */
export const LOAD_ONLY = [
  {
    id: "s7-lone-surrogate",
    source: (P) => wrap(allow(`${P}/ls/{f}`, "read", '"\\ud83d".size() == 1')),
  },
  {
    id: "s8-function-before",
    source: (P) =>
      `rules_version = '2';\nfunction ok() { return true; }\nservice firebase.storage {\n  match /b/{bucket}/o {\n${allow(`${P}/fn/{f}`, "read", "ok()")}  }\n}\n`,
  },
  {
    id: "s8-function-after",
    source: (P) =>
      `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n${allow(`${P}/fn/{f}`, "read", "ok()")}  }\n}\nfunction ok() { return true; }\n`,
  },
];

/** A closed, never-allowing ruleset for the local targets' baseline (and their restore). */
export const LOCAL_BASELINE_RULES = wrap(allow("{path=**}", "read, write", "false"), "2");

/**
 * Rows. `op` is `meta` (Firebase v0 GET of the object), `media` (the same with `alt=media`) or
 * `list` (v0 list of `prefix`). `plan` is what the table will be read against: the UTF-16 reading
 * of the audit (`utf16`) and, for S9, the reading that an empty segment never matches (`refuse`).
 * It is a planning note, never a verdict.
 */
const meta = (program, id, object, plan) => ({ program, id, op: "meta", object, plan });
const media = (program, id, object, plan) => ({ program, id, op: "media", object, plan });
const list = (program, id, prefix, plan, delimiter) => ({
  program,
  id,
  op: "list",
  prefix,
  delimiter,
  plan,
});

export const ROWS = [
  // S9: object names with an empty path segment, under `match /P/pub/{f} { allow read: if true; }`.
  meta("s9", "pub-plain-meta", "pubPlain", "allow"),
  media("s9", "pub-plain-media", "pubPlain", "allow"),
  meta("s9", "pub-trailing-meta", "pubTrailing", "unknown"),
  media("s9", "pub-trailing-media", "pubTrailing", "unknown"),
  meta("s9", "pub-interior-meta", "pubInterior", "refuse"),
  media("s9", "pub-interior-media", "pubInterior", "refuse"),
  meta("s9", "pub-leading-meta", "pubLeading", "refuse"),
  media("s9", "pub-leading-media", "pubLeading", "refuse"),
  meta("s9", "den-meta", "denPlain", "deny"),
  list("s9", "list-pub-delim", (P) => `${P}/pub/`, "unknown", "/"),
  list("s9", "list-pub", (P) => `${P}/pub/`, "unknown"),
  list("s9", "list-pub-leading", (P) => `/${P}/pub/`, "unknown"),
  list("s9", "list-den", (P) => `${P}/den/`, "deny"),
  // S1-S4: UTF-16 counting of an object name and of a custom metadata value.
  meta("units", "c1-true", "c1", "allow"),
  meta("units", "c2-false", "c2", "deny"),
  meta("units", "s1-size4", "s1a", "allow"),
  meta("units", "s1-size3", "s1b", "deny"),
  meta("units", "s1r-units", "s1r", "allow"),
  meta("units", "s1r-points", "s1p", "deny"),
  meta("units", "s2-idx3", "s2a", "allow"),
  meta("units", "s2-idx2", "s2b", "deny"),
  meta("units", "s3-rng03", "s3a", "allow"),
  meta("units", "s3-rng02", "s3b", "deny"),
  meta("units", "s4-meta3", "s4a", "allow"),
  meta("units", "s4-meta2", "s4b", "deny"),
  meta("units", "s4-ctl", "s4c", "allow"),
  // S10: list rules over a capture and over `request.path`.
  list("lists", "l0-true", (P) => `${P}/l0/`, "allow"),
  list("lists", "l1-capture-not-null", (P) => `${P}/l1/`, "allow"),
  list("lists", "l2-false", (P) => `${P}/l2/`, "deny"),
  list("lists", "l3-path-prefix", (P) => `${P}/l3/`, "unknown"),
  list("lists", "l4-single-segment", (P) => `${P}/l4/`, "unknown"),
  list("lists", "l5-capture-empty", (P) => `${P}/l5/`, "unknown"),
];

/**
 * A family of the observation: the tables and the numbers derived from them. Everything the
 * recorder sends comes from one plan, so the S9 family and later families share one recorder.
 */
export function buildPlan({
  id,
  taskId,
  prefixRoot,
  estimatedUsd,
  localBucket,
  objects,
  programs,
  loadOnly,
  rows,
}) {
  for (const program of programs) {
    if (!(program.marker in objects)) throw new Error(`program ${program.id}: unknown marker`);
    for (const object of program.objects)
      if (!(object in objects)) throw new Error(`program ${program.id}: unknown object ${object}`);
  }
  for (const row of rows) {
    if (!programs.some((program) => program.id === row.program))
      throw new Error(`row ${row.id}: unknown program ${row.program}`);
    if (row.object !== undefined && !(row.object in objects))
      throw new Error(`row ${row.id}: unknown object ${row.object}`);
  }
  const rootOf = (runId) => `${prefixRoot}/${runId}/`;
  const prefixOf = (runId, recording) => `${prefixRoot}/${runId}/rec${recording}`;
  const objectNameOf = (objectId, P) => objects[objectId].name(P);
  const rowsOf = (program) => rows.filter((row) => row.program === program);
  const objectCount = Object.keys(objects).length;

  /** Every object name `recordings` recordings can create, for the guard and the cleanup. */
  function plannedNames(runId, recordings = RECORDINGS) {
    const names = [];
    for (let recording = 1; recording <= recordings; recording += 1) {
      const P = prefixOf(runId, recording);
      for (const objectId of Object.keys(objects)) names.push(objectNameOf(objectId, P));
    }
    return names;
  }

  /**
   * Worst-case request counts for production, used as the caps. Setup of a recording: one create per
   * object, one marker pre-read per program. Per program: a ruleset
   * create, up to a PATCH and a POST of the release, its read-back, the settle polls (two markers each),
   * the rows and the still-in-force reads. Then the load-only rulesets (create and delete), the restore
   * (PATCH or DELETE, read-back, up to the settle polls) and the ruleset deletes. Cleanup after the
   * recordings: two lists, a DELETE and a read-back per object, two final lists, the final ruleset and
   * release reads.
   */
  function staticBounds(recordings = RECORDINGS) {
    const preflight = 6;
    const setup = objectCount + programs.length;
    const perProgram = (program) =>
      1 + 2 + 1 + SETTLE_MAX_POLLS * 2 + rowsOf(program.id).length + STILL_IN_FORCE_READS;
    const programTotal = programs.reduce((sum, program) => sum + perProgram(program), 0);
    const loadOnlyTotal = loadOnly.length * 2;
    const restore = 1 + 1 + 1 + SETTLE_MAX_POLLS;
    const rulesetDeletes = programs.length;
    const perRecording = setup + programTotal + loadOnlyTotal + restore + rulesetDeletes;
    const main = preflight + perRecording * recordings;
    const names = objectCount * recordings;
    const cleanup = 2 + 2 * names + 2 + 4;
    return {
      preflight,
      setup,
      programs: programTotal,
      loadOnly: loadOnlyTotal,
      restore,
      perRecording,
      main,
      cleanup,
      total: main + cleanup,
    };
  }

  /**
   * Request count of a production run in which everything behaves as planned: every release settles
   * at the third poll (two markers except for the first program), every compile succeeds.
   */
  function expectedRequests(recordings = RECORDINGS) {
    const preflight = 6;
    let perRecording = objectCount + programs.length;
    programs.forEach((program, index) => {
      perRecording += 1 + 1 + 1; // create, publish, read-back
      perRecording += SETTLE_STREAK * (index === 0 ? 1 : 2);
      perRecording += rowsOf(program.id).length + STILL_IN_FORCE_READS;
    });
    perRecording += loadOnly.length * 2;
    perRecording += 1 + 1 + 1 + SETTLE_STREAK; // restore: read, write, read-back, settle
    perRecording += programs.length; // ruleset deletes
    const cleanup = 2 + 2 * objectCount * recordings + 2 + 2;
    return preflight + perRecording * recordings + cleanup;
  }

  /** The cap of a recovery: the cleanup of a run that created everything, with a margin of twenty. */
  const recoveryCap = (recordings = RECORDINGS) => staticBounds(recordings).cleanup + 20;

  /** The cap of the A2 read-back: the two lists, the release and ruleset reads, every name once. */
  const readbackCap = (recordings = RECORDINGS) => objectCount * recordings + 16;

  return Object.freeze({
    id,
    taskId,
    prefixRoot,
    estimatedUsd,
    localBucket,
    objects,
    programs,
    loadOnly,
    rows,
    runRoot: rootOf,
    recordingPrefix: prefixOf,
    objectName: objectNameOf,
    rowsOf,
    objectsOf: (program) => programs.find((p) => p.id === program).objects,
    plannedNames,
    staticBounds,
    expectedRequests,
    readbackCap,
    recoveryCap,
  });
}

/** The family of the 2026-11-08 sibling audit (S1-S4, S7-S10), sent as STORAGE-RULES-S9. */
export const S9_PLAN = buildPlan({
  id: "s9",
  taskId: "STORAGE-RULES-S9",
  prefixRoot: PREFIX_ROOT,
  estimatedUsd: ESTIMATED_USD,
  localBucket: LOCAL_BUCKET,
  objects: OBJECTS,
  programs: PROGRAMS,
  loadOnly: LOAD_ONLY,
  rows: ROWS,
});

export const objectsOf = S9_PLAN.objectsOf;
export const allObjectIds = () => Object.keys(OBJECTS);
export const rowsOf = S9_PLAN.rowsOf;

export const objectName = S9_PLAN.objectName;
export const unitsAndPoints = (text) => ({ units: unitsOf(text), points: pointsOf(text) });

export const plannedNames = S9_PLAN.plannedNames;
export const staticBounds = S9_PLAN.staticBounds;
export const expectedRequests = S9_PLAN.expectedRequests;
