import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import * as plan from "./storage-rules-s9/plan.mjs";

// The packet pins these tables: a change to a rule source, an object name or a row is a new packet.
const P = plan.recordingPrefix("sr-0123abcd", 1);

const OBJECTS_GOLDEN = {
  mkA: { name: "storage-rules-s9/sr-0123abcd/rec1/mk/a", body: "a" },
  mkB: { name: "storage-rules-s9/sr-0123abcd/rec1/mk/b", body: "b" },
  mkC: { name: "storage-rules-s9/sr-0123abcd/rec1/mk/c", body: "c" },
  pubPlain: { name: "storage-rules-s9/sr-0123abcd/rec1/pub/x", body: "plain" },
  pubInterior: { name: "storage-rules-s9/sr-0123abcd/rec1/pub//x", body: "interior" },
  pubLeading: { name: "/storage-rules-s9/sr-0123abcd/rec1/pub/x", body: "leading" },
  pubTrailing: { name: "storage-rules-s9/sr-0123abcd/rec1/pub/x/", body: "trailing" },
  denPlain: { name: "storage-rules-s9/sr-0123abcd/rec1/den/x", body: "denied" },
  c1: { name: "storage-rules-s9/sr-0123abcd/rec1/c1/abc", body: "c1" },
  c2: { name: "storage-rules-s9/sr-0123abcd/rec1/c2/abc", body: "c2" },
  s1a: { name: "storage-rules-s9/sr-0123abcd/rec1/s1a/\u00e9\u{1f525}x", body: "s1a" },
  s1b: { name: "storage-rules-s9/sr-0123abcd/rec1/s1b/\u00e9\u{1f525}x", body: "s1b" },
  s1r: { name: "storage-rules-s9/sr-0123abcd/rec1/s1r/\u00e9\u{1f525}x", body: "s1r" },
  s1p: { name: "storage-rules-s9/sr-0123abcd/rec1/s1p/\u00e9\u{1f525}x", body: "s1p" },
  s2a: { name: "storage-rules-s9/sr-0123abcd/rec1/s2a/\u00e9\u{1f525}x", body: "s2a" },
  s2b: { name: "storage-rules-s9/sr-0123abcd/rec1/s2b/\u00e9\u{1f525}x", body: "s2b" },
  s3a: { name: "storage-rules-s9/sr-0123abcd/rec1/s3a/\u00e9\u{1f525}x", body: "s3a" },
  s3b: { name: "storage-rules-s9/sr-0123abcd/rec1/s3b/\u00e9\u{1f525}x", body: "s3b" },
  s4a: {
    name: "storage-rules-s9/sr-0123abcd/rec1/s4a/o",
    body: "s4a",
    metadata: { k: "\u{1f525}x" },
  },
  s4b: {
    name: "storage-rules-s9/sr-0123abcd/rec1/s4b/o",
    body: "s4b",
    metadata: { k: "\u{1f525}x" },
  },
  s4c: { name: "storage-rules-s9/sr-0123abcd/rec1/s4c/o", body: "s4c", metadata: { k: "ab" } },
  l0: { name: "storage-rules-s9/sr-0123abcd/rec1/l0/o1", body: "l0" },
  l1: { name: "storage-rules-s9/sr-0123abcd/rec1/l1/o1", body: "l1" },
  l2: { name: "storage-rules-s9/sr-0123abcd/rec1/l2/o1", body: "l2" },
  l3: { name: "storage-rules-s9/sr-0123abcd/rec1/l3/o1", body: "l3" },
  l4: { name: "storage-rules-s9/sr-0123abcd/rec1/l4/o1", body: "l4" },
  l5: { name: "storage-rules-s9/sr-0123abcd/rec1/l5/o1", body: "l5" },
};
const ROWS_GOLDEN = [
  { id: "pub-plain-meta", program: "s9", op: "meta", object: "pubPlain", plan: "allow" },
  { id: "pub-plain-media", program: "s9", op: "media", object: "pubPlain", plan: "allow" },
  { id: "pub-trailing-meta", program: "s9", op: "meta", object: "pubTrailing", plan: "unknown" },
  { id: "pub-trailing-media", program: "s9", op: "media", object: "pubTrailing", plan: "unknown" },
  { id: "pub-interior-meta", program: "s9", op: "meta", object: "pubInterior", plan: "refuse" },
  { id: "pub-interior-media", program: "s9", op: "media", object: "pubInterior", plan: "refuse" },
  { id: "pub-leading-meta", program: "s9", op: "meta", object: "pubLeading", plan: "refuse" },
  { id: "pub-leading-media", program: "s9", op: "media", object: "pubLeading", plan: "refuse" },
  { id: "den-meta", program: "s9", op: "meta", object: "denPlain", plan: "deny" },
  {
    id: "list-pub-delim",
    program: "s9",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/pub/",
    delimiter: "/",
    plan: "unknown",
  },
  {
    id: "list-pub",
    program: "s9",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/pub/",
    plan: "unknown",
  },
  {
    id: "list-pub-leading",
    program: "s9",
    op: "list",
    prefix: "/storage-rules-s9/sr-0123abcd/rec1/pub/",
    plan: "unknown",
  },
  {
    id: "list-den",
    program: "s9",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/den/",
    plan: "deny",
  },
  { id: "c1-true", program: "units", op: "meta", object: "c1", plan: "allow" },
  { id: "c2-false", program: "units", op: "meta", object: "c2", plan: "deny" },
  { id: "s1-size4", program: "units", op: "meta", object: "s1a", plan: "allow" },
  { id: "s1-size3", program: "units", op: "meta", object: "s1b", plan: "deny" },
  { id: "s1r-units", program: "units", op: "meta", object: "s1r", plan: "allow" },
  { id: "s1r-points", program: "units", op: "meta", object: "s1p", plan: "deny" },
  { id: "s2-idx3", program: "units", op: "meta", object: "s2a", plan: "allow" },
  { id: "s2-idx2", program: "units", op: "meta", object: "s2b", plan: "deny" },
  { id: "s3-rng03", program: "units", op: "meta", object: "s3a", plan: "allow" },
  { id: "s3-rng02", program: "units", op: "meta", object: "s3b", plan: "deny" },
  { id: "s4-meta3", program: "units", op: "meta", object: "s4a", plan: "allow" },
  { id: "s4-meta2", program: "units", op: "meta", object: "s4b", plan: "deny" },
  { id: "s4-ctl", program: "units", op: "meta", object: "s4c", plan: "allow" },
  {
    id: "l0-true",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l0/",
    plan: "allow",
  },
  {
    id: "l1-capture-not-null",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l1/",
    plan: "allow",
  },
  {
    id: "l2-false",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l2/",
    plan: "deny",
  },
  {
    id: "l3-path-prefix",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l3/",
    plan: "unknown",
  },
  {
    id: "l4-single-segment",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l4/",
    plan: "unknown",
  },
  {
    id: "l5-capture-empty",
    program: "lists",
    op: "list",
    prefix: "storage-rules-s9/sr-0123abcd/rec1/l5/",
    plan: "unknown",
  },
];

const SOURCE_s9 = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/mk/a {
      allow read: if true;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/pub/{f} {
      allow read: if true;
    }
  }
}
`;
const SOURCE_units = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/mk/b {
      allow read: if true;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/c1/{n} {
      allow read: if n.size() == 3;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/c2/{n} {
      allow read: if n.size() == 4;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s1a/{n} {
      allow read: if n.size() == 4;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s1b/{n} {
      allow read: if n.size() == 3;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s1r/{n} {
      allow read: if resource.name.size() == 42;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s1p/{n} {
      allow read: if resource.name.size() == 41;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s2a/{n} {
      allow read: if n[3] == 'x';
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s2b/{n} {
      allow read: if n[2] == 'x';
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s3a/{n} {
      allow read: if n[0:3] == '\u00e9\u{1f525}';
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s3b/{n} {
      allow read: if n[0:2] == '\u00e9\u{1f525}';
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s4a/{n} {
      allow read: if resource.metadata.k.size() == 3;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s4b/{n} {
      allow read: if resource.metadata.k.size() == 2;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/s4c/{n} {
      allow read: if resource.metadata.k.size() == 2;
    }
  }
}
`;
const SOURCE_lists = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/mk/c {
      allow read: if true;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l0/{file=**} {
      allow list: if true;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l1/{file=**} {
      allow list: if [file] != null;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l2/{file=**} {
      allow list: if false;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l3/{file=**} {
      allow list: if request.path == /b/\$(bucket)/o/storage-rules-s9/sr-0123abcd/rec1/l3;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l4/{file} {
      allow list: if true;
    }
    match /storage-rules-s9/sr-0123abcd/rec1/l5/{file=**} {
      allow list: if file == '';
    }
  }
}
`;
const LOAD_s7_lone_surrogate = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/ls/{f} {
      allow read: if "\\ud83d".size() == 1;
    }
  }
}
`;
const LOAD_s8_function_before = `rules_version = '2';
function ok() { return true; }
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/fn/{f} {
      allow read: if ok();
    }
  }
}
`;
const LOAD_s8_function_after = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /storage-rules-s9/sr-0123abcd/rec1/fn/{f} {
      allow read: if ok();
    }
  }
}
function ok() { return true; }
`;
const LOCAL_BASELINE = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{path=**} {
      allow read, write: if false;
    }
  }
}
`;

const asObjects = () =>
  Object.fromEntries(
    Object.entries(plan.OBJECTS).map(([id, object]) => [
      id,
      {
        name: object.name(P),
        body: object.body,
        ...(object.metadata ? { metadata: object.metadata } : {}),
      },
    ]),
  );
const asRows = () =>
  plan.ROWS.map((row) => ({
    id: row.id,
    program: row.program,
    op: row.op,
    ...(row.object ? { object: row.object } : {}),
    ...(row.prefix ? { prefix: row.prefix(P) } : {}),
    ...(row.delimiter ? { delimiter: row.delimiter } : {}),
    plan: row.plan,
  }));

describe("storage rules s9 pinned tables", () => {
  it("pins the target, the budgets and the settle constants", () => {
    assert.equal(plan.PROJECT, "fireemu-oracle-query");
    assert.equal(plan.BUCKET, "fireemu-oracle-query.firebasestorage.app");
    assert.equal(plan.LOCAL_BUCKET, "demo-storage-s9.appspot.com");
    assert.equal(plan.PREFIX_ROOT, "storage-rules-s9");
    assert.equal(plan.RECORDINGS, 2);
    assert.equal(plan.ESTIMATED_USD, 0.05);
    assert.equal(plan.REQUEST_TIMEOUT_MS, 30_000);
    assert.equal(plan.SETTLE_STREAK, 3);
    assert.equal(plan.SETTLE_POLL_MS, 6000);
    assert.equal(plan.SETTLE_MAX_POLLS, 60);
    assert.equal(plan.STILL_IN_FORCE_READS, 3);
    assert.equal(plan.FIRE_NAME, "\u00e9\u{1f525}x");
    assert.equal(plan.FIRE_META, "\u{1f525}x");
  });

  it("makes run ids of eight hex digits from the random source", () => {
    const digits = [0, 0.0625, 0.5, 0.999, 0.25, 0.75, 0.125, 0.9375];
    let i = 0;
    assert.equal(
      plan.newRunId(() => digits[i++ % digits.length]),
      "sr-018f4c2f",
    );
    assert.match(plan.newRunId(), /^sr-[0-9a-f]{8}$/);
    assert.equal(plan.runRoot("sr-0123abcd"), "storage-rules-s9/sr-0123abcd/");
    assert.equal(plan.recordingPrefix("sr-0123abcd", 2), "storage-rules-s9/sr-0123abcd/rec2");
  });

  it("pins the objects", () => {
    assert.deepEqual(asObjects(), OBJECTS_GOLDEN);
    assert.equal(plan.objectName("pubInterior", P), OBJECTS_GOLDEN.pubInterior.name);
    assert.deepEqual(plan.allObjectIds(), Object.keys(OBJECTS_GOLDEN));
    assert.deepEqual(plan.objectsOf("s9"), [
      "mkA",
      "pubPlain",
      "pubInterior",
      "pubLeading",
      "pubTrailing",
      "denPlain",
    ]);
    assert.deepEqual(plan.unitsAndPoints(plan.FIRE_NAME), { units: 4, points: 3 });
  });

  it("pins the rows", () => {
    assert.deepEqual(asRows(), ROWS_GOLDEN);
    assert.deepEqual(
      plan.rowsOf("lists").map((row) => row.id),
      ROWS_GOLDEN.filter((row) => row.program === "lists").map((row) => row.id),
    );
  });

  it("pins every rule source", () => {
    const sources = Object.fromEntries(
      plan.PROGRAMS.map((program) => [program.id, program.source(P)]),
    );
    assert.equal(sources.s9, SOURCE_s9);
    assert.equal(sources.units, SOURCE_units);
    assert.equal(sources.lists, SOURCE_lists);
    assert.deepEqual(
      plan.PROGRAMS.map((program) => [program.id, program.marker]),
      [
        ["s9", "mkA"],
        ["units", "mkB"],
        ["lists", "mkC"],
      ],
    );
    const loads = Object.fromEntries(plan.LOAD_ONLY.map((item) => [item.id, item.source(P)]));
    assert.equal(loads["s7-lone-surrogate"], LOAD_s7_lone_surrogate);
    assert.equal(loads["s8-function-before"], LOAD_s8_function_before);
    assert.equal(loads["s8-function-after"], LOAD_s8_function_after);
    assert.equal(plan.LOCAL_BASELINE_RULES, LOCAL_BASELINE);
  });

  it("pins the request bounds", () => {
    assert.deepEqual(plan.staticBounds(1), {
      preflight: 6,
      setup: 30,
      programs: 413,
      loadOnly: 6,
      restore: 63,
      perRecording: 515,
      main: 521,
      cleanup: 62,
      total: 583,
    });
    assert.deepEqual(plan.staticBounds(2), {
      preflight: 6,
      setup: 30,
      programs: 413,
      loadOnly: 6,
      restore: 63,
      perRecording: 515,
      main: 1036,
      cleanup: 116,
      total: 1152,
    });
    assert.equal(plan.expectedRequests(1), 176);
    assert.equal(plan.expectedRequests(2), 340);
    assert.deepEqual(
      plan.plannedNames("sr-0123abcd", 1),
      Object.values(OBJECTS_GOLDEN).map((object) => object.name),
    );
  });
});
