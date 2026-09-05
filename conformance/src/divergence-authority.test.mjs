import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { STATUS } from "./config.mjs";
import { classifyScenario } from "./diff.mjs";
import {
  readValidatedDivergenceRegister,
  validateDivergenceRegister,
} from "./divergence-authority.mjs";

const BASELINE = "15.28.2";
const KEY = "firestore/example#step";

/**
 * A throwaway repository root holding the fixture rows an authority may bind to. The
 * validator resolves `fixture` references against this root, so every accepted entry in
 * these tests is bound to a row that really exists.
 */
function repositoryRoot() {
  const root = mkdtempSync(join(tmpdir(), "fireemu-divergence-authority-"));
  const fixtures = join(root, "conformance", "fixtures", "firestore");
  mkdirSync(fixtures, { recursive: true });
  const write = (name, id, steps) =>
    writeFileSync(join(fixtures, name), JSON.stringify({ schemaVersion: 1, id, steps }));
  write("example.json", "firestore/example", [
    { id: "step", status: "documented-divergence" },
    { id: "agreed", status: "parity", value: {} },
  ]);
  write("other.json", "firestore/other", [{ id: "step", status: "documented-divergence" }]);
  writeFileSync(
    join(root, "conformance", "firestore-matrix.json"),
    JSON.stringify({
      programs: [
        {
          id: "values/type-order",
          steps: {
            "descending-name-only": { oracle: { status: 200 } },
            ascending: { oracle: { status: 200 } },
          },
        },
      ],
    }),
  );
  mkdirSync(join(root, "docs"), { recursive: true });
  writeFileSync(
    join(root, "docs", "not-a-fixture.json"),
    JSON.stringify({
      id: "firestore/example",
      steps: [{ id: "step", status: "documented-divergence" }],
    }),
  );
  return root;
}

const entry = (overrides = {}) => ({
  documents: "README.md",
  reason: "Deliberate measured difference.",
  authority: {
    kind: "production-spec",
    sourceUrls: ["https://firebase.google.com/docs/firestore"],
    checkedOn: "2026-09-05",
    officialBaseline: { package: "firebase-tools", version: BASELINE },
    fixture: "conformance/fixtures/firestore/example.json#step",
    decidedBy: "fireemu maintainers",
    ...overrides,
  },
});

const register = (value, key = KEY) => ({
  schemaVersion: 2,
  divergences: { [key]: value },
  firestoreMatrixDivergences: {},
  rulesMatrixDivergences: {},
});

let root;
test.before(() => {
  root = repositoryRoot();
});
test.after(() => {
  rmSync(root, { recursive: true, force: true });
});

const validate = (value) => validateDivergenceRegister(value, BASELINE, { root });
const problemsOf = (value) => validate(value).join("\n");

test("a complete production authority bound to its own row is accepted", () => {
  assert.deepEqual(validate(register(entry())), []);
});

test("missing and unverified authority cannot justify a divergence", () => {
  const missing = register({ reason: "No authority.", documents: "README.md" });
  assert.match(problemsOf(missing), /authority is required/);

  const unverified = register(entry({ kind: "unverified" }));
  assert.match(problemsOf(unverified), /unverified authority cannot justify/);
});

test("bad sources dates baselines and decisions fail closed", () => {
  const problems = problemsOf(
    register(
      entry({
        sourceUrls: ["http://example.test/source"],
        checkedOn: "2026-02-30",
        officialBaseline: { package: "firebase-tools", version: "latest" },
        decidedBy: "",
      }),
    ),
  );
  assert.match(problems, /valid HTTPS URLs/);
  assert.match(problems, /checkedOn is invalid/);
  assert.match(problems, /officialBaseline must match/);
  assert.match(problems, /decidedBy or approvalRecord is required/);
});

test("schema sections kinds fixture and evidence fields are mandatory", () => {
  assert.match(problemsOf({}), /schemaVersion must be 2/);
  const malformed = register(entry({ kind: "guess", fixture: "" }));
  delete malformed.divergences[KEY].reason;
  delete malformed.divergences[KEY].documents;
  delete malformed.rulesMatrixDivergences;
  const problems = problemsOf(malformed);
  assert.match(problems, /reason is required/);
  assert.match(problems, /documents is required/);
  assert.match(problems, /unknown authority kind/);
  assert.match(problems, /fixture is required/);
  assert.match(problems, /rulesMatrixDivergences must be an object/);
});

test("authority URLs cannot carry credentials", () => {
  const problems = problemsOf(
    register(entry({ sourceUrls: ["https://user:secret@example.test/source"] })),
  );
  assert.match(problems, /valid HTTPS URLs/);
});

test("authority URLs with raw whitespace are rejected before parsing", () => {
  for (const url of [
    "https://firebase.google.com/docs\n/firestore",
    "https://firebase.goo\tgle.com/docs",
    "https://firebase.google.com/docs firestore",
    " https://firebase.google.com/docs",
    "https://localhost/docs",
    "https://",
    "https://firebase.google.com/docs\u009B",
  ]) {
    assert.match(
      problemsOf(register(entry({ sourceUrls: [url] }))),
      /valid HTTPS URLs/,
      `expected ${JSON.stringify(url)} to be refused`,
    );
  }
});

test("metadata must be non-empty strings, not objects or arrays", () => {
  const objectValued = register({
    documents: { file: "README.md" },
    reason: ["several", "reasons"],
    authority: {
      ...entry().authority,
      fixture: { path: "conformance/fixtures/firestore/example.json#step" },
      decidedBy: undefined,
      approvalRecord: { record: "README.md" },
    },
  });
  const problems = problemsOf(objectValued);
  assert.match(problems, /documents must be a non-empty string/);
  assert.match(problems, /reason must be a non-empty string/);
  assert.match(problems, /fixture must be a non-empty string/);
  assert.match(problems, /decidedBy or approvalRecord is required/);

  const typed = problemsOf(
    register(
      entry({
        sourceUrls: [{ href: "https://firebase.google.com/docs" }],
        checkedOn: { date: "2026-09-05" },
        decidedBy: ["fireemu maintainers"],
      }),
    ),
  );
  assert.match(typed, /valid HTTPS URLs/);
  assert.match(typed, /checkedOn is invalid/);
  assert.match(typed, /decidedBy or approvalRecord is required/);
});

test("an authority fixture must name a repository-relative conformance file", () => {
  for (const fixture of [
    "docs/not-a-fixture.json#step",
    "../conformance/fixtures/firestore/example.json#step",
    "conformance/../docs/not-a-fixture.json#step",
    `${root}/conformance/fixtures/firestore/example.json#step`,
    "conformance\\fixtures\\firestore\\example.json#step",
    "conformance/fixtures/firestore/example.json",
    "conformance/fixtures/firestore/example.json#step#extra#more",
  ]) {
    assert.match(
      problemsOf(register(entry({ fixture }))),
      /fixture must be a repository-relative conformance file/,
      `expected ${JSON.stringify(fixture)} to be refused`,
    );
  }
});

test("an authority fixture must resolve to an existing documented-divergence row", () => {
  const missingFile = problemsOf(
    register(entry({ fixture: "conformance/fixtures/firestore/missing.json#step" })),
  );
  assert.match(missingFile, /does not name an existing documented-divergence row/);

  const parityRow = problemsOf(
    register(entry({ fixture: "conformance/fixtures/firestore/example.json#agreed" })),
  );
  assert.match(parityRow, /does not name an existing documented-divergence row/);

  const unknownStep = problemsOf(
    register(entry({ fixture: "conformance/fixtures/firestore/example.json#nope" })),
  );
  assert.match(unknownStep, /does not name an existing documented-divergence row/);
});

test("an authority fixture that names another valid row is rejected", () => {
  const otherRow = problemsOf(
    register(entry({ fixture: "conformance/fixtures/firestore/other.json#step" })),
  );
  assert.match(otherRow, /fixture points to different row firestore\/other#step/);

  const wrongKey = problemsOf(register(entry(), "firestore/example#other-step"));
  assert.match(wrongKey, /fixture points to different row firestore\/example#step/);
});

test("the checked-in register is frozen after validation and cannot be promoted later", () => {
  const validated = readValidatedDivergenceRegister();
  const scenarioId = "firestore/injected";
  const injectedKey = `${scenarioId}#step`;
  assert.equal(validated.divergences[injectedKey], undefined);

  assert.throws(() => {
    validated.divergences[injectedKey] = { documents: "x", reason: "injected" };
  }, TypeError);
  assert.throws(() => {
    Object.values(validated.divergences)[0].reason = "rewritten";
  }, TypeError);
  assert.throws(() => {
    Object.values(validated.divergences)[0].authority.kind = "unverified";
  }, TypeError);
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.firestoreMatrixDivergences), true);
  assert.equal(Object.isFrozen(validated.rulesMatrixDivergences), true);

  const steps = classifyScenario({
    scenarioId,
    oracleScenario: { steps: [{ id: "step", value: { status: 200 } }] },
    testdScenario: { steps: [{ id: "step", value: { status: 404 } }] },
    annotations: validated.divergences,
  });
  assert.equal(steps[0].status, STATUS.debt);

  const copy = { ...validated.divergences, [injectedKey]: { documents: "x", reason: "y" } };
  const promoted = classifyScenario({
    scenarioId,
    oracleScenario: { steps: [{ id: "step", value: { status: 200 } }] },
    testdScenario: { steps: [{ id: "step", value: { status: 404 } }] },
    annotations: copy,
  });
  assert.equal(promoted[0].status, STATUS.debt);
});

test("an object-shaped matrix row binds only when the pinned answer differs from the oracle", () => {
  const pinned = {
    fireemu: { status: 409 },
    reason: "pinned",
    authority: {
      ...entry().authority,
      fixture: "conformance/firestore-matrix.json#values/type-order#descending-name-only",
    },
  };
  const register = {
    schemaVersion: 2,
    divergences: {},
    firestoreMatrixDivergences: { "values/type-order#descending-name-only": pinned },
    rulesMatrixDivergences: {},
  };
  assert.deepEqual(validate(register), []);

  const parity = {
    ...pinned,
    fireemu: { status: 200 },
    authority: {
      ...pinned.authority,
      fixture: "conformance/firestore-matrix.json#values/type-order#ascending",
    },
  };
  const promoted = {
    ...register,
    firestoreMatrixDivergences: { "values/type-order#ascending": parity },
  };
  assert.match(problemsOf(promoted), /does not name an existing documented-divergence row/);
});

test("a fixture reached through a symbolic link out of the repository is refused", () => {
  const outside = join(tmpdir(), `fireemu-outside-${process.pid}.json`);
  writeFileSync(
    outside,
    JSON.stringify({
      id: "firestore/example",
      steps: [{ id: "step", status: "documented-divergence" }],
    }),
  );
  const link = join(root, "conformance", "fixtures", "firestore", "linked.json");
  symlinkSync(outside, link);
  try {
    assert.match(
      problemsOf(register(entry({ fixture: "conformance/fixtures/firestore/linked.json#step" }))),
      /must stay inside the repository/,
    );
  } finally {
    rmSync(link, { force: true });
    rmSync(outside, { force: true });
  }
});
