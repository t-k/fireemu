import assert from "node:assert/strict";
import test from "node:test";

import { validateDivergenceRegister } from "./divergence-authority.mjs";

const entry = (overrides = {}) => ({
  documents: "README.md",
  reason: "Deliberate measured difference.",
  authority: {
    kind: "production-spec",
    sourceUrls: ["https://firebase.google.com/docs/firestore"],
    checkedOn: "2026-09-05",
    officialBaseline: { package: "firebase-tools", version: "15.28.2" },
    fixture: "conformance/fixtures/firestore/example.json#step",
    decidedBy: "fireemu maintainers",
    ...overrides,
  },
});

const register = (value) => ({
  schemaVersion: 2,
  divergences: { "scenario#step": value },
  firestoreMatrixDivergences: {},
  rulesMatrixDivergences: {},
});

test("a complete production authority is accepted", () => {
  assert.deepEqual(validateDivergenceRegister(register(entry()), "15.28.2"), []);
});

test("missing and unverified authority cannot justify a divergence", () => {
  const missing = register({ reason: "No authority." });
  assert.match(validateDivergenceRegister(missing, "15.28.2").join("\n"), /authority is required/);

  const unverified = register(entry({ kind: "unverified" }));
  assert.match(
    validateDivergenceRegister(unverified, "15.28.2").join("\n"),
    /unverified authority cannot justify/,
  );
});

test("bad sources dates baselines and decisions fail closed", () => {
  const problems = validateDivergenceRegister(
    register(
      entry({
        sourceUrls: ["http://example.test/source"],
        checkedOn: "2026-02-30",
        officialBaseline: { package: "firebase-tools", version: "latest" },
        decidedBy: "",
      }),
    ),
    "15.28.2",
  ).join("\n");
  assert.match(problems, /valid HTTPS URLs/);
  assert.match(problems, /checkedOn is invalid/);
  assert.match(problems, /officialBaseline must match/);
  assert.match(problems, /decidedBy or approvalRecord is required/);
});

test("schema sections kinds fixture and evidence fields are mandatory", () => {
  assert.match(validateDivergenceRegister({}, "15.28.2").join("\n"), /schemaVersion must be 2/);
  const malformed = register(entry({ kind: "guess", fixture: "" }));
  delete malformed.divergences["scenario#step"].reason;
  delete malformed.divergences["scenario#step"].documents;
  delete malformed.rulesMatrixDivergences;
  const problems = validateDivergenceRegister(malformed, "15.28.2").join("\n");
  assert.match(problems, /reason is required/);
  assert.match(problems, /documents is required/);
  assert.match(problems, /unknown authority kind/);
  assert.match(problems, /fixture is required/);
  assert.match(problems, /rulesMatrixDivergences must be an object/);
});

test("authority URLs cannot carry credentials", () => {
  const problems = validateDivergenceRegister(
    register(entry({ sourceUrls: ["https://user:secret@example.test/source"] })),
    "15.28.2",
  );
  assert.match(problems.join("\n"), /valid HTTPS URLs/);
});
