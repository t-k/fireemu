import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareRecordings,
  freezeSandboxFixture,
  validateSandboxCorpus,
} from "./fs-data-write-sandbox.mjs";

const step = {
  id: "read",
  method: "GET",
  path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents/c/x",
};
const corpus = {
  schemaVersion: 1,
  restPrograms: [{ id: "writes/control", area: "writes", steps: [step] }],
  streamRecipes: [],
  restRequestCount: 1,
};

test("sandbox corpus refuses a route, method, or header outside its bounded project", () => {
  assert.equal(validateSandboxCorpus(corpus).requestCount, 1);
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [{ ...step, path: step.path.replace("fireemu-oracle-sbx", "fireemu-35fe6") }],
          },
        ],
      }),
    /sandbox project/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [{ ...corpus.restPrograms[0], steps: [{ ...step, method: "DELETE" }] }],
      }),
    /method/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [{ ...step, headers: { authorization: "Bearer secret" } }],
          },
        ],
      }),
    /headers/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          { ...corpus.restPrograms[0], steps: [{ ...step, path: `${step.path}/../../other` }] },
        ],
      }),
    /path traversal/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [
              {
                ...step,
                body: { documents: ["projects/fireemu-35fe6/databases/(default)/documents/c/x"] },
              },
            ],
          },
        ],
      }),
    /request body escaped/,
  );
});

test("two recordings must agree row by row before a fixture can be frozen", () => {
  const first = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const second = { "writes/control": { steps: { read: { code: "NOT_FOUND", status: 404 } } } };
  assert.deepEqual(compareRecordings(first, second), []);
  second["writes/control"].steps.read.status = 200;
  assert.deepEqual(compareRecordings(first, second), ["writes/control#read"]);
  assert.throws(
    () =>
      freezeSandboxFixture({
        corpus,
        first,
        second,
        recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
        harnessRevision: "a".repeat(40),
        sdkVersions: { firebaseAdmin: "14.3.2" },
      }),
    /nondeterministic/,
  );
  const unavailable = { "writes/control": { steps: { read: { status: 0, code: "no-response" } } } };
  assert.throws(
    () =>
      freezeSandboxFixture({
        corpus,
        first: unavailable,
        second: unavailable,
        recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
        harnessRevision: "a".repeat(40),
        sdkVersions: { firebaseAdmin: "14.3.2" },
      }),
    /failed observation/,
  );
});

test("fixture binds recipe and time while omitting the real project and token", () => {
  const observed = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const fixture = freezeSandboxFixture({
    corpus,
    first: observed,
    second: observed,
    recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
    harnessRevision: "a".repeat(40),
    sdkVersions: { firebaseAdmin: "14.3.2" },
  });
  assert.match(fixture.evidence.corpusSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(fixture.evidence.recordedAt, ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"]);
  assert.equal(fixture.evidence.project, "demo-firestore-probe");
  assert.deepEqual(fixture.programs, observed);
  assert.ok(!JSON.stringify(fixture).includes("fireemu-oracle-sbx"));
});
