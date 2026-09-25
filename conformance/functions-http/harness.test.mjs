import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  BOUNDS,
  buildInvocation,
  createBudget,
  expectedFunctionName,
  invalidSignatureToken,
  localExpiredToken,
  normalizeInvocation,
  validateCorpus,
  validateFunctionRecord,
  withPublicInvoker,
} from "./harness.mjs";

const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));
const clone = (value) => structuredClone(value);

test("the pinned corpus has exactly the reviewed functions and 136 invocations", () => {
  assert.deepEqual(validateCorpus(corpus), { programs: 15, cases: 68, deployments: 16, invocations: 136 });
  assert.equal(expectedFunctionName("http"), "fireemuHttpProbe");
  assert.equal(expectedFunctionName("callable"), "fireemuCallableProbe");
});

test("corpus validation rejects a destination or request outside the reviewed scope", () => {
  const changedProject = clone(corpus);
  changedProject.project = "other-project";
  assert.throws(() => validateCorpus(changedProject), /project/);

  const externalPath = clone(corpus);
  externalPath.programs[0].cases[0].request.path = "https://other.example/";
  assert.throws(() => validateCorpus(externalPath), /path/);

  const extraHeader = clone(corpus);
  extraHeader.programs[0].cases[0].request.headers.authorization = "Bearer secret";
  assert.throws(() => validateCorpus(extraHeader), /authorization/);

  const extraCase = clone(corpus);
  extraCase.programs[0].cases.push(clone(extraCase.programs[0].cases[0]));
  assert.throws(() => validateCorpus(extraCase), /duplicate|68/);
});

test("request ceilings keep cleanup available after observation exhaustion", () => {
  const budget = createBudget();
  for (let n = 0; n < BOUNDS.invocations; n += 1) budget.take("invocation");
  assert.throws(() => budget.take("invocation"), /ceiling/);
  budget.take("cleanup");
  assert.equal(budget.snapshot().invocation, BOUNDS.invocations);
  assert.equal(budget.snapshot().cleanup, 1);
});

test("a deployed function must resolve to the owned project, region, service and HTTPS URL", () => {
  const record = {
    name: "projects/fireemu-oracle-query/locations/us-central1/functions/fireemuHttpProbe",
    environment: "GEN_2",
    buildConfig: { runtime: "nodejs22", entryPoint: "fireemuHttpProbe" },
    serviceConfig: {
      service: "projects/fireemu-oracle-query/locations/us-central1/services/fireemuhttpprobe",
      uri: "https://fireemuhttpprobe-abc-uc.a.run.app",
    },
  };
  assert.equal(validateFunctionRecord(record, "http"), record.serviceConfig.uri);
  assert.throws(
    () => validateFunctionRecord({ ...record, serviceConfig: { ...record.serviceConfig, uri: "https://evil.example" } }, "http"),
    /URL/,
  );
  assert.throws(
    () => validateFunctionRecord({ ...record, name: record.name.replace("fireemu-oracle-query", "other") }, "http"),
    /name/,
  );
});

test("public invoker update touches only the owned service binding", () => {
  const original = { version: 3, etag: "BwAA", bindings: [{ role: "roles/run.viewer", members: ["user:owner@example.com"] }] };
  const updated = withPublicInvoker(original);
  assert.deepEqual(original.bindings, [{ role: "roles/run.viewer", members: ["user:owner@example.com"] }]);
  assert.equal(updated.etag, "BwAA");
  assert.deepEqual(updated.bindings[1], { role: "roles/run.invoker", members: ["allUsers"] });
  assert.deepEqual(withPublicInvoker(updated), updated);
  assert.throws(
    () => withPublicInvoker({ ...original, bindings: [{ role: "roles/editor", members: ["allUsers"] }] }),
    /allUsers/,
  );
});

test("recorded invocation omits unstable and secret response fields", () => {
  const bytes = Buffer.from(JSON.stringify({ result: { marker: "bounded" }, token: "secret" }));
  const response = normalizeInvocation(200, {
    "content-type": "application/json; charset=utf-8",
    "date": "Fri, 25 Sep 2026 00:00:00 GMT",
    "x-cloud-trace-context": "private",
  }, bytes);
  assert.equal(response.status, 200);
  assert.equal(response.headers["content-type"], "application/json; charset=utf-8");
  assert.equal(response.headers.date, undefined);
  assert.equal(response.headers["x-cloud-trace-context"], undefined);
  assert.equal(response.body.token, undefined);
});

test("request construction substitutes only reviewed token placeholders", () => {
  const step = corpus.programs.find((p) => p.id.endsWith("auth-context")).cases[1];
  const request = buildInvocation(step, "https://fireemucallableprobe-abc-uc.a.run.app", {
    idToken: "private-token",
  });
  assert.equal(request.url, "https://fireemucallableprobe-abc-uc.a.run.app/");
  assert.equal(request.init.headers.authorization, "Bearer private-token");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.redirect, "manual");
  assert.equal(JSON.parse(request.init.body).data.op, "auth");
  assert.throws(() => buildInvocation(step, "https://evil.example", {}), /missing token/);
});

test("invalid signatures preserve claims and local expiry cannot alter signed production tokens", () => {
  const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
  const payload = Buffer.from('{"iat":100,"exp":3700,"sub":"one"}').toString("base64url");
  const unsigned = `${header}.${payload}.`;
  const expired = localExpiredToken(unsigned, 200);
  assert.equal(JSON.parse(Buffer.from(expired.split(".")[1], "base64url")).exp, 199);
  const signed = `${header}.${payload}.signature`;
  assert.throws(() => localExpiredToken(signed, 200), /unsigned/);
  const invalid = invalidSignatureToken(signed);
  assert.deepEqual(invalid.split(".").slice(0, 2), signed.split(".").slice(0, 2));
  assert.notEqual(invalid, signed);
});
