// Whether a deploy that failed made nothing or may have made something. firebase-tools prints the HTTP
// error of a refused create; when the CLI ended by itself and that error is a definite 4xx on this
// function's own create, nothing was created and the deploy is `refused`. Anything else (a killed CLI,
// no such line, a 5xx or a retryable code, a success line, another function) stays `unknown`.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import { classifyDeployFailure } from "./deploy-outcome.mjs";
import { TARGETS } from "./targets.mjs";

const v2 = TARGETS.find((t) => t.functionName === "rtdbCreatedV2");
const v1 = TARGETS.find((t) => t.functionName === "rtdbCreatedV1");
const url2 = (name = "rtdbCreatedV2") =>
  `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions?functionId=${name}`;
const url1 = `https://cloudfunctions.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/functions`;
const line = (url, code, text = "Validation failed") =>
  `⚠  functions: Request to ${url} had HTTP Error: ${code}, ${text} `;

// the refused create of CV14 run 2026-10-27 (deploy 5), as the CLI printed it (the paths of the machine left out)
const RECORDED = [
  "i  functions: creating Node.js 22 (2nd Gen) function rtdb-functions-oracle:rtdbCreatedV2(us-central1)... ",
  `⚠  functions: Request to ${url2()} had HTTP Error: 400, Validation failed for trigger projects/${PROJECT}/locations/us-central1/triggers/rtdbcreatedv2-427149: Invalid resource state for "": Permission denied while using the Eventarc Service Agent. If you recently started to use Eventarc, it may take a few minutes before all necessary permissions are propagated to the Service Agent. Otherwise, verify that it has Eventarc Service Agent role. `,
  "⚠  functions: Since this is your first time using 2nd gen functions, we need a little bit longer to finish setting everything up. Retry the deployment in a few minutes. ",
  `⚠  functions:  failed to create function projects/${PROJECT}/locations/us-central1/functions/rtdbCreatedV2 `,
  `Failed to create function projects/${PROJECT}/locations/us-central1/functions/rtdbCreatedV2`,
  "⚠  functions: Deploys failed. Skipping deletes. ",
].join("\n");

const ended = { exited: true, exitCode: 2 };

test("the recorded refusal of a 2nd gen create is `refused`, with the status as evidence", () => {
  const result = classifyDeployFailure({ output: RECORDED, ...ended, spec: v2 });
  assert.equal(result.class, "refused");
  assert.deepEqual(result.evidence, [{ status: 400, create: "rtdbCreatedV2" }]);
});

test("a 1st gen create is recognised by its own URL (no function id in a v1 create)", () => {
  const output = `${line(url1, 403, "Permission denied")}\nFailed to create function projects/${PROJECT}/locations/us-central1/functions/rtdbCreatedV1`;
  assert.equal(classifyDeployFailure({ output, ...ended, spec: v1 }).class, "refused");
  // a 2nd gen URL does not refuse a 1st gen target, and the other way round
  assert.equal(
    classifyDeployFailure({ output: line(url2(), 400), ...ended, spec: v1 }).class,
    "unknown",
  );
  assert.equal(
    classifyDeployFailure({ output: line(url1, 400), ...ended, spec: v2 }).class,
    "unknown",
  );
});

test("everything but a definite 4xx on this function's own create is unknown", () => {
  const cases = [
    ["a killed or timed-out CLI", RECORDED, { exited: false, exitCode: null }],
    ["a CLI that exited 0", RECORDED, { exited: true, exitCode: 0 }],
    [
      "a CLI that did not end by itself, whatever code it reports",
      RECORDED,
      { exited: false, exitCode: 2 },
    ],
    ["no HTTP error at all", "Error: socket hang up\nDeploys failed.", ended],
    ["empty output", "", ended],
    ["a 5xx", line(url2(), 503), ended],
    ["408", line(url2(), 408), ended],
    ["429", line(url2(), 429), ended],
    ["499", line(url2(), 499), ended],
    ["a 3xx", line(url2(), 302), ended],
    ["an error of another function's create", line(url2("rtdbUpdatedV2"), 400), ended],
    ["an error of another call of this function", line(`${url2()}x`, 400), ended],
    ["a refusal after a retry that met a 503", `${line(url2(), 503)}\n${line(url2(), 400)}`, ended],
    [
      "a refusal and a success line",
      `${RECORDED}\n✔  functions[rtdbCreatedV2(us-central1)] Successful create operation. `,
      ended,
    ],
  ];
  for (const [name, output, track] of cases) {
    assert.equal(classifyDeployFailure({ output, ...track, spec: v2 }).class, "unknown", name);
  }
});

test("several definite refusals of the same create are still refused, and the same line twice is one piece of evidence", () => {
  const twice = `${RECORDED}\n    "message": "Request to ${url2()} had HTTP Error: 400, Validation failed"`;
  const result = classifyDeployFailure({ output: twice, ...ended, spec: v2 });
  assert.equal(result.class, "refused");
  assert.equal(result.evidence.length, 1);
  const two = classifyDeployFailure({
    output: `${line(url2(), 400)}\n${line(url2(), 403)}`,
    ...ended,
    spec: v2,
  });
  assert.equal(two.class, "refused");
  assert.deepEqual(
    two.evidence.map((e) => e.status),
    [400, 403],
  );
});

test("the output of an unknown kind never throws", () => {
  for (const output of [undefined, null, 5, {}]) {
    assert.equal(classifyDeployFailure({ output, ...ended, spec: v2 }).class, "unknown");
  }
  assert.equal(
    classifyDeployFailure({ output: RECORDED, spec: v2 }).class,
    "unknown",
    "no CLI track",
  );
});

test("only this project, this region, this generation's URL form and this function name count", () => {
  const other = (url) =>
    classifyDeployFailure({ output: line(url, 400), ...ended, spec: v2 }).class;
  const base = `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions?functionId=rtdbCreatedV2`;
  assert.equal(other(base), "refused");
  assert.equal(other(base.replace(PROJECT, "someone-else")), "unknown");
  assert.equal(other(base.replace("us-central1", "europe-west1")), "unknown");
  assert.equal(other(base.replace("/v2/", "/v1/")), "unknown");
  assert.equal(other(base.replace("?functionId=rtdbCreatedV2", "")), "unknown");
  // for a 1st gen target: the v1 URL without an id only
  const one = (url) => classifyDeployFailure({ output: line(url, 400), ...ended, spec: v1 }).class;
  assert.equal(one(url1), "refused");
  assert.equal(one(url1.replace("/v1/", "/v2/")), "unknown");
  assert.equal(one(`${url1}?functionId=rtdbCreatedV1`), "unknown");
  assert.equal(one(url1.replace(PROJECT, "someone-else")), "unknown");
  assert.equal(one(url1.replace("us-central1", "europe-west1")), "unknown");
});

// Pairwise rows of docs.local/coverage-ledger/pict/cv14-deploy-class.pict (end, own status, extra lines, success
// line, generation), judged against a reference written from the specification, not from the implementation.
const CLASS_ROWS = [
  ["exit2", "s400", "none", "no", "v2"],
  ["exit2", "s400", "none", "no", "v1"],
  ["exit2", "s403", "otherfn503", "no", "v2"],
  ["exit2", "s503", "none", "no", "v2"],
  ["exit2", "none", "none", "no", "v2"],
  ["exit0", "s400", "none", "no", "v2"],
  ["killed", "s400", "none", "no", "v2"],
  ["exit2", "s400", "own503too", "no", "v2"],
  ["exit2", "s400", "none", "yes", "v2"],
  ["exit0", "s409", "own503too", "yes", "v1"],
  ["exit2", "s409", "none", "no", "v2"],
  ["killed", "s409", "otherfn503", "yes", "v1"],
  ["exit0", "s302", "otherfn503", "yes", "v2"],
  ["killed", "s408", "otherfn503", "no", "v1"],
  ["killed", "s400", "otherfn503", "no", "v2"],
  ["exit0", "s429", "otherfn400", "yes", "v1"],
  ["exit0", "s408", "own503too", "yes", "v2"],
  ["killed", "none", "otherfn503", "yes", "v1"],
  ["killed", "s400", "otherfn400", "no", "v2"],
  ["exit2", "s499", "otherfn503", "yes", "v2"],
  ["exit2", "none", "otherfn400", "yes", "v2"],
  ["killed", "s403", "own503too", "yes", "v1"],
  ["exit0", "s503", "own503too", "yes", "v1"],
  ["exit2", "s302", "none", "no", "v1"],
  ["exit0", "s403", "none", "no", "v2"],
  ["killed", "s429", "otherfn503", "no", "v2"],
  ["killed", "s503", "otherfn503", "no", "v1"],
  ["exit2", "s429", "none", "no", "v1"],
  ["exit2", "s408", "none", "yes", "v2"],
  ["exit0", "s408", "otherfn400", "no", "v1"],
  ["exit0", "none", "own503too", "no", "v1"],
  ["killed", "s302", "own503too", "yes", "v2"],
  ["exit0", "s499", "none", "no", "v1"],
  ["exit2", "s503", "otherfn400", "yes", "v2"],
  ["exit2", "s409", "otherfn400", "yes", "v1"],
  ["killed", "s499", "otherfn400", "yes", "v2"],
  ["killed", "s499", "own503too", "yes", "v1"],
  ["killed", "s302", "otherfn400", "yes", "v2"],
  ["killed", "s403", "otherfn400", "no", "v2"],
  ["exit0", "s429", "own503too", "yes", "v2"],
];

const OWN_STATUS = {
  s400: 400,
  s403: 403,
  s409: 409,
  s408: 408,
  s429: 429,
  s499: 499,
  s503: 503,
  s302: 302,
};
const DEFINITE_4XX = new Set([400, 403, 409]);

function classRowOutput([, own, extra, success, gen]) {
  const url = gen === "v1" ? url1 : url2();
  const other = url2("rtdbUpdatedV2");
  const out = ["i  functions: creating function... "];
  if (own !== "none") out.push(line(url, OWN_STATUS[own]));
  if (extra === "otherfn400") out.push(line(other, 400));
  if (extra === "otherfn503") out.push(line(other, 503));
  if (extra === "own503too") out.push(line(url, 503));
  if (success === "yes")
    out.push("✔  functions[rtdbCreatedV2(us-central1)] Successful create operation. ");
  out.push("Deploys failed. ");
  return out.join("\n");
}

function referenceClass([end, own, extra, success]) {
  const refused =
    end === "exit2" &&
    success === "no" &&
    own !== "none" &&
    DEFINITE_4XX.has(OWN_STATUS[own]) &&
    extra !== "own503too";
  return refused ? "refused" : "unknown";
}

test("pairwise rows of end, own status, extra lines, success line and generation agree with the reference", () => {
  assert.ok(CLASS_ROWS.length >= 40);
  for (const row of CLASS_ROWS) {
    const [end, , , , gen] = row;
    const track =
      end === "exit2"
        ? ended
        : end === "exit0"
          ? { exited: true, exitCode: 0 }
          : { exited: false, exitCode: null };
    const result = classifyDeployFailure({
      output: classRowOutput(row),
      ...track,
      spec: gen === "v1" ? v1 : v2,
    });
    assert.equal(result.class, referenceClass(row), row.join(" "));
    if (result.class === "refused")
      assert.deepEqual(
        result.evidence.map((e) => e.status),
        [OWN_STATUS[row[1]]],
        row.join(" "),
      );
  }
});
