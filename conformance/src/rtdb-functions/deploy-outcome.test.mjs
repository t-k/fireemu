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
