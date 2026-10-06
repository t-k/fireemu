// The v7 judges over what the v6 run recorded (docs.local/runs/functions-events-formal-20261005T002351Z-8cb9bf695034a475):
// the CLI's own summary of the deploy that exited 2 with "3 Functions Errored", the delete that exited 0 with "1 Functions
// Errored", and the shapes of the Gen1 operations (a delete's answer and its done poll, a failed create). The committed copies
// are the CLI's lines and the API bodies as recorded (the failed operation trimmed to its code and message: its details are
// Google-internal stack frames); no project number appears in them.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { cliFailed, erroredFunctions } from "./functions-events/record/deploy.mjs";
import { restDeleteLeftovers } from "./functions-events/record/cleanup.mjs";
import { destination } from "./functions-events/record/guard.mjs";

const recorded = (name) =>
  readFileSync(
    new URL(`./functions-events/record/recorded/v6-run/${name}`, import.meta.url),
    "utf8",
  );
const json = (name) => JSON.parse(recorded(name));
const P = "fireemu-oracle-events";

test("the v6 deploy's summary is 3 errored functions, and with its exit code 2 the deploy failed", () => {
  const tail = recorded("cli-deploy-tail.txt");
  assert.match(tail, /22 Functions Deployed/);
  assert.equal(erroredFunctions(tail), 3);
  assert.equal(cliFailed({ exitCode: 2, errored: erroredFunctions(tail) }), true);
  // the count alone fails it too (an exit code of 0 is not enough: v4's delete said so)
  assert.equal(cliFailed({ exitCode: 0, errored: erroredFunctions(tail) }), true);
  // the three names are the Gen1 Storage functions that were not the first
  assert.deepEqual(
    [...tail.matchAll(/Failed to create function (\w+) in region/g)].map((match) => match[1]),
    ["storageDeletedV1", "storageMetadataUpdatedV1", "storageArchivedV1"],
  );
});

test("the v6 delete's summary is 1 errored function with exit code 0, which still counts as failed (the v4 shape)", () => {
  const tail = recorded("cli-delete-tail.txt");
  assert.equal(erroredFunctions(tail), 1);
  assert.equal(cliFailed({ exitCode: 0, errored: erroredFunctions(tail) }), true);
});

test("a deploy of one function that the CLI reports with 0 errored and exit 0 is not a failure; the same count on its own line is read", () => {
  assert.equal(
    cliFailed({
      exitCode: 0,
      errored: erroredFunctions("[t] 1 Functions Deployed\n[t] 0 Functions Errored\n"),
    }),
    false,
  );
  assert.equal(erroredFunctions("[t] 1 Functions Deployed\n"), null, "no count is not zero");
});

test("the recorded Gen1 delete answer and its done poll are what the REST cleanup follows", async () => {
  const answer = json("gen1-delete-response.json");
  const done = json("gen1-operation-done.json");
  const target = `projects/${P}/locations/us-central1/functions/storageMetadataUpdatedV1`;
  assert.equal(answer.metadata.target, target);
  assert.match(answer.name, /^operations\/[A-Za-z0-9_-]{159}$/);
  // the guard allows exactly this operation read: the real id is 159 characters
  assert.equal(
    destination({
      method: "GET",
      url: `https://cloudfunctions.googleapis.com/v1/${answer.name}`,
      mutation: false,
    }).rule,
    "functions-v1-operation-get",
  );
  const sent = [];
  const request = async (spec) => {
    sent.push([spec.method, spec.url]);
    if (spec.method === "DELETE") return { kind: "success", status: 200, json: answer };
    return { kind: "success", status: 200, json: { ...done, name: answer.name } };
  };
  const result = await restDeleteLeftovers({
    request,
    sleep: async () => {},
    lists: { v1: { items: [{ name: target }], complete: true } },
  });
  assert.deepEqual(sent, [
    ["DELETE", `https://cloudfunctions.googleapis.com/v1/${target}`],
    ["GET", `https://cloudfunctions.googleapis.com/v1/${answer.name}`],
  ]);
  assert.deepEqual(result, [
    {
      name: "storageMetadataUpdatedV1",
      generation: 1,
      delete: { status: 200, kind: "success" },
      polls: 1,
      error: null,
    },
  ]);
});

test("the recorded failed Gen1 create is a done operation with an error, which a delete's poll would report as the entry's error", async () => {
  const failed = json("gen1-operation-failed.json");
  assert.equal(failed.done, true);
  assert.equal(failed.error.code, 13);
  assert.match(
    failed.error.message,
    /Failed to configure trigger providers\/cloud\.storage\/eventTypes\/object\.change/,
  );
  assert.equal(failed.metadata.type, "CREATE_FUNCTION");
  // the cleanup keeps such an error on the entry (the run then needs recovery)
  const target = `projects/${P}/locations/us-central1/functions/storageDeletedV1`;
  const answer = { name: failed.name, metadata: { target } };
  const request = async (spec) =>
    spec.method === "DELETE"
      ? { kind: "success", status: 200, json: answer }
      : { kind: "success", status: 200, json: failed };
  const result = await restDeleteLeftovers({
    request,
    sleep: async () => {},
    lists: { v1: { items: [{ name: target }], complete: true } },
  });
  assert.equal(result[0].error.code, 13);
});

test("no project number appears in the committed v6 copies", () => {
  for (const name of [
    "cli-deploy-tail.txt",
    "cli-delete-tail.txt",
    "gen1-delete-response.json",
    "gen1-operation-done.json",
    "gen1-operation-failed.json",
  ])
    assert.doesNotMatch(recorded(name), /\b\d{12}\b/, name);
});
