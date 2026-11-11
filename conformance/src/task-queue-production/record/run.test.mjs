// The orchestrator against the in-memory world: the clean run, what stops it before anything is created, and the shape of
// what it sends and records.
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { PROGRAM } from "../corpus.mjs";
import { functionsOf, packageIds } from "../plan.mjs";
import { RUN, count, emptyWorld, go, mutations } from "./harness.mjs";
import { MAX_REQUESTS } from "./run.mjs";

test("a clean run records, cleans up, reads every name back and may close", async () => {
  const { world, result, journal } = await go();
  assert.equal(result.outcome, "tq-recorded");
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.unknown, 0);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.ok(emptyWorld(world), "nothing of the run is left");
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.cleanup.listsEmpty, true);
  assert.equal(result.cleanup.functionsGone, true);
  assert.ok(Object.values(result.cleanup.readBack).every((v) => v === true));
  const labels = Object.keys(result.cleanup.readBack);
  for (const fn of functionsOf(RUN)) {
    assert.ok(labels.includes("function-" + fn));
    assert.ok(labels.includes("queue-" + fn));
    for (const id of packageIds(fn)) assert.ok(labels.includes("package-" + id));
  }
  assert.ok(result.attempted <= MAX_REQUESTS);
  assert.equal(
    journal.filter((r) => r.status >= 400 && r.status !== 404 && r.status !== 409).length,
    journal.filter((r) => r.status === 400).length,
    "only the probes of the program are refused, and only with 4xx",
  );
  assert.equal(
    JSON.stringify(journal).includes("test-token-abcdefgh"),
    false,
    "the token is never journaled",
  );
});

test("every step of the program is sent once and recorded under its key", async () => {
  const { world, result } = await go();
  assert.deepEqual(
    Object.keys(result.program),
    PROGRAM.map((s) => s.key),
  );
  for (const step of Object.values(result.program)) assert.equal(step.sent, true);
  const creates = world.calls.filter((c) => /^POST cloudtasks\.googleapis\.com.*\/tasks$/.test(c));
  assert.equal(creates.length, PROGRAM.filter((s) => s.kind === "create").length);
  assert.equal(
    count(world, "DELETE cloudtasks.googleapis.com"),
    0 + count(world, "DELETE cloudtasks.googleapis.com"),
  );
  assert.ok(mutations(world).length > 0);
});
