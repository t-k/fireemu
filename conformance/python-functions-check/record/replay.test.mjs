// The readiness, cleanup and absence judges replayed on real recorded bodies of the same routes: the Cloud Functions v2
// list (with the first-generation functions in it, as production returns them), the Cloud Run services list, the
// not-found layouts of Cloud Scheduler and Pub/Sub, and the 409 a job delete gets right after a run. The bodies are
// the scheduled-delivery recorder's recorded fixtures (events project, with project numbers replaced).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { allActive, nonePresent, summarize } from "./deploy.mjs";
import { ALL_FUNCTIONS, REGION, functionName } from "./plan.mjs";
import { absent, isBusy } from "./run.mjs";

const recorded = JSON.parse(
  readFileSync(
    new URL("../../scheduled-delivery/fixtures/delivery-recorded.json", import.meta.url),
    "utf8",
  ),
).answers;
const v2 = recorded.gcfV2List.body;
const services = recorded.runServicesList.body;
const answer = (r) => ({ status: r.status, json: r.body });

test("the recorded v2 list is large, mixes generations, and holds none of this check's functions", () => {
  assert.ok(v2.functions.length > 20);
  assert.ok(
    v2.functions.some((f) => f.environment === "GEN_1") &&
      v2.functions.some((f) => f.environment === "GEN_2"),
  );
  const summary = summarize({ v2, run: services });
  assert.equal(nonePresent(summary), true);
  assert.equal(allActive(summary), false);
});

test("this check's functions, added to the recorded lists in the recorded shape, are ready and then present", () => {
  const mine = ALL_FUNCTIONS.map((fn) => ({
    name: functionName(fn),
    state: "ACTIVE",
    environment: "GEN_2",
  }));
  const mineServices = ALL_FUNCTIONS.map((fn) => ({
    name: `projects/fireemu-oracle-events/locations/${REGION}/services/${fn}`,
  }));
  const summary = summarize({
    v2: { functions: [...v2.functions, ...mine] },
    run: { services: [...services.services, ...mineServices] },
  });
  assert.equal(allActive(summary), true);
  assert.equal(nonePresent(summary), false);
  const deploying = summarize({
    v2: { functions: [...v2.functions, ...mine.map((f) => ({ ...f, state: "DEPLOYING" }))] },
    run: { services: [...services.services, ...mineServices] },
  });
  assert.equal(allActive(deploying), false, "an output-only state is not ready");
});

test("the recorded not-found layouts of Scheduler and Pub/Sub are absence, and a job that exists is not", () => {
  for (const key of [
    "schedulerAbsentPlain",
    "schedulerAbsentDetailed",
    "topicAbsent",
    "subscriptionAbsent",
  ])
    assert.equal(absent(answer(recorded[key])), true, key);
  assert.equal(absent(answer(recorded.schedulerJobCreated)), false);
  assert.equal(absent(answer(recorded.schedulerJobDeleted)), false);
  assert.equal(absent(answer(recorded.emptyList)), false);
});

test("the recorded 409 of a job delete right after a run is the busy answer", () => {
  assert.equal(isBusy(answer(recorded.schedulerBusy409)), true);
  assert.equal(isBusy(answer(recorded.schedulerAbsentPlain)), false);
});
