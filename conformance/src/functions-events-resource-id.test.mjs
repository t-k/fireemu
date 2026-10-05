// Local scenario ids are the production script's ids in shape and in length.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildResourceId,
  productionCounters,
  resourceId,
} from "./functions-events/resource-id.mjs";
import { SCENARIO_ORDER, buildPass } from "./functions-events/record/script.mjs";

const HEX = "0123456789abcdef01234567";

test("the id is e, 24 hex digits, the role's first letter and the counter", () => {
  assert.equal(buildResourceId("user", 19, HEX), `e${HEX}u19`);
  assert.equal(buildResourceId("fs", 1, HEX), `e${HEX}f1`);
  assert.equal(buildResourceId("obj", 12, HEX), `e${HEX}o12`);
  assert.equal(buildResourceId("msg", 26, HEX), `e${HEX}m26`);
});

test("production formula is unchanged in record/main.mjs, the one the local ids copy", () => {
  const source = readFileSync(
    new URL("./functions-events/record/main.mjs", import.meta.url),
    "utf8",
  );
  assert.ok(
    source.includes('`e${randomBytes(12).toString("hex")}${role.slice(0, 1)}${++n}`'),
    "record/main.mjs builds its ids another way: update resource-id.mjs with it",
  );
});

test("every scenario of the script has the counter its ids get in the first production pass", () => {
  const counters = productionCounters();
  // the same order the runner uses: one counter per id, increasing
  let n = 0;
  const calls = [];
  const { steps } = buildPass({
    pass: 1,
    newId: (role) => {
      n += 1;
      calls.push({ role, n });
      return `e${HEX}${role.slice(0, 1)}${n}`;
    },
  });
  for (const step of steps) {
    const key = `${step.scenarioId}/${step.role}`;
    const ids = JSON.stringify([step.requests, step.matchKey]).match(
      new RegExp(`e${HEX}[a-z](\\d+)`, "g"),
    );
    if (!ids) {
      assert.equal(counters.has(key), false, key);
      continue;
    }
    const first = Math.min(...ids.map((id) => Number(id.slice(`e${HEX}x`.length))));
    assert.equal(counters.get(key), first, key);
  }
  for (const scenario of SCENARIO_ORDER)
    assert.ok(counters.has(`${scenario}/subject`), `${scenario} takes no id`);
  assert.equal(calls.length > 25, true);
});

test("the Auth ids have the production length, so the email and the password provider's uid do too", () => {
  // production (FE v5 run): the Auth uids are 28 characters, the email is the uid and "@example.test" (41)
  for (const scenario of [
    "auth-admin-create",
    "auth-signup",
    "auth-delete",
    "auth-repeat-signin",
  ]) {
    const id = resourceId(scenario, "user");
    assert.equal(id.length, 28, scenario);
    assert.equal(`${id}@example.test`.length, 41, scenario);
    assert.match(id, /^e[0-9a-f]{24}u\d{2}$/);
  }
  const bulk = resourceId("auth-bulk-delete", "user");
  const second = resourceId("auth-bulk-delete", "user", { offset: 1 });
  assert.equal(bulk.length, 28);
  assert.equal(second.length, 28);
  assert.equal(Number(second.match(/u(\d+)$/)[1]), Number(bulk.match(/u(\d+)$/)[1]) + 1);
});

test("ids are random, and the Firestore, Storage and Pub/Sub ids follow the production shape", () => {
  const a = resourceId("fs-create", "fs");
  const b = resourceId("fs-create", "fs");
  assert.notEqual(a, b);
  assert.match(a, /^e[0-9a-f]{24}f\d+$/);
  assert.match(resourceId("storage-upload", "obj"), /^e[0-9a-f]{24}o\d+$/);
  assert.match(resourceId("pubsub-publish", "msg"), /^e[0-9a-f]{24}m\d+$/);
  assert.equal(
    resourceId("storage-delete", "obj", { scenarioRole: "positive-control-after" }).length >= 27,
    true,
  );
  assert.throws(() => resourceId("not-a-scenario", "user"), /takes no id for not-a-scenario/);
});

test("the local drivers build each family's ids with it, under the script's role words", () => {
  const read = (file) =>
    readFileSync(new URL(`./functions-events/${file}`, import.meta.url), "utf8");
  const live = read("live-driver.mjs");
  const storage = read("storage-driver.mjs");
  for (const [source, calls] of [
    [
      live,
      [
        'resourceId(scenario.id, "user")',
        'resourceId(scenario.id, "fs")',
        'resourceId(scenario.id, "msg")',
        'resourceId(scenario.id, "user", { offset: 1 })',
      ],
    ],
    [storage, ['resourceId(scenario.id, "obj")']],
  ])
    for (const call of calls) assert.ok(source.includes(call), call);
  for (const source of [live, storage])
    assert.equal(source.includes('randomUUID().replaceAll("-", "")'), false);
});
