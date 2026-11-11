// The named FUNCTIONS-HTTP fixtures are deleted by their codebase-qualified id, and the name-collision preflight
// that makes that delete safe applies to them as to a spec (presend review of the re-record, Codex finding 5).
import assert from "node:assert/strict";
import { test } from "node:test";

import * as production from "./production.mjs";

test("a named fixture is deleted by its codebase-qualified id, and a spec by its exact resource", async () => {
  const { targetResources } = production;
  for (const [target, name] of [
    ["http", "fireemuHttpProbe"],
    ["callable", "fireemuCallableProbe"],
  ]) {
    assert.deepEqual(targetResources(target).deleteArgs, [
      "functions:delete",
      `functions-http-oracle:${name}`,
      "--region",
      "us-central1",
      "--force",
    ]);
  }
  const spec = {
    functionName: "fireemuSpecProbe",
    region: "us-central1",
    codebase: "spec-oracle",
    generation: "gcfv2",
  };
  assert.equal(targetResources(spec).deleteArgs, null);
});

test("the preflight refuses a named fixture while any function of the region would match the CLI's filter", async () => {
  const listed = (functions) => async (method, url) => {
    if (url.includes("/functions?")) return { status: 200, value: { functions }, bytes: 2 };
    return { status: 404, value: {}, bytes: 2 };
  };
  const named = (id, labels) => ({
    name: `projects/fireemu-oracle-query/locations/us-central1/functions/${id}`,
    ...(labels ? { labels } : {}),
  });
  for (const target of ["http", "callable"]) {
    const name = target === "http" ? "fireemuHttpProbe" : "fireemuCallableProbe";
    await production.assertNoNameCollisions(
      listed([named("unrelated"), named("fireemuOther")]),
      target,
    );
    await assert.rejects(
      production.assertNoNameCollisions(listed([named(`${name}-sibling`)]), target),
      /collides with the function/,
    );
    await assert.rejects(
      production.assertNoNameCollisions(listed([named(name)]), target),
      /collides with the function/,
    );
    await assert.rejects(
      production.assertNoNameCollisions(
        listed([named("other", { "firebase-functions-codebase": name })]),
        target,
      ),
      /equals the codebase/,
    );
    // assertTargetAbsent runs the same check for a named fixture, after the absence reads
    const control = async (method, url) => {
      if (url.includes("/functions?"))
        return { status: 200, value: { functions: [named(`${name}-sibling`)] }, bytes: 2 };
      return { status: 404, value: {}, bytes: 2 };
    };
    await assert.rejects(
      production.assertTargetAbsent(control, target),
      /collides with the function/,
    );
  }
});
