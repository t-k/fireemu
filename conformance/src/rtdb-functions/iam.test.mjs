// The project's IAM bindings before and after the run: a deploy of event-triggered functions can add
// roles for the default service accounts and the service agents. They are reported (masked), never
// reverted by the recorder; a binding that disappeared is not expected and is a reason.

import assert from "node:assert/strict";
import { test } from "node:test";

import { diffPairs, policyPairs, readProjectIam } from "./iam.mjs";

const policy = (bindings) => ({ bindings });

test("a policy is the sorted set of role and member pairs, with conditions kept in the pair", () => {
  assert.deepEqual(
    policyPairs(
      policy([
        { role: "roles/b", members: ["user:z", "user:a"] },
        { role: "roles/a", members: ["user:a", "user:a"] },
        { role: "roles/c", members: ["user:q"], condition: { title: "t", expression: "e" } },
      ]),
    ),
    [
      "roles/a|user:a",
      "roles/b|user:a",
      "roles/b|user:z",
      'roles/c|user:q|{"expression":"e","title":"t"}',
    ],
  );
  assert.deepEqual(policyPairs(policy([])), []);
  assert.deepEqual(policyPairs({}), []);
  for (const bad of [
    null,
    { bindings: "x" },
    { bindings: [{ role: 3, members: [] }] },
    { bindings: [{ role: "r", members: "m" }] },
  ]) {
    assert.throws(() => policyPairs(bad), /IAM policy/);
  }
});

test("the difference names what a deploy added and what disappeared", () => {
  assert.deepEqual(diffPairs(["a|1", "b|2"], ["a|1", "b|2", "c|3"]), {
    added: ["c|3"],
    removed: [],
  });
  assert.deepEqual(diffPairs(["a|1", "b|2"], ["a|1"]), { added: [], removed: ["b|2"] });
  assert.deepEqual(diffPairs(["a|1"], ["a|1"]), { added: [], removed: [] });
});

test("the policy is read with one POST of the project, version 3", async () => {
  const calls = [];
  const control = async (method, url, body, kind) => {
    calls.push([method, url, body, kind]);
    return { status: 200, value: policy([{ role: "roles/x", members: ["serviceAccount:s"] }]) };
  };
  const pairs = await readProjectIam(control, "424242424242");
  assert.deepEqual(pairs, ["roles/x|serviceAccount:s"]);
  assert.deepEqual(calls, [
    [
      "POST",
      "https://cloudresourcemanager.googleapis.com/v3/projects/424242424242:getIamPolicy",
      { options: { requestedPolicyVersion: 3 } },
      "control",
    ],
  ]);
  await assert.rejects(() => readProjectIam(control, "not-a-number"), /project number/);
});
