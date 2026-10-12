import assert from "node:assert/strict";
import test from "node:test";
import { createOwnership, isRunId, newRunId, prefixOf } from "./pubsub-production/names.mjs";

const RUN = "0123456789ab";

test("a run ID is twelve lower-case hex digits and the prefix starts with a letter", () => {
  assert.equal(isRunId(RUN), true);
  for (const bad of [
    "",
    "0123456789a",
    "0123456789abc",
    "0123456789AB",
    "01234567 9ab",
    5,
    null,
    undefined,
  ])
    assert.equal(isRunId(bad), false, String(bad));
  assert.equal(prefixOf(RUN), "fe0123456789ab-");
  assert.throws(() => prefixOf("nope"), /12 hex digits/);
  const generated = newRunId();
  assert.equal(isRunId(generated), true);
  assert.notEqual(newRunId(), newRunId());
  assert.equal(
    newRunId(() => Buffer.from([1, 2, 3, 4, 5, 6])),
    "010203040506",
  );
});

test("a resource name is the project, the kind and the prefixed ID, at most 255 characters", () => {
  const own = createOwnership({ project: "demo-project", runId: RUN });
  assert.equal(own.prefix, "fe0123456789ab-");
  assert.equal(own.resource("topics", "t1"), "projects/demo-project/topics/fe0123456789ab-t1");
  assert.equal(
    own.resource("subscriptions", "s1"),
    "projects/demo-project/subscriptions/fe0123456789ab-s1",
  );
  assert.equal(
    own.resource("snapshots", "n1"),
    "projects/demo-project/snapshots/fe0123456789ab-n1",
  );
  const longest = "x".repeat(255 - own.prefix.length);
  assert.equal(own.resource("topics", longest).split("/").at(-1).length, 255);
  assert.throws(() => own.resource("topics", `${longest}x`), /255/);
  assert.throws(() => own.resource("schemas", "x"), /unknown resource kind/);
  assert.throws(() => createOwnership({ project: "Bad Project", runId: RUN }), /project ID/);
  assert.throws(() => createOwnership({ project: "demo-project", runId: "x" }), /12 hex/);
});

test("only the prefixed resources of the project and the registered probes are owned", () => {
  const own = createOwnership({ project: "demo-project", runId: RUN });
  for (const kind of ["topics", "subscriptions", "snapshots"]) {
    assert.equal(own.isOwned(`projects/demo-project/${kind}/fe0123456789ab-x`), true, kind);
    assert.equal(own.isOwned(`projects/demo-project/${kind}/fe0123456789ab-`), true, kind);
    assert.equal(own.isOwned(`projects/demo-project/${kind}/fe0123456789ac-x`), false, kind);
    assert.equal(own.isOwned(`projects/demo-project/${kind}/other`), false, kind);
    assert.equal(own.isOwned(`projects/other-project/${kind}/fe0123456789ab-x`), false, kind);
  }
  for (const bad of [
    "projects/demo-project/schemas/fe0123456789ab-x",
    "projects/demo-project/topics/fe0123456789ab-x/extra",
    "projects/demo-project/topics/fe0123456789ab-x y",
    "projects/demo-project/topics/xfe0123456789ab-x",
    "demo-project/topics/fe0123456789ab-x",
    "projects/demo-project/topics/",
    "",
    5,
    null,
    undefined,
  ])
    assert.equal(own.isOwned(bad), false, String(bad));
  assert.equal(
    own.assertOwned("projects/demo-project/topics/fe0123456789ab-x"),
    "projects/demo-project/topics/fe0123456789ab-x",
  );
  assert.throws(
    () => own.assertOwned("projects/demo-project/topics/other"),
    /not a resource of this run/,
  );
  // Detached from the object, the methods still work.
  const { assertOwned, isOwned } = own;
  assert.equal(isOwned("projects/demo-project/topics/fe0123456789ab-x"), true);
  assert.throws(() => assertOwned("x"), /not a resource of this run/);
});

test("a probe is owned only after it is registered, and only as one name of the project", () => {
  const own = createOwnership({ project: "demo-project", runId: RUN });
  const probe = "projects/demo-project/topics/ab";
  assert.equal(own.isOwned(probe), false);
  assert.equal(own.registerProbe(probe), probe);
  assert.equal(own.isOwned(probe), true);
  assert.equal(own.isOwned("projects/demo-project/topics/abc"), false);
  assert.deepEqual(own.probes(), [probe]);
  for (const bad of [
    "ab",
    "projects/other-project/topics/ab",
    "projects/demo-project/topics/a/b",
    "projects/demo-project/schemas/ab",
    "projects/demo-project/topics/",
    5,
    null,
  ])
    assert.throws(() => own.registerProbe(bad), /probe/, String(bad));
  assert.deepEqual(own.probes(), [probe]);
});
