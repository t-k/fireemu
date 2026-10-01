import assert from "node:assert/strict";
import { test } from "node:test";

import { fixtureOwnershipFailures } from "./fixture-ownership.mjs";

const fixture = (id, ownership) => [id, { id, ownership }];

test("an orphan owned by the executable corpus fails", () => {
  const fixtures = new Map([fixture("auth/removed-scenario")]);

  assert.deepEqual(fixtureOwnershipFailures(fixtures, []), [
    "auth/removed-scenario: a fixture exists but the corpus no longer declares the scenario",
  ]);
});

test("an explicitly external oracle fixture does not become a local orphan", () => {
  const fixtures = new Map([fixture("auth/production-evidence", "external-oracle")]);

  assert.deepEqual(fixtureOwnershipFailures(fixtures, []), []);
});

test("every declared scenario is included without a variant allowlist", () => {
  const fixtures = new Map([fixture("auth/baseline"), fixture("firestore/future-variant")]);
  const scenarios = [
    { id: "auth/baseline", variant: "baseline" },
    { id: "firestore/future-variant", variant: "future-variant" },
  ];

  assert.deepEqual(fixtureOwnershipFailures(fixtures, scenarios), []);
});

test("unknown fixture ownership fails closed", () => {
  const fixtures = new Map([fixture("auth/mistyped-owner", "external-orcale")]);

  assert.deepEqual(fixtureOwnershipFailures(fixtures, []), [
    "auth/mistyped-owner: unsupported fixture ownership external-orcale",
  ]);
});

// A dataset a lane records and compares with its own tool (its fixtures have their own schema) is
// listed by directory and by the comparer that owns it. The list is explicit: a directory that is not on
// it is still checked against the corpus.
const DATASETS = [{ directory: "own-dataset-production", comparer: "src/own-dataset/run.mjs" }];
const present = () => true;

test("a fixture of a listed dataset with its own comparer is not a local orphan", () => {
  const fixtures = new Map([
    fixture("own-dataset-production/errors--missing"),
    fixture("own-dataset-production/nested/deeper"),
  ]);

  assert.deepEqual(
    fixtureOwnershipFailures(fixtures, [], { datasets: DATASETS, exists: present }),
    [],
  );
});

test("with several datasets, a fixture of any one of them is owned", () => {
  const datasets = [
    { directory: "first-dataset", comparer: "src/first/run.mjs" },
    { directory: "second-dataset", comparer: "src/second/run.mjs" },
  ];
  const fixtures = new Map([fixture("second-dataset/a"), fixture("third-dataset/a")]);

  assert.deepEqual(fixtureOwnershipFailures(fixtures, [], { datasets, exists: present }), [
    "third-dataset/a: a fixture exists but the corpus no longer declares the scenario",
  ]);
});

test("a directory that is not on the list is still checked, whatever its name resembles", () => {
  const fixtures = new Map([
    fixture("own-dataset-production-copy/a"),
    fixture("own-dataset-productio/a"),
    fixture("other/own-dataset-production/a"),
  ]);

  assert.deepEqual(
    fixtureOwnershipFailures(fixtures, [], { datasets: DATASETS, exists: present }),
    [
      "own-dataset-production-copy/a: a fixture exists but the corpus no longer declares the scenario",
      "own-dataset-productio/a: a fixture exists but the corpus no longer declares the scenario",
      "other/own-dataset-production/a: a fixture exists but the corpus no longer declares the scenario",
    ],
  );
});

test("a listed dataset whose comparer does not exist fails the gate, with or without fixtures", () => {
  const missing = (path) => path !== "src/own-dataset/run.mjs";

  assert.deepEqual(
    fixtureOwnershipFailures(new Map(), [], { datasets: DATASETS, exists: missing }),
    [
      "own-dataset-production: its comparer src/own-dataset/run.mjs does not exist, so nothing owns these fixtures",
    ],
  );
  assert.deepEqual(
    fixtureOwnershipFailures(new Map([fixture("own-dataset-production/a")]), [], {
      datasets: DATASETS,
      exists: missing,
    }),
    [
      "own-dataset-production: its comparer src/own-dataset/run.mjs does not exist, so nothing owns these fixtures",
    ],
  );
});

test("a dataset fixture does not hide a mistyped ownership", () => {
  const fixtures = new Map([fixture("own-dataset-production/a", "external-orcale")]);

  assert.deepEqual(
    fixtureOwnershipFailures(fixtures, [], { datasets: DATASETS, exists: present }),
    ["own-dataset-production/a: unsupported fixture ownership external-orcale"],
  );
});

test("the repository's list names datasets and comparers that exist", async () => {
  const { existsSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { CONFORMANCE_DIR, FIXTURES_DIR } = await import("./config.mjs");
  const { OWN_COMPARER_DATASETS } = await import("./fixture-ownership.mjs");

  assert.ok(OWN_COMPARER_DATASETS.length > 0);
  for (const { directory, comparer } of OWN_COMPARER_DATASETS) {
    assert.match(directory, /^[a-z0-9-]+$/, directory);
    assert.ok(existsSync(join(FIXTURES_DIR, directory)), `${directory} is not under fixtures/`);
    assert.ok(existsSync(join(CONFORMANCE_DIR, comparer)), `${comparer} does not exist`);
  }
  assert.deepEqual(fixtureOwnershipFailures(new Map(), []), []);
});
