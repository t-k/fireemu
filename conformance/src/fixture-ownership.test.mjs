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
