// Reading and writing the committed fixtures.
//
// A fixture is the recorded outcome of one scenario: for every step, either the single value
// both sides produced (`parity`), or both values plus why they differ, or the reason no local
// oracle can answer it. Files are written with a fixed key order and two-space indentation so
// that re-recording an unchanged corpus produces a byte-identical tree.

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { FIXTURES_DIR, STATUS } from "./config.mjs";

export const SCHEMA_VERSION = 1;

/** `firestore/values-and-ordering` -> `fixtures/firestore/values-and-ordering.json`. */
export const fixturePath = (scenarioId) => join(FIXTURES_DIR, `${scenarioId}.json`);

const STEP_KEY_ORDER = [
  "id",
  "status",
  "value",
  "oracle",
  "testd",
  "documents",
  "reason",
  "production",
];
const FIXTURE_KEY_ORDER = [
  "schemaVersion",
  "id",
  "product",
  "title",
  "sdks",
  "variant",
  "oracle",
  "summary",
  "steps",
];

const ordered = (object, order) => {
  const out = {};
  for (const key of order) if (object[key] !== undefined) out[key] = object[key];
  for (const key of Object.keys(object).toSorted()) if (!(key in out)) out[key] = object[key];
  return out;
};

/** The per-status counts a fixture carries so a reader sees the tally without diffing. */
export function summarize(steps) {
  const summary = {};
  for (const status of Object.values(STATUS)) summary[status] = 0;
  for (const step of steps) summary[step.status] += 1;
  return summary;
}

export async function writeFixture(fixture) {
  const path = fixturePath(fixture.id);
  await mkdir(dirname(path), { recursive: true });
  const body = ordered(
    {
      ...fixture,
      schemaVersion: SCHEMA_VERSION,
      steps: fixture.steps.map((s) => ordered(s, STEP_KEY_ORDER)),
    },
    FIXTURE_KEY_ORDER,
  );
  await writeFile(path, `${JSON.stringify(body, null, 2)}\n`, "utf8");
  return path;
}

export async function readFixture(scenarioId) {
  const text = await readFile(fixturePath(scenarioId), "utf8");
  const fixture = JSON.parse(text);
  if (fixture.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `${scenarioId}: fixture schemaVersion ${fixture.schemaVersion} is not supported`,
    );
  }
  return fixture;
}

/** Every fixture on disk, keyed by scenario id. */
export async function readAllFixtures() {
  const found = new Map();
  const walk = async (dir, prefix) => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.toSorted((a, b) => (a.name < b.name ? -1 : 1))) {
      if (entry.isDirectory()) {
        await walk(join(dir, entry.name), `${prefix}${entry.name}/`);
      } else if (entry.name.endsWith(".json")) {
        const id = `${prefix}${entry.name.slice(0, -".json".length)}`;
        found.set(id, await readFixture(id));
      }
    }
  };
  await walk(FIXTURES_DIR, "");
  return found;
}
