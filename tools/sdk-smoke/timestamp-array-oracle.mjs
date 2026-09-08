// Exact REST timestamp array regression; production expectations observed 2026-09-08.
// Production: set PRODUCTION_ORACLE_PROJECT_ID and EXPECTED_PROJECT_NUMBER as below.
// Local: set FIRESTORE_EMULATOR_HOST to a loopback Firestore REST endpoint.
// Output includes precise wire inputs, stored values, and update times. Only owned
// UUID fixture documents are deleted; no collection enumeration is performed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const host = process.env.FIRESTORE_EMULATOR_HOST;
const project = host ? "demo-app" : process.env.PRODUCTION_ORACLE_PROJECT_ID;
let token;
let origin = "https://firestore.googleapis.com";
if (host) {
  const url = new URL(`http://${host}`);
  assert(["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
  assert.equal(url.username, "");
  assert.equal(url.password, "");
  assert.equal(url.pathname, "/");
  assert.equal(url.search, "");
  assert.equal(url.hash, "");
  origin = url.origin;
  token = "owner";
} else {
  assert.equal(project, "fireemu-35fe6");
  assert.equal(process.env.PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER, "592603257417");
  token = execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function request(url, body, method = body ? "POST" : "GET") {
  const response = await fetch(url, {
    method,
    redirect: "error",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  assert(response.ok, `${method} ${url}: ${response.status} ${text}`);
  return text ? JSON.parse(text) : {};
}
if (!host) {
  const selected = await request(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${project}`,
  );
  assert.equal(selected.projectNumber, "592603257417");
}
const root = `${origin}/v1/`;
const database = `projects/${project}/databases/(default)`;
const base = `${root}${database}/documents`;
const owned = [];
const results = [];
const timestamp = (precision) => ({ timestampValue: `2026-09-01T00:00:00.${precision}Z` });
try {
  for (const shape of ["timestamp", "map", "nested"]) {
    for (const precision of ["123456789", "123456"]) {
      const wrap = (value) =>
        shape === "timestamp"
          ? value
          : shape === "map"
            ? { mapValue: { fields: { at: value } } }
            : {
                mapValue: {
                  fields: {
                    nested: { arrayValue: { values: [{ mapValue: { fields: { at: value } } }] } },
                  },
                },
              };
      const item = wrap(timestamp(precision));
      const other = wrap(timestamp("123456001"));
      const stored = wrap(timestamp("123456"));
      const name = `${database}/documents/timestamp_array_review/${randomUUID()}`;
      const transform = (remove, values) => ({
        fieldPath: "values",
        [remove ? "removeAllFromArray" : "appendMissingElements"]: { values },
      });
      const update = (values) => ({ name, fields: { values: { arrayValue: { values } } } });
      // Only record ownership after an exclusive create succeeds.
      await request(`${base}:commit`, {
        writes: [{ update: update([]), currentDocument: { exists: false } }],
      });
      owned.push(name);
      const operations = [
        ...[1, 2, 3].map((n) => [
          `union${n}`,
          { transform: { document: name, fieldTransforms: [transform(false, [item])] } },
          [stored],
        ]),
        [
          "remove",
          { transform: { document: name, fieldTransforms: [transform(true, [item])] } },
          [],
        ],
        [
          "remove_again",
          { transform: { document: name, fieldTransforms: [transform(true, [item])] } },
          [],
        ],
        [
          "operand_duplicates",
          { transform: { document: name, fieldTransforms: [transform(false, [item, other])] } },
          [stored],
        ],
        [
          "set_union",
          { update: update([item]), updateTransforms: [transform(false, [other])] },
          [stored],
        ],
        [
          "set_remove",
          { update: update([item]), updateTransforms: [transform(true, [other])] },
          [],
        ],
        ["ordinary_duplicates", { update: update([item, other]) }, [stored, stored]],
        [
          "remove_duplicates",
          { transform: { document: name, fieldTransforms: [transform(true, [item])] } },
          [],
        ],
      ];
      const steps = [];
      results.push({ shape, precision, name, steps });
      for (const [label, write, expected] of operations) {
        const commit = await request(`${base}:commit`, { writes: [write] });
        const document = await request(`${root}${name}`);
        steps.push({ label, write, commit, document });
        assert.deepEqual(
          document.fields.values.arrayValue.values ?? [],
          expected,
          `${shape}/${precision}/${label}`,
        );
        assert.equal(commit.writeResults[0].updateTime, document.updateTime);
        if (write.transform || write.updateTransforms) {
          assert.deepEqual(commit.writeResults[0].transformResults, [{ nullValue: null }]);
        }
        if (["union2", "union3", "remove_again", "set_union"].includes(label)) {
          assert.equal(
            document.updateTime,
            steps.at(-2).document.updateTime,
            `${label} must be a no-op`,
          );
        }
      }
    }
  }
} finally {
  const cleanup = await Promise.allSettled(
    owned.map((name) => request(`${root}${name}`, undefined, "DELETE")),
  );
  console.log(
    JSON.stringify(
      {
        project,
        results,
        cleanup: cleanup.map((entry, i) => ({
          name: owned[i],
          status: entry.status,
          ...(entry.status === "rejected" ? { error: String(entry.reason) } : {}),
        })),
      },
      null,
      2,
    ),
  );
  assert(
    cleanup.every((entry) => entry.status === "fulfilled"),
    "Owned fixture cleanup failed",
  );
}
