// docs/functions-export-inventory.md must name every trigger namespace the installed
// `firebase-functions` SDK exports, with one of the documented statuses. The SDK is the one
// the smoke fixture installs (`npm ci --prefix tools/sdk-smoke`); without it the test is
// skipped with that reason rather than passing on nothing.

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const smoke = resolve(repo, "tools/sdk-smoke");
const inventory = readFileSync(resolve(repo, "docs/functions-export-inventory.md"), "utf8");

const STATUSES = new Set(["served", "deferred", "not-planned", "unsupported"]);
const NON_TRIGGER_V1 = new Set([
  "Change",
  "DEFAULT_FAILURE_POLICY",
  "FunctionBuilder",
  "INGRESS_SETTINGS_OPTIONS",
  "RESET_VALUE",
  "SUPPORTED_REGIONS",
  "VALID_MEMORY_OPTIONS",
  "VPC_EGRESS_SETTINGS_OPTIONS",
  "app",
  "config",
  "firebaseConfig",
  "logger",
  "makeCloudFunction",
  "onInit",
  "optionsToEndpoint",
  "optionsToTrigger",
  "params",
  "region",
  "requiresAPI",
  "runWith",
]);
const NON_TRIGGER_V2 = new Set(["core", "options", "params", "trace", "index", "index.js"]);

/** The rows of one table: `{name, status}` from the first backticked token and the second cell. */
function rows(section) {
  const start = inventory.indexOf(`## ${section}`);
  const end = inventory.indexOf("\n## ", start + 1);
  const body = inventory.slice(start, end === -1 ? undefined : end);
  return body
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .map((line) => {
      const cells = line.split("|").map((cell) => cell.trim());
      const name = cells[1].match(/`([^`]+)`/)[1];
      return { name, status: cells[2] };
    });
}

const sdk = existsSync(join(smoke, "node_modules/firebase-functions/package.json"))
  ? createRequire(join(smoke, "package.json"))
  : null;

test("every row carries a documented status", () => {
  for (const row of [...rows("v1"), ...rows("v2")]) {
    const statuses = row.status.match(/\b(served|deferred|not-planned|unsupported)\b/g) ?? [];
    assert.ok(statuses.length > 0, `${row.name}: status ${JSON.stringify(row.status)}`);
    for (const status of statuses) assert.ok(STATUSES.has(status), `${row.name}: ${status}`);
  }
});

test("every v1 trigger namespace the installed SDK exports has a row", { skip: sdk ? false : "firebase-functions is not installed under tools/sdk-smoke" }, () => {
  const v1 = sdk("firebase-functions/v1");
  const namespaces = Object.keys(v1).filter(
    (key) => !NON_TRIGGER_V1.has(key) && (typeof v1[key] === "object" || typeof v1[key] === "function"),
  );
  assert.ok(namespaces.length >= 8, `unexpectedly few v1 namespaces: ${namespaces}`);
  const documented = new Set(rows("v1").map((row) => row.name));
  for (const namespace of namespaces) {
    assert.ok(documented.has(namespace), `v1 namespace ${namespace} has no inventory row`);
  }
});

test("every v2 module the installed SDK ships has a row", { skip: sdk ? false : "firebase-functions is not installed under tools/sdk-smoke" }, () => {
  const providers = dirname(sdk.resolve("firebase-functions/v2/https"));
  const modules = readdirSync(providers)
    .map((entry) => entry.replace(/\.js$/, ""))
    .filter((entry) => !entry.endsWith(".d.ts") && !entry.endsWith(".map") && !NON_TRIGGER_V2.has(entry));
  assert.ok(modules.length >= 10, `unexpectedly few v2 modules: ${modules}`);
  const documented = new Set(rows("v2").map((row) => row.name));
  for (const module of new Set(modules)) {
    assert.ok(documented.has(module), `v2 module ${module} has no inventory row`);
  }
  for (const module of documented) {
    assert.doesNotThrow(() => sdk.resolve(`firebase-functions/v2/${module}`), `documented v2 module ${module} is not in the SDK`);
  }
});
