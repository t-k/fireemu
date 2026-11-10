import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

import { buildCorpus } from "./corpus.mjs";
import { servingConfig } from "./convert.mjs";

const require = createRequire(import.meta.url);
const real = require(require.resolve("firebase-tools/lib/deploy/hosting/convertConfig.js"));

const noFunctions = { functions: {} };

test("every corpus version converts exactly as firebase-tools 15.28.2 converts it", async () => {
  for (const version of buildCorpus().versions) {
    const hosting = { site: "s", public: "public", ...version.hosting };
    const expected = await real.convertConfig({}, noFunctions, {
      config: hosting,
      version: "sites/s/versions/v",
    });
    assert.deepEqual(
      servingConfig(version.hosting),
      JSON.parse(JSON.stringify(expected)),
      version.id,
    );
  }
});

test("function, run and dynamicLinks rewrites and ambiguous patterns are refused", () => {
  for (const rewrite of [
    { source: "/a", function: "f" },
    { source: "/a", run: { serviceId: "s" } },
    { source: "/a", dynamicLinks: true },
  ]) {
    assert.throws(() => servingConfig({ rewrites: [rewrite] }), /only destination rewrites/);
  }
  assert.throws(
    () => servingConfig({ redirects: [{ source: "/a", regex: "b", destination: "/", type: 301 }] }),
    /both a glob and regex/,
  );
  assert.throws(() => servingConfig({ headers: [{ headers: [] }] }), /no pattern/);
});

test("trailingSlash maps to ADD and REMOVE and absent keys stay absent", () => {
  assert.deepEqual(servingConfig({ trailingSlash: true }), { trailingSlashBehavior: "ADD" });
  assert.deepEqual(servingConfig({ trailingSlash: false }), { trailingSlashBehavior: "REMOVE" });
  assert.deepEqual(servingConfig({}), {});
});
