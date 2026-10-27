// The firebase-admin files the Admin SDK App Check instrumentation (admin-app-check.mjs) is
// written against, pinned by content. The instrumentation patches `verifySignature` and
// `verifyReplayProtection` and relies on the SDK's own decode, claim checks and error mapper, so a
// change in any of these files can change what it does. Each digest is the SHA-256 of the file
// without its first line (the `/*! firebase-admin vX */` banner, the only thing that differs
// between releases here).
//
// - 13.10.0 and 14.3.0 are the versions the tests run against (14.3.0 is what CI installs).
// - 14.5.0 is not installed anywhere in CI: its digests come from the published tarball
//   (`npm pack firebase-admin@14.5.0`, compared on 2026-10-26) and are identical to 14.3.0's.
//
// A pin bump to a version that is not in the table, or to a version whose files differ from its
// row, fails here. Compare the new files with the previous row, re-run admin-app-check.test.mjs
// against the new copy, then update the table and the "tested versions" text in
// docs/specifications/firebase-app-check.md (13.5) and the App Check page of the site.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const DIGESTS = {
  "13.10.0": {
    "lib/app-check/token-verifier.js": "0215e3b98edcde245701cdabbf48d975d04b09f3ffa97697dde8cff4ffb81d5f",
    "lib/app-check/app-check.js": "43b86bb4e9507134b3af7f6ed95532e86d7ac956e8c4b15bcc8fcc51467edef2",
    "lib/app-check/app-check-api-client-internal.js": "a6faf9d5caa857ddb9f1665c0d97db9b1d9abe84b95a0c1ae08f1bb66c26142f",
    "lib/utils/jwt.js": "594ebf8b088eece3327d8d6c206a18b9b40680057fdfcb256b44ea693ff77729"
  },
  "14.3.0": {
    "lib/app-check/token-verifier.js": "d833b5dcd9a3e4907f81d55bd6a5f8e3af189d26eaefe0163c5c18b387924bed",
    "lib/app-check/app-check.js": "32fd6def36746834f4b1abfb4d9be2752dd2fcee71dc588526a6089f964f59c4",
    "lib/app-check/app-check-api-client-internal.js": "9082cd166433d3a4a469b24be15d4a9cbbd54b34fac39f16ec028e9861fde10e",
    "lib/app-check/error.js": "38d03d407ca8c024ae03e713f3dd065a8ef1b26caabb0b8b4e0f9bb60e7f76bc",
    "lib/utils/jwt.js": "3f4d36bf48936da181a94e14b12bc13013fb1afd1914df9cbd2627f4b8bc1560"
  },
  "14.5.0": {
    "lib/app-check/token-verifier.js": "d833b5dcd9a3e4907f81d55bd6a5f8e3af189d26eaefe0163c5c18b387924bed",
    "lib/app-check/app-check.js": "32fd6def36746834f4b1abfb4d9be2752dd2fcee71dc588526a6089f964f59c4",
    "lib/app-check/app-check-api-client-internal.js": "9082cd166433d3a4a469b24be15d4a9cbbd54b34fac39f16ec028e9861fde10e",
    "lib/app-check/error.js": "38d03d407ca8c024ae03e713f3dd065a8ef1b26caabb0b8b4e0f9bb60e7f76bc",
    "lib/utils/jwt.js": "3f4d36bf48936da181a94e14b12bc13013fb1afd1914df9cbd2627f4b8bc1560"
  }
};

function digestOf(path) {
  const bytes = readFileSync(path);
  return createHash("sha256").update(bytes.subarray(bytes.indexOf(0x0a) + 1)).digest("hex");
}

test("firebase-admin 14.5.0 has the same App Check code as 14.3.0", () => {
  assert.deepEqual(DIGESTS["14.5.0"], DIGESTS["14.3.0"]);
});

const installed = [
  join(here, "..", "..", "conformance", "node_modules", "firebase-admin"),
  join(here, "..", "sdk-smoke", "node_modules", "firebase-admin"),
  ...(process.env.FIREEMU_ADMIN_SDK_DIRS ?? "").split(delimiter).filter(Boolean),
].filter((dir) => existsSync(join(dir, "package.json")));

test("a firebase-admin copy is installed to check", { skip: process.env.FIREEMU_REQUIRE_SDK !== "1" }, () => {
  assert.ok(installed.length > 0, "FIREEMU_REQUIRE_SDK=1 but no firebase-admin copy is installed");
});

for (const dir of installed) {
  const version = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version;
  test(`firebase-admin ${version} (${dir.includes("sdk-smoke") ? "tools/sdk-smoke" : dir.includes("conformance") ? "conformance" : "extra"}) matches the pinned App Check digests`, () => {
    const row = DIGESTS[version];
    assert.ok(row, `firebase-admin ${version} is not in DIGESTS: compare its App Check files with the previous row, re-run admin-app-check.test.mjs against it, then add the row`);
    for (const [file, expected] of Object.entries(row)) {
      assert.equal(digestOf(join(dir, file)), expected, `${file} of firebase-admin ${version} changed`);
    }
    // No file of the watched set is missing from the row (13.x has no error.js).
    for (const file of ["lib/app-check/error.js"]) {
      assert.equal(existsSync(join(dir, file)), file in row, `${file} presence changed`);
    }
  });
}
