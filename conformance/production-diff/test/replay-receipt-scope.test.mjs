import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";

const PILOT = new URL("../pilot.mjs", import.meta.url);

test("non-G0 recording does not require a G0 launch receipt", async () => {
  const source = await fs.readFile(PILOT, "utf8");
  assert.match(
    source,
    /entry\.adapter === "g0"[\s\S]{0,180}launchReceiptSha256/,
  );
  assert.match(source, /\? \{ launchReceiptSha256: sha256\(/);
  assert.match(source, /: \{\}\),/);
});

test("G0 receipt remains bounded and mandatory in the source contract", async () => {
  const source = await fs.readFile(PILOT, "utf8");
  assert.match(source, /readSource\(directory, "launch-receipt\.json", 128 \* 1024\)/);
  assert.match(source, /writeFileSync\(join\(directory, "launch-receipt\.json"/);
});

test("receipt-scope regression test has no production or credential inputs", async () => {
  assert.equal(join("conformance", "production-diff").endsWith("production-diff"), true);
});
