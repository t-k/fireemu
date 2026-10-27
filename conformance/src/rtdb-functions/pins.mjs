// The reviewed sources of the CV14 run. Each file's sha256 is fixed here; the packet repeats the values
// and the pre-send checks recompute them. Change a fixture file, update the digest in the same commit.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export const FIXTURE_PINS = Object.freeze({
  "firebase.json": "55d0c9c1cc167b7eec811eb58120a0762577189816e3e5ca8ca9122b449270cf",
  "fixtures/frames.js": "22f8d1ac1e5f062f551330b573c60cfc463e030f56c1c34c510104017cd978e7",
  "fixtures/index.js": "6d447ac0621ffa0b9e723807127fac46aeefb4900ff25d0e276be7f996ae256a",
  "fixtures/package-lock.json": "c492afe0fa1e5336d78be6f1fa76e594d357e0412cacfd9d963d2569389b7dea",
  "fixtures/package.json": "b5d6b04e164233bdbd88f5080a0b0294ffe6c60dd0840e1a04cf0103b67ed772",
});

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const here = (file) => new URL(`./${file}`, import.meta.url);

/** Refuses a fixture file that differs from its pin and any Firebase CLI other than 15.28.2. */
export async function requiredStage2Sources(
  readSource = (file) =>
    readFile(
      file.startsWith("../") ? new URL(`../../${file.slice(3)}`, import.meta.url) : here(file),
    ),
) {
  for (const [file, expected] of Object.entries(FIXTURE_PINS)) {
    if (digest(await readSource(file)) !== expected) {
      throw new Error(`reviewed source changed: ${file}`);
    }
  }
  const cliPackage = JSON.parse(
    (await readSource("../node_modules/firebase-tools/package.json")).toString("utf8"),
  );
  if (cliPackage.version !== "15.28.2") throw new Error("pinned Firebase CLI 15.28.2 is required");
}
