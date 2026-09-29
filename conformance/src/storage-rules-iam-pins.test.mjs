import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { RUNNER_DIRS, SCHEMA_FILES, iamCodeDigests } from "./storage-rules-iam/pins.mjs";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const STAGE3 = "conformance/src/storage-rules";
const IAM = "conformance/src/storage-rules-iam";

async function tree(t, extra = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-iam-pins-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, STAGE3, "nested"), { recursive: true });
  await mkdir(join(root, IAM, "nested"), { recursive: true });
  const files = { [`${STAGE3}/other.mjs`]: "o", [`${STAGE3}/nested/deep.mjs`]: "d", [`${IAM}/policy.mjs`]: "policy", [`${IAM}/targets.mjs`]: "targets", [`${IAM}/run.mjs`]: "run", [`${IAM}/nested/extra.mjs`]: "e", ...extra };
  for (const [path, text] of Object.entries(files)) await writeFile(join(root, path), text);
  return { root, files };
}
const lines = (files) => Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, text]) => `${path}\0${sha(text)}\n`).join("");
const held = (path) => execFileSync("lsof", ["-p", String(process.pid), "-Fn"], { encoding: "utf8" }).split("\n").filter((line) => line.startsWith("n") && line.includes(path));

test("the constants name the two runner directories and the two schema files", () => {
  assert.deepEqual([...RUNNER_DIRS], [STAGE3, IAM]);
  assert.deepEqual([...SCHEMA_FILES].sort(), [`${IAM}/policy.mjs`, `${IAM}/targets.mjs`]);
  assert.equal(Object.isFrozen(RUNNER_DIRS) && Object.isFrozen(SCHEMA_FILES), true);
});

test("the runner pin covers both directories, nested modules included; the schema pin the two schema files; nothing else", async (t) => {
  const { root, files } = await tree(t);
  const digests = await iamCodeDigests(root);
  assert.equal(digests.runnerSha256, sha(lines(Object.fromEntries(Object.entries(files).filter(([path]) => path.endsWith(".mjs"))))));
  assert.equal(digests.fixtureSchemaSha256, sha(lines(Object.fromEntries(Object.entries(files).filter(([path]) => SCHEMA_FILES.includes(path))))));
  assert.equal(Object.isFrozen(digests), true);
  assert.deepEqual(held(root), []);
});

test("the pins move with any module in either directory, the schema pin only with its files, and neither with a non-module file", async (t) => {
  const base = await iamCodeDigests((await tree(t)).root);
  for (const [path, text, moves] of [
    [`${STAGE3}/other.mjs`, "changed", ["runnerSha256"]], [`${STAGE3}/nested/deep.mjs`, "changed", ["runnerSha256"]], [`${IAM}/run.mjs`, "changed", ["runnerSha256"]], [`${IAM}/nested/extra.mjs`, "changed", ["runnerSha256"]], [`${IAM}/new.mjs`, "new", ["runnerSha256"]], [`${STAGE3}/new.mjs`, "new", ["runnerSha256"]],
    [`${IAM}/policy.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [`${IAM}/targets.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]],
    [`${IAM}/README.md`, "notes", []], [`${STAGE3}/data.json`, "{}", []],
  ]) {
    const other = await iamCodeDigests((await tree(t, { [path]: text })).root);
    for (const key of ["runnerSha256", "fixtureSchemaSha256"]) assert.equal(other[key] !== base[key], moves.includes(key), `${path} ${key}`);
  }
});

test("a symbolic link, a missing directory or file, an oversized file and an empty runner directory are refused, and a special file with a module name is ignored", async (t) => {
  const linked = await tree(t);
  await symlink(join(linked.root, IAM, "run.mjs"), join(linked.root, IAM, "link.mjs"));
  await assert.rejects(iamCodeDigests(linked.root), /pin source refused/);
  const dirLink = await tree(t);
  await symlink(join(dirLink.root, STAGE3, "nested"), join(dirLink.root, STAGE3, "nested-link"));
  await assert.rejects(iamCodeDigests(dirLink.root), /pin source refused/);
  const emptyIam = await tree(t);
  for (const name of ["policy.mjs", "targets.mjs", "run.mjs", "nested/extra.mjs"]) await unlink(join(emptyIam.root, IAM, name));
  await assert.rejects(iamCodeDigests(emptyIam.root), /pin source refused/);
  const emptyStage3 = await tree(t);
  for (const name of ["other.mjs", "nested/deep.mjs"]) await unlink(join(emptyStage3.root, STAGE3, name));
  await assert.rejects(iamCodeDigests(emptyStage3.root), /pin source refused/);
  const missing = await tree(t);
  await unlink(join(missing.root, IAM, "policy.mjs"));
  await assert.rejects(iamCodeDigests(missing.root));
  const big = await tree(t, { [`${IAM}/big.mjs`]: "x".repeat(8 * 1024 * 1024 + 1) });
  await assert.rejects(iamCodeDigests(big.root), /pin source refused/);
  const exact = await tree(t, { [`${IAM}/big.mjs`]: "x".repeat(8 * 1024 * 1024) });
  await iamCodeDigests(exact.root);
  const expected = await iamCodeDigests((await tree(t)).root);
  const withPipe = await tree(t);
  execFileSync("mkfifo", [join(withPipe.root, IAM, "pipe.mjs")]);
  assert.deepEqual(await iamCodeDigests(withPipe.root), expected);
  const dirSchema = await tree(t);
  await unlink(join(dirSchema.root, IAM, "targets.mjs"));
  await mkdir(join(dirSchema.root, IAM, "targets.mjs"));
  await assert.rejects(iamCodeDigests(dirSchema.root), /pin source refused/);
});
