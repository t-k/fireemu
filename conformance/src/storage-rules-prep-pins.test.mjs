import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { CLOSURE_SPEC, RUNNER_DIRS, SCHEMA_FILES, prepCodeDigests } from "./storage-rules-prep/pins.mjs";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const STAGE3 = "conformance/src/storage-rules";
const PREP = "conformance/src/storage-rules-prep";

async function tree(t, extra = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-prep-pins-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, STAGE3, "nested"), { recursive: true });
  await mkdir(join(root, PREP, "nested"), { recursive: true });
  await mkdir(join(root, "spec", "compatibility", "closure"), { recursive: true });
  const files = {
    [`${STAGE3}/private-inputs.mjs`]: "p", [`${STAGE3}/acceptance-preflight.mjs`]: "a", [`${STAGE3}/acceptance-core.mjs`]: "c", [`${STAGE3}/other.mjs`]: "o", [`${STAGE3}/nested/deep.mjs`]: "d",
    [`${PREP}/plan.mjs`]: "plan", [`${PREP}/run.mjs`]: "run", [`${PREP}/nested/extra.mjs`]: "e", [CLOSURE_SPEC]: "{}", ...extra,
  };
  for (const [path, text] of Object.entries(files)) await writeFile(join(root, path), text);
  return { root, files };
}
const lines = (files) => Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, text]) => `${path}\0${sha(text)}\n`).join("");
const held = (path) => execFileSync("lsof", ["-p", String(process.pid), "-Fn"], { encoding: "utf8" }).split("\n").filter((line) => line.startsWith("n") && line.includes(path));

test("the constants name the two runner directories, the closure spec and the four schema files", () => {
  assert.deepEqual([...RUNNER_DIRS], [STAGE3, PREP]);
  assert.equal(CLOSURE_SPEC, "spec/compatibility/closure/STORAGE-RULES.json");
  assert.deepEqual([...SCHEMA_FILES].sort(), [`${PREP}/plan.mjs`, `${STAGE3}/acceptance-core.mjs`, `${STAGE3}/acceptance-preflight.mjs`, `${STAGE3}/private-inputs.mjs`]);
  assert.equal(Object.isFrozen(RUNNER_DIRS) && Object.isFrozen(SCHEMA_FILES), true);
});

test("the runner pin covers both directories, nested modules included, and the closure spec; the schema pin the four schema files and the closure spec", async (t) => {
  const { root, files } = await tree(t);
  const digests = await prepCodeDigests(root);
  const modules = Object.fromEntries(Object.entries(files).filter(([path]) => path.endsWith(".mjs") || path === CLOSURE_SPEC));
  assert.equal(digests.runnerSha256, sha(lines(modules)));
  assert.equal(digests.fixtureSchemaSha256, sha(lines(Object.fromEntries(Object.entries(files).filter(([path]) => SCHEMA_FILES.includes(path) || path === CLOSURE_SPEC)))));
  assert.equal(Object.isFrozen(digests), true);
  assert.deepEqual(held(root), []);
});

test("the pins move with any module in either directory or the closure spec, the schema pin only with its files, and neither with a non-module file", async (t) => {
  const base = await prepCodeDigests((await tree(t)).root);
  for (const [path, text, moves] of [
    [`${STAGE3}/other.mjs`, "changed", ["runnerSha256"]], [`${STAGE3}/nested/deep.mjs`, "changed", ["runnerSha256"]], [`${PREP}/run.mjs`, "changed", ["runnerSha256"]], [`${PREP}/nested/extra.mjs`, "changed", ["runnerSha256"]], [`${PREP}/new.mjs`, "new", ["runnerSha256"]], [`${STAGE3}/new.mjs`, "new", ["runnerSha256"]],
    [`${PREP}/plan.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [`${STAGE3}/private-inputs.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [`${STAGE3}/acceptance-core.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [`${STAGE3}/acceptance-preflight.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [CLOSURE_SPEC, "{\"x\":1}", ["runnerSha256", "fixtureSchemaSha256"]],
    [`${PREP}/README.md`, "notes", []], [`${STAGE3}/data.json`, "{}", []],
  ]) {
    const other = await prepCodeDigests((await tree(t, { [path]: text })).root);
    for (const key of ["runnerSha256", "fixtureSchemaSha256"]) assert.equal(other[key] !== base[key], moves.includes(key), `${path} ${key}`);
  }
});

test("a symbolic link, a missing directory or file, an oversized file and an empty runner directory are refused, and a special file with a module name is ignored", async (t) => {
  const linked = await tree(t);
  await symlink(join(linked.root, PREP, "run.mjs"), join(linked.root, PREP, "link.mjs"));
  await assert.rejects(prepCodeDigests(linked.root), /pin source refused/);
  const dirLink = await tree(t);
  await symlink(join(dirLink.root, STAGE3, "nested"), join(dirLink.root, STAGE3, "nested-link"));
  await assert.rejects(prepCodeDigests(dirLink.root), /pin source refused/);
  const linkedClosure = await tree(t);
  await unlink(join(linkedClosure.root, CLOSURE_SPEC));
  await writeFile(join(linkedClosure.root, "closure-real.json"), "{}");
  await symlink(join(linkedClosure.root, "closure-real.json"), join(linkedClosure.root, CLOSURE_SPEC));
  await assert.rejects(prepCodeDigests(linkedClosure.root));
  assert.deepEqual(held(linkedClosure.root), []);
  const dirClosure = await tree(t);
  await unlink(join(dirClosure.root, CLOSURE_SPEC));
  await mkdir(join(dirClosure.root, CLOSURE_SPEC));
  await assert.rejects(prepCodeDigests(dirClosure.root), /pin source refused/);
  const emptyPrep = await tree(t);
  for (const name of ["plan.mjs", "run.mjs"]) await unlink(join(emptyPrep.root, PREP, name));
  await unlink(join(emptyPrep.root, PREP, "nested", "extra.mjs"));
  await assert.rejects(prepCodeDigests(emptyPrep.root), /pin source refused/);
  const emptyStage3 = await tree(t);
  for (const name of ["private-inputs.mjs", "acceptance-preflight.mjs", "acceptance-core.mjs", "other.mjs", "nested/deep.mjs"]) await unlink(join(emptyStage3.root, STAGE3, name));
  await assert.rejects(prepCodeDigests(emptyStage3.root));
  const missing = await tree(t);
  await unlink(join(missing.root, PREP, "plan.mjs"));
  await assert.rejects(prepCodeDigests(missing.root));
  const noClosure = await tree(t);
  await unlink(join(noClosure.root, CLOSURE_SPEC));
  await assert.rejects(prepCodeDigests(noClosure.root));
  const big = await tree(t, { [`${PREP}/big.mjs`]: "x".repeat(8 * 1024 * 1024 + 1) });
  await assert.rejects(prepCodeDigests(big.root), /pin source refused/);
  const exact = await tree(t, { [`${PREP}/big.mjs`]: "x".repeat(8 * 1024 * 1024) });
  await prepCodeDigests(exact.root);
  const expected = await prepCodeDigests((await tree(t)).root);
  const withPipe = await tree(t);
  execFileSync("mkfifo", [join(withPipe.root, PREP, "pipe.mjs")]);
  assert.deepEqual(await prepCodeDigests(withPipe.root), expected);
  void chmod;
});
