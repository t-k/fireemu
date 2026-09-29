import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { checkoutMatches, codeDigests, FIXTURE_FILES, gitOutput } from "./storage-rules/pins.mjs";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const CLOSURE = "spec/compatibility/closure/STORAGE-RULES.json";
const DIR = "conformance/src/storage-rules";

async function tree(t, extra = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-pins-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, DIR, "nested"), { recursive: true });
  await mkdir(join(root, "spec", "compatibility", "closure"), { recursive: true });
  const files = { [`${DIR}/corpus.mjs`]: "c", [`${DIR}/rulesets.mjs`]: "r", [`${DIR}/fixture-proof.mjs`]: "f", [`${DIR}/private-inputs.mjs`]: "p", [`${DIR}/controller.mjs`]: "k", [`${DIR}/nested/deep.mjs`]: "d", [CLOSURE]: "{}", ...extra };
  for (const [path, text] of Object.entries(files)) await writeFile(join(root, path), text);
  return { root, files };
}
const lines = (files) => Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, text]) => `${path}\0${sha(text)}\n`).join("");

test("the runner pin covers every module under the runner directory, nested ones included, and the closure spec", async (t) => {
  const { root, files } = await tree(t);
  const digests = await codeDigests(root);
  const modules = Object.fromEntries(Object.entries(files).filter(([path]) => path.endsWith(".mjs") || path === CLOSURE));
  assert.equal(digests.runnerSha256, sha(lines(modules)));
  assert.equal(digests.fixtureSchemaSha256, sha(lines(Object.fromEntries(Object.entries(files).filter(([path]) => FIXTURE_FILES.includes(path) || path === CLOSURE)))));
  assert.equal(Object.isFrozen(digests), true);
  assert.deepEqual([...FIXTURE_FILES].sort(), [`${DIR}/corpus.mjs`, `${DIR}/fixture-proof.mjs`, `${DIR}/private-inputs.mjs`, `${DIR}/rulesets.mjs`]);
});

test("the pins move with any module, nested module or closure change, and not with a non-module file", async (t) => {
  const base = await codeDigests((await tree(t)).root);
  for (const [path, text, moves] of [
    [`${DIR}/controller.mjs`, "changed", ["runnerSha256"]], [`${DIR}/nested/deep.mjs`, "changed", ["runnerSha256"]], [`${DIR}/new-module.mjs`, "new", ["runnerSha256"]],
    [`${DIR}/corpus.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [`${DIR}/private-inputs.mjs`, "changed", ["runnerSha256", "fixtureSchemaSha256"]], [CLOSURE, "{\"x\":1}", ["runnerSha256", "fixtureSchemaSha256"]],
    [`${DIR}/README.md`, "notes", []], [`${DIR}/data.json`, "{}", []],
  ]) {
    const other = await codeDigests((await tree(t, { [path]: text })).root);
    for (const key of ["runnerSha256", "fixtureSchemaSha256"]) assert.equal(other[key] !== base[key], moves.includes(key), `${path} ${key}`);
  }
});

test("a symbolic link, a missing module directory, a missing fixture file and an oversized file are refused", async (t) => {
  const linked = await tree(t);
  await symlink(join(linked.root, DIR, "controller.mjs"), join(linked.root, DIR, "link.mjs"));
  await assert.rejects(codeDigests(linked.root), /pin source refused/);
  const dirLink = await tree(t);
  await symlink(join(dirLink.root, DIR, "nested"), join(dirLink.root, DIR, "nested-link"));
  await assert.rejects(codeDigests(dirLink.root), /pin source refused/);
  const empty = await mkdtemp("/private/tmp/storage-rules-pins-empty-");
  t.after(() => rm(empty, { recursive: true, force: true }));
  await mkdir(join(empty, DIR), { recursive: true });
  await assert.rejects(codeDigests(empty), /pin source refused/);
  const missing = await tree(t);
  await unlink(join(missing.root, DIR, "rulesets.mjs"));
  await assert.rejects(codeDigests(missing.root));
  const noClosure = await tree(t);
  await unlink(join(noClosure.root, CLOSURE));
  await assert.rejects(codeDigests(noClosure.root));
  const big = await tree(t, { [`${DIR}/big.mjs`]: "x".repeat(8 * 1024 * 1024 + 1) });
  await assert.rejects(codeDigests(big.root), /pin source refused/);
  const exact = await tree(t, { [`${DIR}/big.mjs`]: "x".repeat(8 * 1024 * 1024) });
  await codeDigests(exact.root);
});

test("the checkout must be at the pinned commit with no change to a tracked file", async () => {
  const commit = "a".repeat(40);
  const reader = (head, status) => async (root, args) => { assert.equal(root, "/r"); return args[0] === "rev-parse" ? head : status; };
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: reader(`${commit}\n`, "") }), { ok: true });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: reader(`${commit}\n`, "\n") }), { ok: true });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: reader(`${"b".repeat(40)}\n`, "") }), { ok: false, reason: "source commit mismatch" });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: reader(`${commit}\n`, " M file\n") }), { ok: false, reason: "working tree not clean" });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: reader(`${commit}x\n`, "") }), { ok: false, reason: "source commit mismatch" });
  // Only a tracked-file change counts: the status is asked without untracked files.
  const asked = [];
  await checkoutMatches({ root: "/r", sourceCommit: commit, git: async (root, args) => { asked.push(args); return args[0] === "rev-parse" ? commit : ""; } });
  assert.deepEqual(asked, [["rev-parse", "HEAD"], ["status", "--porcelain", "--untracked-files=no"]]);
});

test("the real git reader reads a scratch repository and refuses a directory that is not one", async (t) => {
  const root = await mkdtemp("/private/tmp/storage-rules-pins-git-");
  t.after(() => rm(root, { recursive: true, force: true }));
  // A scratch repository with no global or system configuration, so it has no signing setup to override.
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" };
  const run = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", env });
  run("init", "-q");
  await writeFile(join(root, "a.txt"), "one");
  run("add", "a.txt");
  run("commit", "-q", "-m", "first");
  const head = run("rev-parse", "HEAD").trim();
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  await writeFile(join(root, "untracked.txt"), "x");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  await writeFile(join(root, "a.txt"), "two");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: false, reason: "working tree not clean" });
  assert.equal((await gitOutput(root, ["rev-parse", "HEAD"])).trim(), head);
  const plain = await mkdtemp("/private/tmp/storage-rules-pins-nogit-");
  t.after(() => rm(plain, { recursive: true, force: true }));
  await assert.rejects(gitOutput(plain, ["rev-parse", "HEAD"]), /git refused/);
});

const held = (path) => execFileSync("lsof", ["-p", String(process.pid), "-Fn"], { encoding: "utf8" }).split("\n").filter((line) => line.startsWith("n") && line.includes(path));

test("the closure spec must be a plain file that is not a link, every file handle is closed, and a special file with a module name is ignored", async (t) => {
  const base = await tree(t);
  const expected = await codeDigests(base.root);
  assert.deepEqual(held(base.root), []);
  const linkedClosure = await tree(t);
  await unlink(join(linkedClosure.root, CLOSURE));
  await writeFile(join(linkedClosure.root, "closure-real.json"), "{}");
  await symlink(join(linkedClosure.root, "closure-real.json"), join(linkedClosure.root, CLOSURE));
  await assert.rejects(codeDigests(linkedClosure.root));
  assert.deepEqual(held(linkedClosure.root), []);
  const dirClosure = await tree(t);
  await unlink(join(dirClosure.root, CLOSURE));
  await mkdir(join(dirClosure.root, CLOSURE));
  await assert.rejects(codeDigests(dirClosure.root), /pin source refused/);
  assert.deepEqual(held(dirClosure.root), []);
  const withPipe = await tree(t);
  execFileSync("mkfifo", [join(withPipe.root, DIR, "pipe.mjs")]);
  assert.deepEqual(await codeDigests(withPipe.root), expected);
});

test("git is run with a fixed environment and the root it was given", async (t) => {
  const bin = await mkdtemp("/private/tmp/storage-rules-pins-bin-");
  t.after(() => rm(bin, { recursive: true, force: true }));
  const out = join(bin, "seen.txt");
  await writeFile(join(bin, "git"), `#!/bin/sh\nprintf '%s\n' "$LC_ALL" "$GIT_OPTIONAL_LOCKS" "$FIREEMU_SECRET" "$#" "$1" "$2" "$3" > "${out}"\nprintf 'value'\n`);
  await chmod(join(bin, "git"), 0o755);
  const previous = { PATH: process.env.PATH, secret: process.env.FIREEMU_SECRET };
  process.env.PATH = `${bin}:${previous.PATH}`;
  process.env.FIREEMU_SECRET = "must-not-reach-git";
  try {
    assert.equal(await gitOutput("/some/root", ["rev-parse", "HEAD"]), "value");
  } finally {
    process.env.PATH = previous.PATH;
    if (previous.secret === undefined) delete process.env.FIREEMU_SECRET; else process.env.FIREEMU_SECRET = previous.secret;
  }
  assert.deepEqual((await readFile(out, "utf8")).split("\n").slice(0, 7), ["C", "0", "", "4", "-C", "/some/root", "rev-parse"]);
});
