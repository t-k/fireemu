import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { checkoutMatches, CLOSURE_SPEC, codeDigests, computePins, FIXTURE_FILES, gitOutput } from "./storage-rules/pins.mjs";
import { loadPrivateInputs } from "./storage-rules/private-inputs.mjs";
import { buildRunManifest, manifestParams, paramsFromInputs, TEMPLATE_RUN_ID } from "./storage-rules/run-manifest.mjs";
import { manifestPin } from "./storage-rules/pins.mjs";
import { ADC, BUCKET, KEY_IDS, NUMBERS, privatePacket } from "./storage-rules-runner-support.mjs";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const CLOSURE = "spec/compatibility/closure/STORAGE-RULES.json";
const DIR = "conformance/src/storage-rules";

async function tree(t, extra = {}) {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-pins-"));
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
  const empty = await mkdtemp(join(tmpdir(), "storage-rules-pins-empty-"));
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
  assert.deepEqual(asked, [["rev-parse", "HEAD"], ["status", "--porcelain", "--untracked-files=no"], ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", DIR, CLOSURE]]);
  // Untracked or ignored files under the runner directory or at the closure spec path are refused, whatever the tracked state is.
  const extra = (out) => async (root, args) => (args[0] === "rev-parse" ? commit : args.includes("--ignored") ? out : "");
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: extra("?? conformance/src/storage-rules/driver.mjs\n") }), { ok: false, reason: "untracked or ignored runner files" });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: extra("!! conformance/src/storage-rules/x.mjs\n") }), { ok: false, reason: "untracked or ignored runner files" });
  assert.deepEqual(await checkoutMatches({ root: "/r", sourceCommit: commit, git: extra("\n") }), { ok: true });
});

test("the real git reader reads a scratch repository and refuses a directory that is not one", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-pins-git-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  // A scratch repository with no global or system configuration, so it has no signing setup to override.
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" };
  const run = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", env });
  run("init", "-q");
  await writeFile(join(root, "a.txt"), "one");
  await mkdir(join(root, DIR), { recursive: true });
  await mkdir(join(root, "spec", "compatibility", "closure"), { recursive: true });
  await writeFile(join(root, DIR, "module.mjs"), "export {};\n");
  await writeFile(join(root, CLOSURE), "{}");
  await writeFile(join(root, ".gitignore"), "ignored-*.mjs\n");
  run("add", "a.txt", DIR, CLOSURE, ".gitignore");
  run("commit", "-q", "-m", "first");
  const head = run("rev-parse", "HEAD").trim();
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  await writeFile(join(root, "untracked.txt"), "x");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  // An untracked or an ignored module under the runner directory is refused; an ignored file elsewhere is not.
  await writeFile(join(root, DIR, "driver.mjs"), "export {};\n");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: false, reason: "untracked or ignored runner files" });
  await unlink(join(root, DIR, "driver.mjs"));
  await writeFile(join(root, DIR, "ignored-thing.mjs"), "export {};\n");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: false, reason: "untracked or ignored runner files" });
  await unlink(join(root, DIR, "ignored-thing.mjs"));
  await writeFile(join(root, "ignored-elsewhere.mjs"), "export {};\n");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  await writeFile(join(root, "spec", "compatibility", "closure", "extra.json"), "{}");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: true });
  await writeFile(join(root, "a.txt"), "two");
  assert.deepEqual(await checkoutMatches({ root, sourceCommit: head }), { ok: false, reason: "working tree not clean" });
  assert.equal((await gitOutput(root, ["rev-parse", "HEAD"])).trim(), head);
  const plain = await mkdtemp(join(tmpdir(), "storage-rules-pins-nogit-"));
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
  const bin = await mkdtemp(join(tmpdir(), "storage-rules-pins-bin-"));
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

const realRoot = fileURLToPath(new URL("../..", import.meta.url));
const realClosure = JSON.parse(readFileSync(join(realRoot, CLOSURE_SPEC)));

async function inputsFile(t, mutate = (packet) => packet) {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-pins-inputs-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const path = join(root, "inputs.json");
  await writeFile(path, JSON.stringify(mutate(privatePacket(adcPath))), { mode: 0o600 });
  return path;
}

test("all three recomputable pins come from the code, the private inputs and the commit, and agree with the entry's checks", async (t) => {
  const { root } = await tree(t);
  const inputs = await loadPrivateInputs({ path: await inputsFile(t) });
  const commit = "c".repeat(40);
  const pins = await computePins({ inputs, closure: realClosure, sourceCommit: commit, codeRoot: root });
  const digests = await codeDigests(root);
  assert.deepEqual(Object.keys(pins), ["sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"]);
  assert.deepEqual([pins.sourceCommit, pins.runnerSha256, pins.fixtureSchemaSha256], [commit, digests.runnerSha256, digests.fixtureSchemaSha256]);
  const template = buildRunManifest(realClosure, paramsFromInputs(inputs, TEMPLATE_RUN_ID, commit));
  assert.equal(pins.manifestSha256, template.sha256);
  // Any run of this approval reproduces the same manifest pin.
  for (const runId of ["first-recording-1", "second-recording-2"]) assert.equal(manifestPin(buildRunManifest(realClosure, paramsFromInputs(inputs, runId, commit)), realClosure), pins.manifestSha256);
  assert.deepEqual(manifestParams(template), paramsFromInputs(inputs, TEMPLATE_RUN_ID, commit));
  // Each parameter comes from its own private input (named independently of the code under test).
  assert.deepEqual(paramsFromInputs(inputs, "some-run-id-1", commit), { bucket: BUCKET, runId: "some-run-id-1", sourceCommit: commit, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, queryApiKeyId: KEY_IDS.query, idpApiKeyId: KEY_IDS.idp });
  assert.equal(new Set([NUMBERS.query, NUMBERS.idp, KEY_IDS.query, KEY_IDS.idp]).size, 4);
  assert.equal(Object.isFrozen(pins), true);
  // The commit and every private input the manifest names move the pin; the API key strings, which it does not name, do not.
  const other = await computePins({ inputs, closure: realClosure, sourceCommit: "d".repeat(40), codeRoot: root });
  assert.notEqual(other.manifestSha256, pins.manifestSha256);
  const moved = await loadPrivateInputs({ path: await inputsFile(t, (packet) => { packet.bucket.name = "another-bucket-name"; return packet; }) });
  assert.notEqual((await computePins({ inputs: moved, closure: realClosure, sourceCommit: commit, codeRoot: root })).manifestSha256, pins.manifestSha256);
});

test("the pin printer prints the pins for a clean checkout and refuses an unclean one, a bad file and bad arguments without echoing the file", async (t) => {
  const { runPrintPins } = await import("./storage-rules/print-pins.mjs");
  const { root } = await tree(t);
  await mkdir(join(root, "spec", "compatibility", "closure"), { recursive: true });
  await writeFile(join(root, CLOSURE), JSON.stringify(realClosure));
  const path = await inputsFile(t);
  const commit = "c".repeat(40);
  const gitFor = (status = "", extra = "") => async (where, args) => { assert.equal(where, root); return args[0] === "rev-parse" ? `${commit}\n` : args.includes("--ignored") ? extra : status; };
  const run = async (args, git) => {
    const seen = { out: "", err: "" };
    const code = await runPrintPins({ args, codeRoot: root, git, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } });
    return { code, ...seen };
  };
  const ok = await run([path], gitFor());
  assert.equal(ok.code, 0);
  assert.equal(ok.err, "");
  assert.match(ok.out, /^\{\n  "sourceCommit": "c{40}",\n/);
  const inputs = await loadPrivateInputs({ path });
  assert.deepEqual(JSON.parse(ok.out), { ...(await computePins({ inputs, closure: realClosure, sourceCommit: commit, codeRoot: root })) });
  assert.deepEqual(Object.keys(JSON.parse(ok.out)), ["sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"]);
  for (const [git, message] of [[gitFor(" M conformance/src/storage-rules/x.mjs\n"), /working tree not clean/], [gitFor("", "?? conformance/src/storage-rules/driver.mjs\n"), /untracked or ignored runner files/], [gitFor("", "!! conformance/src/storage-rules/x.mjs\n"), /untracked or ignored runner files/]]) {
    const refused = await run([path], git);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, "");
    assert.match(refused.err, message);
  }
  for (const args of [[], [path, "extra"]]) {
    const usage = await run(args, gitFor());
    assert.deepEqual([usage.code, usage.out], [2, ""]);
    assert.match(usage.err, /usage/);
  }
  const bad = await inputsFile(t, (packet) => ({ ...packet, extra: "SECRET-VALUE-XYZ" }));
  const failed = await run([bad], gitFor());
  assert.deepEqual([failed.code, failed.out], [1, ""]);
  assert.match(failed.err, /private inputs file refused/);
  assert.equal(failed.err.includes("SECRET-VALUE-XYZ"), false);
  // The command line itself: usage and a bad file end the process with the same codes and print nothing to stdout.
  const script = fileURLToPath(new URL("./storage-rules/print-pins.mjs", import.meta.url));
  assert.equal(spawnSync("node", [script], { encoding: "utf8" }).status, 2);
  const cli = spawnSync("node", [script, bad], { encoding: "utf8" });
  assert.deepEqual([cli.status, cli.stdout], [1, ""]);
  assert.equal(cli.stderr.includes("SECRET-VALUE-XYZ"), false);
});
