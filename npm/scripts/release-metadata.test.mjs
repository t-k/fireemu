import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildPlatformPackage, platformManifest, RUNNER_FILES } from "../platforms/build-platform.mjs";
import { PLATFORMS } from "../platforms/platforms.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const repositoryUrl = "https://github.com/t-k/fireemu";
const retiredRepositoryPath = ["github.com", "reckona", "fireemu"].join("/");

test("every public distribution reference names the canonical repository", () => {
  const launcher = JSON.parse(readFileSync(resolve(repoRoot, "npm/fireemu/package.json"), "utf8"));
  assert.equal(launcher.homepage, `${repositoryUrl}#readme`);
  assert.equal(launcher.bugs, `${repositoryUrl}/issues`);
  assert.equal(launcher.repository.url, `git+${repositoryUrl}.git`);

  for (const platform of PLATFORMS) {
    const manifest = platformManifest(platform, "1.2.3");
    assert.equal(manifest.homepage, `${repositoryUrl}#readme`);
    assert.equal(manifest.repository.url, `git+${repositoryUrl}.git`);
  }

  const search = spawnSync(
    "git",
    [
      "grep",
      "-n",
      retiredRepositoryPath,
      "--",
      "README.md",
      "npm",
      ".github/workflows",
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.equal(search.status, 1, search.stdout || search.stderr);
});

test("the platform package includes every local runner module", () => {
  for (const file of RUNNER_FILES) {
    const source = readFileSync(resolve(repoRoot, "tools/runner-node", file), "utf8");
    const imports = [...source.matchAll(/from ["']\.\/(.+\.mjs)["'];/g)].map(match => match[1]);
    for (const dependency of imports) {
      assert.ok(RUNNER_FILES.includes(dependency), `${file} imports unpackaged ${dependency}`);
    }
  }
});

for (const graph of ["empty", "cyclic-and-ambiguous"]) {
test(`copied platform runner boots without the source checkout (${graph})`, () => {
  const temp = mkdtempSync(resolve(tmpdir(), "fireemu-package-runner-"));
  try {
    // A dummy native file is sufficient for the file-copy contract. It is never
    // executed; this test is not a Rust build or an npm installation test.
    const binary = resolve(temp, "unused-native-fixture");
    writeFileSync(binary, "not a native artifact\n");
    const output = buildPlatformPackage({
      platformName: PLATFORMS[0].name, binaryPath: binary,
      outDir: resolve(temp, "platform"), version: "0.0.0-offline-test",
    });
    const code = resolve(temp, "functions");
    mkdirSync(code);
    writeFileSync(resolve(code, "package.json"), JSON.stringify({main:"index.cjs"}));
    writeFileSync(resolve(code, "index.cjs"), graph === "empty" ? "module.exports={};\n" : `
      const fn=async()=>{};
      fn.run=fn;
      fn.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};
      const group={leaf:fn}; group.self=group;
      module.exports={healthy:fn,group,api:{user:fn},'api-user':fn};
    `);
    const shutdown = JSON.stringify({type:"shutdown"});
    const run = spawnSync(process.execPath, [resolve(output, "bin/runner-node/index.mjs"), "--source", code], {
      cwd: temp, env: {PATH:process.env.PATH,GCLOUD_PROJECT:"demo-package"},
      input: `${Buffer.byteLength(shutdown)}\n${shutdown}`, encoding:"utf8", timeout:5000,
    });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.error, undefined);
    const frames = [];
    let bytes = Buffer.from(run.stdout);
    while (bytes.length) {
      const nl = bytes.indexOf(10);
      assert.ok(nl > 0);
      const length = Number(bytes.subarray(0, nl).toString("ascii"));
      assert.ok(Number.isSafeInteger(length) && length > 0 && length <= 16 * 1024 * 1024);
      assert.ok(bytes.length >= nl + 1 + length);
      frames.push(JSON.parse(bytes.subarray(nl + 1, nl + 1 + length)));
      bytes = bytes.subarray(nl + 1 + length);
    }
    assert.equal(frames.filter(frame => frame.type === "hello").length, 1);
    if (graph !== "empty") {
      const manifest = frames.find(frame => frame.type === "hello").manifest;
      assert.deepEqual(manifest.functions.map(value => value.name), ["healthy", "group-leaf"]);
      assert.deepEqual(new Set(manifest.ignored.map(value => value.name)), new Set(["group-self", "api-user"]));
    }
  } finally {
    rmSync(temp, {recursive:true,force:true});
  }
});
}

test("copied platform runner enforces its output frame limit without checkout imports", () => {
  const temp = mkdtempSync(resolve(tmpdir(), "fireemu-package-output-"));
  try {
    const binary = resolve(temp, "unused-native-fixture");
    writeFileSync(binary, "not a native artifact\n");
    const output = buildPlatformPackage({ platformName: PLATFORMS[0].name,
      binaryPath: binary, outDir: resolve(temp, "platform"), version: "0.0.0-offline-test" });
    const code = resolve(temp, "functions"); mkdirSync(code);
    writeFileSync(resolve(code, "package.json"), JSON.stringify({main: "index.cjs"}));
    writeFileSync(resolve(code, "index.cjs"), `
      const fn=async()=>{};fn.run=fn;
      fn.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'},
        labels:{huge:'x'.repeat(17*1024*1024)}};
      module.exports={fn};
    `);
    const run=spawnSync(process.execPath,[resolve(output,"bin/runner-node/index.mjs"),"--source",code],{
      cwd:temp,env:{PATH:process.env.PATH,GCLOUD_PROJECT:"demo-package"},
      input:"",encoding:"utf8",timeout:5000,maxBuffer:1024*1024,
    });
    assert.equal(run.error,undefined);
    assert.equal(run.status,2);assert.match(run.stderr,/runner output failed \(frame too large\)/);
    assert.equal(run.stdout.includes('"type":"hello"'),false);
  } finally { rmSync(temp,{recursive:true,force:true}); }
});

test("copied runner applies the raw diagnostic limit before evaluating a codebase", () => {
  const temp = mkdtempSync(resolve(tmpdir(), "fireemu-package-diagnostics-"));
  try {
    const binary = resolve(temp, "unused-native-fixture");
    writeFileSync(binary, "not a native artifact\n");
    const output = buildPlatformPackage({ platformName: PLATFORMS[0].name,
      binaryPath: binary, outDir: resolve(temp, "platform"), version: "0.0.0-offline-test" });
    const code = resolve(temp, "functions"); mkdirSync(code);
    writeFileSync(resolve(code, "package.json"), '{"main":"index.cjs"}');
    writeFileSync(resolve(code, "index.cjs"), `
      process.stderr.write(Buffer.alloc(8 * 1024 * 1024 + 1));
      module.exports = {};
    `);
    const run = spawnSync(process.execPath, [resolve(output, "bin/runner-node/index.mjs"), "--source", code], {
      cwd: temp, env: {PATH: process.env.PATH, GCLOUD_PROJECT: "demo-package"},
      input: "", encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024,
    });
    assert.equal(run.error, undefined); assert.equal(run.status, 2);
    assert.equal(run.stderr, "");
    assert.equal(run.stdout.includes('"type":"hello"'), false);
  } finally { rmSync(temp, {recursive: true, force: true}); }
});
