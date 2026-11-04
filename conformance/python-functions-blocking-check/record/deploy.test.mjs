// The deploy helpers: the declaration check of the SDK's own discovery, the readiness summary, the CLI plan, and the refusals
// of the source copy.
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import test from "node:test";
import { tempDir } from "./testtmp.mjs";
import {
  cliPlan,
  declarationProblems,
  discover,
  isActive,
  isGone,
  prepareSource,
  sdkVersionProblems,
  sourceProblems,
  summarize,
} from "./deploy.mjs";
import { functionName } from "./plan.mjs";

const endpoint = () => ({
  entryPoint: "pcblock",
  platform: "gcfv2",
  region: ["us-central1"],
  eventType: "providers/cloud.auth/eventTypes/user.beforeCreate",
  options: { idToken: false, accessToken: false, refreshToken: false },
  eventTrigger: false,
});
const endpoints = () => ({ pcblock: endpoint() });

test("the declared endpoint of the fixture passes", () =>
  assert.deepEqual(declarationProblems(endpoints()), []));

const BREAKS = [
  ["a missing function", (e) => delete e.pcblock, /expected pcblock/],
  ["an extra function", (e) => (e.extra = endpoint()), /expected pcblock/],
  ["a wrong entry point", (e) => (e.pcblock.entryPoint = "x"), /entry point x/],
  ["a wrong platform", (e) => (e.pcblock.platform = "gcfv1"), /platform gcfv1/],
  ["another region", (e) => (e.pcblock.region = ["europe-west1"]), /region/],
  ["two regions", (e) => (e.pcblock.region = ["us-central1", "europe-west1"]), /region/],
  [
    "another blocking event",
    (e) => (e.pcblock.eventType = "providers/cloud.auth/eventTypes/user.beforeSignIn"),
    /blocking event type/,
  ],
  ["an event trigger as well", (e) => (e.pcblock.eventTrigger = true), /event trigger/],
  ["id token forwarding", (e) => (e.pcblock.options.idToken = true), /idToken forwarding is true/],
  [
    "access token forwarding",
    (e) => (e.pcblock.options.accessToken = true),
    /accessToken forwarding/,
  ],
  [
    "refresh token forwarding",
    (e) => (e.pcblock.options.refreshToken = true),
    /refreshToken forwarding/,
  ],
  ["no options", (e) => delete e.pcblock.options, /idToken forwarding is undefined/],
];
for (const [name, edit, pattern] of BREAKS)
  test(`a declaration problem is reported: ${name}`, () => {
    const e = endpoints();
    edit(e);
    assert.ok(
      declarationProblems(e).some((p) => pattern.test(p)),
      JSON.stringify(declarationProblems(e)),
    );
  });

const lists = (state, service = true) => ({
  v2: { functions: state === null ? [] : [{ name: functionName(), state }] },
  run: { services: service ? [{ name: "projects/p/locations/us-central1/services/pcblock" }] : [] },
});

test("readiness needs the function ACTIVE with its Cloud Run service, and gone needs neither nor a stray", () => {
  assert.equal(isActive(summarize(lists("ACTIVE"))), true);
  assert.equal(isActive(summarize(lists("DEPLOYING"))), false);
  assert.equal(isActive(summarize(lists("ACTIVE", false))), false);
  assert.equal(isActive(summarize({})), false);
  assert.equal(isGone(summarize({ v2: { functions: [] }, run: { services: [] } })), true);
  assert.equal(isGone(summarize(lists(null, false))), true);
  assert.equal(isGone(summarize(lists("ACTIVE"))), false);
  assert.equal(isGone(summarize(lists(null, true))), false, "a service without its function");
  const stray = {
    v2: {
      functions: [
        {
          name: "projects/fireemu-oracle-idp/locations/europe-west1/functions/pcblock",
          state: "ACTIVE",
        },
      ],
    },
    run: { services: [] },
  };
  assert.equal(summarize(stray).stray, true);
  assert.equal(isGone(summarize(stray)), false);
  const other = {
    v2: {
      functions: [
        {
          name: "projects/fireemu-oracle-idp/locations/us-central1/functions/another",
          state: "ACTIVE",
        },
      ],
    },
    run: { services: [] },
  };
  assert.equal(summarize(other).stray, false);
  assert.equal(isGone(summarize(other)), true);
});

const options = {
  configHome: "/h/config",
  configPath: "/s/firebase.json",
  workDir: "/s",
  home: "/h",
  path: "/n:/usr/bin",
};
test("the dry run is the deploy argv with --dry-run last, and neither carries --force", () => {
  const deploy = cliPlan("deploy", options);
  const dry = cliPlan("dry-run", options);
  assert.deepEqual(dry.args, [...deploy.args, "--dry-run"]);
  assert.equal(deploy.args.includes("--force"), false);
  assert.ok(deploy.args.includes("--non-interactive"));
  assert.deepEqual(
    deploy.args.slice(deploy.args.indexOf("--only"), deploy.args.indexOf("--only") + 2),
    ["--only", "functions:pcblock"],
  );
  assert.equal(deploy.args.includes("--dry-run"), false);
  assert.deepEqual(
    deploy.args.slice(deploy.args.indexOf("--project"), deploy.args.indexOf("--project") + 2),
    ["--project", "fireemu-oracle-idp"],
  );
});

test("the delete names the one function, the region and the project, forced and non-interactive", () => {
  const { args } = cliPlan("delete", options);
  assert.deepEqual(args.slice(0, 2), ["functions:delete", "pcblock"]);
  assert.deepEqual(args.slice(args.indexOf("--region"), args.indexOf("--region") + 2), [
    "--region",
    "us-central1",
  ]);
  for (const flag of ["--force", "--non-interactive", "--project"])
    assert.ok(args.includes(flag), flag);
  assert.equal(args.filter((a) => a === "pcblock").length, 1);
});

test("the CLI environment is explicit and carries no ambient credential", () => {
  const { env, cwd } = cliPlan("deploy", options);
  assert.deepEqual(Object.keys(env).toSorted(), [
    "FIREBASE_CONFIG",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "HOME",
    "PATH",
    "SHELL",
    "XDG_CONFIG_HOME",
  ]);
  assert.equal(env.SHELL, "/bin/bash");
  assert.equal(env.GCLOUD_PROJECT, "fireemu-oracle-idp");
  assert.equal(cwd, "/s");
});

test("the CLI plan refuses an unknown action, a relative path and a missing PATH", () => {
  assert.throws(() => cliPlan("destroy", options), /unknown CLI action/);
  for (const key of ["configHome", "configPath", "workDir", "home"])
    assert.throws(() => cliPlan("deploy", { ...options, [key]: "relative" }), /absolute/);
  assert.throws(() => cliPlan("deploy", { ...options, path: "" }), /PATH/);
});

test("the source copy needs a full commit SHA", () => {
  const target = tempDir("pcb-deploy-");
  for (const bad of ["main", "abc123", "HEAD", "0".repeat(39), "g".repeat(40), "a".repeat(41)])
    assert.throws(
      () => prepareSource({ repoRoot: "/nonexistent", commit: bad, target }),
      /full SHA/,
    );
  assert.throws(
    () => prepareSource({ repoRoot: "/nonexistent-repo", commit: "a".repeat(40), target }),
    (e) => !/full SHA/.test(e.message),
  );
});

function repoWithFixture() {
  const repo = tempDir("pcb-repo-");
  const env = {
    PATH: process.env.PATH,
    HOME: repo,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_AUTHOR_NAME: "t",
    GIT_AUTHOR_EMAIL: "t@example.com",
    GIT_COMMITTER_NAME: "t",
    GIT_COMMITTER_EMAIL: "t@example.com",
  };
  const git = (...args) =>
    execFileSync("git", ["-C", repo, ...args], { env, encoding: "utf8" }).trim();
  mkdirSync(join(repo, "conformance/python-functions-blocking-check/fixture"), { recursive: true });
  mkdirSync(join(repo, "conformance/other"), { recursive: true });
  writeFileSync(join(repo, "conformance/python-functions-blocking-check/firebase.json"), "{}");
  writeFileSync(
    join(repo, "conformance/python-functions-blocking-check/fixture/main.py"),
    "x = 1\n",
  );
  writeFileSync(join(repo, "conformance/other/file"), "no");
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", "c");
  writeFileSync(join(repo, "conformance/python-functions-blocking-check/untracked.txt"), "u");
  return { repo, sha: git("rev-parse", "HEAD") };
}

test("the source copy takes the tracked files of the check at the commit, links the venv, and nothing else", () => {
  const { repo, sha } = repoWithFixture();
  const target = join(tempDir("pcb-target-"), "nested", "source");
  const venv = tempDir("pcb-venv-");
  const { configPath, fixtureDir } = prepareSource({
    repoRoot: repo,
    commit: sha,
    target,
    venvDir: venv,
  });
  assert.equal(
    configPath,
    join(target, "conformance/python-functions-blocking-check/firebase.json"),
  );
  assert.equal(readFileSync(join(fixtureDir, "main.py"), "utf8"), "x = 1\n");
  assert.equal(existsSync(join(target, "conformance/other")), false);
  assert.equal(
    existsSync(join(target, "conformance/python-functions-blocking-check/untracked.txt")),
    false,
  );
  assert.equal(lstatSync(join(fixtureDir, "venv")).isSymbolicLink(), true);
  assert.equal(lstatSync(target).mode & 0o777, 0o700);
  const none = prepareSource({
    repoRoot: repo,
    commit: sha,
    target: join(target, "again"),
    venvDir: undefined,
  });
  assert.equal(existsSync(join(none.fixtureDir, "venv")), false);
});

function fakeVenv(script) {
  const fixture = tempDir("pcb-fixture-");
  mkdirSync(join(fixture, "venv/bin"), { recursive: true });
  writeFileSync(join(fixture, "venv/bin/python"), script);
  chmodSync(join(fixture, "venv/bin/python"), 0o755);
  return fixture;
}

test("the discovery runs the venv's Python isolated, in the fixture, with the project settings only", () => {
  const fixture = fakeVenv(
    `#!/bin/sh\nprintf '{"first":"%s","pp":"%s","cwd":"%s","fc":%s,"gp":"%s","home":"%s"}' "$1" "$PYTHONPATH" "$(pwd -P)" "$FIREBASE_CONFIG" "$GCLOUD_PROJECT" "$HOME"\n`,
  );
  const directory = join(tempDir("pcb-dir-"), "made", "here");
  const out = discover({ fixtureDir: fixture, directory });
  assert.equal(out.first, "-I");
  assert.equal(out.pp, fixture);
  assert.equal(
    out.cwd,
    execFileSync("sh", ["-c", `cd ${fixture} && pwd -P`], { encoding: "utf8" }).trim(),
  );
  assert.deepEqual(out.fc, {
    projectId: "fireemu-oracle-idp",
    storageBucket: "fireemu-oracle-idp.firebasestorage.app",
  });
  assert.equal(out.gp, "fireemu-oracle-idp");
  assert.equal(out.home, directory);
  assert.equal(lstatSync(directory).mode & 0o777, 0o700);
});

test("an offline discovery failure is a problem, not a throw, and keeps only the first 300 characters of the error", () => {
  const failing = () => {
    throw Object.assign(new Error("boom"), { stderr: "Traceback: ImportError" });
  };
  const problems = sourceProblems({ fixtureDir: "/x", directory: "/y", discoverFn: failing });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /discovery of the fixture failed: Traceback/);
  assert.deepEqual(
    sourceProblems({ fixtureDir: "/x", directory: "/y", discoverFn: endpoints }),
    [],
  );
  const fixture = fakeVenv(`#!/bin/sh\nprintf '%s' "${"E".repeat(400)}" >&2\nexit 3\n`);
  const [problem] = sourceProblems({
    fixtureDir: fixture,
    directory: tempDir("pcb-dir-"),
  });
  assert.equal(problem.length, "the SDK discovery of the fixture failed: ".length + 300);
});

test("the SDK version in the environment must be the pinned one", () => {
  assert.deepEqual(
    sdkVersionProblems("/v", () => "0.6.0\n"),
    [],
  );
  assert.match(sdkVersionProblems("/v", () => "0.7.0")[0], /0\.7\.0, not 0\.6\.0/);
  assert.match(
    sdkVersionProblems("/v", () => {
      throw new Error("no");
    })[0],
    /cannot be imported/,
  );
});
