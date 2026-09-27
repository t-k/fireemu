import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildCanaryCli } from "./functions-events/canary-cli.mjs";

const configPath = new URL("../functions-events/firebase.json", import.meta.url);
const fixtureLockPath = new URL("../functions-events/fixtures/pnpm-lock.yaml", import.meta.url);
const cliOptions = {
  configHome: "/tmp/events-config",
  configPath: "/checkout/conformance/functions-events/firebase.json",
  workDir: "/tmp/events-run",
  home: "/tmp/owner-home",
  path: "/usr/bin:/bin",
  parentEnv: { FIREBASE_TOKEN: "unreviewed-token", GCLOUD_PROJECT: "wrong-project" },
};

test("the production Firebase config contains only the event fixture codebase", () => {
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  assert.deepEqual(config, {
    functions: {
      source: "fixtures",
      codebase: "events",
      runtime: "nodejs22",
    },
  });
});

test("each canary CLI command pins its project, config, quota project, and one function", () => {
  for (const name of ["fsCreatedV1", "fsCreatedV2"]) {
    const deploy = buildCanaryCli("deploy", "demo-events-prod", name, cliOptions);
    assert.deepEqual(deploy.args, [
      "deploy",
      "--config",
      cliOptions.configPath,
      "--project",
      "demo-events-prod",
      "--only",
      `functions:events:${name}`,
      "--non-interactive",
      "--debug",
    ]);
    assert.equal(deploy.env.GOOGLE_CLOUD_QUOTA_PROJECT, "demo-events-prod");
    assert.equal(deploy.env.XDG_CONFIG_HOME, "/tmp/events-config");
    assert.equal(deploy.cwd, cliOptions.workDir);
    assert.equal(deploy.env.HOME, cliOptions.home);
    assert.equal(deploy.env.PATH, cliOptions.path);
    assert.equal(deploy.env.GCLOUD_PROJECT, "demo-events-prod");
    assert.equal(deploy.env.FE_EVENTS_MODE, "production");
    assert.equal(deploy.env.FE_EVENTS_PRIMARY_BUCKET, "demo-events-prod.firebasestorage.app");
    assert.equal(deploy.env.FE_EVENTS_CAPTURE_MODE, "reject-canary");
    for (const envName of [
      "FIREBASE_TOKEN",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "CLOUDSDK_CONFIG",
      "FIRESTORE_EMULATOR_HOST",
    ]) {
      assert.equal(deploy.env[envName], undefined);
    }
    assert.equal(deploy.args.includes("--force"), false);
    const remove = buildCanaryCli("delete", "demo-events-prod", name, cliOptions);
    assert.deepEqual(remove.args, [
      "functions:delete",
      name,
      "--config",
      cliOptions.configPath,
      "--region",
      "us-central1",
      "--project",
      "demo-events-prod",
      "--non-interactive",
      "--force",
      "--debug",
    ]);
    assert.equal(remove.env.GOOGLE_CLOUD_QUOTA_PROJECT, "demo-events-prod");
    assert.equal(remove.env.XDG_CONFIG_HOME, "/tmp/events-config");
    assert.equal(remove.cwd, cliOptions.workDir);
  }
});

test("canary CLI rejects an unreviewed function or malformed project", () => {
  for (const name of ["authCreatedV1", "fsCreatedV2,storageFinalizedV2", ""]) {
    assert.throws(() => buildCanaryCli("deploy", "demo-events-prod", name, cliOptions));
  }
  assert.throws(() => buildCanaryCli("deploy", "futaba-prod;other", "fsCreatedV1", cliOptions));
  assert.throws(() => buildCanaryCli("other", "demo-events-prod", "fsCreatedV1", cliOptions));
  assert.throws(() =>
    buildCanaryCli("deploy", "demo-events-prod", "fsCreatedV1", { ...cliOptions, configHome: "" }),
  );
  assert.throws(() =>
    buildCanaryCli("deploy", "demo-events-prod", "fsCreatedV1", {
      ...cliOptions,
      configPath: "relative",
    }),
  );
  assert.throws(() =>
    buildCanaryCli("deploy", "demo-events-prod", "fsCreatedV1", {
      ...cliOptions,
      workDir: "relative",
    }),
  );
});

test("the deployable fixture has its own frozen SDK dependency lockfile", () => {
  const lock = readFileSync(fixtureLockPath, "utf8");
  assert.match(lock, /^lockfileVersion: '9\.0'/m);
  assert.match(lock, /firebase-admin:\n\s+specifier: 14\.3\.0/);
  assert.match(lock, /firebase-functions:\n\s+specifier: 7\.3\.2/);
});
