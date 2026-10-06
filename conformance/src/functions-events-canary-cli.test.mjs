import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  buildCanaryBatchCli,
  buildCanaryCli,
  formalHandlers,
  gen1StorageDeployOrder,
  mainDeployHandlers,
  probeCanaries,
} from "./functions-events/canary-cli.mjs";

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
  for (const name of ["fsCreatedV1", "fsCreatedV2", "storageFinalizedV1", "storageFinalizedV2"]) {
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

test("the delivery probe selects the stdout capture and nothing else can", () => {
  for (const name of ["fsCreatedV1", "fsCreatedV2", "storageFinalizedV1", "storageFinalizedV2"]) {
    const probe = buildCanaryCli("deploy", "demo-events-prod", name, {
      ...cliOptions,
      captureMode: "stdout",
    });
    assert.equal(probe.env.FE_EVENTS_CAPTURE_MODE, "stdout");
    assert.equal(probe.env.FE_EVENTS_MODE, "production");
    const explicit = buildCanaryCli("deploy", "demo-events-prod", name, {
      ...cliOptions,
      captureMode: "reject-canary",
    });
    assert.equal(explicit.env.FE_EVENTS_CAPTURE_MODE, "reject-canary");
    for (const captureMode of ["socket", "", "STDOUT", 1, null]) {
      assert.throws(
        () => buildCanaryCli("deploy", "demo-events-prod", name, { ...cliOptions, captureMode }),
        /capture mode/,
      );
    }
  }
});

test("canary CLI rejects an unreviewed function or malformed project", () => {
  for (const name of [
    "authCreatedV1",
    "storageDeletedV1",
    "storageFinalizedV2,fsCreatedV2",
    "fsCreatedV2,storageFinalizedV2",
    "",
  ]) {
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

test("the delivery probe set is exactly the twelve reviewed handlers and deploys in one command", () => {
  assert.deepEqual(probeCanaries, [
    "fsUpdatedV1",
    "fsUpdatedV2",
    "fsDeletedV1",
    "fsDeletedV2",
    "fsWrittenV1",
    "fsWrittenV2",
    "storageDeletedV1",
    "storageDeletedV2",
    "storageMetadataUpdatedV1",
    "storageMetadataUpdatedV2",
    "pubsubPublishedV1",
    "pubsubPublishedV2",
  ]);
  const deploy = buildCanaryBatchCli("deploy", "demo-events-prod", probeCanaries, {
    ...cliOptions,
    captureMode: "stdout",
  });
  assert.deepEqual(deploy.args, [
    "deploy",
    "--config",
    cliOptions.configPath,
    "--project",
    "demo-events-prod",
    "--only",
    probeCanaries.map((name) => `functions:events:${name}`).join(","),
    "--non-interactive",
    "--debug",
  ]);
  assert.equal(deploy.env.FE_EVENTS_CAPTURE_MODE, "stdout");
  assert.equal(deploy.env.FE_EVENTS_MODE, "production");
  assert.equal(deploy.args.includes("--force"), false);
  const remove = buildCanaryBatchCli("delete", "demo-events-prod", probeCanaries, cliOptions);
  assert.deepEqual(remove.args, [
    "functions:delete",
    ...probeCanaries,
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
  assert.equal(remove.env.FE_EVENTS_CAPTURE_MODE, "reject-canary");
  for (const built of [deploy, remove]) {
    assert.equal(built.env.GOOGLE_CLOUD_QUOTA_PROJECT, "demo-events-prod");
    assert.equal(built.env.XDG_CONFIG_HOME, cliOptions.configHome);
    for (const envName of [
      "FIREBASE_TOKEN",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "CLOUDSDK_CONFIG",
      "FIRESTORE_EMULATOR_HOST",
    ]) {
      assert.equal(built.env[envName], undefined);
    }
  }
});

test("the batch CLI takes exactly the reviewed set, once each, in the reviewed order", () => {
  const bad = [
    probeCanaries.slice(1),
    probeCanaries.toReversed(),
    [...probeCanaries, "fsCreatedV1"],
    [...probeCanaries.slice(0, 11), "fsUpdatedV1"],
    [...probeCanaries.slice(0, 11), "fsUpdatedV1,fsUpdatedV2"],
    [],
    probeCanaries.join(","),
    ["fsCreatedV1", "fsCreatedV2"],
    ["storageFinalizedV1", "storageFinalizedV2"],
  ];
  for (const names of bad) {
    for (const action of ["deploy", "delete"]) {
      assert.throws(
        () => buildCanaryBatchCli(action, "demo-events-prod", names, cliOptions),
        /exactly one reviewed set/,
      );
    }
  }
  assert.throws(
    () => buildCanaryBatchCli("other", "demo-events-prod", probeCanaries, cliOptions),
    /unknown canary CLI action/,
  );
  assert.throws(
    () => buildCanaryBatchCli("deploy", "futaba-prod;other", probeCanaries, cliOptions),
    /project ID/,
  );
  assert.throws(
    () =>
      buildCanaryBatchCli("deploy", "demo-events-prod", probeCanaries, {
        ...cliOptions,
        configHome: "",
      }),
    /absolute configHome/,
  );
  assert.throws(
    () =>
      buildCanaryBatchCli("deploy", "demo-events-prod", probeCanaries, {
        ...cliOptions,
        captureMode: "socket",
      }),
    /capture mode/,
  );
});

test("the single-function helper still refuses the probe set's names", () => {
  for (const name of probeCanaries) {
    assert.throws(
      () => buildCanaryCli("deploy", "demo-events-prod", name, cliOptions),
      /unreviewed canary function/,
    );
  }
});

test("the formal recording's set is the fixture's 22 handlers and deploys and deletes in one command each", () => {
  const exported = [
    ...readFileSync(
      new URL("../functions-events/fixtures/index.js", import.meta.url),
      "utf8",
    ).matchAll(/^exports\.(\w+) =/gm),
  ].map((m) => m[1]);
  assert.equal(formalHandlers.length, 22);
  assert.deepEqual(formalHandlers.toSorted(), exported.toSorted());
  const deploy = buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, {
    ...cliOptions,
    captureMode: "stdout",
  });
  assert.equal(
    deploy.args[deploy.args.indexOf("--only") + 1],
    formalHandlers.map((n) => `functions:events:${n}`).join(","),
  );
  assert.equal(deploy.env.FE_EVENTS_CAPTURE_MODE, "stdout");
  const remove = buildCanaryBatchCli("delete", "demo-events-prod", formalHandlers, {
    ...cliOptions,
    captureMode: "stdout",
  });
  assert.deepEqual(remove.args.slice(1, 1 + formalHandlers.length), formalHandlers);
  assert.equal(remove.args.filter((a) => a === "functions:delete").length, 1);
});

test("--force and --dry-run are opt-in, for the deploy only, and leave the probe argv as it was", () => {
  const options = { ...cliOptions, captureMode: "stdout" };
  const plain = buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, options);
  assert.ok(!plain.args.includes("--force"));
  assert.ok(!plain.args.includes("--dry-run"));
  const probe = buildCanaryBatchCli("deploy", "demo-events-prod", probeCanaries, cliOptions);
  assert.ok(!probe.args.includes("--force") && !probe.args.includes("--dry-run"));
  const forced = buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, {
    ...options,
    force: true,
  });
  assert.deepEqual(
    forced.args,
    plain.args.toSpliced(plain.args.indexOf("--non-interactive") + 1, 0, "--force"),
  );
  const dry = buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, {
    ...options,
    force: true,
    dryRun: true,
  });
  assert.deepEqual(dry.args, [...forced.args, "--dry-run"]);
  const off = buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, {
    ...options,
    force: false,
    dryRun: false,
  });
  assert.deepEqual(off.args, plain.args);
  for (const flags of [{ force: true }, { dryRun: true }, { force: false }])
    assert.throws(
      () =>
        buildCanaryBatchCli("delete", "demo-events-prod", formalHandlers, { ...options, ...flags }),
      /for the deploy only/,
    );
  for (const flags of [{ force: "yes" }, { dryRun: 1 }, { force: null }])
    assert.throws(
      () =>
        buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, { ...options, ...flags }),
      /boolean/,
    );
  // the single-canary builder takes neither flag
  assert.ok(
    !buildCanaryCli("deploy", "demo-events-prod", "fsCreatedV1", cliOptions).args.includes(
      "--force",
    ),
  );
});

test("the batch CLI still refuses a partial, reordered or mixed set", () => {
  const options = { ...cliOptions, captureMode: "stdout" };
  for (const names of [
    formalHandlers.slice(1),
    formalHandlers.toReversed(),
    [...formalHandlers.slice(0, 21), "fsCreatedV1"],
    [...probeCanaries, ...formalHandlers],
  ]) {
    assert.throws(
      () => buildCanaryBatchCli("deploy", "demo-events-prod", names, options),
      /reviewed/,
    );
  }
});

test("v7: the four Gen1 Storage functions deploy one at a time, storageFinalizedV1 first; the main deploy is the other 18", () => {
  assert.deepEqual(gen1StorageDeployOrder, [
    "storageFinalizedV1",
    "storageDeletedV1",
    "storageMetadataUpdatedV1",
    "storageArchivedV1",
  ]);
  assert.equal(mainDeployHandlers.length, 18);
  assert.deepEqual(
    mainDeployHandlers,
    formalHandlers.filter((name) => !gen1StorageDeployOrder.includes(name)),
    "the other 18, in the formal order",
  );
  // every function is in exactly one of the two groups
  assert.deepEqual(
    [...mainDeployHandlers, ...gen1StorageDeployOrder].toSorted(),
    formalHandlers.toSorted(),
  );
  const options = { ...cliOptions, captureMode: "stdout", force: true };
  const only = (names) =>
    buildCanaryBatchCli("deploy", "demo-events-prod", names, options).args[
      buildCanaryBatchCli("deploy", "demo-events-prod", names, options).args.indexOf("--only") + 1
    ];
  assert.equal(
    only(mainDeployHandlers),
    mainDeployHandlers.map((n) => `functions:events:${n}`).join(","),
  );
  for (const name of gen1StorageDeployOrder) {
    const plan = buildCanaryBatchCli("deploy", "demo-events-prod", [name], options);
    assert.equal(plan.args[plan.args.indexOf("--only") + 1], `functions:events:${name}`);
    assert.ok(plan.args.includes("--force"));
    assert.ok(plan.args.includes("--non-interactive"));
    assert.equal(plan.env.FE_EVENTS_CAPTURE_MODE, "stdout");
  }
  // the full set still deploys (the dry run) and deletes as before
  assert.ok(buildCanaryBatchCli("deploy", "demo-events-prod", formalHandlers, options));
  assert.ok(
    buildCanaryBatchCli("delete", "demo-events-prod", formalHandlers, {
      ...cliOptions,
      captureMode: "stdout",
    }),
  );
});

test("v7: nothing but those reviewed sets deploys, and only the full set deletes", () => {
  const options = { ...cliOptions, captureMode: "stdout" };
  const refuse = (action, names) =>
    assert.throws(
      () => buildCanaryBatchCli(action, "demo-events-prod", names, options),
      /reviewed/,
    );
  // pairs, triples and the whole group of four are not reviewed: one at a time is the point
  refuse("deploy", gen1StorageDeployOrder);
  refuse("deploy", gen1StorageDeployOrder.slice(0, 2));
  refuse("deploy", [gen1StorageDeployOrder[1], gen1StorageDeployOrder[0]]);
  // a single function that is not one of the four
  refuse("deploy", ["fsCreatedV1"]);
  refuse("deploy", ["storageFinalizedV2"]);
  // the main set with one of the four added, or with one removed
  refuse("deploy", [...mainDeployHandlers, "storageFinalizedV1"]);
  refuse("deploy", mainDeployHandlers.slice(1));
  refuse("deploy", mainDeployHandlers.toReversed());
  // a delete of the main set or of one function
  refuse("delete", mainDeployHandlers);
  refuse("delete", ["storageFinalizedV1"]);
  refuse("delete", gen1StorageDeployOrder);
});
