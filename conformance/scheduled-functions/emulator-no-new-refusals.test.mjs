import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("both profiles accept recorded manifests except the documented strict refusals", (t) => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const common = spawnSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(common.status, 0, common.stderr);
  const repository = dirname(common.stdout.trim());
  const binary = resolve(root, process.env.FIREEMU_BIN ?? "target/w4/debug/fireemu");
  const work = mkdtempSync(join(root, "target/codex-out/no-new-refusals-"));
  t.after(() => rmSync(work, { recursive: true, force: true }));
  const home = join(work, "home");
  mkdirSync(home);
  const env = { PATH: process.env.PATH, HOME: home };
  const recorded = [];
  const v5 = JSON.parse(
    readFileSync(join(root, "conformance/scheduled-functions/fixtures/calendar-v5-recorded.json")),
  );
  for (const [id, body] of Object.entries(v5.createRequests)) {
    recorded.push({
      id: `calendar-v5/${id}`,
      body,
      strictRefusal: ["c07-create", "c08-create"].includes(id),
    });
  }
  for (const [label, runId] of [
    ["recording-1", "189fb441835b2645"],
    ["recording-2", "75478d967aa09afc"],
  ]) {
    const directory = join(repository, "docs.local/runs/calendar-v6", label);
    const journal = readFileSync(join(directory, `journal-${runId}.jsonl`), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    const result = JSON.parse(readFileSync(join(directory, `result-${runId}.json`)));
    assert.equal(result.closureReady, true);
    const creates = journal.filter(
      (row) => row.state === "before-send" && row.id.endsWith("-create"),
    );
    assert.equal(creates.length, 46);
    for (const row of creates) {
      const outcome = result.cases.find(({ id }) => `${id}-create` === row.id)?.outcome;
      assert.ok(["accepted", "refused", "refused-other"].includes(outcome), row.id);
      recorded.push({
        id: `${label}/${row.id}`,
        body: row.json,
        anchor: row.dispatchAt,
        strictRefusal: outcome !== "accepted",
      });
    }
  }
  const delivery = join(repository, "docs.local/runs/scheduled-delivery");
  for (const run of ["run-1", "run-2", "run-3", "run-4"]) {
    const directory = join(delivery, run);
    const journals = readdirSync(directory).filter((name) =>
      /^journal-[a-f0-9]+\.jsonl$/.test(name),
    );
    assert.equal(journals.length, 1);
    const journal = readFileSync(join(directory, journals[0]), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    for (const row of journal.filter(
      (row) => row.state === "before-send" && row.method === "POST" && row.json?.schedule,
    )) {
      recorded.push({ id: `delivery/${run}/${row.id}`, body: row.json, anchor: row.dispatchAt });
    }
  }
  for (const item of recorded) {
    const retryConfig = {};
    for (const [key, value] of Object.entries(item.body.retryConfig ?? {})) {
      const field = {
        minBackoffDuration: "minBackoffSeconds",
        maxBackoffDuration: "maxBackoffSeconds",
        maxRetryDuration: "maxRetrySeconds",
      }[key];
      retryConfig[field ?? key] = field ? Number(value.slice(0, -1)) : value;
    }
    item.manifest = {
      specVersion: "v1alpha1",
      endpoints: {
        calendarProbe: {
          platform: "gcfv2",
          entryPoint: "calendarProbe",
          region: ["us-central1"],
          scheduleTrigger: {
            schedule: item.body.schedule,
            timeZone: item.body.timeZone,
            retryConfig,
          },
        },
      },
    };
  }
  for (const run of readdirSync(delivery)
    .filter((name) => /^run-[1-4](?:-check)?$/.test(name))
    .sort()) {
    const manifest = JSON.parse(
      readFileSync(join(delivery, run, "discovery/functions-manifest.json")),
    );
    recorded.push({ id: `delivery/${run}`, manifest });
    // A refused endpoint must not hide the fractional-window or accepted retry declarations.
    for (const [name, endpoint] of Object.entries(manifest.endpoints)) {
      if (endpoint.scheduleTrigger)
        recorded.push({
          id: `delivery/${run}/${name}`,
          manifest: { ...manifest, endpoints: { [name]: endpoint } },
        });
    }
  }
  assert.equal(
    JSON.parse(readFileSync(join(root, "conformance/node_modules/firebase-tools/package.json")))
      .version,
    "15.28.2",
  );
  const emulatorFailures = [],
    strictFailures = [];
  let officialAccepted = 0,
    strictRefused = 0;
  for (const [index, item] of recorded.entries()) {
    const directory = join(work, String(index));
    mkdirSync(directory);
    const saved = join(directory, "sdk-manifest.json");
    writeFileSync(saved, JSON.stringify(item.manifest));
    // The pinned CLI's discovery and emulator conversion are pure; credentials and network are unavailable.
    const official = spawnSync(
      process.execPath,
      [
        "-e",
        `
      const http = require('node:http'), https = require('node:https'), net = require('node:net');
      http.request = https.request = net.connect = net.createConnection = () => { throw new Error('offline acceptance test'); };
      const { createRequire } = require('node:module');
      const req = createRequire(process.argv[1]);
      const manifest = JSON.parse(require('node:fs').readFileSync(process.argv[2]));
      req('./lib/deploy/functions/runtimes/discovery/v1alpha1.js').buildFromV1Alpha1(manifest, 'demo-scheduled-refusals', 'us-central1', 'nodejs22');
      const endpoints = Object.entries(manifest.endpoints).map(([id, ep]) => ({ ...ep, id, project: 'demo-scheduled-refusals', region: ep.region?.[0] ?? 'us-central1' }));
      const emulator = req('./lib/emulator/functionsEmulatorShared.js');
      emulator.prepareEndpoints(endpoints);
      const definitions = emulator.emulatedFunctionsFromEndpoints(endpoints);
      if (definitions.length !== endpoints.length) throw new Error('missing emulator definition');
    `,
        join(root, "conformance/node_modules/firebase-tools/package.json"),
        saved,
      ],
      { cwd: directory, env, encoding: "utf8", timeout: 10000 },
    );
    assert.equal(
      official.status,
      0,
      `${item.id}: pinned CLI discovery: ${official.error ?? official.stderr}`,
    );
    officialAccepted++;
    writeFileSync(
      join(directory, "package.json"),
      JSON.stringify({ private: true, main: "index.cjs" }),
    );
    // Replay the recorded SDK metadata through the actual runner, retaining every endpoint option.
    writeFileSync(
      join(directory, "index.cjs"),
      `
      const manifest = require('./sdk-manifest.json');
      for (const [name, endpoint] of Object.entries(manifest.endpoints)) {
        const handler = async () => {};
        handler.run = handler;
        handler.__endpoint = endpoint;
        exports[name] = handler;
      }
    `,
    );
    const retries = Object.values(item.manifest.endpoints).map(
      (ep) => ep.scheduleTrigger?.retryConfig ?? {},
    );
    const count = retries.some((retry) => retry.retryCount >= 6);
    const fractional = retries.some(
      (retry) => retry.maxRetrySeconds != null && !Number.isInteger(retry.maxRetrySeconds),
    );
    const expectedRefusal = item.strictRefusal || count || fractional;
    for (const profile of ["emulator", "strict"]) {
      const config = join(directory, "fireemu.json");
      writeFileSync(
        config,
        JSON.stringify({
          schemaVersion: 1,
          profile,
          daemon: { clockStart: item.anchor ?? "2026-10-05T00:30:00Z" },
        }),
      );
      const ports = [
        "firestore",
        "http",
        "storage",
        "functions",
        "eventarc",
        "tasks",
        "pubsub",
        "ui",
        "hub",
        "logging",
      ].flatMap((name) => [`--${name}-port`, "0"]);
      const local = spawnSync(
        binary,
        [
          "exec",
          "--config",
          config,
          "--project",
          "demo-scheduled-refusals",
          "--only",
          "functions",
          "--functions",
          directory,
          ...ports,
          "--",
          process.execPath,
          "-e",
          "console.log('MANIFEST_ACCEPTED')",
        ],
        { cwd: root, env, encoding: "utf8", timeout: 20000 },
      );
      assert.equal(local.error, undefined, `${item.id}/${profile}: ${local.error}`);
      const accepted = local.status === 0 && local.stdout.includes("MANIFEST_ACCEPTED");
      if (profile === "emulator" && !accepted)
        emulatorFailures.push(`${item.id}: ${local.stderr.trim()}`);
      if (profile === "strict") {
        if (!accepted) strictRefused++;
        if (
          accepted === Boolean(expectedRefusal) ||
          (!accepted &&
            !/manifest: function .*?(schedule:|time zone:|Cloud Scheduler refuses this schedule's job)/.test(
              local.stderr,
            ))
        ) {
          strictFailures.push(
            `${item.id}: expected ${expectedRefusal ? "refusal" : "acceptance"}; ${local.stderr.trim()}`,
          );
        }
      }
    }
  }
  t.diagnostic(
    `firebase-tools 15.28.2 accepts ${officialAccepted} recorded manifests; strict refuses ${strictRefused}; emulator refuses ${emulatorFailures.length}`,
  );
  assert.deepEqual(strictFailures, [], "strict has exactly the documented startup refusals");
  assert.deepEqual(emulatorFailures, [], "emulator accepts every manifest the pinned CLI accepts");
});
