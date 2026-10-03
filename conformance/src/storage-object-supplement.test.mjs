import assert from "node:assert/strict";
import { test, mock } from "node:test";
import { createServer, request as localHttpRequest } from "node:http";
import https from "node:https";
import fsPromises, { mkdtemp, readFile, realpath, rm, mkdir, copyFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rename, writeFile } from "node:fs/promises";

let api = {};
try {
  api = await import("./storage-object/supplement.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}
let runtime = {};
try {
  runtime = await import("./storage-object/supplement-record.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}
let comparison = {};
try {
  comparison = await import("./storage-object-compare/supplement-run.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}

test("supplement declares exact subjects, physical bounds, and retained original conditions", () => {
  assert.equal(typeof api.supplementPlan, "function", "bounded supplement plan is required");
  const plan = api.supplementPlan();
  assert.deepEqual(plan.limits, {
    m1Normal: 25,
    m1Recovery: 6,
    m1: 31,
    m4: 28,
    storage: 59,
    oauth: 1,
    tokeninfo: 1,
    rules: 4,
    bucket: 1,
    record: 66,
    precheck: 8,
    campaign: 140,
  });
  assert.deepEqual(plan.m1, {
    progress: 262144,
    wrongOffset: 262145,
    total: 262147,
    expectedStatus: "UNKNOWN",
  });
  assert.deepEqual(plan.m4.cases, [
    "gcs-omitted",
    "gcs-empty",
    "firebase-omitted",
    "firebase-empty",
  ]);
  assert.equal(plan.retainedOriginalConditionCount, 28);
  assert.equal(plan.parentClosed, false);
  assert.equal(api.supplementPayload().length, 262147);
  assert.deepEqual([...api.supplementPayload().subarray(262144)], [0, 1, 255]);
});

test("M4 requires every whole-bucket and prefix read and records observed 4xx without guessing status", () => {
  assert.equal(typeof api.judgeM4Case, "function");
  const empty = { status: 200, complete: true, body: Buffer.from('{"items":[]}') };
  const subject = { status: 418, complete: true, body: Buffer.from('{"error":"observed"}') };
  const good = { before: [empty, empty, empty], subject, after: [empty, empty, empty] };
  assert.equal(api.judgeM4Case(good), "RECORDED_UNREVIEWED");
  for (const status of [200, 201, 302, 500, null])
    assert.equal(api.judgeM4Case({ ...good, subject: { ...subject, status } }), "UNKNOWN");
  for (let index = 0; index < 6; index++) {
    const changed = structuredClone(good);
    (index < 3 ? changed.before : changed.after)[index % 3] = {
      ...empty,
      body: Buffer.from('{"nextPageToken":"x"}'),
    };
    assert.equal(api.judgeM4Case(changed), "UNKNOWN");
  }
  assert.equal(api.judgeM4Case({ ...good, after: good.after.slice(1) }), "UNKNOWN");
  assert.equal(api.judgeM4Case({ ...good, subject: { ...subject, complete: false } }), "UNKNOWN");
  assert.equal(
    api.judgeM4Case({
      ...good,
      after: [
        { ...empty, body: Buffer.from('{"items":[{"name":"unexpected"}],"items":[]}') },
        empty,
        empty,
      ],
    }),
    "UNKNOWN",
  );
  assert.equal(
    api.judgeM4Case({
      ...good,
      before: [{ ...empty, body: Buffer.from('{"error":"not a list"}') }, empty, empty],
    }),
    "UNKNOWN",
  );
});

function modelResponse(
  request,
  { wrongStatus = 409, unnamedStatus = 422, bucket = "test.bucket", runId = "a".repeat(20) } = {},
) {
  const name = "fireemu-object-supplement/" + runId + "/m1";
  const metadata = { name, bucket, generation: "1730000000000000", size: "262147" };
  const response = {
    status: 200,
    complete: true,
    headers: { "content-type": "application/json" },
    body: Buffer.from('{"kind":"storage#objects"}'),
  };
  if (
    request.label.includes("absent") ||
    request.label.includes("metadata-after-wrong") ||
    request.label.includes("media-after-wrong")
  ) {
    response.status = 404;
    response.body = Buffer.from('{"error":"missing"}');
  } else if (request.label === "m1-initiate")
    response.headers.location = `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=resumable&upload_id=model-owned&name=${encodeURIComponent(name)}`;
  else if (request.label === "m1-correct-chunk" || request.label.includes("query-")) {
    response.status = 308;
    response.headers.range = "bytes=0-262143";
    response.body = Buffer.alloc(0);
  } else if (request.label === "m1-wrong-offset") {
    response.status = wrongStatus;
    response.body = Buffer.from('{"error":"model-observation"}');
  } else if (
    request.label === "m1-correct-final" ||
    request.label.includes("metadata-positive") ||
    request.label === "m1-fresh-metadata"
  )
    response.body = Buffer.from(JSON.stringify(metadata));
  else if (request.label.includes("media-positive") || request.label === "m1-fresh-media") {
    response.body = api.supplementPayload();
    response.headers = {
      "content-type": "application/octet-stream",
      "x-goog-generation": metadata.generation,
    };
  } else if (request.label === "m1-conditional-delete") {
    response.status = 204;
    response.body = Buffer.alloc(0);
  } else if (request.label.endsWith("-subject")) {
    response.status = unnamedStatus;
    response.body = Buffer.from('{"error":"model-unnamed"}');
  }
  return response;
}

test("complete program observes actual wrong-offset and unnamed statuses and emits 25 plus 28 Storage attempts", async () => {
  assert.equal(typeof api.runSupplementProgram, "function");
  for (const wrongStatus of [400, 409, 418]) {
    const sent = [];
    const result = await api.runSupplementProgram(
      async (request) => {
        sent.push(request);
        return modelResponse(request, { wrongStatus });
      },
      { bucket: "test.bucket", runId: "a".repeat(20) },
    );
    assert.equal(result.outcome, "RECORDED_UNREVIEWED");
    assert.equal(sent.length, 53);
    const wrong = sent.find((request) => request.label === "m1-wrong-offset");
    assert.equal(wrong.headers["content-range"], "bytes 262145-262146/262147");
    assert.deepEqual([...wrong.body], [1, 255]);
    assert.deepEqual(
      [...sent.find((request) => request.label === "m1-correct-final").body],
      [0, 1, 255],
    );
    assert.equal(
      new URL(
        sent.find((request) => request.label === "m1-conditional-delete").url,
      ).searchParams.get("ifGenerationMatch"),
      "1730000000000000",
    );
    for (const request of sent.filter((request) => request.label.includes("-whole-"))) {
      const query = new URL(request.url).searchParams;
      assert.equal(query.get("versions"), "true");
      assert.equal(query.get("maxResults"), "1");
      assert.equal(query.has("prefix"), false);
    }
    for (const caseId of api.supplementPlan().m4.cases) {
      const subject = sent.find((request) => request.label === `${caseId}-subject`);
      assert.equal(new URL(subject.url).searchParams.has("name"), caseId.endsWith("empty"));
      if (caseId.endsWith("empty")) assert.equal(new URL(subject.url).searchParams.get("name"), "");
      assert.ok(subject.body.length <= 512);
    }
  }
});

async function temporaryRootFixture(roleFixturePath) {
  const directory = await mkdtemp(
    join(await realpath(tmpdir()), "object-supplement-root-fixture-"),
  );
  const sourceRoot = new URL("../../", import.meta.url);
  const files = [
    ...api.SUPPLEMENT_PATHS,
    "conformance/src/storage-object-compare/normalize.mjs",
    "conformance/src/storage-object-compare/compare.mjs",
  ];
  for (const path of files) {
    const target = join(directory, path);
    await mkdir(join(target, ".."), { recursive: true });
    await copyFile(new URL(path, sourceRoot), target);
  }
  await writeFile(join(directory, ".gitignore"), "docs.local/\n");
  const git = (args) =>
    execFileSync(
      "git",
      [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Local fixture",
        "-c",
        "user.email=local-fixture@example.invalid",
        ...args,
      ],
      { cwd: directory, stdio: "pipe" },
    );
  git(["init", "--quiet"]);
  git(["add", "."]);
  git(["commit", "--quiet", "-m", "local test fixture, no authority"]);
  const privateRoot = join(directory, "docs.local");
  const home = join(privateRoot, "runs/storage-object-native-supplement");
  for (const path of [
    join(home, "packets"),
    join(privateRoot, "instructions"),
    join(privateRoot, "reviews"),
  ])
    await mkdir(path, { recursive: true, mode: 0o700 });
  const save = async (path, value) => {
    const body = `${JSON.stringify(value)}\n`;
    await writeFile(path, body, { mode: 0o600 });
    return { path, sha256: api.sha256(body) };
  };
  const principal = {
    subject: "local-prior-subject",
    clientId: "local-prior-client",
    requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
  };
  const adc = await save(join(home, "fake-adc.json"), {
    type: "authorized_user",
    client_id: principal.clientId,
    client_secret: "LOCAL_ONLY_FAKE_SECRET",
    refresh_token: "LOCAL_ONLY_FAKE_REFRESH",
    quota_project_id: "fireemu-oracle-query",
  });
  const principalReceipt = await save(join(home, "prior-principal.json"), {
    kind: "ROOT_ACCEPTED_OWNER_PRINCIPAL",
    principalSha256: api.sha256(JSON.stringify(principal)),
    observedAt: new Date(Date.now() - 7200000).toISOString(),
    fixtureNotAuthority: true,
  });
  const mapping = await save(join(home, "prior-mapping.json"), {
    kind: "ROOT_ACCEPTED_FIREBASE_BUCKET_MAPPING",
    projectId: "fireemu-oracle-query",
    projectNumber: "123456789",
    bucket: "fireemu-oracle-query.firebasestorage.app",
    fixtureNotAuthority: true,
  });
  const target = {
    projectId: "fireemu-oracle-query",
    projectNumber: "123456789",
    bucket: "fireemu-oracle-query.firebasestorage.app",
    firebaseMappingReceipt: mapping,
  };
  const snapshot = {
    releaseName: `projects/${target.projectId}/releases/firebase.storage/${target.bucket}`,
    rulesetName: `projects/${target.projectId}/rulesets/local-fixture`,
    createTime: "2026-10-03T00:00:00Z",
    updateTime: "2026-10-03T00:00:00Z",
    sourceSha256: api.sha256("LOCAL_ONLY_ALLOW_RULES"),
  };
  const acceptedReceipt = await save(join(home, "prior-rules.json"), {
    kind: "ROOT_ACCEPTED_OBJECT_RULES_BASELINE",
    targetSha256: api.sha256(JSON.stringify(target)),
    snapshotSha256: api.sha256(JSON.stringify(snapshot)),
    fixtureNotAuthority: true,
  });
  const review = await save(join(privateRoot, "reviews/local-fixture.json"), {
    kind: "LOCAL_ONLY_NOT_REVIEW_AUTHORITY",
  });
  const producer = await save(join(home, "local-cost-producer.json"), {
    kind: "LOCAL_ONLY_NOT_COST_AUTHORITY",
  });
  const costHistory = await save(join(home, "local-cost-history.json"), {
    kind: "LOCAL_ONLY_NOT_COST_AUTHORITY",
    reservations: [],
  });
  const runId = "a".repeat(20);
  const roleFixture = JSON.parse(await readFile(roleFixturePath));
  const ownerLines = Array.from({ length: 800 }, () => "local-only fixture row, no authority");
  for (const row of roleFixture.rows) ownerLines[row.line - 1] = row.rawWithoutLF;
  const currentPath = join(home, "current.json");
  const ownerPath = join(privateRoot, "instructions/owner-decisions.md");
  const ledgerPath = join(privateRoot, "runs/sandbox-ledger.jsonl");
  await save(ledgerPath, {
    ts: new Date(Date.now() - 7200000).toISOString(),
    taskId: "LOCAL_TEST",
    project: target.projectId,
    runId: "local-prior-closed",
    event: "finished",
    outcome: "stopped-clean",
    sandboxAtBaseline: true,
  });
  // HTTPS is intercepted before loading this copied default entry. These are simulated facts.
  const copied = await import(
    pathToFileURL(join(directory, "conformance/src/storage-object/supplement-record.mjs")).href
  );
  const source = await copied.supplementSourcePins();
  const cost = await save(join(home, "cost-current.json"), {
    schemaVersion: 2,
    kind: "ROOT_STORAGE_OBJECT_COST",
    currency: "USD",
    unit: "physical-request",
    producer,
    taskId: "STORAGE-OBJECT-SANDBOX",
    campaignId: "LOCAL_ONLY_FIXTURE",
    sourceCommit: source.commit,
    observedAt: new Date().toISOString(),
    history: costHistory,
    status: "KNOWN",
    ratesMicroUsd: { storage: 1, oauth: 1, tokeninfo: 1, rules: 1, bucket: 1 },
    priorSpentMicroUsd: 0,
    priorReservedMicroUsd: 0,
    reservationMicroUsd: 1000,
    ceilingMicroUsd: 10000000,
  });
  const packet = {
    schemaVersion: 2,
    kind: "ROOT_STORAGE_OBJECT_SUPPLEMENT",
    actor: copied.ROOT_ACTOR,
    basis: copied.ROOT_BASIS,
    foundation: copied.ORIGINAL_ROLE_PINS.map(([line, sha256]) => ({ line, sha256 })),
    source,
    grant: {
      taskId: "STORAGE-OBJECT-SANDBOX",
      stage: "record1",
      recording: 1,
      runId,
      nonce: "d".repeat(64),
      issuedAt: new Date(Date.now() - 10000).toISOString(),
      expiresAt: new Date(Date.now() + 1200000).toISOString(),
      maxPhysicalRequests: 67,
      campaignId: "LOCAL_ONLY_FIXTURE",
      writes: true,
      retries: 0,
      redirects: 0,
      stopOnUnknown: true,
    },
    adc: {
      path: adc.path,
      expectedSha256: adc.sha256,
      expectedClientId: principal.clientId,
      expectedQuotaProjectId: target.projectId,
    },
    principal,
    principalReceipt,
    target,
    rules: { ...snapshot, acceptedReceipt },
    cost,
  };
  const packetRef = await save(join(home, "packets/local-fixture.json"), packet);
  const decisions = {};
  for (const kind of ["E", "V", "GO"]) {
    const row = {
      kind,
      actor: copied.ROOT_ACTOR,
      basis: copied.ROOT_BASIS,
      foundation: packet.foundation,
      taskId: packet.grant.taskId,
      stage: packet.grant.stage,
      nonce: packet.grant.nonce,
      packetSha256: packetRef.sha256,
      sourceCommit: source.commit,
      review: {
        ...review,
        reviewer: "independent-codex-gpt-6.1-sol",
        decision: "APPROVE",
        must: 0,
        should: 0,
      },
      at: new Date(Date.now() - 5000).toISOString(),
    };
    const raw = "LOCAL_ONLY_NOT_AUTHORITY OBJECT-SUPPLEMENT-V2 " + JSON.stringify(row);
    ownerLines.push(raw);
    decisions[kind] = { line: ownerLines.length, sha256: api.sha256(raw) };
  }
  await writeFile(ownerPath, ownerLines.join("\n") + "\n", { mode: 0o600 });
  await save(currentPath, {
    schemaVersion: 2,
    kind: "ROOT_STORAGE_OBJECT_SUPPLEMENT_CURRENT",
    packet: packetRef,
    decisions,
  });
  return {
    directory,
    home,
    copied,
    packet,
    source,
    snapshot,
    runId,
    currentPath,
    ownerPath,
    ledgerPath,
    adcPath: adc.path,
    packetSha256: packetRef.sha256,
    events: join(home, "records", runId, "events.jsonl"),
  };
}

test("temporary default Root runtime binds durable start, one pair, shared precheck and all 61 physical attempts", async (context) => {
  const rolePath = process.env.FIREEMU_STORAGE_OBJECT_TEST_ROLE_FIXTURE;
  if (!rolePath) {
    context.skip("canonical fixture required; no actual Root inputs read");
    return;
  }
  const port = Number(process.env.PORT);
  assert.ok(port > 0, "run with portctl");
  const nativeHttps = https.request;
  const nativeOpen = fsPromises.open;
  let fixture;
  let peerAttempts = 0;
  let adcReads = 0;
  const intercept = mock.method(https, "request", (url, options, callback) => {
    assert.ok(fixture, "fixture must exist before any wire");
    const original = new URL(url);
    assert.equal(original.protocol, "https:");
    const local = new URL(`http://127.0.0.1:${port}${original.pathname}${original.search}`);
    return localHttpRequest(local, options, callback);
  });
  const files = mock.method(fsPromises, "open", async (...args) => {
    if (fixture && args[0] === fixture.adcPath) {
      adcReads++;
      const ledger = (await readFile(fixture.ledgerPath, "utf8"))
        .trim()
        .split("\n")
        .map(JSON.parse);
      assert.equal(ledger.at(-1).event, "started");
      const usage = (
        await readFile(join(fixture.home, "usage", `${fixture.packet.grant.nonce}.jsonl`), "utf8")
      )
        .trim()
        .split("\n")
        .map(JSON.parse);
      assert.equal(usage.at(-1).kind, "ACTIVE");
    }
    return nativeOpen(...args);
  });
  syncBuiltinESMExports();
  const server = createServer(async (request, response) => {
    peerAttempts++;
    const rows = (await readFile(fixture.events, "utf8")).trim().split("\n").map(JSON.parse);
    const intent = rows.at(-1);
    assert.equal(intent.kind, "ATTEMPT");
    assert.equal(intent.sequence, peerAttempts);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    assert.equal(body.length, intent.bodyBytes);
    assert.equal(api.sha256(body), intent.bodySha256);
    let observed;
    if (intent.family === "oauth") {
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/token");
      assert.equal(request.headers.authorization, undefined);
      observed = {
        status: 200,
        body: Buffer.from(
          JSON.stringify({
            access_token: "LOCAL_ONLY_FAKE_TOKEN",
            expires_in: 3600,
            token_type: "Bearer",
          }),
        ),
        headers: { "content-type": "application/json" },
      };
    } else {
      assert.equal(request.headers.authorization, "Bearer LOCAL_ONLY_FAKE_TOKEN");
      if (intent.family === "tokeninfo") {
        assert.equal(request.method, "POST");
        assert.equal(request.url, "/tokeninfo");
        assert.equal(body.length, 0);
        observed = {
          status: 200,
          body: Buffer.from(
            JSON.stringify({
              sub: fixture.packet.principal.subject,
              aud: fixture.packet.principal.clientId,
              azp: fixture.packet.principal.clientId,
              scope: fixture.packet.principal.requiredScopes[0],
              expires_in: "3600",
            }),
          ),
          headers: { "content-type": "application/json" },
        };
      } else if (intent.family === "rules") {
        const release = intent.label.endsWith("release");
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify(
              release
                ? {
                    name: fixture.snapshot.releaseName,
                    rulesetName: fixture.snapshot.rulesetName,
                    createTime: fixture.snapshot.createTime,
                    updateTime: fixture.snapshot.updateTime,
                  }
                : {
                    name: fixture.snapshot.rulesetName,
                    source: { files: [{ name: "local.rules", content: "LOCAL_ONLY_ALLOW_RULES" }] },
                  },
            ),
          ),
        };
      } else if (intent.family === "bucket")
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify({
              name: fixture.packet.target.bucket,
              projectNumber: fixture.packet.target.projectNumber,
              versioning: { enabled: false },
            }),
          ),
        };
      else
        observed = modelResponse(intent, {
          bucket: fixture.packet.target.bucket,
          runId: fixture.runId,
        });
    }
    response.writeHead(observed.status, observed.headers);
    response.end(observed.body);
  });
  try {
    fixture = await temporaryRootFixture(rolePath);
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    const result = await fixture.copied.runRootSupplement();
    assert.equal(result.outcome, "RECORDED_UNREVIEWED");
    assert.equal(result.requests, 61);
    assert.equal(peerAttempts, 61);
    assert.equal(adcReads, 1);
    const rows = (await readFile(fixture.events, "utf8")).trim().split("\n").map(JSON.parse);
    assert.deepEqual(rows.at(-1).families, {
      storage: 53,
      oauth: 1,
      tokeninfo: 1,
      rules: 4,
      bucket: 1,
      precheck: 1,
    });
    assert.deepEqual(
      rows
        .filter((row) => row.kind === "ATTEMPT" && row.phase === "PRECHECK")
        .map((row) => row.family),
      ["rules", "rules", "bucket", "precheck"],
    );
    const bytes = await readFile(fixture.events);
    const decoded = comparison.decodeSupplementJournal(bytes);
    assert.equal(decoded.exchanges.length, 53);
    for (const secret of [
      "LOCAL_ONLY_FAKE_SECRET",
      "LOCAL_ONLY_FAKE_REFRESH",
      "LOCAL_ONLY_FAKE_TOKEN",
    ])
      assert.equal(bytes.includes(Buffer.from(secret)), false);
    await assert.rejects(fixture.copied.runRootSupplement(), /PROJECT_SPACING|STOP/);
    assert.equal(peerAttempts, 61);
    const usage = await readFile(
      join(fixture.home, "usage", `${fixture.packet.grant.nonce}.jsonl`),
      "utf8",
    );
    assert.match(usage, /CONSUMED/);
    assert.equal(result.parentClosed, false);
  } finally {
    intercept.mock.restore();
    files.mock.restore();
    syncBuiltinESMExports();
    assert.equal(https.request, nativeHttps);
    await new Promise((resolve) => server.close(resolve));
    if (fixture) await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("temporary Root faults stop before ADC or wire, retain UNKNOWN locks, and never clean unnamed writes", async (context) => {
  const rolePath = process.env.FIREEMU_STORAGE_OBJECT_TEST_ROLE_FIXTURE;
  if (!rolePath) {
    context.skip("canonical fixture required for final fault gate");
    return;
  }
  const port = Number(process.env.PORT);
  assert.ok(port > 0, "run with portctl");
  for (const mode of [
    "start-fsync",
    "revoke-after-intent",
    "ledger-inode",
    "wrong-principal",
    "unknown-unnamed",
  ]) {
    let fixture;
    let peerAttempts = 0;
    let adcReads = 0;
    let fired = false;
    const nativeOpen = fsPromises.open;
    const intercept = mock.method(https, "request", (url, options, callback) => {
      assert.ok(fixture);
      const original = new URL(url);
      return localHttpRequest(
        new URL(`http://127.0.0.1:${port}${original.pathname}${original.search}`),
        options,
        callback,
      );
    });
    const files = mock.method(fsPromises, "open", async (...args) => {
      const handle = await nativeOpen(...args);
      if (!fixture) return handle;
      if (args[0] === fixture.adcPath) adcReads++;
      const relevant =
        (mode === "start-fsync" && args[0] === fixture.ledgerPath) ||
        (["revoke-after-intent", "ledger-inode"].includes(mode) &&
          args[0] === join(fixture.home, "usage", `${fixture.packet.grant.nonce}.jsonl`));
      if (relevant) {
        const originalSync = handle.sync.bind(handle);
        handle.sync = async () => {
          const data = (await readFile(args[0], "utf8")).trim().split("\n").map(JSON.parse);
          const row = data.at(-1);
          if (
            !fired &&
            ((mode === "start-fsync" && row.event === "started") ||
              (mode !== "start-fsync" && row.kind === "ATTEMPT"))
          ) {
            fired = true;
            if (mode === "start-fsync") throw new Error("LOCAL_TEST_FSYNC_FAILURE");
            if (mode === "revoke-after-intent")
              await writeFile(
                fixture.ownerPath,
                (await readFile(fixture.ownerPath, "utf8")) +
                  `REVOKED packetSha256=${fixture.packetSha256}\n`,
                { mode: 0o600 },
              );
            else {
              const body = await readFile(fixture.ledgerPath);
              await rename(fixture.ledgerPath, `${fixture.ledgerPath}.old`);
              await writeFile(fixture.ledgerPath, body, { mode: 0o600 });
            }
          }
          await originalSync();
        };
      }
      return handle;
    });
    syncBuiltinESMExports();
    const labels = [];
    const server = createServer(async (request, response) => {
      peerAttempts++;
      const intent = (await readFile(fixture.events, "utf8"))
        .trim()
        .split("\n")
        .map(JSON.parse)
        .at(-1);
      assert.equal(intent.kind, "ATTEMPT");
      labels.push(intent.label);
      request.resume();
      let observed;
      if (intent.family === "oauth")
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify({
              access_token: "LOCAL_ONLY_FAKE_TOKEN",
              expires_in: 3600,
              token_type: "Bearer",
            }),
          ),
        };
      else if (intent.family === "tokeninfo")
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify({
              sub:
                mode === "wrong-principal" ? "different-prior" : fixture.packet.principal.subject,
              aud: fixture.packet.principal.clientId,
              azp: fixture.packet.principal.clientId,
              scope: fixture.packet.principal.requiredScopes[0],
              expires_in: "3600",
            }),
          ),
        };
      else if (intent.family === "rules")
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify(
              intent.label.endsWith("release")
                ? {
                    name: fixture.snapshot.releaseName,
                    rulesetName: fixture.snapshot.rulesetName,
                    createTime: fixture.snapshot.createTime,
                    updateTime: fixture.snapshot.updateTime,
                  }
                : {
                    name: fixture.snapshot.rulesetName,
                    source: { files: [{ name: "local.rules", content: "LOCAL_ONLY_ALLOW_RULES" }] },
                  },
            ),
          ),
        };
      else if (intent.family === "bucket")
        observed = {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify({
              name: fixture.packet.target.bucket,
              projectNumber: fixture.packet.target.projectNumber,
            }),
          ),
        };
      else
        observed = modelResponse(intent, {
          bucket: fixture.packet.target.bucket,
          runId: fixture.runId,
          unnamedStatus: mode === "unknown-unnamed" ? 200 : 422,
        });
      response.writeHead(observed.status, observed.headers);
      response.end(observed.body);
    });
    try {
      fixture = await temporaryRootFixture(rolePath);
      await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
      await assert.rejects(fixture.copied.runRootSupplement(), /SUPPLEMENT_STOP/);
      assert.equal(adcReads, mode === "start-fsync" ? 0 : 1);
      assert.equal(
        peerAttempts,
        mode === "wrong-principal" ? 2 : mode === "unknown-unnamed" ? 35 : 0,
      );
      const usage = await readFile(
        join(fixture.home, "usage", `${fixture.packet.grant.nonce}.jsonl`),
        "utf8",
      );
      assert.match(usage, /UNKNOWN/);
      assert.doesNotMatch(usage, /CONSUMED/);
      assert.equal(
        (
          await fsPromises.stat(
            join(
              fixture.directory,
              "docs.local/runs/sandbox-locks",
              `${fixture.packet.target.projectId}.lock`,
            ),
          )
        ).isFile(),
        true,
      );
      const events = (await readFile(fixture.events, "utf8")).trim().split("\n").map(JSON.parse);
      assert.equal(events.at(-1).kind, "UNKNOWN");
      if (mode === "unknown-unnamed") {
        assert.equal(labels.at(-1), "gcs-omitted-subject");
        assert.equal(labels.filter((label) => label.includes("delete")).length, 1);
      }
    } finally {
      intercept.mock.restore();
      files.mock.restore();
      syncBuiltinESMExports();
      await new Promise((resolve) => server.close(resolve));
      if (fixture) await rm(fixture.directory, { recursive: true, force: true });
    }
  }
});

test("every positive ownership fault prevents DELETE; every unnamed unknown prevents guessed cleanup", async () => {
  const positiveLabels = [
    "m1-gcs-metadata-positive",
    "m1-gcs-media-positive",
    "m1-firebase-metadata-positive",
    "m1-firebase-media-positive",
    "m1-fresh-metadata",
    "m1-fresh-media",
  ];
  for (const label of positiveLabels) {
    const sent = [];
    const result = await api.runSupplementProgram(
      async (request) => {
        sent.push(request);
        return request.label === label
          ? { complete: true, status: 404, body: Buffer.from("{}") }
          : modelResponse(request);
      },
      { bucket: "test.bucket", runId: "a".repeat(20) },
    );
    assert.equal(result.outcome, "UNKNOWN");
    assert.equal(
      sent.some((request) => request.method === "DELETE"),
      false,
    );
    assert.equal(result.recoveryRequiresNewGo, true);
  }
  for (const status of [200, 201, 302, 500, null]) {
    const sent = [];
    const result = await api.runSupplementProgram(
      async (request) => {
        sent.push(request);
        return modelResponse(request, { unnamedStatus: status });
      },
      { bucket: "test.bucket", runId: "a".repeat(20) },
    );
    assert.equal(result.outcome, "UNKNOWN");
    assert.equal(sent.at(-1).label, "gcs-omitted-subject");
    assert.equal(sent.filter((request) => request.method === "DELETE").length, 1);
  }
});

test("complete binary comparison keeps wire body layout and every observed error shape", () => {
  assert.equal(typeof comparison.compareSupplementRecords, "function");
  const make = (runId, body, bodyBytes) => ({
    runId,
    bucket: "test.bucket",
    project: "test-project",
    source: {},
    journalSha256: runId.repeat(4).slice(0, 64),
    outcome: "RECORDED_UNREVIEWED",
    exchanges: [
      {
        label: "gcs-omitted-subject",
        method: "POST",
        url: "https://storage.googleapis.com/upload/storage/v1/b/test.bucket/o?uploadType=media",
        status: 418,
        headers: { "content-type": "application/json" },
        body: Buffer.from(body),
        bodyBytes,
      },
    ],
  });
  const native = [
    make("a".repeat(20), '{"error":"observed"}', 24),
    make("b".repeat(20), '{"error":"observed"}', 24),
  ];
  const local = make("c".repeat(20), '{"error":"observed"}', 24);
  assert.equal(comparison.compareSupplementRecords({ native, local }).decision, "MATCH_UNREVIEWED");
  assert.equal(
    comparison.compareSupplementRecords({
      native,
      local: { ...local, exchanges: [{ ...local.exchanges[0], bodyBytes: 22 }] },
    }).decision,
    "NEEDS_REVIEW",
  );
  assert.equal(
    comparison.compareSupplementRecords({
      native,
      local: { ...local, exchanges: [{ ...local.exchanges[0], status: 400 }] },
    }).decision,
    "NEEDS_REVIEW",
  );
  assert.equal(comparison.compareSupplementRecords({ native, local }).parentClosed, false);
});

test("actual wire partial response stays UNKNOWN and a replaced journal inode prevents the next attempt", async () => {
  const port = Number(process.env.PORT);
  assert.ok(port > 0, "run with portctl");
  for (const mode of ["partial", "replace"]) {
    const directory = await mkdtemp(join(await realpath(tmpdir()), "object-supplement-fault-"));
    let received = 0;
    const server = createServer(async (_request, response) => {
      received++;
      if (mode === "partial") {
        response.writeHead(200, { "content-length": "99" });
        response.write("short");
        setImmediate(() => response.destroy());
      } else {
        const path = join(directory, "events.jsonl");
        await rename(path, `${path}.old`);
        await writeFile(path, "replacement", { mode: 0o600 });
        response.end("ok");
      }
    });
    try {
      await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
      const options = {
        origin: `http://127.0.0.1:${port}`,
        directory,
        requests: [
          { method: "GET", path: "/one", body: "" },
          { method: "GET", path: "/two", body: "" },
        ],
      };
      if (mode === "partial") {
        const observed = await runtime.observeLocalSupplement(options);
        assert.equal(observed.outcome, "UNKNOWN");
        assert.equal(observed.exchanges[0].status, null);
        assert.equal(observed.exchanges[0].complete, false);
      } else await assert.rejects(runtime.observeLocalSupplement(options), /HELD_FD_CHANGED/);
      assert.equal(received, 1);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("cleanup requires four consistent positive reads and fresh bytes plus born generation", () => {
  assert.equal(typeof api.cleanupGeneration, "function");
  const payload = api.supplementPayload();
  const generation = "1730000000000000";
  const metadata = {
    status: 200,
    complete: true,
    body: Buffer.from(
      JSON.stringify({ name: "owned/object", bucket: "test.bucket", generation, size: "262147" }),
    ),
  };
  const media = {
    status: 200,
    complete: true,
    body: payload,
    headers: { "x-goog-generation": generation },
  };
  const input = {
    name: "owned/object",
    bucket: "test.bucket",
    bornGeneration: generation,
    reads: [metadata, media, metadata, media],
    fresh: [metadata, media],
  };
  assert.equal(api.cleanupGeneration(input), generation);
  for (let index = 0; index < 6; index++) {
    const changed = { ...input, reads: [...input.reads], fresh: [...input.fresh] };
    (index < 4 ? changed.reads : changed.fresh)[index % (index < 4 ? 4 : 2)] = {
      status: 404,
      complete: true,
      body: Buffer.from("{}"),
    };
    assert.equal(api.cleanupGeneration(changed), null);
  }
  assert.equal(api.cleanupGeneration({ ...input, bornGeneration: "1730000000000001" }), null);
  assert.equal(
    api.cleanupGeneration({
      ...input,
      fresh: [metadata, { ...media, body: Buffer.from("different") }],
    }),
    null,
  );
});

test("finite admission model is sticky and enforces cost, spacing, expiry and family caps", () => {
  assert.equal(typeof api.admissionProblem, "function");
  const base = {
    stage: "record1",
    attempted: 0,
    families: { storage: 0, oauth: 0, tokeninfo: 0, rules: 0, bucket: 0 },
    pending: 0,
    failed: false,
    armed: true,
    sourceCurrent: true,
    grantCurrent: true,
    locksHeld: true,
    now: 2000000,
    started: 2000000,
    previousTerminal: 100000,
    grantExpires: 4000000,
    tokenExpires: 4000000,
    baselineObserved: 2000000,
    costKnown: true,
    priorSpent: 1,
    priorReserved: 2,
    reservation: 3,
    ceiling: 10000000,
    ownerVerified: true,
    ownerPending: false,
  };
  assert.equal(api.admissionProblem(base, "storage"), null);
  const cases = [
    { failed: true },
    { armed: false },
    { sourceCurrent: false },
    { grantCurrent: false },
    { locksHeld: false },
    { pending: 1 },
    { costKnown: false },
    { priorReserved: 10000000 },
    { previousTerminal: 2000000 },
    { now: 3000001 },
    { grantExpires: 2000000 },
    { tokenExpires: 2000000 },
    { baselineObserved: 1600000 },
    { attempted: 66 },
  ];
  for (const delta of cases)
    assert.equal(typeof api.admissionProblem({ ...base, ...delta }, "storage"), "string");
  let state = 0x790;
  for (let sample = 0; sample < 4096; sample++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const family = ["storage", "oauth", "tokeninfo", "rules", "bucket"][state % 5];
    const cap = { storage: 59, oauth: 1, tokeninfo: 1, rules: 4, bucket: 1 }[family];
    const count = (state >>> 8) % (cap + 3);
    const candidate = {
      ...base,
      ownerVerified: !["oauth", "tokeninfo"].includes(family),
      ownerPending: family === "tokeninfo",
      families: { ...base.families, [family]: count },
    };
    assert.equal(api.admissionProblem(candidate, family) === null, count < cap);
  }
});

test("finite phase model excludes every unarmed, expired, unfunded, pending and unverified effect", () => {
  const base = {
    stage: "record1",
    attempted: 0,
    families: { storage: 0, oauth: 0, tokeninfo: 0, rules: 0, bucket: 0 },
    now: 2000000,
    started: 2000000,
    previousTerminal: null,
    grantExpires: 4000000,
    tokenExpires: 4000000,
    baselineObserved: 2000000,
    priorSpent: 0,
    priorReserved: 0,
    reservation: 1,
    ceiling: 10000000,
    ownerPending: false,
  };
  let states = 0;
  for (let bits = 0; bits < 512; bits++) {
    const flags = Array.from({ length: 9 }, (_, index) => Boolean(bits & (1 << index)));
    const [
      armed,
      failed,
      sourceCurrent,
      grantCurrent,
      locksHeld,
      costKnown,
      ownerVerified,
      pending,
      expired,
    ] = flags;
    const state = {
      ...base,
      armed,
      failed,
      sourceCurrent,
      grantCurrent,
      locksHeld,
      costKnown,
      ownerVerified,
      pending: pending ? 1 : 0,
      tokenExpires: expired ? base.now : base.tokenExpires,
    };
    const legal =
      armed &&
      !failed &&
      sourceCurrent &&
      grantCurrent &&
      locksHeld &&
      costKnown &&
      ownerVerified &&
      !pending &&
      !expired;
    assert.equal(api.admissionProblem(state, "storage") === null, legal, `finite state ${bits}`);
    states++;
  }
  assert.equal(states, 512);
  assert.notEqual(
    api.admissionProblem(
      {
        ...base,
        armed: true,
        failed: false,
        sourceCurrent: true,
        grantCurrent: true,
        locksHeld: true,
        costKnown: true,
        ownerVerified: false,
        ownerPending: true,
        pending: 0,
      },
      "storage",
    ),
    null,
  );
});

test("actual local wire has durable intent before independent peer observation, bounded body and no redirect retry", async () => {
  assert.equal(typeof runtime.observeLocalSupplement, "function");
  const port = Number(process.env.PORT);
  assert.ok(Number.isInteger(port) && port > 0, "run physical observer with portctl");
  const directory = await mkdtemp(join(await realpath(tmpdir()), "object-supplement-wire-"));
  let received = 0;
  const server = createServer(async (_request, response) => {
    received++;
    const lines = (await readFile(join(directory, "events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.equal(lines.at(-1).kind, "ATTEMPT");
    assert.equal(lines.at(-1).sequence, received);
    response.writeHead(302, { location: "/second" });
    response.end("observed redirect");
  });
  try {
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    const result = await runtime.observeLocalSupplement({
      origin: `http://127.0.0.1:${port}`,
      directory,
      requests: [{ method: "GET", path: "/first", body: "" }],
    });
    assert.equal(received, 1);
    assert.equal(result.exchanges[0].status, 302);
    assert.equal(result.outcome, "UNKNOWN");
    assert.equal(result.sendAuthorized, false);
    const ledger = (await readFile(join(directory, "events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      ledger.map((row) => row.kind),
      ["STARTED", "ATTEMPT", "RESPONSE", "UNKNOWN"],
    );
    await assert.rejects(
      runtime.observeLocalSupplement({
        origin: "https://storage.googleapis.com",
        directory,
        requests: [],
      }),
      /LOCAL_ONLY/,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
