import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import { lstat, mkdtemp, open, readFile, readdir, rm, mkdir } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { classifyResponse } from "./storage-rules/acceptance.mjs";
import { createCaptureJournal } from "./storage-rules/capture-journal.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";
import { createReservationJournal } from "./storage-rules/reservation-journal.mjs";
import { buildRefTables, createRuntimeRefStore } from "./storage-rules/runtime-refs.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";

const closure = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)),
);
const options = {
  runId: "local-run",
  sourceCommit: "a".repeat(40),
  queryProjectNumber: "1".repeat(12),
  idpProjectNumber: "2".repeat(12),
  queryApiKeyId: "00000000-0000-4000-8000-000000000001",
  idpApiKeyId: "00000000-0000-4000-8000-000000000002",
};
const binding = {
  bucket: "synthetic-rules-bucket",
  prefix: "STORAGE-RULES/local-run/",
  uidA: "storage-rules-local-run-user-a",
  uidB: "storage-rules-local-run-user-b",
};
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "4".repeat(64);
const CANARIES = {
  downloadToken: "0a1b2c3d-CANARYDOWNLOADTOKEN-9f8e7d6c",
  idToken:
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkNBTkFSWSJ9.eyJzdWIiOiJDQU5BUlktVUlEIiwiYXVkIjoiQ0FOQVJZIn0.Q0FOQVJZU0lHTkFUVVJFMDEyMzQ1Njc4OQ",
  accessToken: "ya29.CANARYaccessToken0123456789abcdefABCDEF",
  refreshToken: "1//CANARYrefreshToken0123456789abcdefABCDEFghij",
  apiKey: "AIzaCANARYAPIKEY0123456789abcdefghijklm",
  uploadId: "CANARYUPLOADID0123456789",
  passwordHash: "CANARYPASSWORDHASH0123456789abcdef==",
  keyString: "CANARYKEYSTRINGVALUE0123456789abcdef",
  pem: "Q0FOQVJZUEVNS0VZQk9EWTAxMjM0NTY3ODlhYmNkZWY=",
};
const SESSION = `https://firebasestorage.googleapis.com/v0/b/${binding.bucket}/o?name=x&upload_id=${CANARIES.uploadId}&upload_protocol=resumable`;
const forms = (secret) => [
  secret,
  encodeURIComponent(secret),
  Buffer.from(secret).toString("base64"),
  Buffer.from(secret).toString("hex"),
  JSON.stringify(secret).slice(1, -1),
];
const VALUES = {
  generation: "1700000000000001",
  metageneration: "1",
  "update-time": "2026-09-29T10:00:00Z",
  "ruleset-name": "projects/fireemu-oracle-query/rulesets/abc",
  "page-token": "next",
};
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const json = (status, body, extra = {}) => ({
  status,
  rawHeaders: Object.entries({
    "Content-Type": "application/json; charset=UTF-8",
    ...extra,
  }).flat(),
  bytes: Buffer.from(JSON.stringify(body)),
});
const noisy = (status, body, extra) =>
  json(
    status,
    {
      ...body,
      downloadTokens: CANARIES.downloadToken,
      idToken: CANARIES.idToken,
      access_token: CANARIES.accessToken,
      refreshToken: CANARIES.refreshToken,
      passwordHash: CANARIES.passwordHash,
      keyString: CANARIES.keyString,
      link: `https://x/o?token=${CANARIES.downloadToken}&key=${CANARIES.apiKey}`,
      session: SESSION,
      pem: `-----BEGIN PRIVATE KEY-----\n${CANARIES.pem}\n-----END PRIVATE KEY-----`,
    },
    {
      "X-Goog-Upload-URL": SESSION,
      "Set-Cookie": `SID=${CANARIES.refreshToken}`,
      "X-GUploader-UploadID": CANARIES.uploadId,
      "X-Goog-Upload-Control-URL": CANARIES.uploadId,
      Location: CANARIES.uploadId,
      "X-Firebase-Storage-Download-Tokens": CANARIES.downloadToken,
      ...extra,
    },
  );

async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    const stat = await lstat(path);
    if (stat.isDirectory()) out.push(...(await walk(path)));
    else out.push(path);
  }
  return out;
}

async function scenario(t, _mutate = {}) {
  const directory = await mkdtemp(join(tmpdir(), "storage-rules-run-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const io = { open, lstat, mkdir };
  const requestIds = manifest.rows.map((r) => r.id);
  const reservations = await createReservationJournal({
    directory,
    runId: options.runId,
    sourceCommit: options.sourceCommit,
    manifestDigest: manifest.sha256,
    requestIds,
    preflightIds: manifest.preflightIds,
    io: { open, lstat },
  });
  const capture = await createCaptureJournal({
    directory,
    runId: options.runId,
    sourceCommit: options.sourceCommit,
    manifestDigest: manifest.sha256,
    digestSalt: salt,
    requestIds,
    io,
  });
  const refs = createRuntimeRefStore({
    tables: buildRefTables(manifest),
    runId: options.runId,
    digestSalt: salt,
    writeProof: (proof) => capture.writeProof(proof),
  });
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const counter = createStage3RequestCounter({
    preflightIds: manifest.preflightIds,
    onStarted: reservations.onStarted,
    onReserve: reservations.onReserve,
    onTerminal: reservations.onTerminal,
  });
  const resolve = (reference, rowId) => refs.resolve(reference, rowId);
  const fallback = (reference) => VALUES[reference.type];
  let attempt = 0;
  const step = async (
    id,
    transport,
    { phase = "normal", resolver = fallback, classify = true } = {},
  ) => {
    const r = row(id);
    // Auth and cache rows are carried by their own modules; only their route is recorded here.
    const prepared = ["auth", "credential-cache"].includes(r.family)
      ? {
          targetSha256: "7".repeat(64),
          redacted: `${r.request.method} ${r.request.origin}${r.request.path ?? ""}`,
        }
      : targets.prepare(r, resolver);
    await capture.writeIntent({
      operationId: id,
      phase,
      targetSha256: prepared.targetSha256,
      redactedTarget: prepared.redacted,
      mutationKey: null,
    });
    const raw = await (phase === "preflight"
      ? counter.sendPreflight(id, transport, () => true)
      : counter.send(id, transport));
    attempt++;
    await capture.writeResponse({
      operationId: id,
      attempt,
      response: { status: raw.status, rawHeaders: raw.rawHeaders, bytes: raw.bytes },
    });
    if (classify) {
      const result = classifyResponse(r, raw);
      await capture.writeFacts({
        operationId: id,
        kind: result.kind,
        verdict: result.verdict,
        facts: result.facts,
      });
      return { raw, result, attempt };
    }
    return { raw, attempt };
  };
  return {
    directory,
    reservations,
    capture,
    refs,
    counter,
    targets,
    resolve,
    step,
    close: async () => {
      await capture.close();
      await reservations.close();
    },
  };
}

test("no file in a run directory holds bearer material after a run that meets it in every writer", async (t) => {
  const ctx = await scenario(t);
  await ctx.counter.start({ runId: options.runId });
  for (const id of manifest.preflightIds)
    await ctx.step(id, async () => noisy(200, { note: "preflight" }), {
      phase: "preflight",
      classify: false,
    });
  ctx.counter.admit();

  const name = row("management/control-0/seed").request.objectName;
  const objectBody = (extra = {}) => ({
    kind: "storage#object",
    bucket: binding.bucket,
    name,
    size: "4",
    generation: "1700000000000001",
    metageneration: "1",
    metadata: { firebaseStorageDownloadTokens: CANARIES.downloadToken },
    ...extra,
  });
  await ctx.step("management/control-0/baseline-metadata", async () =>
    noisy(404, {
      error: {
        code: 404,
        message: "No such object",
        errors: [{ reason: "notFound", message: "x" }],
      },
    }),
  );
  const seed = await ctx.step("management/control-0/seed", async () => noisy(200, objectBody()));
  assert.equal(seed.result.verdict, "accepted");
  await ctx.refs.bind({
    ref: {
      kind: "runtime-reference",
      type: "generation",
      key: name,
      resolveOnlyAfterDurableProof: true,
    },
    value: seed.result.facts.generation,
    provenance: {
      operationId: "management/control-0/seed",
      attempt: seed.attempt,
      verdict: "accepted",
      deletable: true,
    },
  });
  const meta = await ctx.step("management/control-0/seed-metadata", async () =>
    noisy(200, objectBody({ generation: "1700000000000002" })),
  );
  assert.equal(meta.result.verdict, "present");
  await ctx.refs.bind({
    ref: {
      kind: "runtime-reference",
      type: "generation",
      key: name,
      resolveOnlyAfterDurableProof: true,
    },
    value: meta.result.facts.generation,
    provenance: {
      operationId: "management/control-0/seed-metadata",
      attempt: meta.attempt,
      verdict: "present",
      deletable: true,
    },
  });
  const del = await ctx.step(
    "management/control-0/delete",
    async () => ({
      status: 204,
      rawHeaders: ["X-Goog-Upload-URL", SESSION],
      bytes: Buffer.alloc(0),
    }),
    { resolver: ctx.resolve },
  );
  assert.equal(del.result.verdict, "accepted");

  // Writers meet bearer material directly; each must refuse or redact it.
  await assert.rejects(
    ctx.capture.writeFacts({
      operationId: "management/control-0/delete",
      kind: "k",
      verdict: "present",
      facts: { leaked: CANARIES.idToken },
    }),
    /event refused/,
  );
  await assert.rejects(
    ctx.capture.writeIntent({
      operationId: "management/control-0/absence-metadata",
      phase: "normal",
      targetSha256: "5".repeat(64),
      redactedTarget: `GET https://x/o?token=${CANARIES.downloadToken}&key=${CANARIES.apiKey}`,
      mutationKey: null,
    }),
    /event refused/,
  );
  await assert.rejects(
    ctx.capture.writeProof({
      runId: options.runId,
      type: "page-token",
      key: `k?upload_id=${CANARIES.uploadId}`,
      operationId: "management/control-0/delete",
      attempt: 9,
      valueSha256: "6".repeat(64),
    }),
    /event refused/,
  );
  await ctx.capture.writeNote({
    operationId: null,
    text: `transport failed for ${SESSION}: access_token=${CANARIES.accessToken} Bearer ${CANARIES.refreshToken} ${CANARIES.idToken} key=${CANARIES.apiKey}`,
  });
  await ctx.counter.finish("finished");
  await ctx.close();

  const files = await walk(ctx.directory);
  assert.ok(
    files.some((f) => f.endsWith("reservations.jsonl")) &&
      files.some((f) => f.endsWith("captures.jsonl")) &&
      files.filter((f) => f.includes("/blobs/")).length >= 3,
  );
  for (const file of files) {
    const bytes = await readFile(file);
    const text = bytes.toString("latin1");
    for (const [label, secret] of Object.entries({ ...CANARIES, session: SESSION })) {
      for (const form of forms(secret))
        assert.equal(text.includes(form), false, `${label} in ${file.slice(ctx.directory.length)}`);
    }
    assert.equal((await lstat(file)).mode & 0o077, 0, file);
  }
  const captured = (await readFile(join(ctx.directory, "captures.jsonl"), "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const responses = captured.filter((entry) => entry.event === "response");
  assert.equal(responses.length, manifest.preflightIds.length + 4);
  assert.ok(responses.every((entry) => entry.data.spans.every((span) => !("value" in span))));
  assert.ok(
    captured.some((entry) => entry.event === "proof") &&
      captured.some((entry) => entry.event === "note"),
  );
  const proof = captured.find((entry) => entry.event === "proof");
  assert.deepEqual(Object.keys(proof.data).sort(), [
    "attempt",
    "key",
    "operationId",
    "runId",
    "type",
    "valueSha256",
  ]);
});
