// Tests of the stage 1 Gen2 upload line probe: a minimal deploy whose only goal is to record the
// two `--debug` line forms (the generateUploadUrl answer and the upload's PUT status) and clean up.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { BOUNDS, createBudget } from "./harness.mjs";
import { assertTargetAbsent } from "./production.mjs";
import { FAKE_RECEIPT_SCRIPT, FH_PACKAGE, UPLOAD_OBJECT, deployWorld } from "./production.fake.mjs";
import {
  PROBE_LIMITS,
  assertProbeApproval,
  createFormsCollector,
  decideAfterDeploy,
  loggingApiState,
  maskProbeLine,
  runUploadProbe,
} from "./upload-probe.mjs";

const NUMBER = "123456789012";
const REAL_LOOKING = "987654321098";
const BUCKET = `gcf-v2-uploads-${NUMBER}.us-central1.cloudfunctions.appspot.com`;
const A_LINE = `[2026-10-26T01:02:03.456Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions:generateUploadUrl {"uploadUrl":"https://storage.googleapis.com/${BUCKET}/${UPLOAD_OBJECT}?X-Goog-Signature=SECRET-MARKER-9f3a","storageSource":{"bucket":"${BUCKET}","object":"${UPLOAD_OBJECT}"}}`;
const B_LINE = `[2026-10-26T01:02:04.000Z] <<< [apiv2][status] PUT https://storage.googleapis.com/${BUCKET}/${UPLOAD_OBJECT} 200`;

test("a recorded line is masked: the project number, the signed URL and nothing else", () => {
  const real = A_LINE.replaceAll(NUMBER, REAL_LOOKING);
  const masked = maskProbeLine(real, REAL_LOOKING);
  assert.doesNotMatch(masked, new RegExp(`${REAL_LOOKING}|SECRET-MARKER|X-Goog`));
  assert.ok(
    masked.includes(`gcf-v2-uploads-${NUMBER}.us-central1`),
    "masked with the fixture number",
  );
  assert.ok(masked.includes(UPLOAD_OBJECT), "the object name is kept");
  assert.ok(masked.includes('"uploadUrl":"[REDACTED UPLOAD URL]"'));
  assert.equal(maskProbeLine(B_LINE.replaceAll(NUMBER, REAL_LOOKING), REAL_LOOKING), B_LINE);
  // a number of another length is still masked with the fixture number, never kept
  assert.equal(maskProbeLine("x 4444444444 y", "4444444444"), "x 123456789012 y");
  assert.equal(maskProbeLine("x 4444444444444 y", "4444444444444"), "x 123456789012 y");
});

test("the forms collector records only the shapes: seen or not, codes, byte lengths, masked lines", () => {
  const collector = createFormsCollector(REAL_LOOKING);
  const aLine = A_LINE.replaceAll(NUMBER, REAL_LOOKING);
  collector.observe({ type: "receipt", bucket: "b", object: "o" }, aLine);
  collector.observe({ type: "put-status", bucket: "b", object: "o", status: 503 }, B_LINE);
  collector.observe({ type: "put-status", bucket: "b", object: "o", status: 200 }, B_LINE);
  const summary = collector.summary();
  assert.deepEqual(summary.putStatusCodes, [503, 200]);
  assert.equal(summary.receiptLineSeen, true);
  assert.equal(summary.putStatusLineSeen, true);
  assert.equal(summary.receiptLineBytes, Buffer.byteLength(aLine));
  assert.equal(collector.maskedLines().length, 3);
  assert.ok(!JSON.stringify(summary).includes(REAL_LOOKING));
  assert.ok(!collector.maskedLines().join("\n").includes(REAL_LOOKING));
  const empty = createFormsCollector(REAL_LOOKING).summary();
  assert.deepEqual(empty, {
    receiptLineSeen: false,
    putStatusLineSeen: false,
    putStatusCodes: [],
    receiptLineBytes: 0,
    putStatusLineBytes: 0,
  });
});

test("the stop rule: only seeing no receipt line stops; a missing PUT line is a finding", () => {
  const forms = (receipt, put) => ({ receiptLineSeen: receipt, putStatusLineSeen: put });
  assert.deepEqual(decideAfterDeploy(forms(true, true)), {
    decision: "continue",
    finding: "both-forms",
  });
  assert.deepEqual(decideAfterDeploy(forms(true, false)), {
    decision: "continue",
    finding: "put-status-line-missing",
  });
  assert.deepEqual(decideAfterDeploy(forms(false, true)), {
    decision: "stop",
    finding: "no-receipt-line",
  });
  assert.deepEqual(decideAfterDeploy(forms(false, false)), {
    decision: "stop",
    finding: "no-receipt-line",
  });
});

test("approval binds one decision, the commit and the packet", () => {
  const ok = "Decision: APPROVE\ngitSha: abc\npacketSha256: def\nNotes\n";
  assert.doesNotThrow(() => assertProbeApproval(ok, "abc", "def"));
  for (const [content, sha, packet] of [
    [ok, "abd", "def"],
    [ok, "abc", "deg"],
    ["Decision: CHANGES REQUESTED\ngitSha: abc\npacketSha256: def\n", "abc", "def"],
    [`${ok}Decision: APPROVE\n`, "abc", "def"],
    [`${ok}see gitSha: abd\n`, "abc", "def"],
    ["gitSha: abc\nDecision: APPROVE\npacketSha256: def\n", "abc", "def"],
  ]) {
    assert.throws(() => assertProbeApproval(content, sha, packet), /APPROVE must bind/);
  }
});

test("the packet's request caps can lower a budget and never raise it", () => {
  const budget = createBudget(PROBE_LIMITS);
  budget.take("cliDeploy");
  assert.throws(() => budget.take("cliDeploy"), /cliDeploy ceiling 1 reached/);
  assert.throws(() => budget.take("invocation"), /invocation ceiling 0 reached/);
  assert.throws(() => budget.take("auth"), /auth ceiling 0 reached/);
  assert.throws(() => createBudget({ cliDeploy: 1.5 }), /invalid request cap/);
  assert.throws(() => createBudget({ nothing: 1 }), /invalid request cap/);
  assert.equal(createBudget({ cliDeploy: 1000 }).snapshot().cliDeploy, 0);
  const wide = createBudget({ cliDeploy: 1000 });
  for (let n = 0; n < BOUNDS.cliDeploy; n += 1) wide.take("cliDeploy");
  assert.throws(() => wide.take("cliDeploy"), /ceiling 16 reached/);
  assert.deepEqual(
    { ...PROBE_LIMITS },
    {
      invocation: 0,
      auth: 0,
      control: 12,
      cleanup: 30,
      upload: 15,
      token: 12,
      cliDeploy: 1,
      cliDelete: 1,
    },
  );
});

async function probe({
  script,
  deleteStatus,
  loggingState,
  versionDeleteStatus,
  usedUploads = 0,
  buildsImage,
}) {
  const world = await deployWorld({
    deployScript: script,
    deleteStatus,
    caps: PROBE_LIMITS,
    buildsImage,
  });
  if (loggingState) world.deployed.loggingState = loggingState;
  if (versionDeleteStatus) world.deployed.versionDeleteStatus = versionDeleteStatus;
  for (let n = 0; n < usedUploads; n += 1) world.budget.take("upload");
  const result = await runUploadProbe({
    control: world.control,
    adcPath: "/adc",
    budget: world.budget,
    runDir: join(world.dir, "run"),
    projectNumber: NUMBER,
    run: world.run,
  });
  return { world, result };
}

const journalOf = (world) => readFile(join(world.dir, "run", "journal.jsonl"), "utf8");

test("both lines seen: the upload is deleted by generation, nothing else is touched, caps hold", async () => {
  const { world, result } = await probe({ script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200) });
  try {
    assert.equal(result.outcome, "recorded");
    assert.equal(result.decision, "continue");
    assert.equal(result.finding, "both-forms");
    assert.deepEqual(result.forms.putStatusCodes, [200]);
    assert.equal(result.uploadsClosureReady, true);
    assert.equal(result.a2Required, false);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    const deletes = world.gcs.requests.filter((r) => r.method === "DELETE");
    assert.equal(deletes.length, 1);
    assert.match(deletes[0].url, /ifGenerationMatch=\d+$/);
    const used = world.budget.snapshot();
    assert.equal(used.cliDeploy, 1);
    assert.equal(used.cliDelete, 1);
    assert.equal(used.invocation, 0);
    assert.equal(used.auth, 0);
    assert.equal(result.requests.cliDeploy, 1);
    assert.equal(result.estimatedUsd, 0.56);
    assert.equal(result.loggingApiState, "ENABLED");
    assert.deepEqual(world.calls, ["cliDeploy", "cliDelete"]);
    assert.doesNotMatch(await journalOf(world), /public-invoker-granted/);
    // the CLI's allUsers invoker binding is removed by exactly one setIamPolicy, and nothing else is written
    assert.equal(world.deployed.setPolicyCalls, 1);
    assert.deepEqual(world.deployed.bindings, []);
    assert.match(await journalOf(world), /public-invoker-revoked/);
    assert.equal(result.iamRevocationError, null);
    assert.match(await journalOf(world), /source-upload-deleted/);
    // the masked lines are what the lane turns into a replay fixture
    assert.equal(result.maskedLines.length, 2);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("the receipt line without the PUT line is a finding, and the upload is still deleted", async () => {
  const { world, result } = await probe({ script: FAKE_RECEIPT_SCRIPT("process.exit(0);") });
  try {
    assert.equal(result.outcome, "recorded");
    assert.equal(result.decision, "continue");
    assert.equal(result.finding, "put-status-line-missing");
    assert.equal(
      result.a2Required,
      true,
      "an unknown create settled by an own read needs the A2 read-back",
    );
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("neither line, or only the PUT line: stop, delete nothing in the bucket, still remove the function", async () => {
  for (const script of [
    'console.log("i  functions: deploying");\nprocess.exit(0);',
    `console.log("${B_LINE.replaceAll('"', '\\"')}");\nprocess.exit(0);`,
  ]) {
    const { world, result } = await probe({ script });
    try {
      assert.equal(result.decision, "stop");
      assert.equal(result.finding, "no-receipt-line");
      assert.equal(result.outcome, "stopped-needs-review");
      assert.equal(result.uploadsClosureReady, false);
      assert.equal(world.gcs.count("DELETE"), 0, "no DELETE in the uploads bucket");
      assert.ok(world.gcs.objects.has(UPLOAD_OBJECT), "the zip stays for a recovery packet");
      assert.deepEqual(world.calls, ["cliDeploy", "cliDelete"], "the function itself is removed");
      assert.equal(world.deployed.present, false);
    } finally {
      await rm(world.dir, { recursive: true, force: true });
    }
  }
});

test("a deploy that failed after both lines still deletes the upload and asks for review", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT(
      'console.error("Error: Failed to create function"); process.exit(1);',
      200,
    ),
  });
  try {
    assert.equal(result.outcome, "stopped-needs-review");
    assert.equal(result.decision, "continue");
    assert.equal(result.uploadsClosureReady, true);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a refused upload DELETE leaves the run needing review with the object in place", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    deleteStatus: 403,
  });
  try {
    assert.equal(result.outcome, "stopped-needs-review");
    assert.equal(result.uploadsClosureReady, false);
    assert.ok(world.gcs.objects.has(UPLOAD_OBJECT));
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("Cloud Logging is only read, never enabled, and its state is recorded", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    loggingState: "DISABLED",
  });
  try {
    assert.equal(result.loggingApiState, "DISABLED");
    assert.equal(result.outcome, "recorded", "the state is information for stage 2, not a stop");
    assert.ok(
      world.gcs.requests.every((r) => r.method !== "POST"),
      "no storage write",
    );
    const reply = await loggingApiState(async () => ({ status: 200, value: { state: "ENABLED" } }));
    assert.equal(reply, "ENABLED");
    assert.equal(await loggingApiState(async () => ({ status: 200, value: {} })), "UNKNOWN");
    assert.equal(await loggingApiState(async () => ({ status: 404, value: {} })), "UNKNOWN");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("the result and the journal name no bucket, object, project number or URL", async () => {
  const { world, result } = await probe({ script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200) });
  try {
    const serialized = JSON.stringify({ ...result, maskedLines: undefined });
    assert.doesNotMatch(
      serialized,
      new RegExp(`${NUMBER}|gcf-v2-uploads|${UPLOAD_OBJECT}|SECRET-MARKER|https://`),
    );
    const journal = await journalOf(world);
    assert.doesNotMatch(journal, new RegExp(`${NUMBER}|gcf-v2-uploads|SECRET-MARKER`));
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("masking removes a signed URL outside the uploadUrl field, and the field even without markers", () => {
  const put = `x PUT https://storage.googleapis.com/${BUCKET}/${UPLOAD_OBJECT}?GoogleAccessId=a%40b&Signature=SECRET-MARKER-9f3a done`;
  assert.doesNotMatch(maskProbeLine(put, NUMBER), /SECRET-MARKER|GoogleAccessId|Signature=/);
  const plain = '{"uploadUrl":"https://example.test/plain-path","storageSource":{}}';
  assert.equal(
    maskProbeLine(plain, NUMBER),
    '{"uploadUrl":"[REDACTED UPLOAD URL]","storageSource":{}}',
  );
});

test("the collector keeps the length of the PUT line, ignores other events and returns copies", () => {
  const collector = createFormsCollector(NUMBER);
  collector.observe({ type: "put-status", status: 200 }, "twelve bytes");
  collector.observe({ type: "other" }, "ignored line");
  collector.observe(null, "ignored line");
  const summary = collector.summary();
  assert.equal(summary.putStatusLineBytes, 12);
  assert.equal(collector.maskedLines().length, 1);
  summary.putStatusCodes.push(999);
  collector.maskedLines().push("x");
  assert.deepEqual(collector.summary().putStatusCodes, [200]);
  assert.equal(collector.maskedLines().length, 1);
});

test("an approval with a second decision on the line right after the packet is refused", () => {
  assert.throws(
    () =>
      assertProbeApproval(
        "Decision: APPROVE\ngitSha: a\npacketSha256: b\nDecision: APPROVE\n",
        "a",
        "b",
      ),
    /APPROVE must bind/,
  );
});

test("the Cloud Logging read trusts only a 200 answer with a state and survives a thrown error", async () => {
  assert.equal(
    await loggingApiState(async () => ({ status: 404, value: { state: "ENABLED" } })),
    "UNKNOWN",
  );
  assert.equal(
    await loggingApiState(async () => {
      throw new Error("reset");
    }),
    "UNKNOWN",
  );
  assert.equal(
    await loggingApiState(async () => ({ status: 200, value: { state: 5 } })),
    "UNKNOWN",
  );
  let allowed;
  await loggingApiState(async (_method, _url, _body, _kind, list) => {
    allowed = list;
    return { status: 200, value: { state: "ENABLED" } };
  });
  assert.deepEqual(allowed, [200, 403, 404]);
});

test("a negative request cap is refused", () => {
  assert.throws(() => createBudget({ cliDeploy: -1 }), /invalid request cap/);
});

test("the upload requests already spent bind the probe's own bound: no deploy when 15 are not left", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    usedUploads: 1,
  });
  try {
    assert.equal(result.outcome, "stopped-needs-review");
    assert.deepEqual(world.calls, [], "no deploy was started");
    assert.equal(result.requests.cliDeploy, 0);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a clean upload with an image that cannot be removed is still a run that needs review", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    versionDeleteStatus: 403,
  });
  try {
    assert.equal(result.uploadsClosureReady, true, "the upload itself was cleaned");
    assert.equal(result.residual, true);
    assert.equal(result.outcome, "stopped-needs-review");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a failed deploy is a residual run even when everything was cleaned", async () => {
  const { world, result } = await probe({
    script: FAKE_RECEIPT_SCRIPT('console.error("Error: Failed"); process.exit(1);', 200),
    buildsImage: false, // the build never ran, so only the failed deploy itself makes the run residual
  });
  try {
    assert.equal(result.uploadsClosureReady, true);
    assert.equal(result.residual, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a reserved function, service or image package that already exists stops before any deploy", async () => {
  const reply = (status, value = {}) => ({ status, value });
  for (const present of ["function", "service", "package"]) {
    const control = async (_method, url) => {
      const hit =
        (present === "function" && url.includes("/functions/")) ||
        (present === "service" && url.includes("/services/")) ||
        (present === "package" && url.includes("/packages/"));
      return hit ? reply(200, url.includes("/packages/") ? { name: FH_PACKAGE } : {}) : reply(404);
    };
    await assert.rejects(() => assertTargetAbsent(control, "http"), /already exists/, present);
  }
  await assert.doesNotReject(() => assertTargetAbsent(async () => reply(404), "http"));
});

test("a failed removal of the CLI's public invoker binding is shown in the result and the journal", async () => {
  const world = await deployWorld({
    deployScript: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    caps: PROBE_LIMITS,
  });
  world.deployed.setPolicyStatus = 403;
  try {
    const result = await runUploadProbe({
      control: world.control,
      adcPath: "/adc",
      budget: world.budget,
      runDir: join(world.dir, "run"),
      projectNumber: NUMBER,
      run: world.run,
    });
    assert.match(result.iamRevocationError, /403/);
    assert.equal(world.deployed.setPolicyCalls, 1, "not retried");
    assert.match(await journalOf(world), /iam-revocation-failed/);
    assert.equal(world.deployed.present, false, "the function is still deleted");
    assert.equal(result.uploadsClosureReady, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("the deployed fixture function has no invoker option, so the CLI makes it public and cleanup must undo that", () => {
  const source = readFileSync(new URL("./fixtures/index.js", import.meta.url), "utf8");
  assert.match(source, /onRequest\(/);
  assert.doesNotMatch(source, /invoker/);
});
