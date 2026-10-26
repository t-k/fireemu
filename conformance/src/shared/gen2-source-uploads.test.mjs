// Tests of the Gen2 source upload helper against a fake Cloud Storage world (T1, T2, T3, T4, T5,
// T6 and T7 of the FUNCTIONS-HTTP Gen2 source upload issue).

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  FAKE_BUCKET,
  FAKE_PROJECT_NUMBER,
  FAKE_REGION,
  SECRET_MARKER,
  answer,
  createFakeGcs,
} from "./gen2-source-uploads.fake.mjs";
import {
  REQUESTS_PER_DEPLOY,
  UPLOAD_BOUNDS,
  assertUploadBucket,
  createReceiptScanner,
  openSourceUploads,
  redactUploadSecrets,
  uploadBucketName,
  uploadEventsFromCliOutput,
} from "./gen2-source-uploads.mjs";

const OBJECT = "9be229fd-1507-4797-ab4b-69f2fda6e54a.zip";
const OTHER = "11111111-2222-4333-8444-555555555555.zip";
const FOREIGN = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.zip";

let dir;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "gen2-uploads-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function open(world, extra = {}) {
  let used = 0;
  const limit = extra.limit ?? 10_000;
  const uploads = openSourceUploads({
    ledgerPath: extra.ledgerPath ?? join(dir, "uploads.jsonl"),
    runId: extra.runId ?? "run-1",
    projectNumber: FAKE_PROJECT_NUMBER,
    region: FAKE_REGION,
    send: async (method, url) => {
      used += 1;
      return world.send(method, url);
    },
    requestsLeft: () => limit - used,
  });
  return { uploads, used: () => used };
}

const receiptOf = (object = OBJECT, bucket = FAKE_BUCKET) => ({ bucket, object });
const putStatus = (deploy, object, status) =>
  deploy.observe({ type: "put-status", bucket: FAKE_BUCKET, object, status });

describe("the reviewed bounds", () => {
  it("are the numbers a packet binds before it sends", () => {
    assert.deepEqual(
      { ...UPLOAD_BOUNDS },
      { pageSize: 100, maxPages: 3, maxReceiptsPerDeploy: 3, maxResponseBytes: 1_048_576 },
    );
    // baseline pages + after pages + a metadata GET, a DELETE and a read-back per receipt
    assert.equal(REQUESTS_PER_DEPLOY, 3 + 3 + 3 * 3);
  });
});

describe("the upload bucket (T1)", () => {
  it("is the dot-separated Gen2 bucket of the project number and region", () => {
    assert.equal(uploadBucketName(FAKE_PROJECT_NUMBER, FAKE_REGION), FAKE_BUCKET);
    assert.doesNotThrow(() =>
      assertUploadBucket(FAKE_BUCKET, { projectNumber: FAKE_PROJECT_NUMBER, region: FAKE_REGION }),
    );
  });

  it("refuses look-alike names, other projects and other regions", () => {
    const expected = { projectNumber: FAKE_PROJECT_NUMBER, region: FAKE_REGION };
    const lookalikes = [
      `gcf-v2-uploads-123456789013.${FAKE_REGION}.cloudfunctions.appspot.com`,
      `gcf-v2-uploads-${FAKE_PROJECT_NUMBER}.europe-west1.cloudfunctions.appspot.com`,
      `uploads-${FAKE_PROJECT_NUMBER}.${FAKE_REGION}.cloudfunctions.appspot.com`,
      `gcf-v2-uploads-${FAKE_PROJECT_NUMBER}-${FAKE_REGION}.cloudfunctions.appspot.com`,
      `gcf-sources-${FAKE_PROJECT_NUMBER}-${FAKE_REGION}`,
      `gcf-v2-sources-${FAKE_PROJECT_NUMBER}-${FAKE_REGION}`,
      `${FAKE_BUCKET}.evil.example`,
      `x${FAKE_BUCKET}`,
      FAKE_BUCKET.toUpperCase(),
      `${FAKE_BUCKET}/`,
      "",
      undefined,
    ];
    for (const bucket of lookalikes) {
      assert.throws(() => assertUploadBucket(bucket, expected), /upload bucket/, String(bucket));
    }
  });

  it("refuses a malformed project number or region when building the name", () => {
    for (const number of [
      "12ab",
      "12345",
      "1234567890123456789",
      "123456789012x",
      "x123456789012",
      " 123456789012",
      "",
      123456789012,
      undefined,
    ]) {
      assert.throws(() => uploadBucketName(number, FAKE_REGION), /project number/, String(number));
    }
    assert.doesNotThrow(() => uploadBucketName("123456", FAKE_REGION));
    assert.doesNotThrow(() => uploadBucketName("1234567890123456", FAKE_REGION));
    for (const region of [
      "US-CENTRAL1",
      "us-central",
      "us-central1x",
      "xus central1",
      "us-central1/",
      "-central1",
      "",
      undefined,
    ]) {
      assert.throws(() => uploadBucketName(FAKE_PROJECT_NUMBER, region), /region/, String(region));
    }
  });
});

describe("receipts", () => {
  it("reads the generateUploadUrl answer from debug output and ignores other lines", () => {
    const body = JSON.stringify({
      uploadUrl: `https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}?X-Goog-Signature=${SECRET_MARKER}`,
      storageSource: { bucket: FAKE_BUCKET, object: OBJECT },
    });
    const output = [
      "i  functions: preparing codebase for deployment",
      `[2026-10-26T01:02:03.456Z] >>> [apiv2][query] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl [none]`,
      `[2026-10-26T01:02:03.999Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl ${body}`,
      `[2026-10-26T01:02:04.000Z] <<< [apiv2][body] GET https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions ${body}`,
      `[2026-10-26T01:02:04.100Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl not json`,
      `<<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl {"uploadUrl":"x"}`,
      `<<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl {not: json}`,
      `<<< [apiv2][body] GET https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl ${body}`,
      `<<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions ${body}`,
      `<<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrlX ${body}`,
    ].join("\n");
    assert.deepEqual(uploadEventsFromCliOutput(output), [{ type: "receipt", ...receiptOf() }]);
  });

  it("reads the status line of the upload's PUT, and only that", () => {
    const put = (url, status) =>
      `[2026-10-26T01:02:05.000Z] <<< [apiv2][status] PUT ${url} ${status}`;
    const base = `https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}`;
    const output = [
      put(base, 200),
      put(base, 403),
      `<<< [apiv2][status] PUT ${base} 503`,
      put(`${base}?X-Goog-Signature=${SECRET_MARKER}`, 200),
      put(`https://example.com/${FAKE_BUCKET}/${OBJECT}`, 200),
      put(`https://storage.googleapis.com/${FAKE_BUCKET}`, 200),
      `[2026-10-26T01:02:05.000Z] <<< [apiv2][status] GET ${base} 200`,
      `[2026-10-26T01:02:05.000Z] <<< [apiv2][status] PUT ${base} 2000`,
      `[2026-10-26T01:02:05.000Z] <<< [apiv2][status] PUT ${base} ok`,
    ].join("\n");
    const status = (code) => ({
      type: "put-status",
      bucket: FAKE_BUCKET,
      object: OBJECT,
      status: code,
    });
    assert.deepEqual(uploadEventsFromCliOutput(output), [status(200), status(403), status(503)]);
  });

  it("scans a stream chunk by chunk, across arbitrary chunk boundaries", () => {
    const body = JSON.stringify({ storageSource: { bucket: FAKE_BUCKET, object: OBJECT } });
    const line = `[2026-10-26T01:02:03.999Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl ${body}\n`;
    for (let cut = 1; cut < line.length; cut += 17) {
      const seen = [];
      const scanner = createReceiptScanner((event) => seen.push(event));
      scanner.feed(line.slice(0, cut));
      scanner.feed(line.slice(cut));
      scanner.flush();
      assert.deepEqual(seen, [{ type: "receipt", ...receiptOf() }], `cut at ${cut}`);
    }
    const seen = [];
    const scanner = createReceiptScanner((event) => seen.push(event));
    scanner.feed(line.trimEnd());
    assert.deepEqual(seen, [], "a line without its newline waits");
    scanner.flush();
    assert.deepEqual(seen, [{ type: "receipt", ...receiptOf() }]);
  });

  it("redacts signed upload URLs and signature parameters (T7)", () => {
    const text = [
      `PUT https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}?GoogleAccessId=a%40b&Expires=1&X-Goog-Signature=${SECRET_MARKER}&x=1`,
      `retry X-Goog-Signature=${SECRET_MARKER}`,
      `{"uploadUrl":"https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}?X-Goog-Credential=${SECRET_MARKER}"}`,
      `plain https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT} stays`,
    ].join("\n");
    const redacted = redactUploadSecrets(text);
    assert.ok(!redacted.includes(SECRET_MARKER), redacted);
    assert.doesNotMatch(redacted, /X-Goog|GoogleAccessId|Signature=|\?Expires/);
    assert.match(redacted, /\[REDACTED UPLOAD URL\]/);
    assert.ok(
      redacted.includes(`plain https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT} stays`),
    );
  });
});

describe("a clean deploy (T3)", () => {
  it("journals the receipt, deletes by generation, reads the absence back and closes", async () => {
    const world = createFakeGcs();
    world.put(`preexisting-${OTHER}`);
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true });
    assert.deepEqual(result.reasons, []);
    assert.equal(result.clean, true);
    assert.ok(!world.objects.has(OBJECT));
    assert.ok(world.objects.has(`preexisting-${OTHER}`), "a baseline object is left alone");
    const deletes = world.requests.filter((request) => request.method === "DELETE");
    assert.equal(deletes.length, 1);
    assert.match(deletes[0].url, /ifGenerationMatch=\d+$/);
    assert.equal(uploads.report().closureReady, true);
    const rows = readFileSync(join(dir, "uploads.jsonl"), "utf8");
    assert.ok(rows.includes(OBJECT) && rows.includes('"delete"'));
  });

  it("is clean when the deploy made no upload at all", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true);
    assert.equal(world.count("DELETE"), 0);
  });

  it("treats a bucket that does not exist yet as empty before and after", async () => {
    const world = createFakeGcs({ bucketExists: false });
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true);
  });

  it("deletes the object of a deploy that failed after the upload (receipt from the CLI)", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true);
    assert.ok(!world.objects.has(OBJECT));
  });

  it("journals the deploy as one placeholder create over the CLI transport", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    await uploads.beginDeploy("program-1:http");
    const rows = readFileSync(join(dir, "uploads.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const intent = rows.find((row) => row.phase === "intent");
    assert.deepEqual(
      [intent.action, intent.name, intent.transport],
      ["create", "deploy:program-1:http", "accounting"],
    );
  });

  it("ignores a null receipt and any receipt after the deploy finished", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.receipt(null);
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true, "a null receipt is not a fault");
    deploy.receipt(receiptOf(OTHER));
    assert.equal(uploads.report().closureReady, true, "a late receipt opens nothing");
  });

  it("flags a receipt that cannot be journaled, such as one another deploy already holds", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const first = await uploads.beginDeploy("program-1:http");
    const second = await uploads.beginDeploy("program-2:http");
    world.put(OBJECT);
    first.receipt(receiptOf());
    second.receipt(receiptOf());
    const result = await second.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("receipt-not-journaled"));
    assert.equal(world.count("DELETE"), 0, "the deploy that holds the receipt has not run yet");
  });

  it("accepts the same receipt from the CLI and from the function record once", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true);
    assert.equal(world.count("DELETE"), 1);
  });
});

describe("ownership (T2)", () => {
  it("never deletes an object that is neither a receipt nor in the baseline", async () => {
    const world = createFakeGcs();
    world.put(`old-${OTHER}`);
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    world.put(FOREIGN);
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.some((reason) => reason.startsWith("unexplained-object")));
    assert.ok(world.objects.has(FOREIGN), "the foreign object is untouched");
    assert.ok(world.objects.has(`old-${OTHER}`));
    assert.ok(!world.objects.has(OBJECT));
    const deletes = world.requests.filter((request) => request.method === "DELETE");
    assert.equal(deletes.length, 1);
    assert.ok(deletes[0].url.includes(OBJECT));
  });

  it("is not clean for an object nobody has a receipt for, and deletes nothing", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.equal(world.count("DELETE"), 0);
    assert.equal(uploads.report().closureReady, false);
  });

  it("refuses a receipt for another bucket and treats the deploy as unknown", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.receipt(
      receiptOf(OBJECT, `gcf-v2-uploads-999999999999.${FAKE_REGION}.cloudfunctions.appspot.com`),
    );
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("receipt-bucket-mismatch"));
    assert.equal(world.count("DELETE"), 0);
  });

  it("refuses an object name that could escape the bucket path", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const bad = [
      "../x.zip",
      "a/b.zip",
      "",
      "a?b.zip",
      "a b.zip",
      ".hidden.zip",
      "-x.zip",
      "a#b.zip",
      5,
    ];
    for (const object of bad) deploy.receipt(receiptOf(object));
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("receipt-object-invalid"));
    assert.equal(world.count("DELETE"), 0);
    // each name alone is refused, not only the set
    for (const object of bad) {
      const single = openSourceUploads({
        ledgerPath: join(dir, `bad-${bad.indexOf(object)}.jsonl`),
        runId: "run-b",
        projectNumber: FAKE_PROJECT_NUMBER,
        region: FAKE_REGION,
        send: (method, url) => world.send(method, url),
        requestsLeft: () => 1000,
      });
      const one = await single.beginDeploy("program-b:http");
      one.receipt(receiptOf(object));
      const outcome = await one.finish({ cliExited: true });
      assert.ok(outcome.reasons.includes("receipt-object-invalid"), String(object));
    }
  });

  it("refuses a receipt that names an object already in the bucket before the deploy", async () => {
    const world = createFakeGcs();
    world.put(OBJECT);
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("receipt-names-baseline-object"));
    assert.equal(world.count("DELETE"), 0);
    assert.ok(world.objects.has(OBJECT));
  });

  it("does not track more receipts than one deploy may own", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    for (let i = 0; i <= UPLOAD_BOUNDS.maxReceiptsPerDeploy; i += 1) {
      const object = `0000000${i}-1111-4222-8333-444444444444.zip`;
      world.put(object);
      deploy.receipt(receiptOf(object));
    }
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("too-many-receipts"));
  });
});

describe("delete and read-back answers (T4)", () => {
  async function deployWithObject(world, extra) {
    const opened = open(world, extra);
    const deploy = await opened.uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    return { ...opened, deploy };
  }

  it("an object already gone at DELETE time is not settled in the run", async () => {
    const world = createFakeGcs();
    const { deploy, uploads } = await deployWithObject(world);
    world.override({ method: "DELETE", url: OBJECT }, answer(404), {
      effect: () => world.remove(OBJECT),
    });
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.equal(uploads.report().closureReady, false);
    assert.equal(world.count("DELETE"), 1);
  });

  it("a generation conflict is reported, not retried, and the new object is not deleted", async () => {
    const world = createFakeGcs();
    const { deploy } = await deployWithObject(world);
    world.override({ method: "DELETE", url: OBJECT }, answer(412), {
      effect: () => world.put(OBJECT),
    });
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.equal(world.count("DELETE"), 1);
    assert.ok(world.objects.has(OBJECT));
  });

  it("a refused DELETE (403) leaves the upload owned and the deploy unclean", async () => {
    const world = createFakeGcs();
    const { deploy, uploads } = await deployWithObject(world);
    world.override({ method: "DELETE", url: OBJECT }, answer(403));
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.deepEqual(uploads.report().owned.length, 1);
  });

  it("an unknown DELETE answer (503, transport error) is sticky and never re-sent", async () => {
    for (const unknown of [answer(503), new Error("socket hang up")]) {
      const world = createFakeGcs();
      const { deploy, uploads } = await deployWithObject(world, {
        ledgerPath: join(dir, `${Math.random()}.jsonl`),
      });
      world.override({ method: "DELETE", url: OBJECT }, unknown);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false);
      assert.equal(world.count("DELETE"), 1);
      assert.equal(uploads.report().closureReady, false);
      assert.ok(uploads.report().unknownDeletes >= 1);
    }
  });

  it("a failed read-back after a good DELETE leaves the deploy unclean", async () => {
    const world = createFakeGcs();
    const { deploy } = await deployWithObject(world);
    // the first GET is the metadata read; the second is the read-back
    let gets = 0;
    const send = world.send;
    world.send = async (method, url) => {
      if (method === "GET" && url.includes(`/o/${OBJECT}`)) {
        gets += 1;
        if (gets === 2) return answer(503);
      }
      return send(method, url);
    };
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
  });

  it("an object still present after a 204 DELETE leaves the deploy unclean", async () => {
    const world = createFakeGcs();
    const { deploy } = await deployWithObject(world);
    world.override(
      { method: "DELETE", url: OBJECT },
      { status: 204, bodyReadable: true, value: {}, bytes: 0 },
    );
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(world.objects.has(OBJECT));
  });

  it("a refused or unknown metadata read sends no DELETE", async () => {
    for (const refusal of [answer(403), answer(503), answer(200, { name: OBJECT })]) {
      const world = createFakeGcs();
      const { deploy } = await deployWithObject(world, {
        ledgerPath: join(dir, `${Math.random()}.jsonl`),
      });
      world.override({ method: "GET", url: `/o/${OBJECT}` }, refusal);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false);
      assert.equal(world.count("DELETE"), 0);
    }
  });

  it("a metadata answer for another bucket, name or a non-numeric generation sends no DELETE", async () => {
    const bad = [
      answer(200, { bucket: "other", name: OBJECT, generation: "1" }),
      answer(200, { bucket: FAKE_BUCKET, name: OTHER, generation: "1" }),
      answer(200, { bucket: FAKE_BUCKET, name: OBJECT, generation: "1e3" }),
      answer(200, { bucket: FAKE_BUCKET, name: OBJECT }),
    ];
    for (const metadata of bad) {
      const world = createFakeGcs();
      const { deploy } = await deployWithObject(world, {
        ledgerPath: join(dir, `${Math.random()}.jsonl`),
      });
      world.override({ method: "GET", url: `/o/${OBJECT}` }, metadata);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false);
      assert.equal(world.count("DELETE"), 0);
    }
  });

  it("names what failed: a refused DELETE and the reads that were not sent after it", async () => {
    for (const [reply, reason] of [
      [answer(403), "delete-refused"],
      [answer(412), "delete-refused"],
      [answer(503), "delete-unknown"],
    ]) {
      const world = createFakeGcs();
      const { deploy } = await deployWithObject(world, {
        ledgerPath: join(dir, `named-${reply.status}.jsonl`),
      });
      world.override({ method: "DELETE", url: OBJECT }, reply);
      const gets = () => world.count("GET");
      const before = gets();
      const result = await deploy.finish({ cliExited: true });
      assert.ok(
        result.reasons.some((r) => r.startsWith(`${reason}:`)),
        result.reasons.join(","),
      );
      // after-list and metadata only: no read-back after a DELETE that did not succeed
      assert.equal(gets() - before, 2, String(reply.status));
    }
  });

  it("tells a read-back that shows the object from one that cannot be read", async () => {
    const cases = [
      [answer(200, { bucket: FAKE_BUCKET, name: OBJECT, generation: "9" }), "deleted-but-present"],
      [
        answer(200, { bucket: "other-bucket", name: OBJECT, generation: "9" }),
        "deleted-unverified",
      ],
      [answer(200, { bucket: FAKE_BUCKET, name: OTHER, generation: "9" }), "deleted-unverified"],
      [answer(503), "deleted-unverified"],
    ];
    for (const [index, [reply, reason]] of cases.entries()) {
      const world = createFakeGcs();
      const { deploy } = await deployWithObject(world, {
        ledgerPath: join(dir, `back-${index}.jsonl`),
      });
      const send = world.send;
      let gets = 0;
      world.send = async (method, url) => {
        if (method === "GET" && url.includes(`/o/${OBJECT}`) && (gets += 1) === 2) return reply;
        return send(method, url);
      };
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false);
      assert.ok(
        result.reasons.some((r) => r.startsWith(`${reason}:`)),
        `${index}: ${result.reasons.join(",")}`,
      );
    }
  });

  it("an unreadable 404 or a 403 that carries a plausible body is not an absence or a generation", async () => {
    const plausible = { bucket: FAKE_BUCKET, name: OBJECT, generation: "7" };
    const replies = [
      { status: 404, bodyReadable: false, bytes: 2 },
      { status: 403, bodyReadable: true, value: plausible, bytes: 50 },
      { status: 200, bodyReadable: false, value: plausible, bytes: 50 },
      {
        status: 200,
        bodyReadable: true,
        value: plausible,
        bytes: UPLOAD_BOUNDS.maxResponseBytes + 1,
      },
    ];
    for (const [index, reply] of replies.entries()) {
      const world = createFakeGcs();
      const { deploy, uploads } = await deployWithObject(world, {
        ledgerPath: join(dir, `meta-${index}.jsonl`),
      });
      world.override({ method: "GET", url: `/o/${OBJECT}` }, reply);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false, String(index));
      assert.equal(world.count("DELETE"), 0, String(index));
      assert.ok(
        result.reasons.some((r) => r.startsWith("object-unreadable:")),
        `${index}: ${result.reasons}`,
      );
      const reasons = uploads.report().reasons;
      assert.ok(
        reasons.some((r) => r.startsWith(`unsettled-create:${FAKE_BUCKET}/${OBJECT}`)),
        reasons.join(","),
      );
      assert.ok(!reasons.some((r) => r.startsWith("in-flight:")), "every ticket is answered");
    }
  });

  it("settles a receipt whose object never arrived only by the PUT's own answer (M2)", async () => {
    const cases = [
      // [PUT status lines, CLI exited, clean, reason]
      [[], true, false, "receipt-unconfirmed"],
      [[], false, false, "receipt-unconfirmed"],
      [[503], true, false, "receipt-unconfirmed"],
      [[408], true, false, "receipt-unconfirmed"],
      [[429], true, false, "receipt-unconfirmed"],
      [[499], true, false, "receipt-unconfirmed"],
      [[301], true, false, "receipt-unconfirmed"],
      [[403], true, true, undefined],
      [[400], true, true, undefined],
      [[403, 403], true, true, undefined],
      [[404, 400], true, true, undefined],
      // a retried PUT: a 5xx or a retryable code before a refusal may have landed (R2-S2)
      [[503, 403], true, false, "receipt-unconfirmed"],
      [[503, 400], true, false, "receipt-unconfirmed"],
      [[429, 403], true, false, "receipt-unconfirmed"],
      [[408, 403], true, false, "receipt-unconfirmed"],
      [[403, 503], true, false, "receipt-unconfirmed"],
      [[403, 429], true, false, "receipt-unconfirmed"],
      [[200], true, false, "confirmed-upload-absent"],
      [[503, 200], true, false, "confirmed-upload-absent"],
      [[200], false, false, "confirmed-upload-absent"],
    ];
    for (const [index, [statuses, cliExited, clean, reason]] of cases.entries()) {
      const world = createFakeGcs();
      const { uploads } = open(world, { ledgerPath: join(dir, `put-${index}.jsonl`) });
      const deploy = await uploads.beginDeploy("program-1:http");
      deploy.receipt(receiptOf());
      for (const status of statuses) putStatus(deploy, OBJECT, status);
      const result = await deploy.finish({ cliExited, exitCode: cliExited ? 1 : null });
      const label = `${JSON.stringify(statuses)} exited=${cliExited}: ${result.reasons}`;
      assert.equal(result.clean, clean, label);
      if (reason)
        assert.ok(
          result.reasons.some((r) => r.startsWith(`${reason}:`)),
          label,
        );
      assert.equal(uploads.report().closureReady, clean, label);
      assert.equal(world.count("DELETE"), 0, "no DELETE for an object that is not there");
      const report = uploads.report();
      if (reason === "confirmed-upload-absent") {
        // a confirmed create that reads 404 is owned and unsettled in the run
        assert.ok(
          report.reasons.some((r) => r.startsWith("confirmed-create-reads-404:")),
          label,
        );
      }
      if (reason === "receipt-unconfirmed") {
        // an unknown create whose only evidence is absence: the coordinator must accept it
        assert.ok(
          report.reasons.some((r) => r.startsWith("unknown-create-absent-unconfirmed:")),
          label,
        );
        assert.ok(report.coordinatorNote, label);
      }
    }
  });

  it("deletes an object whose PUT status was never seen once an own read shows it", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: true, exitCode: 1 });
    assert.equal(result.clean, true);
    assert.ok(!world.objects.has(OBJECT));
    const report = uploads.report();
    assert.equal(report.closureReady, true);
    assert.equal(
      report.a2Required,
      true,
      "an unknown create was settled: the A2 read-back precedes the close row",
    );
  });

  it("does not look for an object the PUT's own answer refused, but flags it if it is there", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    putStatus(deploy, OBJECT, 403);
    const result = await deploy.finish({ cliExited: true, exitCode: 1 });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes(`unexplained-object:${OBJECT}`));
    assert.equal(world.count("DELETE"), 0);
    assert.ok(world.objects.has(OBJECT));
  });

  it("a deploy that ended well with no receipt used a path this helper does not see (S1)", async () => {
    for (const [cliExited, exitCode, reason] of [
      [true, 0, "no-receipt"],
      [false, null, "killed-without-receipt"],
    ]) {
      const world = createFakeGcs();
      const { uploads } = open(world, { ledgerPath: join(dir, `none-${exitCode}.jsonl`) });
      const deploy = await uploads.beginDeploy("program-1:http");
      const result = await deploy.finish({ cliExited, exitCode });
      assert.equal(result.clean, false);
      assert.ok(result.reasons.includes(reason), result.reasons.join(","));
    }
    for (const exitCode of [1, 2, 255, null]) {
      const world = createFakeGcs();
      const { uploads } = open(world, { ledgerPath: join(dir, `fail-${exitCode}.jsonl`) });
      const deploy = await uploads.beginDeploy("program-1:http");
      const result = await deploy.finish({ cliExited: true, exitCode });
      assert.equal(result.clean, true, `exit ${exitCode} before any upload leaves nothing`);
    }
  });

  it("a PUT line for an object with no receipt, or in another bucket, owns nothing", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.observe({ type: "put-status", bucket: FAKE_BUCKET, object: OTHER, status: 200 });
    deploy.observe(null);
    deploy.observe({ type: "other" });
    const result = await deploy.finish({ cliExited: true, exitCode: 1 });
    assert.equal(result.clean, true);
  });

  it("a refusal logged for the same object name in another bucket does not settle the receipt", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.receipt(receiptOf());
    deploy.observe({ type: "put-status", bucket: "elsewhere", object: OBJECT, status: 403 });
    const result = await deploy.finish({ cliExited: true, exitCode: 1 });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.some((r) => r.startsWith("receipt-unconfirmed:")));
  });

  it("opens nothing for events that arrive after the deploy finished", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const result = await deploy.finish({ cliExited: true, exitCode: 1 });
    assert.equal(result.clean, true);
    deploy.observe({ type: "receipt", ...receiptOf(OTHER) });
    deploy.observe({ type: "put-status", bucket: FAKE_BUCKET, object: OTHER, status: 403 });
    assert.equal(uploads.report().closureReady, true);
    assert.deepEqual(uploads.report().owned, []);
  });
});

describe("pagination, counts and budget (T5)", () => {
  it("finds an unexplained object on the last allowed page", async () => {
    const world = createFakeGcs();
    for (let i = 0; i < UPLOAD_BOUNDS.pageSize * 2; i += 1)
      world.put(`base-${String(i).padStart(4, "0")}`);
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put("zzzz-unexplained");
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.some((reason) => reason.includes("zzzz-unexplained")));
  });

  it("refuses to start a deploy when the baseline list is longer than the page bound", async () => {
    const world = createFakeGcs();
    for (let i = 0; i < UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages + 1; i += 1) {
      world.put(`base-${String(i).padStart(5, "0")}`);
    }
    const { uploads } = open(world);
    await assert.rejects(() => uploads.beginDeploy("program-1:http"), /baseline/);
    assert.equal(
      world.count("GET"),
      UPLOAD_BOUNDS.maxPages,
      "no page beyond the bound is requested",
    );
  });

  it("accepts a baseline of exactly the bound", async () => {
    const world = createFakeGcs();
    for (let i = 0; i < UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages; i += 1) {
      world.put(`base-${String(i).padStart(5, "0")}`);
    }
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true);
  });

  it("does not call a list that grew past the bound during the deploy empty", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    for (let i = 0; i < UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages + 1; i += 1) {
      world.put(`new-${String(i).padStart(5, "0")}`);
    }
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("list-incomplete"));
  });

  it("treats an oversized or unreadable list answer as incomplete", async () => {
    for (const reply of [
      {
        status: 200,
        bodyReadable: true,
        value: { items: [] },
        bytes: UPLOAD_BOUNDS.maxResponseBytes + 1,
      },
      { status: 200, bodyReadable: false, bytes: 3 },
      answer(503),
      answer(403),
      answer(200, { items: "nope" }),
      answer(200, { items: [{ name: 5 }] }),
    ]) {
      const world = createFakeGcs();
      const { uploads } = open(world, { ledgerPath: join(dir, `${Math.random()}.jsonl`) });
      const deploy = await uploads.beginDeploy("program-1:http");
      world.override({ method: "GET", url: "/o?" }, reply);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false, JSON.stringify(reply).slice(0, 80));
      assert.ok(result.reasons.includes("list-incomplete"), JSON.stringify(reply).slice(0, 80));
    }
  });

  it("refuses a baseline whose later page is missing, unreadable or has a bad token", async () => {
    const replies = [
      [{ method: "GET", url: "pageToken" }, answer(404)],
      [
        { method: "GET", url: "pageToken" },
        { status: 404, bodyReadable: false, bytes: 2 },
      ],
      [{ method: "GET", url: "pageToken" }, answer(503)],
      [{ method: "GET", url: "/o?" }, answer(200, { items: [], nextPageToken: null })],
      [{ method: "GET", url: "/o?" }, answer(200, { items: [], nextPageToken: "" })],
      [{ method: "GET", url: "/o?" }, answer(200, { items: [], nextPageToken: 5 })],
      [{ method: "GET", url: "/o?" }, answer(200, { items: [{ name: 5 }] })],
      [{ method: "GET", url: "/o?" }, answer(200, { items: {} })],
    ];
    for (const [index, [match, reply]] of replies.entries()) {
      const world = createFakeGcs();
      for (let i = 0; i < UPLOAD_BOUNDS.pageSize + 5; i += 1) {
        world.put(`base-${String(i).padStart(5, "0")}`);
      }
      world.override(match, reply);
      const { uploads } = open(world, { ledgerPath: join(dir, `page-${index}.jsonl`) });
      await assert.rejects(() => uploads.beginDeploy("program-1:http"), /baseline/, String(index));
    }
  });

  it("a page with more items than the reviewed page size is incomplete (S3)", async () => {
    const items = Array.from({ length: UPLOAD_BOUNDS.pageSize + 1 }, (_, i) => ({
      name: `o-${i}`,
    }));
    const world = createFakeGcs();
    world.override({ method: "GET", url: "/o?" }, answer(200, { items }));
    const { uploads } = open(world);
    await assert.rejects(() => uploads.beginDeploy("program-1:http"), /baseline/);
    const exact = createFakeGcs();
    exact.override(
      { method: "GET", url: "/o?" },
      answer(200, { items: items.slice(0, UPLOAD_BOUNDS.pageSize) }),
    );
    const second = open(exact, { ledgerPath: join(dir, "exact.jsonl") });
    assert.ok(await second.uploads.beginDeploy("program-1:http"));
  });

  it("a missing bucket is empty only on the first page, and only when the 404 can be read", async () => {
    const world = createFakeGcs({ bucketExists: false });
    const { uploads } = open(world);
    assert.ok(await uploads.beginDeploy("program-1:http"));
    const unreadable = createFakeGcs();
    unreadable.override(
      { method: "GET", url: "/o?" },
      { status: 404, bodyReadable: false, bytes: 2 },
    );
    const second = open(unreadable, { ledgerPath: join(dir, "unreadable-404.jsonl") });
    await assert.rejects(() => second.uploads.beginDeploy("program-1:http"), /baseline/);
  });

  it("an answer that is not an object is a transport failure, not a crash", async () => {
    for (const reply of [null, undefined, "nope", 5]) {
      const world = createFakeGcs();
      const { uploads } = open(world, { ledgerPath: join(dir, `null-${String(reply)}.jsonl`) });
      const deploy = await uploads.beginDeploy("program-1:http");
      world.put(OBJECT);
      deploy.receipt(receiptOf());
      world.override({ method: "DELETE", url: OBJECT }, reply);
      const result = await deploy.finish({ cliExited: true });
      assert.equal(result.clean, false, String(reply));
    }
  });

  it("sends nothing when the remaining requests are short of the bound, at any size", async () => {
    for (const left of [0, 1, REQUESTS_PER_DEPLOY - 1]) {
      const world = createFakeGcs();
      const { uploads } = open(world, { limit: left, ledgerPath: join(dir, `${left}.jsonl`) });
      await assert.rejects(() => uploads.beginDeploy("program-1:http"), /budget/);
      assert.equal(world.requests.length, 0, `left=${left}`);
    }
  });

  it("starts with exactly the bound left and never exceeds it, even with every receipt", async () => {
    const world = createFakeGcs();
    for (let i = 0; i < UPLOAD_BOUNDS.pageSize * (UPLOAD_BOUNDS.maxPages - 1); i += 1) {
      world.put(`base-${String(i).padStart(5, "0")}`);
    }
    const { uploads, used } = open(world, { limit: REQUESTS_PER_DEPLOY });
    const deploy = await uploads.beginDeploy("program-1:http");
    for (let i = 0; i < UPLOAD_BOUNDS.maxReceiptsPerDeploy; i += 1) {
      const object = `0000000${i}-1111-4222-8333-444444444444.zip`;
      world.put(object);
      deploy.receipt(receiptOf(object));
    }
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, true, result.reasons.join(","));
    assert.ok(used() <= REQUESTS_PER_DEPLOY);
  });

  it("finish needs to be told whether the CLI exited, and can still finish after a bad call", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    for (const bad of [{}, { cliExited: "yes" }, { cliExited: 1 }, { cliExited: undefined }]) {
      await assert.rejects(() => deploy.finish(bad), /cliExited/);
    }
    assert.equal(world.requests.length, 1, "only the baseline list was sent");
    assert.equal((await deploy.finish({ cliExited: true })).clean, true);
  });

  it("finish needs the pages and three requests per receipt, no fewer", async () => {
    for (const receipts of [0, 1, 2]) {
      const need = UPLOAD_BOUNDS.maxPages + 3 * receipts;
      for (const [left, proceeds] of [
        [need - 1, false],
        [need, true],
      ]) {
        const world = createFakeGcs();
        let budget = REQUESTS_PER_DEPLOY;
        let used = 0;
        const uploads = openSourceUploads({
          ledgerPath: join(dir, `need-${receipts}-${left}.jsonl`),
          runId: "run-n",
          projectNumber: FAKE_PROJECT_NUMBER,
          region: FAKE_REGION,
          send: (method, url) => {
            used += 1;
            return world.send(method, url);
          },
          requestsLeft: () => budget - used,
        });
        const deploy = await uploads.beginDeploy("program-1:http");
        for (let i = 0; i < receipts; i += 1) {
          const object = `0000000${i}-1111-4222-8333-444444444444.zip`;
          world.put(object);
          deploy.receipt(receiptOf(object));
        }
        budget = used + left;
        const before = world.requests.length;
        const result = await deploy.finish({ cliExited: true });
        assert.equal(result.reasons.includes("upload-budget"), !proceeds, `${receipts}/${left}`);
        assert.equal(world.requests.length > before, proceeds, `${receipts}/${left}`);
      }
    }
  });

  it("finish dispatches nothing and stays unclean when the budget fell short meanwhile", async () => {
    const world = createFakeGcs();
    let left = REQUESTS_PER_DEPLOY;
    const uploads = openSourceUploads({
      ledgerPath: join(dir, "short.jsonl"),
      runId: "run-1",
      projectNumber: FAKE_PROJECT_NUMBER,
      region: FAKE_REGION,
      send: (method, url) => world.send(method, url),
      requestsLeft: () => left,
    });
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    deploy.receipt(receiptOf());
    left = 2;
    const before = world.requests.length;
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("upload-budget"));
    assert.equal(world.requests.length, before);
    assert.ok(world.objects.has(OBJECT));
    const report = uploads.report();
    assert.equal(report.closureReady, false);
    assert.ok(
      report.reasons.some((r) => r.startsWith(`unsettled-create:${FAKE_BUCKET}/${OBJECT}`)),
    );
    assert.ok(!report.reasons.some((r) => r.startsWith("in-flight:")), "every ticket is answered");
  });
});

describe("stop and resume (T6)", () => {
  it("a run that stops after the upload keeps the responsibility and refuses a quiet restart", async () => {
    const world = createFakeGcs();
    const ledgerPath = join(dir, "resume.jsonl");
    {
      const { uploads } = open(world, { ledgerPath });
      const deploy = await uploads.beginDeploy("program-1:http");
      world.put(OBJECT);
      deploy.receipt(receiptOf());
      // the process stops here: no finish
      uploads.close();
    }
    const requestsBefore = world.requests.length;
    const resumed = open(world, { ledgerPath });
    const report = resumed.uploads.report();
    assert.equal(report.closureReady, false);
    assert.ok(report.reasons.some((reason) => reason.includes(OBJECT)));
    assert.ok(report.reasons.some((reason) => reason.includes("program-1:http")));
    await assert.rejects(
      () => resumed.uploads.beginDeploy("program-1:http"),
      /unsettled|in-flight|deploy/,
    );
    assert.equal(world.requests.length, requestsBefore, "resuming sends nothing");
    assert.ok(world.objects.has(OBJECT));
  });

  it("a deploy that stopped before any receipt is still an open responsibility", async () => {
    const world = createFakeGcs();
    const ledgerPath = join(dir, "resume2.jsonl");
    {
      const { uploads } = open(world, { ledgerPath });
      await uploads.beginDeploy("program-1:http");
      uploads.close();
    }
    const resumed = open(world, { ledgerPath });
    assert.equal(resumed.uploads.report().closureReady, false);
  });

  it("a failed deploy with the CLI killed and the object absent stays unknown", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    deploy.receipt(receiptOf());
    const result = await deploy.finish({ cliExited: false });
    assert.equal(result.clean, false);
    assert.equal(uploads.report().closureReady, false);
  });

  it("a killed CLI with no receipt cannot rule out an upload in flight", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    const result = await deploy.finish({ cliExited: false });
    assert.equal(result.clean, false);
    assert.ok(result.reasons.includes("killed-without-receipt"));
    assert.equal(uploads.report().closureReady, false);
    assert.equal(world.count("DELETE"), 0);
  });

  it("a finished deploy is not finished twice, and a started key is not started twice", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    await deploy.finish({ cliExited: true });
    await assert.rejects(() => deploy.finish({ cliExited: true }), /already finished/);
    await assert.rejects(() => uploads.beginDeploy("program-1:http"), /already|deploy/);
  });
});

describe("credentials never reach the journal or the report (T7)", () => {
  it("keeps signed URLs and secret markers out of every stored artefact", async () => {
    const world = createFakeGcs();
    const { uploads } = open(world);
    const deploy = await uploads.beginDeploy("program-1:http");
    world.put(OBJECT);
    const body = JSON.stringify({
      uploadUrl: `https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}?X-Goog-Signature=${SECRET_MARKER}`,
      storageSource: { bucket: FAKE_BUCKET, object: OBJECT, token: SECRET_MARKER },
    });
    const scanner = createReceiptScanner((event) => deploy.observe(event));
    scanner.feed(
      `[2026-10-26T01:02:03.999Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/${FAKE_REGION}/functions:generateUploadUrl ${body}\n`,
    );
    world.override(
      { method: "GET", url: `/o/${OBJECT}` },
      answer(200, {
        bucket: FAKE_BUCKET,
        name: OBJECT,
        generation: "7",
        authorization: SECRET_MARKER,
      }),
    );
    world.override({ method: "DELETE", url: OBJECT }, answer(403, { error: SECRET_MARKER }));
    const result = await deploy.finish({ cliExited: true });
    assert.equal(result.clean, false);
    const stored = readFileSync(join(dir, "uploads.jsonl"), "utf8");
    assert.ok(!stored.includes(SECRET_MARKER), "ledger");
    assert.ok(!JSON.stringify(result).includes(SECRET_MARKER), "result");
    assert.ok(!JSON.stringify(uploads.report()).includes(SECRET_MARKER), "report");
  });
});
