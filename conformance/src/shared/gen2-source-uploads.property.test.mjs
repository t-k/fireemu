// A generated test of the Gen2 source upload helper: random worlds (baseline objects over several
// pages, receipts that were or were not uploaded, foreign objects, bad receipts, injected answers on
// every request kind, a killed CLI, a short budget) checked against a reference model of when a
// deploy is clean, plus the safety properties that must hold in every world. The seed is fixed, so
// a failure names the case that reproduces it.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  FAKE_BUCKET,
  FAKE_PROJECT_NUMBER,
  FAKE_REGION,
  answer,
  createFakeGcs,
} from "./gen2-source-uploads.fake.mjs";
import { REQUESTS_PER_DEPLOY, UPLOAD_BOUNDS, openSourceUploads } from "./gen2-source-uploads.mjs";

const BASE_SEED = 0x5eed_0b6e;
const CASES = 300;

/** mulberry32: a small deterministic generator. */
function prng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
  return {
    int: (n) => Math.floor(next() * n),
    pick: (list) => list[Math.floor(next() * list.length)],
    chance: (p) => next() < p,
  };
}

const uuid = (n) => `${String(n).padStart(8, "0")}-1111-4222-8333-444444444444.zip`;

/** Faults a receipt's object can meet; `none` is the only one a clean deploy allows. */
const OBJECT_FAULTS = [
  "none",
  "none",
  "none",
  "meta403",
  "meta503",
  "metaThrow",
  "delete403",
  "delete412",
  "delete503",
  "deleteThrow",
  "delete404Gone",
  "deleteStayed",
  "readback503",
];

function scenario(rng) {
  const baselineCount = rng.pick([0, 0, 1, 5, 99, 100, 101, 199, 200, 250, 299, 300]);
  const receipts = [];
  const receiptCount = rng.int(UPLOAD_BOUNDS.maxReceiptsPerDeploy + 2);
  for (let i = 0; i < receiptCount; i += 1) {
    const uploaded = rng.chance(0.8);
    receipts.push({
      object: uuid(1000 + i),
      uploaded,
      fault: uploaded ? rng.pick(OBJECT_FAULTS) : "none",
      // the status lines of the CLI's PUT: an uploaded object may show a 2xx or nothing; one that
      // never arrived may show a refusal, a server error, a 2xx that no longer reads, or nothing
      put: uploaded
        ? rng.pick([[], [200], [503, 200]])
        : rng.pick([[], [403], [503], [200], [503, 403], [403, 503]]),
    });
  }
  return {
    baselineCount,
    receipts,
    duplicateReceipt: rng.chance(0.2),
    badBucketReceipt: rng.chance(0.1),
    badObjectReceipt: rng.chance(0.1),
    baselineReceipt: baselineCount > 0 && rng.chance(0.05),
    foreign: rng.pick([0, 0, 0, 1, 2]),
    afterGrowth: rng.pick([0, 0, 0, 0, UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages]),
    afterListFault: rng.pick(["none", "none", "none", "none", "503"]),
    cliExited: rng.chance(0.8),
    exitCode: rng.pick([0, 1]),
    limit: rng.pick([REQUESTS_PER_DEPLOY, REQUESTS_PER_DEPLOY, REQUESTS_PER_DEPLOY + 40, 2000]),
    shortAtFinish: rng.chance(0.1),
    crashBeforeFinish: rng.chance(0.1),
  };
}

function inject(world, receipt) {
  const get = { method: "GET", url: `/o/${receipt.object}` };
  const del = { method: "DELETE", url: receipt.object };
  switch (receipt.fault) {
    case "meta403":
      world.override(get, answer(403));
      break;
    case "meta503":
      world.override(get, answer(503));
      break;
    case "metaThrow":
      world.override(get, new Error("reset"));
      break;
    case "delete403":
      world.override(del, answer(403));
      break;
    case "delete412":
      world.override(del, answer(412), { effect: () => world.put(receipt.object) });
      break;
    case "delete503":
      world.override(del, answer(503));
      break;
    case "deleteThrow":
      world.override(del, new Error("reset"));
      break;
    case "delete404Gone":
      world.override(del, answer(404), { effect: () => world.remove(receipt.object) });
      break;
    case "readback503": {
      // the metadata read is the first GET of the object; the read-back is the second
      const send = world.send;
      let gets = 0;
      world.send = async (method, url) => {
        if (method === "GET" && url.includes(`/o/${receipt.object}`) && (gets += 1) === 2) {
          return answer(503);
        }
        return send(method, url);
      };
      break;
    }
    case "deleteStayed":
      world.override(del, { status: 204, bodyReadable: true, value: {}, bytes: 0 });
      break;
    default:
  }
}

async function run(seed) {
  const rng = prng(seed);
  const s = scenario(rng);
  const dir = mkdtempSync(join(tmpdir(), "gen2-prop-"));
  try {
    const world = createFakeGcs();
    for (let i = 0; i < s.baselineCount; i += 1) world.put(`base-${String(i).padStart(5, "0")}`);
    const baseline = new Set(world.objects.keys());
    let used = 0;
    let left = s.limit;
    const openUploads = (ledgerPath) =>
      openSourceUploads({
        ledgerPath,
        runId: "run-p",
        projectNumber: FAKE_PROJECT_NUMBER,
        region: FAKE_REGION,
        send: (method, url) => {
          used += 1;
          return world.send(method, url);
        },
        requestsLeft: () => left - used,
      });
    const ledgerPath = join(dir, "l.jsonl");
    const uploads = openUploads(ledgerPath);
    const beginMayFail = s.baselineCount > UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages;
    let deploy;
    try {
      deploy = await uploads.beginDeploy("p:http");
    } catch (error) {
      assert.ok(beginMayFail, `${seed}: beginDeploy failed unexpectedly: ${error.message}`);
      assert.equal(world.count("DELETE"), 0);
      return { skipped: true };
    }
    assert.ok(!beginMayFail, `${seed}: a baseline past the bound was accepted`);

    const modelled = new Set();
    const receiptFaults = [];
    for (const receipt of s.receipts) {
      if (receipt.uploaded) world.put(receipt.object);
      inject(world, receipt);
    }
    for (let i = 0; i < s.foreign; i += 1) world.put(`foreign-${i}.zip`);
    for (let i = 0; i < s.afterGrowth; i += 1) world.put(`grown-${String(i).padStart(5, "0")}`);
    let tracked = 0;
    for (const receipt of s.receipts) {
      deploy.receipt({ bucket: FAKE_BUCKET, object: receipt.object });
      for (const status of receipt.put) {
        deploy.observe({ type: "put-status", bucket: FAKE_BUCKET, object: receipt.object, status });
      }
      if (tracked < UPLOAD_BOUNDS.maxReceiptsPerDeploy) {
        modelled.add(receipt.object);
        tracked += 1;
      } else {
        receiptFaults.push("too-many");
      }
    }
    if (s.duplicateReceipt && s.receipts.length > 0) {
      deploy.receipt({ bucket: FAKE_BUCKET, object: s.receipts[0].object });
    }
    if (s.badBucketReceipt) {
      deploy.receipt({
        bucket: "gcf-v2-uploads-999999999999.us-central1.cloudfunctions.appspot.com",
        object: uuid(7),
      });
      receiptFaults.push("bucket");
    }
    if (s.badObjectReceipt) {
      deploy.receipt({ bucket: FAKE_BUCKET, object: "../x.zip" });
      receiptFaults.push("object");
    }
    if (s.baselineReceipt) {
      deploy.receipt({ bucket: FAKE_BUCKET, object: "base-00000" });
      receiptFaults.push("baseline");
    }
    if (s.afterListFault === "503") {
      world.override({ method: "GET", url: "/o?" }, answer(503));
    }

    if (s.crashBeforeFinish) {
      const before = world.requests.length;
      uploads.close();
      const resumed = openUploads(ledgerPath);
      assert.equal(
        resumed.report().closureReady,
        false,
        `${seed}: resumed ledger closed an open deploy`,
      );
      assert.equal(world.requests.length, before, `${seed}: resume sent requests`);
      resumed.close();
      return { skipped: false };
    }

    if (s.shortAtFinish) left = used + 1;
    const before = world.requests.length;
    const result = await deploy.finish({
      cliExited: s.cliExited,
      exitCode: s.cliExited ? s.exitCode : null,
    });
    const sent = world.requests.slice(before);

    // Safety: only DELETEs of tracked receipt objects, each conditional on a numeric generation.
    for (const request of sent.filter((r) => r.method === "DELETE")) {
      const object = decodeURIComponent(new URL(request.url).pathname.split("/").at(-1));
      assert.ok(modelled.has(object), `${seed}: DELETE of ${object}`);
      assert.ok(!baseline.has(object), `${seed}: DELETE of a baseline object`);
      assert.match(request.url, /ifGenerationMatch=\d+$/, `${seed}: unconditional DELETE`);
    }
    for (const name of baseline) {
      assert.ok(world.objects.has(name), `${seed}: baseline object ${name} was deleted`);
    }
    for (let i = 0; i < s.foreign; i += 1) {
      assert.ok(world.objects.has(`foreign-${i}.zip`), `${seed}: foreign object deleted`);
    }
    // Budget: no dispatch beyond what was left, none at all when the bound was short.
    if (s.shortAtFinish) {
      assert.equal(sent.length, 0, `${seed}: dispatched with a short budget`);
      assert.equal(result.clean, false);
    }
    assert.ok(used <= left || s.shortAtFinish, `${seed}: used ${used} of ${left}`);

    // Reference model.
    const objectsOk = s.receipts.slice(0, UPLOAD_BOUNDS.maxReceiptsPerDeploy).every((r) => {
      if (r.uploaded) return r.fault === "none";
      // never arrived: it settles only when there is a PUT status and every one is a definite 4xx
      const definite = (x) => x >= 400 && x < 500 && ![408, 429, 499].includes(x);
      return r.put.length > 0 && r.put.every(definite);
    });
    const afterTooBig =
      baseline.size + s.foreign + s.afterGrowth + s.receipts.filter((r) => r.uploaded).length >
      UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages;
    const expectClean =
      !s.shortAtFinish &&
      (modelled.size > 0 || (s.cliExited && s.exitCode !== 0)) &&
      objectsOk &&
      receiptFaults.length === 0 &&
      s.foreign === 0 &&
      s.afterGrowth === 0 &&
      s.afterListFault === "none" &&
      !afterTooBig;
    assert.equal(result.clean, expectClean, `${seed}: ${JSON.stringify(s)} -> ${result.reasons}`);
    if (result.clean) {
      for (const r of s.receipts)
        assert.ok(!world.objects.has(r.object), `${seed}: owned object left`);
      assert.equal(uploads.report().closureReady, true, `${seed}: clean but the ledger is open`);
      assert.deepEqual([...world.objects.keys()].toSorted(), [...baseline].toSorted());
    }
    uploads.close();
    return { skipped: false };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("Gen2 source uploads against random worlds", () => {
  it(`agrees with the reference model and keeps the safety properties (${CASES} cases)`, async () => {
    let ran = 0;
    for (let i = 0; i < CASES; i += 1) {
      const outcome = await run(BASE_SEED + i);
      if (!outcome.skipped) ran += 1;
    }
    assert.ok(ran > CASES * 0.8, `only ${ran} cases ran`);
  });
});
