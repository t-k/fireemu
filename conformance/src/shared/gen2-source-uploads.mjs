// Ownership, conditional deletion and read-back of the Gen2 source upload objects that a recorder's
// deploys leave in the `gcf-v2-uploads-<project number>.<region>.cloudfunctions.appspot.com` bucket.
// Nothing deletes them automatically. A recorder that deploys 2nd gen functions opens this helper
// once per run, calls `beginDeploy` before each deploy, feeds it the receipts the deploy produces,
// and calls `finish` during cleanup. A deploy is clean only when every upload it owned is deleted
// and read back as absent and no new object in the bucket is left unexplained.
//
// Receipts. A deploy learns its upload from two places only: the firebase-tools debug output line of
// the `generateUploadUrl` answer (it exists even when the deploy fails afterwards), and the function
// record's `buildConfig.source.storageSource`. Time, size and count never make an object ours.
//
// The responsibility journal is an ownership ledger (ownership.mjs): one placeholder create per
// deploy, which stays open until the deploy is accounted for, and one create per receipt object. A
// run that stops leaves those intents unanswered, and resuming the ledger turns them into unknown
// answers, so the responsibility and the lock outlive the process.
//
// The caller supplies `send(method, url)` (it adds credentials and counts the request in the run's
// budget) and `requestsLeft()` (the number of upload requests the budget still allows). The helper
// checks the bound before it dispatches and never needs a request it was not told about.

import {
  beginCreate,
  beginDelete,
  closeOwnership,
  closureReport,
  openOwnership,
  recordAnswer,
  recordRead,
} from "./ownership.mjs";

export const UPLOAD_BOUNDS = Object.freeze({
  pageSize: 100,
  maxPages: 3,
  maxReceiptsPerDeploy: 3,
  maxResponseBytes: 1024 * 1024,
});

/** Baseline list pages, after list pages, and a metadata GET, a DELETE and a read-back per receipt. */
export const REQUESTS_PER_DEPLOY =
  2 * UPLOAD_BOUNDS.maxPages + 3 * UPLOAD_BOUNDS.maxReceiptsPerDeploy;

const STORAGE_API = "https://storage.googleapis.com/storage/v1";
const OBJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u;

export function uploadBucketName(projectNumber, region) {
  if (typeof projectNumber !== "string" || !/^\d{6,16}$/u.test(projectNumber)) {
    throw new Error("upload bucket needs a numeric project number");
  }
  if (typeof region !== "string" || !/^[a-z]+-[a-z]+\d+$/u.test(region)) {
    throw new Error("upload bucket needs a lowercase region");
  }
  return `gcf-v2-uploads-${projectNumber}.${region}.cloudfunctions.appspot.com`;
}

export function assertUploadBucket(bucket, { projectNumber, region }) {
  if (bucket !== uploadBucketName(projectNumber, region)) {
    throw new Error("upload bucket differs from the project's Gen2 upload bucket");
  }
}

const validObject = (object) =>
  typeof object === "string" && OBJECT_NAME.test(object) && !object.includes("..");

/** The upload a function record names, or null. Only bucket and object are read. */
export function uploadReceiptFromFunctionRecord(record) {
  const source = record?.buildConfig?.source?.storageSource;
  if (typeof source?.bucket !== "string" || typeof source.object !== "string") return null;
  return { bucket: source.bucket, object: source.object };
}

const GENERATE_LINE =
  /<<< \[apiv2\]\[body\] POST \S+\/functions:generateUploadUrl(?:\?\S*)? (\{.*\})\s*$/u;

function receiptFromLine(line) {
  const match = GENERATE_LINE.exec(line);
  if (!match) return null;
  let body;
  try {
    body = JSON.parse(match[1]);
  } catch {
    return null;
  }
  return uploadReceiptFromFunctionRecord({
    buildConfig: { source: { storageSource: body.storageSource } },
  });
}

export function uploadReceiptsFromCliOutput(text) {
  return text
    .split(/\r?\n/u)
    .map(receiptFromLine)
    .filter((receipt) => receipt !== null);
}

/** Reads receipts from a stream of CLI output as it arrives, one complete line at a time. */
export function createReceiptScanner(onReceipt) {
  let tail = "";
  const scan = (line) => {
    const receipt = receiptFromLine(line);
    if (receipt) onReceipt(receipt);
  };
  return {
    feed(chunk) {
      tail += chunk;
      const lines = tail.split(/\r?\n/u);
      tail = lines.pop();
      for (const line of lines) scan(line);
      if (tail.length > UPLOAD_BOUNDS.maxResponseBytes) tail = "";
    },
    flush() {
      const rest = tail;
      tail = "";
      scan(rest);
    },
  };
}

/** Removes signed upload URLs and signature parameters from CLI output before it is stored. */
export function redactUploadSecrets(text) {
  return text
    .replace(
      /https?:\/\/[^\s"'<>]*(?:X-Goog-|Signature=|GoogleAccessId=)[^\s"'<>]*/giu,
      "[REDACTED UPLOAD URL]",
    )
    .replace(
      /(?:X-Goog-[A-Za-z-]+|Signature|GoogleAccessId)=[^&\s"'<>]+/giu,
      "[REDACTED SIGNATURE]",
    );
}

export function openSourceUploads({
  ledgerPath,
  runId,
  projectNumber,
  region,
  send,
  requestsLeft,
}) {
  const bucket = uploadBucketName(projectNumber, region);
  if (typeof send !== "function" || typeof requestsLeft !== "function") {
    throw new Error("source uploads need send and requestsLeft");
  }
  const state = openOwnership({ path: ledgerPath, runId });
  const started = new Set();

  async function dispatch(method, url) {
    let reply;
    try {
      reply = await send(method, url);
    } catch {
      return { transportError: true };
    }
    if (reply === null || typeof reply !== "object") return { transportError: true };
    const oversized = !(reply.bytes <= UPLOAD_BOUNDS.maxResponseBytes);
    return {
      status: reply.status,
      bodyReadable: reply.bodyReadable === true && !oversized,
      value: reply.value,
    };
  }

  const objectUrl = (object, query = "") =>
    `${STORAGE_API}/b/${bucket}/o/${encodeURIComponent(object)}${query}`;

  /** Lists the bucket page by page; `complete` is false whenever a page is missing or unreadable. */
  async function listBucket() {
    const names = new Set();
    let token;
    for (let page = 0; page < UPLOAD_BOUNDS.maxPages; page += 1) {
      const query = `maxResults=${UPLOAD_BOUNDS.pageSize}&fields=${encodeURIComponent("items(name,generation),nextPageToken")}${token === undefined ? "" : `&pageToken=${encodeURIComponent(token)}`}`;
      const reply = await dispatch("GET", `${STORAGE_API}/b/${bucket}/o?${query}`);
      if (reply.status === 404 && reply.bodyReadable && page === 0)
        return { names, complete: true };
      const items = reply.value?.items ?? [];
      if (
        reply.status !== 200 ||
        !reply.bodyReadable ||
        !Array.isArray(items) ||
        items.some((item) => typeof item?.name !== "string")
      ) {
        return { names, complete: false };
      }
      for (const item of items) names.add(item.name);
      token = reply.value?.nextPageToken;
      if (token === undefined) return { names, complete: true };
      if (typeof token !== "string" || token === "") return { names, complete: false };
    }
    return { names, complete: false };
  }

  async function beginDeploy(key) {
    if (typeof key !== "string" || key === "") throw new Error("a deploy needs a key");
    if (started.has(key)) throw new Error(`deploy ${key} was already started in this run`);
    const placeholder = `deploy:${key}`;
    if (closureReport(state).reasons.some((reason) => reason.endsWith(`:${placeholder}`))) {
      throw new Error(`deploy ${key} is unsettled in the ledger; a recovery packet must settle it`);
    }
    if (requestsLeft() < REQUESTS_PER_DEPLOY) {
      throw new Error("upload request budget is short of the bound for one deploy");
    }
    const baseline = await listBucket();
    if (!baseline.complete) {
      throw new Error("upload bucket baseline list is incomplete or unreadable");
    }
    started.add(key);
    const ticket = beginCreate(state, { name: placeholder, transport: "cli" });
    return createDeploy({ placeholder, ticket, baseline: baseline.names });
  }

  function createDeploy({ placeholder, ticket, baseline }) {
    const receipts = new Map();
    const faults = new Set();
    let finished = false;

    // A null candidate (a record without a storageSource) names nothing and is ignored.
    function receipt(candidate) {
      if (finished || candidate === null) return;
      if (candidate?.bucket !== bucket) {
        faults.add("receipt-bucket-mismatch");
        return;
      }
      if (!validObject(candidate.object)) {
        faults.add("receipt-object-invalid");
        return;
      }
      if (baseline.has(candidate.object)) {
        // A fresh upload slot never names an object that was already in the bucket.
        faults.add("receipt-names-baseline-object");
        return;
      }
      if (receipts.has(candidate.object)) return;
      if (receipts.size >= UPLOAD_BOUNDS.maxReceiptsPerDeploy) {
        faults.add("too-many-receipts");
        return;
      }
      const name = `${bucket}/${candidate.object}`;
      try {
        receipts.set(candidate.object, {
          name,
          ticket: beginCreate(state, { name, transport: "rest" }),
        });
      } catch {
        faults.add("receipt-not-journaled");
      }
    }

    async function settleReceipt(object, entry, cliExited, reasons) {
      const { name } = entry;
      const unknown = (reason) => {
        recordAnswer(state, entry.ticket, { transportError: true });
        reasons.push(`${reason}:${name}`);
      };
      const meta = await dispatch("GET", objectUrl(object, "?fields=bucket,name,generation"));
      if (meta.status === 404 && meta.bodyReadable) {
        if (cliExited) {
          recordAnswer(state, entry.ticket, { status: 404, bodyReadable: true });
        } else {
          recordAnswer(state, entry.ticket, { transportError: true });
          recordRead(state, {
            name,
            transport: "rest",
            answer: { status: 404, bodyReadable: true },
          });
          reasons.push(`receipt-unconfirmed:${name}`);
        }
        return;
      }
      const generation = String(meta.value?.generation ?? "");
      if (
        meta.status !== 200 ||
        !meta.bodyReadable ||
        meta.value?.bucket !== bucket ||
        meta.value?.name !== object ||
        !/^\d{1,20}$/u.test(generation)
      ) {
        unknown("object-unreadable");
        return;
      }
      recordAnswer(state, entry.ticket, { status: 200, bodyReadable: true });
      const deleteTicket = beginDelete(state, { name, transport: "rest" });
      const deleted = await dispatch(
        "DELETE",
        objectUrl(object, `?ifGenerationMatch=${generation}`),
      );
      const klass = recordAnswer(state, deleteTicket, deleted);
      if (klass.class !== "ok") {
        reasons.push(`delete-${klass.class}:${name}`);
        return;
      }
      const back = await dispatch("GET", objectUrl(object, "?fields=bucket,name,generation"));
      recordRead(state, {
        name,
        transport: "rest",
        answer: {
          status: back.status,
          bodyReadable: back.bodyReadable,
          transportError: back.transportError,
          ...(back.status === 200 && back.value?.bucket === bucket && back.value?.name === object
            ? { bodyName: name }
            : {}),
        },
      });
    }

    async function finish({ cliExited }) {
      if (finished) throw new Error(`deploy ${placeholder} already finished`);
      if (typeof cliExited !== "boolean") throw new Error("finish needs cliExited");
      finished = true;
      const reasons = [...faults];
      const need = UPLOAD_BOUNDS.maxPages + 3 * receipts.size;
      if (requestsLeft() < need) {
        reasons.push("upload-budget");
        for (const entry of receipts.values()) {
          recordAnswer(state, entry.ticket, { transportError: true });
        }
        recordAnswer(state, ticket, { transportError: true });
      } else {
        const after = await listBucket();
        if (!after.complete) reasons.push("list-incomplete");
        for (const [object, entry] of receipts) {
          await settleReceipt(object, entry, cliExited, reasons);
        }
        for (const name of [...after.names].toSorted()) {
          if (!baseline.has(name) && !receipts.has(name))
            reasons.push(`unexplained-object:${name}`);
        }
        recordAnswer(
          state,
          ticket,
          reasons.length === 0 ? { status: 404, bodyReadable: true } : { transportError: true },
        );
      }
      const own = new Set([placeholder, ...[...receipts.values()].map((entry) => entry.name)]);
      for (const reason of closureReport(state).reasons) {
        if (own.has(reason.slice(reason.indexOf(":") + 1)) && !reasons.includes(reason)) {
          reasons.push(reason);
        }
      }
      return { clean: reasons.length === 0, reasons };
    }

    return { receipt, finish };
  }

  return {
    beginDeploy,
    report: () => closureReport(state),
    close: () => closeOwnership(state),
  };
}
