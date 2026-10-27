// Ownership, conditional deletion and read-back of the Gen2 source upload objects that a recorder's
// deploys leave in the `gcf-v2-uploads-<project number>.<region>.cloudfunctions.appspot.com` bucket.
// Nothing deletes them automatically. A recorder that deploys 2nd gen functions opens this helper
// once per run, calls `beginDeploy` before each deploy, feeds it the receipts the deploy produces,
// and calls `finish` during cleanup. A deploy is clean only when every upload it owned is deleted
// and read back as absent and no new object in the bucket is left unexplained.
//
// Receipts. A deploy learns its upload from one place only: the firebase-tools `--debug` output. The
// answer of `generateUploadUrl` (`<<< [apiv2][body] POST .../functions:generateUploadUrl {...}`) names
// the bucket and object and exists even when the deploy fails afterwards; the upload's own status
// line (`<<< [apiv2][status] PUT https://storage.googleapis.com/<bucket>/<object> <code>`) says
// whether the CLI's create was answered. The function record is not a receipt: a deployed record
// names the copy Cloud Functions made in `gcf-v2-sources-<number>-<region>` (recorded: FE v4 lists),
// not the upload. Time, size and count never make an object ours. An object that appears in the
// bucket without a receipt is reported as unexplained and never deleted.
//
// The upload is a create whose answer the recorder reads from that PUT line. 2xx: confirmed. A
// definite 4xx: refused (nothing was created). A missing line, a 5xx, a 408, 429 or 499: unknown, and
// a 404 read of the object never settles it (the ownership rules of ownership.mjs); only an own read
// that shows the object does, and then the object is deleted by generation.
//
// The responsibility journal is an ownership ledger (ownership.mjs): one placeholder create per
// deploy, which stays open until the deploy is accounted for, and one create per receipt object. A
// run that stops leaves those intents unanswered, and resuming the ledger turns them into unknown
// answers, so the responsibility and the lock outlive the process. The `deploy:<key>` placeholder
// names no resource, so no read can ever settle it; on a clean deploy it is answered with a
// bookkeeping 404 (transport label `accounting`, not a production status), and on an unclean one it
// stays unknown until the coordinator accepts it with an owner-ledger line and an A2 list that shows
// no unexplained object and every receipt absent.
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

const validObject = (object) => typeof object === "string" && OBJECT_NAME.test(object);

const GENERATE_LINE =
  /<<< \[apiv2\]\[body\] POST \S+\/functions:generateUploadUrl(?:\?\S*)? (\{.*\})\s*$/u;
const PUT_STATUS_LINE =
  /<<< \[apiv2\]\[status\] PUT https:\/\/storage\.googleapis\.com\/([^/\s?]+)\/([^\s?]+) (\d{3})\s*$/u;

/** One CLI output line as an event: a receipt, an upload status, or null. */
export function uploadEventFromLine(line) {
  const put = PUT_STATUS_LINE.exec(line);
  if (put) return { type: "put-status", bucket: put[1], object: put[2], status: Number(put[3]) };
  const match = GENERATE_LINE.exec(line);
  if (!match) return null;
  let body;
  try {
    body = JSON.parse(match[1]);
  } catch {
    return null;
  }
  const source = body?.storageSource;
  if (typeof source?.bucket === "string" && typeof source.object === "string") {
    return { type: "receipt", bucket: source.bucket, object: source.object };
  }
  return externalUpload(body?.uploadUrl);
}

/**
 * A 1st gen `generateUploadUrl` answer names only the signed `uploadUrl`, of a bucket outside the
 * project (firebase-tools 15.28.2, FE v4 debug log: `uploads-<other number>.<region>.cloudfunctions.appspot.com`).
 * It is no receipt: nothing in the project's own bucket is made. The event keeps the bucket and object
 * name and never the query string with the signature.
 */
function externalUpload(uploadUrl) {
  if (typeof uploadUrl !== "string") return null;
  let url;
  try {
    url = new URL(uploadUrl);
  } catch {
    return null;
  }
  const [bucket, object, ...rest] = url.pathname.split("/").filter((part) => part !== "");
  if (url.host !== "storage.googleapis.com" || rest.length > 0) return null;
  if (typeof bucket !== "string" || !validObject(object)) return null;
  return { type: "external-upload", bucket, object };
}

export function uploadEventsFromCliOutput(text) {
  return text
    .split(/\r?\n/u)
    .map(uploadEventFromLine)
    .filter((event) => event !== null);
}

/** Reads upload events from a stream of CLI output as it arrives, one complete line at a time. */
export function createReceiptScanner(onEvent) {
  let tail = "";
  const scan = (line) => {
    const event = uploadEventFromLine(line);
    if (event) onEvent(event, line);
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
  // The receipts of every deploy of this run, by the exact object each one named: a deploy that finishes
  // later than its siblings started finds their objects in the bucket. Such an object is explained only
  // while the sibling's own PUT is not a definite refusal (a refused create made nothing, so an object
  // that is there anyway belongs to nobody). Deleting stays with the deploy whose receipt named it.
  const claimed = new Map();

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
        items.length > UPLOAD_BOUNDS.pageSize ||
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

  // `generation` is the function generation the CLI deploys. A 1st gen upload goes to a bucket outside
  // the project, so such a deploy is not expected to show a receipt.
  async function beginDeploy(key, { generation = 2 } = {}) {
    if (typeof key !== "string" || key === "") throw new Error("a deploy needs a key");
    if (generation !== 1 && generation !== 2) throw new Error("deploy generation must be 1 or 2");
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
    const ticket = beginCreate(state, { name: placeholder, transport: "accounting" });
    return createDeploy({
      placeholder,
      ticket,
      baseline: baseline.names,
      deployGeneration: generation,
    });
  }

  /**
   * "confirmed": some status is a 2xx. "refused": there is at least one status and every one is a
   * definite 4xx (not 408, 429 or 499), so nothing was made. Anything else is "unknown": no line, a
   * 3xx or 5xx, 408/429/499, or a retried PUT that met a 5xx or a retryable code before a refusal
   * (503 then 400 may mean the first attempt landed).
   */
  function putClass(statuses) {
    if (statuses.some((status) => status >= 200 && status < 300)) return "confirmed";
    const definite = (status) => status >= 400 && status < 500 && ![408, 429, 499].includes(status);
    return statuses.length > 0 && statuses.every(definite) ? "refused" : "unknown";
  }

  function createDeploy({ placeholder, ticket, baseline, deployGeneration }) {
    const receipts = new Map();
    const faults = new Set();
    let finished = false;

    // A null candidate names nothing and is ignored, as is anything after the deploy finished.
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
        const entry = {
          name,
          statuses: [],
          ticket: beginCreate(state, { name, transport: "rest" }),
        };
        receipts.set(candidate.object, entry);
        claimed.set(candidate.object, entry);
      } catch {
        faults.add("receipt-not-journaled");
      }
    }

    /** Feeds one event from the CLI output: a receipt, or the status of the upload's PUT. */
    function observe(event) {
      if (finished || event === null || typeof event !== "object") return;
      if (event.type === "receipt") receipt(event);
      else if (event.type === "put-status" && event.bucket === bucket) {
        receipts.get(event.object)?.statuses.push(event.status);
      }
    }

    async function readObject(object) {
      const meta = await dispatch("GET", objectUrl(object, "?fields=bucket,name,generation"));
      if (meta.status === 404 && meta.bodyReadable) return { found: false };
      const generation = String(meta.value?.generation ?? "");
      if (
        meta.status !== 200 ||
        !meta.bodyReadable ||
        meta.value?.bucket !== bucket ||
        meta.value?.name !== object ||
        !/^\d{1,20}$/u.test(generation)
      ) {
        return { found: null };
      }
      return { found: true, generation };
    }

    async function settleReceipt(object, entry, reasons) {
      const { name } = entry;
      const klass = putClass(entry.statuses);
      if (klass === "refused") {
        // The CLI's own create was answered with a definite refusal: nothing was made.
        recordAnswer(state, entry.ticket, { status: entry.statuses.at(-1), bodyReadable: true });
        return;
      }
      const unknown = (reason) => {
        recordAnswer(state, entry.ticket, { transportError: true });
        reasons.push(`${reason}:${name}`);
      };
      const read = await readObject(object);
      if (read.found === null) {
        unknown("object-unreadable");
        return;
      }
      if (!read.found) {
        if (klass === "confirmed") {
          // A create that was answered 2xx and now reads 404: not settled in the run.
          recordAnswer(state, entry.ticket, { status: 200, bodyReadable: true });
          reasons.push(`confirmed-upload-absent:${name}`);
        } else {
          recordAnswer(state, entry.ticket, { transportError: true });
          reasons.push(`receipt-unconfirmed:${name}`);
        }
        recordRead(state, { name, transport: "rest", answer: { status: 404, bodyReadable: true } });
        return;
      }
      if (klass === "unknown") {
        // The PUT's answer was never seen. An own read that shows the object settles the unknown
        // create (it is ours by its receipt); the run still needs the A2 read-back before it closes.
        recordAnswer(state, entry.ticket, { transportError: true });
        recordRead(state, {
          name,
          transport: "rest",
          answer: { status: 200, bodyReadable: true, bodyName: name },
        });
      } else {
        recordAnswer(state, entry.ticket, { status: 200, bodyReadable: true });
      }
      const deleteTicket = beginDelete(state, { name, transport: "rest" });
      const deleted = await dispatch(
        "DELETE",
        objectUrl(object, `?ifGenerationMatch=${read.generation}`),
      );
      const result = recordAnswer(state, deleteTicket, deleted);
      if (result.class !== "ok") {
        reasons.push(`delete-${result.class}:${name}`);
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

    /**
     * Accounts for the deploy once its CLI is over. `exitCode` is the CLI's exit code, or null when
     * it did not end by itself.
     */
    async function finish({ cliExited, exitCode = null }) {
      if (finished) throw new Error(`deploy ${placeholder} already finished`);
      if (typeof cliExited !== "boolean") throw new Error("finish needs cliExited");
      finished = true;
      const reasons = [...faults];
      // A CLI that was killed before any receipt was seen may have an upload in flight; a deploy that
      // ended well without one used an upload path this helper does not see (or printed no debug line).
      if (deployGeneration === 2) {
        if (!cliExited && receipts.size === 0) reasons.push("killed-without-receipt");
        if (cliExited && exitCode === 0 && receipts.size === 0) reasons.push("no-receipt");
      }
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
          await settleReceipt(object, entry, reasons);
        }
        for (const name of [...after.names].toSorted()) {
          const entry = receipts.get(name);
          const holder = entry ?? claimed.get(name);
          const explained = holder !== undefined && putClass(holder.statuses) !== "refused";
          if (!baseline.has(name) && !explained) reasons.push(`unexplained-object:${name}`);
        }
        // Bookkeeping only: this name is no resource, so the answer is not a production status.
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

    return { receipt, observe, finish };
  }

  return {
    // One helper serves the uploads bucket of one region: callers refuse a target elsewhere.
    region,
    bucket,
    beginDeploy,
    report: () => closureReport(state),
    close: () => closeOwnership(state),
  };
}
