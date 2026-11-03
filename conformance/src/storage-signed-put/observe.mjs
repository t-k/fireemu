// Orchestrator of the signed PUT observation. It is target-agnostic: `deps` supplies the network,
// the SDK signer, the clock and the credentials, so the same code runs against production, against
// fireemu (the dry run) and against the fake world of the tests.
//
// Order: preflight (bucket, signer, empty run prefix), then two recordings of every case, then
// cleanup in a `finally`: list the prefix, delete every object this run created or listed under its
// own planned names, read each back absent, list again. An unknown answer stops the run and goes
// to cleanup; it is never retried.

import { Buffer } from "node:buffer";

import {
  GuardError,
  RequestBudget,
  isUnknownStatus,
  classifyRequest,
  dropSignature,
  tamperSignature,
} from "./guard.mjs";
import {
  clockSkewOk,
  compareRecordings,
  describeSignedUrl,
  judgePut,
  normalizeBody,
  normalizeHeaders,
  parseXmlError,
  putRow,
  settleObjects,
} from "./judge.mjs";
import {
  CASES,
  EXPIRY_MARGIN_MS,
  MAIN_CAP,
  MAX_SIGN_PROBES,
  RANGE_HEADER,
  READBACK_CAP,
  ROLE_ID,
  SIGN_PROBE_WAIT_MS,
  RECORDINGS,
  REQUEST_TIMEOUT_MS,
  TOTAL_CAP,
  caseObjects,
  expectedRequests,
  plannedNames,
  recordingPrefix,
  runPrefix,
} from "./plan.mjs";
import {
  iamGrant,
  iamPreflight,
  holdsRole,
  iamRemove,
  ourBinding,
  roleName,
  samePolicy,
  settleIam,
  signerPolicyRequest,
  validateMember,
  validateWindow,
} from "./iam.mjs";
import { UnknownAnswer, createWire } from "./wire.mjs";

export { UnknownAnswer };

export class StopRun extends Error {}

const META_FIELDS = [
  "kind",
  "name",
  "bucket",
  "size",
  "contentType",
  "storageClass",
  "md5Hash",
  "crc32c",
  "contentEncoding",
  "cacheControl",
  "contentDisposition",
  "metadata",
];

const isCreated = (event) =>
  (event.event === "create" && event.status >= 200 && event.status < 300) ||
  (event.event === "read" && event.status === 200);

/**
 * @param {object} options
 * @param {object} options.target `{name, bucket, project?, signer?, origin?}`
 * @param {string} options.runId `sp-xxxxxxxx`
 * @param {object} options.deps `{net, sign, adminHeaders, now, sleep}`
 * @param {object} options.out `{journal(entry), save(name, data)}`
 * @param {{member: string, windowMinutes: number}} [options.iam] the signer binding (production)
 */
export async function observe({
  target,
  runId,
  cases = CASES,
  recordings = RECORDINGS,
  deps,
  out: rawOut,
  iam = null,
  caps = { main: MAIN_CAP, total: TOTAL_CAP },
}) {
  // A failure to journal or save (a full disk) is reported, never allowed to end the run before the
  // object cleanup and the IAM removal have happened.
  const reportingErrors = [];
  const noteReportingError = (label, error) => {
    const text = `${label}: ${error?.message ?? error}`;
    if (reportingErrors.length < 20 && !reportingErrors.includes(text)) reportingErrors.push(text);
  };
  const out = {
    journal(entry) {
      try {
        rawOut.journal(entry);
      } catch (error) {
        noteReportingError("journal", error);
      }
    },
    save(name, data) {
      try {
        rawOut.save(name, data);
      } catch (error) {
        noteReportingError(name, error);
      }
    },
  };
  if (target.name === "production") {
    if (!iam) throw new StopRun("the production run needs the signer IAM settings");
    validateMember(iam.member);
    validateWindow(iam.windowMinutes);
  }
  const prefix = runPrefix(runId);
  const budget = new RequestBudget(caps.main, caps.total);
  const masks = [
    [target.signer ?? "", "<signer>"],
    [target.bucket, "<bucket>"],
    [target.project ?? "", "<project>"],
    [runId, "<run>"],
  ].filter(([value]) => value);
  const events = [];
  const rows = [];
  const reads = [];
  const planned = new Set(plannedNames(runId, cases, recordings));
  const jsonBase = target.name === "production" ? "https://storage.googleapis.com" : target.origin;
  const objectUrl = (name, query = "") =>
    `${jsonBase}/storage/v1/b/${target.bucket}/o/${encodeURIComponent(name)}${query}`;
  const listUrl = `${jsonBase}/storage/v1/b/${target.bucket}/o?prefix=${encodeURIComponent(prefix)}&maxResults=1000`;
  let stopped = null;
  let finished = false;

  const { wire, meter, unknownLabels } = createWire({ target, prefix, budget, deps, out });
  const iamEvents = [];
  const iamCtx = {};
  let probes = 0;
  let ours = null;
  const io = {
    wire: (label, request, options) => wire(label, request, { admin: true, ...options }),
    events: iamEvents,
  };

  async function preflight() {
    if (target.name === "production") {
      const bucket = await wire(
        "bucket",
        { method: "GET", url: `${jsonBase}/storage/v1/b/${target.bucket}` },
        { admin: true },
      );
      if (
        bucket.status !== 200 ||
        JSON.parse(bucket.body.toString("utf8")).name !== target.bucket
      ) {
        throw new StopRun("bucket is not the expected one");
      }
      if (!clockSkewOk(deps.now(), bucket.headers.date)) {
        throw new StopRun("local clock differs from the server's by more than the allowed skew");
      }
      const signer = await wire(
        "signer",
        {
          method: "GET",
          url: `https://iam.googleapis.com/v1/projects/${target.project}/serviceAccounts/${target.signer}`,
        },
        { admin: true },
      );
      const account = signer.status === 200 ? JSON.parse(signer.body.toString("utf8")) : {};
      if (account.email !== target.signer || account.disabled === true) {
        throw new StopRun("signer service account not readable");
      }
      const found = await iamPreflight({ io, target });
      iamCtx.saPolicy = found.saPolicy;
      iamCtx.roleReads = found.roleReads;
      out.save("iam-preflight.json", {
        runId,
        signer: target.signer,
        policy: found.saPolicy,
        signerRoles: found.roles,
        conditionalSignerBindings: found.conditional,
      });
    }
    const list = await wire("prefix-empty", { method: "GET", url: listUrl }, { admin: true });
    if (list.status !== 200 || JSON.parse(list.body.toString("utf8")).items?.length) {
      throw new StopRun("run prefix is not empty");
    }
  }

  async function grantAndAwaitSigner() {
    if (target.name !== "production") return;
    const endMs = deps.now() + iam.windowMinutes * 60_000;
    ours = ourBinding({ project: target.project, member: iam.member, runId, endMs });
    out.save("iam-grant-plan.json", { binding: ours, windowEndMs: endMs });
    await iamGrant({ io, target, ctx: iamCtx, ours });
    for (probes = 1; probes <= MAX_SIGN_PROBES; probes += 1) {
      const before = unknownLabels.length;
      try {
        await deps.sign(
          {
            name: `${prefix}probe.png`,
            contentType: "image/png",
            range: null,
            expires: deps.now() + 5 * 60_000,
          },
          meter,
        );
        return;
      } catch (error) {
        if (unknownLabels.length > before || error instanceof GuardError) throw error;
        if (probes === MAX_SIGN_PROBES) {
          throw new StopRun(`signBlob still refused after ${probes} probes: ${error.message}`);
        }
        await deps.sleep(SIGN_PROBE_WAIT_MS);
      }
    }
  }

  function summarize(json) {
    const picked = {};
    for (const field of META_FIELDS) if (json[field] !== undefined) picked[field] = json[field];
    return JSON.parse(normalizeBody(JSON.stringify(picked), masks));
  }

  async function followUps(recording, testCase, name, verdict) {
    const record = (step, extra) => reads.push({ recording, id: testCase.id, step, ...extra });
    if (verdict.class === "accepted") {
      const meta = await wire(
        `${testCase.id}-metadata`,
        { method: "GET", url: objectUrl(name) },
        { admin: true },
      );
      events.push({ name, event: "read", status: meta.status });
      record("metadata", {
        status: meta.status,
        metadata: meta.status === 200 ? summarize(JSON.parse(meta.body.toString("utf8"))) : null,
      });
      if (testCase.followUps === "full") {
        // `File#exists()` is this same metadata GET: true on a 200, false on a 404 (the SDK's
        // ServiceObject#exists). It is recorded from the read above, so every request is metered.
        record("exists", { value: meta.status === 200, via: "metadata-read" });
        const media = await wire(
          `${testCase.id}-media`,
          { method: "GET", url: objectUrl(name, "?alt=media") },
          { admin: true },
        );
        record("media", {
          status: media.status,
          equalsBody:
            media.status === 200 && Buffer.compare(media.body, Buffer.from(testCase.body)) === 0,
        });
      }
    } else {
      const absent = await wire(
        `${testCase.id}-absence`,
        { method: "GET", url: objectUrl(name) },
        { admin: true },
      );
      record("absence", { status: absent.status });
      if (absent.status === 200) {
        events.push({ name, event: "read", status: 200 });
        record("unexpected-object", { name: normalizeBody(name, masks) });
      }
    }
  }

  async function runCase(recording, testCase) {
    const names = caseObjects(testCase);
    const signedName = `${recordingPrefix(runId, recording)}${names.signed}`;
    const sentName = `${recordingPrefix(runId, recording)}${names.sent}`;
    const short = testCase.short === true;
    let now = deps.now();
    // The SDK refuses an expiry in the past, and signing takes a moment: do not start the shortest
    // lifetime in the last part of a second.
    if (short && now % 1000 > 800) {
      await deps.sleep(1000 - (now % 1000) + 5);
      now = deps.now();
    }
    const accessibleAt = short ? Math.floor(now / 1000) * 1000 : undefined;
    const expires = short ? accessibleAt + 1000 : now + 5 * 60 * 1000;
    let url = await deps.sign(
      {
        name: signedName,
        contentType: testCase.signed.contentType,
        range: testCase.signed.range,
        expires,
        accessibleAt,
      },
      meter,
    );
    out.save(`signed-url-${recording}-${testCase.id}.json`, describeSignedUrl(url, masks));
    if (testCase.mutate === "tamper") url = tamperSignature(url);
    if (testCase.mutate === "drop-signature") url = dropSignature(url);
    if (sentName !== signedName) {
      const swapped = url.replace(signedName, sentName);
      if (swapped === url) throw new StopRun("signed name not found in the URL");
      url = swapped;
    }
    if (testCase.preflight) {
      const options = await wire(`${testCase.id}-preflight`, {
        method: "OPTIONS",
        url,
        headers: {
          origin: testCase.sent.origin,
          "access-control-request-method": "PUT",
          "access-control-request-headers": ["content-type", RANGE_HEADER].join(","),
        },
      });
      reads.push({
        recording,
        id: testCase.id,
        step: "options",
        status: options.status,
        code: parseXmlError(options.body)?.Code ?? null,
        bodyBytes: options.body.length,
        headers: normalizeHeaders(options.headers),
      });
    }
    if (short) {
      while (deps.now() < expires + EXPIRY_MARGIN_MS) await deps.sleep(250);
    }
    const headers = {};
    if (testCase.sent.contentType) headers["content-type"] = testCase.sent.contentType;
    if (testCase.sent.range) headers[RANGE_HEADER] = testCase.sent.range;
    if (testCase.sent.origin) headers.origin = testCase.sent.origin;
    let answer;
    try {
      answer = await wire(
        `${recording}-${testCase.id}-put`,
        { method: "PUT", url, headers, body: Buffer.from(testCase.body) },
        { context: { case: testCase.id, recording } },
      );
    } catch (error) {
      if (error instanceof UnknownAnswer) {
        events.push({ name: sentName, event: "create", status: error.status });
      }
      throw error;
    }
    events.push({ name: sentName, event: "create", status: answer.status });
    const verdict = judgePut(testCase, answer);
    rows.push(
      putRow({
        recording,
        testCase,
        answer,
        verdict,
        masks,
      }),
    );
    out.save("results.json", {
      source: "production observation; not a canonical fixture",
      rows,
      reads,
    });
    if (verdict.stopRun) {
      throw new StopRun(
        `positive control ${testCase.id} was not accepted (status ${answer.status})`,
      );
    }
    await followUps(recording, testCase, sentName, verdict);
  }

  const cleanupErrors = [];
  async function cleanup() {
    budget.cleanup = true;
    const generation = new Map();
    let items = [];
    // A failed list does not stop the deletion of the objects this run already confirmed.
    try {
      const listed = await wire("cleanup-list", { method: "GET", url: listUrl }, { admin: true });
      if (listed.status !== 200) throw new Error(`cleanup list answered ${listed.status}`);
      items = JSON.parse(listed.body.toString("utf8")).items ?? [];
    } catch (error) {
      cleanupErrors.push(error);
    }
    for (const item of items) {
      events.push({ name: item.name, event: "listed" });
      generation.set(item.name, item.generation);
    }
    const confirmed = events.filter(isCreated).map((event) => event.name);
    const targets = new Set([
      ...confirmed,
      ...items.map((item) => item.name).filter((name) => planned.has(name)),
    ]);
    try {
      for (const name of targets) {
        const precondition = generation.get(name)
          ? `?ifGenerationMatch=${generation.get(name)}`
          : "";
        try {
          const deleted = await wire(
            "cleanup-delete",
            { method: "DELETE", url: objectUrl(name, precondition) },
            { admin: true },
          );
          events.push({ name, event: "delete", status: deleted.status });
        } catch (error) {
          if (!(error instanceof UnknownAnswer)) throw error;
          events.push({ name, event: "delete", status: error.status });
          continue;
        }
        try {
          const readBack = await wire(
            "cleanup-readback",
            { method: "GET", url: objectUrl(name) },
            { admin: true },
          );
          events.push({ name, event: "read-after-delete", status: readBack.status });
        } catch (error) {
          if (!(error instanceof UnknownAnswer)) throw error;
        }
      }
    } catch (error) {
      cleanupErrors.push(error);
      return [];
    }
    try {
      const after = await wire(
        "cleanup-list-final",
        { method: "GET", url: listUrl },
        { admin: true },
      );
      if (after.status !== 200) throw new Error(`final cleanup list answered ${after.status}`);
      return (JSON.parse(after.body.toString("utf8")).items ?? []).map((item) => item.name);
    } catch (error) {
      cleanupErrors.push(error);
      return [];
    }
  }

  let iamError = null;
  async function removeSignerAccessInRun() {
    if (target.name !== "production" || !(iamCtx.grantAttempted || iamCtx.roleCreateAttempted)) {
      return;
    }
    budget.cleanup = true;
    try {
      await iamRemove({ io, target, ctx: iamCtx, ours });
    } catch (error) {
      iamError = error;
      out.save("iam-failure.json", {
        message: normalizeBody(String(error?.message ?? error), masks),
      });
    }
  }

  let remaining = [];
  try {
    try {
      await preflight();
      await grantAndAwaitSigner();
      for (let recording = 1; recording <= recordings; recording += 1) {
        for (const testCase of cases) await runCase(recording, testCase);
      }
      finished = true;
    } catch (error) {
      stopped = error instanceof Error ? error.message : String(error);
      out.save("failure.json", {
        message: normalizeBody(stopped, masks),
        kind: error?.constructor?.name,
      });
    } finally {
      remaining = await cleanup();
      if (cleanupErrors.length > 0) {
        out.save("cleanup-failure.json", {
          message: normalizeBody(String(cleanupErrors[0]?.message ?? cleanupErrors[0]), masks),
        });
      }
    }
  } finally {
    // Last and unconditional: the signer access ends whatever happened above.
    await removeSignerAccessInRun();
  }
  const cleanupError = cleanupErrors[0] ?? null;
  const iamTouched = iamEvents.length > 0;
  const iamUnresolved = [
    ...settleIam(iamEvents, { touched: iamTouched }),
    ...(iamError
      ? [{ name: "signer binding", reason: `removal failed: ${iamError.message}` }]
      : []),
  ];
  function iamReport() {
    const finalRead = iamEvents.findLast(
      (e) => e.resource === "binding" && e.event === "final-read",
    );
    const roleRead = iamEvents.findLast((e) => e.resource === "role" && e.event === "final-read");
    return {
      roleReads: iamCtx.roleReads ?? null,
      granted: iamEvents.some((e) => e.event === "grant" && e.status >= 200 && e.status < 300),
      signProbes: probes,
      policyEqualsPreflight: finalRead ? finalRead.equalsPreflight : null,
      bindingStillPresent: finalRead ? finalRead.present : null,
      roleDeleted: roleRead ? roleRead.deleted : null,
      windowEnd: ours?.condition.expression ?? null,
    };
  }
  const settled = settleObjects(events);
  const unresolved = [
    ...settled.unresolved,
    ...iamUnresolved,
    ...remaining
      .filter((name) => !planned.has(name))
      .map((name) => ({ name, reason: "foreign object under the run prefix" })),
    ...remaining
      .filter((name) => planned.has(name))
      .map((name) => ({ name, reason: "still listed after cleanup" })),
  ];
  const report = {
    runId,
    target: target.name,
    requests: budget.count,
    expectedRequests: expectedRequests(cases, recordings, target.name, {
      roleReads: iamCtx.roleReads ?? 0,
      probes,
    }),
    iam: target.name === "production" ? iamReport() : null,
    rows: rows.length,
    finished,
    stopped,
    unknownRequests: unknownLabels,
    cleanupError: cleanupError ? String(cleanupError.message) : null,
    // Everything this run created is deleted and read back absent, with no unknown answer.
    reportingErrors,
    cleanupVerified:
      !cleanupError &&
      unresolved.length === 0 &&
      unknownLabels.length === 0 &&
      reportingErrors.length === 0,
    closureReady:
      finished &&
      !cleanupError &&
      unresolved.length === 0 &&
      unknownLabels.length === 0 &&
      reportingErrors.length === 0,
    unresolved: unresolved.map((item) => ({
      reason: item.reason,
      name: normalizeBody(item.name, masks),
    })),
    recordingDifferences: compareRecordings(rows),
  };
  out.save("report.json", report);
  return { report, rows, reads };
}

/**
 * The A2 read-back, a separate command run at least 10 minutes after the last request of the
 * run: the run prefix lists empty and every name the plan can create reads 404. Reads only.
 */
export async function readbackAbsent({
  target,
  runId,
  cases = CASES,
  recordings = RECORDINGS,
  deps,
  out,
}) {
  const prefix = runPrefix(runId);
  const budget = new RequestBudget(READBACK_CAP, READBACK_CAP);
  const jsonBase = target.name === "production" ? "https://storage.googleapis.com" : target.origin;
  const get = async (label, url) => {
    const request = { method: "GET", url };
    classifyRequest(target, request, prefix);
    const n = budget.take();
    out.journal({ phase: "before", n, label, method: "GET", url });
    let res;
    try {
      res = await deps.net({
        ...request,
        headers: deps.adminHeaders(),
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch {
      // A transport failure is a status no read-back can call absent.
      out.journal({ phase: "unknown", n, label });
      return { status: Number.NaN, body: Buffer.alloc(0) };
    }
    const body = Buffer.from(res.body ?? []);
    out.journal({ phase: "after", n, label, status: res.status, bodyBytes: body.length });
    return { status: res.status, body };
  };
  const listed = await get(
    "a2-list",
    `${jsonBase}/storage/v1/b/${target.bucket}/o?prefix=${encodeURIComponent(prefix)}&maxResults=1000`,
  );
  const items =
    listed.status === 200 ? (JSON.parse(listed.body.toString("utf8")).items ?? []) : null;
  const results = [];
  for (const name of plannedNames(runId, cases, recordings)) {
    const read = await get(
      "a2-read",
      `${jsonBase}/storage/v1/b/${target.bucket}/o/${encodeURIComponent(name)}`,
    );
    results.push({ name, status: read.status });
  }
  const report = {
    runId,
    requests: budget.count,
    listStatus: listed.status,
    listEmpty: items !== null && items.length === 0,
    statuses: results.filter((r) => r.status !== 404),
    allAbsent: items !== null && items.length === 0 && results.every((r) => r.status === 404),
  };
  out.save("a2.json", report);
  return report;
}

/**
 * The A2 read-back of the signer access, at least 10 minutes after the run: the signer's policy
 * equals the preflight policy apart from the etag, no binding of the signer role remains, and the
 * role reads absent or deleted. Reads only.
 */
export async function readbackIam({ target, runId, deps, out, preflight }) {
  const budget = new RequestBudget(4, 4);
  const { wire } = createWire({ target, prefix: runPrefix(runId), budget, deps, out });
  const base = `https://iam.googleapis.com/v1/projects/${target.project}`;
  const report = { runId, requests: 0, unreadable: false };
  try {
    const policy = await wire("a2-signer-policy", signerPolicyRequest(target), { admin: true });
    const current = policy.status === 200 ? JSON.parse(policy.body.toString("utf8")) : null;
    const role = await wire(
      "a2-role",
      { method: "GET", url: `${base}/roles/${ROLE_ID}` },
      { admin: true },
    );
    report.policyEqualsPreflight = current ? samePolicy(current, preflight.policy) : null;
    report.bindingPresent = current ? holdsRole(current, roleName(target.project)) : null;
    report.roleState =
      role.status === 404
        ? "absent"
        : role.status === 200
          ? JSON.parse(role.body.toString("utf8")).deleted === true
            ? "deleted"
            : "live"
          : "unreadable";
  } catch (error) {
    if (!(error instanceof UnknownAnswer)) throw error;
    report.unreadable = true;
  }
  report.requests = budget.count;
  report.clean =
    !report.unreadable &&
    report.policyEqualsPreflight === true &&
    report.bindingPresent === false &&
    (report.roleState === "absent" || report.roleState === "deleted");
  out.save("a2-iam.json", report);
  return report;
}

/**
 * The reviewed standalone removal, for a run whose removal was unknown or failed: reads the
 * signer's policy, removes the run's binding (from `iam-grant-plan.json`) on its etag, deletes the
 * role this run created, and reads both back. The same code and the same shape checks as the run.
 * `roleCreate` is the outcome of the run's role create read from its journal (`roleCreateOutcome`):
 * the role is deleted only for `created` and `unknown`; for `refused`, `none` or a missing value it
 * is kept and reported, because it may not be the run's.
 */
export async function removeSignerAccess({
  target,
  runId,
  deps,
  out,
  preflight,
  plan,
  roleCreate,
}) {
  const budget = new RequestBudget(12, 12);
  const { wire, unknownLabels } = createWire({
    target,
    prefix: runPrefix(runId),
    budget,
    deps,
    out,
  });
  const events = [];
  const io = {
    wire: (label, request, options) => wire(label, request, { admin: true, ...options }),
    events,
  };
  const roleIsOurs = roleCreate === "created" || roleCreate === "unknown";
  const ctx = { grantAttempted: true, roleCreateAttempted: roleIsOurs, saPolicy: preflight.policy };
  let error = null;
  try {
    await iamRemove({ io, target, ctx, ours: plan.binding });
  } catch (caught) {
    error = caught;
  }
  const finalPolicy = events.findLast((e) => e.resource === "binding" && e.event === "final-read");
  const finalRole = events.findLast((e) => e.resource === "role" && e.event === "final-read");
  const unknownRemoval = events.some((e) => e.event === "remove" && isUnknownStatus(e.status));
  const report = {
    runId,
    requests: budget.count,
    unknownRequests: unknownLabels,
    error: error ? String(error.message) : null,
    policyEqualsPreflight: finalPolicy ? finalPolicy.equalsPreflight : null,
    bindingPresent: finalPolicy ? finalPolicy.present : null,
    roleDeleted: finalRole ? finalRole.deleted : null,
    roleCreate: roleCreate ?? null,
    roleKept: !events.some((e) => e.resource === "role" && e.event === "delete"),
  };
  report.clean =
    !error &&
    !unknownRemoval &&
    unknownLabels.length === 0 &&
    report.policyEqualsPreflight === true &&
    report.bindingPresent === false &&
    report.roleDeleted !== false;
  out.save("iam-remove.json", report);
  return report;
}
