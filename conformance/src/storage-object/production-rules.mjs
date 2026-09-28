import { createHash } from "node:crypto";
import { isDeepStrictEqual, types } from "node:util";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";

const CHECKPOINTS = [
  "initial",
  "rules-before-1",
  "rules-after-1",
  "rules-before-2",
  "rules-after-2",
  "final",
];
const rulesStates = new WeakMap();

/** Require the original Rules state bound to the canonical plan and recording. */
export function verifyProductionRulesBinding(state, supplied) {
  try {
    const proof = record(supplied, ["plan", "recording"]),
      binding = rulesStates.get(state);
    return (
      Object.keys(proof).length === 2 &&
      binding !== undefined &&
      proof.recording === binding.recording &&
      isDeepStrictEqual(copy(proof.plan), binding.plan)
    );
  } catch {
    return false;
  }
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const ascii = (value, max) =>
  typeof value === "string" && /^[\x21-\x7e]+$/.test(value) && value.length <= max;
const timestamp = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) &&
  Number.isFinite(Date.parse(value));
function record(value, keys) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const fields = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      (keys && !keys.includes(key)) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error();
    fields[key] = descriptor.value;
  }
  return fields;
}
function copy(value, depth = 0) {
  if (depth > 16) throw new Error();
  if (value === null || typeof value !== "object") {
    if (value !== null && !["string", "number", "boolean"].includes(typeof value))
      throw new Error();
    return value;
  }
  if (types.isProxy(value)) throw new Error();
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > 64 ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      throw new Error();
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
      return copy(descriptor.value, depth + 1);
    });
  }
  return Object.fromEntries(
    Object.entries(record(value)).map(([key, item]) => [key, copy(item, depth + 1)]),
  );
}
function releaseShape(data, projectId) {
  const row = record(data, ["name", "rulesetName", "createTime", "updateTime"]);
  if (
    Object.keys(row).length !== 4 ||
    !ascii(row.name, 512) ||
    !row.name.startsWith(`projects/${projectId}/releases/`) ||
    !ascii(row.rulesetName, 512) ||
    !new RegExp(`^projects/${projectId}/rulesets/[A-Za-z0-9_-]+$`).test(row.rulesetName) ||
    !timestamp(row.createTime) ||
    !timestamp(row.updateTime)
  )
    throw new Error();
}
function rulesetShape(data, name) {
  const row = record(data, ["name", "source", "createTime", "metadata", "attachment_point"]);
  if (
    row.name !== name ||
    !timestamp(row.createTime) ||
    (Object.hasOwn(row, "attachment_point") && row.attachment_point !== "")
  )
    throw new Error();
  const source = record(row.source, ["files"]);
  if (Object.keys(source).length !== 1 || !Array.isArray(source.files) || source.files.length !== 1)
    throw new Error();
  const file = record(source.files[0], ["name", "content", "fingerprint"]);
  if (
    !ascii(file.name, 128) ||
    typeof file.content !== "string" ||
    Buffer.byteLength(file.content) > 32768 ||
    sha256(file.content) !== FIXED_PRODUCTION_RULES_SHA256 ||
    (Object.hasOwn(file, "fingerprint") &&
      (typeof file.fingerprint !== "string" ||
        file.fingerprint.length > 128 ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(file.fingerprint)))
  )
    throw new Error();
  if (Object.hasOwn(row, "metadata")) {
    const metadata = record(row.metadata, ["services"]);
    if (
      Object.keys(metadata).length !== 1 ||
      !isDeepStrictEqual(metadata.services, ["firebase.storage"])
    )
      throw new Error();
  }
}

/** Fixed Rules snapshots and stage2-owned deletion; shared project exclusion is required and does not prevent external console changes atomically. */
export function createProductionRulesState(input) {
  let options, plan, baseline;
  try {
    options = record(input, [
      "plan",
      "recording",
      "baseline",
      "controls",
      "verifyAdmission",
      "verifySharedUse",
      "onProof",
      "onConfigChange",
    ]);
    options.controls = record(options.controls, ["send", "snapshot"]);
    if (
      Object.keys(options).length !== 8 ||
      ![1, 2].includes(options.recording) ||
      [
        options.controls.send,
        options.verifyAdmission,
        options.verifySharedUse,
        options.onProof,
        options.onConfigChange,
      ].some((fn) => typeof fn !== "function" || types.isProxy(fn)) ||
      [options.verifyAdmission, options.verifySharedUse].some(
        (fn) => Object.getPrototypeOf(fn) !== Function.prototype,
      )
    )
      throw new Error();
    plan = copy(options.plan);
    if (
      !isDeepStrictEqual(
        plan,
        buildProductionStage3DraftPlan({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runIds: plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error();
    baseline = copy(options.baseline);
    record(baseline, ["release", "ruleset", "ownedInStage2"]);
    if (
      Object.keys(baseline).length !== 3 ||
      typeof baseline.ownedInStage2 !== "boolean" ||
      baseline.release?.name !==
        `projects/${plan.projectId}/releases/firebase.storage/${plan.bucket}`
    )
      throw new Error();
    releaseShape(baseline.release, plan.projectId);
    rulesetShape(baseline.ruleset, baseline.release.rulesetName);
  } catch {
    throw new Error("invalid production Rules configuration");
  }
  const recording = options.recording;
  let completed = 0,
    busy = false,
    failed = false,
    closed = false,
    cleanupAttempted = false,
    mutationState = "none";
  function requestContext(id, phase) {
    return Object.freeze({
      recording,
      phase,
      kind: "rules-state",
      operationId: `r${recording}/control/${sha256(id)}`,
    });
  }
  function admitted(context) {
    if (closed || failed || options.verifyAdmission(context) !== true || closed || failed)
      throw new Error();
  }
  function shared(context) {
    admitted(context);
    if (options.verifySharedUse(context) !== true || closed || failed) throw new Error();
  }
  async function send(id, phase, recipeToken, parameters = {}) {
    const context = requestContext(id, phase);
    admitted(context);
    const response = await options.controls.send(id, {
      recipeToken,
      parameters,
      body: Buffer.alloc(0),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    admitted(context);
    if (bytes.length < 2 || bytes.length > 65536) throw new Error();
    const text = bytes.toString("utf8");
    if (!Buffer.from(text).equals(bytes) || parseCaptureJsonSpans(text).type !== "object")
      throw new Error();
    return {
      status: response.status,
      data: JSON.parse(text),
      bodySha256: sha256(bytes),
      id,
      context,
    };
  }
  function absent(result) {
    if (
      result.status !== 404 ||
      result.data.error?.code !== 404 ||
      result.data.error.status !== "NOT_FOUND"
    )
      throw new Error();
  }
  function releaseMatches(result) {
    releaseShape(result.data, plan.projectId);
    if (result.status !== 200 || !isDeepStrictEqual(result.data, baseline.release))
      throw new Error();
  }
  function rulesetMatches(result) {
    rulesetShape(result.data, baseline.ruleset.name);
    if (result.status !== 200 || !isDeepStrictEqual(result.data, baseline.ruleset))
      throw new Error();
  }
  async function snapshot(label, phase, recipeToken) {
    const release = await send(`r${recording}/${label}-rules-release`, phase, recipeToken);
    releaseMatches(release);
    const ruleset = await send(`r${recording}/${label}-rules-ruleset`, phase, recipeToken);
    rulesetMatches(ruleset);
    const bucketless = await send(`r${recording}/${label}-rules-bucketless`, phase, recipeToken);
    absent(bucketless);
    await options.onProof(
      Object.freeze({
        type: "production-rules-checkpoint",
        recording,
        checkpoint: label,
        sourceSha256: FIXED_PRODUCTION_RULES_SHA256,
        releaseBodySha256: release.bodySha256,
        rulesetBodySha256: ruleset.bodySha256,
        bucketlessBodySha256: bucketless.bodySha256,
        bucketlessAbsent: true,
      }),
    );
    admitted(bucketless.context);
  }
  async function list(label, releaseExpected) {
    const seenTokens = new Set(),
      seenNames = new Set();
    let token,
      ownRelease = false;
    for (let page = 1; page <= 3; page++) {
      const result = await send(
        `r2/rules-delete-list-${label}-${page}`,
        "cleanup",
        undefined,
        token === undefined ? {} : { pageToken: token },
      );
      if (
        result.status !== 200 ||
        Object.keys(result.data).some((key) => !["releases", "nextPageToken"].includes(key))
      )
        throw new Error();
      const rows = result.data.releases ?? [];
      if (!Array.isArray(rows) || rows.length > 100) throw new Error();
      for (const row of rows) {
        releaseShape(row, plan.projectId);
        if (seenNames.has(row.name)) throw new Error();
        seenNames.add(row.name);
        if (row.name === baseline.release.name) {
          if (!releaseExpected || !isDeepStrictEqual(row, baseline.release)) throw new Error();
          ownRelease = true;
        } else if (row.rulesetName === baseline.ruleset.name) throw new Error();
      }
      token = result.data.nextPageToken;
      if (token === undefined || token === "") {
        if (ownRelease !== releaseExpected) throw new Error();
        await options.onProof(
          Object.freeze({
            type: "production-rules-reference-list",
            recording,
            label,
            pages: page,
            releaseCount: seenNames.size,
            bodySha256: result.bodySha256,
            exhausted: true,
          }),
        );
        admitted(result.context);
        return;
      }
      if (!ascii(token, 4096) || seenTokens.has(token)) throw new Error();
      seenTokens.add(token);
    }
    throw new Error();
  }
  async function config(state, context) {
    await options.onConfigChange(
      Object.freeze({
        type: "production-rules-config-change",
        recording,
        state,
        releaseName: baseline.release.name,
        rulesetName: baseline.ruleset.name,
        sourceSha256: FIXED_PRODUCTION_RULES_SHA256,
      }),
    );
    admitted(context);
  }
  function deletion(result) {
    if (result.status !== 200 || Object.keys(result.data).length !== 0) throw new Error();
  }
  const state = Object.freeze({
    async checkpoint(label, recipeToken) {
      if (closed || failed) throw new Error("production Rules are unavailable");
      if (
        busy ||
        label !== CHECKPOINTS[completed] ||
        (label.startsWith("rules-") ? recipeToken === undefined : recipeToken !== undefined)
      )
        throw new Error("invalid production Rules checkpoint");
      busy = true;
      try {
        await snapshot(
          label,
          label.includes("after") || label === "final" ? "cleanup" : "subject",
          recipeToken,
        );
        completed++;
      } catch {
        failed = true;
        throw new Error("production Rules are unavailable");
      } finally {
        busy = false;
      }
    },
    async cleanup() {
      if (closed || failed) throw new Error("production Rules are unavailable");
      if (busy || recording !== 2 || completed !== 6 || !baseline.ownedInStage2 || cleanupAttempted)
        throw new Error("invalid production Rules cleanup");
      busy = true;
      cleanupAttempted = true;
      const context = requestContext("r2/rules-delete", "cleanup");
      try {
        shared(context);
        await snapshot("rules-delete-before", "cleanup");
        await list("before", true);
        shared(context);
        await config("release-delete-intent", context);
        mutationState = "release-delete-intent";
        shared(context);
        deletion(await send("r2/rules-delete-release", "cleanup"));
        absent(await send("r2/rules-delete-release-absence", "cleanup"));
        mutationState = "release-absent";
        await config("release-absent", context);
        await list("after", false);
        rulesetMatches(await send("r2/rules-delete-ruleset-recheck", "cleanup"));
        shared(context);
        await config("ruleset-delete-intent", context);
        mutationState = "ruleset-delete-intent";
        shared(context);
        deletion(await send("r2/rules-delete-ruleset", "cleanup"));
        absent(await send("r2/rules-delete-ruleset-absence", "cleanup"));
        mutationState = "ruleset-absent";
        await config("ruleset-absent", context);
        absent(await send("r2/rules-delete-bucketless-absence", "cleanup"));
        await options.onProof(
          Object.freeze({
            type: "production-rules-cleanup",
            recording,
            releaseAbsent: true,
            rulesetAbsent: true,
            bucketlessAbsent: true,
            sourceSha256: FIXED_PRODUCTION_RULES_SHA256,
          }),
        );
        admitted(context);
        mutationState = "complete";
      } catch {
        failed = true;
        throw new Error("production Rules are unavailable");
      } finally {
        busy = false;
      }
    },
    snapshot: () =>
      Object.freeze({
        recording,
        completedCheckpoints: completed,
        busy,
        failed,
        closed,
        cleanupAttempted,
        mutationState,
        needsRecovery: !["none", "complete"].includes(mutationState),
      }),
    close() {
      closed = true;
    },
  });
  rulesStates.set(state, { plan, recording });
  return state;
}
