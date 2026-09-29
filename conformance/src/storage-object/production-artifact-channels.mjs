import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { buildCorpus } from "./corpus.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import {
  copyProductionCaptureArray,
  copyProductionCaptureRecord,
} from "./production-capture-input.mjs";
import { productionArtifactProfileUsesPlan } from "./production-artifact-policy.mjs";
import {
  createProductionArtifactWriter,
  isProductionArtifactReceipt,
} from "./production-artifact-writer.mjs";
import { failStopProductionStandalone } from "./production-standalone-fail-stop.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const owners = new WeakMap(),
  callbacks = new WeakMap();
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const controlId = (recording, label) => `r${recording}/control/${hash(label)}`;
function canonicalPlan(value) {
  const rows = copyProductionCaptureArray(
    Object.getOwnPropertyDescriptor(value, "recordings").value,
    2,
  );
  return buildProductionStage3DraftPlan({
    projectId: Object.getOwnPropertyDescriptor(value, "projectId").value,
    bucket: Object.getOwnPropertyDescriptor(value, "bucket").value,
    runIds: rows.map((row) => Object.getOwnPropertyDescriptor(row, "runId").value),
  });
}
function operationMatches(value, recording, recipeIndex = null) {
  return (
    typeof value === "string" &&
    new RegExp(
      `^r${recording}/${recipeIndex === null ? "control" : `p${recipeIndex + 1}`}/[a-f0-9]{64}$`,
    ).test(value)
  );
}
/** These identities prove only which source-owned persistence callback was returned. */
export function isProductionArtifactChannelCallback(callback, channels, role, recording, recipeId) {
  const binding = callbacks.get(callback);
  return (
    owners.has(channels) &&
    binding?.channels === channels &&
    binding.role === role &&
    binding.recording === recording &&
    binding.recipeId === recipeId
  );
}
export function productionArtifactChannelsUseContext(channels, supplied) {
  const binding = owners.get(channels);
  if (!binding) return false;
  try {
    const input = copyProductionCaptureRecord(supplied, [
      "directory",
      "profile",
      "boundary",
      "plan",
    ]);
    return (
      Object.keys(input).length === 4 &&
      input.directory === binding.directory &&
      input.profile === binding.profile &&
      input.boundary === binding.boundary &&
      productionArtifactProfileUsesPlan(binding.profile, input.plan)
    );
  } catch {
    return false;
  }
}

/** The factory constructs its writer internally and accepts no injected writer, callback or clock. */
export function createProductionArtifactChannels(supplied) {
  let input, plan, writer;
  try {
    input = copyProductionCaptureRecord(supplied, ["directory", "profile", "boundary", "plan"]);
    if (
      Object.keys(input).length !== 4 ||
      !productionArtifactProfileUsesPlan(input.profile, input.plan)
    )
      throw new Error();
    plan = canonicalPlan(input.plan);
    writer = createProductionArtifactWriter({
      directory: input.directory,
      profile: input.profile,
      boundary: input.boundary,
    });
  } catch {
    throw new Error("invalid production artifact channels");
  }
  const recipeIds = [
    ...buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes,
    ...buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[0].runId,
    }).recipes,
  ].map((row) => row.id);
  let currentRecording = 0,
    total = 0,
    wireSequence = 0,
    active = null,
    closed = false;
  const counts = [
      { subject: 0, cleanup: 0 },
      { subject: 0, cleanup: 0 },
    ],
    finished = [0, 0],
    reservations = new Map(),
    recordingChannels = new Map(),
    recipeChannels = new Map();
  const channels = {};
  const stop = (recording) =>
    failStopProductionStandalone(input.boundary, {
      recording: recording || currentRecording || 1,
      operationId: controlId(recording || currentRecording || 1, "artifact-channel-failure"),
      reason: "PERSISTENCE_UNCERTAIN",
      providerKind: "runtime",
    });
  function save(recording, kind, value, operationId = controlId(recording, kind)) {
    if (closed || recording !== currentRecording) throw new Error();
    const receipt = writer.write({ recording, kind, value, operationId });
    if (!isProductionArtifactReceipt(receipt, { writer, recording, kind, operationId }))
      throw new Error();
    return receipt;
  }
  function callback(role, recording, recipeId, action) {
    const fn = (value) => {
      try {
        if (closed) throw new Error();
        return action(value);
      } catch {
        return stop(recording);
      }
    };
    callbacks.set(fn, { channels, role, recording, recipeId });
    return fn;
  }
  channels.counter = Object.freeze({
    onStart: callback("counter-start", null, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
          "maxRequests",
          "recordings",
          "estimatedUsd",
          "maxUsdReservation",
          "recording",
          "runId",
          "prefix",
          "taskMaxRequests",
          "subjectCapRequests",
          "cleanupReserveRequests",
        ]),
        recording = currentRecording + 1;
      if (recording > 2 || active || (recording === 2 && finished[0] !== recipeIds.length))
        throw new Error();
      const item = plan.recordings[recording - 1],
        expected = {
          maxRequests: item.maxRequests,
          recordings: 1,
          estimatedUsd: plan.estimatedUsd,
          maxUsdReservation: plan.maxUsdReservation,
          recording,
          runId: item.runId,
          prefix: item.prefix,
          taskMaxRequests: plan.maxRequests,
          subjectCapRequests: item.subjectCapRequests,
          cleanupReserveRequests: item.cleanupReserveRequests,
        };
      if (!isDeepStrictEqual(row, expected)) throw new Error();
      // This artifact does not replace the runtime's actual durable shared started row.
      currentRecording = recording;
      return save(recording, "ledger", row);
    }),
    onReserve: callback("counter-reserve", null, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
        "sequence",
        "operationId",
        "phase",
        "recording",
        "recipeId",
        "semanticOperationId",
      ]);
      if (
        row.recording !== currentRecording ||
        ![1, 2].includes(currentRecording) ||
        row.sequence !== total + 1 ||
        row.sequence > plan.maxRequests ||
        !["subject", "cleanup"].includes(row.phase)
      )
        throw new Error();
      const item = plan.recordings[currentRecording - 1],
        limit = row.phase === "subject" ? item.subjectCapRequests : item.cleanupReserveRequests;
      if (
        counts[currentRecording - 1][row.phase] >= limit ||
        row.recipeId !== (active?.recipeId ?? null)
      )
        throw new Error();
      if (
        !operationMatches(row.operationId, currentRecording) &&
        !(active && operationMatches(row.operationId, currentRecording, active.index))
      )
        throw new Error();
      if (
        active &&
        operationMatches(row.operationId, currentRecording, active.index) &&
        !Object.hasOwn(row, "semanticOperationId")
      )
        throw new Error();
      if (Object.hasOwn(row, "semanticOperationId")) {
        if (
          !active ||
          typeof row.semanticOperationId !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(row.semanticOperationId) ||
          row.operationId !==
            `r${currentRecording}/p${active.index + 1}/${hash(row.semanticOperationId)}`
        )
          throw new Error();
      }
      const receipt = save(currentRecording, "intent", row, row.operationId);
      total++;
      counts[currentRecording - 1][row.phase]++;
      reservations.set(row.operationId, { ...row });
      return receipt;
    }),
    onBegin: callback("recipe-begin", null, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
          "recording",
          "recipeId",
          "prefix",
          "sequence",
        ]),
        index = finished[currentRecording - 1];
      if (
        active ||
        row.recording !== currentRecording ||
        row.recipeId !== recipeIds[index] ||
        row.prefix !== plan.recordings[currentRecording - 1]?.prefix ||
        row.sequence !== total
      )
        throw new Error();
      const receipt = save(currentRecording, "journal", row);
      active = {
        recipeId: row.recipeId,
        index,
        startTotal: total,
        startCounts: { ...counts[currentRecording - 1] },
      };
      return receipt;
    }),
    onFinish: callback("recipe-finish", null, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
        "recording",
        "recipeId",
        "prefix",
        "firstSequence",
        "lastSequence",
        "requests",
        "subject",
        "cleanup",
      ]);
      if (!active) throw new Error();
      const current = counts[currentRecording - 1],
        expected = {
          recording: currentRecording,
          recipeId: active.recipeId,
          prefix: plan.recordings[currentRecording - 1].prefix,
          firstSequence: active.startTotal + 1,
          lastSequence: total,
          requests: total - active.startTotal,
          subject: current.subject - active.startCounts.subject,
          cleanup: current.cleanup - active.startCounts.cleanup,
        };
      if (!isDeepStrictEqual(row, expected)) throw new Error();
      const receipt = save(currentRecording, "journal", row);
      finished[currentRecording - 1]++;
      active = null;
      return receipt;
    }),
  });
  channels.wire = Object.freeze({
    onReserve: callback("wire-reserve", null, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
          "sequence",
          "operationId",
          "requestReservedBytes",
          "responseReservedBytes",
        ]),
        reservation = reservations.get(row.operationId);
      if (
        Object.keys(row).length !== 4 ||
        !reservation ||
        reservation.sequence !== total ||
        row.sequence !== total ||
        row.sequence !== wireSequence + 1 ||
        !Number.isSafeInteger(row.requestReservedBytes) ||
        row.requestReservedBytes <= 0 ||
        row.responseReservedBytes !== plan.maxPerResponseWireBytes + plan.responseReadUnitBytes
      )
        throw new Error();
      const receipt = save(
        currentRecording,
        "intent",
        { ...row, recording: currentRecording, phase: reservation.phase },
        row.operationId,
      );
      wireSequence = row.sequence;
      return receipt;
    }),
  });
  const proofKeys = {
    "owner-proof": [
      "type",
      "recording",
      "stage",
      "adcSha256",
      "adcType",
      "clientId",
      "principalSha256",
      "scopeSha256",
      "accessTokenSha256",
      "accessTokenByteLength",
      "exchangeBodySha256",
      "tokeninfoBodySha256",
      "deadlineMonotonicMs",
    ],
    "auth-proof": [
      "type",
      "recording",
      "accountRef",
      "stage",
      "ownedUidSha256",
      "emailSha256",
      "tokenSha256",
      "tokenByteLength",
      "responseBodySha256",
      "deadlineMonotonicMs",
      "absent",
    ],
    "rules-proof": [
      "type",
      "recording",
      "checkpoint",
      "sourceSha256",
      "releaseBodySha256",
      "rulesetBodySha256",
      "bucketlessBodySha256",
      "bucketlessAbsent",
      "label",
      "pages",
      "releaseCount",
      "bodySha256",
      "exhausted",
      "releaseAbsent",
      "rulesetAbsent",
    ],
    "configuration-change": [
      "type",
      "recording",
      "state",
      "releaseName",
      "rulesetName",
      "sourceSha256",
    ],
  };
  const proofTypes = {
    "owner-proof": ["production-owner"],
    "auth-proof": ["production-auth-account", "production-auth-cleanup"],
    "rules-proof": [
      "production-rules-checkpoint",
      "production-rules-reference-list",
      "production-rules-cleanup",
    ],
    "configuration-change": ["production-rules-config-change"],
  };
  channels.forRecording = (recording) => {
    if (![1, 2].includes(recording))
      throw new Error("invalid production artifact channel recording");
    if (recordingChannels.has(recording)) return recordingChannels.get(recording);
    const result = {};
    for (const [name, role] of [
      ["onOwnerProof", "owner-proof"],
      ["onAuthProof", "auth-proof"],
      ["onRulesProof", "rules-proof"],
      ["onConfigurationChange", "configuration-change"],
    ])
      result[name] = callback(role, recording, null, (value) => {
        const row = copyProductionCaptureRecord(value, proofKeys[role]);
        if (
          row.recording !== recording ||
          !proofTypes[role].includes(row.type) ||
          ((role === "configuration-change" || row.type === "production-rules-cleanup") &&
            recording !== 2)
        )
          throw new Error();
        return save(recording, role, row);
      });
    result.onAuthJournal = callback("auth-journal", recording, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
        "type",
        "operationId",
        "accountRef",
        "accountMutation",
        "ownedUid",
      ]);
      if (
        row.type !== "production-auth-ownership" ||
        !["create", "receipt", "delete"].includes(row.accountMutation) ||
        !operationMatches(row.operationId, recording)
      )
        throw new Error();
      return save(recording, "journal", { ...row, recording }, row.operationId);
    });
    result.onControlProof = callback("control-proof", recording, null, (value) => {
      const row = copyProductionCaptureRecord(value, [
          "type",
          "slotId",
          "recording",
          "phase",
          "recipeId",
          "placement",
          "operationId",
          "sequence",
          "status",
          "bodyByteLength",
          "bodySha256",
        ]),
        reservation = reservations.get(row.operationId);
      if (
        row.type !== "production-control" ||
        row.recording !== recording ||
        !operationMatches(row.operationId, recording) ||
        !reservation ||
        reservation.sequence !== row.sequence ||
        reservation.phase !== row.phase
      )
        throw new Error();
      return save(recording, "control-proof", row, row.operationId);
    });
    for (const [name, kind] of [
      ["onManifest", "manifest"],
      ["onExport", "export"],
    ])
      result[name] = callback(kind, recording, null, (value) => save(recording, kind, value));
    result.onError = callback("error", recording, null, (value) => {
      const row = copyProductionCaptureRecord(value, ["recording", "state", "reason"]);
      if (
        Object.keys(row).length !== 3 ||
        row.recording !== recording ||
        !["BLOCKED", "NEEDS_RECOVERY"].includes(row.state) ||
        typeof row.reason !== "string" ||
        row.reason.length > 128
      )
        throw new Error();
      save(recording, "error", row);
      return failStopProductionStandalone(input.boundary, {
        recording,
        operationId: controlId(recording, "artifact-error-stop"),
        reason: "TERMINAL_UNCERTAIN",
        providerKind: "runtime",
      });
    });

    const frozen = Object.freeze(result);
    recordingChannels.set(recording, frozen);
    return frozen;
  };
  channels.forRecipe = (recording, recipeId) => {
    const index = recipeIds.indexOf(recipeId);
    if (![1, 2].includes(recording) || index < 0)
      throw new Error("invalid production artifact channel recipe");
    const key = `${recording}:${recipeId}`;
    if (recipeChannels.has(key)) return recipeChannels.get(key);
    const requireActive = () => {
      if (currentRecording !== recording || active?.recipeId !== recipeId) throw new Error();
    };
    const result = Object.freeze({
      onJournal: callback("storage-journal", recording, recipeId, (value) => {
        requireActive();
        const row = copyProductionCaptureRecord(value, [
          "type",
          "bucket",
          "prefix",
          "recording",
          "recipeId",
          "sequence",
          "namespaceEmpty",
          "operationId",
          "name",
          "method",
          "continuationOf",
          "sessionUriSha256",
          "credentialProof",
          "ifGenerationMatch",
        ]);
        if (row.type === "recipe-terminal") {
          if (
            row.recording !== recording ||
            row.recipeId !== recipeId ||
            row.bucket !== plan.bucket ||
            row.prefix !== plan.recordings[recording - 1].prefix ||
            row.sequence !== total ||
            row.namespaceEmpty !== true
          )
            throw new Error();
          return save(
            recording,
            "journal",
            row,
            `r${recording}/p${index + 1}/${hash("terminal-journal")}`,
          );
        }
        if (
          typeof row.operationId !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(row.operationId)
        )
          throw new Error();
        const operationId = `r${recording}/p${index + 1}/${hash(row.operationId)}`,
          reservation = reservations.get(operationId);
        if (
          !reservation ||
          reservation.sequence !== total ||
          reservation.semanticOperationId !== row.operationId ||
          reservation.recipeId !== recipeId
        )
          throw new Error();
        if (
          (Object.hasOwn(row, "bucket") && row.bucket !== plan.bucket) ||
          (Object.hasOwn(row, "prefix") && row.prefix !== plan.recordings[recording - 1].prefix)
        )
          throw new Error();
        return save(recording, "journal", { ...row, recording, recipeId }, operationId);
      }),
      onCapture: callback("diagnostic-capture", recording, recipeId, (value) => {
        requireActive();
        const row = copyProductionCaptureRecord(value, [
            "operationId",
            "stepId",
            "dialect",
            "status",
            "headers",
            "bodyBase64",
            "bodyByteLength",
            "bodySha256",
          ]),
          stepId = row.operationId ?? row.stepId;
        if (Object.hasOwn(row, "operationId") === Object.hasOwn(row, "stepId")) throw new Error();
        if (
          typeof stepId !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(stepId) ||
          !Number.isSafeInteger(row.status) ||
          row.status < 100 ||
          row.status > 599
        )
          throw new Error();
        let bodyByteLength, bodySha256;
        if (Object.hasOwn(row, "bodyBase64")) {
          if (
            Object.hasOwn(row, "bodyByteLength") ||
            Object.hasOwn(row, "bodySha256") ||
            typeof row.bodyBase64 !== "string" ||
            row.bodyBase64.length > Math.ceil(MAX_RESPONSE_BODY_BYTES / 3) * 4
          )
            throw new Error();
          const body = Buffer.from(row.bodyBase64, "base64");
          if (body.length > MAX_RESPONSE_BODY_BYTES || body.toString("base64") !== row.bodyBase64)
            throw new Error();
          bodyByteLength = body.length;
          bodySha256 = hash(body);
        } else {
          bodyByteLength = row.bodyByteLength;
          bodySha256 = row.bodySha256;
          if (
            !Number.isSafeInteger(bodyByteLength) ||
            bodyByteLength < 0 ||
            bodyByteLength > MAX_RESPONSE_BODY_BYTES ||
            typeof bodySha256 !== "string" ||
            !/^[a-f0-9]{64}$/.test(bodySha256)
          )
            throw new Error();
        }
        // A diagnostic step may be followed by later reads, so it claims no HTTP sequence or operation.
        return save(
          recording,
          "journal",
          {
            type: "receipt",
            recording,
            recipeId,
            stepId,
            status: row.status,
            bodyByteLength,
            bodySha256,
          },
          `r${recording}/p${index + 1}/${hash("diagnostic:" + stepId)}`,
        );
      }),
    });
    recipeChannels.set(key, result);
    return result;
  };
  channels.close = () => {
    closed = true;
    writer.close();
  };
  owners.set(channels, {
    directory: input.directory,
    profile: input.profile,
    boundary: input.boundary,
    plan,
  });
  return Object.freeze(channels);
}
