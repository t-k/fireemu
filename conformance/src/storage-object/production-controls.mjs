import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { copyCanonicalProductionStage3Plan } from "./production-context.mjs";
import { productionStage3CounterUsesArtifactContext } from "./request-counter.mjs";
import { productionWireUsesArtifactContext } from "./production-wire-transport.mjs";
const controlBindings = new WeakMap();
import { createHash } from "node:crypto";
import { isDeepStrictEqual, types } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const AUTH_RECIPES = [
  "storage-object/errors/authorization",
  "storage-object/auth/firebase-id-token",
];
const RULES_KINDS = ["rules-release", "rules-ruleset", "rules-bucketless"];

function canonicalPlan(input) {
  const plan = copyCanonicalProductionStage3Plan(input);
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
    throw new Error("invalid production control plan");
  return plan;
}

/** Fixed slots bound every helper to one recording, phase and placement; unused slots do not authorize retries. */
export function buildProductionControlInventory(input) {
  const plan = canonicalPlan(input),
    rows = [];
  for (const recording of [1, 2]) {
    const add = (
      suffix,
      kind,
      phase,
      recipeId = null,
      placement = recipeId === null ? "recording-final" : "recipe",
    ) =>
      rows.push(
        Object.freeze({
          id: `r${recording}/${suffix}`,
          recording,
          kind,
          phase,
          recipeId,
          placement,
        }),
      );
    for (const [label, phase, recipeId, placement] of [
      ["initial", "subject", null, "recording-initial"],
      ["subject-renewal", "subject", AUTH_RECIPES[0], "recipe"],
      ["cleanup-renewal", "cleanup", AUTH_RECIPES[1], "recipe"],
    ])
      for (const kind of ["owner-exchange", "owner-tokeninfo"])
        add(`${label}-${kind}`, kind, phase, recipeId, placement);
    for (const kind of [
      "project-binding",
      "default-bucket",
      "bucket-config",
      "auth-config",
      "api-key-metadata",
      "api-key-value",
    ])
      add(`initial-${kind}`, kind, "subject", null, "recording-initial");
    for (const kind of RULES_KINDS)
      add(`initial-${kind}`, kind, "subject", null, "recording-initial");
    for (const [index, recipeId] of AUTH_RECIPES.entries()) {
      for (const kind of RULES_KINDS) {
        add(`rules-before-${index + 1}-${kind}`, kind, "subject", recipeId);
        add(`rules-after-${index + 1}-${kind}`, kind, "cleanup", recipeId);
      }
      for (const account of ["valid", "competitor"]) {
        for (const [stage, kind] of [
          ["email-absence", "auth-admin-lookup"],
          ["signup", "auth-signup"],
          ["client-lookup", "auth-token-lookup"],
          ["admin-lookup", "auth-admin-lookup"],
        ])
          add(`auth${index + 1}-${account}-setup-${stage}`, kind, "subject", recipeId);
        for (const [stage, kind] of [
          ["refresh", "auth-refresh"],
          ["client-lookup", "auth-token-lookup"],
          ["admin-lookup", "auth-admin-lookup"],
        ])
          add(`auth${index + 1}-${account}-refresh-${stage}`, kind, "subject", recipeId);
        for (const [stage, kind] of [
          ["admin-before", "auth-admin-lookup"],
          ["delete", "auth-admin-delete"],
          ["uid-absence", "auth-admin-lookup"],
          ["email-absence", "auth-admin-lookup"],
        ])
          add(`auth${index + 1}-${account}-cleanup-${stage}`, kind, "cleanup", recipeId);
      }
    }
    for (const kind of [
      "bucket-config",
      "auth-config",
      "api-key-metadata",
      "default-bucket",
      ...RULES_KINDS,
    ])
      add(`final-${kind}`, kind, "cleanup");
    if (recording === 2) {
      for (const kind of RULES_KINDS) add(`rules-delete-before-${kind}`, kind, "cleanup");
      for (const phase of ["before", "after"])
        for (let page = 1; page <= 3; page++)
          add(`rules-delete-list-${phase}-${page}`, "rules-list", "cleanup");
      for (const [suffix, kind] of [
        ["release", "rules-release-delete"],
        ["release-absence", "rules-release"],
        ["ruleset-recheck", "rules-ruleset"],
        ["ruleset", "rules-ruleset-delete"],
        ["ruleset-absence", "rules-ruleset"],
        ["bucketless-absence", "rules-bucketless"],
      ])
        add(`rules-delete-${suffix}`, kind, "cleanup");
    }
    const subset = rows.filter((row) => row.recording === recording);
    if (
      subset.filter((row) => row.phase === "subject").length !== 47 ||
      subset.filter((row) => row.phase === "cleanup").length !== (recording === 1 ? 31 : 46)
    )
      throw new Error("production control inventory differs");
  }
  if (
    plan.recordings.length !== 2 ||
    rows.length !== 171 ||
    new Set(rows.map((row) => row.id)).size !== 171
  )
    throw new Error("production control inventory differs");
  return Object.freeze(rows);
}

function record(value, keys) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error("invalid production control input");
  const result = {};
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !keys.includes(key) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error("invalid production control input");
    result[key] = descriptor.value;
  }
  return result;
}

/** Reserve and dispatch each declared control once through the shared counter and production wire. */
export function createProductionControlDispatcher(input) {
  const options = record(input, ["plan", "counter", "wire", "onProof"]);
  const rows = buildProductionControlInventory(options.plan),
    slots = new Map(rows.map((row) => [row.id, row]));
  const { counter, wire, onProof } = options;
  if (
    !counter ||
    typeof counter.snapshot !== "function" ||
    typeof counter.send !== "function" ||
    !wire ||
    typeof wire.fetchControl !== "function" ||
    typeof onProof !== "function"
  )
    throw new Error("invalid production control dispatcher");
  const attempted = new Set();
  let busy = false,
    failed = false;
  const dispatcher = Object.freeze({
    async send(id, suppliedInput = {}) {
      if (failed) throw new Error("production control dispatcher is halted");
      if (busy) throw new Error("concurrent production control is forbidden");
      const slot = slots.get(id),
        supplied = record(suppliedInput, ["recipeToken", "parameters", "body"]),
        state = counter.snapshot();
      if (
        !slot ||
        state.mode !== slot.phase ||
        state.recording !== slot.recording ||
        (state.activeRecipeId ?? null) !== slot.recipeId ||
        (slot.placement === "recording-final" &&
          state.completedRecipes?.[slot.recording - 1] !== 26)
      )
        throw new Error("production control context differs");
      if (slot.recipeId !== null && supplied.recipeToken === undefined)
        throw new Error("invalid recipe capability");
      if (slot.recipeId === null && supplied.recipeToken !== undefined)
        throw new Error("invalid recipe capability");
      if (attempted.has(id)) throw new Error("production control was already attempted");
      attempted.add(id);
      busy = true;
      const operationId = `r${slot.recording}/control/${createHash("sha256").update(id).digest("hex")}`;
      try {
        let sequence;
        const response = await counter.send(
          operationId,
          () => {
            sequence = counter.snapshot().total;
            return wire.fetchControl(slot.recording, slot.kind, supplied.parameters ?? {}, {
              operationId,
              accountingPhase: slot.phase,
              body: supplied.body,
            });
          },
          supplied.recipeToken,
        );
        const body = Buffer.from(await response.arrayBuffer());
        if (
          !Number.isSafeInteger(response.status) ||
          response.status < 100 ||
          response.status > 599 ||
          body.length > MAX_RESPONSE_BODY_BYTES
        )
          throw new Error();
        await onProof(
          Object.freeze({
            type: "production-control",
            slotId: id,
            recording: slot.recording,
            phase: slot.phase,
            recipeId: slot.recipeId,
            placement: slot.placement,
            operationId,
            sequence,
            status: response.status,
            bodyByteLength: body.length,
            bodySha256: createHash("sha256").update(body).digest("hex"),
          }),
        );
        return response;
      } catch {
        failed = true;
        throw new Error("production control failed");
      } finally {
        busy = false;
      }
    },
    snapshot: () => Object.freeze({ attempted: attempted.size, busy, failed }),
  });
  controlBindings.set(dispatcher, {
    plan: copyCanonicalProductionStage3Plan(options.plan),
    counter,
    wire,
    healthy: () => !failed && !busy,
  });
  return dispatcher;
}

/** Shape dispatchers remain prototypes; only matching original counter and wire supply local lineage. */
export function productionControlDispatcherUsesArtifactContext(dispatcher, supplied) {
  try {
    const source = controlBindings.get(dispatcher),
      input = copyProductionCaptureRecord(supplied, ["profile", "plan", "counter", "wire"]);
    return (
      Object.keys(input).length === 4 &&
      !!source &&
      source.healthy() &&
      source.counter === input.counter &&
      source.wire === input.wire &&
      isDeepStrictEqual(source.plan, copyCanonicalProductionStage3Plan(input.plan)) &&
      productionStage3CounterUsesArtifactContext(source.counter, {
        profile: input.profile,
        plan: source.plan,
      }) &&
      productionWireUsesArtifactContext(source.wire, { profile: input.profile, plan: source.plan })
    );
  } catch {
    return false;
  }
}
