import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { readProductionOwnerAdc } from "./owner-adc.mjs";
import { verifyProductionOwnerTokenInfo } from "./owner-tokeninfo.mjs";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";

const STAGES = ["initial", "subject-renewal", "cleanup-renewal"];
const ownerStates = new WeakMap();

/** Identity alone does not prove a usable token; the original provider retains its admission and expiry checks. */
export function originalProductionOwnerAuthorizationProvider(state, recording) {
  const binding = ownerStates.get(state);
  if (!binding || recording !== binding.recording)
    throw new Error("invalid original production owner provider");
  return binding.provider;
}
const OWNER_KINDS = new Set([
  "storage",
  "owner-tokeninfo",
  "project-binding",
  "default-bucket",
  "bucket-config",
  "auth-config",
  "api-key-metadata",
  "api-key-value",
  "rules-release",
  "rules-bucketless",
  "rules-ruleset",
  "rules-list",
  "rules-release-delete",
  "rules-ruleset-delete",
  "auth-admin-lookup",
  "auth-admin-delete",
]);
const EXCHANGE_KEYS = new Set(["access_token", "token_type", "expires_in", "scope", "id_token"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const ascii = (value, max) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= max &&
  /^[\x21-\x7e]+$/.test(value);

function record(value, keys) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const copy = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !keys.includes(key) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error();
    copy[key] = descriptor.value;
  }
  return copy;
}

async function jsonResponse(response) {
  if (response.status !== 200) throw new Error();
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > 32768) throw new Error();
  const text = bytes.toString("utf8");
  if (!Buffer.from(text).equals(bytes) || parseCaptureJsonSpans(text).type !== "object")
    throw new Error();
  return { data: JSON.parse(text), bodySha256: sha256(bytes) };
}

/** Exchange only the three declared pairs. ADC and tokens stay in memory; the runner pins the prior principal and real control producer. */
export function createProductionOwnerState(input) {
  let options, principal, pinned;
  try {
    options = record(input, [
      "recording",
      "adcInput",
      "principal",
      "controls",
      "verifyAdmission",
      "onProof",
      "onSecret",
    ]);
    options.controls = record(options.controls, ["send", "snapshot"]);
    if (
      Object.keys(options).length !== 7 ||
      ![1, 2].includes(options.recording) ||
      typeof options.controls?.send !== "function" ||
      typeof options.verifyAdmission !== "function" ||
      typeof options.onProof !== "function" ||
      typeof options.onSecret !== "function"
    )
      throw new Error();
    if (
      [options.controls.send, options.verifyAdmission, options.onProof, options.onSecret].some(
        (fn) => types.isProxy(fn),
      ) ||
      Object.getPrototypeOf(options.verifyAdmission) !== Function.prototype ||
      Object.getPrototypeOf(options.onSecret) !== Function.prototype
    )
      throw new Error();
    principal = record(options.principal, ["subject", "clientId", "requiredScopes"]);
    if (
      Object.keys(principal).length !== 3 ||
      !ascii(principal.subject, 512) ||
      !ascii(principal.clientId, 512)
    )
      throw new Error();
    const scopes = principal.requiredScopes;
    if (
      types.isProxy(scopes) ||
      !Array.isArray(scopes) ||
      Object.getPrototypeOf(scopes) !== Array.prototype ||
      scopes.length < 1 ||
      scopes.length > 32 ||
      Reflect.ownKeys(scopes).length !== scopes.length + 1
    )
      throw new Error();
    principal.requiredScopes = Array.from({ length: scopes.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(scopes, String(index));
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !ascii(descriptor.value, 1024)
      )
        throw new Error();
      return descriptor.value;
    });
    if (new Set(principal.requiredScopes).size !== principal.requiredScopes.length)
      throw new Error();
    Object.freeze(principal.requiredScopes);
    Object.freeze(principal);
    pinned = record(options.adcInput, [
      "path",
      "expectedSha256",
      "expectedClientId",
      "expectedQuotaProjectId",
    ]);
    if (Object.keys(pinned).length !== 4 || pinned.expectedClientId !== principal.clientId)
      throw new Error();
    Object.freeze(pinned);
  } catch {
    throw new Error("invalid production owner configuration");
  }
  const recording = options.recording;
  let adc = null,
    pending = null,
    verified = null,
    completed = 0,
    busy = false,
    failed = false,
    closed = false,
    lastTime = -Infinity;
  function now() {
    const time = performance.now();
    if (!Number.isFinite(time) || time < 0 || time < lastTime) {
      failed = true;
      throw new Error();
    }
    lastTime = time;
    return time;
  }
  function context(stage, kind) {
    const id = `r${recording}/${stage}-${kind}`;
    return Object.freeze({
      recording,
      phase: stage === "cleanup-renewal" ? "cleanup" : "subject",
      kind,
      operationId: `r${recording}/control/${sha256(id)}`,
    });
  }
  function admitted(requestContext) {
    try {
      if (closed || failed || options.verifyAdmission(requestContext) !== true || closed || failed)
        throw new Error();
    } catch {
      failed = true;
      dispose();
      throw new Error();
    }
  }
  function registerSecret(value) {
    if (closed || failed) throw new Error();
    const result = options.onSecret(value);
    if (types.isPromise(result)) void Promise.prototype.then.call(result, undefined, () => {});
    if (result !== undefined || closed || failed) throw new Error();
  }
  function dispose() {
    adc?.dispose();
    adc = null;
    pending = null;
    verified = null;
  }
  const state = Object.freeze({
    async exchangeAndProve(stage, recipeToken) {
      if (closed || failed) throw new Error("production owner is unavailable");
      if (
        busy ||
        stage !== STAGES[completed] ||
        (stage === "initial" ? recipeToken !== undefined : recipeToken === undefined)
      )
        throw new Error("invalid production owner stage");
      busy = true;
      verified = null;
      try {
        const exchangeContext = context(stage, "owner-exchange");
        admitted(exchangeContext);
        if (stage === "initial") adc = readProductionOwnerAdc(pinned);
        const startedAt = now();
        const body = adc.exchangeBody();
        let exchange;
        try {
          if (stage === "initial") {
            const form = new URLSearchParams(body.toString());
            registerSecret(form.get("client_secret"));
            registerSecret(form.get("refresh_token"));
          }
          admitted(exchangeContext);
          exchange = await jsonResponse(
            await options.controls.send(`r${recording}/${stage}-owner-exchange`, {
              recipeToken,
              body,
            }),
          );
        } finally {
          body.fill(0);
        }
        if (closed || failed) throw new Error();
        const data = exchange.data;
        if (
          Object.keys(data).some((key) => !EXCHANGE_KEYS.has(key)) ||
          !ascii(data.access_token, 8192) ||
          data.token_type !== "Bearer" ||
          !Number.isSafeInteger(data.expires_in) ||
          data.expires_in <= 60 ||
          data.expires_in > 3600 ||
          (Object.hasOwn(data, "scope") &&
            (typeof data.scope !== "string" ||
              data.scope.length > 8192 ||
              !/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(data.scope))) ||
          (Object.hasOwn(data, "id_token") && !ascii(data.id_token, 8192))
        )
          throw new Error();
        const deadline = startedAt + data.expires_in * 1000;
        registerSecret(data.access_token);
        if (Object.hasOwn(data, "id_token")) registerSecret(data.id_token);
        if (deadline - now() <= 60000) throw new Error();
        const tokeninfoContext = context(stage, "owner-tokeninfo");
        pending = { token: data.access_token, deadline, context: tokeninfoContext };
        admitted(tokeninfoContext);
        const requestStartedAtMs = now();
        const tokeninfo = await jsonResponse(
          await options.controls.send(`r${recording}/${stage}-owner-tokeninfo`, {
            recipeToken,
            body: Buffer.alloc(0),
          }),
        );
        const receivedAtMs = now();
        const proof = verifyProductionOwnerTokenInfo({
          principal,
          data: tokeninfo.data,
          requestStartedAtMs,
          receivedAtMs,
        });
        const usableUntil = Math.min(deadline, proof.deadlineMonotonicMs);
        if (usableUntil - receivedAtMs <= 60000) throw new Error();
        await options.onProof(
          Object.freeze({
            type: "production-owner",
            recording,
            stage,
            adcSha256: adc.receipt.sha256,
            adcType: adc.receipt.type,
            clientId: adc.receipt.clientId,
            principalSha256: proof.principalSha256,
            scopeSha256: proof.scopeSha256,
            accessTokenSha256: sha256(pending.token),
            accessTokenByteLength: Buffer.byteLength(pending.token),
            exchangeBodySha256: exchange.bodySha256,
            tokeninfoBodySha256: tokeninfo.bodySha256,
            deadlineMonotonicMs: usableUntil,
          }),
        );
        admitted(tokeninfoContext);
        if (usableUntil - now() <= 60000) throw new Error();
        verified = { token: pending.token, deadline: usableUntil };
        pending = null;
        completed++;
      } catch {
        failed = true;
        dispose();
        throw new Error("production owner is unavailable");
      } finally {
        busy = false;
      }
    },
    ownerAuthorization(suppliedInput) {
      try {
        const supplied = record(suppliedInput, ["recording", "kind", "phase", "operationId"]);
        if (
          Object.keys(supplied).length !== 4 ||
          supplied.recording !== recording ||
          !["subject", "cleanup"].includes(supplied.phase) ||
          !OWNER_KINDS.has(supplied.kind) ||
          typeof supplied.operationId !== "string" ||
          !new RegExp(`^r${recording}/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)/[a-f0-9]{64}$`).test(
            supplied.operationId,
          )
        )
          throw new Error();
        const owner = pending ?? verified;
        if (
          !owner ||
          (pending &&
            (supplied.kind !== "owner-tokeninfo" ||
              supplied.operationId !== pending.context.operationId ||
              supplied.phase !== pending.context.phase))
        )
          throw new Error();
        admitted(supplied);
        if (owner.deadline - now() <= 60000) {
          failed = true;
          throw new Error();
        }
        return `Bearer ${owner.token}`;
      } catch {
        if (failed || closed) dispose();
        throw new Error("production owner is unavailable");
      }
    },
    snapshot: () =>
      Object.freeze({
        recording,
        completedStages: completed,
        busy,
        failed,
        closed,
        hasVerifiedOwner: verified !== null && !failed && !closed,
      }),
    close() {
      closed = true;
      dispose();
    },
  });
  ownerStates.set(state, { recording, provider: state.ownerAuthorization });
  return state;
}
