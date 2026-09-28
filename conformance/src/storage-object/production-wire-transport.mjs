import { isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { isDeepStrictEqual, types } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { buildSymbolicStorageAuthPlan } from "./auth-plan.mjs";
import { validateProductionCredentialDeclaration } from "./production-credentials.mjs";
import { createObjectMutationPacer } from "./production-pacing.mjs";
import {
  resolveProductionControlRoute,
  resolveProductionStorageRoute,
} from "./production-routes.mjs";
import { serializeProductionHttpRequest } from "./production-serialization.mjs";
import { productionTlsOptions } from "./production-tls.mjs";
import { createProductionWireAttempt } from "./production-wire-capture.mjs";
import { createWireTransportCore } from "./wire-transport-core.mjs";
import { buildCorpus } from "./corpus.mjs";
import {
  resolveProductionSessionRoute,
  validateProductionSessionUri,
} from "./production-session.mjs";

const CONFIG_KEYS = [
  "plan",
  "resources",
  "captureDirectory",
  "onByteReserve",
  "verifyAdmission",
  "ownerAuthorization",
  "accountAuthorization",
];
const INIT_KEYS = new Set([
  "method",
  "headers",
  "body",
  "redirect",
  "operationId",
  "accountingPhase",
]);

function record(value) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const copy = {};
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || !descriptor.enumerable || !Object.hasOwn(descriptor, "value"))
      throw new Error();
    Object.defineProperty(copy, key, {
      value: descriptor.value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return copy;
}

function planCopy(value, depth = 0) {
  if (depth > 16 || types.isProxy(value)) throw new Error();
  if (value === null || ["string", "boolean", "number"].includes(typeof value)) return value;
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
      return planCopy(descriptor.value, depth + 1);
    });
  }
  const copy = record(value);
  for (const key of Object.keys(copy)) copy[key] = planCopy(copy[key], depth + 1);
  return copy;
}

/** Closed routes, TLS, pacing and sanitized captures share one task meter. The runner must supply its live admission and credential closures. */
export function createProductionWireTransport(input) {
  let config, plan, boundaries, accountRefs, expectedEmails, sessionPrograms;
  try {
    config = record(input);
    if (
      Reflect.ownKeys(config).length !== CONFIG_KEYS.length ||
      CONFIG_KEYS.some((key) => !Object.hasOwn(config, key))
    )
      throw new Error();
    plan = planCopy(config.plan);
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
    const resources = record(config.resources);
    if (
      Reflect.ownKeys(resources).length !== 3 ||
      ["projectNumber", "apiKeyResource", "rulesetResource"].some(
        (key) => !Object.hasOwn(resources, key),
      )
    )
      throw new Error();
    boundaries = plan.recordings.map((row) => ({
      ...resources,
      projectId: plan.projectId,
      bucket: plan.bucket,
      prefix: row.prefix,
    }));
    for (const boundary of boundaries) resolveProductionControlRoute("owner-exchange", boundary);
    if (
      typeof config.captureDirectory !== "string" ||
      !isAbsolute(config.captureDirectory) ||
      config.captureDirectory.length > 4096 ||
      config.captureDirectory.includes("\0")
    )
      throw new Error();
    for (const key of [
      "onByteReserve",
      "verifyAdmission",
      "ownerAuthorization",
      "accountAuthorization",
    ])
      if (
        typeof config[key] !== "function" ||
        types.isProxy(config[key]) ||
        (Object.getPrototypeOf(config[key]) !== Function.prototype && key !== "onByteReserve")
      )
        throw new Error();
    productionTlsOptions("https://storage.googleapis.com");
    accountRefs = plan.recordings.map((row) =>
      buildSymbolicStorageAuthPlan({
        projectId: plan.projectId,
        bucket: plan.bucket,
        runId: row.runId,
      }).programs.flatMap((program) => [program.validAccountRef, program.competitorAccountRef]),
    );
    expectedEmails = [
      "storage-object@example.com",
      ...plan.recordings.flatMap((row) =>
        ["authorization-errors", "firebase-id-token"].map(
          (program) => `storage-object-control-${row.runId}-${program}@example.com`,
        ),
      ),
    ];
    sessionPrograms = boundaries.map((boundary) =>
      buildCorpus(boundary).recipes.flatMap((recipe, index) =>
        recipe.id.endsWith("/resumable-upload") ? [{ recipe, ordinal: index + 1 }] : [],
      ),
    );
  } catch {
    throw new Error("invalid production wire configuration");
  }

  const secrets = new Set(),
    names = new Set();
  const sessionResponses = new WeakMap(),
    sessionCapabilities = new WeakMap(),
    sessionAttempts = new Set();
  const pacer = createObjectMutationPacer({ ownedPrefixes: boundaries.map((row) => row.prefix) });
  let active = null,
    busy = false,
    binding = false,
    failed = false,
    closed = false;
  const core = createWireTransportCore({
    limits: plan,
    onByteReserve: (row) => config.onByteReserve({ ...row, recording: active.context.recording }),
    serializeRequest: (route, init) => serializeProductionHttpRequest(route, init),
    createCapture: ({ sequence, serialized, metadata }) =>
      createProductionWireAttempt({
        directory: config.captureDirectory,
        sequence,
        request: {
          ...serialized,
          url: serialized.url.href,
          headers: Array.from({ length: serialized.headers.length / 2 }, (_, index) =>
            serialized.headers.slice(index * 2, index * 2 + 2),
          ),
        },
        metadata: { operationId: metadata.operationId, phase: metadata.phase },
        policy: {
          knownSecrets: [...secrets],
          expectedObjectNames: [...names],
          expectedBucket: plan.bucket,
          expectedEmails,
          responseBodyKind: active.media ? "media" : "json",
        },
      }),
    tlsConnectionOptions: (url) => productionTlsOptions(url.href),
  });

  function registerSecret(value) {
    if (
      closed ||
      busy ||
      typeof value !== "string" ||
      !value ||
      value.length > 8192 ||
      !value.isWellFormed() ||
      (!secrets.has(value) && secrets.size >= 64)
    )
      throw new Error("PRODUCTION_WIRE_SECRET_REJECTED");
    secrets.add(value);
  }

  function authorize(context, declaration) {
    if (declaration.credential === "none") return null;
    const owner = declaration.credential === "admin";
    const authorization = owner
      ? config.ownerAuthorization(context)
      : config.accountAuthorization(declaration.credentialRef, context);
    if (
      typeof authorization !== "string" ||
      !(owner ? /^Bearer [\x21-\x7e]{1,8192}$/ : /^Firebase [\x21-\x7e]{1,8192}$/).test(
        authorization,
      )
    )
      throw new Error();
    const secret = authorization.slice(authorization.indexOf(" ") + 1);
    if (!secrets.has(secret) && secrets.size >= 64) throw new Error();
    secrets.add(secret);
    return authorization;
  }

  function prepare(recording, suppliedInit, resolve) {
    if (!Number.isSafeInteger(recording) || recording < 1 || recording > 2) throw new Error();
    const init = record(suppliedInit);
    if (
      Object.keys(init).some((key) => !INIT_KEYS.has(key)) ||
      !["subject", "cleanup"].includes(init.accountingPhase) ||
      typeof init.operationId !== "string" ||
      !new RegExp(`^r${recording}/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)/[a-f0-9]{64}$`).test(
        init.operationId,
      ) ||
      (init.redirect !== undefined && init.redirect !== "manual")
    )
      throw new Error();
    const headers = record(init.headers ?? {});
    if (
      Object.keys(headers).some((key) =>
        ["authorization", "x-goog-user-project"].includes(key.toLowerCase()),
      )
    )
      throw new Error();
    const request = resolve(boundaries[recording - 1]);
    if (request.sessionDeclaration) {
      const { step, program, phase } = request.sessionDeclaration;
      const operation = `r${recording}/p${program.ordinal}/${createHash("sha256").update(step.id).digest("hex")}`;
      if (
        init.operationId !== operation ||
        init.accountingPhase !== phase ||
        !isDeepStrictEqual(headers, step.headers ?? {})
      )
        throw new Error();
      const actual = serializeProductionHttpRequest(request.route, {
        method: init.method,
        headers,
        body: init.body,
      }).body;
      const expected = step.body?.json
        ? Buffer.from(JSON.stringify(step.body.json))
        : step.body?.base64
          ? Buffer.from(step.body.base64, "base64")
          : Buffer.alloc(0);
      if (!actual.equals(expected)) throw new Error();
      if (sessionAttempts.has(operation)) throw new Error();
      sessionAttempts.add(operation);
    }
    const context = Object.freeze({
      recording,
      phase: init.accountingPhase,
      operationId: init.operationId,
      kind: request.kind,
    });
    if (config.verifyAdmission(context) !== true) throw new Error();
    const authorization = authorize(context, request.declaration);
    if (authorization !== null) headers.Authorization = authorization;
    if (request.quotaProject !== null) headers["x-goog-user-project"] = request.quotaProject;
    if (request.headerProfile) {
      const contentType = ["owner-refresh", "owner-tokeninfo", "client-form"].includes(
        request.headerProfile,
      )
        ? "application/x-www-form-urlencoded;charset=UTF-8"
        : "application/json";
      for (const key of Object.keys(headers))
        if (key.toLowerCase() === "content-type") {
          if (headers[key] !== contentType) throw new Error();
          delete headers[key];
        }
      headers["Content-Type"] = contentType;
      headers.Accept = "application/json";
    }
    const finalInit = { ...init, headers, redirect: "manual", method: request.route.method };
    if (init.method !== undefined && init.method !== request.route.method) throw new Error();
    const serialized = serializeProductionHttpRequest(request.route, finalInit);
    if (
      (request.kind === "owner-tokeninfo" || ["GET", "DELETE"].includes(request.route.method)) &&
      serialized.body.length !== 0
    )
      throw new Error();
    finalInit.body = serialized.body;
    finalInit.verifyBeforeDispatch = () => {
      if (
        closed ||
        failed ||
        config.verifyAdmission(context) !== true ||
        authorize(context, request.declaration) !== authorization
      )
        throw new Error();
      productionTlsOptions(request.route.url);
    };
    if (request.route.objectName) names.add(request.route.objectName);
    return { ...request, context, init: finalInit };
  }

  async function dispatch(recording, init, resolve) {
    if (closed) throw new Error("PRODUCTION_WIRE_CLOSED");
    if (failed) throw new Error("PRODUCTION_WIRE_HALTED");
    if (binding) {
      failed = true;
      throw new Error("PRODUCTION_WIRE_BINDING_IN_PROGRESS");
    }
    if (busy) throw new Error("PRODUCTION_WIRE_CONCURRENT_REQUEST");
    busy = true;
    try {
      active = prepare(recording, init, resolve);
      const send = () => core.fetch(active.route, active.init);
      const response = await (active.route.mutation
        ? pacer.dispatch(active.route.objectName, send)
        : send());
      if (active.sessionInitiation && response.status === 200) {
        const { step, program } = active.sessionDeclaration,
          dialect = step.dialect,
          boundary = boundaries[recording - 1],
          uri = response.headers.get(dialect === "gcs" ? "location" : "x-goog-upload-url"),
          captured = validateProductionSessionUri(uri, {
            dialect,
            bucket: boundary.bucket,
            prefix: boundary.prefix,
            objectName: step.objectName,
          });
        const body = Buffer.from(await response.arrayBuffer());
        if (body.length !== 0 && !body.equals(Buffer.from("OK"))) throw new Error();
        if (dialect === "firebase" && response.headers.get("x-goog-upload-status") !== "active")
          throw new Error();
        sessionResponses.set(response, {
          recording,
          program,
          initiateStep: step.id,
          dialect,
          objectName: step.objectName,
          uri: captured.url,
          uploadId: captured.uploadId,
          uriSha256: captured.uriSha256,
          wireSequence: core.snapshot().attempts,
          responseBodySha256: createHash("sha256").update(body).digest("hex"),
          context: active.context,
          bound: false,
        });
      }
      return response;
    } catch {
      failed = true;
      throw new Error("PRODUCTION_WIRE_REQUEST_REJECTED");
    } finally {
      active = null;
      busy = false;
    }
  }

  return Object.freeze({
    registerSecret,
    bindSession(recording, response) {
      let ownsBinding = false;
      try {
        const captured = sessionResponses.get(response);
        if (
          closed ||
          failed ||
          busy ||
          binding ||
          !captured ||
          captured.recording !== recording ||
          captured.bound
        )
          throw new Error();
        captured.bound = true;
        binding = true;
        ownsBinding = true;
        const admitted = config.verifyAdmission(captured.context);
        if (admitted !== true || closed || failed || busy || !captured.bound) throw new Error();
        registerSecret(captured.uri);
        registerSecret(captured.uploadId);
        const capability = Object.freeze({ sessionUriSha256: captured.uriSha256 });
        sessionCapabilities.set(capability, captured);
        return capability;
      } catch {
        failed = true;
        throw new Error("PRODUCTION_SESSION_BINDING_REJECTED");
      } finally {
        if (ownsBinding) binding = false;
      }
    },
    fetchSession(recording, capability, suppliedStep, init) {
      return dispatch(recording, init, (boundary) => {
        const captured = sessionCapabilities.get(capability),
          step = planCopy(suppliedStep);
        if (!captured || captured.recording !== recording) throw new Error();
        const subject = captured.program.recipe.steps.find((row) => row.id === step.id),
          cleanup = captured.program.recipe.cleanup.find((row) => row.id === step.id),
          canonical = subject ?? cleanup;
        if (!canonical || !isDeepStrictEqual(step, canonical)) throw new Error();
        const route = resolveProductionSessionRoute(step, {
          dialect: captured.dialect,
          bucket: boundary.bucket,
          prefix: boundary.prefix,
          objectName: captured.objectName,
          uri: captured.uri,
          initiateStep: captured.initiateStep,
        });
        return {
          route,
          declaration: { credential: "admin" },
          kind: "storage",
          quotaProject: plan.projectId,
          media: false,
          sessionDeclaration: {
            step: canonical,
            program: captured.program,
            phase: subject ? "subject" : "cleanup",
          },
        };
      });
    },
    fetchStorage(recording, suppliedStep, init) {
      return dispatch(recording, init, (boundary) => {
        const step = planCopy(suppliedStep);
        let sessionDeclaration;
        const programs = sessionPrograms[recording - 1];
        if (
          step.query?.uploadType === "resumable" ||
          step.headers?.["x-goog-upload-protocol"] === "resumable" ||
          programs.some((program) =>
            program.recipe.steps.some(
              (row) => !row.sessionUriReference && row.method === "POST" && row.id === step.id,
            ),
          )
        ) {
          const program = programs.find((row) => row.recipe.objects.includes(step.objectName)),
            canonical = program?.recipe.steps.find((row) => row.id === step.id);
          if (!canonical || !isDeepStrictEqual(step, canonical)) throw new Error();
          sessionDeclaration = { step: canonical, program, phase: "subject" };
        }
        const route = resolveProductionStorageRoute(step, boundary);
        const declaration = validateProductionCredentialDeclaration(step, {
          accountRefs: accountRefs[recording - 1],
        });
        return {
          route,
          declaration,
          kind: "storage",
          quotaProject: declaration.credential === "admin" ? plan.projectId : null,
          media: step.query.alt === "media",
          ...(sessionDeclaration ? { sessionDeclaration, sessionInitiation: true } : {}),
        };
      });
    },
    fetchControl(recording, kind, parameters, init) {
      return dispatch(recording, init, (boundary) => {
        const route = resolveProductionControlRoute(kind, boundary, record(parameters));
        return {
          route,
          declaration: { credential: route.credential },
          kind,
          quotaProject: route.quotaProject,
          headerProfile: route.headerProfile,
          media: false,
        };
      });
    },
    snapshot: () => ({ ...core.snapshot(), failed, closed }),
    async close() {
      closed = true;
      await core.close();
      secrets.clear();
      names.clear();
    },
  });
}
