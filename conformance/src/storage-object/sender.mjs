import { createHash } from "node:crypto";
import { createRunOwnership } from "./ownership.mjs";
import { createStage3RequestCounter, claimStage3RecipeContext } from "./request-counter.mjs";
import { isDeepStrictEqual, types } from "node:util";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";
import { evaluateRewriteProgress, validateRewriteDeclaration } from "./rewrite-attempts.mjs";
import { buildCorpus } from "./corpus.mjs";
import { createLocalAuthState } from "./local-auth-state.mjs";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { validateProductionCredentialDeclaration } from "./production-credentials.mjs";
import { buildSymbolicStorageAuthPlan } from "./auth-plan.mjs";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const senderClosureProofs = new WeakMap();
const productionSenders = new WeakSet();

/** Verify a module-private terminal proof against the actual active recipe and sequence. */
export function verifyLocalRecipeTerminal(sender, proof) {
  return senderClosureProofs.get(sender)?.(proof) === true;
}

/** Production terminal evidence requires the original module-private sender identity. */
export function verifyProductionRecipeTerminal(sender, proof) {
  return productionSenders.has(sender) && verifyLocalRecipeTerminal(sender, proof);
}

function productionRecord(value, allowed) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error("invalid production sender data");
  const entries = [];
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      (allowed && !allowed.includes(key)) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error("invalid production sender data");
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}

function productionData(value, depth = 0) {
  if (depth > 16 || types.isProxy(value)) throw new Error("invalid production sender data");
  if (
    value === null ||
    value === undefined ||
    ["string", "number", "boolean"].includes(typeof value)
  )
    return value;
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > 64 ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      throw new Error("invalid production sender data");
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value"))
        throw new Error("invalid production sender data");
      return productionData(descriptor.value, depth + 1);
    });
  }
  return Object.fromEntries(
    Object.entries(productionRecord(value)).map(([key, item]) => [
      key,
      productionData(item, depth + 1),
    ]),
  );
}

/** Bind the shared ownership core to a canonical production plan, capability and closed wire. */
export function createProductionStorageSender(input) {
  try {
    const options = productionRecord(input, [
      "plan",
      "recipeToken",
      "wire",
      "verifyAdmission",
      "onJournal",
    ]);
    if (Object.keys(options).length !== 5 || options.recipeToken === undefined) throw new Error();
    options.plan = productionData(options.plan);
    if (
      !isDeepStrictEqual(
        options.plan,
        buildProductionStage3DraftPlan({
          projectId: options.plan.projectId,
          bucket: options.plan.bucket,
          runIds: options.plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error();
    const wire = productionRecord(options.wire);
    if (
      [wire.fetchStorage, options.verifyAdmission, options.onJournal].some(
        (fn) => typeof fn !== "function" || types.isProxy(fn),
      ) ||
      Object.getPrototypeOf(options.verifyAdmission) !== Function.prototype
    )
      throw new Error();
    const sender = createStorageSender(
      { plan: options.plan, recipeToken: options.recipeToken, onJournal: options.onJournal },
      { fetchStorage: wire.fetchStorage, verifyAdmission: options.verifyAdmission },
    );
    productionSenders.add(sender);
    return sender;
  } catch {
    throw new Error("invalid production sender configuration");
  }
}

function localOrigin(value) {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw new Error("sender origin must be a bare loopback HTTP origin");
  return url.origin;
}

function encodeBody(body) {
  if (body === undefined) return undefined;
  if (body && Object.keys(body).length === 1 && typeof body.base64 === "string") {
    const bytes = Buffer.from(body.base64, "base64");
    if (bytes.toString("base64") !== body.base64) throw new Error("noncanonical request body");
    return bytes;
  }
  if (body && Object.keys(body).length === 1 && body.json !== undefined)
    return JSON.stringify(body.json);
  throw new Error("unresolved or unsupported request body");
}

function completePrefixList(response, bucket, scopePrefix) {
  let body;
  try {
    body = JSON.parse(response.raw.toString("utf8"));
  } catch {
    throw new Error("prefix list is not JSON");
  }
  if (
    response.status !== 200 ||
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.hasOwn(body, "error") ||
    (body.kind !== undefined && body.kind !== "storage#objects") ||
    (body.items === undefined ? body.kind !== "storage#objects" : !Array.isArray(body.items)) ||
    (body.prefixes !== undefined &&
      (!Array.isArray(body.prefixes) || body.prefixes.length !== 0)) ||
    (body.nextPageToken !== undefined && body.nextPageToken !== null) ||
    (body.items ?? []).some(
      (item) =>
        !item ||
        typeof item !== "object" ||
        Array.isArray(item) ||
        item.bucket !== bucket ||
        typeof item.name !== "string" ||
        !item.name.startsWith(scopePrefix) ||
        item.name.length === 0,
    )
  )
    throw new Error("prefix list is malformed or incomplete");
  return body.items ?? [];
}

/** Validate the route independently of credentials, references and transport. */
export function validateStorageRoute(step, { bucket, prefix } = {}) {
  const checkName = (name) => {
    if (
      typeof name !== "string" ||
      !name.startsWith(prefix) ||
      name.length === prefix.length ||
      name
        .slice(prefix.length)
        .split("/")
        .some((part) => part === "." || part === "..")
    )
      throw new Error("object name is outside the owned run prefix");
  };
  if (
    typeof bucket !== "string" ||
    typeof prefix !== "string" ||
    !/^storage-object\/[a-z0-9]{8,32}\/$/.test(prefix)
  )
    throw new Error("invalid owned route boundary");
  if (!step || !["firebase", "gcs"].includes(step.dialect))
    throw new Error("invalid Storage dialect");
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(step.method))
    throw new Error("invalid Storage method");
  if (step.query === null || typeof step.query !== "object" || Array.isArray(step.query))
    throw new Error("invalid Storage query");
  const expectedCollection =
    step.dialect === "firebase" ? `/v0/b/${bucket}/o` : `/storage/v1/b/${bucket}/o`;
  if (step.collection === true) {
    if (
      step.objectName !== undefined ||
      step.method !== "GET" ||
      step.path !== expectedCollection ||
      step.sessionUriReference !== undefined ||
      step.transfer !== undefined ||
      typeof step.scopePrefix !== "string" ||
      !step.scopePrefix.startsWith(prefix) ||
      typeof step.query.prefix !== "string" ||
      !step.query.prefix.startsWith(step.scopePrefix)
    )
      throw new Error("collection request is outside the owned prefix or route");
    return "direct";
  }
  if (step.collection !== undefined) throw new Error("invalid collection declaration");
  checkName(step.objectName);
  if (step.query.name !== undefined && step.query.name !== step.objectName)
    throw new Error("upload name differs from owned object");
  if (
    step.query.prefix !== undefined &&
    (typeof step.query.prefix !== "string" || !step.query.prefix.startsWith(prefix))
  )
    throw new Error("list prefix is outside the owned run prefix");
  if (step.sessionUriReference !== undefined) {
    if (step.path !== undefined || step.sessionUriReference.expectedName !== step.objectName)
      throw new Error("session reference has a conflicting object route");
    return "session";
  }
  const expectedObject = `${expectedCollection}/${encodeURIComponent(step.objectName)}`;
  const uploadCollection =
    step.dialect === "gcs" ? `/upload/storage/v1/b/${bucket}/o` : expectedCollection;
  let allowed = [expectedCollection, expectedObject, uploadCollection];
  if (step.transfer !== undefined) {
    if (
      step.dialect !== "gcs" ||
      step.method !== "POST" ||
      !["copyTo", "rewriteTo"].includes(step.transfer.operation) ||
      step.transfer.destinationName !== step.objectName
    )
      throw new Error("invalid owned transfer route");
    checkName(step.transfer.sourceName);
    allowed = [
      `${expectedCollection}/${encodeURIComponent(step.transfer.sourceName)}` +
        `/${step.transfer.operation}/b/${bucket}/o/${encodeURIComponent(step.objectName)}`,
    ];
  }
  if (typeof step.path !== "string" || !allowed.includes(step.path))
    throw new Error("Storage route is not the declared owned object route");
  if (step.collection === true && step.path !== expectedCollection)
    throw new Error("collection request has wrong route");
  if (
    step.method !== "GET" &&
    step.method !== "DELETE" &&
    step.path === expectedCollection &&
    step.query.name === undefined
  )
    throw new Error("mutation lacks an owned object name");
  return "direct";
}

/** Local-only sender seam. Production entry points remain disabled separately. */
export function createLocalStorageSender(options = {}) {
  return createStorageSender(options, null);
}

function createStorageSender(
  {
    plan,
    recipeToken,
    origin,
    authOrigin,
    localAuth,
    localControl,
    fetchImpl,
    onStart,
    onReserve,
    onJournal,
    credentials = {},
  } = {},
  production,
) {
  const base = production ? null : localOrigin(origin);
  const authBase = authOrigin === undefined ? null : localOrigin(authOrigin);
  const controlBase = localControl === undefined ? null : localOrigin(localControl.origin);
  if (
    localControl &&
    (typeof localControl.token !== "string" || !/^[^\s]+$/.test(localControl.token))
  )
    throw new Error("local control credential is invalid");
  let localRulesVerified = false,
    rulesProofSerial = 0;
  if ((!production && typeof fetchImpl !== "function") || typeof onJournal !== "function")
    throw new Error("fetch and durable ownership journal writers are required");
  if (
    plan?.status !== (production ? "PRODUCTION_DRAFT_NO_SEND" : "LOCAL_DRAFT_NO_SEND") ||
    plan.recordings?.length !== 2
  )
    throw new Error("a reviewed two-recording draft shape is required");
  const context = recipeToken === undefined ? null : claimStage3RecipeContext(recipeToken, plan);
  const bucket = context?.bucket ?? plan.bucket;
  const prefix = context?.prefix ?? plan.recordings[0].prefix;
  const ownership = createRunOwnership({ bucket, prefix });
  const counter = context?.counter ?? createStage3RequestCounter(plan, { onStart, onReserve });
  const accountRefs = production
    ? buildSymbolicStorageAuthPlan({
        projectId: plan.projectId,
        bucket,
        runId: plan.recordings[context.recording - 1].runId,
      }).programs.flatMap((program) => [program.validAccountRef, program.competitorAccountRef])
    : [];
  let productionFailed = false;
  let terminalProof = null;
  let recipeClosed = false;
  let namespaceAdmitted = false;
  let ordinal = 0;
  let runListProofSerial = 0;
  const attemptedInvalidProofNames = new Set();
  const observed = new Map();
  const lastMutation = new Map();
  const confirmed = new Map();
  const rewriteChains = new Map(),
    rewriteDispatches = new Map();
  const sessions = new Map();
  const authSubjectDispatches = new Map();
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials))
    throw new Error("invalid local credentials");

  function adminHeaders() {
    if (production) return {};
    const authorization = credentials.admin;
    if (typeof authorization !== "string" || !/^Bearer [^\s]+$/.test(authorization))
      throw new Error("admin OAuth credential is unresolved");
    return { authorization };
  }

  function productionAdmitted(requestContext) {
    if (!production) return;
    try {
      if (
        productionFailed ||
        production.verifyAdmission(requestContext) !== true ||
        productionFailed
      )
        throw new Error();
    } catch {
      productionFailed = true;
      throw new Error("production sender admission is unavailable");
    }
  }

  function internalProductionStep(path, query, init) {
    const collection = `/storage/v1/b/${bucket}/o`;
    if (path !== collection && !path.startsWith(`${collection}/`))
      throw new Error("invalid production helper route");
    return {
      dialect: "gcs",
      method: init.method,
      credential: "admin",
      path,
      query,
      ...(path === collection
        ? { collection: true, scopePrefix: prefix }
        : { objectName: decodeURIComponent(path.slice(collection.length + 1)) }),
    };
  }

  async function countedFetch(
    operationId,
    path,
    query,
    init,
    beforeFetch = async () => {},
    requestOrigin = base,
    verifyBeforeFetch = () => {},
    storageStep,
  ) {
    terminalProof = null;
    const dispatchOperationId = context?.dispatchOperationId(operationId) ?? operationId;
    if (production) {
      const requestContext = Object.freeze({
        recording: context.recording,
        phase: counter.snapshot().mode,
        kind: "storage",
        operationId: dispatchOperationId,
      });
      const declaration = storageStep ?? internalProductionStep(path, query, init);
      validateStorageRoute(declaration, { bucket, prefix });
      validateProductionCredentialDeclaration(declaration, { accountRefs });
      productionAdmitted(requestContext);
      try {
        return await counter.send(operationId, async () => {
          await beforeFetch();
          verifyBeforeFetch();
          productionAdmitted(requestContext);
          const response = await production.fetchStorage(context.recording, declaration, {
            method: init.method,
            headers: init.headers ?? {},
            body: init.body,
            redirect: "manual",
            operationId: dispatchOperationId,
            accountingPhase: requestContext.phase,
          });
          const bytes = Buffer.from(await response.arrayBuffer());
          productionAdmitted(requestContext);
          if (bytes.length > MAX_RESPONSE_BYTES) throw new Error();
          return {
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            raw: bytes,
          };
        });
      } catch {
        productionFailed = true;
        throw new Error("production sender request is unavailable");
      }
    }
    const url = new URL(path, requestOrigin);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (typeof value !== "string") throw new Error("unresolved request query");
      url.searchParams.set(key, value);
    }
    return counter.send(operationId, async () => {
      await beforeFetch();
      verifyBeforeFetch();
      const response = await fetchImpl(url.href, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
        operationId: dispatchOperationId,
        accountingPhase: counter.snapshot().mode,
        verifyBeforeDispatch: verifyBeforeFetch,
      });
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length > MAX_RESPONSE_BYTES)
        throw new Error("response body exceeds local capture bound");
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        raw: bytes,
      };
    });
  }

  const auth =
    authBase === null
      ? null
      : createLocalAuthState({
          ...localAuth,
          plan,
          recording: context ? context.recording - 1 : 0,
          onJournal,
          request: (operationId, path, query, { owner, body }, beforeFetch) =>
            countedFetch(
              operationId,
              path,
              query,
              {
                method: "POST",
                headers: { "content-type": "application/json", ...(owner ? adminHeaders() : {}) },
                body: JSON.stringify(body),
              },
              beforeFetch,
              authBase,
            ),
        });

  function ownedReadbacks(name, metadataOperationId, mediaOperationId) {
    if (typeof name !== "string" || !name.startsWith(prefix) || name.length === prefix.length)
      throw new Error("object is outside the owned run prefix");
    const metadata = observed.get(metadataOperationId);
    const media = observed.get(mediaOperationId);
    if (
      !metadata ||
      !media ||
      metadata.ordinal >= media.ordinal ||
      metadata.ordinal <= (lastMutation.get(name) ?? 0) ||
      metadata.step.objectName !== name ||
      media.step.objectName !== name ||
      metadata.step.method !== "GET" ||
      media.step.method !== "GET" ||
      Object.keys(metadata.step.query).length !== 0 ||
      Object.keys(media.step.query).length !== 1 ||
      media.step.query.alt !== "media" ||
      Object.keys(media.step.headers ?? {}).some((header) => header.toLowerCase() === "range") ||
      metadata.response.status !== 200 ||
      media.response.status !== 200
    )
      throw new Error("owned metadata and media readbacks are missing or stale");
    let parsed;
    try {
      parsed = JSON.parse(metadata.response.raw.toString("utf8"));
    } catch {
      throw new Error("owned metadata is not JSON");
    }
    if (
      parsed?.bucket !== bucket ||
      parsed.name !== name ||
      typeof parsed.generation !== "string" ||
      !/^[1-9][0-9]{0,19}$/.test(parsed.generation)
    )
      throw new Error("owned metadata identity or generation differs");
    const bytesSha256 = createHash("sha256").update(media.response.raw).digest("hex");
    return { bucket, name, generation: parsed.generation, bytesSha256 };
  }

  function boundRewriteProgress(name) {
    const chain = rewriteChains.get(name);
    if (!chain || chain.ids.length === 0) throw new Error("rewrite response chain is missing");
    const attempts = chain.ids.map((id) => {
      const captured = observed.get(id);
      if (!captured) throw new Error("rewrite response is uncertain");
      return {
        stepId: id,
        query: captured.step.query,
        status: captured.response.status,
        bodyBase64: captured.response.raw.toString("base64"),
      };
    });
    const progress = evaluateRewriteProgress({ recipe: chain.recipe, attempts, bucket });
    if (progress.objectSize !== `${chain.sourceBytes}`)
      throw new Error("rewrite size differs from owned source");
    return progress;
  }

  function canonicalSessionRecipe(recipe) {
    if (
      !["storage-object/firebase/resumable-upload", "storage-object/gcs/resumable-upload"].includes(
        recipe?.id,
      )
    )
      throw new Error("invalid local session recipe");
    const canonical = buildCorpus({ bucket, prefix }).recipes.find((row) => row.id === recipe.id);
    if (!isDeepStrictEqual(recipe, canonical)) throw new Error("local session declaration differs");
    return canonical;
  }

  function localSessionUrl(value, dialect, name, path) {
    if (typeof value !== "string" || !value || Buffer.byteLength(value) > 8192 || /\s/.test(value))
      throw new Error("invalid local session URI");
    let url;
    try {
      url = new URL(value);
    } catch {
      throw new Error("invalid local session URI");
    }
    const keys = [...url.searchParams.keys()];
    const protocolKey = dialect === "gcs" ? "uploadType" : "upload_protocol";
    if (
      url.href !== value ||
      url.origin !== base ||
      url.username ||
      url.password ||
      url.hash ||
      url.pathname !== path ||
      keys.toSorted().join(",") !== ["name", protocolKey, "upload_id"].toSorted().join(",") ||
      url.searchParams.get("name") !== name ||
      url.searchParams.get(protocolKey) !== "resumable" ||
      !/^[A-Za-z0-9_-]{1,4096}$/.test(url.searchParams.get("upload_id") ?? "")
    )
      throw new Error("invalid local session URI");
    return url;
  }

  const sender = {
    start: () => counter.start(),
    snapshot: () => counter.snapshot(),
    async admitNamespace() {
      if (namespaceAdmitted) throw new Error("namespace was already admitted");
      const response = await countedFetch(
        "initial-prefix-list",
        `/storage/v1/b/${bucket}/o`,
        { prefix, maxResults: "1000" },
        { method: "GET", headers: adminHeaders() },
      );
      if (response.status !== 200) throw new Error("initial prefix list failed");
      const items = completePrefixList(response, bucket, prefix);
      ownership.assertInitialEmpty({
        bucket,
        prefix,
        pages: [{ items, nextPageToken: null }],
      });
      namespaceAdmitted = true;
    },
    admitObject(name) {
      if (!namespaceAdmitted) throw new Error("initial namespace is unproved");
      return ownership.noteInitialAbsentFromNamespace(name);
    },
    async sendAuthStep(options = {}) {
      if (
        !auth ||
        !namespaceAdmitted ||
        counter.snapshot().mode !== (options.cleanupIndex !== undefined ? "cleanup" : "subject")
      )
        throw new Error("local Auth dispatch phase is unavailable");
      return auth.send(options);
    },
    async verifyLocalAuthRules() {
      localRulesVerified = false;
      if (!auth || !controlBase || !["subject", "cleanup"].includes(counter.snapshot().mode))
        throw new Error("local Rules readback is unavailable");
      const operationId = `local-auth-rules-${++rulesProofSerial}`;
      const response = await countedFetch(
        operationId,
        "/v1/storage/rules",
        {},
        { method: "GET", headers: { authorization: `Bearer ${localControl.token}` } },
        undefined,
        controlBase,
      );
      let body;
      try {
        body = JSON.parse(response.raw.toString("utf8"));
      } catch {
        throw new Error("local Rules readback is malformed");
      }
      if (
        response.status !== 200 ||
        body?.loaded !== true ||
        body.targeted !== false ||
        typeof body.source !== "string" ||
        createHash("sha256").update(body.source).digest("hex") !== FIXED_PRODUCTION_RULES_SHA256
      )
        throw new Error("local Rules readback differs from the fixed source");
      await onJournal({
        operationId,
        rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
        loaded: true,
        localOnly: true,
      });
      localRulesVerified = true;
      return Object.freeze({
        rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
        sendAuthorized: false,
      });
    },
    authAccountSnapshot: (options) => {
      if (!auth) throw new Error("local Auth is unavailable");
      return auth.snapshot(options);
    },
    async sendAuthSubject(options = {}) {
      if (!auth || !localRulesVerified || counter.snapshot().mode !== "subject")
        throw new Error("local Auth subject dispatch is unavailable");
      const { probe, authorization, proof } = auth.wire(options);
      const step = {
        id: `${options.recipe.id}/${probe.id}/subject`,
        dialect: "firebase",
        method: probe.subject.method,
        objectName: probe.objectName,
        path: probe.subject.path,
        query: probe.subject.query,
        credential: "none",
        headers: probe.action === "write" ? { "content-type": "application/octet-stream" } : {},
        ...(probe.subject.body ? { body: probe.subject.body } : {}),
      };
      const bound = structuredClone({ recipe: options.recipe, probeIndex: options.probeIndex });
      authSubjectDispatches.set(step.id, {
        authorization,
        proof,
        check: () => {
          if (auth.wire(bound).authorization !== authorization)
            throw new Error("local Auth wire credential changed before send");
        },
      });
      try {
        return await sender.sendStep(step);
      } finally {
        authSubjectDispatches.delete(step.id);
      }
    },
    async sendStep(suppliedStep, suppliedOptions = {}) {
      const step = production ? productionData(suppliedStep) : suppliedStep;
      const options = production
        ? productionRecord(suppliedOptions, ["operationId"])
        : suppliedOptions;
      const { operationId = step?.id } = options;
      if (production) validateProductionCredentialDeclaration(step, { accountRefs });
      if (counter.snapshot().mode === "not-started") throw new Error("no durable started row");
      const route = validateStorageRoute(step, { bucket, prefix });
      if (route !== "direct") throw new Error("session reference is unresolved");
      if (
        step.transfer?.operation === "rewriteTo" &&
        (step.continuation !== undefined || step.query.rewriteToken !== undefined) &&
        !rewriteDispatches.has(operationId)
      )
        throw new Error("rewrite continuation lacks captured response provenance");
      if (observed.has(operationId) || operationId === "initial-prefix-list")
        throw new Error("request operation ID was already used");
      const headers = { ...step.headers };
      const authDispatch = authSubjectDispatches.get(operationId);
      if (authDispatch?.authorization) headers.authorization = authDispatch.authorization;
      if (!production && step.credential !== undefined && step.credential !== "none") {
        const authorization = credentials[step.credential];
        if (typeof authorization !== "string" || !/^(Bearer|Firebase) [^\s]+$/.test(authorization))
          throw new Error("local credential is unresolved");
        headers.authorization = authorization;
      }
      const body = encodeBody(step.body);
      const mutates = !["GET", "HEAD"].includes(step.method);
      if (mutates && !namespaceAdmitted) throw new Error("initial namespace is unproved");
      if (mutates && counter.snapshot().mode !== "subject")
        throw new Error("mutation outside the subject phase requires owned cleanup");
      const response = await countedFetch(
        operationId,
        step.path,
        step.query,
        { method: step.method, headers, body },
        async () => {
          if (authDispatch)
            await onJournal({
              operationId,
              name: step.objectName,
              credentialProof: authDispatch.proof,
            });
          if (mutates) {
            await onJournal({
              bucket,
              prefix,
              name: step.objectName,
              operationId,
              method: step.method,
              ...(rewriteDispatches.get(operationId)?.previousOperationId
                ? { continuationOf: rewriteDispatches.get(operationId).previousOperationId }
                : {}),
            });
            const previous = rewriteDispatches.get(operationId)?.previousOperationId;
            if (previous)
              ownership.noteMutationContinuation(step.objectName, previous, operationId);
            else ownership.noteMutationAttempt(step.objectName, operationId);
          }
        },
        base,
        authDispatch?.check,
        step,
      );
      observed.set(operationId, { step, response, ordinal: ++ordinal });
      if (mutates) lastMutation.set(step.objectName, ordinal);
      return response;
    },
    async sendRewriteStep({ recipe, stepIndex } = {}) {
      const ids = validateRewriteDeclaration({ recipe, bucket });
      const declared = recipe.steps[stepIndex];
      const index = ids.indexOf(declared?.id);
      if (index < 0) throw new Error("request is not a declared rewrite slot");
      const name = declared.objectName;
      let chain = rewriteChains.get(name),
        query;
      if (index === 0) {
        if (chain) throw new Error("rewrite sequence was already started");
        const records = new Map(
          [...observed].map(([id, row]) => [
            id,
            {
              status: row.response.status,
              bodyBase64: row.response.raw.toString("base64"),
            },
          ]),
        );
        query = resolveDeclaredQuery({ recipe, stepIndex, responses: records, bucket });
        const metadataId = declared.query.ifSourceGenerationMatch.step;
        const metadataIndex = recipe.steps.findIndex((row) => row.id === metadataId);
        const mediaId = recipe.steps[metadataIndex + 1]?.id;
        sender.assertOwnedReadbacks({
          name: declared.transfer.sourceName,
          metadataOperationId: metadataId,
          mediaOperationId: mediaId,
        });
        chain = {
          recipe: structuredClone(recipe),
          ids: [],
          sourceBytes: observed.get(mediaId).response.raw.length,
        };
        rewriteChains.set(name, chain);
      } else {
        if (!chain || !isDeepStrictEqual(chain.recipe, recipe) || chain.ids.length !== index)
          throw new Error("rewrite continuation differs from the bound declaration or order");
        const progress = boundRewriteProgress(name);
        if (progress.done) throw new Error("rewrite already completed");
        query = { rewriteToken: progress.rewriteToken };
      }
      const operationId = declared.id;
      rewriteDispatches.set(operationId, { previousOperationId: chain.ids.at(-1) ?? null });
      chain.ids.push(operationId);
      try {
        return await sender.sendStep({ ...declared, query });
      } finally {
        rewriteDispatches.delete(operationId);
      }
    },
    rewriteProgress({ name } = {}) {
      const progress = boundRewriteProgress(name);
      return Object.freeze({ done: progress.done, attempts: progress.attempts });
    },
    bindSession({ recipe, initiateOperationId } = {}) {
      const canonical = canonicalSessionRecipe(recipe);
      const captured = observed.get(initiateOperationId);
      const start = canonical.steps.find((step) => step.id === initiateOperationId);
      if (
        !captured ||
        !start ||
        start.sessionUriReference ||
        start.method !== "POST" ||
        !isDeepStrictEqual(start, captured.step) ||
        captured.response.status !== 200 ||
        (captured.response.raw.length !== 0 && !captured.response.raw.equals(Buffer.from("OK"))) ||
        sessions.has(start.objectName) ||
        (start.dialect === "firebase" &&
          captured.response.headers["x-goog-upload-status"] !== "active")
      )
        throw new Error("local session initiation is unproved");
      const header = start.dialect === "firebase" ? "x-goog-upload-url" : "location";
      const uri = localSessionUrl(
        captured.response.headers[header],
        start.dialect,
        start.objectName,
        start.path,
      );
      const uriSha256 = createHash("sha256").update(uri.href).digest("hex");
      sessions.set(start.objectName, {
        uri,
        uriSha256,
        recipe: structuredClone(canonical),
        initiateOperationId,
        mutationId: initiateOperationId,
        attempted: new Set([initiateOperationId]),
        completed: false,
        cancelled: false,
        cancelOperationId: null,
        finishOperationId: null,
      });
      return Object.freeze({ sessionUriSha256: uriSha256, sendAuthorized: false });
    },
    async sendSessionStep({ recipe, stepIndex, cleanupIndex } = {}) {
      const canonical = canonicalSessionRecipe(recipe);
      const cleanup = cleanupIndex !== undefined;
      const index = cleanup ? cleanupIndex : stepIndex;
      if (!Number.isInteger(index) || index < 0 || (cleanup && stepIndex !== undefined))
        throw new Error("invalid local session request index");
      const step = (cleanup ? canonical.cleanup : canonical.steps)[index];
      if (
        !step?.sessionUriReference ||
        validateStorageRoute(step, { bucket, prefix }) !== "session"
      )
        throw new Error("request is not a declared local session continuation");
      const session = sessions.get(step.objectName);
      if (
        !session ||
        !isDeepStrictEqual(session.recipe, canonical) ||
        session.initiateOperationId !== step.sessionUriReference.initiateStep ||
        observed.has(step.id)
      )
        throw new Error("local session response binding is missing or stale");
      if (counter.snapshot().mode !== (cleanup ? "cleanup" : "subject"))
        throw new Error("local session request has the wrong budget phase");
      const condition = step.continuation;
      const preceding = observed.get(condition.afterStep);
      if (
        !condition ||
        !session.attempted.has(condition.afterStep) ||
        (condition.afterStep !== session.initiateOperationId &&
          preceding?.sessionBinding !== session) ||
        (condition.status !== undefined && preceding?.response.status !== condition.status) ||
        (condition.uploadStatus !== undefined &&
          preceding?.response.headers["x-goog-upload-status"] !== condition.uploadStatus) ||
        (condition.receivedBytes !== undefined &&
          preceding?.response.headers["x-goog-upload-size-received"] !==
            `${condition.receivedBytes}`) ||
        (condition.range !== undefined &&
          (preceding?.response.headers.range !== condition.range ||
            preceding.response.raw.length !== 0)) ||
        (condition.completionUnconfirmed === true && session.completed) ||
        (condition.cancellationUnconfirmed === true && session.cancelled)
      )
        throw new Error("local session continuation prerequisite failed");
      const command = step.headers["x-goog-upload-command"];
      const cancel = step.method === "DELETE" || command === "cancel";
      const mutates =
        cancel ||
        (step.dialect === "firebase"
          ? command?.startsWith("upload")
          : !step.headers["content-range"]?.startsWith("bytes */"));
      if (mutates && (session.completed || session.cancelled))
        throw new Error("local session is already terminal");
      const authorization = credentials[step.credential];
      if (typeof authorization !== "string" || !/^(Bearer|Firebase) [^\s]+$/.test(authorization))
        throw new Error("local credential is unresolved");
      const response = await countedFetch(
        step.id,
        session.uri.pathname,
        Object.fromEntries(session.uri.searchParams),
        {
          method: step.method,
          headers: { ...step.headers, authorization },
          body: encodeBody(step.body),
        },
        async () => {
          if (mutates) {
            await onJournal({
              bucket,
              prefix,
              name: step.objectName,
              operationId: step.id,
              method: step.method,
              continuationOf: session.mutationId,
              sessionUriSha256: session.uriSha256,
            });
            ownership.noteMutationContinuation(step.objectName, session.mutationId, step.id);
            session.mutationId = step.id;
            if (cancel) session.cancelOperationId = step.id;
          }
          session.attempted.add(step.id);
        },
      );
      observed.set(step.id, { step, response, ordinal: ++ordinal, sessionBinding: session });
      if (mutates) lastMutation.set(step.objectName, ordinal);
      if (step.id === "finish") session.finishOperationId = step.id;
      return response;
    },
    sessionSnapshot({ name } = {}) {
      const session = sessions.get(name);
      return session
        ? Object.freeze({
            completed: session.completed,
            cancelled: session.cancelled,
            sessionUriSha256: session.uriSha256,
          })
        : null;
    },
    async confirmCancelledSession({
      name,
      cancelOperationId,
      queryOperationId,
      readbackOperationIds,
    } = {}) {
      const session = sessions.get(name),
        cancel = observed.get(cancelOperationId),
        query = observed.get(queryOperationId);
      const firebase = query?.step.dialect === "firebase";
      if (
        !session ||
        session.completed ||
        session.cancelled ||
        session.mutationId !== cancelOperationId ||
        session.cancelOperationId !== cancelOperationId ||
        !session.attempted.has(cancelOperationId) ||
        !session.attempted.has(queryOperationId) ||
        !query ||
        query.sessionBinding !== session ||
        !isDeepStrictEqual(
          query.step,
          [...session.recipe.steps, ...session.recipe.cleanup].find(
            (step) => step.id === queryOperationId,
          ),
        ) ||
        query.step.objectName !== name ||
        query.step.continuation.afterStep !== cancelOperationId ||
        (cancel &&
          (cancel.sessionBinding !== session ||
            cancel.step.objectName !== name ||
            cancel.ordinal >= query.ordinal)) ||
        (firebase
          ? (cancel && cancel.response.status !== 200) ||
            query.response.status !== 200 ||
            query.response.headers["x-goog-upload-status"] !== "cancelled" ||
            query.response.headers["x-goog-upload-size-received"] !== "0"
          : cancel?.response.status !== 499 || ![400, 404].includes(query.response.status))
      )
        throw new Error("local session cancellation is not terminally confirmed");
      if (
        !Array.isArray(readbackOperationIds) ||
        readbackOperationIds.length !== 4 ||
        new Set(readbackOperationIds).size !== 4
      )
        throw new Error("session absence reads are incomplete");
      const kinds = new Set();
      for (const id of readbackOperationIds) {
        const row = observed.get(id);
        const kind = row?.step.query.alt === "media" ? "media" : "metadata";
        if (
          !row ||
          row.ordinal <= query.ordinal ||
          row.step.objectName !== name ||
          row.step.method !== "GET" ||
          row.response.status !== 404 ||
          (kind === "metadata"
            ? Object.keys(row.step.query).length !== 0
            : Object.keys(row.step.query).length !== 1) ||
          Object.keys(row.step.headers ?? {}).some((key) => key.toLowerCase() === "range")
        )
          throw new Error("session absence reads are stale or selected");
        kinds.add(`${row.step.dialect}/${kind}`);
      }
      if (kinds.size !== 4) throw new Error("both APIs must confirm session object absence");
      const listing = await countedFetch(
        `${cancelOperationId}-session-prefix-absence`,
        `/storage/v1/b/${bucket}/o`,
        { prefix: name, maxResults: "1000" },
        { method: "GET", headers: adminHeaders() },
      );
      const items = completePrefixList(listing, bucket, name);
      ownership.noteCancelledSessionAbsent(name, {
        operationId: cancelOperationId,
        sessionCancelled: true,
        metadataStatus: 404,
        mediaStatus: 404,
        prefixPagesComplete: true,
        nameFound: items.some((item) => item.name === name),
      });
      session.cancelled = true;
      return "cancelled-and-absent";
    },
    assertOwnedReadbacks({ name, metadataOperationId, mediaOperationId } = {}) {
      const current = ownedReadbacks(name, metadataOperationId, mediaOperationId);
      const prior = confirmed.get(name);
      if (
        !prior ||
        prior.generation !== current.generation ||
        prior.bytesSha256 !== current.bytesSha256 ||
        prior.mutationOrdinal !== lastMutation.get(name)
      )
        throw new Error("prerequisite readbacks differ from confirmed ownership");
      return current.generation;
    },
    confirmOwned({
      name,
      uploadOperationId,
      metadataOperationId,
      mediaOperationId,
      expectedBytesSha256,
    } = {}) {
      const upload = observed.get(uploadOperationId);
      const current = ownedReadbacks(name, metadataOperationId, mediaOperationId);
      if (
        !upload ||
        upload.step.objectName !== name ||
        !["POST", "PUT", "PATCH"].includes(upload.step.method) ||
        upload.response.status < 200 ||
        upload.response.status >= 300 ||
        upload.ordinal !== lastMutation.get(name)
      )
        throw new Error("owned upload response is absent or stale");
      let uploaded;
      try {
        uploaded = JSON.parse(upload.response.raw.toString("utf8"));
      } catch {
        throw new Error("owned upload response is not JSON");
      }
      if (upload.step.transfer?.operation === "rewriteTo") {
        const progress = boundRewriteProgress(name);
        if (!progress.done || rewriteChains.get(name).ids.at(-1) !== uploadOperationId)
          throw new Error("rewrite completion is not bound to the owned upload");
        uploaded = uploaded.resource;
      }
      if (
        uploaded?.bucket !== bucket ||
        uploaded.name !== name ||
        uploaded.generation !== current.generation
      )
        throw new Error("owned upload generation differs from readback");
      if (
        typeof expectedBytesSha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(expectedBytesSha256) ||
        current.bytesSha256 !== expectedBytesSha256
      )
        throw new Error("owned bytes do not match expected bytes");
      const session = sessions.get(name);
      if (
        session &&
        (session.finishOperationId !== uploadOperationId ||
          session.mutationId !== uploadOperationId ||
          session.cancelled ||
          (upload.step.dialect === "firebase" &&
            upload.response.headers["x-goog-upload-status"] !== "final"))
      )
        throw new Error("session completion is not bound to the owned object");
      ownership.observeOwnedGeneration(
        name,
        { ...current, operationId: uploadOperationId },
        expectedBytesSha256,
      );
      confirmed.set(name, { ...current, mutationOrdinal: upload.ordinal });
      if (session) session.completed = true;
      return current.generation;
    },
    confirmRefused({ name, mutationOperationId, metadataOperationId, mediaOperationId } = {}) {
      const mutation = observed.get(mutationOperationId);
      const current = ownedReadbacks(name, metadataOperationId, mediaOperationId);
      const prior = confirmed.get(name);
      if (
        !mutation ||
        mutation.step.objectName !== name ||
        !["POST", "PUT", "PATCH", "DELETE"].includes(mutation.step.method) ||
        mutation.response.status < 400 ||
        mutation.response.status > 599 ||
        mutation.ordinal !== lastMutation.get(name) ||
        !prior ||
        prior.generation !== current.generation ||
        prior.bytesSha256 !== current.bytesSha256
      )
        throw new Error("refused mutation or unchanged owned state is unproved");
      ownership.noteRefusedMutation(
        name,
        {
          operationId: mutationOperationId,
          status: mutation.response.status,
        },
        current,
      );
      confirmed.set(name, { ...current, mutationOrdinal: mutation.ordinal });
      return current.generation;
    },
    async confirmAbsent({ name, mutationOperationId, metadataOperationId, mediaOperationId } = {}) {
      const session = sessions.get(name);
      if (session && !session.completed && !session.cancelled)
        throw new Error("active session responsibility needs terminal confirmation");
      if (typeof name !== "string" || !name.startsWith(prefix) || name.length === prefix.length)
        throw new Error("object is outside the owned run prefix");
      const mutation = observed.get(mutationOperationId);
      const metadata = observed.get(metadataOperationId);
      const media = observed.get(mediaOperationId);
      if (
        !mutation ||
        !metadata ||
        !media ||
        mutation.step.objectName !== name ||
        !["POST", "PUT", "PATCH", "DELETE"].includes(mutation.step.method) ||
        mutation.ordinal !== lastMutation.get(name) ||
        metadata.ordinal <= mutation.ordinal ||
        media.ordinal <= metadata.ordinal ||
        metadata.step.objectName !== name ||
        media.step.objectName !== name ||
        metadata.step.method !== "GET" ||
        media.step.method !== "GET" ||
        Object.keys(metadata.step.query).length !== 0 ||
        Object.keys(media.step.query).length !== 1 ||
        media.step.query.alt !== "media" ||
        Object.keys(media.step.headers ?? {}).some((header) => header.toLowerCase() === "range") ||
        metadata.response.status !== 404 ||
        media.response.status !== 404
      )
        throw new Error("fresh bound absence readbacks are missing");
      const listing = await countedFetch(
        `subject-absence-${ordinal + 1}`,
        `/storage/v1/b/${bucket}/o`,
        { prefix: name, maxResults: "1000" },
        { method: "GET", headers: adminHeaders() },
      );
      if (listing.status !== 200) throw new Error("subject absence prefix list failed");
      const items = completePrefixList(listing, bucket, name);
      const proof = {
        operationId: mutationOperationId,
        status: mutation.response.status,
        metadataStatus: metadata.response.status,
        mediaStatus: media.response.status,
        prefixPagesComplete: true,
        nameFound: items.some((item) => item.name === name),
      };
      if (confirmed.has(name)) {
        ownership.noteSubjectDeleted(name, proof);
        confirmed.delete(name);
        return "deleted";
      }
      ownership.noteRefusedAbsent(name, proof);
      return "already-absent";
    },
    async confirmRefusedInvalidName({
      name,
      mutationOperationId,
      metadataOperationId,
      mediaOperationId,
    } = {}) {
      if (counter.snapshot().mode !== "subject")
        throw new Error("invalid-name refusal proof requires the subject phase");
      if (typeof name !== "string" || !name.startsWith(prefix) || name.length === prefix.length)
        throw new Error("invalid-name target is outside the owned run prefix");
      const mutation = observed.get(mutationOperationId);
      const metadata = observed.get(metadataOperationId);
      const media = observed.get(mediaOperationId);
      const malformed = mutation?.step.malformedObjectName;
      const uploadStep = mutation?.step;
      const uploadPath =
        uploadStep?.dialect === "firebase"
          ? `/v0/b/${bucket}/o`
          : `/upload/storage/v1/b/${bucket}/o`;
      const uploadQueryKeys =
        uploadStep?.dialect === "firebase" ? ["name"] : ["name", "uploadType"];
      if (
        !mutation ||
        mutation.step.objectName !== name ||
        mutation.step.method !== "POST" ||
        mutation.response.status < 400 ||
        mutation.response.status > 499 ||
        mutation.ordinal !== lastMutation.get(name) ||
        !["firebase", "gcs"].includes(uploadStep.dialect) ||
        uploadStep.path !== uploadPath ||
        Object.keys(uploadStep.query).toSorted().join(",") !==
          uploadQueryKeys.toSorted().join(",") ||
        uploadStep.query.name !== name ||
        (uploadStep.dialect === "gcs" && uploadStep.query.uploadType !== "media") ||
        uploadStep.headers?.["content-type"] !== "application/octet-stream" ||
        typeof uploadStep.body?.base64 !== "string" ||
        !malformed ||
        malformed.attemptedName !== name ||
        malformed.scopePrefix !== `${prefix}errors/object-name/` ||
        !name.startsWith(malformed.scopePrefix) ||
        !["linefeed", "oversized"].includes(malformed.kind) ||
        (malformed.kind === "linefeed" && !name.includes("\n")) ||
        (malformed.kind === "oversized" && Buffer.byteLength(name) <= 1024)
      )
        throw new Error("invalid-name refusal is not bound to the declared upload route and name");
      if (
        !metadata ||
        !media ||
        metadata.ordinal <= mutation.ordinal ||
        media.ordinal <= metadata.ordinal ||
        metadata.step.objectName !== name ||
        media.step.objectName !== name ||
        metadata.step.method !== "GET" ||
        media.step.method !== "GET" ||
        Object.keys(metadata.step.query).length !== 0 ||
        Object.keys(media.step.query).length !== 1 ||
        media.step.query.alt !== "media" ||
        Object.keys(media.step.headers ?? {}).some((header) => header.toLowerCase() === "range") ||
        metadata.response.status < 400 ||
        metadata.response.status > 499 ||
        media.response.status < 400 ||
        media.response.status > 499
      )
        throw new Error("fresh invalid-name readbacks are missing");
      if (attemptedInvalidProofNames.has(name) || attemptedInvalidProofNames.size >= 4)
        throw new Error("invalid-name proof was already attempted or exceeds its budget");
      attemptedInvalidProofNames.add(name);
      const pages = [];
      const serial = ++runListProofSerial;
      const seenTokens = new Set();
      let pageToken = null;
      for (let pageIndex = 0; pageIndex < 32; pageIndex++) {
        const response = await countedFetch(
          `invalid-name-run-list-${serial}-${pageIndex}`,
          `/storage/v1/b/${bucket}/o`,
          { prefix, maxResults: "1000", ...(pageToken ? { pageToken } : {}) },
          { method: "GET", headers: adminHeaders() },
        );
        if (response.status !== 200) throw new Error("invalid-name run prefix list failed");
        let body;
        try {
          body = JSON.parse(response.raw.toString("utf8"));
        } catch {
          throw new Error("invalid-name run prefix list is not JSON");
        }
        if (
          !body ||
          typeof body !== "object" ||
          Array.isArray(body) ||
          (body.kind !== undefined && body.kind !== "storage#objects") ||
          (body.items !== undefined && !Array.isArray(body.items)) ||
          (body.prefixes !== undefined && (!Array.isArray(body.prefixes) || body.prefixes.length))
        )
          throw new Error("invalid-name run prefix list is malformed");
        const next = body.nextPageToken ?? null;
        if (
          next !== null &&
          (typeof next !== "string" ||
            !next ||
            Buffer.byteLength(next) > 4096 ||
            [...next].some((character) => {
              const code = character.codePointAt(0);
              return code < 32 || code === 127;
            }) ||
            seenTokens.has(next))
        )
          throw new Error("invalid-name run prefix list token is invalid");
        if (next !== null) seenTokens.add(next);
        pages.push({ pageToken, items: body.items ?? [], nextPageToken: next });
        if (next === null) break;
        pageToken = next;
      }
      ownership.noteRefusedAbsentFromRunList(name, {
        operationId: mutationOperationId,
        status: mutation.response.status,
        bucket,
        prefix,
        pages,
      });
      return "absent-by-run-list";
    },
    async cleanupConfirmedOwned({
      operationPrefix = "exception-cleanup",
      canSend = () => true,
    } = {}) {
      if (
        counter.snapshot().mode !== "cleanup" ||
        typeof canSend !== "function" ||
        typeof operationPrefix !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$/.test(operationPrefix)
      )
        throw new Error("invalid confirmed exception cleanup");
      const cleanedNames = [],
        cleanupFailures = [];
      const names = [...confirmed.keys()].toSorted();
      for (const [index, name] of names.entries()) {
        if (!canSend()) break;
        if (
          !ownership.unresolved().includes(name) ||
          confirmed.get(name).mutationOrdinal !== lastMutation.get(name)
        )
          continue;
        const metadataOperationId = `${operationPrefix}-${index}-metadata`;
        const mediaOperationId = `${operationPrefix}-${index}-media`;
        const path = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
        try {
          for (const [id, query] of [
            [metadataOperationId, {}],
            [mediaOperationId, { alt: "media" }],
          ]) {
            if (!canSend()) throw new Error("cleanup transport unavailable");
            await sender.sendStep({
              id,
              dialect: "gcs",
              method: "GET",
              objectName: name,
              path,
              query,
              credential: "admin",
            });
          }
          if (!canSend()) throw new Error("cleanup transport unavailable");
          await sender.cleanupOwned({
            name,
            metadataOperationId,
            mediaOperationId,
            operationId: `${operationPrefix}-${index}-delete`,
          });
          cleanedNames.push(name);
        } catch {
          cleanupFailures.push({ name, reason: "CONFIRMED_EXCEPTION_CLEANUP_FAILED" });
        }
      }
      return { cleanedNames, cleanupFailures, unresolved: sender.unresolved() };
    },
    async cleanupOwned({ name, metadataOperationId, mediaOperationId, operationId } = {}) {
      if (counter.snapshot().mode !== "cleanup") throw new Error("owned cleanup phase is required");
      const current = ownedReadbacks(name, metadataOperationId, mediaOperationId);
      const prior = confirmed.get(name);
      if (
        !prior ||
        prior.generation !== current.generation ||
        prior.bytesSha256 !== current.bytesSha256 ||
        prior.mutationOrdinal !== lastMutation.get(name)
      )
        throw new Error("owned cleanup readbacks do not match the confirmed write");
      const path = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
      const deletion = await countedFetch(
        operationId,
        path,
        { ifGenerationMatch: current.generation },
        { method: "DELETE", headers: adminHeaders() },
        async () => {
          await onJournal({
            bucket,
            prefix,
            name,
            operationId,
            method: "DELETE",
            ifGenerationMatch: current.generation,
          });
          ownership.cleanupRequest(name, current);
        },
      );
      if (deletion.status !== 204) throw new Error("owned conditional delete was not confirmed");
      const metadata = await countedFetch(
        `${operationId}-metadata-absence`,
        path,
        {},
        { method: "GET", headers: adminHeaders() },
      );
      const media = await countedFetch(
        `${operationId}-media-absence`,
        path,
        { alt: "media" },
        { method: "GET", headers: adminHeaders() },
      );
      ownership.noteDeleted(name, {
        status: deletion.status,
        metadataStatus: metadata.status,
        mediaStatus: media.status,
      });
      confirmed.delete(name);
      return deletion;
    },
    async verifyRunEmpty() {
      if (context && (!namespaceAdmitted || counter.snapshot().mode !== "cleanup"))
        throw new Error("admitted namespace and cleanup phase are required for terminal proof");
      if (sender.unresolved().length > 0)
        throw new Error("owned objects or sessions remain unresolved");
      const response = await countedFetch(
        "final-prefix-list",
        `/storage/v1/b/${bucket}/o`,
        { prefix, maxResults: "1000" },
        { method: "GET", headers: adminHeaders() },
      );
      if (response.status !== 200) throw new Error("final prefix list failed");
      const items = completePrefixList(response, bucket, prefix);
      const empty = ownership.verifyEmpty({
        bucket,
        prefix,
        pages: [{ items, nextPageToken: null }],
      });
      if (context) {
        const proof = Object.freeze({
          type: "recipe-terminal",
          bucket,
          prefix,
          recording: context.recording,
          recipeId: context.recipeId,
          sequence: counter.snapshot().total,
          namespaceEmpty: true,
        });
        const persistTerminal = async () => {
          await onJournal(proof);
          if (production)
            productionAdmitted(
              Object.freeze({
                recording: context.recording,
                phase: counter.snapshot().mode,
                kind: "storage",
                operationId: context.dispatchOperationId("final-prefix-list"),
              }),
            );
          if (counter.snapshot().total !== proof.sequence || sender.unresolved().length !== 0)
            throw new Error("recipe terminal proof became stale");
          terminalProof = Object.freeze(proof);
        };
        if (!production) await persistTerminal();
        else
          try {
            await persistTerminal();
          } catch {
            productionFailed = true;
            throw new Error("production sender terminal proof is unavailable");
          }
      }
      return empty;
    },
    beginCleanup: () => counter.beginCleanup(),
    nextRecording: () => counter.nextRecording(),
    enterRecovery: () => counter.enterRecovery(),
    close: () => {
      if (
        context &&
        (productionFailed ||
          !terminalProof ||
          terminalProof.sequence !== counter.snapshot().total ||
          sender.unresolved().length !== 0)
      )
        throw new Error("fresh durable recipe terminal proof required");
      counter.close();
      if (context) recipeClosed = true;
    },
    unresolved: () =>
      [
        ...new Set([
          ...ownership.unresolved(),
          ...(auth?.unresolved() ?? []),
          ...[...sessions]
            .filter(([, session]) => !session.completed && !session.cancelled)
            .map(([name]) => name),
        ]),
      ].toSorted(),
  };
  if (context) {
    senderClosureProofs.set(sender, (proof) =>
      Boolean(
        !productionFailed &&
        recipeClosed &&
        terminalProof &&
        context.isActive() &&
        counter.snapshot().globalMode === "cleanup" &&
        terminalProof.sequence === counter.snapshot().total &&
        proof?.recipeToken === recipeToken &&
        proof.recording === context.recording &&
        proof.recipeId === context.recipeId &&
        proof.prefix === prefix &&
        proof.sequence === terminalProof.sequence &&
        sender.unresolved().length === 0,
      ),
    );
    return Object.freeze(sender);
  }
  return sender;
}
