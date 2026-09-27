import { createRunOwnership } from "./ownership.mjs";
import { createStage3RequestCounter } from "./request-counter.mjs";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

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
export function createLocalStorageSender({
  plan,
  origin,
  fetchImpl,
  onStart,
  onReserve,
  onJournal,
  credentials = {},
} = {}) {
  const base = localOrigin(origin);
  if (typeof fetchImpl !== "function" || typeof onJournal !== "function")
    throw new Error("fetch and durable ownership journal writers are required");
  if (plan?.status !== "LOCAL_DRAFT_NO_SEND" || plan.recordings?.length !== 2)
    throw new Error("a reviewed two-recording draft shape is required");
  const bucket = plan.bucket;
  const prefix = plan.recordings[0].prefix;
  const ownership = createRunOwnership({ bucket, prefix });
  const counter = createStage3RequestCounter(plan, { onStart, onReserve });
  let namespaceAdmitted = false;
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials))
    throw new Error("invalid local credentials");

  async function countedFetch(operationId, path, query, init, beforeFetch = async () => {}) {
    const url = new URL(path, base);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (typeof value !== "string") throw new Error("unresolved request query");
      url.searchParams.set(key, value);
    }
    return counter.send(operationId, async () => {
      await beforeFetch();
      const response = await fetchImpl(url.href, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
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

  return {
    start: () => counter.start(),
    snapshot: () => counter.snapshot(),
    async admitNamespace() {
      if (namespaceAdmitted) throw new Error("namespace was already admitted");
      const response = await countedFetch(
        "initial-prefix-list",
        `/storage/v1/b/${bucket}/o`,
        { prefix, maxResults: "1000" },
        { method: "GET", headers: {} },
      );
      if (response.status !== 200) throw new Error("initial prefix list failed");
      let parsed;
      try {
        parsed = JSON.parse(response.raw.toString("utf8"));
      } catch {
        throw new Error("initial prefix list is not JSON");
      }
      if (parsed?.nextPageToken) throw new Error("initial prefix list is incomplete");
      ownership.assertInitialEmpty({
        bucket,
        prefix,
        pages: [{ items: parsed?.items ?? [], nextPageToken: null }],
      });
      namespaceAdmitted = true;
    },
    admitObject(name) {
      if (!namespaceAdmitted) throw new Error("initial namespace is unproved");
      return ownership.noteInitialAbsentFromNamespace(name);
    },
    async sendStep(step, { operationId = step?.id } = {}) {
      if (counter.snapshot().mode === "not-started") throw new Error("no durable started row");
      const route = validateStorageRoute(step, { bucket, prefix });
      if (route !== "direct") throw new Error("session reference is unresolved");
      if (step.method === "DELETE") throw new Error("cleanup requires owned-generation proof");
      const headers = { ...step.headers };
      if (step.credential !== undefined && step.credential !== "none") {
        const authorization = credentials[step.credential];
        if (typeof authorization !== "string" || !/^(Bearer|Firebase) [^\s]+$/.test(authorization))
          throw new Error("local credential is unresolved");
        headers.authorization = authorization;
      }
      const body = encodeBody(step.body);
      const mutates = !["GET", "HEAD"].includes(step.method);
      if (mutates && !namespaceAdmitted) throw new Error("initial namespace is unproved");
      return countedFetch(
        operationId,
        step.path,
        step.query,
        { method: step.method, headers, body },
        mutates
          ? async () => {
              await onJournal({
                bucket,
                prefix,
                name: step.objectName,
                operationId,
                method: step.method,
              });
              ownership.noteMutationAttempt(step.objectName, operationId);
            }
          : undefined,
      );
    },
    beginCleanup: () => counter.beginCleanup(),
    nextRecording: () => counter.nextRecording(),
    enterRecovery: () => counter.enterRecovery(),
    close: () => counter.close(),
    unresolved: () => ownership.unresolved(),
  };
}
