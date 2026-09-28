import { createHash } from "node:crypto";
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
  let ordinal = 0;
  let runListProofSerial = 0;
  const attemptedInvalidProofNames = new Set();
  const observed = new Map();
  const lastMutation = new Map();
  const confirmed = new Map();
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials))
    throw new Error("invalid local credentials");

  function adminHeaders() {
    const authorization = credentials.admin;
    if (typeof authorization !== "string" || !/^Bearer [^\s]+$/.test(authorization))
      throw new Error("admin OAuth credential is unresolved");
    return { authorization };
  }

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

  return {
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
      if (observed.has(operationId) || operationId === "initial-prefix-list")
        throw new Error("request operation ID was already used");
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
      if (mutates && counter.snapshot().mode !== "subject")
        throw new Error("mutation outside the subject phase requires owned cleanup");
      const response = await countedFetch(
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
      observed.set(operationId, { step, response, ordinal: ++ordinal });
      if (mutates) lastMutation.set(step.objectName, ordinal);
      return response;
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
      ownership.observeOwnedGeneration(
        name,
        { ...current, operationId: uploadOperationId },
        expectedBytesSha256,
      );
      confirmed.set(name, { ...current, mutationOrdinal: upload.ordinal });
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
      let parsed;
      try {
        parsed = JSON.parse(listing.raw.toString("utf8"));
      } catch {
        throw new Error("subject absence prefix list is not JSON");
      }
      const proof = {
        operationId: mutationOperationId,
        status: mutation.response.status,
        metadataStatus: metadata.response.status,
        mediaStatus: media.response.status,
        prefixPagesComplete: !parsed?.nextPageToken,
        nameFound: Array.isArray(parsed?.items) && parsed.items.some((item) => item?.name === name),
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
      if (ownership.unresolved().length > 0) throw new Error("owned objects remain unresolved");
      const response = await countedFetch(
        "final-prefix-list",
        `/storage/v1/b/${bucket}/o`,
        { prefix, maxResults: "1000" },
        { method: "GET", headers: adminHeaders() },
      );
      if (response.status !== 200) throw new Error("final prefix list failed");
      let parsed;
      try {
        parsed = JSON.parse(response.raw.toString("utf8"));
      } catch {
        throw new Error("final prefix list is not JSON");
      }
      return ownership.verifyEmpty({
        bucket,
        prefix,
        pages: [{ items: parsed?.items ?? [], nextPageToken: parsed?.nextPageToken ?? null }],
      });
    },
    beginCleanup: () => counter.beginCleanup(),
    nextRecording: () => counter.nextRecording(),
    enterRecovery: () => counter.enterRecovery(),
    close: () => counter.close(),
    unresolved: () => ownership.unresolved(),
  };
}
