import { validateStorageRoute } from "./sender.mjs";

const STORAGE_QUERY_KEYS = new Set([
  "name",
  "alt",
  "uploadType",
  "generation",
  "prefix",
  "maxResults",
  "delimiter",
  "pageToken",
  "startOffset",
  "endOffset",
  "matchGlob",
  "ifGenerationMatch",
  "ifGenerationNotMatch",
  "ifMetagenerationMatch",
  "ifMetagenerationNotMatch",
  "ifSourceGenerationMatch",
  "ifSourceGenerationNotMatch",
  "ifSourceMetagenerationMatch",
  "ifSourceMetagenerationNotMatch",
  "rewriteToken",
  "create_token",
  "delete_token",
  "token",
]);

function dataRecord(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    throw new Error();
  const result = Object.create(null);
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
    result[name] = descriptor.value;
  }
  return result;
}

function storageBoundary(value) {
  const config = dataRecord(value);
  const { bucket, prefix } = config;
  if (
    typeof bucket !== "string" ||
    bucket.length < 3 ||
    bucket.length > 222 ||
    !bucket.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) ||
    typeof prefix !== "string" ||
    !/^storage-object\/[a-z0-9]{8,32}\/$/.test(prefix)
  )
    throw new Error();
  return { bucket, prefix };
}

function controlBoundary(value) {
  const config = dataRecord(value);
  storageBoundary(config);
  const { projectId, projectNumber, apiKeyResource, rulesetResource } = config;
  if (
    Object.keys(config).some(
      (key) =>
        ![
          "projectId",
          "projectNumber",
          "bucket",
          "prefix",
          "apiKeyResource",
          "rulesetResource",
        ].includes(key),
    ) ||
    typeof projectId !== "string" ||
    !/^[a-z][a-z0-9-]{4,29}$/.test(projectId) ||
    typeof projectNumber !== "string" ||
    !/^[1-9][0-9]{5,19}$/.test(projectNumber) ||
    typeof apiKeyResource !== "string" ||
    !apiKeyResource.startsWith(`projects/${projectNumber}/locations/global/keys/`) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(
      apiKeyResource.slice(`projects/${projectNumber}/locations/global/keys/`.length),
    ) ||
    typeof rulesetResource !== "string" ||
    !rulesetResource.startsWith(`projects/${projectId}/rulesets/`) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(rulesetResource.slice(`projects/${projectId}/rulesets/`.length))
  )
    throw new Error();
  return config;
}

function checkStorageFamily(step, { bucket }) {
  const conditions = [
    "ifGenerationMatch",
    "ifGenerationNotMatch",
    "ifMetagenerationMatch",
    "ifMetagenerationNotMatch",
  ];
  let keys;
  if (step.transfer !== undefined) {
    keys = [
      ...conditions,
      "ifSourceGenerationMatch",
      "ifSourceGenerationNotMatch",
      "ifSourceMetagenerationMatch",
      "ifSourceMetagenerationNotMatch",
      ...(step.transfer.operation === "rewriteTo" ? ["rewriteToken"] : []),
    ];
  } else if (step.collection === true) {
    keys = [
      "prefix",
      "maxResults",
      "delimiter",
      "pageToken",
      ...(step.dialect === "gcs" ? ["startOffset", "endOffset", "matchGlob"] : []),
    ];
  } else if (
    step.path ===
    (step.dialect === "gcs" ? `/upload/storage/v1/b/${bucket}/o` : `/v0/b/${bucket}/o`)
  ) {
    if (step.method !== "POST") throw new Error();
    if (
      step.dialect === "gcs" &&
      !["media", "multipart", "resumable"].includes(step.query.uploadType)
    )
      throw new Error();
    keys = ["name", ...conditions, ...(step.dialect === "gcs" ? ["uploadType"] : [])];
  } else if (step.dialect === "firebase" && step.method === "POST") {
    const names = Object.keys(step.query);
    if (
      names.length !== 1 ||
      !["create_token", "delete_token"].includes(names[0]) ||
      (names[0] === "create_token" && step.query.create_token !== "true")
    )
      throw new Error();
    keys = ["create_token", "delete_token"];
  } else {
    const collection = step.dialect === "gcs" ? `/storage/v1/b/${bucket}/o` : `/v0/b/${bucket}/o`;
    if (step.path !== `${collection}/${encodeURIComponent(step.objectName)}`) throw new Error();
    if (
      !["GET", "PATCH", "PUT", "DELETE"].includes(step.method) ||
      (step.dialect === "firebase" && step.method === "PUT")
    )
      throw new Error();
    keys = [
      ...conditions,
      ...(step.method === "GET"
        ? ["alt", "generation", ...(step.dialect === "firebase" ? ["token"] : [])]
        : []),
    ];
  }
  if (Object.keys(step.query).some((key) => !keys.includes(key))) throw new Error();
}

/** Resolve only the direct, owned Storage route. Session URLs require a separate capture binding. */
export function resolveProductionStorageRoute(value, boundary) {
  try {
    const config = storageBoundary(boundary);
    const step = dataRecord(value);
    step.query = dataRecord(step.query);
    if (step.transfer !== undefined) step.transfer = dataRecord(step.transfer);
    for (const [key, entry] of Object.entries(step.query)) {
      if (
        !STORAGE_QUERY_KEYS.has(key) ||
        typeof entry !== "string" ||
        !entry.isWellFormed() ||
        Buffer.byteLength(entry) > 8192
      )
        throw new Error();
      if (
        ["startOffset", "endOffset", "matchGlob"].includes(key) &&
        !entry.startsWith(config.prefix)
      )
        throw new Error();
    }
    if (typeof step.objectName === "string" && !step.objectName.isWellFormed()) throw new Error();
    if (validateStorageRoute(step, config) !== "direct") throw new Error();
    checkStorageFamily(step, config);
    const service = step.dialect === "firebase" ? "firebasestorage" : "storage";
    const url = new URL(step.path, `https://${service}.googleapis.com`);
    for (const [key, entry] of Object.entries(step.query)) url.searchParams.set(key, entry);
    if (Buffer.byteLength(url.href) > 8192) throw new Error();
    return Object.freeze({
      method: step.method,
      url: url.href,
      objectName: step.collection === true ? null : step.objectName,
      mutation: step.method !== "GET",
    });
  } catch {
    throw new Error("invalid production Storage route");
  }
}

/** Resolve fixed control templates; this supplies no credentials, phase admission or HTTP transport. */
export function resolveProductionControlRoute(kind, boundary, suppliedParameters = {}) {
  try {
    const config = controlBoundary(boundary);
    const parameters = dataRecord(suppliedParameters);
    const release = `projects/${config.projectId}/releases/firebase.storage/${config.bucket}`;
    const bucketless = `projects/${config.projectId}/releases/firebase.storage`;
    const project = `projects/${config.projectId}`;
    const routes = {
      "owner-exchange": ["POST", "oauth2", "/token", "none", "owner-refresh"],
      "owner-tokeninfo": ["POST", "oauth2", "/tokeninfo", "admin", "owner-tokeninfo"],
      "project-binding": ["GET", "cloudresourcemanager", `/v1/${project}`, "admin", "owner-json"],
      "bucket-config": ["GET", "storage", `/storage/v1/b/${config.bucket}`, "admin", "owner-json"],
      "default-bucket": [
        "GET",
        "firebasestorage",
        `/v1alpha/${project}/defaultBucket`,
        "admin",
        "owner-json",
      ],
      "auth-config": [
        "GET",
        "identitytoolkit",
        `/admin/v2/${project}/config`,
        "admin",
        "owner-json",
      ],
      "api-key-metadata": ["GET", "apikeys", `/v2/${config.apiKeyResource}`, "admin", "owner-json"],
      "api-key-value": [
        "GET",
        "apikeys",
        `/v2/${config.apiKeyResource}/keyString`,
        "admin",
        "owner-json",
      ],
      "rules-release": ["GET", "firebaserules", `/v1/${release}`, "admin", "owner-json"],
      "rules-bucketless": ["GET", "firebaserules", `/v1/${bucketless}`, "admin", "owner-json"],
      "rules-ruleset": [
        "GET",
        "firebaserules",
        `/v1/${config.rulesetResource}`,
        "admin",
        "owner-json",
      ],
      "rules-list": ["GET", "firebaserules", `/v1/${project}/releases`, "admin", "owner-json"],
      "rules-release-delete": ["DELETE", "firebaserules", `/v1/${release}`, "admin", "owner-json"],
      "rules-ruleset-delete": [
        "DELETE",
        "firebaserules",
        `/v1/${config.rulesetResource}`,
        "admin",
        "owner-json",
      ],
      "auth-admin-lookup": [
        "POST",
        "identitytoolkit",
        `/v1/${project}/accounts:lookup`,
        "admin",
        "owner-json",
      ],
      "auth-admin-delete": [
        "POST",
        "identitytoolkit",
        `/v1/${project}/accounts:delete`,
        "admin",
        "owner-json",
      ],
      "auth-signup": ["POST", "identitytoolkit", "/v1/accounts:signUp", "none", "client-json"],
      "auth-token-lookup": [
        "POST",
        "identitytoolkit",
        "/v1/accounts:lookup",
        "none",
        "client-json",
      ],
      "auth-signin": [
        "POST",
        "identitytoolkit",
        "/v1/accounts:signInWithPassword",
        "none",
        "client-json",
      ],
      "auth-refresh": ["POST", "securetoken", "/v1/token", "none", "client-form"],
    };
    if (typeof kind !== "string" || !Object.hasOwn(routes, kind)) throw new Error();
    const [method, service, path, credential, headerProfile] = routes[kind];
    const url = new URL(path, `https://${service}.googleapis.com`);
    const client = ["client-json", "client-form"].includes(headerProfile);
    const allowed = client ? ["apiKey"] : kind === "rules-list" ? ["pageToken"] : [];
    if (Object.keys(parameters).some((key) => !allowed.includes(key))) throw new Error();
    if (client) {
      if (
        typeof parameters.apiKey !== "string" ||
        !/^[A-Za-z0-9_-]{1,256}$/.test(parameters.apiKey)
      )
        throw new Error();
      url.searchParams.set("key", parameters.apiKey);
    }
    if (kind === "rules-list") {
      url.searchParams.set("pageSize", "100");
      if (Object.hasOwn(parameters, "pageToken")) {
        if (
          typeof parameters.pageToken !== "string" ||
          !/^[\x21-\x7e]{1,4096}$/.test(parameters.pageToken)
        )
          throw new Error();
        url.searchParams.set("pageToken", parameters.pageToken);
      }
    }
    return Object.freeze({
      method,
      url: url.href,
      credential,
      headerProfile,
      quotaProject: headerProfile === "owner-json" ? config.projectId : null,
    });
  } catch {
    throw new Error("invalid production control route");
  }
}
