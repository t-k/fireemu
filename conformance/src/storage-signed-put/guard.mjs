// Request guard and budget of the signed PUT observation. Every request, raw or made by the SDK,
// passes `classifyRequest` before it leaves the process: only the forms below, only the project's
// own bucket, and every object name under the run prefix.

import { PREFIX_ROOT, ROLE_ID } from "./plan.mjs";

const PRODUCTION_HOSTS = new Set([
  "storage.googleapis.com",
  "iam.googleapis.com",
  "iamcredentials.googleapis.com",
  "cloudresourcemanager.googleapis.com",
]);
const SIGNED_PARAMS = [
  "X-Goog-Algorithm",
  "X-Goog-Credential",
  "X-Goog-Date",
  "X-Goog-Expires",
  "X-Goog-SignedHeaders",
];

export class GuardError extends Error {}

function fail(message) {
  throw new GuardError(`request refused: ${message}`);
}

function decodeSegment(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return fail("undecodable path segment");
  }
}

function checkName(name, prefix) {
  if (!name.startsWith(prefix)) fail("object outside the run prefix");
  if ([...name].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f)) {
    fail("control character in object name");
  }
  if (name.split("/").some((part) => part === ".." || part === "."))
    fail("dot segment in object name");
  return name;
}

export const POLICY_VERSION_PARAM = "options.requestedPolicyVersion";
const ROLE_NAME = /^[A-Za-z0-9_.-]{1,64}$/;

/** The iam.googleapis.com forms: the signer, its policy, the signer role, and role definitions. */
function classifyIam(target, method, segments, only, { url, body }) {
  const decoded = segments.map(decodeSegment);
  if (decoded[0] !== "v1") fail("IAM version");
  const account = `serviceAccounts`;
  const project = target.project;
  if (
    decoded.length === 5 &&
    decoded[1] === "projects" &&
    decoded[2] === project &&
    decoded[3] === account
  ) {
    const leaf = decoded[4];
    if (leaf === target.signer) {
      if (method !== "GET") fail("IAM method");
      only([]);
      return "signer-get";
    }
    for (const [suffix, kind] of [
      [":getIamPolicy", "signer-get-policy"],
      [":setIamPolicy", "signer-set-policy"],
    ]) {
      if (leaf === `${target.signer}${suffix}`) {
        if (method !== "POST") fail("IAM policy method");
        if (kind === "signer-get-policy") {
          // serviceAccounts.getIamPolicy takes the policy version as a query parameter and has no body.
          only([POLICY_VERSION_PARAM]);
          const values = url.searchParams.getAll(POLICY_VERSION_PARAM);
          if (values.length !== 1 || values[0] !== "3") fail("IAM policy version");
          if (body !== undefined && body.length !== 0) fail("IAM policy read has no body");
        } else {
          only([]);
        }
        return kind;
      }
    }
    return fail("IAM path");
  }
  if (
    decoded.length === 4 &&
    decoded[1] === "projects" &&
    decoded[2] === project &&
    decoded[3] === "roles"
  ) {
    if (method !== "POST") fail("IAM role method");
    only([]);
    return "role-create";
  }
  if (
    decoded.length === 5 &&
    decoded[1] === "projects" &&
    decoded[2] === project &&
    decoded[3] === "roles"
  ) {
    if (!ROLE_NAME.test(decoded[4])) fail("IAM role name");
    if (method === "DELETE" && decoded[4] === ROLE_ID) {
      only(["etag"]);
      return "role-delete";
    }
    if (method !== "GET") fail("IAM role method");
    only([]);
    return decoded[4] === ROLE_ID ? "role-get" : "role-read";
  }
  if (decoded.length === 3 && decoded[1] === "roles") {
    if (method !== "GET" || !ROLE_NAME.test(decoded[2])) fail("IAM predefined role");
    only([]);
    return "role-read";
  }
  return fail("IAM path");
}

/**
 * @param {object} target `{name: "production" | "local", bucket, project, signer, origin?}`;
 *   `origin` is the emulator origin for the local target.
 * @param {{method: string, url: string, headers?: object}} request
 * @param {string} prefix the run prefix, `storage-signed-put/<run>/`
 * @returns {string} the request kind
 */
export function classifyRequest(target, request, prefix) {
  if (!prefix.startsWith(`${PREFIX_ROOT}/`) || !prefix.endsWith("/")) fail("bad run prefix");
  const url = new URL(request.url);
  if (url.username || url.password) fail("credentials in URL");
  const method = request.method;
  const headers = Object.fromEntries(
    Object.entries(request.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]),
  );
  if (target.name === "production") {
    if (url.protocol !== "https:" || url.port || !PRODUCTION_HOSTS.has(url.hostname))
      fail("host not allowed");
  } else if (target.name === "local") {
    const origin = new URL(target.origin);
    if (url.origin !== origin.origin) fail("host not allowed");
  } else {
    fail("unknown target");
  }
  const segments = url.pathname.split("/").slice(1);
  const bucket = target.bucket;
  const keys = [...url.searchParams.keys()];
  const only = (allowed) => {
    if (keys.some((key) => !allowed.includes(key))) fail("query parameter not allowed");
  };
  const jsonBase = ["storage", "v1", "b", bucket];

  if (url.hostname === "iam.googleapis.com") {
    return classifyIam(target, method, segments, only, { url, body: request.body });
  }
  if (url.hostname === "cloudresourcemanager.googleapis.com") {
    if (method !== "POST") fail("resource manager method");
    const expected = ["v1", `projects`, `${target.project}:getIamPolicy`];
    if (segments.length !== 3 || segments.some((s, i) => decodeSegment(s) !== expected[i]))
      fail("resource manager path");
    only([]);
    return "project-policy";
  }
  if (url.hostname === "iamcredentials.googleapis.com") {
    if (method !== "POST") fail("IAM credentials method");
    const expected = ["v1", "projects", "-", "serviceAccounts", `${target.signer}:signBlob`];
    if (segments.length !== 5 || segments.some((s, i) => decodeSegment(s) !== expected[i]))
      fail("signBlob path");
    only([]);
    return "sign-blob";
  }
  if (segments[0] === "storage" && segments[1] === "v1") {
    const head = segments.slice(0, 4).map(decodeSegment);
    if (head.join("/") !== jsonBase.join("/")) fail("bucket not allowed");
    if (segments.length === 4) {
      if (method !== "GET") fail("bucket method");
      only([]);
      return "bucket-get";
    }
    if (segments.length === 5 && segments[4] === "iam") {
      if (method !== "GET") fail("bucket policy method");
      only(["optionsRequestedPolicyVersion"]);
      return "bucket-policy";
    }
    if (segments.length === 5 && segments[4] === "o") {
      if (method !== "GET") fail("list method");
      only(["prefix", "maxResults"]);
      const listed = url.searchParams.get("prefix");
      if (listed === null || !listed.startsWith(prefix)) fail("list prefix outside the run prefix");
      return "list";
    }
    if (segments.length === 6 && segments[4] === "o") {
      checkName(decodeSegment(segments[5]), prefix);
      if (method === "GET") {
        only(["alt"]);
        if (url.searchParams.has("alt") && url.searchParams.get("alt") !== "media") fail("alt");
        return "object-get";
      }
      if (method === "DELETE") {
        only(["ifGenerationMatch"]);
        return "object-delete";
      }
    }
    return fail("storage JSON path");
  }
  // XML API: /<bucket>/<object...>
  if (decodeSegment(segments[0] ?? "") !== bucket || segments.length < 2)
    fail("bucket not allowed");
  checkName(segments.slice(1).map(decodeSegment).join("/"), prefix);
  only([...SIGNED_PARAMS, "X-Goog-Signature"]);
  if (method !== "PUT" && method !== "OPTIONS") fail("XML method");
  if (headers.authorization !== undefined) fail("signed requests carry no Authorization header");
  for (const key of SIGNED_PARAMS) if (!url.searchParams.has(key)) fail(`signed URL lacks ${key}`);
  return method === "PUT" ? "xml-put" : "xml-options";
}

/**
 * The signer is named on the command line (the packet pins it); it must be a service account of
 * the sandbox project, so a typo can never sign as anyone else.
 */
export function validateSigner(value, project) {
  const domain = `${project}.iam.gserviceaccount.com`.replaceAll(".", "\\.");
  if (
    typeof value !== "string" ||
    !new RegExp(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@${domain}$`).test(value)
  ) {
    fail("signer is not a service account of the sandbox project");
  }
  return value;
}

/** A request counter with a main-phase cap and a total cap (cleanup may exceed the main cap). */
export class RequestBudget {
  constructor(mainCap, totalCap) {
    this.mainCap = mainCap;
    this.totalCap = totalCap;
    this.count = 0;
    this.cleanup = false;
  }

  take() {
    const cap = this.cleanup ? this.totalCap : this.mainCap;
    if (this.count + 1 > cap) throw new GuardError("request budget exhausted");
    this.count += 1;
    return this.count;
  }
}

/** Unknown by the shared rule: below 200, any 3xx, any 5xx. Transport failures are unknown too. */
export function isUnknownStatus(status) {
  return (
    !Number.isInteger(status) || status < 200 || (status >= 300 && status < 400) || status >= 500
  );
}

const SIGNATURE_PARAM = /([?&]X-Goog-Signature=)([0-9a-f]+)(?=&|$)/;

/** Flips the last hex digit of the signature in place; every other byte of the URL is kept. */
export function tamperSignature(url) {
  const match = SIGNATURE_PARAM.exec(url);
  if (!match) fail("no hex signature to tamper with");
  const signature = match[2];
  const flipped = signature.slice(0, -1) + (signature.at(-1) === "0" ? "1" : "0");
  return url.replace(SIGNATURE_PARAM, `$1${flipped}`);
}

/** Removes the signature parameter in place. */
export function dropSignature(url) {
  if (!SIGNATURE_PARAM.test(url)) fail("no signature to drop");
  return url.replace(/([?&])X-Goog-Signature=[0-9a-f]+&?/, "$1").replace(/[?&]$/, "");
}

/** Redacts the credential and signature of a signed URL for any stored text. */
export function redactSignedUrl(text) {
  return String(text)
    .replace(/(X-Goog-Signature=)[^&\s"']+/gi, "$1<redacted>")
    .replace(/(X-Goog-Credential=)[^&\s"']+/gi, "$1<redacted>");
}
