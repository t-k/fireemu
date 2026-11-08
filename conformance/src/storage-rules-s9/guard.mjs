// Request guard of the Storage Rules observation. Every request passes `classifyRequest` before it
// leaves the process: only the forms below, only the project's own bucket and release, only object
// names under the run's root (`storage-rules-s9/<runId>/`, with one optional leading slash), and a
// release body only with a ruleset this run created or the baseline ruleset the run must restore.

import { PREFIX_ROOT } from "./plan.mjs";

export { isUnknownStatus } from "../storage-signed-put/guard.mjs";

const HOSTS = {
  gcs: "storage.googleapis.com",
  firebase: "firebasestorage.googleapis.com",
  rules: "firebaserules.googleapis.com",
};
const RULESET_ID = /^[A-Za-z0-9_-]{1,128}$/;

export class GuardError extends Error {}

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

/** An object name this run may touch: under the run root, optionally behind one leading slash. */
export function ownedName(name, root) {
  const rest = name.startsWith("/") ? name.slice(1) : name;
  if (!rest.startsWith(root) || rest.length === root.length) return false;
  if ([...name].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f)) return false;
  // Empty segments are the point of some rows; dot segments never are.
  return !name.split("/").some((part) => part === "." || part === "..");
}

function checkName(name, root) {
  if (!ownedName(name, root)) fail("object outside the run root");
  return name;
}

function checkPrefix(prefix, root) {
  const rest = prefix.startsWith("/") ? prefix.slice(1) : prefix;
  if (!rest.startsWith(root)) fail("prefix outside the run root");
  if ([...prefix].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f))
    fail("control character in prefix");
  if (prefix.split("/").some((part) => part === "." || part === ".."))
    fail("dot segment in prefix");
}

function jsonBody(request) {
  try {
    return JSON.parse(Buffer.from(request.body ?? []).toString("utf8"));
  } catch {
    return fail("body is not JSON");
  }
}

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value, keys) =>
  plain(value) && Object.keys(value).length === keys.length && keys.every((k) => k in value);

/**
 * @param {object} target `{name: "production" | "local", bucket, project, origin?}`
 * @param {{method: string, url: string, headers?: object, body?: Uint8Array}} request
 * @param {{runId: string, root: string, ownRulesets: Set<string>, baseline: string}} state
 *   `ownRulesets`: full names of rulesets this run created. `baseline`: `"absent"`, a full ruleset
 *   name, or `"local"`.
 * @returns {string} the request kind
 */
export function classifyRequest(target, request, state) {
  const root = state.root;
  if (!root.startsWith(`${PREFIX_ROOT}/`) || !root.endsWith("/")) fail("bad run root");
  const url = new URL(request.url);
  if (url.username || url.password) fail("credentials in URL");
  const method = request.method;
  const headers = Object.fromEntries(
    Object.entries(request.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]),
  );
  const production = target.name === "production";
  if (production) {
    if (url.protocol !== "https:" || url.port) fail("host not allowed");
  } else if (target.name === "local") {
    if (url.origin !== new URL(target.origin).origin) fail("host not allowed");
  } else {
    fail("unknown target");
  }
  const hostOk = (kind) => !production || url.hostname === HOSTS[kind];
  const segments = url.pathname.split("/").slice(1);
  const keys = [...url.searchParams.keys()];
  const only = (allowed) => {
    if (keys.some((key) => !allowed.includes(key))) fail("query parameter not allowed");
    if (new Set(keys).size !== keys.length) fail("repeated query parameter");
  };
  const bucket = target.bucket;
  const adminHeaders = () => {
    if (!headers.authorization) fail("owner request without Authorization");
    if (production && headers["x-goog-user-project"] !== target.project)
      fail("owner request without the quota project");
  };
  const anonymous = () => {
    if (headers.authorization !== undefined) fail("anonymous request with Authorization");
  };

  if (!production && url.pathname === "/internal/setRules") {
    if (method !== "PUT") fail("setRules method");
    only([]);
    return "local-set-rules";
  }

  // Cloud Storage JSON API (owner credential: rules never apply).
  if (segments[0] === "storage" && segments[1] === "v1") {
    if (!hostOk("gcs")) fail("host not allowed");
    adminHeaders();
    if (decodeSegment(segments[2]) !== "b" || decodeSegment(segments[3] ?? "") !== bucket)
      fail("bucket not allowed");
    if (segments.length === 4) {
      if (method !== "GET") fail("bucket method");
      only([]);
      return "bucket-get";
    }
    if (segments.length === 5 && segments[4] === "o") {
      if (method !== "GET") fail("list method");
      only(["prefix", "maxResults"]);
      const prefix = url.searchParams.get("prefix");
      if (prefix === null) fail("list without a prefix");
      checkPrefix(prefix, root);
      return "gcs-list";
    }
    if (segments.length === 6 && segments[4] === "o") {
      checkName(decodeSegment(segments[5]), root);
      if (method === "GET") {
        only([]);
        return "gcs-get";
      }
      if (method === "DELETE") {
        only(["ifGenerationMatch"]);
        if (!/^[1-9]\d{0,19}$/.test(url.searchParams.get("ifGenerationMatch") ?? ""))
          fail("delete without a generation precondition");
        return "gcs-delete";
      }
    }
    return fail("storage JSON path");
  }
  if (segments[0] === "upload" && segments[1] === "storage" && segments[2] === "v1") {
    if (!hostOk("gcs")) fail("host not allowed");
    adminHeaders();
    if (decodeSegment(segments[4] ?? "") !== bucket || segments.length !== 6 || segments[5] !== "o")
      fail("upload path");
    if (method !== "POST") fail("upload method");
    only(["uploadType", "name", "ifGenerationMatch"]);
    const type = url.searchParams.get("uploadType");
    if (type !== "media" && type !== "multipart") fail("upload type");
    if (url.searchParams.get("ifGenerationMatch") !== "0")
      fail("upload without ifGenerationMatch=0");
    const name = checkName(url.searchParams.get("name") ?? "", root);
    if (type === "multipart") {
      // The metadata part names the same object and carries nothing but custom metadata.
      const contentType = headers["content-type"] ?? "";
      const boundary = /^multipart\/related; boundary=([A-Za-z0-9_-]{8,70})$/.exec(
        contentType,
      )?.[1];
      if (!boundary) fail("multipart content type");
      const parts = Buffer.from(request.body ?? [])
        .toString("utf8")
        .split(`--${boundary}`);
      const jsonPart = parts[1]?.split("\r\n\r\n")[1]?.replace(/\r\n$/, "");
      let meta;
      try {
        meta = JSON.parse(jsonPart);
      } catch {
        return fail("multipart metadata part");
      }
      if (!exactKeys(meta, ["name", "metadata"]) || meta.name !== name || !plain(meta.metadata))
        fail("multipart metadata");
    }
    return "gcs-create";
  }

  // Firebase v0 API: anonymous reads under the rules in force.
  if (segments[0] === "v0") {
    if (!hostOk("firebase")) fail("host not allowed");
    anonymous();
    if (decodeSegment(segments[1]) !== "b" || decodeSegment(segments[2] ?? "") !== bucket)
      fail("bucket not allowed");
    if (method !== "GET") fail("v0 method");
    if (segments.length === 5 && segments[3] === "o") {
      checkName(decodeSegment(segments[4]), root);
      only(["alt"]);
      if (url.searchParams.has("alt") && url.searchParams.get("alt") !== "media") fail("alt");
      return url.searchParams.has("alt") ? "v0-media" : "v0-meta";
    }
    if (segments.length === 4 && segments[3] === "o") {
      only(["prefix", "delimiter"]);
      const prefix = url.searchParams.get("prefix");
      if (prefix === null) fail("list without a prefix");
      checkPrefix(prefix, root);
      if (url.searchParams.has("delimiter") && url.searchParams.get("delimiter") !== "/")
        fail("delimiter");
      return "v0-list";
    }
    return fail("v0 path");
  }

  // Firebase Rules API (production only).
  if (segments[0] === "v1" && segments[1] === "projects") {
    if (!production) fail("rules API on a local target");
    if (!hostOk("rules")) fail("host not allowed");
    adminHeaders();
    if (decodeSegment(segments[2] ?? "") !== target.project) fail("project not allowed");
    const releaseName = `projects/${target.project}/releases/firebase.storage/${bucket}`;
    const leaf = segments.slice(3).map(decodeSegment);
    if (leaf[0] === "rulesets" && leaf.length === 1) {
      if (method === "POST") {
        only([]);
        const body = jsonBody(request);
        const files = body?.source?.files;
        if (
          !exactKeys(body, ["source"]) ||
          !exactKeys(body.source, ["files"]) ||
          !Array.isArray(files) ||
          files.length !== 1 ||
          !exactKeys(files[0], ["name", "content"]) ||
          files[0].name !== "storage.rules" ||
          typeof files[0].content !== "string"
        )
          fail("ruleset body");
        return "ruleset-create";
      }
      if (method === "GET") {
        only(["pageSize"]);
        if (url.searchParams.has("pageSize") && url.searchParams.get("pageSize") !== "100")
          fail("page size");
        return "ruleset-list";
      }
    }
    if (leaf[0] === "rulesets" && leaf.length === 2) {
      if (!RULESET_ID.test(leaf[1])) fail("ruleset id");
      const full = `projects/${target.project}/rulesets/${leaf[1]}`;
      only([]);
      if (method === "GET") return "ruleset-get";
      if (method === "DELETE") {
        if (!state.ownRulesets.has(full)) fail("delete of a ruleset this run did not create");
        return "ruleset-delete";
      }
    }
    if (leaf[0] === "releases" && leaf.length === 1 && method === "POST") {
      only([]);
      const body = jsonBody(request);
      if (
        !exactKeys(body, ["name", "rulesetName"]) ||
        body.name !== releaseName ||
        !state.ownRulesets.has(body.rulesetName)
      )
        fail("release create body");
      return "release-create";
    }
    if (leaf[0] === "releases" && leaf[1] === "firebase.storage" && leaf.length === 2) {
      if (method !== "GET") fail("bucketless release method");
      only([]);
      return "release-bucketless-get";
    }
    if (
      leaf[0] === "releases" &&
      leaf[1] === "firebase.storage" &&
      leaf[2] === bucket &&
      leaf.length === 3
    ) {
      only([]);
      if (method === "GET") return "release-get";
      if (method === "PATCH") {
        const body = jsonBody(request);
        if (
          !exactKeys(body, ["release", "updateMask"]) ||
          body.updateMask !== "rulesetName" ||
          !exactKeys(body.release, ["name", "rulesetName"]) ||
          body.release.name !== releaseName
        )
          fail("release patch body");
        if (
          !state.ownRulesets.has(body.release.rulesetName) &&
          body.release.rulesetName !== state.baseline
        )
          fail("release patch to a ruleset that is neither this run's nor the baseline");
        return "release-patch";
      }
      if (method === "DELETE") {
        if (state.baseline !== "absent") fail("release delete with a baseline release");
        return "release-delete";
      }
    }
    return fail("rules API path");
  }
  return fail("path");
}

/** The baseline is `absent` or a full ruleset name of the sandbox project. */
export function validateBaseline(value, project) {
  if (value === "absent") return value;
  if (
    typeof value !== "string" ||
    !new RegExp(`^projects/${project}/rulesets/[A-Za-z0-9_-]{1,128}$`).test(value)
  )
    fail("baseline is neither `absent` nor a ruleset of the sandbox project");
  return value;
}
