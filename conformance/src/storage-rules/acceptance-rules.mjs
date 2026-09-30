import { googleError, isObject, isTimestamp, jsonBody, result, unexpected, digest } from "./acceptance-core.mjs";

// Closed response schemas of the Firebase Rules REST API (rulesets, releases, list, test), read from the published
// reference. A schema says what a response is, never whether a step wants it. Names are compared to the row's own
// request; source text becomes a digest and never reaches a fact.
const RULESET_NAME = /^projects\/fireemu-oracle-query\/rulesets\/[A-Za-z0-9_-]{1,128}$/;
const RELEASE_NAME = /^projects\/fireemu-oracle-query\/releases\/firebase\.storage(?:\/[a-z0-9][a-z0-9._-]{2,221})?$/;
const PAGE_TOKEN = /^[A-Za-z0-9._~+/=-]{1,2048}$/;
const SEVERITIES = new Set(["SEVERITY_UNSPECIFIED", "DEPRECATION", "WARNING", "ERROR"]);
const onlyKeys = (value, allowed) => Object.keys(value).every((key) => allowed.includes(key));
const notFound = (response) => googleError(response, 404, "NOT_FOUND");
const emptyObject = (response) => response.status === 200 && isObject(jsonBody(response)) && Object.keys(jsonBody(response)).length === 0;

function rulesetOf(body) {
  if (!isObject(body) || !onlyKeys(body, ["name", "createTime", "source", "metadata"]) || typeof body.name !== "string" || !RULESET_NAME.test(body.name) || !isTimestamp(body.createTime)) return null;
  if (!isObject(body.source) || !onlyKeys(body.source, ["files"]) || !Array.isArray(body.source.files) || body.source.files.length !== 1) return null;
  const file = body.source.files[0];
  if (!isObject(file) || !onlyKeys(file, ["name", "content", "fingerprint"]) || file.name !== "storage.rules" || typeof file.content !== "string" || (file.fingerprint !== undefined && typeof file.fingerprint !== "string")) return null;
  if (body.metadata !== undefined && !isObject(body.metadata)) return null;
  return { name: body.name, createTime: body.createTime, content: file.content };
}

function releaseOf(body, expectedName) {
  if (!isObject(body) || !onlyKeys(body, ["name", "rulesetName", "createTime", "updateTime"]) || body.name !== expectedName || !RELEASE_NAME.test(body.name)) return null;
  if (typeof body.rulesetName !== "string" || !RULESET_NAME.test(body.rulesetName) || !isTimestamp(body.createTime) || !isTimestamp(body.updateTime)) return null;
  return { name: body.name, rulesetName: body.rulesetName, updateTime: body.updateTime };
}
// A listed ruleset as production returns it: its name and creation time, and the metadata Firebase adds (the services it serves, such as
// `firebase.storage` or `cloud.firestore`). The page reports each entry's name and sorted services, never its creation time or source.
const SERVICE_NAME = /^[a-z][a-z0-9._-]{0,63}$/;
function listEntryOf(entry) {
  if (!isObject(entry) || !onlyKeys(entry, ["name", "createTime", "metadata"]) || typeof entry.name !== "string" || !RULESET_NAME.test(entry.name) || !isTimestamp(entry.createTime)) return null;
  let services = [];
  if (entry.metadata !== undefined) {
    const metadata = entry.metadata;
    if (!isObject(metadata) || !onlyKeys(metadata, ["services"])) return null;
    if (metadata.services !== undefined) {
      if (!Array.isArray(metadata.services) || metadata.services.length > 8 || !metadata.services.every((service) => typeof service === "string" && SERVICE_NAME.test(service))) return null;
      services = [...metadata.services].sort();
    }
  }
  return { name: entry.name, services };
}
const pathName = (row) => (typeof row.request.path === "string" && row.request.path.startsWith("/v1/") ? row.request.path.slice(4) : null);

export const RULES_CLASSIFIERS = {
  "rules-ruleset-create": (row, response) => {
    const ruleset = response.status === 200 ? rulesetOf(jsonBody(response)) : null;
    const sent = row.request.body?.json?.source?.files?.[0]?.content;
    if (ruleset && typeof sent === "string" && ruleset.content === sent) return result("rules-ruleset-create", "accepted", { status: 200, rulesetName: ruleset.name, createTime: ruleset.createTime, sourceSha256: digest(Buffer.from(ruleset.content)) });
    return unexpected("rules-ruleset-create", response);
  },
  "rules-ruleset-read": (row, response) => {
    const ruleset = response.status === 200 ? rulesetOf(jsonBody(response)) : null;
    if (ruleset) return result("rules-ruleset-read", "present", { status: 200, rulesetName: ruleset.name, createTime: ruleset.createTime, sourceSha256: digest(Buffer.from(ruleset.content)) });
    if (notFound(response)) return result("rules-ruleset-read", "absent", { status: 404 });
    return unexpected("rules-ruleset-read", response);
  },
  "rules-ruleset-delete": (row, response) => (emptyObject(response) ? result("rules-ruleset-delete", "accepted", { status: 200 }) : unexpected("rules-ruleset-delete", response)),
  "rules-release-read": (row, response) => {
    const expected = pathName(row);
    const release = response.status === 200 && expected !== null ? releaseOf(jsonBody(response), expected) : null;
    if (release) return result("rules-release-read", "present", { status: 200, releaseName: release.name, rulesetName: release.rulesetName, updateTime: release.updateTime });
    if (notFound(response)) return result("rules-release-read", "absent", { status: 404 });
    return unexpected("rules-release-read", response);
  },
  "rules-release-create": (row, response) => {
    const release = response.status === 200 ? releaseOf(jsonBody(response), row.request.body?.json?.name) : null;
    return release ? result("rules-release-create", "accepted", { status: 200, releaseName: release.name, rulesetName: release.rulesetName, updateTime: release.updateTime }) : unexpected("rules-release-create", response);
  },
  "rules-release-patch": (row, response) => {
    const expected = pathName(row);
    const release = response.status === 200 && expected !== null ? releaseOf(jsonBody(response), expected) : null;
    return release ? result("rules-release-patch", "accepted", { status: 200, releaseName: release.name, rulesetName: release.rulesetName, updateTime: release.updateTime }) : unexpected("rules-release-patch", response);
  },
  "rules-release-delete": (row, response) => (emptyObject(response) ? result("rules-release-delete", "accepted", { status: 200 }) : unexpected("rules-release-delete", response)),
  "rules-list-page": (row, response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    if (isObject(body) && onlyKeys(body, ["rulesets", "nextPageToken"])) {
      const list = body.rulesets === undefined ? [] : body.rulesets;
      const token = body.nextPageToken;
      const tokenOk = token === undefined || (typeof token === "string" && PAGE_TOKEN.test(token));
      const entries = Array.isArray(list) && list.length <= 100 ? list.map(listEntryOf) : [];
      if (Array.isArray(list) && list.length <= 100 && tokenOk && entries.every((entry) => entry !== null)) {
        const rulesets = entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
        return result("rules-list-page", "accepted", { status: 200, count: list.length, hasNextPage: token !== undefined, ...(token === undefined ? {} : { nextPageToken: token }), rulesets });
      }
    }
    return unexpected("rules-list-page", response);
  },
  "rules-test": (row, response) => {
    if (googleError(response, 400, "INVALID_ARGUMENT")) return result("rules-test", "rejected", { status: 400, issues: 0, errors: 0 });
    const body = response.status === 200 ? jsonBody(response) : undefined;
    if (isObject(body) && onlyKeys(body, ["issues", "testResults"])) {
      const issues = body.issues === undefined ? [] : body.issues;
      const results = body.testResults === undefined ? [] : body.testResults;
      const valid = (issue) => isObject(issue) && onlyKeys(issue, ["sourcePosition", "description", "severity"]) && typeof issue.description === "string" && issue.description.length <= 4096 && SEVERITIES.has(issue.severity) && isObject(issue.sourcePosition);
      if (Array.isArray(issues) && issues.length <= 1000 && issues.every(valid) && Array.isArray(results) && results.every(isObject)) {
        const errors = issues.filter((issue) => issue.severity === "ERROR").length;
        return result("rules-test", errors === 0 ? "accepted" : "rejected", { status: 200, issues: issues.length, errors });
      }
    }
    return unexpected("rules-test", response);
  },
};
