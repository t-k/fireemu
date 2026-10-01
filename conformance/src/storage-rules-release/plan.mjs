import { createHash } from "node:crypto";
import { bucketReleaseName, BUCKETLESS_RELEASE_NAME, isBucket, isRulesetName, parseBaseline, PROJECT_ID, RELEASES_URL, rulesUrl } from "./release.mjs";

// Stage 2c: two runs against the query project's Firebase Rules releases. `pre` moves the bucket release out of the way (11 requests at
// most: five preflight reads, the deletion and two absence reads, and the three requests that put the release back if the deletion's
// result is wrong or unknown). `post` publishes it again after the recordings (8 requests at most: the same five preflight reads, the
// publication and its readback, and one read as its recovery).
export const MODES = Object.freeze(["pre", "post"]);
const COMMON = { token: "preflight/auth/owner-token", identity: "preflight/owner/identity", ruleset: "preflight/ruleset/saved", bucket: "preflight/release/bucket", bucketless: "preflight/release/bucketless" };
const PRE = Object.freeze({ ...COMMON, remove: "release/bucket/delete", absence: "release/bucket/absence", absenceBucketless: "release/bucketless/absence", current: "recovery/release/bucket/current", restore: "recovery/release/bucket/restore", restored: "recovery/release/bucket/after" });
const POST = Object.freeze({ ...COMMON, create: "release/bucket/create", after: "release/bucket/after", current: "recovery/release/bucket/current" });
export const IDS = Object.freeze({ pre: PRE, post: POST });
export const PREFLIGHT_IDS = Object.freeze([COMMON.token, COMMON.identity, COMMON.ruleset, COMMON.bucket, COMMON.bucketless]);
export const ALL_IDS = Object.freeze({
  pre: Object.freeze([...PREFLIGHT_IDS, PRE.remove, PRE.absence, PRE.absenceBucketless, PRE.current, PRE.restore, PRE.restored]),
  post: Object.freeze([...PREFLIGHT_IDS, POST.create, POST.after, POST.current]),
});
export const MAX_REQUESTS = Object.freeze({ pre: ALL_IDS.pre.length, post: ALL_IDS.post.length });
const sha = (value) => createHash("sha256").update(value).digest("hex");

/**
 * The operation corpus the approval pins as its manifest: every request with its method, URL and body, the bucket, the ruleset the release
 * must point at, the owner's address digest, for `pre` the baseline (times and digests of the release and the ruleset) it confirms before writing, and for `post` the digest of the saved record the release is published from.
 */
export function releaseCorpus({ mode, bucket, rulesetName, ownerEmailSha256, savedSha256 = null, baseline = null }) {
  if (!MODES.includes(mode) || !isBucket(bucket) || !isRulesetName(rulesetName) || typeof ownerEmailSha256 !== "string" || !/^[0-9a-f]{64}$/.test(ownerEmailSha256)) throw new Error("invalid corpus input");
  if ((mode === "post") !== (savedSha256 !== null) || (savedSha256 !== null && !/^[0-9a-f]{64}$/.test(savedSha256))) throw new Error("invalid corpus input");
  // A `pre` run confirms the baseline before it writes, so the baseline is part of what the approval pins; `post` has none.
  if ((mode === "pre") !== (baseline !== null)) throw new Error("invalid corpus input");
  const pinnedBaseline = baseline === null ? null : parseBaseline(baseline);
  const releaseUrl = rulesUrl(bucketReleaseName(bucket));
  const publish = { method: "POST", url: RELEASES_URL, body: { name: bucketReleaseName(bucket), rulesetName } };
  const ids = IDS[mode];
  const shared = [
    { id: ids.token, method: "POST", url: "https://oauth2.googleapis.com/token" },
    { id: ids.identity, method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo" },
    { id: ids.ruleset, method: "GET", url: rulesUrl(rulesetName) },
    { id: ids.bucket, method: "GET", url: releaseUrl },
    { id: ids.bucketless, method: "GET", url: rulesUrl(BUCKETLESS_RELEASE_NAME) },
  ];
  const list = mode === "pre"
    ? [...shared, { id: ids.remove, method: "DELETE", url: releaseUrl }, { id: ids.absence, method: "GET", url: releaseUrl }, { id: ids.absenceBucketless, method: "GET", url: rulesUrl(BUCKETLESS_RELEASE_NAME) },
      { id: ids.current, method: "GET", url: releaseUrl }, { id: ids.restore, ...publish }, { id: ids.restored, method: "GET", url: releaseUrl }]
    : [...shared, { id: ids.create, ...publish }, { id: ids.after, method: "GET", url: releaseUrl }, { id: ids.current, method: "GET", url: releaseUrl }];
  const document = { mode, project: PROJECT_ID, bucket, rulesetName, ownerEmailSha256, savedSha256, baseline: pinnedBaseline, list };
  return Object.freeze({ list, sha256: sha(JSON.stringify(document)) });
}
