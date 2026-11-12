// The judge of the public onRequest malformed Bearer observation. Pure: it reads the four captures of one
// run (two passes of the control case and the malformed Bearer case, in that order) and the recorded
// baseline (bearer-observation.baseline.json), and says whether production answered the malformed Bearer
// with the provisional page fireemu strict returns today.
//
// Recorded answer (FUNCTIONS-HTTP-BEARER-20261110-01, conformance/functions-http-bearer-production.json):
// `different`. Production passed the malformed Bearer to the public onRequest function, which answered
// its 200 echo, byte-equal to the control. The provisional page is not production's answer for a real
// onRequest function. FUNCTIONS-HTTP-CALLABLE-INGRESS (2026-11-11, callable-ingress/) then recorded what
// a callable's code served as onRequest answers: the callable wrapper's own 401 envelope, not the page.
//
//   same-as-provisional  status, content-type, byte count and SHA-256 of the body equal the stage 3
//                        recorded 401 page (functions-http/callable/auth-refusal#malformed-bearer)
//   different            every capture is a complete, readable 2xx or 4xx answer, both passes agree,
//                        the control is the recorded echo shape, and the malformed answer differs:
//                        `differences` names each field (needs review before any change follows)
//   unknown              anything else (transport failure, 1xx/3xx/5xx, unreadable body, a
//                        content-length that disagrees with the bytes, passes that disagree, a control
//                        that is not the recorded echo shape, missing or misordered captures). Needs
//                        review; the coordinator keeps the project lock.
//
// Bodies are compared by their byte count and digest, never by stored text layout. Only content-type was
// recorded among the baseline's headers, so other headers are listed, never compared.

import { createHash } from "node:crypto";

export const CASE_IDS = Object.freeze(["no-authorization", "malformed-bearer"]);
const AUTHORIZATION = Object.freeze({
  "no-authorization": null,
  "malformed-bearer": "Bearer malformed",
});
// The frozen request body (bearer-observation.corpus.json), as the session sends it.
const REQUEST_BODY = JSON.stringify({ data: { op: "auth" } });
const COMPARED = ["status", "contentType", "bodyBytes", "bodySha256"];

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const complete = (status) =>
  Number.isInteger(status) &&
  ((status >= 200 && status <= 299) || (status >= 400 && status <= 499));
const fieldsOf = (capture) => ({
  status: capture.status,
  contentType: capture.headers?.["content-type"] ?? null,
  bodyBytes: capture.bodyBytes,
  bodySha256: capture.bodySha256,
});

function captureProblems(capture, index) {
  const pass = Math.floor(index / 2) + 1;
  const caseId = CASE_IDS[index % 2];
  const label = `pass ${pass} ${caseId}`;
  if (capture?.pass !== pass || capture.caseId !== caseId)
    return [`capture ${index + 1} is not ${label}`];
  if (capture.authorization !== AUTHORIZATION[caseId])
    return [`${label}: sent with the wrong Authorization`];
  if (capture.error) return [`${label}: transport failure (${capture.error})`];
  if (!complete(capture.status)) return [`${label}: status ${capture.status} is an unknown answer`];
  if (!Number.isInteger(capture.bodyBytes) || !/^[0-9a-f]{64}$/.test(capture.bodySha256 ?? ""))
    return [`${label}: body unreadable`];
  const length = capture.headers?.["content-length"];
  if (length !== undefined && Number(length) !== capture.bodyBytes)
    return [`${label}: content-length ${length} disagrees with ${capture.bodyBytes} body bytes`];
  return [];
}

/** Why the control answer is not the recorded echo shape (functions-http/http/request-shape#POST). */
function controlProblems(capture, baseline) {
  const reference = baseline.control;
  const problems = [];
  if (capture.status !== reference.status) problems.push(`status ${capture.status}`);
  if (capture.headers?.["content-type"] !== reference.contentType) problems.push("content-type");
  let echo;
  try {
    echo = JSON.parse(capture.bodyText ?? "");
  } catch {
    return [...problems, "body is not JSON"];
  }
  if (!echo || typeof echo !== "object" || Array.isArray(echo))
    return [...problems, "body is not an object"];
  if (JSON.stringify(Object.keys(echo)) !== JSON.stringify(reference.keys)) problems.push("keys");
  // The handler answers with res.json, a compact layout: the byte count says so, not the stored text.
  if (Buffer.byteLength(JSON.stringify(echo)) !== capture.bodyBytes) problems.push("layout");
  const exact = {
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: JSON.parse(REQUEST_BODY),
    rawBodyLength: Buffer.byteLength(REQUEST_BODY),
    rawBodySha256: sha256(REQUEST_BODY),
    query: {},
  };
  for (const [key, value] of Object.entries(exact)) {
    if (JSON.stringify(echo[key]) !== JSON.stringify(value)) problems.push(key);
  }
  const types = {
    customHeader: (v) => v === null,
    forwardedForPresent: (v) => typeof v === "boolean",
    forwardedForHopCount: (v) => Number.isInteger(v),
    forwardedProto: (v) => v === null || typeof v === "string",
    executionIdPresent: (v) => typeof v === "boolean",
  };
  for (const [key, ok] of Object.entries(types)) if (!ok(echo[key])) problems.push(key);
  return problems;
}

export function judgeObservation(captures, baseline) {
  const unknown = (reasons) => ({
    verdict: "unknown",
    reasons,
    differences: [],
    servedByFunction: null,
    headersNotInBaseline: [],
    needsReview: true,
    lockKept: true,
  });
  if (!Array.isArray(captures) || captures.length !== 4)
    return unknown([`expected 4 captures, got ${Array.isArray(captures) ? captures.length : 0}`]);
  const reasons = captures.flatMap(captureProblems);
  if (reasons.length) return unknown(reasons);
  for (const [first, second] of [
    [captures[0], captures[2]],
    [captures[1], captures[3]],
  ]) {
    const a = fieldsOf(first);
    const b = fieldsOf(second);
    for (const field of COMPARED) {
      if (a[field] !== b[field]) reasons.push(`passes disagree on ${first.caseId} ${field}`);
    }
  }
  if (reasons.length) return unknown(reasons);
  const control = controlProblems(captures[0], baseline);
  if (control.length)
    return unknown([`control differs from the recorded echo shape: ${control.join(", ")}`]);
  const observed = fieldsOf(captures[1]);
  const differences = COMPARED.filter(
    (field) => observed[field] !== baseline.provisional[field],
  ).map((field) => ({
    field,
    provisional: baseline.provisional[field],
    observed: observed[field],
  }));
  const servedByFunction =
    observed.status === captures[0].status && observed.bodySha256 === captures[0].bodySha256;
  const headersNotInBaseline = [
    ...new Set(
      captures.flatMap((capture) =>
        (capture.headerNames ?? []).filter(
          (name) => name !== "content-type" && name !== "content-length",
        ),
      ),
    ),
  ].toSorted();
  const same = differences.length === 0;
  return {
    verdict: same ? "same-as-provisional" : "different",
    reasons: [],
    differences,
    servedByFunction,
    headersNotInBaseline,
    needsReview: !same,
    lockKept: false,
  };
}
