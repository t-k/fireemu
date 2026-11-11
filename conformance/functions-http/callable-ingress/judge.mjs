// The judge of the callable-ingress observation. Pure: it reads the twelve captures of one run (two passes
// of six cases, in corpus order) and the baseline, and classifies each case's answer. It decides nothing
// about what fireemu should answer; it states what production answered, in classes that already have a
// recorded shape, and lists the cases whose shape is new.
//
//   served-by-function  status, content-type, byte count and SHA-256 equal the control's: the request
//                       reached the function and the function (the callable wrapper) accepted it
//   front-end-page      equal to the 294-byte Google front end 401 page of stage 3
//                       (functions-http/callable/auth-refusal#malformed-bearer)
//   other               anything else that is a complete 2xx/4xx answer: a new shape, recorded in full
//
// verdict `recorded`: all twelve captures are complete, readable, ordered, sent with the right
// Authorization, both passes agree per case, and the control is the recorded callable answer.
// verdict `unknown`: anything else (transport failure, 1xx/3xx/5xx, unreadable body, a content-length
// that disagrees with the bytes, passes that disagree, a control that is not the recorded answer,
// missing or misordered captures). Needs review; the coordinator keeps the project lock.
//
// Bodies are compared by their byte count and digest, never by stored text layout.

// The credentials of the frozen corpus, in order. `null` sends no Authorization header. The shapes are the
// ones the strict profile's callable Bearer check branches on (crates/fireemu-adapter-functions/src/http.rs
// `strict_callable_bearer_unverified`): a Bearer that is not a user, a scheme in another case, a scheme
// without a token, another scheme, and a three-part token that is not a Firebase ID token.
export const CASES = Object.freeze(
  [
    ["no-authorization", null],
    ["malformed-bearer", "Bearer malformed"],
    ["lowercase-scheme", "bearer malformed"],
    ["bare-scheme", "Bearer"],
    ["basic-scheme", "Basic dXNlcjpwYXNz"],
    ["unsigned-jwt", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2ln"],
  ].map(([id, authorization]) => Object.freeze({ id, authorization })),
);
export const CASE_IDS = Object.freeze(CASES.map(({ id }) => id));
const PASSES = 2;
const COMPARED = ["status", "contentType", "bodyBytes", "bodySha256"];

const complete = (status) =>
  Number.isInteger(status) &&
  ((status >= 200 && status <= 299) || (status >= 400 && status <= 499));
const fieldsOf = (capture) => ({
  status: capture.status,
  contentType: capture.headers?.["content-type"] ?? null,
  bodyBytes: capture.bodyBytes,
  bodySha256: capture.bodySha256,
});
const sameFields = (a, b) => COMPARED.every((field) => a[field] === b[field]);

function captureProblems(capture, index) {
  const pass = Math.floor(index / CASES.length) + 1;
  const step = CASES[index % CASES.length];
  const label = `pass ${pass} ${step.id}`;
  if (capture?.pass !== pass || capture.caseId !== step.id)
    return [`capture ${index + 1} is not ${label}`];
  if (capture.authorization !== step.authorization)
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

/** Why the control answer is not the recorded callable answer (stage 3 auth-context#no-authorization). */
function controlProblems(capture, baseline) {
  const reference = baseline.control;
  const problems = [];
  if (capture.status !== reference.status) problems.push(`status ${capture.status}`);
  if (capture.headers?.["content-type"] !== reference.contentType) problems.push("content-type");
  // The SDK answers with res.send of an object, a compact layout: the byte count says so, not the stored text.
  if (capture.bodyBytes !== reference.bodyBytes || capture.bodySha256 !== reference.bodySha256)
    problems.push("body bytes");
  return problems;
}

export function judgeObservation(captures, baseline) {
  const unknown = (reasons) => ({
    verdict: "unknown",
    reasons,
    answers: [],
    newShapes: [],
    needsReview: true,
    lockKept: true,
  });
  const total = CASES.length * PASSES;
  if (!Array.isArray(captures) || captures.length !== total)
    return unknown([
      `expected ${total} captures, got ${Array.isArray(captures) ? captures.length : 0}`,
    ]);
  const reasons = captures.flatMap(captureProblems);
  if (reasons.length) return unknown(reasons);
  for (let i = 0; i < CASES.length; i += 1) {
    const first = fieldsOf(captures[i]);
    const second = fieldsOf(captures[i + CASES.length]);
    for (const field of COMPARED) {
      if (first[field] !== second[field])
        reasons.push(`passes disagree on ${CASE_IDS[i]} ${field}`);
    }
  }
  if (reasons.length) return unknown(reasons);
  const control = controlProblems(captures[0], baseline);
  if (control.length)
    return unknown([`control differs from the recorded callable answer: ${control.join(", ")}`]);
  const controlFields = fieldsOf(captures[0]);
  const pageFields = {
    status: baseline.frontEndPage.status,
    contentType: baseline.frontEndPage.contentType,
    bodyBytes: baseline.frontEndPage.bodyBytes,
    bodySha256: baseline.frontEndPage.bodySha256,
  };
  const answers = CASES.map((step, i) => {
    const fields = fieldsOf(captures[i]);
    const kind = sameFields(fields, controlFields)
      ? "served-by-function"
      : sameFields(fields, pageFields)
        ? "front-end-page"
        : "other";
    return {
      caseId: step.id,
      class: kind,
      status: fields.status,
      contentType: fields.contentType,
      bodyBytes: fields.bodyBytes,
      bodySha256: fields.bodySha256,
    };
  });
  const newShapes = answers
    .filter(({ class: kind }) => kind === "other")
    .map(({ caseId }) => caseId);
  return {
    verdict: "recorded",
    reasons: [],
    answers,
    newShapes,
    needsReview: newShapes.length > 0,
    lockKept: false,
  };
}
