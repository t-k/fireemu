// The judge of the stage 3 re-recording (FUNCTIONS-HTTP-CALLABLE-RERECORD). Pure: it reads the twelve
// captures of one run (two programs, each sent twice: one pass right after the public invoker is granted
// and one 60 s later) and the baseline, and classifies every answer.
//
//   function-answer      the callable's own answer to a request without Authorization (the control)
//   valid-token-answer   200 with the callable result for a valid Firebase ID token of the project
//   front-end-page       the Google front end's 294-byte 401 page (stage 3, 2026-09-27)
//   wrapper-envelope     the callable wrapper's 66-byte 401 envelope (FUNCTIONS-HTTP-CALLABLE-INGRESS)
//   other                any other complete answer, recorded in full
//
// verdict `recorded`: all twelve captures are complete, readable, in the frozen order, sent with the right
// kind of Authorization, and every control (no Authorization) is the callable's own answer, so the public
// invoker was in effect for each pass. Anything else is `unknown` and keeps the project lock.
//
// The judge decides nothing about which recording stands. It lists, per row, the class of each pass, and
// names the rows whose class differs between the immediate pass and the pass 60 s later.
//
// Bodies are compared by their byte count and digest, never by stored text layout.

export const PROGRAMS = Object.freeze([
  Object.freeze({
    id: "functions-http/callable/auth-context",
    cases: Object.freeze([
      Object.freeze({ id: "no-authorization", authorization: "none" }),
      Object.freeze({ id: "valid-project-id-token", authorization: "token" }),
    ]),
  }),
  Object.freeze({
    id: "functions-http/callable/auth-refusal",
    cases: Object.freeze([
      Object.freeze({ id: "no-authorization", authorization: "none" }),
      Object.freeze({ id: "malformed-bearer", authorization: "Bearer malformed" }),
      Object.freeze({ id: "invalid-signature", authorization: "token" }),
      Object.freeze({ id: "expired-id-token", authorization: "token" }),
    ]),
  }),
]);

/** What a capture records of a token it sent: the shape, never the token. */
export const MASKED_TOKEN = "Bearer {{jwt}}";

/** The order of the twelve requests: for each program, pass 1 then pass 2, every case in corpus order. */
export const SLOTS = Object.freeze(
  PROGRAMS.flatMap((program) =>
    [1, 2].flatMap((pass) =>
      program.cases.map((step) => Object.freeze({ pass, program: program.id, caseId: step.id })),
    ),
  ),
);

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
const referenceFields = (reference) => ({
  status: reference.status,
  contentType: reference.contentType,
  bodyBytes: reference.bodyBytes,
  bodySha256: reference.bodySha256,
});

function expectedAuthorization(program, caseId) {
  const step = PROGRAMS.find(({ id }) => id === program).cases.find(({ id }) => id === caseId);
  if (step.authorization === "none") return null;
  if (step.authorization === "token") return MASKED_TOKEN;
  return step.authorization;
}

function captureProblems(capture, index) {
  const slot = SLOTS[index];
  const label = `pass ${slot.pass} ${slot.program.split("/").at(-1)} ${slot.caseId}`;
  if (
    capture?.pass !== slot.pass ||
    capture.program !== slot.program ||
    capture.caseId !== slot.caseId
  )
    return [`capture ${index + 1} is not ${label}`];
  if (capture.authorization !== expectedAuthorization(slot.program, slot.caseId))
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

function validTokenAnswer(capture, baseline) {
  const reference = baseline.validToken;
  if (capture.status !== reference.status) return false;
  if (capture.headers?.["content-type"] !== reference.contentType) return false;
  try {
    const result = JSON.parse(capture.bodyText ?? "").result;
    return (
      Buffer.byteLength(JSON.stringify({ result })) === capture.bodyBytes &&
      JSON.stringify(Object.keys(result)) === JSON.stringify(reference.resultKeys) &&
      typeof result.uid === "string" &&
      result.uid.length > 0
    );
  } catch {
    return false;
  }
}

/** The class of one complete capture. */
export function classOf(capture, baseline) {
  const fields = fieldsOf(capture);
  if (sameFields(fields, referenceFields(baseline.control))) return "function-answer";
  if (sameFields(fields, referenceFields(baseline.frontEndPage))) return "front-end-page";
  if (sameFields(fields, referenceFields(baseline.wrapperEnvelope))) return "wrapper-envelope";
  if (capture.caseId === "valid-project-id-token" && validTokenAnswer(capture, baseline))
    return "valid-token-answer";
  return "other";
}

export function judgeRerecord(captures, baseline) {
  const unknown = (reasons) => ({
    verdict: "unknown",
    reasons,
    rows: [],
    timingDiffers: [],
    needsReview: true,
    lockKept: true,
  });
  if (!Array.isArray(captures) || captures.length !== SLOTS.length)
    return unknown([
      `expected ${SLOTS.length} captures, got ${Array.isArray(captures) ? captures.length : 0}`,
    ]);
  const reasons = captures.flatMap(captureProblems);
  if (reasons.length) return unknown(reasons);
  const classes = captures.map((capture) => classOf(capture, baseline));
  captures.forEach((capture, index) => {
    if (capture.caseId === "no-authorization" && classes[index] !== "function-answer")
      reasons.push(
        `pass ${capture.pass} ${capture.program.split("/").at(-1)}: the control is not the callable's own answer (the public invoker was not in effect)`,
      );
  });
  if (reasons.length) return unknown(reasons);
  const rows = PROGRAMS.flatMap((program) =>
    program.cases.map((step) => ({
      program: program.id,
      caseId: step.id,
      passes: [1, 2].map((pass) => {
        const index = SLOTS.findIndex(
          (slot) => slot.program === program.id && slot.pass === pass && slot.caseId === step.id,
        );
        return Object.assign({ pass, class: classes[index] }, fieldsOf(captures[index]));
      }),
    })),
  );
  const timingDiffers = rows
    .filter(({ passes }) => passes[0].class !== passes[1].class)
    .map(({ program, caseId }) => `${program.split("/").at(-1)}#${caseId}`);
  const settled = new Set(["function-answer", "valid-token-answer"]);
  const needsReview = rows.some(({ passes }) =>
    passes.some(({ class: kind }) => !settled.has(kind)),
  );
  return {
    verdict: "recorded",
    reasons: [],
    rows,
    timingDiffers,
    needsReview,
    lockKept: false,
  };
}
