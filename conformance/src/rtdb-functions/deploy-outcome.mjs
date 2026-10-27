// Whether a deploy that failed made nothing or may have made something. firebase-tools prints
// `Request to <url> had HTTP Error: <code>, ...` for a request production refused. When the CLI ended by
// itself (it was not killed) and every such line for this function's own create is a definite 4xx, the
// create was refused and nothing was made; the CV14 run of 2026-10-27 was a case (deploy 5: 400, the
// Eventarc service agent not yet propagated). Anything else stays unknown: a killed CLI, no such line, a
// 5xx or a retryable code (408, 429, 499) or a conflict (409, 412) among the answers, a success line, an error of another request.
// The create of an unknown deploy is settled only by the run's own 200 read of the function before its
// exact delete, or by the coordinator's acceptance.

const HTTP_ERROR =
  /Request to https:\/\/cloudfunctions\.googleapis\.com\/v([12])\/projects\/([^/\s]+)\/locations\/([^/\s]+)\/functions(?:\?functionId=([A-Za-z0-9_-]+))? had HTTP Error: (\d{3})/gu;
const SUCCESS = /Successful (?:create|update|delete) operation/u;

// 409 and 412 say the function (or its state) exists or changed: the opposite of "nothing was made"
const definite = (status) =>
  status >= 400 && status < 500 && ![408, 409, 412, 429, 499].includes(status);

/** `{ class: "refused" | "unknown", evidence }`; the evidence is the statuses of this function's own create. */
export function classifyDeployFailure({ output, exited, exitCode, spec }) {
  const unknown = (evidence = []) => ({ class: "unknown", evidence });
  if (
    typeof output !== "string" ||
    exited !== true ||
    !Number.isInteger(exitCode) ||
    exitCode === 0
  ) {
    return unknown();
  }
  if (SUCCESS.test(output)) return unknown();
  const generation = spec.generation === "gcfv1" ? "1" : "2";
  const evidence = [];
  const seen = new Set();
  for (const match of output.matchAll(HTTP_ERROR)) {
    const [, version, project, region, functionId, code] = match;
    const own =
      version === generation &&
      project === spec.project &&
      region === spec.region &&
      (generation === "2" ? functionId === spec.functionName : functionId === undefined);
    if (!own) continue;
    const status = Number(code);
    if (!definite(status)) return unknown();
    if (!seen.has(status)) {
      seen.add(status);
      evidence.push({ status, create: spec.functionName });
    }
  }
  return evidence.length > 0 ? { class: "refused", evidence } : unknown();
}
