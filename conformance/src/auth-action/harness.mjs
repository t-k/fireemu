// Normalization of the AUTH-ACTION sandbox harness: how an answer is recorded. This module is
// part of the fixture's harness digest (run.mjs): a change here makes every saved row stale.
// Request construction, the production/local context and transient classification come from
// the AUTH-ACCOUNT harness; token decoding comes from the AUTH-CREDENTIAL harness; the request
// guard and the corpus rules live in guard.mjs.

import { normalizeCredentialResponse } from "../auth-credential/tokens.mjs";

/**
 * The recorded form of an action link. Where the handler lives (production's hosted action
 * page, fireemu's own `/emulator/action`) is not compared (scope decision E2); every query
 * parameter is, with the code recorded as whether it is the answer's own `oobCode` and the API
 * key by presence.
 */
export function describeLink(link, oobCode) {
  let url;
  try {
    url = new URL(link);
  } catch {
    return "<unparsable-link>";
  }
  const params = {};
  let code = "absent";
  for (const [name, value] of url.searchParams) {
    // Kept out of `params`: the normalization masks every `oobCode` member, which would hide
    // whether the link carries the answer's own code.
    if (name === "oobCode") code = value === oobCode ? "the-answer-oobCode" : "another-code";
    else if (name === "apiKey") params.apiKey = value ? "<present>" : "<empty>";
    else params[name] = value;
  }
  return { handler: "<action-handler>", code, params };
}

function describeLinks(value) {
  if (Array.isArray(value)) return value.map(describeLinks);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        k === "oobLink" && typeof v === "string"
          ? describeLink(v, value.oobCode)
          : describeLinks(v),
      ]),
    );
  }
  return value;
}

/**
 * The recorded form of one HTTP answer: action links described as above, then the
 * AUTH-CREDENTIAL normalization (tokens decoded; codes, ids, run-window times, the project,
 * its number and the API key as placeholders).
 */
export function normalizeActionResponse(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  return normalizeCredentialResponse(status, JSON.stringify(describeLinks(body)), ctx);
}
