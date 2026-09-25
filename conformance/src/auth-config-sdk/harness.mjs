// Normalization of the AUTH-CONFIG-SDK sandbox harness: how an answer (HTTP or SDK) is recorded.
// This module is part of the fixture's harness digest (run.mjs): a change here makes every saved
// row stale. Request construction and the production/local context come from the AUTH-ACCOUNT
// harness, token decoding from the AUTH-CREDENTIAL harness and action-link description from the
// AUTH-ACTION harness; the request guard and the corpus rules live in guard.mjs.

import { describeLink, normalizeActionResponse } from "../auth-action/harness.mjs";

/**
 * Config members other lanes own and may change on the shared sandbox (scope decisions K9 and
 * K10): left out of every recorded configuration, REST or SDK.
 */
export const OTHER_LANE_MEMBERS = ["mfa", "multiTenant", "blockingFunctions", "multiFactorConfig"];

/** Members that carry key material or volatile challenge values (scope decision K12). */
const MASKED = {
  signerKey: "<bytes>",
  saltSeparator: "<bytes>",
  apiKey: "<api-key>",
  recaptchaStoken: "<recaptcha-stoken>",
  recaptchaSiteKey: "<recaptcha-site-key>",
  recaptchaKey: "<recaptcha-key>",
  producerProjectNumber: "<producer-project-number>",
  // An Admin SDK UserRecord carries the stored hash and salt.
  passwordSalt: "<bytes>",
  // createAuthUri's session handle, new on every answer.
  sessionId: "<sessionId>",
  // A temporary sign-up quota's start, which the corpus sets relative to the run.
  startTime: "<start-time>",
};

/**
 * An action link as AUTH-ACTION records it (E2), and when production wraps it for an app
 * (mobile link settings: `/__/auth/links?link=<action link>`), the inner link described the
 * same way, so its code is never recorded.
 */
export function describeActionLink(link, oobCode) {
  const described = describeLink(link, oobCode);
  if (described && typeof described === "object" && typeof described.params?.link === "string")
    described.params.link = describeLink(described.params.link, oobCode);
  return described;
}

function describeLinks(value) {
  if (Array.isArray(value)) return value.map(describeLinks);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        k === "oobLink" && typeof v === "string"
          ? describeActionLink(v, value.oobCode)
          : describeLinks(v),
      ]),
    );
  }
  return value;
}

/** An RFC 1123 time as the Admin SDK prints it (UserRecord metadata, tokensValidAfterTime). */
const HTTP_DATE = /^[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT$/;

function mask(value, key, ctx) {
  if (typeof value === "string" && MASKED[key]) return MASKED[key];
  if (typeof value === "string" && HTTP_DATE.test(value)) {
    const millis = Date.parse(value);
    return millis >= ctx.window.from && millis <= ctx.window.to ? "<run-time:http-date>" : value;
  }
  // A reCAPTCHA key name ends in a generated key id.
  if (typeof value === "string" && key === "key" && /\/keys\/[^/]+$/.test(value))
    return value.replace(/\/keys\/[^/]+$/, "/keys/<recaptcha-key-id>");
  if (Array.isArray(value)) return value.map((v) => mask(v, key, ctx));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, mask(v, k, ctx)]));
  }
  return value;
}

/** A configuration without the members other lanes own. */
export function withoutOtherLanes(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) return config;
  return Object.fromEntries(
    Object.entries(config).filter(([key]) => !OTHER_LANE_MEMBERS.includes(key)),
  );
}

/**
 * The recorded form of one HTTP answer. A project configuration (the Admin config route) loses
 * the members other lanes own; key material and volatile challenge values become placeholders;
 * then the AUTH-ACTION normalization applies (action links described, tokens decoded, ids,
 * run-window times, the project, its number and the API key as placeholders).
 */
export function normalizeHttp(status, text, ctx, { config = false } = {}) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  const projected = describeLinks(config ? withoutOtherLanes(body) : body);
  return normalizeActionResponse(status, JSON.stringify(mask(projected, "", ctx)), ctx);
}

/**
 * The recorded form of one SDK call: `{sdk: "ok", value}` or `{sdk: "error", code, message}`,
 * with the value normalized as an HTTP answer body is. A generated uid is masked wherever the
 * SDK names it (`uid`, `sub`, `user_id`, `localId`).
 */
export function normalizeSdk(outcome, ctx) {
  if (outcome.error) {
    const { code, message } = outcome.error;
    const text = JSON.stringify({ code: code ?? "<none>", message: message ?? "" });
    return { sdk: "error", ...normalizeActionResponse(0, text, ctx).body };
  }
  if (outcome.value === undefined) return { sdk: "ok" };
  const value = withoutOtherLanes(outcome.value);
  const normalized = normalizeActionResponse(0, JSON.stringify(mask(value, "", ctx)), ctx);
  return { sdk: "ok", value: maskGeneratedIds(normalized.body) };
}

const GENERATED_ID = /^[A-Za-z0-9]{28}$/;
const ID_KEYS = new Set(["uid", "sub", "user_id", "localId"]);

function maskGeneratedIds(value, key) {
  if (typeof value === "string" && ID_KEYS.has(key) && GENERATED_ID.test(value))
    return "<generated-localId>";
  if (Array.isArray(value)) return value.map((v) => maskGeneratedIds(v, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskGeneratedIds(v, k)]));
  }
  return value;
}
