// SDK steps of the AUTH-CONFIG-SDK sandbox harness: the declared SDK versions (owner decision
// K1: firebase-admin for Node and the Web SDK in Node) driven through a closed vocabulary of
// operations, against the production sandbox or fireemu. This module is part of the fixture's
// harness digest (run.mjs): what an operation calls and returns decides the recorded row.
//
// Every HTTP request an SDK makes passes the harness guard before it leaves the process: the
// Web SDK's fetch is wrapped before `firebase/auth` is first imported (it captures fetch when
// it loads), and the Admin SDK's http/https requests are checked at `request()` (URL, method,
// headers) and again at `end()` (body) before anything is written.
//
// Against fireemu the Admin SDK runs in its emulator mode (FIREBASE_AUTH_EMULATOR_HOST) and the
// Web SDK is connected with connectAuthEmulator: that is how an application uses fireemu, and
// what the comparison is about. Against production the Admin SDK authenticates with the owner's
// access token (never a key file), bills the sandbox project, and signs custom tokens through
// IAM signBlob of the project's own Admin SDK account (K6).

import http from "node:http";
import http2 from "node:http2";
import https from "node:https";

import { describeJwt, decodeJwt } from "../auth-credential/tokens.mjs";
import { describeActionLink as describeLink } from "./harness.mjs";
import { SANDBOX_PROJECT, resolveValue } from "../auth-account/harness.mjs";
import { materialize } from "../auth-credential/session.mjs";

/** The guard and the request counter the transport hooks consult; set per program. */
let hooks;

const nativeFetch = globalThis.fetch;

function headersObject(headers) {
  if (!headers) return {};
  if (typeof headers.forEach === "function" && !Array.isArray(headers)) {
    const out = {};
    headers.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  return Object.fromEntries(Array.isArray(headers) ? headers : Object.entries(headers));
}

/** Web SDK transport: every fetch is guarded and counted, and never follows a redirect. */
async function guardedFetch(input, init = {}) {
  if (!hooks) throw new Error("an SDK request outside an SDK step");
  const url = typeof input === "string" ? input : String(input.url ?? input);
  const method = init.method ?? "GET";
  const headers = headersObject(init.headers);
  const body = typeof init.body === "string" ? init.body : undefined;
  hooks.check({ url, method, headers, body }, "sdk-web");
  return nativeFetch(input, { ...init, redirect: "error" });
}

function requestUrl(options, protocol) {
  if (typeof options === "string" || options instanceof URL) return String(options);
  const host = options.hostname ?? options.host ?? "localhost";
  const port = options.port ? `:${options.port}` : "";
  return `${options.protocol ?? protocol}//${host}${port}${options.path ?? "/"}`;
}

/** Admin SDK transport: checked at request() and, with the body, at end(). */
function guardTransport(module, protocol) {
  const original = module.request;
  module.request = function guardedRequest(options, ...rest) {
    if (!hooks) throw new Error("an SDK request outside an SDK step");
    const url = requestUrl(options, protocol);
    const method = options.method ?? "GET";
    const headers = options.headers ?? {};
    hooks.check({ url, method, headers }, "sdk-admin", { bodyPending: true });
    const request = original.call(this, options, ...rest);
    const end = request.end.bind(request);
    // The body is checked whole at end(); a body written in parts is refused.
    request.write = () => {
      const error = new Error("an SDK request body written before end()");
      hooks.refuse(error);
      request.destroy(error);
      return false;
    };
    request.end = (chunk, ...more) => {
      try {
        const body =
          chunk === undefined || typeof chunk === "function"
            ? undefined
            : Buffer.isBuffer(chunk) || typeof chunk === "string"
              ? chunk.toString()
              : undefined;
        if (chunk !== undefined && typeof chunk !== "function" && body === undefined)
          throw new Error("an SDK request body of an unexpected type");
        hooks.check({ url, method, headers, body }, "sdk-admin");
      } catch (error) {
        request.destroy(error);
        return request;
      }
      return end(chunk, ...more);
    };
    return request;
  };
  // `get` calls the module's internal request, not the export; route it through the guard.
  module.get = function guardedGet(...args) {
    const request = module.request(...args);
    request.end();
    return request;
  };
}

let loaded;

/** Installs the transport guards, then loads the SDKs (the Web SDK captures fetch on load). */
async function loadSdks() {
  if (loaded) return loaded;
  globalThis.fetch = guardedFetch;
  guardTransport(http, "http:");
  guardTransport(https, "https:");
  // No operation of the vocabulary uses HTTP/2 (the Admin SDK uses it for Messaging only).
  http2.connect = () => {
    throw new Error("HTTP/2 is not used by any SDK step");
  };
  const [adminApp, adminAuth, webApp, webAuth] = await Promise.all([
    import("firebase-admin/app"),
    import("firebase-admin/auth"),
    import("firebase/app"),
    import("firebase/auth"),
  ]);
  loaded = { adminApp, adminAuth, webApp, webAuth };
  return loaded;
}

/** The fetch the harness's own REST steps use: the original, outside the SDK hooks. */
export const harnessFetch = (...args) => nativeFetch(...args);

let appCount = 0;

/**
 * Opens one Admin app and one Web app for a program. `check(request, role)` is the guard (it
 * also counts the request) and `refuse(error)` records a refusal made outside it; production
 * needs the owner's access token and the web config.
 */
export async function openSdk(ctx, { check, refuse }) {
  const sdk = await loadSdks();
  hooks = { check, refuse };
  const name = `acs-${(appCount += 1)}`;
  const local = ctx.target.kind === "local";
  let admin;
  if (local) {
    const origin = new URL(ctx.target.origin);
    process.env.FIREBASE_AUTH_EMULATOR_HOST = origin.host;
    admin = sdk.adminApp.initializeApp({ projectId: ctx.project }, name);
  } else {
    delete process.env.FIREBASE_AUTH_EMULATOR_HOST;
    process.env.GOOGLE_CLOUD_QUOTA_PROJECT = SANDBOX_PROJECT;
    admin = sdk.adminApp.initializeApp(
      {
        projectId: ctx.project,
        serviceAccountId: `firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}.iam.gserviceaccount.com`,
        credential: {
          getAccessToken: async () => {
            await ctx.target.refresh?.();
            return { access_token: ctx.target.adminToken, expires_in: 1800 };
          },
        },
      },
      name,
    );
  }
  const web = sdk.webApp.initializeApp(
    {
      apiKey: local ? "fake-api-key" : ctx.target.apiKey,
      authDomain: `${ctx.project}.firebaseapp.com`,
      projectId: ctx.project,
    },
    name,
  );
  const webAuth = sdk.webAuth.initializeAuth(web, {
    persistence: sdk.webAuth.inMemoryPersistence,
  });
  if (local) sdk.webAuth.connectAuthEmulator(webAuth, ctx.target.origin, { disableWarnings: true });
  const adminAuth = sdk.adminAuth.getAuth(admin);
  return {
    sdk,
    adminAuth,
    webAuth,
    async close() {
      try {
        await sdk.webApp.deleteApp(web);
        await sdk.adminApp.deleteApp(admin);
      } finally {
        hooks = undefined;
      }
    },
  };
}

// ---- recorded shapes ---------------------------------------------------------------------

/** Claims with iat/exp relative to iat and auth_time as a placeholder (as REST tokens are). */
function relativeClaims(claims) {
  return describeJwt(
    `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.`,
  ).claims;
}

/** A custom token's signer names the SDK's credential, not fireemu or production (K5). */
function customTokenShape(token) {
  const claims = decodeJwt(token)?.claims;
  if (!claims) return "<undecodable-jwt>";
  const signer = claims.iss === claims.sub ? "<custom-token-signer>" : "<mismatched-signer>";
  return relativeClaims({ ...claims, iss: signer, sub: signer });
}

function userShape(user) {
  if (!user) return user;
  return {
    uid: user.uid,
    email: user.email ?? null,
    emailVerified: user.emailVerified,
    isAnonymous: user.isAnonymous,
    phoneNumber: user.phoneNumber ?? null,
    displayName: user.displayName ?? null,
    providerId: user.providerId,
    providerData: (user.providerData ?? []).map(({ providerId, uid, email, phoneNumber }) => ({
      providerId,
      uid,
      email: email ?? null,
      phoneNumber: phoneNumber ?? null,
    })),
    tenantId: user.tenantId ?? null,
  };
}

function credentialShape(credential) {
  return {
    operationType: credential.operationType,
    providerId: credential.providerId ?? null,
    user: userShape(credential.user),
  };
}

function policyShape(policy) {
  if (!policy) return policy;
  return {
    customStrengthOptions: policy.customStrengthOptions,
    allowedNonAlphanumericCharacters: policy.allowedNonAlphanumericCharacters,
    enforcementState: policy.enforcementState,
    forceUpgradeOnSignin: policy.forceUpgradeOnSignin,
  };
}

function tokenResultShape(result) {
  return {
    claims: relativeClaims(result.claims),
    signInProvider: result.signInProvider,
    signInSecondFactor: result.signInSecondFactor,
  };
}

// ---- the vocabulary ----------------------------------------------------------------------

/** A sign-in's recorded shape; later steps may name its uid (`{$sdk: step, path: "uid"}`). */
const signedIn = (credential) => ({
  value: credentialShape(credential),
  keep: { uid: credential.user.uid },
});

const currentUser = (s) => {
  if (!s.webAuth.currentUser)
    throw Object.assign(new Error("no signed-in user"), { code: "harness/no-user" });
  return s.webAuth.currentUser;
};

/**
 * Each operation takes the open SDK pair and resolved arguments and returns `{value, keep}`:
 * `value` is recorded (after normalization), `keep` is what later steps may reference.
 */
export const OPERATIONS = {
  "admin.getProjectConfig": async (s) => ({
    value: (await s.adminAuth.projectConfigManager().getProjectConfig()).toJSON(),
  }),
  "admin.updateProjectConfig": async (s, [request]) => ({
    value: (await s.adminAuth.projectConfigManager().updateProjectConfig(request)).toJSON(),
  }),
  "admin.createUser": async (s, [properties]) => {
    const user = await s.adminAuth.createUser(properties);
    return { value: user.toJSON(), keep: user.toJSON() };
  },
  "admin.getUser": async (s, [uid]) => ({ value: (await s.adminAuth.getUser(uid)).toJSON() }),
  "admin.getUserByEmail": async (s, [email]) => ({
    value: (await s.adminAuth.getUserByEmail(email)).toJSON(),
  }),
  "admin.updateUser": async (s, [uid, properties]) => ({
    value: (await s.adminAuth.updateUser(uid, properties)).toJSON(),
  }),
  "admin.deleteUser": async (s, [uid]) => ({ value: await s.adminAuth.deleteUser(uid) }),
  "admin.revokeRefreshTokens": async (s, [uid]) => ({
    value: await s.adminAuth.revokeRefreshTokens(uid),
  }),
  "admin.verifyIdToken": async (s, [token, checkRevoked]) => {
    const decoded = await s.adminAuth.verifyIdToken(token, checkRevoked);
    return { value: relativeClaims(decoded) };
  },
  "admin.createSessionCookie": async (s, [token, expiresIn]) => {
    const cookie = await s.adminAuth.createSessionCookie(token, { expiresIn });
    return { value: relativeClaims(decodeJwt(cookie)?.claims ?? {}), keep: cookie };
  },
  "admin.verifySessionCookie": async (s, [cookie, checkRevoked]) => ({
    value: relativeClaims(await s.adminAuth.verifySessionCookie(cookie, checkRevoked)),
  }),
  "admin.createCustomToken": async (s, [uid, claims]) => {
    const token = await s.adminAuth.createCustomToken(uid, claims);
    return { value: customTokenShape(token), keep: token };
  },
  "admin.generatePasswordResetLink": async (s, [email, settings]) => ({
    value: describeLink(await s.adminAuth.generatePasswordResetLink(email, settings)),
  }),
  "admin.generateEmailVerificationLink": async (s, [email, settings]) => ({
    value: describeLink(await s.adminAuth.generateEmailVerificationLink(email, settings)),
  }),
  "admin.generateSignInWithEmailLink": async (s, [email, settings]) => ({
    value: describeLink(await s.adminAuth.generateSignInWithEmailLink(email, settings)),
  }),
  "admin.generateVerifyAndChangeEmailLink": async (s, [email, newEmail, settings]) => ({
    value: describeLink(
      await s.adminAuth.generateVerifyAndChangeEmailLink(email, newEmail, settings),
    ),
  }),
  "web.createUserWithEmailAndPassword": async (s, [email, password]) =>
    signedIn(await s.sdk.webAuth.createUserWithEmailAndPassword(s.webAuth, email, password)),
  "web.signInWithEmailAndPassword": async (s, [email, password]) =>
    signedIn(await s.sdk.webAuth.signInWithEmailAndPassword(s.webAuth, email, password)),
  "web.signInAnonymously": async (s) => signedIn(await s.sdk.webAuth.signInAnonymously(s.webAuth)),
  "web.signInWithCustomToken": async (s, [token]) =>
    signedIn(await s.sdk.webAuth.signInWithCustomToken(s.webAuth, token)),
  "web.signOut": async (s) => ({ value: await s.sdk.webAuth.signOut(s.webAuth) }),
  "web.getIdTokenResult": async (s, [force]) => {
    const user = currentUser(s);
    const result = await s.sdk.webAuth.getIdTokenResult(user, force === true);
    return { value: tokenResultShape(result), keep: result.token };
  },
  "web.getIdToken": async (s, [force]) => {
    const token = await currentUser(s).getIdToken(force === true);
    return { value: relativeClaims(decodeJwt(token)?.claims ?? {}), keep: token };
  },
  "web.currentUser": async (s) => ({ value: userShape(s.webAuth.currentUser) }),
  "web.reload": async (s) => {
    await s.sdk.webAuth.reload(currentUser(s));
    return { value: userShape(s.webAuth.currentUser) };
  },
  "web.updatePassword": async (s, [password]) => ({
    value: await s.sdk.webAuth.updatePassword(currentUser(s), password),
  }),
  "web.deleteUser": async (s) => ({ value: await s.sdk.webAuth.deleteUser(currentUser(s)) }),
  "web.fetchSignInMethodsForEmail": async (s, [email]) => ({
    value: await s.sdk.webAuth.fetchSignInMethodsForEmail(s.webAuth, email),
  }),
  "web.validatePassword": async (s, [password]) => {
    const status = await s.sdk.webAuth.validatePassword(s.webAuth, password);
    const { passwordPolicy, ...rest } = status;
    return { value: { ...rest, passwordPolicy: policyShape(passwordPolicy) } };
  },
  "web.initializeRecaptchaConfig": async (s) => ({
    value: await s.sdk.webAuth.initializeRecaptchaConfig(s.webAuth),
  }),
};

export const SDK_OPERATIONS = new Set(Object.keys(OPERATIONS));

/**
 * Resolves an SDK step's arguments: placeholders as in REST steps, `{$sdk: step}` (what an
 * earlier SDK step kept) and `{$from: step, path}` (an earlier REST answer).
 */
function resolveArgs(args, ctx, raw, kept) {
  const walk = (value) => {
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === "object") {
      if (typeof value.$sdk === "string") {
        if (!kept.has(value.$sdk)) throw new Error(`step ${value.$sdk} recorded nothing at kept`);
        const found = value.path
          ? String(value.path)
              .split(".")
              .reduce((v, k) => (v == null ? undefined : v[k]), kept.get(value.$sdk))
          : kept.get(value.$sdk);
        if (found === undefined)
          throw new Error(`step ${value.$sdk} recorded nothing at ${value.path}`);
        return found;
      }
      if (typeof value.$from === "string") return materialize(value, raw, new Map());
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, walk(v)]));
    }
    return typeof value === "string" ? resolveValue(value, ctx, raw) : value;
  };
  return walk(args ?? []);
}

/** Runs one SDK step; returns `{value}` or `{error: {code, message}}` and what it keeps. */
export async function runSdkStep(opened, step, ctx, raw, kept) {
  const operation = OPERATIONS[step.sdk];
  if (!operation) throw new Error(`unknown SDK operation ${step.sdk}`);
  let args;
  try {
    args = resolveArgs(step.args, ctx, raw, kept);
  } catch (error) {
    return { outcome: { error: { code: "harness/unresolved", message: String(error.message) } } };
  }
  try {
    const { value, keep } = await operation(opened, args);
    if (keep !== undefined) kept.set(step.id, keep);
    return { outcome: { value } };
  } catch (error) {
    if (error?.fatal) throw error;
    return {
      outcome: {
        error: {
          code: error?.code ?? error?.name ?? "error",
          message: String(error?.message ?? error),
        },
      },
    };
  }
}
