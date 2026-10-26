// Version-bounded instrumentation of `firebase-admin`'s App Check `verifyToken` for the
// Functions runner (HTTP Functions that verify the `X-Firebase-AppCheck` header themselves).
//
// Why it exists. firebase-admin verifies an App Check token offline: it decodes the JWT, checks
// the claims and then checks the signature against the keys at a Google URL hard-coded in the
// SDK. A token the emulator minted can never verify there, and an SDK that did not reach the
// emulator's key could not see a session reset in any case (it caches keys for six hours). So
// the one step that cannot work, the signature check, is replaced by a question to the daemon,
// which answers from the same verifier the callable boundary uses, against the project's
// current epoch and app registry, under the session admission barrier. Nothing is cached here.
//
// What stays the SDK's: `safeDecode` and `verifyContent` (so malformed tokens and wrong
// algorithm, audience, issuer and subject fail with the SDK's own code and message, before the
// daemon is asked), and every error the daemon's answer becomes: the verdict is turned into
// the `JwtError` the analogous production condition raises and thrown through the SDK's own
// `mapJwtErrorToAppCheckError`, so the code, message and (14.x) `cause` shape are the SDK's.
//
// What is refused. `verifyToken(token, { consume: true })` would call Google's
// `verifyAppCheckToken` with the developer's credentials. Limited-use consumption is
// unimplemented (`APPCHECK-REPLAY-1`), so `verifyReplayProtection` is replaced by a fixed
// refusal that never builds a request. It is installed together with the signature check, in
// one step, because once fireemu tokens verify, the consume request becomes reachable.
//
// Failing closed. Outside the supported majors, or when any structural probe or the startup
// self-test fails, nothing stays patched: the stock SDK then fetches Google's keys, which no
// fireemu token verifies against, so it rejects fireemu tokens and never accepts one it cannot
// check. A second copy of `firebase-admin` somewhere else in `node_modules` is not the one
// resolved from the codebase and stays stock (and therefore rejecting).

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, parse as parsePath } from "node:path";
import https from "node:https";
import timers from "node:timers";

// The natives, captured before the runtime clock can virtualize timers: a verification
// deadline is a real-time safety bound.
const { setTimeout, clearTimeout } = timers;

/// `firebase-admin` majors whose App Check internals this instrumentation is written for. 14.3.0
/// and 14.5.0 were compared and are identical on this path; 13.10.0 differs only in how the
/// SDK constructs its errors, which the instrumentation never does itself.
export const SUPPORTED_MAJORS = [13, 14];

/// How long a question to the daemon may stay unanswered. The daemon waits for a session reset
/// to finish before it answers, so this is generous.
export const DEFAULT_TIMEOUT_MS = 15_000;

/// Questions in flight at once; the daemon refuses more than this per runner as well.
export const MAX_IN_FLIGHT = 64;

const SELF_TEST_TIMEOUT_MS = 5_000;
const SELF_TEST_PROJECT = "fireemu-self-test";

/// The text of `AppCheckTokenVerifier.safeDecode`'s failure (identical in 13 and 14).
const DECODE_FAILED =
  "Decoding App Check token failed. Make sure you passed the entire string JWT which represents the Firebase App Check token.";
const PROJECT_MATCH =
  " Make sure the App Check token comes from the same Firebase project as the service account used to authenticate this SDK.";

/// What each reason of the daemon's verdict becomes. `code` names a `JwtErrorCode`; the SDK's
/// mapper turns the `JwtError` into the `FirebaseAppCheckError` (or, for the codes it
/// does not name, an `invalid-argument` carrying this message).
const REASONS = {
  "no-matching-kid": {
    code: "NO_MATCHING_KID",
    message: "no-matching-kid-error",
  },
  "invalid-signature": { code: "INVALID_SIGNATURE", message: "invalid signature" },
  "token-expired": {
    code: "TOKEN_EXPIRED",
    message: "The provided token has expired. Get a fresh token from your client app and try again.",
  },
  malformed: { code: "INVALID_ARGUMENT", message: DECODE_FAILED },
  claims: {
    code: "INVALID_ARGUMENT",
    message: `The provided App Check token has incorrect "iss" (issuer) or "aud" (audience) claim for this project.${PROJECT_MATCH}`,
  },
  "not-yet-valid": {
    code: "INVALID_ARGUMENT",
    message: 'The provided App Check token has an "iat" (issued-at) claim in the future.',
  },
  "unknown-app": {
    code: "INVALID_ARGUMENT",
    message:
      'The provided App Check token has a "sub" (subject) claim that names no registered, enabled app of this project in fireemu.',
  },
};

/// The failure of a question the daemon could not answer. This is the text of the SDK's own
/// JWKS-fetch failure path, so the caller sees the error it would see if the keys were
/// unreachable.
function unavailableMessage(why) {
  return `Error fetching Json Web Keys: ${why}`;
}

/// The runner's side of the pipe to the daemon: the questions in flight and their deadlines.
/// It exists before the instrumentation does, so that the daemon's answers have somewhere to
/// go while the startup self-test is still waiting for one.
export function createAdminChannel(send, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const pending = new Map();
  let sequence = 0;
  let asked = 0;
  let deadlineMs = timeoutMs;
  const settle = (id, verdict) => {
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    clearTimeout(entry.timer);
    entry.resolve(verdict);
  };
  return {
    /// Questions asked so far, answered or not.
    get asked() {
      return asked;
    },
    pending: () => pending.size,
    /// Shortens (or restores) the deadline of the questions asked from now on.
    setDeadline(ms) {
      deadlineMs = ms;
    },
    ask(projectId, token) {
      return new Promise((resolve) => {
        asked += 1;
        if (typeof projectId !== "string" || projectId === "" || typeof token !== "string") {
          resolve({ ok: false, reason: "unavailable" });
          return;
        }
        if (pending.size >= MAX_IN_FLIGHT) {
          resolve({ ok: false, reason: "unavailable" });
          return;
        }
        const id = `admin-${++sequence}`;
        const timer = setTimeout(() => settle(id, { ok: false, reason: "timeout" }), deadlineMs);
        pending.set(id, { resolve, timer });
        try {
          send({ type: "appCheck:verify", requestId: id, projectId, token });
        } catch {
          settle(id, { ok: false, reason: "unavailable" });
        }
      });
    },
    /// Hands over one `appCheck:verdict` frame. Only the right request id settles anything, once.
    deliver(message) {
      if (message?.type !== "appCheck:verdict" || typeof message.requestId !== "string") return;
      settle(
        message.requestId,
        message.ok === true ? { ok: true } : { ok: false, reason: String(message.reason ?? "unavailable") },
      );
    },
    /// Fails everything in flight: the runner is going away.
    dispose() {
      for (const id of [...pending.keys()]) settle(id, { ok: false, reason: "disposed" });
    },
  };
}

function unsupported(reason, version = null) {
  return {
    supported: false,
    instrumentation: reason,
    version,
    report: { instrumentation: reason, firebaseAdminVersion: version },
    restore() {},
  };
}

/// The directory of the `firebase-admin` package that owns `entry`.
function packageRootOf(entry) {
  let dir = dirname(entry);
  const { root: filesystemRoot } = parsePath(dir);
  for (;;) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      if (pkg.name === "firebase-admin") return dir;
    } catch {
      // Not a package directory; keep walking up.
    }
    if (dir === filesystemRoot) break;
    dir = dirname(dir);
  }
  throw new Error(`no firebase-admin package directory above ${entry}`);
}

/// Whether `name` is an own function property of `target` that may be replaced.
function isPatchable(target, name) {
  if (target === null || target === undefined) return false;
  const d = Object.getOwnPropertyDescriptor(target, name);
  return !!d && typeof d.value === "function" && d.writable !== false && d.configurable !== false;
}

function loadModules(require, root) {
  const load = (relative) => require(join(root, relative));
  return {
    verifier: load("lib/app-check/token-verifier.js"),
    jwt: load("lib/utils/jwt.js"),
    client: load("lib/app-check/app-check-api-client-internal.js"),
    utils: load("lib/utils/index.js"),
    error: (() => {
      try {
        return load("lib/app-check/error.js");
      } catch {
        return null;
      }
    })(),
  };
}

/// Builds `(code, message) => FirebaseAppCheckError` for whichever constructor shape the
/// installed SDK has (13: positional, 14: info object), checking the result.
function errorFactory(modules) {
  const Ctor = modules.error?.FirebaseAppCheckError ?? modules.client.FirebaseAppCheckError;
  if (typeof Ctor !== "function") return null;
  const shapes = [
    (code, message) => new Ctor({ code, message }),
    (code, message) => new Ctor(code, message),
  ];
  for (const make of shapes) {
    try {
      const probe = make("invalid-argument", "probe");
      if (probe instanceof Error && probe.code === "app-check/invalid-argument" && probe.message === "probe") {
        return make;
      }
    } catch {
      // Try the other shape.
    }
  }
  return null;
}

/// An agent that refuses to open any connection: the self-test hands it to the SDK so that a
/// probe that unexpectedly reaches the stock key fetch cannot leave the process.
class RefusingAgent extends https.Agent {
  createConnection() {
    throw new Error("fireemu self-test: network access is refused");
  }
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/// A well-formed token the SDK's own decode and claim checks accept, signed by nothing.
function probeToken() {
  return [
    base64url({ alg: "RS256", typ: "JWT", kid: "fireemu-self-test" }),
    base64url({
      iss: "https://firebaseappcheck.googleapis.com/0",
      aud: [`projects/${SELF_TEST_PROJECT}`],
      sub: "fireemu-self-test",
      iat: 0,
      exp: 1,
    }),
    "AAAA",
  ].join(".");
}

/// Installs the instrumentation for the `firebase-admin` the codebase resolves.
///
/// `channel` is [`createAdminChannel`]'s: every `appCheck:verdict` frame the daemon sends must
/// reach its `deliver` from the moment it is created, the startup self-test included.
///
/// `options.enabled` is false unless the daemon asked for the instrumentation
/// (`FIREEMU_APP_CHECK_ADMIN=1`): without App Check there are no fireemu tokens to verify.
export async function instrumentAdminAppCheck(sourceDir, channel, options = {}) {
  const enabled = options.enabled ?? process.env.FIREEMU_APP_CHECK_ADMIN === "1";
  if (!enabled) return unsupported("disabled");

  const require = createRequire(join(sourceDir, "package.json"));
  let root;
  let version;
  try {
    root = packageRootOf(require.resolve("firebase-admin"));
    version = String(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version ?? "");
  } catch {
    return unsupported("not-installed");
  }
  const major = Number.parseInt(version.split(".")[0], 10);
  if (!SUPPORTED_MAJORS.includes(major)) {
    return unsupported(
      `firebase-admin ${version} is outside the supported range (major ${SUPPORTED_MAJORS.join(", ")})`,
      version,
    );
  }
  let modules;
  try {
    // By absolute path on purpose: these are internal modules the package's `exports` map does
    // not publish, and the realpath is the module instance the SDK itself holds.
    modules = loadModules(require, root);
  } catch (e) {
    return unsupported(`firebase-admin ${version} has no App Check internals: ${e?.message ?? e}`, version);
  }
  const { verifier, jwt, client, utils } = modules;
  const Verifier = verifier.AppCheckTokenVerifier;
  const Client = client.AppCheckApiClient;
  const probes = [
    [Verifier?.prototype, "verifySignature"],
    [Verifier?.prototype, "mapJwtErrorToAppCheckError"],
    [Verifier?.prototype, "verifyContent"],
    [Verifier?.prototype, "safeDecode"],
    [Verifier?.prototype, "verifyToken"],
    [Client?.prototype, "verifyReplayProtection"],
  ];
  for (const [target, name] of probes) {
    if (!isPatchable(target, name)) {
      return unsupported(`firebase-admin ${version} has no patchable ${name}`, version);
    }
  }
  const codes = jwt.JwtErrorCode;
  if (
    typeof jwt.JwtError !== "function" ||
    typeof utils.findProjectId !== "function" ||
    !codes ||
    ["NO_MATCHING_KID", "INVALID_SIGNATURE", "TOKEN_EXPIRED", "INVALID_ARGUMENT", "KEY_FETCH_ERROR"].some(
      (name) => typeof codes[name] !== "string",
    )
  ) {
    return unsupported(`firebase-admin ${version} no longer defines the JWT errors this instrumentation maps to`, version);
  }
  const makeError = errorFactory(modules);
  if (!makeError) {
    return unsupported(`firebase-admin ${version} constructs FirebaseAppCheckError in a shape this instrumentation does not know`, version);
  }

  const originals = {
    verifySignature: Verifier.prototype.verifySignature,
    verifyReplayProtection: Client.prototype.verifyReplayProtection,
  };

  /// The error a verdict becomes, thrown through the SDK's own mapper.
  function failure(self, verdict) {
    const reason = Object.hasOwn(REASONS, verdict.reason) ? REASONS[verdict.reason] : undefined;
    if (reason) {
      return self.mapJwtErrorToAppCheckError(new jwt.JwtError(codes[reason.code], reason.message));
    }
    const why =
      verdict.reason === "timeout"
        ? "the daemon did not answer in time"
        : verdict.reason === "disposed"
          ? "the Functions runner is shutting down"
          : "the daemon cannot verify App Check tokens";
    return self.mapJwtErrorToAppCheckError(
      new jwt.JwtError(codes.KEY_FETCH_ERROR, unavailableMessage(why)),
    );
  }

  function verifySignature(jwtToken) {
    const self = this;
    return utils
      .findProjectId(self.app)
      .then((projectId) => channel.ask(projectId, jwtToken))
      .then((verdict) => {
        if (verdict?.ok === true) return undefined;
        throw failure(self, verdict ?? { ok: false, reason: "unavailable" });
      });
  }
  function verifyReplayProtection() {
    return Promise.reject(
      makeError(
        "unimplemented",
        "verifyToken({ consume: true }) is not supported by fireemu: limited-use App Check " +
          "token consumption (APPCHECK-REPLAY-1) is unimplemented, and the production App Check " +
          "API is never called.",
      ),
    );
  }

  Verifier.prototype.verifySignature = verifySignature;
  Client.prototype.verifyReplayProtection = verifyReplayProtection;
  const restore = () => {
    Verifier.prototype.verifySignature = originals.verifySignature;
    Client.prototype.verifyReplayProtection = originals.verifyReplayProtection;
  };

  const handle = {
    supported: true,
    instrumentation: "ok",
    version,
    report: { instrumentation: "ok", firebaseAdminVersion: version },
    restore,
  };

  // Startup self-test. Run the SDK's real `verifyToken` on a probe app and require that the
  // patched step was the one consulted, exactly once, and that it failed the way a verdict
  // does. A supported-range release that routes verification around `verifySignature` fails
  // here instead of silently verifying nothing.
  const app = { options: { projectId: SELF_TEST_PROJECT, httpAgent: new RefusingAgent() } };
  const before = channel.asked;
  channel.setDeadline(
    Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, options.selfTestTimeoutMs ?? SELF_TEST_TIMEOUT_MS),
  );
  let outcome;
  try {
    const probe = new Verifier(app);
    const expected = probe.mapJwtErrorToAppCheckError(
      new jwt.JwtError(codes.NO_MATCHING_KID, REASONS["no-matching-kid"].message),
    );
    outcome = await probe.verifyToken(probeToken()).then(
      () => ({ kind: "accepted" }),
      (error) => ({ kind: "rejected", error, expected }),
    );
  } catch (e) {
    outcome = { kind: "threw", error: e };
  }
  channel.setDeadline(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const consultedOnce = channel.asked - before === 1;
  if (outcome.kind === "accepted" || !consultedOnce) {
    channel.dispose();
    restore();
    return unsupported(
      `the startup self-test did not reach the instrumented signature step in firebase-admin ${version}`,
      version,
    );
  }
  const answeredByDaemon =
    outcome.kind === "rejected" &&
    outcome.error?.code === outcome.expected.code &&
    outcome.error?.message === outcome.expected.message;
  if (!answeredByDaemon) {
    // Still installed and still failing closed (every question ends in the SDK's key-fetch
    // failure), but the daemon is not answering: say so.
    channel.dispose();
    handle.instrumentation = "daemon-unavailable";
    handle.report = { instrumentation: "daemon-unavailable", firebaseAdminVersion: version };
  }
  return handle;
}
