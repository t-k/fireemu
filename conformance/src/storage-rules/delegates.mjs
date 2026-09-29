import { createHmac } from "node:crypto";
import { createAuthWireTransport } from "./auth-wire.mjs";
import { createCountedCredentialCache } from "./credential-cache.mjs";
import { createCredentialFixtureSession } from "./credential-session.mjs";
import { plain } from "./shape.mjs";

// Glue between the controller's delegated steps and the modules that carry their own requests: the counted credential cache,
// the fixture session and the Auth wire. Every request they make goes through `gate.delegated`. This module holds credentials
// only in memory and hands them to the gate as headers; it records digests through the injected writers, never a token.
const USER_PRINCIPALS = new Set(["user-a", "user-b", "user-plain", "revoked-token"]);
const OWNER_REFRESH_MARGIN_SECONDS = 300;
const USER_TOKEN_MARGIN_SECONDS = 60;
const OWNER_MARGIN_SECONDS = 60;
// The web Storage SDK sends the user's ID token as `Authorization: Firebase <token>` (pinned firebase 12.18.0,
// @firebase/storage 0.14.5: conformance/node_modules/@firebase/storage/dist/index.esm.js:816, dist/node-esm/index.node.esm.js:813).
const USER_TOKEN_SCHEME = "Firebase";
const PROJECTS = new Set(["fireemu-oracle-query", "fireemu-oracle-idp"]);
const EVIDENCE = ["writeCredentialProof", "writeOwnership", "writeCleanup"];
const INPUTS = ["gate", "adc", "apiKeys", "passwords", "digestSalt", "runId", "nowSeconds", "waitUntilSeconds", "evidence", "malformed"];
const bad = (message) => { throw new Error(message); };

function tokenExpiry(token) {
  try { return JSON.parse(Buffer.from(token.split(".")[1], "base64url")).exp; } catch { return bad("unreadable token"); }
}

export function createRunnerDelegates(options) {
  if (!plain(options) || Reflect.ownKeys(options).length !== INPUTS.length || !INPUTS.every((key) => Object.hasOwn(options, key))) bad("invalid runner delegate options");
  const { gate, adc, apiKeys, passwords, digestSalt, runId, nowSeconds, waitUntilSeconds, evidence, malformed } = options;
  if (
    typeof gate?.delegated?.http !== "function" || typeof gate?.delegated?.counter?.send !== "function" || typeof gate?.snapshot !== "function" ||
    !plain(evidence) || !EVIDENCE.every((name) => typeof evidence[name] === "function") || !plain(malformed) ||
    ["malformed-token", "malformed-oauth"].some((key) => typeof malformed[key] !== "string" || !/^[\x21-\x7e][\x20-\x7e]{0,255}$/.test(malformed[key])) ||
    ![nowSeconds, waitUntilSeconds].every((fn) => typeof fn === "function")
  ) bad("invalid runner delegate options");

  // The modules write their own record shapes; the journal takes only digests. An address becomes a salted digest, its run prefix stays.
  const writeProof = (proof) => evidence.writeCredentialProof(proof);
  const writeOwnership = (receipt) => evidence.writeOwnership({
    account: receipt.account, project: receipt.project, uid: receipt.uid, runPrefix: `storage-rules-${runId}`,
    emailSha256: createHmac("sha256", Buffer.from(digestSalt, "hex")).update("storage-rules-email\0").update(receipt.email).digest("hex"), creationRequestId: receipt.creationRequestId,
  });
  const writeCleanup = (receipt) => evidence.writeCleanup({ account: receipt.account, project: receipt.project, uid: receipt.uid, absent: receipt.absent, requestId: receipt.requestId });
  const cache = createCountedCredentialCache({ adc, counter: gate.delegated.counter, digestSalt, nowSeconds, sendHttp: gate.delegated.http, writeProof });
  const wire = createAuthWireTransport({ runId, apiKeys, ownerCredential: () => cache.ownerCredential(), nowSeconds, sendHttp: gate.delegated.http });
  let session = null;
  let foreign = null;
  let foreignToken = null;
  const nextRefresh = { normal: 2, recovery: 1 };

  function createSession() {
    if (session !== null) bad("fixture session already created");
    session = createCredentialFixtureSession({
      runId, counter: gate.delegated.counter, transport: (operationId, spec) => wire.send(operationId, spec), keySet: cache.keySet(), digestSalt, passwords,
      nowSeconds, waitUntilSeconds, writeOwnership, writeProof, writeCleanup,
    });
    return session;
  }

  const ownerExpiresIn = () => { try { return cache.ownerCredential().expiresAt - nowSeconds(); } catch { return -1; } };

  // Refresh the owner token through the next declared refresh ID when it is close to expiry. Refresh IDs are a budget: none is reused.
  async function refreshOwnerIfStale(margin) {
    if (ownerExpiresIn() > margin) return;
    const mode = gate.snapshot().mode;
    if (!["normal", "recovery"].includes(mode)) bad("no refresh outside a request mode");
    const index = nextRefresh[mode]++;
    if (index > 8) bad("owner token refresh budget exhausted");
    await cache.refreshOwner(mode === "recovery" ? `recovery/auth-shared/owner-token/${index}` : `auth-shared/owner-token/${index}`);
  }

  function userToken(principal) {
    if (principal === "foreign-project-token") return foreignToken ?? bad("no foreign token");
    return session?.token(principal) ?? bad("no session");
  }

  const delegates = {
    async "preflight-cache"(row) {
      if (row.id === "preflight/auth/owner-token") await cache.refreshOwner(row.id);
      else if (row.id === "preflight/auth/signing-keys") await cache.fetchSigningKeys(row.id);
      else bad("unknown preflight cache row");
    },
    // The first refresh of each kind in the normal phase; the other declared refreshes are spent only on demand.
    async "credential-cache"() {
      await cache.refreshOwner("auth-shared/owner-token/1");
      await cache.fetchSigningKeys("auth-shared/signing-keys/1");
    },
    async "prepare-query"() { await createSession().prepareQuery(); },
    // The declared foreign row runs between these two steps; the fixture session holds the account open until the cleanup step.
    async "foreign-signup"() {
      if (session === null || foreign !== null) bad("foreign fixture unavailable");
      let release;
      const hold = new Promise((resolve, reject) => { release = { resolve, reject }; });
      let ready;
      const opened = new Promise((resolve) => { ready = resolve; });
      const done = session.withForeignFixture(async (token) => { foreignToken = token; ready(true); try { await hold; } finally { foreignToken = null; } });
      done.catch(() => ready(false));
      foreign = { release, done };
      if (!(await opened)) { foreign = null; await done; bad("foreign fixture did not open"); }
    },
    async "foreign-cleanup"() {
      if (foreign === null) bad("no foreign fixture is open");
      const { release, done } = foreign;
      foreign = null;
      release.resolve();
      await done;
    },
    async "cleanup-query"() { await (session ?? bad("no session")).cleanupQuery(); },
    // Recovery: abandon an open foreign fixture (its own cleanup deletes the account), then delete every owned account.
    async "recover-accounts"() {
      if (session === null) return;
      if (foreign !== null) {
        const { release, done } = foreign;
        foreign = null;
        release.reject(new Error("foreign fixture abandoned"));
        await done.catch(() => {});
      }
      await refreshOwnerIfStale(OWNER_REFRESH_MARGIN_SECONDS);
      await session.recoverOwnedAccounts();
    },
  };

  const credentials = {
    // Called before the freshness check of every row: keep the owner token from expiring mid-run.
    async ensure(row) {
      if (row.request.credential === "admin" && gate.snapshot().mode !== "preflight") await refreshOwnerIfStale(OWNER_REFRESH_MARGIN_SECONDS);
    },
    fresh(row) {
      const credential = row.request.credential;
      if (["anonymous", "malformed-token", "malformed-oauth"].includes(credential)) return true;
      if (credential === "admin") return ownerExpiresIn() > OWNER_MARGIN_SECONDS;
      if (USER_PRINCIPALS.has(credential) || credential === "foreign-project-token") {
        try { return tokenExpiry(userToken(credential)) - nowSeconds() > USER_TOKEN_MARGIN_SECONDS; } catch { return false; }
      }
      return false;
    },
    headersFor(credential, context) {
      if (credential === "anonymous") return {};
      if (credential === "malformed-token" || credential === "malformed-oauth") return { authorization: malformed[credential] };
      if (credential === "admin") {
        if (!PROJECTS.has(context?.project)) bad("no known project for the owner credential");
        const owner = cache.ownerCredential();
        return { authorization: `Bearer ${owner.accessToken}`, "x-goog-user-project": context.project };
      }
      if (USER_PRINCIPALS.has(credential) || credential === "foreign-project-token") return { authorization: `${USER_TOKEN_SCHEME} ${userToken(credential)}` };
      return bad("unknown credential");
    },
  };

  return Object.freeze({ delegates: Object.freeze(delegates), credentials: Object.freeze(credentials), snapshot: () => Object.freeze({ session: session?.snapshot() ?? null, foreignOpen: foreign !== null, cache: cache.snapshot() }) });
}
