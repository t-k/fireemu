import { verifyFixtureIdToken } from "./fixture-proof.mjs";

const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const ACCOUNTS = ["user-a", "user-b", "revoked-token", "foreign-project-token"];
const INPUTS = ["runId", "counter", "transport", "keySet", "digestSalt", "passwords", "nowSeconds", "waitUntilSeconds", "writeOwnership", "writeProof", "writeCleanup"];
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;

function dataRecord(value, keys) {
  if (!plain(value)) throw new Error("invalid credential session input");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error("invalid credential session input");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("invalid credential session input");
  }
}

/** Execute the reviewed fixture lifecycle through one supplied counter; no built-in network or file I/O. */
export function createCredentialFixtureSession(options) {
  dataRecord(options, INPUTS);
  dataRecord(options.passwords, ACCOUNTS);
  dataRecord(options.keySet, ["fetchedAt", "expiresAt", "publicKeys"]);
  if (!plain(options.keySet.publicKeys)) throw new Error("invalid credential session input");
  const kids = Reflect.ownKeys(options.keySet.publicKeys);
  dataRecord(options.keySet.publicKeys, kids);
  if (
    typeof options.runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(options.runId) ||
    typeof options.digestSalt !== "string" || !/^[a-f0-9]{64}$/.test(options.digestSalt) ||
    ACCOUNTS.some((name) => typeof options.passwords[name] !== "string" || !/^[!-~]{20,128}$/.test(options.passwords[name])) ||
    ["transport", "nowSeconds", "waitUntilSeconds", "writeOwnership", "writeProof", "writeCleanup"].some((key) => typeof options[key] !== "function") ||
    !options.counter || ["send", "snapshot", "enterRecovery"].some((key) => typeof options.counter[key] !== "function") ||
    !Number.isSafeInteger(options.keySet.fetchedAt) || !Number.isSafeInteger(options.keySet.expiresAt) ||
    kids.length === 0 || kids.length > 20 || kids.some((kid) => typeof kid !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(kid) || typeof options.keySet.publicKeys[kid] !== "string")
  ) throw new Error("invalid credential session input");
  const { runId, counter, transport, digestSalt, nowSeconds, waitUntilSeconds, writeOwnership, writeProof, writeCleanup } = options;
  const passwords = { ...options.passwords };
  const keySet = structuredClone(options.keySet);
  const owned = new Map();
  const unconfirmedCreations = new Set();
  const tokens = new Map();
  let mode = "new";
  let busy = false;
  let journalHealthy = true;

  function now() {
    let value;
    try { value = nowSeconds(); } catch { throw new Error("fixture clock failed"); }
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error("fixture clock failed");
    return value;
  }
  const email = (account) => `storage-rules-${runId}-${account}@example.com`;
  const uid = (account) => `storage-rules-${runId}-${account}`;

  async function journal(writer, value) {
    if (!journalHealthy) throw new Error("fixture journal uncertain");
    try { await writer(Object.freeze(value)); } catch {
      journalHealthy = false;
      throw new Error("fixture journal uncertain");
    }
  }

  function checkNormal() {
    if (counter.snapshot().mode !== "normal") throw new Error("fixture session unavailable");
  }

  async function exclusive(allowed, execute, requireNormal = false) {
    if (busy) throw new Error("fixture session busy");
    if (!allowed.includes(mode)) throw new Error("fixture session unavailable");
    if (!journalHealthy) throw new Error("fixture journal uncertain");
    if (requireNormal) checkNormal();
    busy = true;
    try { return await execute(); } catch (error) {
      mode = "failed";
      throw error;
    } finally { busy = false; }
  }

  async function request(account, step, action, body, { project = QUERY, client = false, prefix = "auth", allowRecovery = false } = {}) {
    if (!journalHealthy) throw new Error("fixture journal uncertain");
    if (!allowRecovery) checkNormal();
    else {
      const state = counter.snapshot();
      if (!["normal", "recovery"].includes(state.mode)) throw new Error("fixture counter unavailable");
      if (state.mode === "normal" && state.normal >= state.normalCap) counter.enterRecovery();
    }
    const operationId = `${prefix}/${account}/${step}`;
    const path = client ? `/v1/accounts:${action}` : `/v1/projects/${project}/accounts${action ? `:${action}` : ""}`;
    const spec = Object.freeze({ project, method: "POST", origin: "https://identitytoolkit.googleapis.com", path,
      credential: client ? "api-key-only" : "owner-oauth", apiKeyReference: project === QUERY ? "query-api-key" : "idp-api-key", body: Object.freeze(body) });
    let response;
    try { response = await counter.send(operationId, () => transport(operationId, spec)); } catch {
      if (counter.snapshot().mode === "journal-uncertain") journalHealthy = false;
      throw new Error(journalHealthy ? "fixture request failed" : "fixture journal uncertain");
    }
    if (!plain(response) || response.status !== 200 || !plain(response.body)) throw new Error("invalid fixture response");
    return response.body;
  }

  function users(body) {
    if (!Object.hasOwn(body, "users")) return [];
    if (!Array.isArray(body.users) || body.users.some((user) => !plain(user))) throw new Error("invalid fixture account readback");
    return body.users;
  }

  function checkUser(body, account, expectedUid, expectedClaims = {}) {
    const found = users(body);
    const user = found[0];
    let attributes;
    try { attributes = JSON.parse(user?.customAttributes ?? "{}"); } catch { throw new Error("invalid fixture account readback"); }
    if (
      found.length !== 1 || user.localId !== expectedUid || user.email !== email(account) || user.emailVerified !== (account === "user-a") ||
      Object.hasOwn(user, "tenantId") || !plain(attributes) || Object.keys(attributes).length !== Object.keys(expectedClaims).length ||
      Object.keys(expectedClaims).some((key) => attributes[key] !== expectedClaims[key])
    ) throw new Error("invalid fixture account readback");
    return user;
  }

  async function register(account, project, body, expectedUid = null) {
    if (typeof body.localId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(body.localId) || body.email !== email(account) || (expectedUid !== null && body.localId !== expectedUid)) {
      throw new Error("invalid fixture creation receipt");
    }
    const receipt = { account, project, uid: body.localId, email: email(account), creationRequestId: `auth/${account}/${project === QUERY ? "create" : "sign-up"}` };
    owned.set(account, { ...receipt, deleteAttempted: false, deleted: false });
    await journal(writeOwnership, receipt);
    unconfirmedCreations.delete(account);
    return body.localId;
  }

  function verifySnapshot(principal, token, expectedUid, validSince = null) {
    return verifyFixtureIdToken({ token, principal, runId, expectedUid, keySet, nowSeconds: now(), validSince, digestSalt });
  }

  async function capture(principal, token, expectedUid, validSince = null) {
    const proof = verifySnapshot(principal, token, expectedUid, validSince);
    await journal(writeProof, proof);
    checkNormal();
    verifySnapshot(principal, token, expectedUid, validSince);
    tokens.set(principal, Object.freeze({ token, expectedUid, validSince, project: proof.project }));
    return proof;
  }

  async function create(account) {
    unconfirmedCreations.add(account);
    const created = await request(account, "create", "", { localId: uid(account), email: email(account), password: passwords[account], emailVerified: account === "user-a" });
    await register(account, QUERY, created, uid(account));
    checkUser(await request(account, "lookup-created", "lookup", { localId: [uid(account)] }), account, uid(account));
  }

  async function setClaims(account, attributes, suffix) {
    await request(account, suffix === "plain" ? "clear-claims" : "set-claims", "update", { localId: uid(account), customAttributes: JSON.stringify(attributes) });
    checkUser(await request(account, `lookup-${suffix}`, "lookup", { localId: [uid(account)] }), account, uid(account), attributes);
  }

  async function signIn(account, principal = account) {
    const body = await request(account, principal === "user-plain" ? "sign-in-plain" : "sign-in", "signInWithPassword", { email: email(account), password: passwords[account], returnSecureToken: true }, { client: true });
    if (body.localId !== uid(account) || body.email !== email(account) || typeof body.idToken !== "string") throw new Error("invalid fixture issuance receipt");
    return body.idToken;
  }

  async function deleteOwned(account, prefix = "auth") {
    const owner = owned.get(account);
    if (!owner || owner.deleted) return;
    if (!owner.deleteAttempted) {
      owner.deleteAttempted = true;
      await request(account, "delete", "delete", { localId: owner.uid }, { project: owner.project, prefix, allowRecovery: true });
    }
    const absent = await request(account, "absence", "lookup", { localId: [owner.uid] }, { project: owner.project, prefix, allowRecovery: true });
    if (users(absent).length !== 0) throw new Error("fixture cleanup unconfirmed");
    await journal(writeCleanup, { account, project: owner.project, uid: owner.uid, absent: true, requestId: `${prefix}/${account}/absence` });
    owner.deleted = true;
    for (const [principal, token] of tokens) if (token.project === owner.project && token.expectedUid === owner.uid) tokens.delete(principal);
  }

  return {
    prepareQuery() {
      return exclusive(["new"], async () => {
        await create("user-a");
        await setClaims("user-a", { role: "reader", level: 7 }, "claims");
        await capture("user-a", await signIn("user-a"), uid("user-a"));
        await setClaims("user-a", {}, "plain");
        await capture("user-plain", await signIn("user-a", "user-plain"), uid("user-a"));
        await create("user-b");
        await setClaims("user-b", { role: "writer", level: "7" }, "claims");
        await capture("user-b", await signIn("user-b"), uid("user-b"));
        await create("revoked-token");
        const token = await signIn("revoked-token");
        let issuedAt;
        try { issuedAt = JSON.parse(Buffer.from(token.split(".")[1], "base64url")).iat; } catch { throw new Error("invalid fixture token"); }
        if (!Number.isSafeInteger(issuedAt) || issuedAt <= 0 || issuedAt > now()) throw new Error("invalid fixture time");
        if (now() <= issuedAt) {
          try { await waitUntilSeconds(issuedAt + 1); } catch { throw new Error("fixture clock failed"); }
        }
        const boundary = now();
        if (boundary <= issuedAt) throw new Error("invalid revocation boundary");
        await request("revoked-token", "revoke", "update", { localId: uid("revoked-token"), validSince: String(boundary) });
        const readback = checkUser(await request("revoked-token", "lookup-revoked", "lookup", { localId: [uid("revoked-token")] }), "revoked-token", uid("revoked-token"));
        if (readback.validSince !== String(boundary)) throw new Error("invalid revocation readback");
        await capture("revoked-token", token, uid("revoked-token"), boundary);
        mode = "query-ready";
        return Object.freeze({ uidA: uid("user-a"), uidB: uid("user-b"), uidRevoked: uid("revoked-token"), sendAuthorized: false });
      }, true);
    },
    token(principal) {
      if (busy || mode !== "query-ready" || !journalHealthy || counter.snapshot().mode !== "normal" || !tokens.has(principal)) throw new Error("fixture session unavailable");
      const snapshot = tokens.get(principal);
      verifySnapshot(principal, snapshot.token, snapshot.expectedUid, snapshot.validSince);
      return snapshot.token;
    },
    withForeignFixture(subject) {
      return exclusive(["query-ready"], async () => {
        if (typeof subject !== "function" || owned.has("foreign-project-token")) throw new Error("fixture session unavailable");
        let result;
        let failure;
        try {
          const baseline = await request("foreign-project-token", "baseline", "lookup", { email: [email("foreign-project-token")] }, { project: IDP });
          if (users(baseline).length !== 0) throw new Error("fixture account already exists");
          unconfirmedCreations.add("foreign-project-token");
          const signup = await request("foreign-project-token", "sign-up", "signUp", { email: email("foreign-project-token"), password: passwords["foreign-project-token"], returnSecureToken: true }, { project: IDP, client: true });
          const foreignUid = await register("foreign-project-token", IDP, signup);
          checkUser(await request("foreign-project-token", "lookup-token", "lookup", { idToken: signup.idToken }, { project: IDP, client: true }), "foreign-project-token", foreignUid);
          await capture("foreign-project-token", signup.idToken, foreignUid);
          checkNormal();
          verifySnapshot("foreign-project-token", signup.idToken, foreignUid);
          try { result = await subject(signup.idToken); } catch { throw new Error("fixture subject failed"); }
        } catch (error) { failure = error; }
        if (journalHealthy && owned.has("foreign-project-token")) {
          if (failure && counter.snapshot().mode === "normal") counter.enterRecovery();
          try { await deleteOwned("foreign-project-token", counter.snapshot().mode === "recovery" ? "recovery/auth" : "auth"); } catch (error) { failure = error; }
        }
        if (failure) throw failure;
        return result;
      }, true);
    },
    cleanupQuery() {
      return exclusive(["query-ready"], async () => {
        for (const account of ACCOUNTS.slice(0, 3)) await deleteOwned(account);
        mode = "closed";
      });
    },
    recoverOwnedAccounts() {
      return exclusive(["failed", "query-ready"], async () => {
        if (counter.snapshot().mode === "normal") counter.enterRecovery();
        if (counter.snapshot().mode !== "recovery") throw new Error("fixture counter unavailable");
        for (const account of ["foreign-project-token", ...ACCOUNTS.slice(0, 3)]) await deleteOwned(account, "recovery/auth");
        if (unconfirmedCreations.size !== 0) throw new Error("fixture creation unconfirmed");
        mode = "recovered";
      });
    },
    snapshot() {
      return Object.freeze({ mode, busy, journalHealthy, sendAuthorized: false, unconfirmedCreations: Object.freeze([...unconfirmedCreations].sort()), remainingAccounts: Object.freeze([...owned.values()].filter((owner) => !owner.deleted).map((owner) => Object.freeze({ account: owner.account, project: owner.project, uid: owner.uid, deleteAttempted: owner.deleteAttempted }))) });
    },
  };
}
