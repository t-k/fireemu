import { createHash, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { isDeepStrictEqual, types } from "node:util";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const ascii = (value, max) =>
  typeof value === "string" && /^[\x21-\x7e]+$/.test(value) && value.length <= max;
const authStates = new WeakMap();

/** Origin and recording are private; usability still requires the original UID, clock and admission proofs. */
export function originalProductionAuthAuthorizationProvider(state, recording) {
  const binding = authStates.get(state);
  if (!binding || recording !== binding.recording)
    throw new Error("invalid original production Auth provider");
  return binding.provider;
}

/** Verify the original state and its canonical production recording without invoking caller hooks. */
export function verifyProductionAuthBinding(state, supplied) {
  try {
    const proof = record(supplied, ["plan", "recording"]),
      binding = authStates.get(state);
    return (
      Object.keys(proof).length === 2 &&
      binding !== undefined &&
      proof.recording === binding.recording &&
      isDeepStrictEqual(planCopy(proof.plan), binding.plan)
    );
  } catch {
    return false;
  }
}

/** Cleanup is terminal only after the original recipe capability and final proof persistence succeed. */
export function verifyProductionAuthRecipeTerminal(state, supplied) {
  try {
    const proof = record(supplied, ["recipeId", "recipeToken"]);
    return (
      Object.keys(proof).length === 2 &&
      typeof proof.recipeId === "string" &&
      proof.recipeToken !== undefined &&
      authStates.get(state)?.terminal(proof) === true
    );
  } catch {
    return false;
  }
}
function record(value, keys) {
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const copy = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      (keys && !keys.includes(key)) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error();
    copy[key] = descriptor.value;
  }
  return copy;
}
function planCopy(value, depth = 0) {
  if (depth > 16) throw new Error();
  if (value === null || typeof value !== "object") {
    if (!["string", "number", "boolean"].includes(typeof value) && value !== null)
      throw new Error();
    return value;
  }
  if (types.isProxy(value)) throw new Error();
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > 64 ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      throw new Error();
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
      return planCopy(descriptor.value, depth + 1);
    });
  }
  return Object.fromEntries(
    Object.entries(record(value)).map(([key, item]) => [key, planCopy(item, depth + 1)]),
  );
}
function parseJson(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 32768) throw new Error();
  const text = bytes.toString("utf8");
  if (!Buffer.from(text).equals(bytes) || parseCaptureJsonSpans(text).type !== "object")
    throw new Error();
  return JSON.parse(text);
}
async function responseJson(response) {
  if (response.status !== 200) throw new Error();
  const bytes = Buffer.from(await response.arrayBuffer()),
    data = parseJson(bytes);
  if (Object.hasOwn(data, "error")) throw new Error();
  return { data, bodySha256: sha256(bytes) };
}
function userMatches(data, account, absent = false) {
  if (
    (Object.hasOwn(data, "kind") && data.kind !== "identitytoolkit#GetAccountInfoResponse") ||
    (Object.hasOwn(data, "users") && !Array.isArray(data.users))
  )
    throw new Error();
  const users = data.users ?? [];
  if (absent) {
    if (users.length !== 0) throw new Error();
    return;
  }
  if (
    users.length !== 1 ||
    users[0]?.localId !== account.uid ||
    users[0].email !== account.email ||
    users[0].disabled === true ||
    Object.hasOwn(users[0], "tenantId")
  )
    throw new Error();
}

/** Production-only account lifecycle using declared slots; JWT decoding is correlated with client and owner lookup, not treated as signature verification. */
export function createProductionAuthState(input) {
  let options, plan, recipes;
  try {
    options = record(input, [
      "plan",
      "recording",
      "projectNumber",
      "apiKey",
      "controls",
      "verifyAdmission",
      "onSecret",
      "onJournal",
      "onProof",
    ]);
    options.controls = record(options.controls, ["send", "snapshot"]);
    if (
      Object.keys(options).length !== 9 ||
      ![1, 2].includes(options.recording) ||
      typeof options.projectNumber !== "string" ||
      !/^[1-9][0-9]{5,20}$/.test(options.projectNumber) ||
      typeof options.apiKey !== "string" ||
      !/^[A-Za-z0-9_-]{1,256}$/.test(options.apiKey)
    )
      throw new Error();
    const callbacks = [
      options.controls.send,
      options.verifyAdmission,
      options.onSecret,
      options.onJournal,
      options.onProof,
    ];
    if (
      callbacks.some((fn) => typeof fn !== "function" || types.isProxy(fn)) ||
      [options.verifyAdmission, options.onSecret].some(
        (fn) => Object.getPrototypeOf(fn) !== Function.prototype,
      )
    )
      throw new Error();
    plan = planCopy(options.plan);
    if (
      !isDeepStrictEqual(
        plan,
        buildProductionStage3DraftPlan({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runIds: plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error();
    recipes = buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[options.recording - 1].runId,
    }).recipes;
  } catch {
    throw new Error("invalid production Auth configuration");
  }
  const recording = options.recording,
    accounts = new Map(),
    programs = new Map(
      recipes.map((recipe, index) => [
        recipe.id,
        {
          recipe,
          index: index + 1,
          setup: false,
          refresh: false,
          cleanup: false,
          capability: undefined,
          refreshCapability: undefined,
          cleanupCapability: undefined,
          cleanupComplete: false,
        },
      ]),
    );
  for (const program of programs.values())
    for (const kind of ["valid", "competitor"])
      accounts.set(program.recipe.accounts[kind].ref, {
        ...program.recipe.accounts[kind],
        kind,
        program,
        state: "unobserved",
        uid: null,
        token: null,
        refreshToken: null,
        password: null,
        deadline: null,
      });
  let busy = false,
    subjectFailed = false,
    closed = false,
    keyRegistered = false,
    malformed = null,
    lastMonotonic = -Infinity,
    lastWall = -Infinity;
  function clearCredentials() {
    for (const account of accounts.values()) {
      account.token = null;
      account.refreshToken = null;
      account.password = null;
      account.deadline = null;
    }
    malformed = null;
    options.apiKey = null;
  }
  function clock() {
    const monotonic = performance.now(),
      wall = Date.now();
    if (
      !Number.isFinite(monotonic) ||
      monotonic < 0 ||
      !Number.isSafeInteger(wall) ||
      wall < 0 ||
      monotonic < lastMonotonic ||
      wall < lastWall ||
      (lastMonotonic !== -Infinity &&
        Math.abs(wall - lastWall - (monotonic - lastMonotonic)) > 5000)
    )
      throw new Error();
    lastMonotonic = monotonic;
    lastWall = wall;
    return { monotonic, wall };
  }
  function admitted(suppliedContext) {
    if (closed || options.verifyAdmission(suppliedContext) !== true || closed) throw new Error();
  }
  function secret(value) {
    if (closed || !ascii(value, 8192)) throw new Error();
    const result = options.onSecret(value);
    if (types.isPromise(result)) void Promise.prototype.then.call(result, undefined, () => {});
    if (result !== undefined || closed) throw new Error();
  }
  function slot(account, stage, suffix) {
    return `r${recording}/auth${account.program.index}-${account.kind}-${stage}-${suffix}`;
  }
  function context(id, phase) {
    return Object.freeze({
      recording,
      phase,
      kind: "auth-state",
      operationId: `r${recording}/control/${sha256(id)}`,
    });
  }
  async function send(account, stage, suffix, capability, body, client, mutation) {
    const id = slot(account, stage, suffix),
      phase = stage === "cleanup" ? "cleanup" : "subject",
      requestContext = context(id, phase);
    admitted(requestContext);
    const started = clock();
    if (mutation) {
      await options.onJournal(
        Object.freeze({
          type: "production-auth-ownership",
          operationId: requestContext.operationId,
          accountRef: account.ref,
          accountMutation: mutation,
          ...(mutation === "delete" ? { ownedUid: account.uid } : {}),
        }),
      );
      admitted(requestContext);
      account.state = mutation === "create" ? "creating" : "deleting";
    }
    admitted(requestContext);
    const response = await options.controls.send(id, {
      recipeToken: capability,
      parameters: client ? { apiKey: options.apiKey } : {},
      body: Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body)),
    });
    const result = await responseJson(response);
    admitted(requestContext);
    const received = clock();
    return { ...result, started, received, id, requestContext };
  }
  function tokenProof(account, result, token, expiresIn) {
    if (
      !ascii(token, 8192) ||
      typeof expiresIn !== "string" ||
      !/^[1-9][0-9]{1,3}$/.test(expiresIn)
    )
      throw new Error();
    const ttl = Number(expiresIn);
    if (ttl <= 60 || ttl > 3600) throw new Error();
    const parts = token.split(".");
    if (
      parts.length !== 3 ||
      parts.some(
        (part) =>
          !/^[A-Za-z0-9_-]+$/.test(part) ||
          Buffer.from(part, "base64url").toString("base64url") !== part,
      )
    )
      throw new Error();
    const header = parseJson(Buffer.from(parts[0], "base64url")),
      claims = parseJson(Buffer.from(parts[1], "base64url"));
    const seconds = result.received.wall / 1000;
    if (
      header.alg !== "RS256" ||
      !ascii(header.kid, 256) ||
      claims.sub !== account.uid ||
      claims.user_id !== account.uid ||
      claims.email !== account.email ||
      claims.aud !== plan.projectId ||
      claims.iss !== `https://securetoken.google.com/${plan.projectId}` ||
      Object.hasOwn(claims, "tenant_id") ||
      claims.firebase?.sign_in_provider !== "password" ||
      Object.hasOwn(claims.firebase, "tenant") ||
      !Number.isSafeInteger(claims.iat) ||
      !Number.isSafeInteger(claims.exp) ||
      claims.iat > seconds + 5 ||
      claims.exp <= seconds + 60 ||
      claims.exp <= claims.iat ||
      claims.exp - claims.iat > 3600
    )
      throw new Error();
    const deadline = Math.min(
      result.started.monotonic + ttl * 1000,
      result.received.monotonic + claims.exp * 1000 - result.received.wall,
    );
    if (deadline - result.received.monotonic <= 60000) throw new Error();
    return { token, deadline };
  }
  async function publish(account, stage, response, proof) {
    await options.onProof(
      Object.freeze({
        type: "production-auth-account",
        recording,
        accountRef: account.ref,
        stage,
        ownedUidSha256: sha256(account.uid),
        emailSha256: sha256(account.email),
        tokenSha256: sha256(proof.token),
        tokenByteLength: Buffer.byteLength(proof.token),
        responseBodySha256: response.bodySha256,
        deadlineMonotonicMs: proof.deadline,
      }),
    );
    admitted(response.requestContext);
    if (proof.deadline - clock().monotonic <= 60000) throw new Error();
    account.token = proof.token;
    account.deadline = proof.deadline;
    account.state = "verified";
  }
  async function setupAccount(account, capability) {
    userMatches(
      (await send(account, "setup", "email-absence", capability, { email: [account.email] }, false))
        .data,
      account,
      true,
    );
    account.state = "absent";
    account.password = randomBytes(24).toString("base64url");
    secret(account.password);
    const result = await send(
        account,
        "setup",
        "signup",
        capability,
        { email: account.email, password: account.password, returnSecureToken: true },
        true,
        "create",
      ),
      data = result.data;
    if (
      typeof data.localId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(data.localId) ||
      data.email !== account.email ||
      [...accounts.values()].some((other) => other !== account && other.uid === data.localId)
    )
      throw new Error();
    account.uid = data.localId;
    account.state = "owned";
    await options.onJournal(
      Object.freeze({
        type: "production-auth-ownership",
        operationId: result.requestContext.operationId,
        accountRef: account.ref,
        accountMutation: "receipt",
        ownedUid: account.uid,
      }),
    );
    admitted(result.requestContext);
    secret(data.idToken);
    secret(data.refreshToken);
    const proof = tokenProof(account, result, data.idToken, data.expiresIn);
    account.refreshToken = data.refreshToken;
    account.password = null;
    userMatches(
      (await send(account, "setup", "client-lookup", capability, { idToken: proof.token }, true))
        .data,
      account,
    );
    const admin = await send(
      account,
      "setup",
      "admin-lookup",
      capability,
      { localId: [account.uid] },
      false,
    );
    userMatches(admin.data, account);
    await publish(account, "setup", result, proof);
  }
  async function refreshAccount(account, capability) {
    account.token = null;
    account.deadline = null;
    const body = Buffer.from(
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: account.refreshToken,
      }).toString(),
    );
    let result;
    try {
      result = await send(account, "refresh", "refresh", capability, body, true);
    } finally {
      body.fill(0);
    }
    const data = result.data;
    if (
      data.user_id !== account.uid ||
      data.project_id !== options.projectNumber ||
      data.token_type !== "Bearer"
    )
      throw new Error();
    secret(data.id_token);
    secret(data.refresh_token);
    const proof = tokenProof(account, result, data.id_token, data.expires_in);
    account.refreshToken = data.refresh_token;
    userMatches(
      (await send(account, "refresh", "client-lookup", capability, { idToken: proof.token }, true))
        .data,
      account,
    );
    userMatches(
      (
        await send(
          account,
          "refresh",
          "admin-lookup",
          capability,
          { localId: [account.uid] },
          false,
        )
      ).data,
      account,
    );
    await publish(account, "refresh", result, proof);
  }
  async function cleanupAccount(account, capability) {
    if (!account.uid || ["creating", "deleting", "absent-after-delete"].includes(account.state))
      return;
    userMatches(
      (
        await send(
          account,
          "cleanup",
          "admin-before",
          capability,
          { localId: [account.uid] },
          false,
        )
      ).data,
      account,
    );
    const result = await send(
      account,
      "cleanup",
      "delete",
      capability,
      { localId: account.uid, targetProjectId: plan.projectId },
      false,
      "delete",
    );
    if (
      Object.keys(result.data).some((key) => key !== "kind") ||
      (Object.hasOwn(result.data, "kind") &&
        result.data.kind !== "identitytoolkit#DeleteAccountResponse")
    )
      throw new Error();
    account.state = "deleted";
    account.token = null;
    account.refreshToken = null;
    account.deadline = null;
    userMatches(
      (await send(account, "cleanup", "uid-absence", capability, { localId: [account.uid] }, false))
        .data,
      account,
      true,
    );
    userMatches(
      (
        await send(
          account,
          "cleanup",
          "email-absence",
          capability,
          { email: [account.email] },
          false,
        )
      ).data,
      account,
      true,
    );
    account.state = "absent-after-delete";
    await options.onProof(
      Object.freeze({
        type: "production-auth-cleanup",
        recording,
        accountRef: account.ref,
        ownedUidSha256: sha256(account.uid),
        absent: true,
      }),
    );
    admitted(result.requestContext);
  }
  async function run(stage, recipeId, capability) {
    const program = programs.get(recipeId);
    if (closed || (subjectFailed && stage !== "cleanup"))
      throw new Error("production Auth is unavailable");
    if (
      busy ||
      !program ||
      capability === undefined ||
      program[stage] ||
      (stage === "refresh" && !program.setup)
    )
      throw new Error("invalid production Auth stage");
    busy = true;
    program[stage] = true;
    if (stage === "setup") program.capability = capability;
    if (stage === "refresh") program.refreshCapability = capability;
    if (stage === "cleanup") program.cleanupCapability = capability;
    try {
      admitted(
        context(
          `r${recording}/auth${program.index}-${stage}`,
          stage === "cleanup" ? "cleanup" : "subject",
        ),
      );
      if (stage === "setup" && !keyRegistered) {
        secret(options.apiKey);
        keyRegistered = true;
      }
      for (const kind of ["valid", "competitor"]) {
        const account = accounts.get(program.recipe.accounts[kind].ref);
        await { setup: setupAccount, refresh: refreshAccount, cleanup: cleanupAccount }[stage](
          account,
          capability,
        );
      }
      if (stage === "cleanup") program.cleanupComplete = true;
    } catch {
      subjectFailed = true;
      clearCredentials();
      throw new Error("production Auth is unavailable");
    } finally {
      busy = false;
    }
  }
  const state = Object.freeze({
    setup: (recipeId, capability) => run("setup", recipeId, capability),
    refresh: (recipeId, capability) => run("refresh", recipeId, capability),
    cleanup: (recipeId, capability) => run("cleanup", recipeId, capability),
    accountAuthorization(suppliedRef, suppliedContext) {
      try {
        const ref = record(suppliedRef, ["kind", "accountRef"]),
          requestContext = record(suppliedContext, ["recording", "kind", "phase", "operationId"]);
        if (
          closed ||
          subjectFailed ||
          Object.keys(requestContext).length !== 4 ||
          requestContext.recording !== recording ||
          requestContext.kind !== "storage" ||
          requestContext.phase !== "subject" ||
          typeof requestContext.operationId !== "string"
        )
          throw new Error();
        const account = accounts.get(ref.accountRef),
          program = ref.kind === "malformed" ? [...programs.values()][0] : account?.program;
        if (
          !program ||
          !new RegExp(`^r${recording}/p${24 + program.index}/[a-f0-9]{64}$`).test(
            requestContext.operationId,
          )
        )
          throw new Error();
        if (ref.kind === "malformed") {
          if (Object.keys(ref).length !== 1 || !program.setup || program.cleanup) throw new Error();
        } else if (
          Object.keys(ref).length !== 2 ||
          !["valid", "competitor"].includes(ref.kind) ||
          account.kind !== ref.kind ||
          account.state !== "verified" ||
          !account.token
        )
          throw new Error();
        try {
          admitted(requestContext);
          const time = clock().monotonic;
          if (account && account.deadline - time <= 60000) throw new Error();
          if (ref.kind === "malformed") {
            if (!malformed) {
              malformed = randomBytes(24).toString("base64url");
              secret(malformed);
            }
            return `Firebase ${malformed}`;
          }
          return `Firebase ${account.token}`;
        } catch {
          subjectFailed = true;
          clearCredentials();
          throw new Error();
        }
      } catch {
        throw new Error("production Auth is unavailable");
      }
    },
    snapshot: () =>
      Object.freeze({
        recording,
        busy,
        closed,
        subjectFailed,
        accounts: Object.freeze(
          [...accounts.values()].map((account) =>
            Object.freeze({
              accountRef: account.ref,
              state: account.state,
              uidSha256: account.uid === null ? null : sha256(account.uid),
            }),
          ),
        ),
        unresolved: Object.freeze(
          [...accounts.values()]
            .filter((account) =>
              ["creating", "owned", "verified", "deleting", "deleted"].includes(account.state),
            )
            .map((account) =>
              Object.freeze({
                accountRef: account.ref,
                state: account.state,
                uidSha256: account.uid === null ? null : sha256(account.uid),
              }),
            ),
        ),
      }),
    close() {
      closed = true;
      clearCredentials();
    },
  });
  authStates.set(state, {
    plan,
    recording,
    provider: state.accountAuthorization,
    terminal(proof) {
      const program = programs.get(proof.recipeId);
      return (
        !busy &&
        !closed &&
        program !== undefined &&
        program.setup &&
        program.cleanupComplete &&
        program.capability === proof.recipeToken &&
        program.cleanupCapability === proof.recipeToken &&
        (!program.refresh || program.refreshCapability === proof.recipeToken) &&
        ["valid", "competitor"].every((kind) =>
          ["unobserved", "absent", "absent-after-delete"].includes(
            accounts.get(program.recipe.accounts[kind].ref).state,
          ),
        )
      );
    },
  });
  return state;
}
