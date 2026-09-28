import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { buildAuthCorpus } from "./auth-corpus.mjs";

function jsonBody(response) {
  let body;
  try {
    body = JSON.parse(response.raw.toString("utf8"));
  } catch {
    throw new Error("local Auth response is not JSON");
  }
  if (
    response.status !== 200 ||
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.hasOwn(body, "error")
  )
    throw new Error("local Auth response is not a successful object");
  return body;
}

function emptyUsers(response) {
  const body = jsonBody(response);
  if (
    body.kind !== "identitytoolkit#GetAccountInfoResponse" ||
    (body.users !== undefined && (!Array.isArray(body.users) || body.users.length !== 0))
  )
    throw new Error("local account absence is not proved");
}

function tokenClaims(token, account, projectId, now) {
  let claims;
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part)))
      throw new Error();
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("local token claims are malformed");
  }
  const seconds = now() / 1000;
  if (
    !Number.isFinite(seconds) ||
    seconds < 0 ||
    claims?.sub !== account.uid ||
    claims.user_id !== account.uid ||
    claims.email !== account.email ||
    claims.aud !== projectId ||
    claims.iss !== `https://securetoken.google.com/${projectId}` ||
    !Number.isSafeInteger(claims.iat) ||
    !Number.isSafeInteger(claims.exp) ||
    claims.iat > seconds + 5 ||
    claims.exp <= seconds ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 3600
  )
    throw new Error("local token identity or expiry is unproved");
  return claims;
}

/** Local-only account state; every transport is supplied by the Storage counter. */
export function createLocalAuthState({
  plan,
  apiKey,
  password,
  now = Date.now,
  request,
  onJournal,
} = {}) {
  if (
    apiKey !== "storage-object-local-key" ||
    typeof password !== "string" ||
    password.length < 16 ||
    typeof now !== "function" ||
    typeof request !== "function" ||
    typeof onJournal !== "function"
  )
    throw new Error("synthetic local Auth configuration is required");
  const projectId = plan.projectId;
  const corpus = buildAuthCorpus({
    projectId,
    bucket: plan.bucket,
    runId: plan.recordings[0].runId,
  });
  const accounts = new Map(),
    attempted = new Set();
  function canonical(recipe) {
    const expected = corpus.recipes.find((row) => row.id === recipe?.id);
    if (!expected || !isDeepStrictEqual(recipe, expected))
      throw new Error("local Auth declaration differs");
    return expected;
  }
  const stateFor = (recipe, kind) => {
    const declaration = recipe.accounts[kind];
    if (!accounts.has(declaration.ref))
      accounts.set(declaration.ref, {
        ...declaration,
        kind,
        state: "unobserved",
        uid: null,
        token: null,
      });
    return accounts.get(declaration.ref);
  };
  return {
    canonical,
    async send({ recipe, stepIndex, cleanupIndex } = {}) {
      recipe = canonical(recipe);
      const cleanup = cleanupIndex !== undefined,
        index = cleanup ? cleanupIndex : stepIndex;
      if (!Number.isInteger(index) || index < 0 || (cleanup && stepIndex !== undefined))
        throw new Error("invalid local Auth step index");
      const step = (cleanup ? recipe.accountCleanup : recipe.accountSetup)[index];
      if (!step) throw new Error("local Auth step is missing");
      const kind = step.id.startsWith("valid-") ? "valid" : "competitor",
        account = stateFor(recipe, kind);
      const operationId = `${recipe.id}/${step.id}`;
      if (attempted.has(operationId)) throw new Error("local Auth operation was already attempted");
      const signup = step.id.endsWith("-signup"),
        lookup = step.id.endsWith("-token-lookup"),
        deletion = step.id.endsWith("-delete"),
        absentAfter = step.id.endsWith("-absence") && cleanup;
      if (
        (signup && account.state !== "absent") ||
        (lookup && account.state !== "owned") ||
        (deletion && !["owned", "verified"].includes(account.state)) ||
        (absentAfter && account.state !== "deleted") ||
        (!signup && !lookup && !deletion && !absentAfter && account.state !== "unobserved")
      )
        throw new Error("local account lifecycle prerequisite failed");
      const owner = step.credential === "owner";
      const path = owner
        ? `/identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:${deletion ? "delete" : "lookup"}`
        : `/identitytoolkit.googleapis.com${step.path}`;
      const body = signup
        ? { email: account.email, password, returnSecureToken: true }
        : lookup
          ? { idToken: account.token }
          : deletion
            ? { localId: account.uid, targetProjectId: projectId }
            : { email: [account.email], targetProjectId: projectId };
      const response = await request(
        operationId,
        path,
        owner ? {} : { key: apiKey },
        { owner, body },
        async () => {
          if (signup || deletion) {
            await onJournal({
              operationId,
              accountRef: account.ref,
              accountMutation: signup ? "create" : "delete",
              ...(deletion ? { ownedUid: account.uid } : {}),
            });
            account.state = signup ? "creating" : "deleting";
          }
          attempted.add(operationId);
        },
      );
      if (signup) {
        const data = jsonBody(response);
        if (
          typeof data.localId !== "string" ||
          !/^[A-Za-z0-9_-]{1,128}$/.test(data.localId) ||
          data.email !== account.email ||
          [...accounts.values()].some((other) => other !== account && other.uid === data.localId)
        )
          throw new Error("local signup UID or email is unproved");
        account.uid = data.localId;
        account.state = "owned";
        await onJournal({
          operationId,
          accountRef: account.ref,
          ownedUid: account.uid,
          accountMutation: "receipt",
        });
        if (
          typeof data.idToken !== "string" ||
          data.idToken.length > 8192 ||
          data.expiresIn !== "3600"
        )
          throw new Error("local signup token is missing");
        account.token = data.idToken;
        tokenClaims(account.token, account, projectId, now);
      } else if (lookup) {
        const data = jsonBody(response);
        if (
          !Array.isArray(data.users) ||
          data.users.length !== 1 ||
          data.users[0]?.localId !== account.uid ||
          data.users[0].email !== account.email
        )
          throw new Error("local token lookup does not prove the signup identity");
        tokenClaims(account.token, account, projectId, now);
        account.state = "verified";
      } else if (deletion) {
        if (jsonBody(response).kind !== "identitytoolkit#DeleteAccountResponse")
          throw new Error("local owned account deletion is unproved");
        account.state = "deleted";
        account.token = null;
      } else {
        emptyUsers(response);
        account.state = absentAfter ? "absent-after-delete" : "absent";
      }
      return response;
    },
    wire({ recipe, probeIndex } = {}) {
      recipe = canonical(recipe);
      if (!Number.isInteger(probeIndex) || probeIndex < 0 || !recipe.probes[probeIndex])
        throw new Error("invalid local Auth probe index");
      const probe = recipe.probes[probeIndex],
        kind = probe.credential;
      let authorization = null,
        accountRef = null;
      if (["valid", "competitor"].includes(kind)) {
        const account = stateFor(recipe, kind);
        if (account.state !== "verified")
          throw new Error("local Auth credential has no server lookup proof");
        tokenClaims(account.token, account, projectId, now);
        authorization = `Firebase ${account.token}`;
        accountRef = account.ref;
      } else if (kind === "malformed") authorization = "Firebase local-malformed-id-token";
      else if (kind !== "anonymous") throw new Error("invalid local Auth credential kind");
      return {
        probe,
        authorization,
        proof: {
          credentialKind: kind,
          accountRef,
          wireScheme: authorization ? "Firebase" : null,
          tokenSha256: authorization
            ? createHash("sha256").update(authorization.slice(9)).digest("hex")
            : null,
        },
      };
    },
    snapshot({ recipe } = {}) {
      recipe = canonical(recipe);
      return Object.fromEntries(
        ["valid", "competitor"].map((kind) => [kind, stateFor(recipe, kind).state]),
      );
    },
    unresolved: () =>
      [...accounts.values()]
        .filter((row) =>
          ["creating", "owned", "verified", "deleting", "deleted"].includes(row.state),
        )
        .map((row) => row.ref)
        .toSorted(),
  };
}
