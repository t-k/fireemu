// Executes FS-RULES programs against one target and returns what it answered.
//
// A session owns the run's principals (Auth accounts it creates and deletes itself, never a
// project-wide wipe, because the AUTH lanes share the sandbox's Auth), the run's tenant and
// named databases, and the Rules releases of the lane's Firestore. Every program starts and ends
// with a wipe of the databases it uses. Requests made as a principal are recorded as rows;
// harness calls (sign-in, refresh, seed, wipe, publication, account changes) are counted but not
// recorded.

import { createRequire } from "node:module";

import { BASELINE_CONFIG } from "../auth-account/corpus.mjs";
import { configMatches } from "../auth-account/session.mjs";
import { customTokenClaims, decodeJwt, signLocally, tamper } from "../auth-credential/tokens.mjs";
import {
  buildFirestoreGrpc,
  buildFirestoreRest,
  databaseId,
  databaseName,
  documentsName,
  guardFirestoreRequest,
  guardGrpcRequest,
  isTransient,
  normalizeGrpc,
  normalizeRest,
  PASSWORD,
  principalEmail,
  PRODUCTION,
  resolveValue,
  TEST_PHONE_CODE,
  TEST_PHONES,
} from "./harness.mjs";
import { markerOf, rulesetSource } from "./rulesets.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");
const { v1 } = require("@google-cloud/firestore");

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
export const fatal = (message) => Object.assign(new Error(message), { fatal: true });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const COMMIT_BATCH = 400;
/** Consecutive marker answers that must agree before a publication counts as propagated. */
export const SETTLE_STREAK = 30;
const SETTLE_LIMIT_MS = 8 * 60_000;
const RELEASE = "cloud.firestore";

export function createSession(
  ctx,
  {
    signers = {},
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    log = () => {},
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;
  const principals = new Map();
  /** Rulesets this session created in production, deleted at the end. */
  const createdRulesets = new Set();
  /** The label of the ruleset in force per database (`null`: no release), as the harness set it. */
  const active = new Map();
  let tenant;
  let tenantConfigChanged = false;
  const gapic = new v1.FirestoreClient({ projectId: ctx.project });
  const protos = gapic._protos;
  const grpcClient =
    ctx.target.kind === "production"
      ? new grpc.Client(
          `${PRODUCTION.grpc.host}:${PRODUCTION.grpc.port}`,
          grpc.credentials.createSsl(),
        )
      : new grpc.Client(
          `${ctx.target.grpcHost}:${ctx.target.grpcPort}`,
          grpc.credentials.createInsecure(),
        );

  const charge = (harness) => {
    if (harness) {
      if (harnessRequests >= maxHarnessRequests)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  };

  async function refreshOwner() {
    try {
      await ctx.target.refresh?.();
    } catch (error) {
      throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
    }
  }

  const ownerHeaders = () =>
    ctx.target.kind === "production"
      ? {
          authorization: `Bearer ${ctx.target.adminToken}`,
          "x-goog-user-project": ctx.target.quotaProject,
        }
      : { authorization: "Bearer owner" };

  /** Origins of the non-Firestore APIs the harness calls. */
  function apiUrl(api, path) {
    if (ctx.target.kind === "production") return `${PRODUCTION[api]}/${path}`;
    if (api === "itk") return `${ctx.target.authOrigin}/identitytoolkit.googleapis.com/${path}`;
    if (api === "securetoken") return `${ctx.target.authOrigin}/securetoken.googleapis.com/${path}`;
    if (api === "firestore") return `${ctx.target.firestoreOrigin}/${path}`;
    throw new Error(`${api} has no local form`);
  }

  /** One harness HTTP call; a failure to reach the target is fatal. */
  async function call(url, init, { expect = [200] } = {}) {
    charge(true);
    let response;
    try {
      response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      throw fatal(
        `harness ${init.method} ${new URL(url).pathname}: ${error?.cause?.code ?? error?.name}`,
      );
    }
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    if (!expect.includes(response.status)) {
      throw fatal(
        `harness ${init.method} ${new URL(url).pathname}: HTTP ${response.status} ${text.slice(0, 300)}`,
      );
    }
    return { status: response.status, json };
  }

  async function admin(method, api, path, body, options) {
    await refreshOwner();
    return call(
      apiUrl(api, path),
      {
        method,
        headers: {
          ...ownerHeaders(),
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      options,
    );
  }

  const apiKey = () => (ctx.target.kind === "production" ? ctx.target.apiKey : "fake-api-key");

  async function client(path, body) {
    return call(apiUrl("itk", `${path}?key=${apiKey()}`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  // ---- principals ----------------------------------------------------------------------------

  async function mint(spec, uid) {
    const signer = signers[spec.signer ?? "project"];
    if (!signer) throw fatal(`no signer ${spec.signer ?? "project"}`);
    const claims = customTokenClaims(
      { ...spec, uid },
      signer.serviceAccount,
      Math.floor(Date.now() / 1000),
      (t) => t,
    );
    if (signer.privateKeyPem) return signLocally(claims, signer.privateKeyPem, signer.kid);
    if (ctx.target.kind !== "production") throw fatal("signJwt is production-only");
    await refreshOwner();
    const { json } = await call(
      `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${signer.serviceAccount}:signJwt`,
      {
        method: "POST",
        headers: { ...ownerHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ payload: JSON.stringify(claims) }),
      },
    );
    if (typeof json?.signedJwt !== "string") throw fatal("signJwt returned no token");
    return json.signedJwt;
  }

  function adopt(name, spec, answer) {
    const idToken = answer.idToken ?? answer.id_token;
    const refreshToken = answer.refreshToken ?? answer.refresh_token;
    const uid = answer.localId ?? answer.user_id ?? decodeJwt(idToken)?.claims?.sub;
    if (!idToken || !refreshToken || !uid) throw fatal(`sign-in of ${name} returned no token`);
    const existing = principals.get(name);
    principals.set(name, {
      ...existing,
      spec,
      uid,
      idToken,
      refreshToken,
      snapshots: existing?.snapshots ?? new Map(),
    });
  }

  /** Creates (or signs in) one principal as its spec says and applies its profile changes. */
  async function createPrincipal(name, spec) {
    let answer;
    const tenantId = spec.tenant ? tenant?.id : undefined;
    if (spec.tenant && !tenantId) throw fatal(`principal ${name} needs the run's tenant`);
    switch (spec.provider) {
      case "anonymous":
        ({ json: answer } = await client("v1/accounts:signUp", { returnSecureToken: true }));
        break;
      case "password":
        ({ json: answer } = await client("v1/accounts:signUp", {
          email: principalEmail(ctx, name),
          password: PASSWORD,
          returnSecureToken: true,
          ...(tenantId ? { tenantId } : {}),
        }));
        break;
      case "phone": {
        const phoneNumber = TEST_PHONES[spec.phone ?? 0];
        const { json: sent } = await client("v1/accounts:sendVerificationCode", { phoneNumber });
        ({ json: answer } = await client("v1/accounts:signInWithPhoneNumber", {
          sessionInfo: sent.sessionInfo,
          code: TEST_PHONE_CODE,
        }));
        break;
      }
      case "custom": {
        const token = await mint(spec.token ?? {}, `fsr-${ctx.run}-${name}`);
        ({ json: answer } = await client("v1/accounts:signInWithCustomToken", {
          token,
          returnSecureToken: true,
        }));
        break;
      }
      default:
        throw fatal(`unknown provider ${spec.provider}`);
    }
    adopt(name, spec, answer);
    const principal = principals.get(name);
    principal.tenantId = tenantId;
    let changed = false;
    if (spec.profile) {
      await client("v1/accounts:update", {
        idToken: principal.idToken,
        ...spec.profile,
        returnSecureToken: true,
      });
      changed = true;
    }
    if (spec.emailVerified || spec.customAttributes) {
      await accountUpdate(name, {
        ...(spec.emailVerified ? { emailVerified: true } : {}),
        ...(spec.customAttributes
          ? { customAttributes: JSON.stringify(spec.customAttributes) }
          : {}),
      });
      changed = true;
    }
    if (changed) await refresh(name);
  }

  const accountsPath = (principal) =>
    principal.tenantId
      ? `v1/projects/${ctx.project}/tenants/${principal.tenantId}/accounts`
      : `v1/projects/${ctx.project}/accounts`;

  async function accountUpdate(name, changes) {
    const principal = principals.get(name);
    await admin("POST", "itk", `${accountsPath(principal)}:update`, {
      localId: principal.uid,
      ...changes,
    });
  }

  async function refresh(name) {
    const principal = principals.get(name);
    const { json } = await call(apiUrl("securetoken", `v1/token?key=${apiKey()}`), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: principal.refreshToken,
      }).toString(),
    });
    adopt(name, principal.spec, json);
  }

  async function deletePrincipal(name) {
    const principal = principals.get(name);
    if (!principal || principal.deleted) return;
    await admin("POST", "itk", `${accountsPath(principal)}:delete`, { localId: principal.uid });
    principal.deleted = true;
  }

  /** Deletes every account this session created; nothing else in the project is touched. */
  async function deletePrincipals() {
    for (const name of principals.keys()) await deletePrincipal(name);
  }

  // ---- sign-in configuration -----------------------------------------------------------------

  const pick = (object, path) => path.split(".").reduce((value, key) => value?.[key], object);

  /**
   * The AUTH-ACCOUNT sign-in baseline (email/password, anonymous, test phones): read and checked
   * in production, where it is set once for the sandbox; applied to fireemu.
   */
  async function prepareSignIn() {
    const mask = Object.keys(BASELINE_CONFIG);
    const path = `admin/v2/projects/${ctx.project}/config`;
    if (ctx.target.kind === "local") {
      const body = {};
      for (const key of mask) {
        const segments = key.split(".");
        let node = body;
        for (const segment of segments.slice(0, -1)) node = node[segment] ??= {};
        node[segments.at(-1)] = BASELINE_CONFIG[key];
      }
      await admin("PATCH", "itk", `${path}?updateMask=${mask.join(",")}`, body);
    }
    const { json } = await admin("GET", "itk", path);
    const drift = mask.filter((key) => !configMatches(pick(json, key), BASELINE_CONFIG[key]));
    if (drift.length) throw fatal(`sign-in baseline differs at ${drift.join(", ")}`);
  }

  // ---- tenant --------------------------------------------------------------------------------

  async function createTenant() {
    if (ctx.target.kind === "production") {
      const { json } = await admin("GET", "itk", `admin/v2/projects/${ctx.project}/config`);
      if (json?.multiTenant?.allowTenants !== true) {
        await admin(
          "PATCH",
          "itk",
          `admin/v2/projects/${ctx.project}/config?updateMask=multiTenant.allowTenants`,
          { multiTenant: { allowTenants: true } },
        );
        tenantConfigChanged = true;
      }
    }
    const { json } = await admin("POST", "itk", `v2/projects/${ctx.project}/tenants`, {
      displayName: "fsr-tenant",
      allowPasswordSignup: true,
    });
    const id = String(json?.name ?? "").split("/tenants/")[1];
    if (!id) throw fatal("tenant creation returned no name");
    tenant = { id };
    return id;
  }

  async function deleteTenant() {
    if (tenant && !tenant.deleted) {
      await admin("DELETE", "itk", `v2/projects/${ctx.project}/tenants/${tenant.id}`);
      tenant.deleted = true;
    }
    if (tenantConfigChanged) {
      await admin(
        "PATCH",
        "itk",
        `admin/v2/projects/${ctx.project}/config?updateMask=multiTenant.allowTenants`,
        { multiTenant: { allowTenants: false } },
      );
      tenantConfigChanged = false;
    }
  }

  // ---- databases -----------------------------------------------------------------------------

  /** Production only: creates the run's named databases (fireemu declares them at start). */
  async function createDatabases() {
    if (ctx.target.kind !== "production") return;
    for (const id of Object.values(ctx.databases)) {
      const { json } = await admin(
        "POST",
        "firestore",
        `v1/projects/${ctx.project}/databases?databaseId=${id}`,
        {
          type: "FIRESTORE_NATIVE",
          locationId: "us-central1",
        },
      );
      await waitOperation(json);
    }
  }

  async function deleteDatabases() {
    if (ctx.target.kind !== "production") return;
    for (const id of Object.values(ctx.databases)) {
      const { status, json } = await admin(
        "DELETE",
        "firestore",
        `v1/projects/${ctx.project}/databases/${id}`,
        undefined,
        {
          expect: [200, 404],
        },
      );
      if (status === 200) await waitOperation(json);
    }
  }

  async function waitOperation(operation) {
    let current = operation;
    for (let i = 0; i < 60 && current?.done !== true; i += 1) {
      await sleep(2000);
      ({ json: current } = await admin("GET", "firestore", `v1/${operation.name}`));
    }
    if (current?.done !== true || current.error) throw fatal(`operation ${operation?.name} failed`);
  }

  // ---- documents -----------------------------------------------------------------------------

  async function commit(writes, which) {
    for (let i = 0; i < writes.length; i += COMMIT_BATCH) {
      await admin("POST", "firestore", `v1/${databaseName(ctx, which)}/documents:commit`, {
        writes: writes.slice(i, i + COMMIT_BATCH),
      });
    }
  }

  /** Deletes every document of one database with owner credentials. */
  async function wipe(which = "default") {
    if (ctx.target.kind === "local") {
      await call(
        `${ctx.target.firestoreOrigin}/emulator/v1/projects/${ctx.project}/databases/${databaseId(ctx, which)}/documents`,
        { method: "DELETE", headers: ownerHeaders() },
      );
      return;
    }
    for (let round = 0; round < 40; round += 1) {
      const { json } = await admin(
        "POST",
        "firestore",
        `v1/${documentsName(ctx, which)}:runQuery`,
        {
          structuredQuery: {
            from: [{ allDescendants: true }],
            select: { fields: [{ fieldPath: "__name__" }] },
            limit: COMMIT_BATCH,
          },
        },
      );
      const names = (json ?? []).filter((e) => e.document).map((e) => e.document.name);
      if (names.length === 0) return;
      await commit(
        names.map((name) => ({ delete: name })),
        which,
      );
    }
    throw fatal(`wipe of ${which}: documents remain after 40 rounds`);
  }

  async function seed(documents, raw) {
    const byDatabase = new Map();
    for (const { doc, fields, database = "default" } of documents ?? []) {
      const list = byDatabase.get(database) ?? [];
      list.push({
        update: {
          name: `${documentsName(ctx, database)}/${resolveValue(doc, ctx, raw, principals, database)}`,
          fields: resolveValue(fields ?? {}, ctx, raw, principals, database),
        },
      });
      byDatabase.set(database, list);
    }
    for (const [database, writes] of byDatabase) await commit(writes, database);
  }

  // ---- rules publication ---------------------------------------------------------------------

  const releaseName = (which) =>
    which === "default" ? RELEASE : `${RELEASE}/${databaseId(ctx, which)}`;

  async function createRuleset(source) {
    const { json } = await admin("POST", "rules", `v1/projects/${ctx.project}/rulesets`, {
      source: { files: [{ name: "firestore.rules", content: source }] },
    });
    createdRulesets.add(json.name);
    return json.name;
  }

  /** The status of an unauthenticated get of a marker document: 404 in force, 403 not. */
  async function markerStatus(label, which) {
    charge(true);
    const url = `${ctx.target.kind === "production" ? PRODUCTION.firestore : ctx.target.firestoreOrigin}/v1/${documentsName(ctx, which)}/fsr-marker/${label}`;
    try {
      return (await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })).status;
    } catch {
      return 0;
    }
  }

  /**
   * Waits until SETTLE_STREAK consecutive polls see `label` in force and `previous` not (or,
   * with `label` null, the previous marker refused). Production serves a switch from several
   * frontends that change over at different times, so one good answer proves nothing.
   */
  async function settle(label, previous, which) {
    const expect = [];
    if (label) expect.push([label, 404]);
    if (previous && previous !== label) expect.push([previous, 403]);
    // Without a release every marker this lane could have left in force must be refused.
    if (!label) {
      for (const id of which === "default" ? ["main", "alt"] : ["named"]) {
        if (markerOf(id) !== previous) expect.push([markerOf(id), 403]);
      }
    }
    if (expect.length === 0) return;
    // fireemu switches synchronously; a marker that disagrees there is a difference the rows
    // record, not a propagation delay.
    if (ctx.target.kind !== "production") return;
    const start = Date.now();
    let streak = 0;
    while (Date.now() - start < SETTLE_LIMIT_MS) {
      let ok = true;
      for (const [marker, status] of expect)
        ok = ok && (await markerStatus(marker, which)) === status;
      streak = ok ? streak + 1 : 0;
      if (streak >= SETTLE_STREAK) return;
      await sleep(1000);
    }
    throw fatal(`release of ${label ?? "nothing"} on ${which} did not settle`);
  }

  /** Puts `rulesetId` in force on a database (`null`: deletes the release). */
  async function publish(rulesetId, which = "default") {
    const previous = active.get(which) ?? null;
    const label = rulesetId ? markerOf(rulesetId) : null;
    if (active.has(which) && previous === label) return;
    if (ctx.target.kind === "production") {
      const name = `projects/${ctx.project}/releases/${releaseName(which)}`;
      if (rulesetId === null) {
        await admin("DELETE", "rules", `v1/${name}`, undefined, { expect: [200, 404] });
      } else {
        const rulesetName = await createRuleset(rulesetSource(rulesetId));
        const { status } = await admin(
          "PATCH",
          "rules",
          `v1/${name}`,
          { release: { name, rulesetName } },
          {
            expect: [200, 404],
          },
        );
        if (status === 404)
          await admin("POST", "rules", `v1/projects/${ctx.project}/releases`, {
            name,
            rulesetName,
          });
        const { json } = await admin("GET", "rules", `v1/${name}`);
        if (json?.rulesetName !== rulesetName) throw fatal(`release ${name} did not read back`);
      }
    } else if (which !== "default") {
      // fireemu loads named-database rules from firebase.json at start; nothing to switch.
    } else if (rulesetId === null) {
      await call(`${ctx.target.control.url}/v1/rules`, {
        method: "DELETE",
        headers: controlHeaders(),
      });
    } else {
      await loadLocal(rulesetSource(rulesetId));
    }
    await settle(label, previous, which);
    active.set(which, label);
    log(`release ${which}: ${label ?? "none"}`);
  }

  const controlHeaders = () =>
    ctx.target.control?.token ? { authorization: `Bearer ${ctx.target.control.token}` } : {};

  async function loadLocal(source, { expect = [200] } = {}) {
    return call(
      `${ctx.target.firestoreOrigin}/emulator/v1/projects/${ctx.project}:securityRules`,
      {
        method: "PUT",
        headers: { ...ownerHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: source }] } }),
      },
      { expect },
    );
  }

  /** Whether a ruleset compiles: production `rulesets.create`, fireemu's ruleset load. */
  async function compiles(source) {
    if (ctx.target.kind === "production") {
      const { status, json } = await admin(
        "POST",
        "rules",
        `v1/projects/${ctx.project}/rulesets`,
        {
          source: { files: [{ name: "firestore.rules", content: source }] },
        },
        { expect: [200, 400] },
      );
      if (status === 200) await admin("DELETE", "rules", `v1/${json.name}`);
      return { compiled: status === 200 };
    }
    const { status } = await loadLocal(source, { expect: [200, 400] });
    // A local load activates the ruleset: put the one in force back.
    const current = active.get("default");
    if (status === 200) {
      if (current) await loadLocal(rulesetSource(current.split("-")[0]));
      else
        await call(`${ctx.target.control.url}/v1/rules`, {
          method: "DELETE",
          headers: controlHeaders(),
        });
    }
    return { compiled: status === 200 };
  }

  async function deleteCreatedRulesets() {
    for (const name of createdRulesets) {
      await admin("DELETE", "rules", `v1/${name}`, undefined, { expect: [200, 404, 400] });
      createdRulesets.delete(name);
    }
  }

  // ---- requests made as a principal ----------------------------------------------------------

  /** The Authorization header value a step's `as` resolves to (undefined: none). */
  function bearerFor(as) {
    if (as === "none" || as === undefined) return undefined;
    if (typeof as === "string") {
      const [name, snapshot] = as.split("@");
      const principal = principals.get(name);
      if (!principal) throw fatal(`unknown principal ${name}`);
      const token = snapshot ? principal.snapshots.get(snapshot) : principal.idToken;
      if (!token) throw fatal(`principal ${name} has no token ${snapshot}`);
      return `Bearer ${token}`;
    }
    const { bearer, of } = as;
    const token = of ? principals.get(of)?.idToken : undefined;
    switch (bearer) {
      case "empty":
        return "Bearer ";
      case "malformed":
        return "Bearer fsr-not-a-token";
      case "basic":
        return "Basic ZnNyOmZzcg==";
      case "lowercase-scheme":
        return `bearer ${token}`;
      case "tampered":
        return `Bearer ${tamper(token, "signature")}`;
      case "unsigned":
        return `Bearer ${tamper(token, "alg-none")}`;
      default:
        throw fatal(`unknown bearer form ${bearer}`);
    }
  }

  async function sendRest(step, raw) {
    const request = buildFirestoreRest(step, ctx, raw, principals, bearerFor(step.as));
    guardFirestoreRequest(request, ctx);
    charge(false);
    let response;
    try {
      response = await fetch(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      return {
        recorded: { status: 0, transport: error?.cause?.code ?? error?.name ?? "error" },
        json: null,
      };
    }
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded as non-JSON */
    }
    return { recorded: normalizeRest(response.status, text, ctx, principals), json };
  }

  function sendGrpc(step, raw) {
    const built = buildFirestoreGrpc(step, ctx, raw, principals);
    guardGrpcRequest(built, ctx);
    charge(false);
    const requestType = protos.google.firestore.v1[`${built.method}Request`];
    const responseType =
      built.method === "GetDocument" ||
      built.method === "CreateDocument" ||
      built.method === "UpdateDocument"
        ? protos.google.firestore.v1.Document
        : built.method === "DeleteDocument" || built.method === "Rollback"
          ? protos.google.protobuf.Empty
          : protos.google.firestore.v1[`${built.method}Response`];
    const metadata = new grpc.Metadata();
    const bearer = bearerFor(step.as);
    if (bearer !== undefined) metadata.set("authorization", bearer);
    metadata.set("google-cloud-resource-prefix", built.resourcePrefix);
    metadata.set("x-goog-request-params", built.routing);
    const path = `/google.firestore.v1.Firestore/${built.method}`;
    const options = { deadline: new Date(Date.now() + timeoutMs) };
    return new Promise((resolve) => {
      const messages = [];
      const finish = (error) => {
        const recorded = normalizeGrpc(
          {
            code: error ? error.code : 0,
            details: error ? error.details : "",
            messages: JSON.parse(JSON.stringify(messages)),
          },
          ctx,
          principals,
        );
        resolve({ recorded, json: built.stream ? messages : (messages[0] ?? null) });
      };
      const serialize = (message) => requestType.serialize(message);
      const deserialize = (bytes) => responseType.deserialize(bytes);
      if (built.stream) {
        const stream = grpcClient.makeServerStreamRequest(
          path,
          serialize,
          deserialize,
          built.request,
          metadata,
          options,
        );
        let failed;
        stream.on("data", (message) => messages.push(message));
        stream.on("error", (error) => {
          failed = error;
        });
        stream.on("status", (status) => finish(failed ?? (status.code ? status : undefined)));
      } else {
        grpcClient.makeUnaryRequest(
          path,
          serialize,
          deserialize,
          built.request,
          metadata,
          options,
          (error, message) => {
            if (message) messages.push(message);
            finish(error ?? undefined);
          },
        );
      }
    });
  }

  // ---- programs ------------------------------------------------------------------------------

  /** Harness actions a program interleaves with its rows. */
  async function act(step, raw) {
    const { action, principal } = step;
    switch (action) {
      case "principal":
        return createPrincipal(principal, step.spec);
      case "refresh":
        return refresh(principal);
      case "snapshot":
        principals.get(principal).snapshots.set(step.as, principals.get(principal).idToken);
        return undefined;
      case "claims":
        return accountUpdate(principal, { customAttributes: JSON.stringify(step.claims) });
      case "revoke":
        // validSince after the token's auth_time: the next whole second.
        return accountUpdate(principal, { validSince: String(Math.floor(Date.now() / 1000) + 1) });
      case "disable":
        return accountUpdate(principal, { disableUser: true });
      case "delete-account":
        return deletePrincipal(principal);
      case "publish":
        return publish(step.ruleset, step.database ?? "default");
      case "seed":
        return seed(step.documents, raw);
      case "sleep":
        return sleep(step.ms);
      default:
        throw fatal(`unknown action ${action}`);
    }
  }

  /**
   * Waits until a principal's token claim plus whole seconds (+300 ms): production sleeps,
   * fireemu moves its virtual clock to the same instant. Returns whether the timer was on time.
   */
  async function waitUntil({ principal, claim = "exp", plus }) {
    const base = decodeJwt(principals.get(principal)?.idToken ?? "")?.claims?.[claim];
    if (typeof base !== "number") throw fatal(`principal ${principal} has no ${claim}`);
    const target = (base + plus) * 1000 + 300;
    if (ctx.target.kind === "production") {
      await sleep(Math.max(0, target - Date.now()));
      return Date.now() - target <= 200;
    }
    await call(`${ctx.target.control.url}/v1/sessions/default/clock:advanceTo`, {
      method: "POST",
      headers: { ...controlHeaders(), "content-type": "application/json" },
      body: JSON.stringify({ instant: new Date(target).toISOString() }),
    });
    return true;
  }

  const databasesOf = (program) => [...new Set(["default", ...(program.databases ?? [])])];

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
    const touched = databasesOf(program);
    for (const which of touched) await wipe(which);
    let failure;
    try {
      if (program.ruleset !== undefined) await publish(program.ruleset);
      for (const [which, rulesetId] of Object.entries(program.releases ?? {}))
        await publish(rulesetId, which);
      for (const name of program.refresh ?? []) await refresh(name);
      await seed(program.seed, raw);
      for (const step of program.steps) {
        if (step.action) {
          await act(step, raw);
          continue;
        }
        if (step.waitUntil && !(await waitUntil(step.waitUntil))) {
          steps[step.id] = { status: 0, transport: "late-timer" };
          raw.set(step.id, null);
          continue;
        }
        let outcome;
        try {
          if (step.compile !== undefined) {
            charge(false);
            outcome = { recorded: await compiles(step.compile), json: null };
          } else {
            outcome =
              (step.transport ?? "rest") === "grpc"
                ? await sendGrpc(step, raw)
                : await sendRest(step, raw);
          }
        } catch (error) {
          if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
          const dependency = /^step (\S+) recorded nothing/.exec(String(error.message))?.[1];
          outcome = {
            recorded: {
              status: -1,
              unresolved: String(error.message),
              dependencyTransient: isTransient(steps[dependency]),
            },
            json: null,
          };
        }
        raw.set(step.id, outcome.json);
        steps[step.id] = outcome.recorded;
        log(
          `${program.id}#${step.id} ${outcome.recorded.status ?? `grpc ${outcome.recorded.grpc}`}`,
        );
      }
      // A row counts only if the ruleset it ran under was still in force after it.
      if (ctx.target.kind === "production") {
        for (const [which, label] of active) {
          if (!touched.includes(which) || !label) continue;
          for (let i = 0; i < 3; i += 1) {
            if ((await markerStatus(label, which)) !== 404) {
              for (const recorded of Object.values(steps)) recorded.publication = "unsettled";
              break;
            }
          }
        }
      }
    } catch (error) {
      failure = error;
    }
    let cleanup;
    try {
      for (const which of touched) await wipe(which);
    } catch (error) {
      cleanup = error;
    }
    if (cleanup) throw cleanup;
    if (failure) throw failure;
    return { steps };
  }

  return {
    runProgram,
    prepareSignIn,
    createPrincipal,
    createTenant,
    deleteTenant,
    createDatabases,
    deleteDatabases,
    deletePrincipals,
    deleteCreatedRulesets,
    publish,
    wipe,
    principals,
    /** Databases with a release this session made, `default` last. */
    releasedDatabases: () =>
      [...active.entries()]
        .filter(([, label]) => label)
        .map(([which]) => which)
        .toSorted((a, b) => (a === "default") - (b === "default")),
    tenant: () => tenant,
    close: async () => {
      grpcClient.close();
      await gapic.close();
    },
    counts: () => ({ requests, harnessRequests }),
  };
}

/**
 * Runs a whole corpus: tenant, named databases and principals first, then every program, then
 * cleanup in reverse order, which always runs. A program that throws is recorded as a failure;
 * a fatal error stops the run after cleanup.
 */
export async function runCorpus({ programs, principals: principalSpecs }, ctx, options = {}) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  let fatalError;
  try {
    await session.prepareSignIn();
    if (Object.values(principalSpecs).some((spec) => spec.tenant)) await session.createTenant();
    if (programs.some((program) => (program.databases ?? []).length))
      await session.createDatabases();
    for (const [name, spec] of Object.entries(principalSpecs))
      await session.createPrincipal(name, spec);
    for (const program of programs) {
      try {
        results[program.id] = await session.runProgram(program);
      } catch (error) {
        if (error.fatal) throw error;
        failures.push({ program: program.id, error: String(error.message ?? error) });
      }
    }
  } catch (error) {
    fatalError = error;
  }
  const cleanupErrors = [];
  for (const step of [
    ...session.releasedDatabases().map((which) => () => session.publish(null, which)),
    () => session.wipe(),
    () => session.deleteDatabases(),
    () => session.deletePrincipals(),
    () => session.deleteTenant(),
    () => session.deleteCreatedRulesets(),
  ]) {
    try {
      await step();
    } catch (error) {
      cleanupErrors.push(String(error.message ?? error));
    }
  }
  await session.close();
  const out = {
    context: { run: ctx.run, startedMs: ctx.startedMs },
    results,
    failures,
    cleanupErrors,
    ...session.counts(),
  };
  if (fatalError) throw Object.assign(fatalError, { partial: out });
  if (cleanupErrors.length)
    throw Object.assign(fatal(`cleanup failed: ${cleanupErrors.join("; ")}`), { partial: out });
  return out;
}
