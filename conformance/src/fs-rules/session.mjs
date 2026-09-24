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
  normalizeString,
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
    shouldStop = () => false,
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;
  /** A sleep that ends early once a stop is requested, so a signal never waits out a long wait. */
  async function pause(ms) {
    const until = Date.now() + ms;
    // Cleanup waits its full time: a stop request must not turn its polling into a burst.
    const keepWaiting = () => cleaningUp || !shouldStop();
    while (Date.now() < until && keepWaiting()) await sleep(Math.min(1000, until - Date.now()));
    if (shouldStop() && !cleaningUp) throw fatal("stopped by a signal");
  }

  /** Applies `action` to every item, even after one fails, then reports every failure. */
  async function eachOf(items, action) {
    const errors = [];
    for (const item of items) {
      try {
        await action(item);
      } catch (error) {
        errors.push(String(error.message ?? error));
      }
    }
    if (errors.length) throw fatal(errors.join("; "));
  }
  const principals = new Map();
  /** Rulesets this session created in production, deleted at the end. */
  const createdRulesets = new Set();
  /** The label of the ruleset in force per database (`null`: no release), as the harness set it. */
  const active = new Map();
  /** Databases whose release this session created, patched or deleted: cleanup unpublishes them. */
  const touched = new Set();
  /** The label a publication replaced, per database, checked to be refused after each program. */
  const superseded = new Map();
  /** Every publication with how long it took to settle, for the evidence. */
  const publications = [];
  /** Sandbox configuration changes, for the ledger. */
  const changes = [];
  let tenant;
  let tenantConfigChanged = false;
  /** Cleanup is never refused by the harness ceiling: it must always run to the end. */
  let cleaningUp = false;
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
      if (harnessRequests >= maxHarnessRequests && !cleaningUp)
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
  async function call(url, init, { expect = [200], timeout = timeoutMs } = {}) {
    charge(true);
    let response;
    try {
      response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeout) });
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
        `harness ${init.method} ${new URL(url).pathname}: HTTP ${response.status} ${normalizeString(text.slice(0, 300), ctx, principals)}`,
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
    // A phone number or custom uid that already has an account signs in to it: that account
    // belongs to someone else (another lane), so it is never adopted, and never deleted.
    if (
      ctx.target.kind === "production" &&
      answer?.isNewUser !== true &&
      spec.provider !== "anonymous" &&
      spec.provider !== "password"
    ) {
      throw fatal(`principal ${name} signed in to an existing account; refusing to adopt it`);
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

  async function accountUpdate(name, fields) {
    const principal = principals.get(name);
    await admin("POST", "itk", `${accountsPath(principal)}:update`, {
      localId: principal.uid,
      ...fields,
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
    await eachOf([...principals.keys()], deletePrincipal);
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
        // Recorded before the change, so a failure after it still restores the flag.
        tenantConfigChanged = true;
        await admin(
          "PATCH",
          "itk",
          `admin/v2/projects/${ctx.project}/config?updateMask=multiTenant.allowTenants`,
          { multiTenant: { allowTenants: true } },
        );
        changes.push("multiTenant.allowTenants false -> true");
      }
    }
    const { json } = await admin("POST", "itk", `v2/projects/${ctx.project}/tenants`, {
      displayName: "fsr-tenant",
      allowPasswordSignup: true,
    });
    const id = String(json?.name ?? "").split("/tenants/")[1];
    if (!id) throw fatal("tenant creation returned no name");
    tenant = { id };
    changes.push("tenant created");
    return id;
  }

  /** Deletes the run's tenant and restores the flag, whatever fails first; both read back. */
  async function deleteTenant() {
    let failure;
    try {
      if (tenant && !tenant.deleted) {
        await admin("DELETE", "itk", `v2/projects/${ctx.project}/tenants/${tenant.id}`, undefined, {
          expect: [200, 404],
        });
        const { json } = await admin(
          "GET",
          "itk",
          `v2/projects/${ctx.project}/tenants?pageSize=100`,
        );
        if ((json?.tenants ?? []).some(({ name }) => name.endsWith(`/tenants/${tenant.id}`)))
          throw fatal("the run's tenant is still listed after its deletion");
        tenant.deleted = true;
        changes.push("tenant deleted");
      }
    } catch (error) {
      failure = error;
    }
    if (tenantConfigChanged) {
      try {
        await admin(
          "PATCH",
          "itk",
          `admin/v2/projects/${ctx.project}/config?updateMask=multiTenant.allowTenants`,
          { multiTenant: { allowTenants: false } },
        );
        const { json } = await admin("GET", "itk", `admin/v2/projects/${ctx.project}/config`);
        if (json?.multiTenant?.allowTenants === true)
          throw fatal("multiTenant.allowTenants did not read back as restored");
        tenantConfigChanged = false;
        changes.push("multiTenant.allowTenants restored to false (read back)");
      } catch (error) {
        failure = failure
          ? fatal(`${failure.message}; and the flag restore failed: ${error.message}`)
          : error;
      }
    }
    if (failure) throw failure;
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
      await databaseReadsBack(id, 200);
    }
  }

  async function deleteDatabases() {
    if (ctx.target.kind !== "production") return;
    await eachOf(Object.values(ctx.databases), async (id) => {
      const { status, json } = await admin(
        "DELETE",
        "firestore",
        `v1/projects/${ctx.project}/databases/${id}`,
        undefined,
        { expect: [200, 404] },
      );
      if (status === 200) await waitOperation(json);
      await databaseReadsBack(id, 404);
    });
  }

  /**
   * Waits for a database operation. Production has answered a finished delete with a
   * `response` and no `done` field, so either one ends the wait; an `error` is a failure.
   */
  async function waitOperation(operation) {
    const finished = (op) =>
      op?.done === true || op?.response !== undefined || op?.error !== undefined;
    let current = operation;
    for (let i = 0; i < 60 && !finished(current); i += 1) {
      await sleep(2000);
      ({ json: current } = await admin("GET", "firestore", `v1/${operation.name}`));
    }
    if (!finished(current) || current.error) throw fatal(`operation ${operation?.name} failed`);
  }

  /** Reads a database back until it answers `status` (200: created, 404: deleted). */
  async function databaseReadsBack(id, status) {
    for (let i = 0; i < 30; i += 1) {
      const { status: got } = await admin(
        "GET",
        "firestore",
        `v1/projects/${ctx.project}/databases/${id}`,
        undefined,
        { expect: [200, 404] },
      );
      if (got === status) return;
      await sleep(2000);
    }
    throw fatal(`database ${id} did not read back as ${status === 200 ? "created" : "deleted"}`);
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

  /**
   * The status of an unauthenticated get of a marker document over REST and over gRPC, as HTTP
   * statuses: 404 (allowed: in force), 403 (refused), anything else unknown.
   */
  async function markerStatus(label, which) {
    charge(true);
    const url = `${ctx.target.kind === "production" ? PRODUCTION.firestore : ctx.target.firestoreOrigin}/v1/${documentsName(ctx, which)}/fsr-marker/${label}`;
    let rest;
    try {
      rest = (await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })).status;
    } catch {
      rest = 0;
    }
    charge(true);
    const code = await new Promise((resolve) => {
      const metadata = new grpc.Metadata();
      metadata.set("google-cloud-resource-prefix", databaseName(ctx, which));
      metadata.set(
        "x-goog-request-params",
        `name=${encodeURIComponent(`${documentsName(ctx, which)}/fsr-marker/${label}`)}`,
      );
      grpcClient.makeUnaryRequest(
        "/google.firestore.v1.Firestore/GetDocument",
        (message) => protos.google.firestore.v1.GetDocumentRequest.serialize(message),
        (bytes) => protos.google.firestore.v1.Document.deserialize(bytes),
        { name: `${documentsName(ctx, which)}/fsr-marker/${label}` },
        metadata,
        { deadline: new Date(Date.now() + timeoutMs) },
        (error) => resolve(error ? error.code : 0),
      );
    });
    const grpcStatus = { 5: 404, 7: 403 }[code] ?? -code - 1;
    return rest === grpcStatus ? rest : `rest ${rest} grpc ${code}`;
  }

  /** The markers a database must answer 403 for when `label` is in force (or nothing is). */
  function refusedMarkers(label, previous, which) {
    const refused = new Set();
    if (previous && previous !== label) refused.add(previous);
    // Without a release every marker this lane could have left in force must be refused.
    if (!label) {
      for (const id of which === "default" ? ["main", "alt"] : ["named"]) refused.add(markerOf(id));
    }
    return [...refused];
  }

  /**
   * Waits until SETTLE_STREAK consecutive polls, each over REST and gRPC, see `label` in force
   * and every other marker refused. Production serves a switch from several frontends that
   * change over at different times, so one good answer proves nothing.
   */
  async function settle(label, previous, which) {
    const expect = [
      ...(label ? [[label, 404]] : []),
      ...refusedMarkers(label, previous, which).map((marker) => [marker, 403]),
    ];
    // fireemu switches synchronously; a marker that disagrees there is a difference the rows
    // record, not a propagation delay.
    if (expect.length === 0 || ctx.target.kind !== "production") return { settleMs: 0, polls: 0 };
    const start = Date.now();
    let streak = 0;
    let polls = 0;
    while (Date.now() - start < SETTLE_LIMIT_MS) {
      let ok = true;
      for (const [marker, status] of expect)
        ok = ok && (await markerStatus(marker, which)) === status;
      polls += 1;
      streak = ok ? streak + 1 : 0;
      if (streak >= SETTLE_STREAK) return { settleMs: Date.now() - start, polls };
      await pause(1000);
    }
    throw fatal(`release of ${label ?? "nothing"} on ${which} did not settle`);
  }

  /** Puts `rulesetId` in force on a database (`null`: deletes the release). */
  async function publish(rulesetId, which = "default") {
    const previous = active.get(which) ?? null;
    const label = rulesetId ? markerOf(rulesetId) : null;
    if (active.has(which) && previous === label) return;
    // Known before anything is sent, so cleanup deletes a release whatever fails after this.
    touched.add(which);
    active.delete(which);
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
          { expect: [200, 404] },
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
    const settled = await settle(label, previous, which);
    active.set(which, label);
    superseded.set(which, previous);
    publications.push({ database: which, label, previous, ...settled });
    log(`release ${which}: ${label ?? "none"} (${settled.polls} polls, ${settled.settleMs} ms)`);
  }

  /** Whether the rulesets in force are still the ones the rows ran under (10 polls each). */
  async function stillInForce(databases) {
    for (const which of databases) {
      if (!active.has(which)) continue;
      const label = active.get(which);
      const expect = [
        ...(label ? [[label, 404]] : []),
        ...refusedMarkers(label, superseded.get(which), which).map((marker) => [marker, 403]),
      ];
      for (let i = 0; i < 10; i += 1) {
        for (const [marker, status] of expect) {
          if ((await markerStatus(marker, which)) !== status) return false;
        }
      }
    }
    return true;
  }

  const controlHeaders = () =>
    ctx.target.control?.token ? { authorization: `Bearer ${ctx.target.control.token}` } : {};

  /** fireemu's ruleset load grows superlinearly with the ruleset (see the open issue). */
  const LOCAL_LOAD_TIMEOUT_MS = 600_000;

  async function loadLocal(source, { expect = [200] } = {}) {
    return call(
      `${ctx.target.firestoreOrigin}/emulator/v1/projects/${ctx.project}:securityRules`,
      {
        method: "PUT",
        headers: { ...ownerHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: source }] } }),
      },
      { expect, timeout: LOCAL_LOAD_TIMEOUT_MS },
    );
  }

  const COMPILE_STATUSES = [200, 400, 413, 429, 500, 502, 503, 504];

  /**
   * Whether a ruleset compiles: production `rulesets.create`, fireemu's ruleset load. A status
   * other than 200 or 400 is recorded as it is and says nothing about compilation.
   */
  async function compiles(source) {
    if (ctx.target.kind === "production") {
      const { status, json } = await admin(
        "POST",
        "rules",
        `v1/projects/${ctx.project}/rulesets`,
        { source: { files: [{ name: "firestore.rules", content: source }] } },
        { expect: COMPILE_STATUSES },
      );
      if (status === 200) {
        createdRulesets.add(json.name);
        await admin("DELETE", "rules", `v1/${json.name}`);
        createdRulesets.delete(json.name);
      }
      return status === 200 || status === 400
        ? { compiled: status === 200 }
        : { status, transport: "compile-status" };
    }
    const { status } = await loadLocal(source, { expect: COMPILE_STATUSES });
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
    return status === 200 || status === 400
      ? { compiled: status === 200 }
      : { status, transport: "compile-status" };
  }

  /** Deletes the run's rulesets; one still in use by a release (400) is a cleanup failure. */
  async function deleteCreatedRulesets() {
    await eachOf([...createdRulesets], async (name) => {
      await admin("DELETE", "rules", `v1/${name}`, undefined, { expect: [200, 404] });
      createdRulesets.delete(name);
    });
  }

  /**
   * Reads back that the run left nothing behind: no release, no database but `(default)`, no
   * ruleset of the run, no project-level account of the run. Production only.
   */
  async function audit() {
    if (ctx.target.kind !== "production") return [];
    const problems = [];
    const { json: releases } = await admin("GET", "rules", `v1/projects/${ctx.project}/releases`);
    if ((releases?.releases ?? []).length) problems.push("a release remains");
    const { json: databases } = await admin(
      "GET",
      "firestore",
      `v1/projects/${ctx.project}/databases`,
    );
    const extra = (databases?.databases ?? []).filter(({ name }) => !name.endsWith("/(default)"));
    if (extra.length) problems.push(`${extra.length} named database(s) remain`);
    if (createdRulesets.size) problems.push(`${createdRulesets.size} ruleset(s) of the run remain`);
    // The lane owns Rules on the sandbox: any ruleset left is one a lost answer hid from the run.
    const { json: rulesets } = await admin("GET", "rules", `v1/projects/${ctx.project}/rulesets`);
    if ((rulesets?.rulesets ?? []).length)
      problems.push(`${rulesets.rulesets.length} ruleset(s) remain`);
    const { json: accounts } = await admin(
      "POST",
      "itk",
      `v1/projects/${ctx.project}/accounts:query`,
      {
        returnUserInfo: true,
        limit: 500,
      },
    );
    const ours = new Set([...principals.values()].map(({ uid }) => uid));
    const left = (accounts?.userInfo ?? []).filter(({ localId }) => ours.has(localId));
    if (left.length) problems.push(`${left.length} account(s) of the run remain`);
    return problems;
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
    let text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded as non-JSON */
    }
    // Production answers a batchGet in no particular order; SDKs reorder by request.
    if (step.rpc === "batchGet" && Array.isArray(json)) {
      json = inBatchOrder(json);
      text = JSON.stringify(json);
    }
    return { recorded: normalizeRest(response.status, text, ctx, principals), json };
  }

  /** BatchGet results sorted by the document they name (`found.name` or `missing`). */
  const inBatchOrder = (results) =>
    results.toSorted((a, b) => {
      const key = (result) => result?.found?.name ?? result?.missing ?? "";
      return key(a).localeCompare(key(b));
    });

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
        const received = built.method === "BatchGetDocuments" ? inBatchOrder(messages) : messages;
        const recorded = normalizeGrpc(
          {
            code: error ? error.code : 0,
            details: error ? error.details : "",
            messages: JSON.parse(JSON.stringify(received)),
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
        return pause(step.ms);
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
      await pause(Math.max(0, target - Date.now()));
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
    const databases = databasesOf(program);
    for (const which of databases) await wipe(which);
    let failure;
    try {
      if (program.ruleset !== undefined) await publish(program.ruleset);
      for (const [which, rulesetId] of Object.entries(program.releases ?? {}))
        await publish(rulesetId, which);
      for (const name of program.refresh ?? []) await refresh(name);
      await seed(program.seed, raw);
      for (const step of program.steps) {
        if (shouldStop()) throw fatal("stopped by a signal");
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
      // A row counts only if the rulesets it ran under were still in force after it.
      if (ctx.target.kind === "production" && !(await stillInForce(databases))) {
        for (const recorded of Object.values(steps)) recorded.publication = "unsettled";
      }
    } catch (error) {
      failure = error;
    }
    let cleanup;
    try {
      for (const which of databases) await wipe(which);
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
    audit,
    beginCleanup: () => {
      cleaningUp = true;
    },
    /** Databases whose release this session touched, `default` last. */
    touchedDatabases: () => [...touched].toSorted((a, b) => (a === "default") - (b === "default")),
    evidence: () => ({ publications, changes }),
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
  session.beginCleanup();
  for (const step of [
    ...session.touchedDatabases().map((which) => () => session.publish(null, which)),
    () => session.wipe(),
    () => session.deleteDatabases(),
    () => session.deletePrincipals(),
    () => session.deleteTenant(),
    () => session.deleteCreatedRulesets(),
    async () => {
      const problems = await session.audit();
      if (problems.length) throw new Error(`audit: ${problems.join("; ")}`);
    },
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
    ...session.evidence(),
    ...session.counts(),
  };
  if (fatalError) throw Object.assign(fatalError, { partial: out });
  if (cleanupErrors.length)
    throw Object.assign(fatal(`cleanup failed: ${cleanupErrors.join("; ")}`), { partial: out });
  return out;
}
