// Requests and the request guard of the Secure Token body recording.
//
// Production is only ever the disposable Identity Platform sandbox. Every request is built here
// and checked by `guardRequest` as the last step before it leaves the process: a reviewed path
// of this project on the target's host, whose body and query name only this project, this run's
// example.com addresses and (for the tenant) the one tenant this run created. Only the
// `harness` requests (account and tenant management, the multi-tenancy switch) use the owner
// credential; the question rows use the API key alone, as a client does.

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";

export const ORIGINS = Object.freeze({
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
});
const LOCAL_PREFIX = Object.freeze({
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
});

/** Password of the corpus accounts; they exist for seconds, in a project nobody else signs in to. */
const PASSWORD = "fireemu-stb-Password-1";

export const emailOf = (run, name) => `fireemu-stb-${run}-${name}@example.com`;
export const localIdOf = (run, name) => `stb-${run}-${name}`;
/** Tenant display names are 4 to 20 letters, digits and hyphens, starting with a letter. */
export const tenantNameOf = (run) => `stb-${run}`;

const escapeRegExp = (text) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The URL and `fetch` init of one request of the recording. */
export function buildRequest(ctx, spec) {
  const api = spec.api ?? "itk";
  const origin =
    ctx.target.kind === "production" ? ORIGINS[api] : `${ctx.target.origin}/${LOCAL_PREFIX[api]}`;
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(spec.query ?? {})) query.set(name, String(value));
  const headers = {};
  if (spec.auth === "key") {
    query.set("key", ctx.target.kind === "production" ? ctx.target.apiKey : "fake-api-key");
  } else if (spec.auth === "admin") {
    headers.authorization = `Bearer ${ctx.target.kind === "production" ? ctx.target.adminToken : "owner"}`;
    if (ctx.target.kind === "production") headers["x-goog-user-project"] = ctx.target.quotaProject;
  } else {
    throw new Error(`request ${spec.id}: auth must be key or admin`);
  }
  const init = { method: spec.method ?? "POST", headers };
  if (spec.body !== undefined) {
    headers["content-type"] = spec.contentType ?? "application/json";
    init.body = typeof spec.body === "string" ? spec.body : JSON.stringify(spec.body);
  }
  const search = query.toString();
  return { url: `${origin}/${spec.path}${search ? `?${search}` : ""}`, init };
}

// ---- the reviewed requests -----------------------------------------------------------------

const itk = (id, auth, method, path, extra = {}) => ({
  id,
  api: "itk",
  auth,
  method,
  path,
  ...extra,
});

export const requests = {
  /** The question: one refresh. Body text and content type come from `encodeBody`. */
  refresh: (encoded) => ({
    id: "refresh",
    api: "securetoken",
    auth: "key",
    method: "POST",
    path: "v1/token",
    contentType: encoded.contentType,
    body: encoded.body,
  }),
  /** Owner-side creation of a password account with a chosen local id. */
  createAccount: (run, name, tenantId) =>
    itk(
      "create-account",
      "admin",
      "POST",
      tenantId === undefined
        ? "v1/projects/{project}/accounts"
        : `v1/projects/{project}/tenants/${tenantId}/accounts`,
      {
        body: {
          localId: localIdOf(run, name),
          email: emailOf(run, name),
          password: PASSWORD,
          emailVerified: true,
        },
      },
    ),
  deleteAccount: (run, name, tenantId) =>
    itk(
      "delete-account",
      "admin",
      "POST",
      tenantId === undefined
        ? "v1/projects/{project}/accounts:delete"
        : `v1/projects/{project}/tenants/${tenantId}/accounts:delete`,
      { body: { localId: localIdOf(run, name) } },
    ),
  lookupAccount: (run, name, tenantId) =>
    itk(
      "lookup-account",
      "admin",
      "POST",
      tenantId === undefined
        ? "v1/projects/{project}/accounts:lookup"
        : `v1/projects/{project}/tenants/${tenantId}/accounts:lookup`,
      { body: { localId: [localIdOf(run, name)] } },
    ),
  /** The sign-in that yields the refresh token. The tenant is named in the body, as a client does. */
  signIn: (run, name, tenantId) =>
    itk("sign-in", "key", "POST", "v1/accounts:signInWithPassword", {
      body: {
        email: emailOf(run, name),
        password: PASSWORD,
        returnSecureToken: true,
        ...(tenantId === undefined ? {} : { tenantId }),
      },
    }),
  countAccounts: () =>
    itk("count-accounts", "admin", "POST", "v1/projects/{project}/accounts:query", {
      body: { returnUserInfo: false },
    }),
  createTenant: (run) =>
    itk("create-tenant", "admin", "POST", "v2/projects/{project}/tenants", {
      body: { displayName: tenantNameOf(run), allowPasswordSignup: true },
    }),
  getTenant: (tenantId) =>
    itk("get-tenant", "admin", "GET", `v2/projects/{project}/tenants/${tenantId}`),
  deleteTenant: (tenantId) =>
    itk("delete-tenant", "admin", "DELETE", `v2/projects/{project}/tenants/${tenantId}`),
  listTenants: (pageToken) =>
    itk("list-tenants", "admin", "GET", "v2/projects/{project}/tenants", {
      query: { pageSize: 100, ...(pageToken ? { pageToken } : {}) },
    }),
  readConfig: () => itk("read-config", "admin", "GET", "admin/v2/projects/{project}/config"),
  /** The only configuration this recording ever writes. */
  writeTenancy: (allow) =>
    itk("write-tenancy", "admin", "PATCH", "admin/v2/projects/{project}/config", {
      query: { updateMask: "multiTenant.allowTenants" },
      body: { multiTenant: { allowTenants: allow } },
    }),
};

/** Fills `{project}` in a request spec. */
export const withProject = (spec, project) => ({
  ...spec,
  path: spec.path.replaceAll("{project}", project),
});

// ---- the guard -----------------------------------------------------------------------------

function* walkStrings(value, key = "") {
  if (typeof value === "string") yield [key, value];
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v, key);
  else if (value && typeof value === "object")
    for (const [k, v] of Object.entries(value)) yield* walkStrings(v, k);
}

/**
 * The last check before a request leaves the process.
 *
 * `ctx.run` is the run id, `ctx.tenantId` the tenant this run created (undefined before it
 * exists). Throws on anything outside the reviewed families.
 */
export function guardRequest({ url, init }, ctx) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  let api;
  let path;
  if (ctx.target.kind === "production") {
    api = Object.entries(ORIGINS).find(([, origin]) => origin === parsed.origin)?.[0];
    path = parsed.pathname;
  } else {
    if (parsed.origin !== new URL(ctx.target.origin).origin)
      throw new Error("request left the local target");
    api = Object.entries(LOCAL_PREFIX).find(([, prefix]) =>
      parsed.pathname.startsWith(`/${prefix}/`),
    )?.[0];
    path = api ? parsed.pathname.slice(LOCAL_PREFIX[api].length + 1) : parsed.pathname;
  }
  const project = escapeRegExp(ctx.project);
  const method = init.method ?? "GET";
  const tenant = "[A-Za-z0-9_-]{1,64}";
  const families =
    api === "securetoken"
      ? [["POST", /^\/v1\/token$/]]
      : [
          ["POST", /^\/v1\/accounts:signInWithPassword$/],
          ["POST", new RegExp(`^/v1/projects/${project}/accounts(:(lookup|delete|query))?$`)],
          [
            "POST",
            new RegExp(`^/v1/projects/${project}/tenants/${tenant}/accounts(:(lookup|delete))?$`),
          ],
          ["POST", new RegExp(`^/v2/projects/${project}/tenants$`)],
          ["GET", new RegExp(`^/v2/projects/${project}/tenants$`)],
          ["GET", new RegExp(`^/v2/projects/${project}/tenants/${tenant}$`)],
          ["DELETE", new RegExp(`^/v2/projects/${project}/tenants/${tenant}$`)],
          ["GET", new RegExp(`^/admin/v2/projects/${project}/config$`)],
          ["PATCH", new RegExp(`^/admin/v2/projects/${project}/config$`)],
        ];
  if (!api || !families.some(([m, family]) => m === method && family.test(path)))
    throw new Error(`request is not a reviewed family: ${method} ${path}`);

  const query = Object.fromEntries(parsed.searchParams);
  if (
    path.endsWith("/config") &&
    method === "PATCH" &&
    query.updateMask !== "multiTenant.allowTenants"
  )
    throw new Error("the only configuration written is multiTenant.allowTenants");
  if (api === "securetoken" && Object.keys(query).join() !== "key")
    throw new Error("the refresh request carries the API key alone");

  const tenantInPath = /\/tenants\/([^/:]+)/.exec(path)?.[1];
  if (tenantInPath !== undefined && tenantInPath !== ctx.tenantId)
    throw new Error(`request names a tenant this run did not create: ${tenantInPath}`);

  if (typeof init.body === "string") {
    const json = init.headers["content-type"] === "application/json";
    // A refresh row sends its own spellings; its body is not parsed as the API's.
    if (api !== "securetoken") {
      const body = json ? JSON.parse(init.body) : {};
      const bodyTenant = body.tenantId;
      if (bodyTenant !== undefined && bodyTenant !== ctx.tenantId)
        throw new Error("request names a tenant this run did not create");
      if (path.endsWith("/config")) {
        const keys = Object.keys(body.multiTenant ?? {});
        if (Object.keys(body).join() !== "multiTenant" || keys.join() !== "allowTenants")
          throw new Error("the only configuration written is multiTenant.allowTenants");
      }
      if (path.endsWith("/tenants") && method === "POST") {
        if (body.displayName !== tenantNameOf(ctx.run))
          throw new Error("the tenant is named for this run");
      }
      for (const [key, value] of walkStrings(body)) {
        if (key === "email" && !value.startsWith(`fireemu-stb-${ctx.run}-`))
          throw new Error(`email is not this run's: ${key}`);
        if (key === "localId" && !value.startsWith(`stb-${ctx.run}-`))
          throw new Error("localId is not this run's");
        if (/@/.test(value) && !/^fireemu-stb-\d+-[a-z]+@example\.com$/.test(value))
          throw new Error(`address outside example.com: ${key}`);
        if (/\+\d{8,15}/.test(value.replaceAll(/[\s().-]/g, "")))
          throw new Error("a phone number is never sent");
      }
    } else if (init.body.length > 4096) {
      throw new Error("a refresh body is small");
    }
  }
  for (const key of Object.keys(query)) {
    if (!["key", "pageSize", "pageToken", "updateMask"].includes(key))
      throw new Error(`unreviewed query parameter ${key}`);
  }
}

export const SANDBOX = SANDBOX_PROJECT;
