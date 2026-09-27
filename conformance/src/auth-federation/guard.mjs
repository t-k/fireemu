// Request guard and corpus validation of the AUTH-FEDERATION sandbox harness (draft; the
// closure conditions are not frozen yet and no request has been sent). The guard refuses a
// request before it leaves the process; the validator refuses a corpus before a run starts.
//
// Production is only ever the disposable Identity Platform sandbox. The guard allows:
// - the federation families of this project: signInWithIdp, createAuthUri, token refresh,
//   session cookies, account lookup and deletion, provider configuration (oauthIdpConfigs,
//   inboundSamlConfigs, defaultSupportedIdpConfigs) and the duplicate-email switch;
// - provider writes only to the run's own providers (`oidc.fireemu-…`, `saml.fireemu-…`) or
//   to default IdPs the program declares, so no provider another lane or the project owns is
//   changed;
// - issuers, SSO URLs and callback URIs only on the sandbox's own hosts (the controlled IdP);
// - IdP credentials for third-party providers only when they are synthetic (`fireemu-…`) or
//   signed with the run's own key, so no real third-party token is ever sent;
// - @example.com addresses only.

const HOSTS = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};

/** Providers observed only for their refusals and configuration (scope F3, F5). */
export const THIRD_PARTY_PROVIDERS = new Set([
  "google.com",
  "facebook.com",
  "apple.com",
  "twitter.com",
  "github.com",
  "microsoft.com",
  "yahoo.com",
  "playgames.google.com",
]);

/** The run's own providers: an OIDC or SAML ID with the `fireemu-` prefix. */
export const RUN_PROVIDER = /^(oidc|saml)\.fireemu-[a-z0-9-]{1,48}$/;

/**
 * The hosts a request may name: the sandbox's own Hosting domains, localhost and the run's
 * issuer host (a Hosting preview channel, known only after its deploy).
 */
export function allowedHosts(project, issuerHost) {
  const hosts = new Set([`${project}.firebaseapp.com`, `${project}.web.app`, "localhost"]);
  if (issuerHost) {
    if (!issuerHost.startsWith(`${project}--`) || !issuerHost.endsWith(".web.app")) {
      throw new Error(`issuer host ${issuerHost} is not a preview channel of the sandbox`);
    }
    hosts.add(issuerHost);
  }
  return hosts;
}

const PROVIDER_COLLECTION =
  /^\/(admin\/)?v2\/projects\/([^/]+)\/(oauthIdpConfigs|inboundSamlConfigs|defaultSupportedIdpConfigs)(?:\/([^/]+))?$/;

function families(project, role) {
  const p = project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return [
    /^\/v1\/accounts:(signInWithIdp|createAuthUri|lookup|update|delete)$/,
    new RegExp(`^/v1/projects/${p}/accounts(:(lookup|update|delete))?$`),
    new RegExp(`^/v1/projects/${p}:createSessionCookie$`),
    new RegExp(`^/(admin/)?v2/projects/${p}/config$`),
    new RegExp(
      `^/(admin/)?v2/projects/${p}/(oauthIdpConfigs|inboundSamlConfigs|defaultSupportedIdpConfigs)(/[^/]+)?$`,
    ),
    /^\/(admin\/)?v2\/defaultSupportedIdps$/,
    ...(role === "harness"
      ? [new RegExp(`^/v1/projects/${p}/accounts:(batchGet|batchDelete)$`)]
      : []),
  ];
}

function walkEntries(value, visit, key = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkEntries(v, visit, k);
  } else visit(key, value);
}

function assertOnlyExampleEmail(text, where) {
  for (const [, domain] of String(text).matchAll(/[^\s@"'<>(),;:=&]+@([^\s@"'<>/?#&]+)/g)) {
    if (domain.toLowerCase() !== "example.com") {
      throw new Error(`${where}: email outside example.com (${domain})`);
    }
  }
}

const URL_KEYS = new Set([
  "requestUri",
  "continueUri",
  "issuer",
  "ssoUrl",
  "idpEntityId",
  "callbackUri",
  "spEntityId",
]);

function assertHost(value, ctx, key) {
  let host;
  try {
    host = new URL(value).hostname;
  } catch {
    // Not an absolute URL: sent as written, to be validated by the service.
    return;
  }
  if (!allowedHosts(ctx.project, ctx.issuerHost).has(host))
    throw new Error(`${key} host ${host} is not reviewed`);
}

/** Whether `value` is a credential the run made: synthetic text or a JWS of the run's key. */
export function isRunCredential(value, ctx) {
  if (typeof value !== "string" || value === "") return true;
  if (value.startsWith("fireemu-")) return true;
  const [header] = value.split(".");
  try {
    const { kid } = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
    // A negative row names a key the issuer does not publish: `fireemu-…`, never a real kid.
    return (ctx.runKids?.includes(kid) ?? false) || String(kid).startsWith("fireemu-");
  } catch {
    return false;
  }
}

const CREDENTIAL_KEYS = new Set(["id_token", "access_token", "code", "oauth_token", "SAMLResponse"]);

function guardIdpRequest(body, ctx) {
  const postBody = new URLSearchParams(typeof body.postBody === "string" ? body.postBody : "");
  const provider = postBody.get("providerId") ?? body.providerId;
  if (provider && !RUN_PROVIDER.test(provider) && !THIRD_PARTY_PROVIDERS.has(provider)) {
    throw new Error(`provider ${provider} is not the run's or a reviewed third party`);
  }
  for (const [key, value] of postBody) {
    if (CREDENTIAL_KEYS.has(key) && !isRunCredential(value, ctx)) {
      throw new Error(`${key} is not a credential this run made`);
    }
    if (URL_KEYS.has(key)) assertHost(value, ctx, key);
    assertOnlyExampleEmail(value, key);
  }
}

function guardProviderWrite(method, path, query, ctx) {
  const [, , , collection, resource] = PROVIDER_COLLECTION.exec(path) ?? [];
  if (!collection || method === "GET") return;
  const id =
    resource ??
    query.get(
      collection === "oauthIdpConfigs"
        ? "oauthIdpConfigId"
        : collection === "inboundSamlConfigs"
          ? "inboundSamlConfigId"
          : "idpId",
    );
  if (collection === "defaultSupportedIdpConfigs") {
    if (!ctx.defaultIdpWrites?.includes(id)) {
      throw new Error(`default IdP ${id} is not declared by the program`);
    }
    return;
  }
  // A malformed ID is refused by the service; only well-formed IDs must be the run's.
  if (/^(oidc|saml)\.[a-z0-9-]+$/i.test(id ?? "") && !RUN_PROVIDER.test(id)) {
    throw new Error(`provider ${id} is not one of the run's`);
  }
}

function guardConfigWrite(method, query) {
  if (method === "GET") return;
  const mask = (query.get("updateMask") ?? "").split(",").filter(Boolean);
  if (mask.length === 0) throw new Error("a config write names a non-empty updateMask");
  for (const path of mask) {
    if (path !== "signIn.allowDuplicateEmails") {
      throw new Error(`config path ${path} is not written by AUTH-FEDERATION`);
    }
  }
}

/** The API family and the path below the target's origin, or a refusal. */
function locate(parsed, ctx) {
  if (ctx.target.kind === "production") {
    if (parsed.protocol !== "https:") throw new Error("production requests use https");
    const api = Object.entries(HOSTS).find(([, host]) => host === parsed.host)?.[0];
    if (api) return { api, path: parsed.pathname };
    throw new Error(`request host ${parsed.host} is not reviewed`);
  }
  if (parsed.origin !== new URL(ctx.target.origin).origin)
    throw new Error("request left the local target");
  const api = Object.entries(HOSTS).find(([, host]) =>
    parsed.pathname.startsWith(`/${host}/`),
  )?.[0];
  return { api, path: api ? parsed.pathname.slice(HOSTS[api].length + 1) : parsed.pathname };
}

/** The last check before a request leaves the process. `role` is "step" or "harness". */
export function guardHttp({ url, method = "GET", body }, ctx, { role }) {
  if (!["step", "harness"].includes(role)) throw new Error("unknown role");
  // A run's issuer host is checked before anything is sent, whatever the request names.
  allowedHosts(ctx.project, ctx.issuerHost);
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const { api, path } = locate(parsed, ctx);
  const allowed =
    api === "securetoken" ? [/^\/v1\/token$/] : api === "itk" ? families(ctx.project, role) : [];
  if (!allowed.some((family) => family.test(path)))
    throw new Error(`request path is not a reviewed family: ${path}`);
  let parsedBody = {};
  if (body !== undefined && body !== "") {
    if (typeof body !== "string") throw new Error("request body is not text");
    try {
      parsedBody = JSON.parse(body);
    } catch {
      parsedBody = Object.fromEntries(new URLSearchParams(body));
    }
  }
  if (path.endsWith("/config")) guardConfigWrite(method, parsed.searchParams);
  guardProviderWrite(method, path, parsed.searchParams, ctx);
  if (path.endsWith(":signInWithIdp") || path.endsWith(":createAuthUri"))
    guardIdpRequest(parsedBody, ctx);
  for (const input of [Object.fromEntries(parsed.searchParams), parsedBody]) {
    walkEntries(input, (key, value) => {
      if (typeof value !== "string") return;
      if (URL_KEYS.has(key)) assertHost(value, ctx, key);
      assertOnlyExampleEmail(value, key);
    });
  }
}

/**
 * Refuses a corpus that is not what the guard and the restore can hold: every program names
 * the providers it creates (and deletes them), the default IdPs it writes, and its config
 * paths; step IDs are unique.
 */
export function validateFederationCorpus(programs) {
  const ids = new Set();
  for (const program of programs) {
    if (ids.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    ids.add(program.id);
    if (!program.id.startsWith("auth-federation/")) throw new Error(`${program.id}: not ours`);
    const steps = new Set();
    for (const provider of program.providers ?? []) {
      if (!RUN_PROVIDER.test(provider)) throw new Error(`${program.id}: provider ${provider}`);
    }
    for (const step of program.steps) {
      if (steps.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      steps.add(step.id);
      // Whatever a step may create is declared, so the harness deletes it after the program.
      const created = step.query?.oauthIdpConfigId ?? step.query?.inboundSamlConfigId;
      if (step.method === "POST" && RUN_PROVIDER.test(created ?? "")) {
        if (!program.providers?.includes(created)) {
          throw new Error(`${program.id}#${step.id}: creates undeclared ${created}`);
        }
      }
      const idp = step.query?.idpId;
      if (idp !== undefined && !program.defaultIdpWrites?.includes(idp)) {
        throw new Error(`${program.id}#${step.id}: writes undeclared default IdP ${idp}`);
      }
    }
    for (const touched of program.touches ?? []) {
      if (touched !== "signIn.allowDuplicateEmails") {
        throw new Error(`${program.id}: touches ${touched}`);
      }
    }
  }
}
