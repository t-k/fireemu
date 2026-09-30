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

/** A run tag: six lowercase hex digits, so it can name nothing else (no path, no label). */
export const RUN_TAG = /^[0-9a-f]{6}$/;

/** The run's tag, or a refusal. */
export function checkRun(run) {
  if (!RUN_TAG.test(String(run))) throw new Error(`run tag ${run} is not six hex digits`);
  return run;
}

/**
 * The run's own providers: an OIDC or SAML ID `…fireemu-<run>-…`, so a run never writes or
 * deletes another run's or another lane's providers.
 */
export function runProvider(run) {
  return new RegExp(`^(oidc|saml)\\.fireemu-${checkRun(run)}-[a-z0-9-]{1,40}$`);
}

/** The Hosting preview channel that serves the run's issuer: `<project>--fed-<run>-<hash>`. */
export function issuerChannelHost(project, run) {
  const p = project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${p}--fed-${checkRun(run)}-[a-z0-9]{1,16}\\.web\\.app$`);
}

/**
 * The hosts a request may name: the sandbox's own Hosting domains, localhost and the run's
 * issuer host (the run's Hosting preview channel, known only after its deploy).
 */
export function allowedHosts(project, issuerHost, run) {
  const hosts = new Set([`${project}.firebaseapp.com`, `${project}.web.app`, "localhost"]);
  if (issuerHost) {
    if (!issuerChannelHost(project, run).test(issuerHost)) {
      throw new Error(`issuer host ${issuerHost} is not the run's preview channel of the sandbox`);
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
  if (!allowedHosts(ctx.project, ctx.issuerHost, ctx.run).has(host))
    throw new Error(`${key} host ${host} is not reviewed`);
}

/** The run's own SAML IdP entity ID (corpus-saml.mjs): the project's web.app host, the run. */
const runSamlIdp = (ctx) => ({
  test: (issuer) => issuer === `https://${ctx.project}.web.app/saml/${checkRun(ctx.run)}`,
});

/**
 * Whether an unsigned response is the run's own (pre-send review S1): no signature or
 * certificate element (any prefix, any case; the text of other elements, such as a NameID
 * naming a signature, is not markup, pre-send re-review R-M1), and every `Issuer` element (any
 * prefix, any attributes) collected and naming exactly the run's SAML IdP (a comment or CDATA
 * in one is never that).
 */
const SIGNATURE_MARKUP =
  /<\/?(?:[\w-]+:)?(?:Signature|SignatureValue|SignedInfo|KeyInfo|X509[A-Za-z]*)\b/i;

function isRunUnsignedResponse(xml, ctx) {
  if (SIGNATURE_MARKUP.test(xml)) return false;
  const openings = xml.match(/<(?:[\w-]+:)?Issuer\b/g) ?? [];
  const issuers = [
    ...xml.matchAll(/<(?:[\w-]+:)?Issuer\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?Issuer>/g),
  ].map((match) => match[1]);
  return (
    issuers.length > 0 &&
    issuers.length === openings.length &&
    issuers.every((issuer) => runSamlIdp(ctx).test(issuer))
  );
}

/** Whether `value` is a credential the run made: synthetic text or a JWS of the run's key. */
export function isRunCredential(value, ctx) {
  if (typeof value !== "string" || value === "") return true;
  if (value.startsWith("fireemu-")) return true;
  // A SAMLResponse (base64 XML): every certificate it carries is one this run made, or it is
  // unsigned and issued by the run's own SAML IdP (no credential at all).
  const xml = Buffer.from(value, "base64").toString("utf8");
  if (xml.includes("<samlp:Response")) {
    const carried = [...xml.matchAll(/<ds:X509Certificate>([^<]*)<\/ds:X509Certificate>/g)].map(
      (match) => match[1].replaceAll(/\s/g, ""),
    );
    if (carried.length === 0) return isRunUnsignedResponse(xml, ctx);
    return carried.every((c) => ctx.runCertificates?.includes(c) ?? false);
  }
  const [header] = value.split(".");
  try {
    const { kid } = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
    // A negative row names a key the issuer does not publish: `fireemu-…`, never a real kid.
    return (ctx.runKids?.includes(kid) ?? false) || String(kid).startsWith("fireemu-");
  } catch {
    return false;
  }
}

const CREDENTIAL_KEYS = new Set([
  "id_token",
  "access_token",
  "code",
  "oauth_token",
  "SAMLResponse",
]);

function guardIdpRequest(body, ctx) {
  const postBody = new URLSearchParams(typeof body.postBody === "string" ? body.postBody : "");
  const provider = postBody.get("providerId") ?? body.providerId;
  // A sign-in may name the run's provider in another case (a strict refusal row); it reads only.
  if (
    provider &&
    !runProvider(ctx.run).test(String(provider).toLowerCase()) &&
    !THIRD_PARTY_PROVIDERS.has(provider)
  ) {
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
  if (/^(oidc|saml)\.[a-z0-9-]+$/i.test(id ?? "") && !runProvider(ctx.run).test(id)) {
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
  // A run's tag and issuer host are checked before anything is sent, whatever the request names.
  checkRun(ctx.run);
  allowedHosts(ctx.project, ctx.issuerHost, ctx.run);
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
export function validateFederationCorpus(programs, { run }) {
  const own = runProvider(run);
  const ids = new Set();
  for (const program of programs) {
    if (ids.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    ids.add(program.id);
    if (!program.id.startsWith("auth-federation/")) throw new Error(`${program.id}: not ours`);
    const steps = new Set();
    for (const provider of program.providers ?? []) {
      if (!own.test(provider)) throw new Error(`${program.id}: provider ${provider}`);
    }
    for (const step of program.steps) {
      if (steps.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      steps.add(step.id);
      // Whatever a step may create is declared, so the harness deletes it after the program.
      const created = step.query?.oauthIdpConfigId ?? step.query?.inboundSamlConfigId;
      if (step.method === "POST" && /^(oidc|saml)\./i.test(created ?? "")) {
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
