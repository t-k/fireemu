// An in-process stand-in for the sandbox, used by the tests and by nothing else.
//
// It answers in the shapes production was recorded giving (the AUTH-CREDENTIAL refusals program
// for the Secure Token errors, AUTH-TENANT-BLOCKING for tenants and the missing-account lookup)
// and refuses a request that misses a field production requires, so a recorder that builds a
// wrong request fails here as it would there. The refresh policy is a parameter: the tests run
// the recorder against several hypotheses of what production does with the new spellings, since
// none is recorded yet.

import { randomBytes } from "node:crypto";

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

const error = (status, message, extra = {}) => ({
  status,
  json: { error: { code: status, message, status: "INVALID_ARGUMENT", ...extra } },
});

/**
 * @param {object} [options]
 * @param {"snake"|"camel"|"last"|"refuse"} [options.precedence] which spelling wins when both come
 * @param {boolean} [options.camelJson] whether JSON camelCase is read
 * @param {boolean} [options.camelForm] whether form camelCase is read
 * @param {boolean} [options.mixed] whether spellings of different fields mix
 * @param {boolean} [options.tenancy] the starting value of multiTenant.allowTenants
 * @param {string} [options.project] the project id
 * @param {string} [options.number] the project number in answers
 * @param {Array<(req: object, world: object) => (object|string|undefined)>} [options.faults]
 * answered instead of the request, which is not applied ("throw" is a transport failure)
 * @param {Array<(req: object, res: object) => (object|string|undefined)>} [options.lateFaults]
 * applied the request, then replace its answer: a lost or garbled answer
 */
export function createWorld(options = {}) {
  const {
    precedence = "snake",
    camelJson = true,
    camelForm = false,
    mixed = true,
    tenancy = false,
    project = "fireemu-oracle-idp",
    number = "123456789012",
    faults = [],
    lateFaults = [],
  } = options;
  const world = {
    tenancy,
    tenants: new Map(),
    accounts: new Map(),
    tokens: new Map(),
    log: [],
    apiKey: "fake-api-key",
  };

  const issueToken = (account) => {
    const token = `AMf-${randomBytes(24).toString("base64url")}`;
    world.tokens.set(token, account);
    return token;
  };

  const jwt = (account) => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: `https://securetoken.google.com/${project}`,
      aud: project,
      auth_time: now,
      user_id: account.localId,
      sub: account.localId,
      iat: now,
      exp: now + 3600,
      email: account.email,
      email_verified: true,
      firebase: {
        identities: { email: [account.email] },
        sign_in_provider: "password",
        ...(account.tenantId ? { tenant: account.tenantId } : {}),
      },
    };
    return `${b64({ alg: "RS256", kid: "k1", typ: "JWT" })}.${b64(claims)}.${randomBytes(12).toString("base64url")}`;
  };

  /** The refresh endpoint under the policy. */
  function refresh(contentType, rawBody) {
    let fields = [];
    if (contentType.startsWith("application/json")) {
      try {
        fields = Object.entries(JSON.parse(rawBody));
      } catch {
        return error(400, "Invalid JSON payload received.");
      }
    } else {
      fields = [...new URLSearchParams(rawBody)];
    }
    const json = contentType.startsWith("application/json");
    const readsCamel = json ? camelJson : camelForm;
    const names = new Set(fields.map(([k]) => k));
    const grantSnake = names.has("grant_type");
    const grantCamel = readsCamel && names.has("grantType");
    const tokenSnake = names.has("refresh_token");
    const tokenCamel = readsCamel && names.has("refreshToken");
    const camelUsed = grantCamel || tokenCamel;
    const snakeUsed = grantSnake || tokenSnake;
    if (camelUsed && snakeUsed && !mixed && !(grantSnake && grantCamel)) {
      if (!(grantSnake && tokenSnake) && !(grantCamel && tokenCamel))
        return error(400, "MISSING_GRANT_TYPE");
    }
    const pick = (snakeName, camelName, hasCamel) => {
      const list = fields.filter(([k]) => k === snakeName || (hasCamel && k === camelName));
      if (list.length === 0) return undefined;
      const snake = list.find(([k]) => k === snakeName)?.[1];
      const camel = list.find(([k]) => k === camelName)?.[1];
      if (snake !== undefined && camel !== undefined) {
        if (precedence === "refuse") return Symbol.for("duplicate");
        if (precedence === "camel") return camel;
        if (precedence === "last") return list.at(-1)[1];
        return snake;
      }
      return snake ?? camel;
    };
    const grant = pick("grant_type", "grantType", readsCamel);
    const token = pick("refresh_token", "refreshToken", readsCamel);
    if (grant === Symbol.for("duplicate") || token === Symbol.for("duplicate"))
      return error(400, "Invalid JSON payload received. Duplicate field.");
    if (grant === undefined) return error(400, "MISSING_GRANT_TYPE");
    if (grant !== "refresh_token") return error(400, "INVALID_GRANT_TYPE");
    if (token === undefined || token === "") return error(400, "MISSING_REFRESH_TOKEN");
    const account = world.tokens.get(token);
    if (!account || account.deleted) return error(400, "INVALID_REFRESH_TOKEN");
    const idToken = jwt(account);
    return {
      status: 200,
      json: {
        access_token: idToken,
        expires_in: "3600",
        token_type: "Bearer",
        refresh_token: token,
        id_token: idToken,
        user_id: account.localId,
        project_id: number,
      },
    };
  }

  const tenantOf = (path) => /\/tenants\/([^/:]+)/.exec(path)?.[1];

  function handle({ method, path, query, body, contentType, authorized }) {
    if (path === "v1/token") {
      if (query.key !== world.apiKey)
        return error(400, "API key not valid. Please pass a valid API key.");
      return refresh(contentType, body);
    }
    if (path === "v1/accounts:signInWithPassword") {
      if (query.key !== world.apiKey) return error(400, "API key not valid.");
      const payload = JSON.parse(body);
      if (!payload.email || !payload.password) return error(400, "MISSING_EMAIL");
      const account = [...world.accounts.values()].find(
        (a) =>
          a.email === payload.email &&
          a.password === payload.password &&
          (a.tenantId ?? undefined) === payload.tenantId,
      );
      if (!account) return error(400, "INVALID_LOGIN_CREDENTIALS");
      return {
        status: 200,
        json: {
          kind: "identitytoolkit#VerifyPasswordResponse",
          localId: account.localId,
          email: account.email,
          idToken: jwt(account),
          refreshToken: issueToken(account),
          expiresIn: "3600",
        },
      };
    }
    if (!authorized) return error(401, "Request had invalid authentication credentials.");
    if (path === "admin/v2/projects/%P/config") {
      if (method === "GET")
        return {
          status: 200,
          json: {
            name: `projects/${number}/config`,
            signIn: { email: { enabled: true } },
            multiTenant: world.tenancy ? { allowTenants: true } : {},
          },
        };
      const patch = JSON.parse(body);
      if (query.updateMask !== "multiTenant.allowTenants") return error(400, "bad mask");
      world.tenancy = patch.multiTenant?.allowTenants === true;
      return { status: 200, json: { name: `projects/${number}/config` } };
    }
    if (path === "v2/projects/%P/tenants" && method === "GET") {
      if (!world.tenancy) return error(400, "MULTI_TENANCY_REQUIRED");
      return {
        status: 200,
        json: world.tenants.size
          ? {
              tenants: [...world.tenants.values()].map((t) => ({
                name: t.name,
                displayName: t.displayName,
              })),
            }
          : {},
      };
    }
    if (path === "v2/projects/%P/tenants" && method === "POST") {
      if (!world.tenancy) return error(400, "MULTI_TENANCY_REQUIRED");
      const payload = JSON.parse(body);
      if (!/^[A-Za-z][A-Za-z0-9-]{3,19}$/.test(payload.displayName ?? ""))
        return error(
          400,
          "INVALID_DISPLAY_NAME : display_name should start with a letter and only consist of letters, digits and hyphens with 4-20 characters.",
        );
      const id = `${payload.displayName}-${randomBytes(3).toString("hex")}`;
      const tenant = {
        name: `projects/${number}/tenants/${id}`,
        displayName: payload.displayName,
        id,
      };
      world.tenants.set(id, tenant);
      return {
        status: 200,
        json: {
          name: tenant.name,
          displayName: tenant.displayName,
          allowPasswordSignup: true,
          inheritance: {},
        },
      };
    }
    const tenantMatch = /^v2\/projects\/%P\/tenants\/([^/]+)$/.exec(path);
    if (tenantMatch) {
      const tenant = world.tenants.get(tenantMatch[1]);
      if (!tenant) return error(404, "TENANT_NOT_FOUND", { status: "NOT_FOUND" });
      if (method === "DELETE") {
        world.tenants.delete(tenant.id);
        for (const [id, a] of world.accounts)
          if (a.tenantId === tenant.id) world.accounts.delete(id);
        return { status: 200, json: {} };
      }
      return { status: 200, json: { name: tenant.name, displayName: tenant.displayName } };
    }
    const accountMatch =
      /^v1\/projects\/%P(\/tenants\/[^/]+)?\/accounts(:(lookup|delete|query))?$/.exec(path);
    if (accountMatch) {
      const tenantId = tenantOf(path);
      if (tenantId !== undefined && !world.tenants.has(tenantId))
        return error(400, "INVALID_TENANT_ID");
      const action = accountMatch[3];
      const payload = body ? JSON.parse(body) : {};
      const mine = () => [...world.accounts.values()].filter((a) => a.tenantId === tenantId);
      if (action === "query") return { status: 200, json: { recordsCount: String(mine().length) } };
      if (action === "lookup") {
        const found = mine().filter((a) => (payload.localId ?? []).includes(a.localId));
        return {
          status: 200,
          json: found.length
            ? {
                kind: "identitytoolkit#GetAccountInfoResponse",
                users: found.map((a) => ({ localId: a.localId, email: a.email })),
              }
            : { kind: "identitytoolkit#GetAccountInfoResponse" },
        };
      }
      if (action === "delete") {
        if (!payload.localId) return error(400, "MISSING_LOCAL_ID");
        const account = mine().find((a) => a.localId === payload.localId);
        if (!account) return error(400, "USER_NOT_FOUND");
        world.accounts.delete(account.localId);
        account.deleted = true; // its refresh tokens stop working
        return { status: 200, json: { kind: "identitytoolkit#DeleteAccountResponse" } };
      }
      if (!payload.localId || !payload.email || !payload.password)
        return error(400, "MISSING_LOCAL_ID");
      if (world.accounts.has(payload.localId)) return error(400, "DUPLICATE_LOCAL_ID");
      world.accounts.set(payload.localId, { ...payload, tenantId });
      return {
        status: 200,
        json: { kind: "identitytoolkit#SetAccountInfoResponse", localId: payload.localId },
      };
    }
    return error(404, `no route ${method} ${path}`);
  }

  /** A `fetch` look-alike. */
  async function fetchImpl(url, init) {
    const parsed = new URL(url);
    let path = parsed.pathname
      .replace(/^\/(identitytoolkit|securetoken)\.googleapis\.com\//, "")
      .replace(/^\//, "");
    path = path.replace(`projects/${project}`, "projects/%P");
    const req = {
      method: init.method ?? "GET",
      path,
      query: Object.fromEntries(parsed.searchParams),
      body: init.body,
      contentType: init.headers?.["content-type"] ?? "",
      authorized: (init.headers?.authorization ?? "").startsWith("Bearer "),
    };
    world.log.push({
      method: req.method,
      path: req.path,
      contentType: req.contentType,
      body: req.body,
    });
    for (const fault of faults) {
      const injected = fault(req, world);
      if (injected === "throw")
        throw Object.assign(new Error("fetch failed"), { cause: { code: "ECONNRESET" } });
      if (injected) return reply(injected);
    }
    const handled = handle(req);
    for (const fault of lateFaults) {
      const injected = fault(req, handled);
      if (injected === "throw")
        throw Object.assign(new Error("fetch failed"), { cause: { code: "ETIMEDOUT" } });
      if (injected) return reply(injected);
    }
    return reply(handled);
  }
  const reply = ({ status, json, text }) => ({
    status,
    text: async () => text ?? JSON.stringify(json ?? {}),
  });

  return { world, fetch: fetchImpl };
}
