// A fake of the parts of production the FS-3 recorder talks to, for the tests: the Firebase Rules
// API, Firestore (REST and gRPC), Identity Toolkit sign-up, delete and query, and a Listen stream.
//
// It refuses what production refuses: a write call that misses a required field answers 400, a
// release of a missing ruleset 400, a delete of a ruleset a release still uses 400, and a read or
// write is allowed only when the ruleset in force allows it. Each call is logged with its method
// and URL so a test can check what was addressed. `scenario` picks the facts under test:
//   v1Group      "allow" | "deny"  a collection-group read under the v1 recursive rule
//   pathV1       "compiles" | "refused"
//   unreadable   a function (method, url, n) returning an answer to use instead
// The facts are the test's choice, not claims about production.

import { SANDBOX_PROJECT } from "../fs-rules/harness.mjs";

const PROJECT = SANDBOX_PROJECT;

const json = (status, body) => ({
  status,
  text: async () => JSON.stringify(body),
  json: async () => body,
});

export function createWorld(scenario = {}) {
  const world = {
    log: [],
    rulesets: new Map(),
    releases: new Map(),
    accounts: new Map(),
    documents: new Map(),
    counter: 0,
    /** The number of writes in each commit, in order. */
    commits: [],
    /** Every marker write: its label and whether the ruleset in force allowed it. */
    markerAnswers: [],
    scenario: { v1Group: "allow", pathV1: "refused", ...scenario },
    /** Set by a test to run code before an answer is built. */
    onCall: undefined,
  };

  const active = () => {
    const name = world.releases.get("cloud.firestore");
    return name ? world.rulesets.get(name) : undefined;
  };
  const kind = (source) => ({
    v2: source.startsWith("rules_version = '2';"),
    recursive: source.includes("match /{document=**}"),
    path: source.includes("match /{path=**}/posts/{d}"),
  });

  /** `pathV1: "release-refused"`: the v1 path form compiles, but a release of it is refused. */
  const releaseRefused = (rulesetName) => {
    const source = world.rulesets.get(rulesetName) ?? "";
    const { path: isPath, v2 } = kind(source);
    return world.scenario.pathV1 === "release-refused" && isPath && !v2;
  };

  /** Whether the ruleset in force allows a read of this shape for anyone. */
  function readAllowed(shape) {
    const source = active();
    if (!source) return false;
    const { v2, recursive, path } = kind(source);
    if (recursive) {
      if (!shape.group && !shape.kindless) return true;
      return v2 || world.scenario.v1Group === "allow";
    }
    if (path) return v2 && shape.group;
    return false;
  }

  const shapeOfQuery = (query) => {
    const from = query?.from?.[0] ?? {};
    return {
      group: from.allDescendants === true && Boolean(from.collectionId),
      kindless: from.allDescendants === true && !from.collectionId,
      collectionId: from.collectionId,
    };
  };

  const visible = (shape, parent) =>
    [...world.documents.keys()]
      .filter((path) => {
        const segments = path.split("/");
        if (shape.group) return segments.at(-2) === shape.collectionId;
        if (shape.kindless) return parent === "" || path.startsWith(`${parent}/`);
        const prefix = parent ? `${parent}/` : "";
        return (
          path.startsWith(prefix) &&
          segments.length === prefix.split("/").length - 1 + 2 &&
          segments.at(-2) === shape.collectionId
        );
      })
      .toSorted();

  const names = (path) => `projects/${PROJECT}/databases/(default)/documents/${path}`;
  const relative = (full) => full.split("/documents/")[1] ?? "";

  function markerAllowed(path) {
    const source = active();
    if (!source) return false;
    const label = path.split("/")[1];
    return source.includes(`label == '${label}'`);
  }

  /** The decision for a Firestore request, shared by the REST and gRPC fakes. */
  function firestore({ op, path, body, owner }) {
    const rel = path.replace(/^projects\/[^/]+\/databases\/\(default\)\/documents\/?/, "");
    if (op === "commit") {
      if (!Array.isArray(body?.writes)) return { code: 3, status: 400 };
      world.commits.push(body.writes.length);
      for (const write of body.writes) {
        if (write.update)
          world.documents.set(relative(write.update.name), write.update.fields ?? {});
        else if (write.delete) world.documents.delete(relative(write.delete));
      }
      return { code: 0, status: 200, body: { writeResults: body.writes.map(() => ({})) } };
    }
    if (op === "patch") {
      const allowed = owner || markerAllowed(rel);
      if (rel.startsWith("fsr-marker/"))
        world.markerAnswers.push({ label: rel.split("/")[1], allowed });
      if (!allowed) return { code: 7, status: 403 };
      world.documents.set(rel, body?.fields ?? {});
      return { code: 0, status: 200, body: { name: names(rel) } };
    }
    if (op === "get") {
      if (!owner && !readAllowed({})) return { code: 7, status: 403 };
      return world.documents.has(rel)
        ? { code: 0, status: 200, body: { name: names(rel) } }
        : { code: 5, status: 404 };
    }
    const query = body?.structuredQuery ?? body?.structuredAggregationQuery?.structuredQuery;
    if (!query) return { code: 3, status: 400 };
    if (op === "runAggregationQuery" && !body.structuredAggregationQuery?.aggregations?.length)
      return { code: 3, status: 400 };
    const shape = shapeOfQuery(query);
    if (!owner && !readAllowed(shape)) return { code: 7, status: 403 };
    const parent = rel.replace(/:.*$/, "");
    const matches = visible(shape, parent);
    if (op === "runAggregationQuery") {
      return {
        code: 0,
        status: 200,
        body: [{ result: { aggregateFields: { n: { integerValue: String(matches.length) } } } }],
      };
    }
    const limited = query.limit ? matches.slice(0, query.limit?.value ?? query.limit) : matches;
    return {
      code: 0,
      status: 200,
      body: limited.length
        ? limited.map((p) => ({
            document: { name: names(p), fields: world.documents.get(p) ?? {} },
          }))
        : [{}],
    };
  }

  async function fetchImpl(url, init = {}) {
    const method = init.method ?? "GET";
    const parsed = new URL(url);
    world.log.push({
      method,
      url,
      host: parsed.host,
      path: decodeURIComponent(parsed.pathname),
      headers: { ...init.headers },
      body: init.body ? JSON.parse(init.body) : undefined,
    });
    // A real network call takes a turn of the event loop and honours its timeout signal.
    await new Promise((resolve) => setImmediate(resolve));
    if (init.signal?.aborted) throw Object.assign(new Error("aborted"), { name: "TimeoutError" });
    // A test can replace the answer: `throw` (a transport failure with a cause code),
    // `rejectWith` (any error) or `status`. With `applyFirst` the call takes effect in the world
    // first, as a call whose answer was lost would.
    const override = world.onCall?.(method, url, world.log.length, world);
    if (override) {
      if (override.applyFirst) await handle(method, parsed, init);
      if (override.rejectWith) throw override.rejectWith;
      if (override.throw)
        throw Object.assign(new Error("fetch failed"), { cause: { code: override.throw } });
      return json(override.status, override.body ?? {});
    }
    return handle(method, parsed, init);
  }

  /** What production does before routing: JSON bodies need a JSON content type and parse. */
  function refuse(init) {
    if (init.body === undefined) return undefined;
    if (!String(init.headers?.["content-type"] ?? "").startsWith("application/json"))
      return json(415, { error: { status: "UNSUPPORTED_MEDIA_TYPE" } });
    try {
      JSON.parse(init.body);
    } catch {
      return json(400, { error: { status: "INVALID_ARGUMENT" } });
    }
    return undefined;
  }

  /** An owner call (user credentials) must name the sandbox as its quota project. */
  const ownerRefused = (init) =>
    init.headers?.["x-goog-user-project"] === PROJECT
      ? undefined
      : json(403, { error: { status: "PERMISSION_DENIED", message: "quota project" } });

  async function handle(method, parsed, init) {
    const refused = refuse(init);
    if (refused) return refused;
    const path = decodeURIComponent(parsed.pathname);
    const body = init.body ? JSON.parse(init.body) : undefined;
    const owner = String(init.headers?.authorization ?? "").startsWith("Bearer ya29.");
    if (owner && ownerRefused(init)) return ownerRefused(init);
    const mine = `/v1/projects/${PROJECT}`;

    if (parsed.host === "firebaserules.googleapis.com") {
      if (!owner) return json(401, {});
      if (method === "POST" && path === `${mine}/rulesets`) {
        const file = body?.source?.files?.[0];
        if (file?.name !== "firestore.rules" || typeof file?.content !== "string")
          return json(400, { error: { status: "INVALID_ARGUMENT", message: "missing source" } });
        const { path: isPath, v2 } = kind(file.content);
        if (isPath && !v2 && world.scenario.pathV1 === "refused")
          return json(400, {
            error: {
              status: "INVALID_ARGUMENT",
              message: `Compilation error in ${PROJECT}: line 6`,
            },
          });
        world.counter += 1;
        const name = `projects/${PROJECT}/rulesets/rs${world.counter}`;
        world.rulesets.set(name, file.content);
        return json(200, { name });
      }
      if (method === "GET" && path === `${mine}/rulesets`)
        return json(200, { rulesets: [...world.rulesets.keys()].map((name) => ({ name })) });
      if (method === "DELETE" && path.startsWith(`${mine}/rulesets/`)) {
        const name = path.slice(4);
        if (!world.rulesets.has(name)) return json(404, {});
        if ([...world.releases.values()].includes(name))
          return json(400, { error: { status: "FAILED_PRECONDITION" } });
        world.rulesets.delete(name);
        return json(200, {});
      }
      if (path === `${mine}/releases` && method === "GET")
        return json(200, {
          releases: [...world.releases.keys()].map((n) => ({
            name: `projects/${PROJECT}/releases/${n}`,
          })),
        });
      if (path === `${mine}/releases` && method === "POST") {
        if (typeof body?.name !== "string" || !world.rulesets.has(body?.rulesetName))
          return json(400, {});
        if (releaseRefused(body.rulesetName))
          return json(400, {
            error: { status: "INVALID_ARGUMENT", message: `release refused in ${PROJECT}` },
          });
        world.releases.set("cloud.firestore", body.rulesetName);
        return json(200, body);
      }
      if (path === `${mine}/releases/cloud.firestore`) {
        if (method === "GET")
          return world.releases.has("cloud.firestore")
            ? json(200, { name: path.slice(4), rulesetName: world.releases.get("cloud.firestore") })
            : json(404, {});
        if (method === "PATCH") {
          if (!world.releases.has("cloud.firestore")) return json(404, {});
          if (!world.rulesets.has(body?.release?.rulesetName)) return json(400, {});
          if (releaseRefused(body.release.rulesetName))
            return json(400, {
              error: { status: "INVALID_ARGUMENT", message: `release refused in ${PROJECT}` },
            });
          world.releases.set("cloud.firestore", body.release.rulesetName);
          return json(200, body.release);
        }
        if (method === "DELETE") {
          if (!world.releases.delete("cloud.firestore")) return json(404, {});
          return json(200, {});
        }
      }
    }

    if (parsed.host === "identitytoolkit.googleapis.com") {
      if (method === "POST" && path === "/v1/accounts:signUp") {
        if (
          parsed.searchParams.get("key") !==
          (world.scenario.apiKey ?? parsed.searchParams.get("key"))
        )
          return json(400, { error: { message: "API key not valid" } });
        if (!parsed.searchParams.get("key") || body?.returnSecureToken !== true)
          return json(400, { error: { message: "INVALID_REQUEST" } });
        world.counter += 1;
        const localId = `uid${world.counter}`;
        world.accounts.set(localId, {});
        return json(200, { localId, idToken: `eyJ.token-${localId}.sig`, refreshToken: "refresh" });
      }
      if (!owner) return json(401, {});
      if (path === `${mine}/accounts:delete`) {
        if (!world.accounts.delete(body?.localId))
          return json(400, { error: { message: "USER_NOT_FOUND" } });
        return json(200, {});
      }
      if (path === `${mine}/accounts:query`)
        return json(200, { recordsCount: String(world.accounts.size) });
      if (path === `/admin/v2/projects/${PROJECT}/config`)
        return json(200, { signIn: { anonymous: { enabled: true } } });
    }

    if (parsed.host === "firestore.googleapis.com") {
      if (path === `${mine}/databases`)
        return json(200, {
          databases: ["(default)", ...(world.scenario.extraDatabases ?? [])].map((id) => ({
            name: `projects/${PROJECT}/databases/${id}`,
          })),
        });
      const match =
        /^\/v1\/(projects\/[^/]+\/databases\/\(default\)\/documents.*?)(?::(\w+))?$/.exec(path);
      if (!match) return json(404, {});
      const rpc = match[2];
      if (rpc && method !== "POST") return json(405, { error: { status: "METHOD_NOT_ALLOWED" } });
      const op = rpc ?? { GET: "get", PATCH: "patch" }[method];
      const answer = firestore({ op, path: match[1], body, owner });
      if (answer.status !== 200)
        return json(answer.status, {
          error: { code: answer.status, status: answer.code === 7 ? "PERMISSION_DENIED" : "ERROR" },
        });
      return json(200, answer.body ?? {});
    }
    return json(404, {});
  }

  /** The gRPC adapter fake: same decisions as REST, plus scripted Listen frames. */
  const grpc = {
    calls: [],
    listens: [],
    async call(built, bearer) {
      grpc.calls.push({ method: built.method, request: built.request, bearer });
      const owner = false;
      const rel = built.request.name ?? built.request.document?.name ?? built.request.parent ?? "";
      const op = {
        GetDocument: "get",
        UpdateDocument: "patch",
        RunQuery: "runQuery",
        RunAggregationQuery: "runAggregationQuery",
      }[built.method];
      const body =
        built.method === "UpdateDocument"
          ? { fields: built.request.document?.fields }
          : {
              structuredQuery: built.request.structuredQuery,
              structuredAggregationQuery: built.request.structuredAggregationQuery,
            };
      const answer = firestore({ op, path: rel, body, owner });
      if (answer.code !== 0)
        return { code: answer.code, details: "Missing or insufficient permissions.", messages: [] };
      const messages = Array.isArray(answer.body) ? answer.body : [answer.body];
      return { code: 0, details: "", messages };
    },
    listen({ parent, structuredQuery }) {
      const shape = shapeOfQuery(structuredQuery);
      const allowed = readAllowed(shape);
      const rel = (parent.split("/documents")[1] ?? "").replace(/^\//, "");
      const documents = allowed ? visible(shape, rel) : [];
      const frames = allowed
        ? [
            {
              at: 1,
              kind: "targetChange",
              targetChange: { targetChangeType: "ADD", targetIds: [1], resumeToken: "AA==" },
            },
            ...documents.map((p) => ({
              at: 2,
              kind: "documentChange",
              documentChange: {
                document: { name: names(p), fields: world.documents.get(p) ?? {} },
                targetIds: [1],
              },
            })),
            {
              at: 3,
              kind: "targetChange",
              targetChange: {
                targetChangeType: "CURRENT",
                targetIds: [1],
                resumeToken: "AQ==",
                readTime: "2026-01-01T00:00:00Z",
              },
            },
          ]
        : [
            {
              at: 1,
              kind: "targetChange",
              targetChange: {
                targetChangeType: "REMOVE",
                targetIds: [1],
                cause: { code: 7, message: `Missing or insufficient permissions in ${PROJECT}` },
              },
            },
          ];
      const stream = {
        frames,
        end: undefined,
        ended: () => stream.end,
        close: async () => {
          stream.end ??= { reason: "closed-by-harness", at: 0 };
        },
      };
      grpc.listens.push({ shape, allowed });
      return stream;
    },
    close: async () => {
      await new Promise((resolve) => setImmediate(resolve));
      grpc.closed = true;
    },
    closed: false,
  };

  return { world, fetchImpl, grpc };
}

/** A virtual clock: sleeping advances it, so settle and listen waits cost no time. */
export function createClock(start = 1_000_000) {
  const clock = { t: start };
  return {
    now: () => clock.t,
    // A wait takes a turn of the event loop, as a real one does, so a wait that is not awaited
    // does not advance the clock in time.
    sleep: async (ms) => {
      await new Promise((resolve) => setImmediate(resolve));
      clock.t += ms;
    },
    advance: (ms) => {
      clock.t += ms;
    },
  };
}
