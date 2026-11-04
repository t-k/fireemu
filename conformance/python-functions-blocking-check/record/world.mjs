// Test support for the blocking check: an in-memory Firebase project API, Service Usage, Identity Platform (configuration and
// accounts), Cloud Functions, Cloud Run, Artifact Registry, Cloud Storage and Cloud Logging that answer in the documented shapes
// and enforce the documented required fields of each request the check sends, plus a fake Firebase CLI that creates and
// deletes what a real deploy creates (and registers and removes the blocking trigger in the configuration). A virtual
// clock advances only when the recorder sleeps. Not part of the packet; it sends nothing.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { frameOrigin, parseFramesFromText } from "./logs.mjs";
import {
  FRAME_MARK,
  FUNCTION,
  PROJECT,
  REGION,
  functionName,
  packageIds,
  sourceBuckets,
} from "./plan.mjs";
import { emailOf, passwordOf } from "./script.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const NUMBER = "123456789012";
export const START = Date.parse("2026-11-05T00:00:30Z");
export const SERVICE_ACCOUNT = NUMBER + "-compute@developer.gserviceaccount.com";
export const SERVICE_URI = "https://" + FUNCTION + "-abc-uc.a.run.app";
export const LOCAL_ID = "Wd3kJ9xQ2mP7sT4vB8nL5cZ6yH1a";
export const pretty = (json) => JSON.stringify(json, null, 2) + "\n";
export const reply = (status, json) =>
  new Response(pretty(json), { status, headers: { "content-type": "application/json" } });
const notFound = (what) =>
  reply(404, { error: { code: 404, message: what + " not found", status: "NOT_FOUND" } });
const gcsNotFound = (what) =>
  reply(404, {
    error: {
      code: 404,
      message: "No such object: " + what,
      errors: [{ message: "No such object: " + what, domain: "global", reason: "notFound" }],
    },
  });
const badRequest = (message) =>
  reply(400, { error: { code: 400, message, status: "INVALID_ARGUMENT" } });
const iso = (ms) => new Date(ms).toISOString();
const GOLDEN = parseFramesFromText(
  readFileSync(join(here, "../local/golden-frames.txt"), "utf8"),
).frames.map((f) => f.frame);

/** The dry run's frames reshaped to what the check expects of production, so a clean run judges all-as-expected. */
function productionShaped(frame, { runId, localId }) {
  const text = JSON.stringify(frame).replaceAll("RUNID", runId).replaceAll("LOCALID", localId);
  const f = JSON.parse(text);
  if (f.kind === "blocking-raw") {
    f.request.headers["user-agent"] = "Google-Cloud-Identity-Toolkit";
    f.request.token.header = {
      alg: "RS256",
      typ: "JWT",
      has_kid: true,
      names: ["alg", "kid", "typ"],
    };
    f.request.token.claims.iss = "https://securetoken.google.com/" + PROJECT;
    f.request.token.claims.aud = SERVICE_URI;
    f.request.token.claims.event_type =
      "providers/cloud.auth/eventTypes/user.beforeCreate:password";
  }
  if (f.kind === "blocking-sdk")
    f.event_type = "providers/cloud.auth/eventTypes/user.beforeCreate:password";
  return f;
}
export const productionFrames = (options) =>
  GOLDEN.map((frame) => productionShaped(frame, options));

const REQUIRED = [
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "firebaseextensions.googleapis.com",
  "identitytoolkit.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
];

/**
 * `hooks` maps "METHOD host/path" to a function returning a Response, "throw", or nothing. `leaveOnDelete` makes the fake CLI's
 * delete leave the function behind; `leaveTrigger` makes it leave the trigger registered. `failDeploy` makes the deploy exit 1
 * without creating anything. `uploadLines` is "normal", "none" (no receipt in the CLI log), "refused" (the upload PUT answered 403)
 * or "extra" (a second receipt for an object nobody made). `silent` suppresses the frames. `preexistingAccounts` is the number of accounts the project already has.
 */
export function createWorld({
  runId = "0123456789abcdef",
  hooks = {},
  leaveOnDelete = false,
  leaveTrigger = false,
  failDeploy = false,
  silent = false,
  deployState = "ACTIVE",
  listPageSize = 0,
  logPageSize = 0,
  preexistingAccounts = 3,
  withSourceBuckets = true,
  baselineBlocking = undefined,
  publicInvoker = true,
  uploadLines = "normal",
  deleteLeaves = undefined,
  sourcePageSize = 0,
} = {}) {
  const w = {
    runId,
    now: START,
    calls: [],
    functions: new Map(),
    runServices: new Set(),
    packages: new Set(),
    accounts: new Map(
      Array.from({ length: preexistingAccounts }, (_, n) => ["old" + n, { localId: "old" + n }]),
    ),
    config: {
      name: `projects/${NUMBER}/config`,
      signIn: { email: { enabled: true, passwordRequired: true } },
      mfa: { state: "DISABLED" },
      ...(baselineBlocking === undefined ? {} : { blockingFunctions: baselineBlocking }),
    },
    entries: [],
    cliRuns: [],
    signUps: 0,
    insert: 0,
    generations: new Map(),
    upload: null,
    policy: null,
    sourceBuckets: withSourceBuckets
      ? new Map(
          sourceBuckets(NUMBER).map((name) => [
            name,
            name.startsWith("gcf-v2-uploads") ? ["old-upload.zip"] : [],
          ]),
        )
      : new Map(),
    repository: true,
    services: new Set([...REQUIRED, "firebase.googleapis.com"]),
  };
  const log = (entry) => w.entries.push({ insertId: "w" + ++w.insert, ...entry });
  w.advance = (ms) => {
    w.now += ms;
  };

  const createDeployed = () => {
    const name = functionName();
    w.functions.set(name, {
      name,
      state: deployState,
      environment: "GEN_2",
      serviceConfig: { uri: SERVICE_URI, serviceAccountEmail: SERVICE_ACCOUNT },
    });
    w.runServices.add(FUNCTION);
    for (const id of packageIds()) w.packages.add(id);
    w.config.blockingFunctions = {
      triggers: { beforeCreate: { functionUri: SERVICE_URI, updateTime: iso(w.now) } },
    };
    for (const [bucket, items] of w.sourceBuckets) {
      if (bucket.startsWith("gcf-v2-uploads")) {
        w.upload =
          "514cacbe-3258-46fd-9a02-54b7485b" + String(++w.insert).padStart(4, "0") + ".zip";
        if (uploadLines !== "refused") {
          items.push(w.upload);
          w.generations.set(bucket + "/" + w.upload, String(1760000000000000 + w.insert));
        }
      } else items.push(FUNCTION + "/function-source.zip");
    }
    w.policy = {
      version: 1,
      etag: "etag-1",
      bindings: publicInvoker ? [{ role: "roles/run.invoker", members: ["allUsers"] }] : [],
    };
  };
  const deleteDeployed = () => {
    if (!leaveOnDelete) {
      w.functions.delete(functionName());
      w.runServices.delete(FUNCTION);
      w.policy = null;
    }
    if (!leaveTrigger) {
      if (deleteLeaves !== undefined) w.config.blockingFunctions = structuredClone(deleteLeaves);
      else if (baselineBlocking === undefined) delete w.config.blockingFunctions;
      else w.config.blockingFunctions = structuredClone(baselineBlocking);
    }
  };

  /** The fake CLI: returns what `runCli` returns. */
  w.runCli = async ({ action }) => {
    w.cliRuns.push(action);
    if (action === "deploy") {
      if (failDeploy)
        return {
          action,
          exitCode: 1,
          timedOut: false,
          error: null,
          errored: 1,
          uploadEvents: [],
          durationMs: 1,
        };
      createDeployed();
      w.advance(110_000);
    } else if (action === "delete") {
      deleteDeployed();
      w.advance(30_000);
    }
    const bucket = sourceBuckets(NUMBER)[0];
    const uploadEvents =
      action === "deploy" && uploadLines !== "none" && w.upload
        ? [
            { type: "receipt", bucket, object: w.upload },
            {
              type: "put-status",
              bucket,
              object: w.upload,
              status: uploadLines === "refused" ? 403 : 200,
            },
            ...(uploadLines === "extra"
              ? [{ type: "receipt", bucket, object: "99999999-0000-0000-0000-000000000000.zip" }]
              : []),
          ]
        : action === "deploy"
          ? []
          : undefined;
    return {
      action,
      exitCode: 0,
      signal: null,
      timedOut: false,
      error: null,
      errored: 0,
      unknownWrites: [],
      ...(uploadEvents ? { uploadEvents } : {}),
      durationMs: 1,
    };
  };

  const page = (items, key, url) => {
    if (!listPageSize || !url) return reply(200, items.length ? { [key]: items } : {});
    const start = Number(url.searchParams.get("pageToken") ?? 0);
    const slice = items.slice(start, start + listPageSize);
    return reply(200, {
      ...(slice.length ? { [key]: slice } : {}),
      ...(start + listPageSize < items.length
        ? { nextPageToken: String(start + listPageSize) }
        : {}),
    });
  };

  w.send = async (request) => {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    const key = method + " " + url.hostname + path;
    w.calls.push(key);
    const body = request.body ? JSON.parse(request.body) : undefined;
    const hook = hooks[key] ?? hooks[method + " " + path];
    if (hook) {
      const out = await hook({ w, body, url, method });
      if (out === "throw") throw new Error("transport");
      if (out) return out;
    }
    const host = url.hostname;
    if (host === "firebase.googleapis.com")
      return reply(200, { projectId: PROJECT, projectNumber: NUMBER, state: "ACTIVE" });
    if (host === "serviceusage.googleapis.com")
      return reply(200, {
        services: [...w.services].toSorted().map((id) => ({
          name: "projects/" + NUMBER + "/services/" + id,
          config: { name: id },
          state: "ENABLED",
        })),
      });
    if (path.endsWith(":getIamPolicy") && host === "cloudresourcemanager.googleapis.com")
      return reply(200, { version: 1, etag: "e", bindings: [] });
    if (host === "identitytoolkit.googleapis.com") {
      if (method === "GET" && path === `/admin/v2/projects/${PROJECT}/config`)
        return reply(200, w.config);
      if (path === `/v1/projects/${PROJECT}/accounts:query`)
        return reply(200, { recordsCount: String(w.accounts.size) });
      if (path === "/v1/accounts:signUp") {
        if (
          body?.email !== emailOf(w.runId) ||
          body?.password !== passwordOf(w.runId) ||
          body?.returnSecureToken !== true
        )
          return badRequest("email, password and returnSecureToken are required");
        w.signUps++;
        w.accounts.set(LOCAL_ID, { localId: LOCAL_ID, email: body.email });
        if (w.config.blockingFunctions?.triggers?.beforeCreate && !silent) {
          for (const frame of productionFrames({ runId: w.runId, localId: LOCAL_ID })) {
            const o = frameOrigin(FUNCTION);
            log({
              timestamp: iso(w.now + 3000),
              logName: o.logNames[0],
              resource: { type: o.resourceType, labels: o.labels },
              textPayload: FRAME_MARK + " " + JSON.stringify(frame),
            });
          }
        }
        return reply(200, {
          kind: "identitytoolkit#SignupNewUserResponse",
          idToken: "x.y.z",
          email: body.email,
          refreshToken: "r",
          expiresIn: "3600",
          localId: LOCAL_ID,
        });
      }
      if (path === `/v1/projects/${PROJECT}/accounts:lookup`) {
        const ids = body?.localId;
        if (!Array.isArray(ids)) return badRequest("localId");
        const users = ids.filter((id) => w.accounts.has(id)).map((id) => w.accounts.get(id));
        return reply(
          200,
          users.length
            ? { kind: "identitytoolkit#GetAccountInfoResponse", users }
            : { kind: "identitytoolkit#GetAccountInfoResponse" },
        );
      }
      if (path === `/v1/projects/${PROJECT}/accounts:delete`) {
        if (typeof body?.localId !== "string") return badRequest("localId");
        if (!w.accounts.delete(body.localId))
          return reply(400, {
            error: { code: 400, message: "USER_NOT_FOUND", status: "INVALID_ARGUMENT" },
          });
        return reply(200, { kind: "identitytoolkit#DeleteAccountResponse" });
      }
    }
    if (host === "cloudfunctions.googleapis.com") {
      if (path.includes("/operations/"))
        return reply(200, { name: path.split("/").slice(-1)[0], done: true });
      if (path.endsWith("/functions")) return page([...w.functions.values()], "functions", url);
      const name = path.slice(path.indexOf("/projects/") + 1);
      if (method === "GET")
        return w.functions.has(name) ? reply(200, w.functions.get(name)) : notFound(name);
      if (method === "DELETE") {
        if (!w.functions.has(name)) return notFound(name);
        w.functions.delete(name);
        w.runServices.delete(FUNCTION);
        return reply(200, {
          name: "projects/" + PROJECT + "/locations/" + REGION + "/operations/del-" + ++w.insert,
          done: false,
        });
      }
    }
    if (host === "cloudbuild.googleapis.com") return notFound("build");
    if (host === "run.googleapis.com") {
      if (path.endsWith("/services"))
        return page(
          [...w.runServices].map((id) => ({
            name: "projects/" + PROJECT + "/locations/" + REGION + "/services/" + id,
          })),
          "services",
          url,
        );
      if (path.endsWith(":getIamPolicy"))
        return w.runServices.has(FUNCTION) && w.policy ? reply(200, w.policy) : notFound("service");
      if (path.endsWith(":setIamPolicy")) {
        if (!w.runServices.has(FUNCTION) || !w.policy) return notFound("service");
        const given = body?.policy;
        if (method !== "POST" || !given || Object.keys(body).length !== 1)
          return reply(400, {
            error: { code: 400, status: "INVALID_ARGUMENT", message: "policy" },
          });
        if (given.etag !== w.policy.etag)
          return reply(409, { error: { code: 409, status: "ABORTED", message: "etag mismatch" } });
        w.policy = { version: 1, etag: given.etag + "+", bindings: given.bindings ?? [] };
        return reply(200, w.policy);
      }
    }
    if (host === "artifactregistry.googleapis.com") {
      if (path.includes("/operations/")) return reply(200, { name: path, done: true });
      const base = "projects/" + PROJECT + "/locations/" + REGION + "/repositories/gcf-artifacts";
      if (path.endsWith("/gcf-artifacts"))
        return w.repository ? reply(200, { name: base, format: "DOCKER" }) : notFound("repository");
      if (path.endsWith("/packages"))
        return page(
          [...w.packages].map((id) => ({ name: base + "/packages/" + id })),
          "packages",
          url,
        );
      const id = path.slice(path.indexOf("/packages/") + "/packages/".length);
      if (method === "GET")
        return w.packages.has(id)
          ? reply(200, { name: base + "/packages/" + id })
          : notFound("package");
      if (method === "DELETE") {
        if (!w.packages.delete(id)) return notFound("package");
        return reply(200, {
          name: "projects/" + PROJECT + "/locations/" + REGION + "/operations/pk-" + ++w.insert,
          done: true,
        });
      }
    }
    if (host === "storage.googleapis.com") {
      const object = /^\/storage\/v1\/b\/([^/]+)\/o\/([^/]+)$/.exec(path);
      if (object) {
        const held = w.sourceBuckets.get(object[1]);
        const name = decodeURIComponent(object[2]);
        if (!held || !held.includes(name)) return gcsNotFound(name);
        const generation = w.generations.get(object[1] + "/" + name) ?? "1";
        if (method === "GET") return reply(200, { name, bucket: object[1], generation });
        if (method === "DELETE") {
          const wanted = url.searchParams.get("ifGenerationMatch");
          if (wanted !== null && wanted !== generation)
            return reply(412, {
              error: {
                code: 412,
                message: "Precondition Failed",
                errors: [{ domain: "global", reason: "conditionNotMet" }],
              },
            });
          held.splice(held.indexOf(name), 1);
          return new Response(null, { status: 204 });
        }
      }
      const bucket = /^\/storage\/v1\/b\/([^/]+)\/o$/.exec(path)?.[1];
      const items = bucket ? w.sourceBuckets.get(bucket) : null;
      if (!items) return gcsNotFound(bucket ?? path);
      const start = Number(url.searchParams.get("pageToken") ?? 0);
      const slice = sourcePageSize ? items.slice(start, start + sourcePageSize) : items;
      return reply(200, {
        ...(slice.length ? { items: slice.map((name) => ({ name })) } : {}),
        ...(sourcePageSize && start + sourcePageSize < items.length
          ? { nextPageToken: String(start + sourcePageSize) }
          : {}),
      });
    }
    if (host === "logging.googleapis.com") {
      const filter = body.filter;
      const from = /timestamp>="([^"]+)"/.exec(filter)?.[1];
      const to = /timestamp<="([^"]+)"/.exec(filter)?.[1];
      const wantErrors = filter.includes("severity>=ERROR");
      const hits = w.entries.filter((e) => {
        const at = Date.parse(e.timestamp);
        if (at < Date.parse(from) || at > Date.parse(to)) return false;
        return wantErrors
          ? e.severity === "ERROR"
          : typeof e.textPayload === "string" && e.textPayload.includes(FRAME_MARK);
      });
      const start = body.pageToken ? Number(body.pageToken) : 0;
      const size = logPageSize || body.pageSize;
      const slice = hits.slice(start, start + size);
      return reply(200, {
        ...(slice.length ? { entries: slice } : {}),
        ...(start + size < hits.length ? { nextPageToken: String(start + size) } : {}),
      });
    }
    throw new Error("world: unexpected " + key);
  };
  return w;
}
