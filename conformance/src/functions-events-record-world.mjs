// A small in-memory model of the production services the recorder talks to (Firestore, Storage, Auth,
// Pub/Sub, Logging, the Functions lists), driven by a virtual clock. It delivers events to the 22
// handlers the way the closure expects (including the cases that must stay silent), so the recorder
// can be run end to end in a test, offline, in milliseconds. It is a test double for the recorder's
// own logic, not a claim about production behaviour.

import { createHash } from "node:crypto";

import { HANDLERS, FRAME_MARKER, origin } from "./functions-events/record/logs.mjs";
import { REQUIRED_APIS } from "./functions-events/record/preflight.mjs";
import {
  CONTROL_BUCKET,
  PRIMARY_BUCKET,
  PRIMARY_COLLECTION,
  PROJECT,
  MARKER_COLLECTION,
} from "./functions-events/record/script.mjs";

export const NUMBER = "123456789012";
export const healthy = () => ({
  "preflight.project": {
    status: 200,
    json: { projectId: PROJECT, lifecycleState: "ACTIVE", projectNumber: NUMBER },
  },
  "preflight.services": {
    status: 200,
    json: { services: REQUIRED_APIS.map((name) => ({ config: { name } })) },
  },
  "preflight.firestore-database": { status: 200, json: { type: "FIRESTORE_NATIVE" } },
  "preflight.primary-bucket": { status: 200, json: { versioning: { enabled: false } } },
  "preflight.control-bucket": { status: 404, json: { error: { code: 404 } } },
  "preflight.topics": { status: 200, json: {} },
  "preflight.artifact-repository": {
    status: 200,
    json: { name: `projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts` },
  },
  "preflight.artifact-packages": { status: 404, json: {} },
  "preflight.iam": {
    status: 200,
    json: {
      bindings: [
        {
          role: "roles/eventarc.serviceAgent",
          members: [`serviceAccount:service-${NUMBER}@gcp-sa-eventarc.iam.gserviceaccount.com`],
        },
      ],
    },
  },
  "preflight.auth-config": { status: 200, json: { signIn: { email: { enabled: true } } } },
  "preflight.rules-release": {
    status: 200,
    json: { rulesetName: `projects/${PROJECT}/rulesets/abc-123` },
  },
  "preflight.rules-ruleset": {
    status: 200,
    json: {
      source: {
        files: [
          {
            content: `match /${PRIMARY_COLLECTION}/{id} { allow create: if request.auth != null; }`,
          },
        ],
      },
    },
  },
  "preflight.objects-fe-events": { status: 200, json: {} },
  "preflight.objects-other": { status: 200, json: {} },
  "preflight.collection-fe_events_primary": {
    status: 200,
    json: [{ readTime: "2026-10-04T00:00:00Z" }],
  },
  "preflight.collection-fe_events_control": {
    status: 200,
    json: [{ readTime: "2026-10-04T00:00:00Z" }],
  },
  "preflight.collection-fe_events_retry_markers": {
    status: 200,
    json: [{ readTime: "2026-10-04T00:00:00Z" }],
  },
  "preflight.api-key-project": { status: 200, json: { projectId: PROJECT } },
  "preflight.functions-v1": { status: 200, json: {} },
  "preflight.functions-v2": { status: 200, json: {} },
  "preflight.run-services": { status: 200, json: {} },
  "preflight.eventarc-triggers": { status: 200, json: {} },
});

const iso = (ms) => new Date(ms).toISOString().replace("Z", "000Z");
const json = (status, body) => ({
  status,
  arrayBuffer: async () => Buffer.from(body === undefined ? "" : JSON.stringify(body)),
});
const notFound = () => json(404, { error: { code: 404, status: "NOT_FOUND" } });
const handlerNames = (names) => HANDLERS.filter((h) => names.includes(h.name));

export function createWorld({ now, rulesAllow = true }) {
  const world = {
    docs: new Map(),
    objects: new Map(),
    buckets: new Map([[PRIMARY_BUCKET, { versioning: false }]]),
    users: new Map(),
    topics: new Set(),
    entries: [],
    deployed: false,
    rulesAllow,
    failures: [],
    requests: [],
    counter: 0,
    retryPending: [],
  };
  const next = () => (world.counter += 1);

  function emit(names, source, data, { delay = 2000 } = {}) {
    if (!world.deployed) return;
    for (const handler of handlerNames(names)) {
      const id = `ev-${next()}`;
      const when = now() + delay; // when the log line is written; the event itself happened when the source call committed
      const committed = now();
      const o = origin(handler);
      const event =
        handler.generation === 1
          ? {
              context: {
                eventId: id,
                timestamp: iso(committed),
                eventType: `${source}.event`,
                resource: { name: data.resource ?? "r" },
                params: {},
                authType: null,
                authId: null,
              },
              data: data.payload,
            }
          : {
              id,
              time: iso(committed),
              type: `google.cloud.${source}.event`,
              source: `//${source}`,
              subject: data.resource ?? null,
              specversion: "1.0",
              datacontenttype: "application/json",
              params: {},
              authType: null,
              authId: null,
              data: data.payload,
            };
      const frame = {
        handler: handler.name,
        generation: handler.generation,
        source: handler.source,
        event,
      };
      world.entries.push({
        logName: o.logName,
        resource: { type: o.resourceType, labels: o.labels },
        insertId: `ins-${next()}`,
        timestamp: iso(when),
        textPayload: `${FRAME_MARKER}${JSON.stringify(frame)}`,
        when,
      });
    }
  }

  const doc = (path, fields) => ({
    name: `projects/${PROJECT}/databases/(default)/documents/${path}`,
    fields,
    createTime: iso(now()),
    updateTime: iso(now()),
  });
  const snapshot = (path, fields) => ({
    exists: fields !== null,
    id: path.split("/").at(-1),
    path,
    data: fields,
    createTime: null,
    updateTime: null,
  });
  const FS = {
    create: [
      "fsCreatedV1",
      "fsCreatedV2",
      "fsWrittenV1",
      "fsWrittenV2",
      "fsWrittenWithAuthContextV2",
    ],
    update: [
      "fsUpdatedV1",
      "fsUpdatedV2",
      "fsWrittenV1",
      "fsWrittenV2",
      "fsWrittenWithAuthContextV2",
    ],
    delete: [
      "fsDeletedV1",
      "fsDeletedV2",
      "fsWrittenV1",
      "fsWrittenV2",
      "fsWrittenWithAuthContextV2",
    ],
  };
  const plain = (fields) =>
    Object.fromEntries(
      Object.entries(fields ?? {}).map(([k, v]) => [k, v.stringValue ?? v.integerValue]),
    );

  function firestoreEvent(kind, path, before, after) {
    const [collection] = path.split("/");
    if (collection !== PRIMARY_COLLECTION) return;
    const data = {
      resource: path,
      payload: {
        before: before === null ? null : snapshot(path, plain(before)),
        after: after === null ? null : snapshot(path, plain(after)),
      },
    };
    emit(FS[kind], "firestore", data);
    if (kind === "create" && after?.fixtureKind?.stringValue === "retry" && world.deployed) {
      const markerId = createHash("sha256").update(`retry-${path}`).digest("hex");
      world.docs.set(`${MARKER_COLLECTION}/${markerId}`, {
        documentPath: { stringValue: path },
        eventId: { stringValue: "x" },
      });
      emit(["fsRetryV2"], "firestore", {
        resource: path,
        payload: { after: snapshot(path, plain(after)), fixtureAttempt: "failed" },
      });
      emit(
        ["fsRetryV2"],
        "firestore",
        {
          resource: path,
          payload: { after: snapshot(path, plain(after)), fixtureAttempt: "succeeded" },
        },
        { delay: 12000 },
      );
    }
  }

  async function route(method, url, init) {
    const u = new URL(url);
    const body = init.body === undefined || init.body === null ? undefined : String(init.body);
    const parsed =
      body && (init.headers["content-type"] ?? "").includes("json") ? JSON.parse(body) : undefined;
    const path = decodeURIComponent(u.pathname);
    let m;
    if (u.hostname === "oauth2.googleapis.com")
      return json(200, { access_token: "synthetic-access-token", expires_in: 3600 });
    // ---- Firestore
    if (u.hostname === "firestore.googleapis.com") {
      if ((m = /^\/v1\/projects\/[^/]+\/databases\/\(default\)$/.exec(path)))
        return json(200, healthy()["preflight.firestore-database"].json);
      if (path.endsWith("/documents:runQuery")) {
        const filter = parsed.structuredQuery.where?.fieldFilter?.value?.stringValue;
        const collection = parsed.structuredQuery.from[0].collectionId;
        const hits = [...world.docs].filter(
          ([p, f]) =>
            p.startsWith(`${collection}/`) &&
            (filter === undefined || f.documentPath?.stringValue === filter),
        );
        return json(
          200,
          hits.length
            ? hits.map(([p, f]) => ({ document: doc(p, f) }))
            : [{ readTime: iso(now()) }],
        );
      }
      if ((m = /\/documents\/(fe_events_[a-z_]+)$/.exec(path)) && method === "POST") {
        const full = `${m[1]}/${u.searchParams.get("documentId")}`;
        if (init.headers.authorization === "Bearer synthetic-id-token" && !world.rulesAllow)
          return json(403, { error: { code: 403, status: "PERMISSION_DENIED" } });
        if (world.docs.has(full)) return json(409, { error: { code: 409 } });
        world.docs.set(full, parsed.fields);
        firestoreEvent("create", full, null, parsed.fields);
        return json(200, doc(full, parsed.fields));
      }
      if ((m = /\/documents\/(fe_events_[a-z_]+\/[^/]+)$/.exec(path))) {
        const full = m[1];
        const current = world.docs.get(full);
        if (method === "GET") return current ? json(200, doc(full, current)) : notFound();
        if (method === "DELETE") {
          if (current) {
            world.docs.delete(full);
            firestoreEvent("delete", full, current, null);
          }
          return json(200, {});
        }
        if (method === "PATCH") {
          if (u.searchParams.get("currentDocument.exists") === "true" && !current)
            return notFound();
          const mask = u.searchParams.getAll("updateMask.fieldPaths");
          const merged = mask.length
            ? { ...current, ...Object.fromEntries(mask.map((k) => [k, parsed.fields[k]])) }
            : parsed.fields;
          const changed = JSON.stringify(merged) !== JSON.stringify(current);
          world.docs.set(full, merged);
          if (changed) firestoreEvent("update", full, current, merged);
          return json(200, doc(full, merged));
        }
      }
    }
    // ---- Storage
    if (u.hostname === "storage.googleapis.com") {
      if (method === "GET" && path === "/storage/v1/b") {
        const prefix = u.searchParams.get("prefix") ?? "";
        const items = [...world.buckets.keys()]
          .filter((name) => name.startsWith(prefix))
          .map((name) => ({ name }));
        return json(200, items.length ? { items } : {});
      }
      if (method === "POST" && path === "/storage/v1/b") {
        world.buckets.set(parsed.name, { versioning: false });
        return json(200, { name: parsed.name });
      }
      if ((m = /^\/upload\/storage\/v1\/b\/([^/]+)\/o$/.exec(path)) && method === "POST") {
        const bucket = m[1];
        const name = u.searchParams.get("name");
        const hash = init.headers["x-goog-hash"];
        if (hash && hash !== `md5=${createHash("md5").update(body).digest("base64")}`)
          return json(400, { error: { code: 400 } });
        const key = `${bucket}/${name}`;
        const list = world.objects.get(key) ?? [];
        const live = list.find((g) => g.live);
        if (u.searchParams.get("ifGenerationMatch") === "0" && live)
          return json(412, { error: { code: 412 } });
        const gen = {
          generation: String(1700000000000000 + next()),
          metageneration: "1",
          live: true,
          body,
          metadata: {},
        };
        if (live) {
          live.live = false;
          if (world.buckets.get(bucket)?.versioning)
            emit(["storageArchivedV1", "storageArchivedV2"], "storage", {
              resource: key,
              payload: { bucket, name, generation: live.generation },
            });
          else list.splice(list.indexOf(live), 1);
        }
        list.push(gen);
        world.objects.set(key, list);
        if (bucket === PRIMARY_BUCKET)
          emit(["storageFinalizedV1", "storageFinalizedV2"], "storage", {
            resource: key,
            payload: { bucket, name, generation: gen.generation },
          });
        return json(200, {
          bucket,
          name,
          generation: gen.generation,
          metageneration: "1",
          contentType: "text/plain",
        });
      }
      if ((m = /^\/storage\/v1\/b\/([^/]+)\/o\/(.+)$/.exec(path))) {
        const [, bucket, name] = m;
        const key = `${bucket}/${name}`;
        const list = world.objects.get(key) ?? [];
        const live = list.find((g) => g.live);
        if (method === "GET")
          return live
            ? json(200, {
                bucket,
                name,
                generation: live.generation,
                metageneration: live.metageneration,
                contentType: "text/plain",
              })
            : notFound();
        if (method === "PATCH") {
          if (!live) return notFound();
          live.metadata = { ...live.metadata, ...parsed.metadata };
          live.metageneration = String(Number(live.metageneration) + 1);
          if (bucket === PRIMARY_BUCKET)
            emit(["storageMetadataUpdatedV1", "storageMetadataUpdatedV2"], "storage", {
              resource: key,
              payload: { bucket, name, generation: live.generation },
            });
          return json(200, {
            bucket,
            name,
            generation: live.generation,
            metageneration: live.metageneration,
          });
        }
        if (method === "DELETE") {
          const wanted = u.searchParams.get("generation");
          const target = wanted ? list.find((g) => g.generation === wanted) : live;
          if (!target) return notFound();
          list.splice(list.indexOf(target), 1);
          if (bucket === PRIMARY_BUCKET)
            emit(["storageDeletedV1", "storageDeletedV2"], "storage", {
              resource: key,
              payload: { bucket, name, generation: target.generation },
            });
          return { status: 204, arrayBuffer: async () => Buffer.alloc(0) };
        }
      }
      if ((m = /^\/storage\/v1\/b\/([^/]+)\/o$/.exec(path)) && method === "GET") {
        const items = [...world.objects]
          .filter(
            ([k]) =>
              k.startsWith(`${m[1]}/`) &&
              k.slice(m[1].length + 1).startsWith(u.searchParams.get("prefix") ?? ""),
          )
          .flatMap(([k, l]) =>
            l
              .filter((g) => g.live || u.searchParams.get("versions") === "true")
              .map((g) => ({ name: k.slice(m[1].length + 1), generation: g.generation })),
          );
        return json(200, items.length ? { items } : {});
      }
      if ((m = /^\/storage\/v1\/b\/([^/]+)$/.exec(path))) {
        const bucket = world.buckets.get(m[1]);
        if (method === "GET")
          return bucket ? json(200, { versioning: { enabled: bucket.versioning } }) : notFound();
        if (method === "PATCH") {
          if (!bucket) return notFound();
          bucket.versioning = parsed.versioning.enabled;
          return json(200, { versioning: { enabled: bucket.versioning } });
        }
        if (method === "DELETE") {
          if (m[1] !== CONTROL_BUCKET || !bucket) return notFound();
          world.buckets.delete(m[1]);
          return { status: 204, arrayBuffer: async () => Buffer.alloc(0) };
        }
      }
    }
    // ---- Auth
    if (u.hostname === "identitytoolkit.googleapis.com") {
      if (path === "/v1/projects" && method === "GET") return json(200, { projectId: PROJECT });
      if (path === "/v1/accounts:signUp") {
        const uid = `signup-${next()}`;
        world.users.set(uid, { email: parsed.email });
        emit(["authCreatedV1"], "auth", { resource: uid, payload: { uid, email: parsed.email } });
        return json(200, {
          idToken: "synthetic-id-token",
          refreshToken: "synthetic-refresh",
          localId: uid,
        });
      }
      if (path === "/v1/accounts:signInWithPassword") {
        const entry = [...world.users].find(([, v]) => v.email === parsed.email);
        return entry
          ? json(200, { idToken: "synthetic-id-token", localId: entry[0] })
          : json(400, { error: { code: 400 } });
      }
      if (path.endsWith("/accounts:lookup")) {
        const found = parsed.localId
          ? parsed.localId.filter((id) => world.users.has(id))
          : [...world.users]
              .filter(([, user]) => parsed.email.includes(user.email))
              .map(([id]) => id);
        return json(200, found.length ? { users: found.map((localId) => ({ localId })) } : {});
      }
      if (path.endsWith("/accounts:delete")) {
        world.users.delete(parsed.localId);
        emit(["authDeletedV1"], "auth", {
          resource: parsed.localId,
          payload: { uid: parsed.localId },
        });
        return json(200, {});
      }
      if (path.endsWith("/accounts:batchDelete")) {
        for (const id of parsed.localIds) world.users.delete(id);
        return json(200, {});
      }
      if (path.endsWith("/accounts") && method === "POST") {
        world.users.set(parsed.localId, { email: parsed.email });
        emit(["authCreatedV1"], "auth", {
          resource: parsed.localId,
          payload: { uid: parsed.localId, email: parsed.email },
        });
        return json(200, { localId: parsed.localId });
      }
      if (path.endsWith("/config")) return json(200, healthy()["preflight.auth-config"].json);
    }
    // ---- Pub/Sub
    if (u.hostname === "pubsub.googleapis.com") {
      if ((m = /\/topics\/([a-z-]+):publish$/.exec(path))) {
        const id = `msg-${next()}`;
        if (m[1] === "fe-events-primary")
          emit(["pubsubPublishedV1", "pubsubPublishedV2"], "pubsub", {
            resource: m[1],
            payload: { message: { ...parsed.messages[0], messageId: id } },
          });
        return json(200, { messageIds: [id] });
      }
      if ((m = /\/topics\/([a-z-]+)$/.exec(path))) {
        if (method === "PUT")
          return world.topics.has(m[1])
            ? json(409, {})
            : (world.topics.add(m[1]), json(200, { name: path.slice(4) }));
        if (method === "GET")
          return world.topics.has(m[1]) ? json(200, { name: m[1] }) : notFound();
        if (method === "DELETE") return world.topics.delete(m[1]) ? json(200, {}) : notFound();
      }
      if (path.endsWith("/topics"))
        return json(
          200,
          world.topics.size
            ? {
                topics: [...world.topics].map((t) => ({ name: `projects/${PROJECT}/topics/${t}` })),
              }
            : {},
        );
      if (path.endsWith("/subscriptions")) return json(200, {});
    }
    // ---- Logging, Functions, Run, Eventarc and the static reads
    if (u.hostname === "logging.googleapis.com") {
      const filter = parsed.filter;
      const start = Date.parse(/timestamp>="([^"]+)"/.exec(filter)[1].replace(/\d{3}Z$/, "Z"));
      const end = Date.parse(/timestamp<="([^"]+)"/.exec(filter)[1].replace(/\d{3}Z$/, "Z"));
      const entries = world.entries
        .filter((e) => e.when >= start && e.when <= end && e.when <= now())
        .map(({ when: _when, ...entry }) => entry);
      return json(200, entries.length ? { entries } : {});
    }
    const names = HANDLERS;
    if (u.hostname === "cloudfunctions.googleapis.com") {
      const gen = path.startsWith("/v1/") ? 1 : 2;
      const list = world.deployed
        ? names
            .filter((h) => h.generation === gen)
            .map((h) =>
              gen === 1
                ? {
                    name: `projects/${PROJECT}/locations/us-central1/functions/${h.name}`,
                    status: "ACTIVE",
                  }
                : {
                    name: `projects/${PROJECT}/locations/us-central1/functions/${h.name.toLowerCase()}`,
                    state: "ACTIVE",
                  },
            )
        : [];
      return json(200, list.length ? { functions: list } : {});
    }
    if (u.hostname === "run.googleapis.com")
      return json(
        200,
        world.deployed
          ? {
              services: names
                .filter((h) => h.generation === 2)
                .map((h) => ({
                  name: `projects/${PROJECT}/locations/us-central1/services/${h.name.toLowerCase()}`,
                })),
            }
          : {},
      );
    if (u.hostname === "eventarc.googleapis.com")
      return json(
        200,
        world.deployed
          ? {
              triggers: names
                .filter((h) => h.generation === 2)
                .map((h) => ({
                  name: `projects/${PROJECT}/locations/us-central1/triggers/${h.name.toLowerCase()}-1`,
                })),
            }
          : {},
      );
    const fixed = {
      "cloudresourcemanager.googleapis.com": path.endsWith(":getIamPolicy")
        ? {
            bindings: [
              ...healthy()["preflight.iam"].json.bindings,
              ...(world.extraIam
                ? [
                    {
                      role: "roles/pubsub.publisher",
                      members: ["serviceAccount:gcs-agent@example"],
                    },
                  ]
                : []),
            ],
          }
        : healthy()["preflight.project"].json,
      "serviceusage.googleapis.com": healthy()["preflight.services"].json,
      "artifactregistry.googleapis.com": path.endsWith("gcf-artifacts")
        ? healthy()["preflight.artifact-repository"].json
        : {},
    };
    if (fixed[u.hostname] !== undefined) return json(200, fixed[u.hostname]);
    if (u.hostname === "firebaserules.googleapis.com")
      return json(
        200,
        path.includes("/releases/")
          ? healthy()["preflight.rules-release"].json
          : healthy()["preflight.rules-ruleset"].json,
      );
    throw new Error(`the world has no route for ${method} ${u.hostname}${path}`);
  }

  world.hooks = [];
  world.fetch = async (url, init = {}) => {
    const method = init.method ?? "GET";
    world.requests.push({ method, url });
    for (const hook of world.hooks) hook(method, url, init);
    const normalized = {
      ...init,
      headers: Object.fromEntries(
        Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
      ),
    };
    for (const failure of world.failures) {
      if (failure.match(method, url) && (failure.times === undefined || failure.times-- > 0)) {
        if (failure.error) throw Object.assign(new Error("injected"), { name: failure.error });
        // `after`: the service did the work and the answer was lost (the status is what the caller sees)
        if (failure.after) await route(method, url, normalized);
        return json(failure.status, {});
      }
    }
    return route(method, url, normalized);
  };
  world.deploy = () => {
    world.deployed = true;
  };
  world.undeploy = () => {
    world.deployed = false;
  };
  return world;
}
