import { createHash, randomUUID } from "node:crypto";

// A stand-in for production, used only by tests: it answers every request family the recording sends, in the shapes the
// closed response schemas accept, and keeps just enough state (objects, Rulesets, the release, sessions, documents) for a
// whole recording to run. Access decisions are a simple function of the active release, not Rules evaluation.
const json = (status, body, headers = {}) => ({ status, rawHeaders: Object.entries({ "Content-Type": "application/json; charset=UTF-8", ...headers }).flat(), bytes: Buffer.from(JSON.stringify(body)), startedAtMs: 1, finishedAtMs: 2 });
const empty = (status, headers = {}) => ({ status, rawHeaders: Object.entries(headers).flat(), bytes: Buffer.alloc(0), startedAtMs: 1, finishedAtMs: 2 });
const denial = () => json(403, { error: { code: 403, message: "Permission denied. Could not perform this operation" } });
// The answer production gave to a Firebase Storage v0 request on a bucket with no release (stage 3 v7 recording 1, 2026-09-30, `management/no-release/entry/subject` and the last
// restoration settle reads: status 400, this body, `application/json; charset=UTF-8`; the fixture `noRelease` of the production fixtures).
const noRelease = () => json(400, { error: { code: 400, message: "Your bucket has not been set up properly for Firebase Storage. Please visit 'https://console.firebase.google.com/project/fireemu-oracle-query/storage/rules' to set up security rules." } });
// The answers production gave to the stage 2d probe: a missing object is a JSON error for a metadata read (its message names the bucket and the object, and so does
// its one error), and a plain sentence with a text content type for a media download; a missing document is a Firestore NOT_FOUND that quotes the document name.
const gcsNotFound = (bucket, name) => json(404, { error: { code: 404, message: `No such object: ${bucket}/${name}`, errors: [{ message: `No such object: ${bucket}/${name}`, domain: "global", reason: "notFound" }] } });
const gcsMediaNotFound = (bucket, name) => ({ status: 404, rawHeaders: ["Content-Type", "text/html; charset=UTF-8"], bytes: Buffer.from(`No such object: ${bucket}/${name}`), startedAtMs: 1, finishedAtMs: 2 });
const documentNotFound = (name) => json(404, { error: { code: 404, message: `Document "${name}" not found.`, status: "NOT_FOUND" } });
const rpcNotFound = () => json(404, { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } });
const sha = (text) => createHash("sha256").update(text).digest("hex");
const time = () => "2026-09-29T10:00:00.000000Z";

// The delete cases whose subject (a Firebase v0 DELETE by a test user) the case's own rules deny, so the object stays: 403 "Permission denied." by the rules, not by a missing release
// (stage 3 v7 recording 1, `method-read-delete-present`, attempt 636, blob 8cb089d6: 403 with this body). The list is deterministic from the rules each case states; the simulator does not
// evaluate rules, so it takes the answer from here. A case that is not listed answers by the release, as before.
export const DENIED_SUBJECT_DELETE_CASES = Object.freeze([
  "method-read-delete-present", "method-get-delete-present", "method-list-delete-present", "method-create-delete-present", "method-update-delete-present",
  "stored-size-false-delete-present", "stored-contentType-false-delete-present", "stored-name-false-delete-present", "stored-metadata-false-delete-present",
  "state-delete-nonnull-present", "stored-null-true-delete-present", "denial-delete-present", "boundary-firebase-user-a-delete-present",
]);
const rulesDenial = () => json(403, { error: { code: 403, message: "Permission denied." } });

export function createSimulator({ manifest, options = {} }) {
  const { bucket } = manifest.binding;
  const project = "fireemu-oracle-query";
  const controls = manifest.resources.controls;
  const witnessOf = { v1: controls[0], v2: controls[1], A: controls[3], B: controls[4] };
  const sourceBySha = new Map(manifest.sources.map((entry) => [entry.sha256, entry.id]));
  const invalidContent = options.invalidContent ?? null;
  const deniedDeleteCases = options.deniedSubjectDeleteCases ?? DENIED_SUBJECT_DELETE_CASES;
  // Answers of the Firebase v0 capabilities that a recording must survive (they are record-only): `finalize-anyway` (a session finalizes an object the rules deny), `two-tokens` (a token request
  // answers a list), `start-denied` (a session start fails), `odd-cancel` (a cancel answers 400). Off by default.
  const odd = new Set(options.oddV0 ?? []);
  const objects = new Map();
  const rulesets = new Map();
  // The rulesets that exist in production before the run (a storage one and a Firestore one, listed with their metadata). The run never creates,
  // reads or deletes them; a request that names one is counted in `touchedEntryRulesets`.
  const entryRulesets = (options.entryRulesets ?? [
    { id: "22b746af-a48a-458d-ab5c-7853473bc8c8", createTime: "2026-09-25T11:08:54.358767Z", services: ["firebase.storage"] },
    { id: "d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1", createTime: "2026-09-23T23:02:05.839536Z", services: ["cloud.firestore"] },
  ]).map((entry) => ({ ...entry, name: `projects/fireemu-oracle-query/rulesets/${entry.id}` }));
  const touchedEntryRulesets = [];
  let listCalls = 0;
  // A ruleset another party adds while the run is going: the lists after the first show it (a test's way to prove the final list is compared with the entry list).
  const stranger = { name: "projects/fireemu-oracle-query/rulesets/aaaaaaaa-0000-4000-8000-000000000000", createTime: "2026-09-29T00:00:00.000000Z", metadata: { services: ["firebase.storage"] } };
  const documents = new Map();
  const sessions = new Map();
  const log = [];
  const secrets = ["AIzaSIMULATEDKEYSTRING0123456789abcdefg", "owner@example.com"];
  let generation = 1700000000000000;
  let release = null;
  let staleReads = 0;
  let previousSource = null;
  let previousRelease = null;
  const state = { failures: options.failures ?? new Map(), calls: 0 };
  for (const name of options.preexisting ?? []) objects.set(name, { bytes: Buffer.from("foreign"), generation: ++generation, metageneration: 1, previous: null });

  const activeSource = () => {
    if (release === null) return null;
    const ruleset = [...rulesets.values()].find((r) => r.name === release);
    return ruleset ? sourceBySha.get(sha(ruleset.content)) ?? null : null;
  };
  const effectiveSource = () => (staleReads > 0 ? previousSource : activeSource());
  // What the serving plane still answers by: the release before the last change while it is stale, the current one after. A bucket with none answers 400, not 403.
  const servingRelease = () => (staleReads > 0 ? previousRelease : release);
  const refusal = () => (servingRelease() === null ? noRelease() : denial());
  const allowed = (name) => {
    const source = effectiveSource();
    if (source === null) return false;
    if (Object.values(witnessOf).includes(name)) return witnessOf[source] === name;
    if (controls.includes(name)) return false;
    return source === "v1" || source === "v2";
  };
  const objectJson = (name, object, extra = {}) => ({ kind: "storage#object", bucket, name, size: String(object.bytes.length), generation: String(object.generation), metageneration: String(object.metageneration), contentType: "text/plain", ...extra });
  const firebaseJson = (name, object, extra = {}) => ({ name, bucket, generation: String(object.generation), metageneration: String(object.metageneration), size: String(object.bytes.length), contentType: "text/plain", ...extra });
  const putObject = (name, bytes) => { const existing = objects.get(name); const object = { bytes, generation: ++generation, metageneration: 1, previous: existing ?? null }; objects.set(name, object); return object; };
  const consumeStale = () => { if (staleReads > 0) staleReads--; };

  function storage(method, url, spec) {
    const path = url.pathname;
    let match = new RegExp(`^/storage/v1/b/${bucket}/o/([^/]+)$`).exec(path);
    if (match) {
      const name = decodeURIComponent(match[1]);
      const object = objects.get(name);
      if (method === "GET") {
        if (!object) return url.searchParams.get("alt") === "media" ? gcsMediaNotFound(bucket, name) : gcsNotFound(bucket, name);
        return url.searchParams.get("alt") === "media" ? { status: 200, rawHeaders: ["Content-Type", "text/plain", "X-Goog-Generation", String(object.generation)], bytes: object.bytes, startedAtMs: 1, finishedAtMs: 2 } : json(200, objectJson(name, object));
      }
      if (method === "PATCH") {
        if (!object) return gcsNotFound(bucket, name);
        const g = url.searchParams.get("ifGenerationMatch"); const m = url.searchParams.get("ifMetagenerationMatch");
        if ((g !== null && g !== String(object.generation)) || (m !== null && m !== String(object.metageneration))) return json(412, { error: { code: 412, message: "Precondition Failed" } });
        object.metageneration++;
        return json(200, objectJson(name, object));
      }
      if (method === "DELETE") {
        if (!object) return gcsNotFound(bucket, name);
        const g = url.searchParams.get("ifGenerationMatch");
        if (g !== null && g !== String(object.generation)) return json(412, { error: { code: 412, message: "Precondition Failed" } });
        objects.delete(name);
        return empty(204);
      }
    }
    if (method === "POST" && path === `/upload/storage/v1/b/${bucket}/o`) {
      const name = url.searchParams.get("name");
      if (url.searchParams.get("ifGenerationMatch") === "0" && objects.has(name)) return json(412, { error: { code: 412, message: "Precondition Failed" } });
      return json(200, objectJson(name, putObject(name, spec.body ?? Buffer.alloc(0))));
    }
    if (method === "GET" && path === `/storage/v1/b/${bucket}/o`) {
      const prefix = url.searchParams.get("prefix") ?? "";
      const items = [...objects.keys()].filter((name) => name.startsWith(prefix)).slice(0, Number(url.searchParams.get("maxResults") ?? "1000")).map((name) => ({ kind: "storage#object", name }));
      return json(200, { kind: "storage#objects", ...(items.length ? { items } : {}) });
    }
    if (method === "GET" && path === `/storage/v1/b/${bucket}`) return json(200, { kind: "storage#bucket", id: bucket, name: bucket, projectNumber: options.queryProjectNumber ?? "1".repeat(12), location: "US-CENTRAL1", storageClass: "STANDARD", iamConfiguration: { uniformBucketLevelAccess: { enabled: false }, publicAccessPrevention: "inherited" } });
    if (method === "GET" && path === `/storage/v1/b/${bucket}/iam`) return json(200, { kind: "storage#policy", version: 3, etag: "CAE=", bindings: [{ role: "roles/storage.legacyBucketOwner", members: ["projectOwner:x"] }] });
    if (method === "GET" && path === `/storage/v1/b/${bucket}/iam/testPermissions`) return json(200, { kind: "storage#testIamPermissionsResponse", permissions: url.searchParams.getAll("permissions") });
    return json(404, { error: { code: 404, message: "unrouted" } });
  }

  function firebaseStorage(method, url, spec) {
    const path = url.pathname;
    const command = spec.headers["x-goog-upload-command"];
    if (path !== `/v0/b/${bucket}/o` && !path.startsWith(`/v0/b/${bucket}/o/`)) return json(404, { error: { code: 404, message: "unrouted" } });
    const match = new RegExp(`^/v0/b/${bucket}/o/([^/]+)$`).exec(path);
    if (match) {
      const name = decodeURIComponent(match[1]);
      const object = objects.get(name);
      if (method === "POST" && url.searchParams.get("create_token") === "true") {
        if (!object) return json(404, { error: { code: 404, message: "Not Found." } });
        object.token = odd.has("two-tokens") ? `${randomUUID()},${randomUUID()}` : object.token ? `${object.token},${randomUUID()}` : randomUUID();
        secrets.push(object.token);
        return json(200, firebaseJson(name, object, { downloadTokens: object.token }));
      }
      consumeStale();
      if (method === "DELETE" && servingRelease() !== null && deniedDeleteCases.some((id) => name.includes(`/${id}/`))) return rulesDenial();
      if (!allowed(name)) return refusal();
      if (method === "GET") {
        if (!object) return json(404, { error: { code: 404, message: "Not Found." } });
        return url.searchParams.get("alt") === "media" ? { status: 200, rawHeaders: ["Content-Type", "text/plain"], bytes: object.bytes, startedAtMs: 1, finishedAtMs: 2 } : json(200, firebaseJson(name, object));
      }
      if (method === "PATCH") { if (!object) return json(404, { error: { code: 404, message: "Not Found." } }); object.metageneration++; return json(200, firebaseJson(name, object)); }
      if (method === "DELETE") { if (!object) return json(404, { error: { code: 404, message: "Not Found." } }); objects.delete(name); return empty(204); }
    }
    if (method === "GET" && path === `/v0/b/${bucket}/o`) {
      consumeStale();
      const prefix = url.searchParams.get("prefix") ?? "";
      if (!allowed(`${prefix}x`)) return refusal();
      return json(200, { prefixes: [], items: [...objects.keys()].filter((name) => name.startsWith(prefix)).slice(0, 3).map((name) => ({ name, bucket })) });
    }
    if (method === "POST" && path === `/v0/b/${bucket}/o`) {
      const name = url.searchParams.get("name");
      consumeStale();
      if (command === "start") {
        if (odd.has("start-denied")) return json(500, { error: { code: 500, message: "Internal error encountered." } });
        if (!allowed(name)) return refusal();
        const id = `SIMSESSION${sessions.size}${randomUUID().replaceAll("-", "").slice(0, 12)}`;
        sessions.set(id, { name, state: "active" });
        secrets.push(id);
        return json(200, {}, { "X-Goog-Upload-URL": `https://firebasestorage.googleapis.com/v0/b/${bucket}/o?name=${encodeURIComponent(name)}&upload_id=${id}&upload_protocol=resumable`, "X-Goog-Upload-Status": "active", "X-GUploader-UploadID": id });
      }
      if (!allowed(name)) return refusal();
      return json(200, firebaseJson(name, putObject(name, spec.body ?? Buffer.alloc(0))));
    }
    return json(404, { error: { code: 404, message: "unrouted" } });
  }

  // Every answer about a session carries its upload ID in X-GUploader-UploadID, as the real service does; it is a canary like the URL.
  const tagged = (response, id) => ({ ...response, rawHeaders: [...response.rawHeaders, "X-GUploader-UploadID", id] });
  function session(url, spec) {
    const id = url.searchParams.get("upload_id");
    const entry = sessions.get(id);
    return entry ? tagged(sessionAnswer(url, spec, id), id) : sessionAnswer(url, spec, id);
  }
  function sessionAnswer(url, spec, id) {
    const entry = sessions.get(id);
    const command = spec.headers["x-goog-upload-command"];
    if (!entry) return json(404, { error: { code: 404, message: "Not Found." } });
    consumeStale();
    if (command === "query") return { status: 200, rawHeaders: ["X-Goog-Upload-Status", entry.state === "active" ? "active" : "final", "X-Goog-Upload-Size-Received", entry.state === "final" && entry.received ? "4" : "0"], bytes: Buffer.alloc(0), startedAtMs: 1, finishedAtMs: 2 };
    if (command === "cancel" && odd.has("odd-cancel")) return json(400, { error: { code: 400, message: "Bad request." } });
    if (command === "cancel") { if (entry.state === "active") entry.state = "cancelled"; return { status: 200, rawHeaders: ["X-Goog-Upload-Status", "cancelled"], bytes: Buffer.alloc(0), startedAtMs: 1, finishedAtMs: 2 }; }
    if (command === "upload, finalize") {
      if ((!allowed(entry.name) && !odd.has("finalize-anyway")) || entry.state !== "active") return refusal();
      entry.state = "final"; entry.received = true;
      return json(200, firebaseJson(entry.name, putObject(entry.name, spec.body ?? Buffer.alloc(0))));
    }
    return json(400, { error: { code: 400, message: "bad command" } });
  }

  function rules(method, url, spec) {
    const path = url.pathname;
    const body = spec.body ? JSON.parse(spec.body.toString()) : null;
    if (method === "POST" && path === `/v1/projects/${project}:test`) {
      const content = body.source.files[0].content;
      return json(200, content === invalidContent ? { issues: [{ severity: "ERROR", description: "Unexpected token", sourcePosition: { fileName: "storage.rules", line: 1, column: 1 } }] } : {});
    }
    if (method === "POST" && path === `/v1/projects/${project}/rulesets`) {
      const id = randomUUID();
      const ruleset = { name: `projects/${project}/rulesets/${id}`, content: body.source.files[0].content, createTime: time() };
      rulesets.set(id, ruleset);
      return json(200, { name: ruleset.name, createTime: ruleset.createTime, source: { files: [{ name: "storage.rules", content: ruleset.content, fingerprint: "AbCd" }] }, metadata: { services: ["firebase.storage"] } });
    }
    let match = new RegExp(`^/v1/projects/${project}/rulesets/([^/]+)$`).exec(path);
    if (match) {
      if (entryRulesets.some((entry) => entry.id === match[1])) { touchedEntryRulesets.push(`${method} ${match[1]}`); return json(200, {}); }
      const ruleset = rulesets.get(match[1]);
      if (!ruleset) return rpcNotFound();
      if (method === "DELETE") { rulesets.delete(match[1]); return json(200, {}); }
      return json(200, { name: ruleset.name, createTime: ruleset.createTime, source: { files: [{ name: "storage.rules", content: ruleset.content }] } });
    }
    if (method === "GET" && path === `/v1/projects/${project}/rulesets`) return json(200, { rulesets: [...(options.strangerAfterEntry && listCalls++ > 0 ? [stranger] : []), ...entryRulesets.map((entry) => ({ name: entry.name, createTime: entry.createTime, metadata: { services: entry.services } })), ...[...rulesets.values()].map((r) => ({ name: r.name, createTime: r.createTime, metadata: { services: ["firebase.storage"] } }))] });
    const name = `projects/${project}/releases/firebase.storage/${bucket}`;
    const releaseJson = () => ({ name, rulesetName: release, createTime: time(), updateTime: time() });
    if (method === "POST" && path === `/v1/projects/${project}/releases`) { previousSource = activeSource(); previousRelease = release; release = body.rulesetName; staleReads = options.lag ?? 0; return json(200, releaseJson()); }
    if (path === `/v1/${name}`) {
      if (method === "GET") return release === null ? rpcNotFound() : json(200, releaseJson());
      if (method === "PATCH") { previousSource = activeSource(); previousRelease = release; release = body.release.rulesetName; staleReads = options.lag ?? 0; return json(200, releaseJson()); }
      if (method === "DELETE") { if (release === null) return rpcNotFound(); previousSource = activeSource(); previousRelease = release; release = null; staleReads = options.lag ?? 0; return json(200, {}); }
    }
    if (method === "GET" && path === `/v1/projects/${project}/releases/firebase.storage`) return rpcNotFound();
    return json(404, { error: { code: 404, message: "unrouted", status: "NOT_FOUND" } });
  }

  function firestore(method, url, spec) {
    const path = decodeURIComponent(url.pathname);
    const base = `/v1/projects/${project}/databases/(default)`;
    if (method === "GET" && path === base) return json(200, { name: `projects/${project}/databases/(default)`, uid: "u", createTime: time(), updateTime: time(), locationId: "us-central1", type: "FIRESTORE_NATIVE" });
    const prefix = `${base}/documents/`;
    if (!path.startsWith(prefix)) return json(404, { error: { code: 404, message: "unrouted", status: "NOT_FOUND" } });
    let name = `projects/${project}/databases/(default)/documents/${path.slice(prefix.length)}`;
    const doc = (n, d) => ({ name: n, fields: d.fields, createTime: d.createTime, updateTime: d.updateTime });
    const stamp = () => { const t = new Date(1790000000000 + ++generation % 1000000).toISOString().replace("Z", "000Z"); return t; };
    if (method === "POST") { name = `${name}/${url.searchParams.get("documentId")}`; const d = { fields: {}, createTime: stamp(), updateTime: stamp() }; documents.set(name, d); return json(200, doc(name, d)); }
    const existing = documents.get(name);
    if (method === "GET") return existing ? json(200, doc(name, existing)) : documentNotFound(name);
    if (method === "PATCH") { const d = { fields: {}, createTime: existing?.createTime ?? stamp(), updateTime: stamp() }; documents.set(name, d); return json(200, doc(name, d)); }
    if (method === "DELETE") { if (!existing) return rpcNotFound(); documents.delete(name); return json(200, {}); }
    return json(404, { error: { code: 404, message: "unrouted", status: "NOT_FOUND" } });
  }

  function preflight(method, url, spec) {
    const path = url.pathname;
    if (url.host === "www.googleapis.com") return json(200, { id: "1234567890", email: "owner@example.com", verified_email: true });
    if (url.host === "cloudresourcemanager.googleapis.com") {
      if (method === "POST" && path.endsWith(":testIamPermissions")) return json(200, { permissions: JSON.parse(spec.body.toString()).permissions });
      if (method === "POST") return json(200, { version: 3, etag: "CAE=", bindings: [{ role: "roles/owner", members: ["user:owner@example.com"] }] });
      const number = path.split("/").at(-1);
      return json(200, { name: `projects/${number}`, projectId: options.projectIds?.[number] ?? project, state: "ACTIVE", displayName: "n", etag: "e" });
    }
    if (url.host === "apikeys.googleapis.com") {
      if (path.endsWith("/keyString")) return json(200, { keyString: "AIzaSIMULATEDKEYSTRING0123456789abcdefg" });
      return json(200, { name: path.slice(4), uid: "08c3ec4e-d284-4034-a35a-c061cafeeff7", displayName: "k", restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }, { service: "securetoken.googleapis.com" }] }, etag: "e" });
    }
    return json(404, {});
  }

  return Object.freeze({
    async send(spec) {
      state.calls++;
      const url = new URL(spec.url);
      log.push(`${spec.method} ${url.host}${url.pathname}`);
      const override = state.failures.get(state.calls);
      if (override === "throw") throw new Error("socket closed");
      if (typeof override === "function") return override(spec);
      const method = spec.method;
      if (url.host === "storage.googleapis.com") return storage(method, url, spec);
      if (url.host === "firebasestorage.googleapis.com") return url.searchParams.has("upload_id") ? session(url, spec) : firebaseStorage(method, url, spec);
      if (url.host === "firebaserules.googleapis.com") return rules(method, url, spec);
      if (url.host === "firestore.googleapis.com") return firestore(method, url, spec);
      return preflight(method, url, spec);
    },
    touchedEntryRulesets: () => [...touchedEntryRulesets],
    state: () => ({ objects: objects.size, rulesets: rulesets.size, release, documents: documents.size, sessions: [...sessions.values()].map((s) => s.state), calls: state.calls, log }),
    objects: () => [...objects.keys()],
    /** Every bearer value the simulator handed out, for sweeps that prove none was saved. */
    // The simulator accepts every target the controller builds; the real transport's checks are tested on their own.
    validate() {},
    secrets: () => [...secrets],
  });
}
