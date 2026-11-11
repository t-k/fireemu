import { gunzipSync } from "node:zlib";

const PROJECT = "fireemu-oracle-idp";
const RESERVED = ["/__/firebase/init.json", "/__/firebase/init.js"];
const response = (status, value) => ({ status, text: JSON.stringify(value) });
const error = (status, message) =>
  response(status, {
    error: { code: status, message, status: status === 404 ? "NOT_FOUND" : "INVALID_ARGUMENT" },
  });

/** A deterministic, entirely in-memory Hosting API and preview edge. */
export function createWorld({ run, secrets, overrides = [], versionNameForm = "short" }) {
  // How version create names the version: `sites/<site>/versions/<id>` (as a list does), or, under
  // the `projects/-` wildcard, with the project number in front (what production answered).
  const shown = (name) =>
    versionNameForm === "number"
      ? `projects/${secrets.projectNumber}/${name}`
      : versionNameForm === "projectId"
        ? `projects/${PROJECT}/${name}`
        : typeof versionNameForm === "function"
          ? versionNameForm(name)
          : name;
  const short = (name) => String(name).replace(/^projects\/[^/]+\//, "");
  const state = {
    channels: new Map(),
    versions: new Map(),
    uploadedHashes: new Map(),
    releasedVersions: new Map(),
    authorizedDomains: ["localhost"],
    rejectAppAssociation: false,
    counters: {},
  };
  const log = [];
  const matches = new Map();
  let nextVersion = 1;

  function overridden(method, url, call) {
    for (const [index, rule] of overrides.entries()) {
      const match = /^([A-Z]+) \/(.*)\/$/.exec(rule.match);
      if (!match || match[1] !== method || !new RegExp(match[2]).test(url.pathname + url.search))
        continue;
      const count = (matches.get(index) ?? 0) + 1;
      matches.set(index, count);
      if (rule.nth !== undefined && rule.nth !== count) continue;
      if (typeof rule.answer === "function") return rule.answer(call, state);
      if (rule.answer === "network-error" || rule.answer === "timeout")
        return { status: 0, text: "" };
      return rule.answer;
    }
    return undefined;
  }

  async function http(call) {
    const { method, body } = call;
    const url = new URL(call.url);
    log.push({
      kind: url.hostname === "upload-firebasehosting.googleapis.com" ? "upload" : "http",
      ...call,
    });
    state.counters[method] = (state.counters[method] ?? 0) + 1;
    const injected = overridden(method, url, call);
    if (injected !== undefined) return await injected;
    const path = url.pathname;
    const parse = () => JSON.parse(body || "{}");
    if (url.hostname === "serviceusage.googleapis.com") return response(200, { state: "ENABLED" });
    if (url.hostname === "identitytoolkit.googleapis.com")
      return response(200, { authorizedDomains: state.authorizedDomains });
    if (url.hostname === "upload-firebasehosting.googleapis.com") {
      const hash = path.split("/").at(-1);
      state.uploadedHashes.set(hash, gunzipSync(Buffer.from(body)));
      return response(200, {});
    }
    if (url.hostname !== "firebasehosting.googleapis.com") return error(404, "unknown host");
    if (path === `/v1beta1/projects/${PROJECT}/sites/${PROJECT}`)
      return response(200, { name: `projects/${PROJECT}/sites/${PROJECT}` });
    const channelCollection = new RegExp(
      `^/v1beta1/projects/(?:-|${PROJECT})/sites/${PROJECT}/channels$`,
    );
    if (channelCollection.test(path)) {
      if (method === "GET")
        return response(200, { channels: [...state.channels.values()].filter((c) => !c.deleted) });
      if (method === "POST") {
        // Every recorded channel create names the project; the `-` wildcard is recorded for version
        // creates and releases only.
        if (path.includes("/projects/-/")) return error(404, "channel create needs the project id");
        const id = url.searchParams.get("channelId");
        if (!id) return error(400, "channelId required");
        if (state.channels.has(id) && !state.channels.get(id).deleted)
          return error(409, "already exists");
        const data = parse();
        const channel = {
          name: `projects/${PROJECT}/sites/${PROJECT}/channels/${id}`,
          url: `https://${PROJECT}--${id}-abcdef12.web.app`,
          expireTime: "2030-01-01T00:00:00Z",
          labels: data.labels ?? {},
          deleted: false,
        };
        state.channels.set(id, channel);
        return response(200, channel);
      }
    }
    const channelMatch = new RegExp(
      `^/v1beta1/projects/(?:-|${PROJECT})/sites/${PROJECT}/channels/([^/]+)(/releases)?$`,
    ).exec(path);
    if (channelMatch) {
      const [, id, releases] = channelMatch;
      const channel = state.channels.get(id);
      if (!channel || channel.deleted) return error(404, "channel not found");
      if (releases && method === "POST") {
        const name = short(url.searchParams.get("versionName"));
        const version = state.versions.get(name);
        if (!version || version.deleted || version.status !== "FINALIZED")
          return error(404, "version not found");
        state.releasedVersions.set(id, name);
        return response(200, { version: { name } });
      }
      if (!releases && method === "GET") {
        const released = state.releasedVersions.get(id);
        return response(
          200,
          released ? { ...channel, release: { version: { name: released } } } : channel,
        );
      }
      if (!releases && method === "DELETE") {
        channel.deleted = true;
        return response(200, {});
      }
    }
    if (
      new RegExp(`^/v1beta1/projects/-/sites/${PROJECT}/versions$`).test(path) &&
      method === "POST"
    ) {
      const name = `sites/${PROJECT}/versions/${String(nextVersion++).padStart(16, "0")}`;
      const version = {
        name,
        status: "CREATED",
        createTime: "2026-11-10T16:12:57.000Z",
        labels: parse().labels ?? {},
        config: {},
        files: {},
        deleted: false,
      };
      state.versions.set(name, version);
      return response(200, { ...version, name: shown(name) });
    }
    if (path === `/v1beta1/sites/${PROJECT}/versions` && method === "GET")
      return response(200, { versions: [...state.versions.values()] });
    const versionMatch = new RegExp(
      `^/v1beta1/(?:projects/[^/]+/)?(sites/${PROJECT}/versions/[^/:]+)(?::(populateFiles)|(/files))?$`,
    ).exec(path);
    if (versionMatch) {
      const [, name, populate, files] = versionMatch;
      const version = state.versions.get(name);
      // A deleted version still reads, with status DELETED (recorded by the 2026-09-28 cleanup).
      const readable = method === "GET" && !populate && !files;
      if (!version || (version.deleted && !readable)) return error(404, "version not found");
      if (populate && method === "POST") {
        const data = parse();
        if (!data.files || typeof data.files !== "object") return error(400, "files required");
        version.files = data.files;
        return response(200, {
          uploadRequiredHashes: [...new Set(Object.values(data.files))].filter(
            (hash) => !state.uploadedHashes.has(hash),
          ),
          uploadUrl: `https://upload-firebasehosting.googleapis.com/upload/${name}/files`,
        });
      }
      if (files && method === "GET")
        return response(200, {
          files: [...Object.keys(version.files), ...RESERVED].map((file) => ({ path: file })),
        });
      if (!populate && !files && method === "PATCH") {
        if (!url.searchParams.has("updateMask")) return error(400, "updateMask required");
        const data = parse();
        if (state.rejectAppAssociation && data.config?.appAssociation !== undefined)
          return error(400, "appAssociation rejected");
        version.status = data.status;
        version.config = data.config;
        return response(200, version);
      }
      if (!populate && !files && method === "GET") {
        const bytes = Object.values(version.files).reduce(
          (sum, hash) => sum + (state.uploadedHashes.get(hash)?.length ?? 0),
          0,
        );
        return response(200, {
          ...version,
          fileCount: String(Object.keys(version.files).length + RESERVED.length),
          versionBytes: String(bytes),
        });
      }
      if (!populate && !files && method === "DELETE") {
        version.deleted = true;
        version.status = "DELETED";
        return response(200, {});
      }
    }
    return error(404, "not found");
  }

  async function edge(call) {
    const url = new URL(`https://${call.host}${call.target}`);
    log.push({ kind: "edge", ...call });
    state.counters.edge = (state.counters.edge ?? 0) + 1;
    const injected = overridden(call.method, url, call);
    if (injected !== undefined) {
      const answer = await injected;
      if (answer?.status === 0) return { outcome: "unknown", reason: "network-error" };
      return answer;
    }
    const channel = [...state.channels.values()].find(
      (entry) => !entry.deleted && new URL(entry.url).host === call.host,
    );
    const version = state.versions.get(state.releasedVersions.get(channel?.name.split("/").at(-1)));
    let status = 404;
    let body = Buffer.alloc(0);
    let headers = [];
    const redirect = version?.config?.redirects?.find((entry) => entry.glob === "**");
    if (version && RESERVED.includes(url.pathname)) {
      // Reserved paths come before a configured redirect (the published priority).
      status = 200;
      body = Buffer.from(
        url.pathname.endsWith(".json")
          ? JSON.stringify(secrets)
          : `firebase.initializeApp(${JSON.stringify(secrets)});\n`,
      );
      headers = [
        [
          "content-type",
          url.pathname.endsWith(".json") ? "application/json" : "application/javascript",
        ],
      ];
    } else if (redirect) {
      status = redirect.statusCode ?? 302;
      headers = [["location", redirect.location]];
    } else if (
      version?.files[url.pathname] &&
      state.uploadedHashes.has(version.files[url.pathname])
    ) {
      status = 200;
      body = state.uploadedHashes.get(version.files[url.pathname]);
      headers = [
        ["content-type", url.pathname.endsWith(".json") ? "application/json" : "text/plain"],
        ["etag", '"fake-etag"'],
      ];
    }
    return {
      outcome: "answered",
      status,
      headers,
      body: call.method === "HEAD" ? Buffer.alloc(0) : body,
    };
  }

  return { http, edge, state, log, run };
}
