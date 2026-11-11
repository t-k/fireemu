// An in-memory world for the tests of the Storage Rules observation: a bucket, the Cloud Storage
// JSON API, the Firebase v0 API with rules that take effect after a number of reads (production
// serves a switch from several frontends), and the Firebase Rules API. Bodies follow the layouts
// recorded from production (conformance/src/storage-rules-production-fixtures.mjs): pretty JSON
// with two-space indent, 403 `Permission denied.`, 400 `Your bucket has not been set up properly`,
// 404 `Requested entity was not found.`. The test doubles refuse what production refuses: a create
// without `ifGenerationMatch=0` over an existing name answers 412, a release for an unknown
// ruleset 400.

import { Buffer } from "node:buffer";

import { S9_PLAN } from "./plan.mjs";

const pretty = (value) => `${JSON.stringify(value, null, 2)}\n`;
const reply = (status, body, contentType = "application/json; charset=UTF-8") => ({
  status,
  headers: { "content-type": contentType },
  body: Buffer.from(typeof body === "string" ? body : pretty(body)),
});
const notFound = () =>
  reply(404, {
    error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" },
  });
const denied = () =>
  reply(403, '{\n  "error": {\n    "code": 403,\n    "message": "Permission denied."\n  }\n}');
const noRelease = (project) =>
  reply(
    400,
    `{\n  "error": {\n    "code": 400,\n    "message": "Your bucket has not been set up properly for Firebase Storage. Please visit 'https://console.firebase.google.com/project/${project}/storage/rules' to set up security rules."\n  }\n}`,
  );

/**
 * @param {object} options
 * @param {object} [options.plan] the family the world serves; the s9 family when omitted
 * @param {string} options.project
 * @param {string} options.bucket
 * @param {string|null} options.baseline full name of the baseline ruleset, or null for no release
 * @param {number} [options.lag] v0 reads a release change needs before it is served
 * @param {(row: object, P: string) => boolean} [options.allow] whether the active program lets a row through
 * @param {Array<{match: (req: object) => boolean, answer: object|"transport"}>} [options.faults] one-shot answers
 * @param {Set<string>} [options.refuseNames] object names a create refuses with 400
 */
export function createWorld({
  plan = S9_PLAN,
  project,
  bucket,
  baseline,
  lag = 2,
  allow = (row) => row.plan === "allow",
  faults = [],
  refuseNames = new Set(),
}) {
  const baselineRulesets = [
    {
      name: `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`,
      services: ["firebase.storage"],
    },
    {
      name: `projects/${project}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
      services: ["cloud.firestore"],
    },
  ];
  const world = {
    objects: new Map(),
    rulesets: new Map(
      baselineRulesets.map((r) => [r.name, { services: r.services, source: "baseline" }]),
    ),
    release: baseline === null ? null : { rulesetName: baseline },
    serving: baseline === null ? { kind: "none" } : { kind: "baseline" },
    pending: null,
    calls: [],
    sources: [],
    nextGeneration: 1790000000000000,
    nextRuleset: 1,
    local: { rulesSource: null },
    faults: [...faults],
  };
  const root = (name) => (name.startsWith("/") ? name.slice(1) : name);
  const preOf = (name) => root(name).split("/").slice(0, 3).join("/");

  function serve() {
    if (world.pending) {
      world.pending.remaining -= 1;
      if (world.pending.remaining <= 0) {
        world.serving = world.pending.to;
        world.pending = null;
      }
    }
  }
  function changeRelease(next) {
    const to =
      next === null
        ? { kind: "none" }
        : next === baseline
          ? { kind: "baseline" }
          : { kind: "program", name: next };
    world.release = next === null ? null : { rulesetName: next };
    world.pending = { to, remaining: lag };
  }
  // A source belongs to the program whose marker object it opens a rule for.
  const programOf = (source) =>
    plan.programs.find(
      (program) => source !== undefined && source.includes(`${plan.objects[program.marker].name("")} {`),
    )?.id ?? null;
  function allowed(op, subject, P) {
    const serving = world.serving;
    if (serving.kind === "none") return "none";
    if (serving.kind === "baseline") return false;
    const active = programOf(world.rulesets.get(serving.name)?.source);
    if (op === "list") {
      const row = plan.rows.find((r) => r.op === "list" && r.prefix(P) === subject);
      return Boolean(row && row.program === active && allow(row, P));
    }
    const id = Object.keys(plan.objects).find((key) => plan.objects[key].name(P) === subject);
    if (id === undefined) return false;
    const program = plan.programs.find((p) => p.marker === id);
    if (program) return program.id === active;
    const row = plan.rows.find((r) => r.op === op && r.object === id);
    return Boolean(row && row.program === active && allow(row, P));
  }

  function objectResource(name, object) {
    return {
      kind: "storage#object",
      id: `${bucket}/${name}/${object.generation}`,
      selfLink: `https://www.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
      mediaLink: `https://storage.googleapis.com/download/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}?generation=${object.generation}&alt=media`,
      name,
      bucket,
      generation: String(object.generation),
      metageneration: "1",
      contentType: "text/plain",
      size: String(object.body.length),
      ...(object.metadata ? { metadata: object.metadata } : {}),
    };
  }

  async function net(request) {
    const url = new URL(request.url);
    world.calls.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body,
    });
    const faultIndex = world.faults.findIndex((f) =>
      f.match({ method: request.method, url, path: url.pathname, body: request.body }),
    );
    if (faultIndex !== -1) {
      const [fault] = world.faults.splice(faultIndex, 1);
      // `afterReal`: the request takes effect and its answer is lost.
      if (fault.afterReal) await handle(request, url);
      if (fault.answer === "transport") throw new Error("transport failure");
      return fault.answer;
    }
    return handle(request, url);
  }

  async function handle(request, url) {
    const method = request.method;
    const path = url.pathname;
    const decode = (segment) => decodeURIComponent(segment);
    const segments = path.split("/").slice(1);

    // Local targets: the setRules route.
    if (path === "/internal/setRules") {
      const body = JSON.parse(Buffer.from(request.body).toString("utf8"));
      const source = body.rules.files[0].content;
      if (/allow [a-z, ]+: if ;/.test(source)) return reply(400, { error: "compile" });
      world.local.rulesSource = source;
      world.sources.push(source);
      const program = programOf(source);
      world.serving = program ? { kind: "program", name: "local" } : { kind: "baseline" };
      world.rulesets.set("local", { services: ["firebase.storage"], source });
      return reply(200, "", "text/plain");
    }

    // Cloud Storage JSON API.
    if (segments[0] === "storage" && segments[1] === "v1") {
      if (segments.length === 4)
        return reply(200, { kind: "storage#bucket", name: decode(segments[3]) });
      if (segments.length === 5) {
        const prefix = url.searchParams.get("prefix");
        const items = [...world.objects.entries()]
          .filter(([name]) => name.startsWith(prefix))
          .map(([name, object]) => objectResource(name, object));
        return reply(
          200,
          items.length ? { kind: "storage#objects", items } : { kind: "storage#objects" },
        );
      }
      const name = decode(segments[5]);
      const object = world.objects.get(name);
      if (method === "GET") return object ? reply(200, objectResource(name, object)) : notFound();
      if (method === "DELETE") {
        if (!object) return notFound();
        if (url.searchParams.get("ifGenerationMatch") !== String(object.generation))
          return reply(412, { error: { code: 412, message: "Precondition Failed" } });
        world.objects.delete(name);
        return {
          status: 204,
          headers: { "content-type": "application/json" },
          body: Buffer.alloc(0),
        };
      }
      if (method === "PATCH") {
        if (!object) return notFound();
        object.metadata = JSON.parse(Buffer.from(request.body).toString("utf8")).metadata;
        return reply(200, objectResource(name, object));
      }
    }
    if (segments[0] === "upload") {
      const name = url.searchParams.get("name");
      if (refuseNames.has(name))
        return reply(400, { error: { code: 400, message: "Invalid object name." } });
      if (world.objects.has(name))
        return reply(412, { error: { code: 412, message: "Precondition Failed" } });
      let metadata = null;
      let body = Buffer.from(request.body);
      if (url.searchParams.get("uploadType") === "multipart") {
        const text = body.toString("utf8");
        const boundary = /boundary=([A-Za-z0-9_-]+)/.exec(request.headers["content-type"])[1];
        const parts = text.split(`--${boundary}`);
        metadata = JSON.parse(parts[1].split("\r\n\r\n")[1].replace(/\r\n$/, "")).metadata;
        body = Buffer.from(parts[2].split("\r\n\r\n")[1].replace(/\r\n$/, ""));
      }
      const object = { generation: world.nextGeneration++, body, metadata };
      world.objects.set(name, object);
      return reply(200, objectResource(name, object));
    }

    // Firebase v0: anonymous reads.
    if (segments[0] === "v0") {
      serve();
      if (segments.length === 5) {
        const name = decode(segments[4]);
        const object = world.objects.get(name);
        const decision = allowed(url.searchParams.has("alt") ? "media" : "meta", name, preOf(name));
        if (decision === "none") return noRelease(project);
        if (!decision) return denied();
        if (!object) return notFound();
        if (url.searchParams.has("alt"))
          return reply(200, object.body.toString("utf8"), "text/plain");
        return reply(200, {
          ...objectResource(name, object),
          downloadTokens: "00000000-0000-4000-8000-000000000000",
        });
      }
      const prefix = url.searchParams.get("prefix");
      const P = preOf(prefix);
      const decision = allowed("list", prefix, P);
      if (decision === "none") return noRelease(project);
      if (!decision) return denied();
      const items = [...world.objects.keys()]
        .filter((n) => n.startsWith(prefix))
        .map((n) => ({ name: n, bucket }));
      return reply(200, { prefixes: [], items });
    }

    // Firebase Rules API.
    if (segments[0] === "v1") {
      const releaseName = `projects/${project}/releases/firebase.storage/${bucket}`;
      const rest = segments.slice(3).map(decode).join("/");
      if (rest === "rulesets" && method === "POST") {
        const body = JSON.parse(Buffer.from(request.body).toString("utf8"));
        const content = body.source.files[0].content;
        if (/allow [a-z, ]+: if ;/.test(content) || content.includes("COMPILE_ERROR"))
          return reply(400, {
            error: { code: 400, message: "Compilation failed", status: "INVALID_ARGUMENT" },
          });
        const name = `projects/${project}/rulesets/${String(world.nextRuleset++).padStart(8, "0")}-0000-4000-8000-000000000000`;
        world.rulesets.set(name, { services: ["firebase.storage"], source: content });
        world.sources.push(content);
        return reply(200, {
          name,
          source: body.source,
          createTime: "2026-11-08T00:00:00.000000Z",
          metadata: { services: ["firebase.storage"] },
        });
      }
      if (rest === "rulesets" && method === "GET") {
        const list = [...world.rulesets.entries()]
          .filter(([name]) => name.startsWith("projects/"))
          .map(([name, r]) => ({
            name,
            createTime: "2026-09-25T11:08:54.358767Z",
            metadata: { services: r.services },
          }))
          .sort((a, b) => (a.name < b.name ? -1 : 1));
        return reply(200, { rulesets: list });
      }
      if (rest.startsWith("rulesets/")) {
        const name = `projects/${project}/${rest}`;
        if (!world.rulesets.has(name)) return notFound();
        if (method === "GET") return reply(200, { name });
        if (method === "DELETE") {
          if (world.release?.rulesetName === name)
            return reply(400, { error: { code: 400, message: "Ruleset is in use" } });
          world.rulesets.delete(name);
          return reply(200, "{}\n");
        }
      }
      if (rest === "releases/firebase.storage") return notFound();
      if (rest === `releases/firebase.storage/${bucket}`) {
        if (method === "GET")
          return world.release
            ? reply(200, {
                name: releaseName,
                rulesetName: world.release.rulesetName,
                createTime: "2026-09-25T11:09:23.326708Z",
                updateTime: "2026-09-25T11:09:23.326708Z",
              })
            : notFound();
        if (method === "PATCH") {
          if (!world.release) return notFound();
          const body = JSON.parse(Buffer.from(request.body).toString("utf8"));
          if (!world.rulesets.has(body.release.rulesetName))
            return reply(400, { error: { code: 400, message: "unknown ruleset" } });
          changeRelease(body.release.rulesetName);
          return reply(200, { name: releaseName, rulesetName: body.release.rulesetName });
        }
        if (method === "DELETE") {
          if (!world.release) return notFound();
          changeRelease(null);
          return reply(200, "{}\n");
        }
      }
      if (rest === "releases" && method === "POST") {
        const body = JSON.parse(Buffer.from(request.body).toString("utf8"));
        if (world.release) return reply(409, { error: { code: 409, message: "exists" } });
        if (!world.rulesets.has(body.rulesetName))
          return reply(400, { error: { code: 400, message: "unknown ruleset" } });
        changeRelease(body.rulesetName);
        return reply(200, { name: releaseName, rulesetName: body.rulesetName });
      }
    }
    return reply(404, { error: { code: 404, message: "unrouted in the fake world" } });
  }

  return { world, net, recordingPrefix: plan.recordingPrefix };
}
