import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { createHash } from "node:crypto";

const recordings = [
  "v7-replay",
  "stage-c-replay",
  "h-lists",
  "h1-preflight",
  "h-readiness",
].flatMap((name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/h-fe/${name}.json`, import.meta.url), "utf8")),
);

/** Recorded envelopes and name formats; item bodies remain raw observations. */
export function hProductionAnswer(reply, spec) {
  if (
    !spec ||
    reply?.unknown ||
    !Number.isInteger(reply?.status) ||
    !reply.body ||
    typeof reply.body !== "object" ||
    Array.isArray(reply.body)
  )
    return false;
  const origin = {
    usage: "serviceusage.googleapis.com",
    firestore: "firestore.googleapis.com",
    functions: "cloudfunctions.googleapis.com",
    run: "run.googleapis.com",
    eventarc: "eventarc.googleapis.com",
    logging: "logging.googleapis.com",
    artifact: "artifactregistry.googleapis.com",
    publishing: "eventarcpublishing.googleapis.com",
    pubsub: "pubsub.googleapis.com",
  }[spec.host];
  if (!origin) return false;
  // Measured byte counts calibrate Google's JSON layout, independently of compact fixture text.
  if (
    reply.bodyBase64Parts !== undefined &&
    (!Array.isArray(reply.bodyBase64Parts) ||
      reply.bodyBase64Parts.some((part) => typeof part !== "string") ||
      (reply.bodyBase64 !== undefined && reply.bodyBase64 !== reply.bodyBase64Parts.join("")))
  )
    return false;
  const encoded = reply.bodyBase64 ?? reply.bodyBase64Parts?.join("");
  if (typeof encoded !== "string" || !Number.isInteger(reply.bodyBytes)) return false;
  const native = Buffer.from(encoded, "base64");
  const serialized = JSON.stringify(reply.body, null, 2);
  const layout = `${
    origin === "serviceusage.googleapis.com"
      ? serialized.replace(
          /[<>&]/g,
          (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
        )
      : serialized
  }\n`;
  if (
    native.toString("base64") !== encoded ||
    native.length !== reply.bodyBytes ||
    !native.equals(Buffer.from(layout)) ||
    (reply.headers?.["content-length"] !== undefined &&
      reply.headers["content-length"] !== String(native.length)) ||
    (reply.bodySha256 !== undefined &&
      reply.bodySha256 !== createHash("sha256").update(native).digest("hex"))
  )
    return false;
  if (
    !recordings.some((recorded) => {
      const host = recorded.url
        ? new URL(recorded.url).hostname
        : recorded.sequence === 1
          ? "serviceusage.googleapis.com"
          : [184, 190].includes(recorded.sequence)
            ? "eventarcpublishing.googleapis.com"
            : "eventarc.googleapis.com";
      const rendered = JSON.stringify(recorded.body, null, 2);
      return (
        host === origin &&
        Number.isInteger(recorded.bodyBytes) &&
        recorded.bodyBytes ===
          Buffer.byteLength(
            `${
              host === "serviceusage.googleapis.com"
                ? rendered.replace(
                    /[<>&]/g,
                    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
                  )
                : rendered
            }\n`,
          )
      );
    })
  )
    return false;
  const actual = new URL(spec.path, `https://${origin}`);
  // Values may identify a different resource; route, method and answer must still be pinned.
  const route = (url) =>
    `${url.hostname}${url.pathname}`
      .replace(/\/projects\/[^/]+/, "/projects/<project>")
      .replace(
        /\/(functions|triggers|operations|channels|topics|subscriptions)\/[^/:]+(:[^/]+)?$/,
        "/$1/<name>$2",
      )
      .replace(/\/documents\/[^/]+\/[^/]+$/, "/documents/<name>")
      .replace(/^run.googleapis.com(.*)\/services\/[^/]+$/, "run.googleapis.com$1/services/<name>");
  return recordings.some((recorded) => {
    const url = new URL(recorded.url ?? recorded.path, "https://eventarc.googleapis.com");
    // Stage C's service and publishing answers come from different API hosts.
    if (!recorded.url && recorded.sequence === 1) url.hostname = "serviceusage.googleapis.com";
    if (!recorded.url && [184, 190].includes(recorded.sequence))
      url.hostname = "eventarcpublishing.googleapis.com";
    const collection = actual.pathname.match(
      /\/(functions|services|triggers|topics|subscriptions|channels)$/,
    )?.[1];
    if (collection && spec.method === "GET") {
      if (
        recorded.method !== "GET" ||
        route(url) !== route(actual) ||
        !isDeepStrictEqual(
          [...url.searchParams]
            .filter(([key]) => !["pageToken", "pageSize"].includes(key))
            .toSorted(),
          [...actual.searchParams]
            .filter(([key]) => !["pageToken", "pageSize"].includes(key))
            .toSorted(),
        ) ||
        recorded.status !== 200 ||
        reply.status !== 200 ||
        JSON.stringify(Object.keys(recorded.body)) !== JSON.stringify(Object.keys(reply.body))
      )
        return false;
      const items = reply.body[collection];
      if (items !== undefined && !Array.isArray(items)) return false;
      if (
        reply.body.nextPageToken !== undefined &&
        (typeof reply.body.nextPageToken !== "string" || !reply.body.nextPageToken)
      )
        return false;
      return (items ?? []).every((item) => {
        const name = typeof item === "string" ? item : item?.name;
        if (typeof name !== "string") return false;
        if (spec.host === "usage")
          return (
            /^projects\/[0-9]{12}\/services\/[a-z][a-z0-9.-]+\.googleapis\.com$/.test(name) &&
            item.config?.name === name.split("/").at(-1) &&
            item.state === "ENABLED"
          );
        const prefix = actual.pathname.slice(4);
        if (
          typeof item === "string" &&
          !(spec.host === "pubsub" && /\/topics\/[^/]+\/subscriptions$/.test(prefix))
        )
          return false;
        const parent = prefix.replace(/\/topics\/[^/]+\/subscriptions$/, "/subscriptions");
        if (spec.host === "functions" && parent.includes("/locations/-/"))
          return new RegExp(
            `^${parent.replace("/locations/-/", "/locations/[a-z0-9-]+/")}/[A-Za-z][A-Za-z0-9._~-]*$`,
          ).test(name);
        return (
          name.startsWith(`${parent}/`) &&
          /^[A-Za-z][A-Za-z0-9._~-]*$/.test(name.slice(parent.length + 1))
        );
      });
    }
    const envelope =
      ["usage", "firestore", "logging"].includes(spec.host) ||
      (spec.host === "artifact" && actual.pathname.endsWith("/repositories/gcf-artifacts")) ||
      /\/(operations|channels)\//.test(actual.pathname) ||
      (spec.host === "functions" && spec.method === "DELETE");
    const shape =
      envelope &&
      JSON.stringify(Object.keys(recorded.body)) === JSON.stringify(Object.keys(reply.body)) &&
      Object.keys(recorded.body).every(
        (key) => typeof recorded.body[key] === typeof reply.body[key],
      ) &&
      (!recorded.body.error ||
        (recorded.body.error.code === reply.body.error?.code &&
          recorded.body.error.status === reply.body.error?.status)) &&
      (!recorded.body.metadata ||
        JSON.stringify(Object.keys(recorded.body.metadata)) ===
          JSON.stringify(Object.keys(reply.body.metadata ?? {})));
    return (
      recorded.method === spec.method &&
      route(url) === route(actual) &&
      url.search === actual.search &&
      recorded.status === reply.status &&
      (shape ||
        (isDeepStrictEqual(recorded.body, reply.body) &&
          JSON.stringify(recorded.body) === JSON.stringify(reply.body)))
    );
  });
}

/** The packet declares the FE-style write allowance and persistent residue. */
export const hProductionEvidence = Object.freeze({
  preflight: (reply, spec) =>
    (spec?.method === "GET" ||
      (spec?.host === "usage" &&
        spec.method === "POST" &&
        spec.path.endsWith("/services/eventarcpublishing.googleapis.com:enable"))) &&
    hProductionAnswer(reply, spec),
  readiness: (reply, spec) =>
    ["GET", "DELETE"].includes(spec?.method) && hProductionAnswer(reply, spec),
  operation: (reply, spec) =>
    typeof reply?.body?.name === "string" &&
    typeof reply?.body?.metadata?.target === "string" &&
    typeof reply?.body?.done === "boolean" &&
    hProductionAnswer(reply, spec),
  notFound: (reply, spec) => reply?.status === 404 && hProductionAnswer(reply, spec),
  logging: (reply, spec) =>
    spec?.host === "logging" &&
    spec.method === "POST" &&
    spec.path === "/v2/entries:list" &&
    hProductionAnswer(reply, spec),
  cliWrites: (deployed, m, name) => {
    const resources = [];
    const queries = [
      ...`${deployed?.stdout ?? ""}\n${deployed?.stderr ?? ""}`.matchAll(
        /\[apiv2\]\[query\] (POST|PUT|PATCH|DELETE) (https:\/\/\S+)([^\n]*)/g,
      ),
    ];
    const full = `projects/${m?.project}/locations/us-central1/functions/${name}`;
    let ownCreate = false;
    const bodies = [];
    for (const [
      ,
      direction,
      method,
      address,
      raw,
    ] of `${deployed?.stdout ?? ""}\n${deployed?.stderr ?? ""}`.matchAll(
      /(>>>|<<<) \[apiv2\]\[body\] (POST|PUT|PATCH|GET) (https:\/\/\S+) (\{.*\})/g,
    )) {
      try {
        bodies.push({ direction, method, url: new URL(address), body: JSON.parse(raw) });
      } catch {
        return { complete: false, resources, reason: "H unreadable CLI write body" };
      }
    }
    const policies = new Set();
    for (const [, method, address, tail] of queries) {
      const url = new URL(address);
      const path = url.pathname;
      // POST permission/policy reads are observations, not writes.
      if (method === "POST" && /:(testIamPermissions|getIamPolicy)$/.test(path)) continue;
      if (
        method === "POST" &&
        url.hostname === "cloudfunctions.googleapis.com" &&
        path === `/v2/projects/${m.project}/locations/us-central1/functions` &&
        (url.searchParams.get("functionId") === name || tail.trim() === `functionId=${name}`)
      ) {
        if (ownCreate) return { complete: false, resources, reason: "H duplicate CLI CREATE" };
        ownCreate = true;
        continue;
      }
      if (
        method === "POST" &&
        url.hostname === "cloudfunctions.googleapis.com" &&
        path === `/v2/projects/${m.project}/locations/us-central1/functions:generateUploadUrl`
      )
        continue;
      if (
        method === "PUT" &&
        url.hostname === "storage.googleapis.com" &&
        path.startsWith(
          `/gcf-v2-uploads-${m.projectNumber}.us-central1.cloudfunctions.appspot.com/`,
        ) &&
        /^\/[a-z0-9.-]+\/[a-f0-9-]+\.zip$/.test(path)
      )
        continue;
      if (
        method === "POST" &&
        url.hostname === "eventarc.googleapis.com" &&
        path === `/v1/projects/${m.project}/locations/us-central1/channels` &&
        (url.searchParams.get("channelId") === "firebase" || tail.trim() === "channelId=firebase")
      ) {
        resources.push({
          name: m.channel,
          host: "eventarc",
          kind: "channel",
          action: "create",
          state: "unknown",
        });
        continue;
      }
      // The approved delta preserves all baseline bindings and adds only ledger 304/312 grants.
      if (
        method === "POST" &&
        url.hostname === "cloudresourcemanager.googleapis.com" &&
        [
          `/v1/projects/${m.project}:setIamPolicy`,
          `/v1/projects/${m.projectNumber}:setIamPolicy`,
        ].includes(path)
      ) {
        if (policies.has(path))
          return { complete: false, resources, reason: "H repeated IAM policy write" };
        policies.add(path);
        const before = bodies.find(
          (b) =>
            b.direction === "<<<" &&
            b.url.hostname === url.hostname &&
            b.url.pathname === path.replace(":setIamPolicy", ":getIamPolicy"),
        )?.body;
        const after = bodies.find(
          (b) =>
            b.direction === ">>>" && b.url.hostname === url.hostname && b.url.pathname === path,
        )?.body?.policy;
        if (
          Array.isArray(before?.bindings) &&
          Array.isArray(after?.bindings) &&
          before.bindings.every((binding) =>
            binding.members?.every((member) =>
              after.bindings.some(
                (b) =>
                  b.role === binding.role &&
                  JSON.stringify(b.condition) === JSON.stringify(binding.condition) &&
                  b.members?.includes(member),
              ),
            ),
          ) &&
          after.bindings.every((binding) =>
            binding.members?.every(
              (member) =>
                before.bindings.some(
                  (b) =>
                    b.role === binding.role &&
                    JSON.stringify(b.condition) === JSON.stringify(binding.condition) &&
                    b.members?.includes(member),
                ) ||
                (binding.condition === undefined &&
                  ((binding.role === "roles/iam.serviceAccountTokenCreator" &&
                    member ===
                      `serviceAccount:service-${m.projectNumber}@gcp-sa-pubsub.iam.gserviceaccount.com`) ||
                    (["roles/run.invoker", "roles/eventarc.eventReceiver"].includes(binding.role) &&
                      member ===
                        `serviceAccount:${m.projectNumber}-compute@developer.gserviceaccount.com`))),
            ),
          )
        )
          continue;
      }
      if (
        method === "POST" &&
        url.hostname === "serviceusage.googleapis.com" &&
        ["pubsub", "eventarc"].some(
          (api) =>
            path ===
            `/v1beta1/projects/${m.projectNumber}/services/${api}.googleapis.com:generateServiceIdentity`,
        )
      )
        continue;
      return { complete: false, resources, reason: "H undeclared CLI write" };
    }
    return {
      complete: ownCreate,
      function: { state: "unknown", name: full },
      resources,
      reason: ownCreate ? "declared FE-style write allowance" : "H missing native CLI CREATE",
    };
  },
  retention: async ({ manifest: m, result, recording, get }) => {
    const run = result ?? recording;
    if (!m || !run || !get) return { complete: false, atBaseline: false, resources: [] };
    const packages = await get(
      "artifact",
      `/v1/projects/${m.project}/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=100`,
      hProductionEvidence.readiness,
    );
    const complete =
      packages.status === 200 &&
      Object.keys(packages.body).length === 0 &&
      !(run.cleanup.unconfirmed ?? []).some((name) => name.startsWith("cli:"));
    return {
      complete,
      atBaseline: complete,
      resources: [
        "source staging objects until the existing cleanup policy",
        "logs",
        "build history",
        "approved IAM grants (ledger 304/312)",
        "eventarcpublishing.googleapis.com remains enabled",
      ],
    };
  },
});
