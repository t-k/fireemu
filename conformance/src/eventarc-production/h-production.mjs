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
    if (
      spec.host === "functions" &&
      spec.method === "POST" &&
      reply.status >= 400 &&
      reply.status < 500 &&
      recorded.status >= 400 &&
      recorded.status < 500 &&
      recorded.method === "POST" &&
      route(url) === route(actual) &&
      JSON.stringify(Object.keys(reply.body)) === '["error"]' &&
      JSON.stringify(Object.keys(recorded.body.error ?? {})) ===
        JSON.stringify(Object.keys(reply.body.error ?? {})) &&
      Object.keys(recorded.body.error ?? {}).every(
        (key) => typeof recorded.body.error[key] === typeof reply.body.error[key],
      ) &&
      reply.body.error.code === reply.status &&
      typeof reply.body.error.message === "string" &&
      reply.body.error.message.length > 0 &&
      /^[A-Z_]+$/.test(reply.body.error.status ?? "")
    )
      return true;
    if (
      recorded.run === "H1-v4" &&
      recorded.case === "source-refusal" &&
      spec.host === "functions" &&
      spec.method === "POST" &&
      reply.status === 400 &&
      route(url) === route(actual)
    ) {
      const normalized = (body) =>
        JSON.stringify(body)
          .replace(/projects\/[^/]+/g, "projects/<project>")
          .replace(/triggers\/[A-Za-z0-9._~-]+/g, "triggers/<name>");
      const expected = normalized(recorded.body).replaceAll(
        "'source'",
        `'${spec.refusalAttribute ?? "source"}'`,
      );
      return (
        reply.body.error?.message?.startsWith(
          `Validation failed for trigger ${actual.pathname.slice(4).replace(/\/functions$/, "/triggers/")}`,
        ) &&
        ["source", "tenant", "subject"].includes(spec.refusalAttribute ?? "source") &&
        expected === normalized(reply.body)
      );
    }
    const envelope =
      ["usage", "firestore", "logging"].includes(spec.host) ||
      (spec.host === "artifact" && actual.pathname.endsWith("/repositories/gcf-artifacts")) ||
      /\/(operations|channels)\//.test(actual.pathname) ||
      (spec.host === "eventarc" &&
        spec.method === "POST" &&
        actual.pathname.endsWith("/channels")) ||
      (spec.host === "functions" && ["POST", "DELETE"].includes(spec.method));
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
        (JSON.stringify(Object.keys(recorded.body.metadata)) ===
          JSON.stringify(Object.keys(reply.body.metadata ?? {})) &&
          Object.keys(recorded.body.metadata).every(
            (key) => typeof recorded.body.metadata[key] === typeof reply.body.metadata[key],
          ))) &&
      (recorded.body.done === undefined || recorded.body.done === reply.body.done);
    return (
      recorded.method === spec.method &&
      route(url) === route(actual) &&
      (url.search === actual.search ||
        (spec.host === "eventarc" &&
          spec.method === "POST" &&
          actual.pathname.endsWith("/channels") &&
          [...actual.searchParams.keys()].length === 1 &&
          actual.searchParams.get("channelId") === spec.body?.name?.split("/").at(-1) &&
          url.searchParams.has("channelId"))) &&
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
  publish: (reply, spec) =>
    spec?.host === "publishing" && spec.method === "POST" && hProductionAnswer(reply, spec),
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
    const descriptor = m.functions?.find((f) => f.name === name);
    const nativeRequest = bodies.find(
      (b) =>
        b.direction === ">>>" &&
        b.method === "POST" &&
        b.url.hostname === "cloudfunctions.googleapis.com" &&
        b.url.pathname.endsWith("/functions"),
    );
    let native;
    if (m.functions) {
      const request = nativeRequest?.body;
      const filters = Object.entries(descriptor?.filters ?? {}).map(([attribute, value]) => ({
        attribute,
        value,
      }));
      if (
        !descriptor ||
        request?.buildConfig?.runtime !== "nodejs22" ||
        request?.serviceConfig?.minInstanceCount !== 0 ||
        request?.serviceConfig?.maxInstanceCount !== 2 ||
        request?.name !== full ||
        request.eventTrigger?.eventType !== descriptor.type ||
        request.eventTrigger?.channel !== descriptor.channel ||
        request.eventTrigger?.retryPolicy !==
          (descriptor.retry ? "RETRY_POLICY_RETRY" : "RETRY_POLICY_DO_NOT_RETRY") ||
        !isDeepStrictEqual(request.eventTrigger?.eventFilters ?? [], filters)
      )
        return {
          complete: false,
          resources,
          reason: "H2 native filter/channel construction differs",
        };
      const issued = deployed.native?.filter(
        (r) =>
          r.kind === "cli-native-issued" &&
          r.value.host === "cloudfunctions.googleapis.com" &&
          r.value.method === "POST" &&
          r.value.path === `/v2/projects/${m.project}/locations/us-central1/functions`,
      );
      if (issued?.length !== 1)
        return { complete: false, resources, reason: "H2 requires one durable native CREATE" };
      const rows = deployed.native.filter(
        (r) => r.kind === "cli-native-answer" && r.value.id === issued[0].value.id,
      );
      const sent = deployed.native.find(
        (r) => r.kind === "cli-native-body" && r.value.id === issued[0].value.id,
      );
      if (rows.length !== 1 || !sent)
        return { complete: false, resources, reason: "H2 incomplete native CREATE capture" };
      const answer = rows[0].value;
      if (answer.unknown === true)
        return { complete: false, resources, reason: "H2 unknown native CREATE answer" };
      try {
        if (!isDeepStrictEqual(JSON.parse(Buffer.from(sent.value.bodyBase64, "base64")), request))
          return { complete: false, resources, reason: "H2 emitted request differs" };
        const bytes = Buffer.from(answer.bodyBase64, "base64");
        native = {
          status: answer.status,
          body: JSON.parse(bytes),
          bodyBase64: answer.bodyBase64,
          bodyBytes: bytes.length,
          request,
          requestBase64: sent.value.bodyBase64,
          requestBytes: Buffer.from(sent.value.bodyBase64, "base64").length,
        };
      } catch {
        return { complete: false, resources, reason: "H2 unreadable native answer" };
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
    const refusal =
      native?.status >= 400 &&
      native?.status < 500 &&
      !native.body.name &&
      !native.body.metadata &&
      hProductionAnswer(native, {
        host: "functions",
        method: "POST",
        path: `/v2/projects/${m.project}/locations/us-central1/functions`,
      });
    if (
      m.functions &&
      !refusal &&
      !hProductionAnswer(native, {
        host: "functions",
        method: "POST",
        path: `/v2/projects/${m.project}/locations/us-central1/functions`,
      })
    )
      return { complete: false, resources, native, reason: "H2 unadmitted native CREATE answer" };
    if (
      m.functions &&
      native.status >= 200 &&
      native.status < 300 &&
      (typeof native.body.name !== "string" ||
        !native.body.name.startsWith(`projects/${m.project}/locations/${m.location}/operations/`) ||
        native.body.metadata?.target !== full)
    )
      return { complete: false, resources, native, reason: "H2 CREATE operation target differs" };
    return {
      ...(m.functions ? { native, refusal } : {}),
      complete: ownCreate,
      function: {
        state: m.functions ? (refusal ? "failed" : "pending") : "unknown",
        name: full,
        ...(m.functions && !refusal ? { operation: native.body.name } : {}),
      },
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
