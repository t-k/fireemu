import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

const recordings = ["v7-replay", "stage-c-replay"].flatMap((name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/h-fe/${name}.json`, import.meta.url), "utf8")),
);

/** Exact recorded answers only. New bodies and unobserved routes require review. */
export function hProductionAnswer(reply, spec) {
  if (!spec || reply?.unknown || !Number.isInteger(reply?.status)) return false;
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
    return (
      recorded.method === spec.method &&
      route(url) === route(actual) &&
      url.search === actual.search &&
      recorded.status === reply.status &&
      isDeepStrictEqual(recorded.body, reply.body) &&
      JSON.stringify(recorded.body) === JSON.stringify(reply.body)
    );
  });
}

/** Replay pins are evidence, not permission to infer H CLI writes or retention. */
export const hProductionEvidence = Object.freeze({
  preflight: (reply, spec) => spec?.method === "GET" && hProductionAnswer(reply, spec),
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
  cliWrites: () => ({
    complete: false,
    resources: [],
    reason: "needs-review: H CLI write inventory is unobserved",
  }),
  retention: async () => ({
    complete: false,
    atBaseline: false,
    resources: [],
    reason: "needs-review: H retention readback is unobserved",
  }),
});
