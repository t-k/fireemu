// A fake of the Google APIs the CV14 run touches besides the RTDB: Cloud Functions (v1 and v2), Cloud
// Run, Artifact Registry, Eventarc, Pub/Sub, Cloud Logging, Cloud Storage (through the shared fake), and a
// stand-in for the Firebase CLI that creates and, on request, leaves behind what a deploy makes. The
// integration test runs the real flow, operations and judge against it. Shapes follow the FE v4 records
// (function records, Eventarc trigger and topic names) and the stage 1 and FE debug lines.

import {
  FAKE_BUCKET,
  FAKE_PROJECT_NUMBER,
  createFakeGcs,
} from "../shared/gen2-source-uploads.fake.mjs";
import { uploadEventFromLine } from "../shared/gen2-source-uploads.mjs";
import { PROJECT } from "../../functions-http/harness.mjs";
import { targetResources } from "../../functions-http/production.mjs";
import { FIXTURE_HANDLERS, FRAME_MARKER, LOCATION } from "./frames.mjs";
import { origin } from "./logs.mjs";
import { CODEBASE, TARGETS } from "./targets.mjs";
import { documentedFires } from "./sequence.mjs";

const HANDLER = new Map(FIXTURE_HANDLERS.map((h) => [h.name, h]));
const SPEC = new Map(TARGETS.map((t) => [t.functionName, t]));
const GEN2_NAMES = TARGETS.filter((t) => t.generation === "gcfv2").map((t) => t.functionName);
const REGION_PATH = `projects/${PROJECT}/locations/${LOCATION}`;
const DIGEST = `sha256:${"ab".repeat(32)}`;

/** The frame a handler prints for an item going from `before` to `after` (the fixture's own shape). */
export function frameForTransition(handlerName, id, before, after, extra = {}) {
  const handler = HANDLER.get(handlerName);
  const snap = (value) => ({ exists: value !== null, key: id, value });
  const data =
    handler.event === "create"
      ? snap(after)
      : handler.event === "delete"
        ? snap(before)
        : { before: snap(before), after: snap(after) };
  const eventId = extra.eventId ?? `ev-${handlerName}-${id}-${extra.seq ?? 1}`;
  return {
    handler: handlerName,
    generation: handler.generation,
    seq: extra.seq ?? 1,
    receivedAt: extra.receivedAt ?? "2026-10-27T00:00:05.000Z",
    event:
      handler.generation === 1
        ? { context: { eventId, params: { id } }, data }
        : { id: eventId, params: { id }, data },
  };
}

const reply = (status, value = {}) => ({ status, value, bytes: 10 });
const lowerOf = (name) => name.toLowerCase();

/**
 * Options: failDeploy (a function name), leaveTrigger (keep the Eventarc trigger and topic after the
 * function delete), keepImage (keep the image after the function delete), loggingState, dropEvents and
 * duplicateEvents (Sets of handler names), foreignFunctions (names present before the run), clock.
 */
export function createGcpWorld({ budget, clock, options = {} }) {
  const gcs = createFakeGcs();
  const w = {
    gcs,
    functions: new Map(),
    packages: new Map(),
    triggers: new Set(options.foreignTriggers ?? []),
    topics: new Set(options.foreignTopics ?? []),
    foreignFunctions: new Set(options.foreignFunctions ?? []),
    logEntries: [],
    requests: [],
    deploys: [],
    deleted: [],
    bindings: new Map(),
    opN: 0,
    insertN: 0,
    eventN: 0,
    uploadN: 0,
  };

  const fnResource = (name) => `${REGION_PATH}/functions/${name}`;
  const triggerOf = (name) => `${REGION_PATH}/triggers/${lowerOf(name)}-494903`;
  const topicOf = (name) =>
    `projects/${PROJECT}/topics/eventarc-${LOCATION}-${lowerOf(name)}-494903-679`;

  function gen2Record(name) {
    const spec = SPEC.get(name);
    return {
      name: fnResource(name),
      environment: "GEN_2",
      state: "ACTIVE",
      buildConfig: { runtime: spec.runtime, entryPoint: spec.entryPoint },
      serviceConfig: {
        service: `${REGION_PATH}/services/${lowerOf(name)}`,
        uri: `https://${lowerOf(name)}-xei277hwaa-uc.a.run.app`,
      },
      labels: { "deployment-tool": "cli-firebase", "firebase-functions-codebase": CODEBASE },
      eventTrigger: {
        trigger: triggerOf(name),
        triggerRegion: LOCATION,
        eventType: "google.firebase.database.ref.v1.written",
        pubsubTopic: topicOf(name),
      },
    };
  }
  function gen1Record(name) {
    const spec = SPEC.get(name);
    return {
      name: fnResource(name),
      status: "ACTIVE",
      entryPoint: spec.entryPoint,
      runtime: spec.runtime,
      labels: { "firebase-functions-codebase": CODEBASE, "deployment-tool": "cli-firebase" },
      eventTrigger: {
        eventType: "providers/google.firebase.database/eventTypes/ref.write",
        resource: "projects/_/instances/x/refs/cv14-rtdb/items/{id}",
        service: "firebaseio.com",
      },
      sourceUploadUrl:
        "https://storage.googleapis.com/uploads-100000000001.us-central1.cloudfunctions.appspot.com",
    };
  }

  const packageOf = (name) => targetResources(SPEC.get(name)).packageName;
  const serviceOf = (name) => `${REGION_PATH}/services/${lowerOf(name)}`;

  function removeFunction(name) {
    const entry = w.functions.get(name);
    w.functions.delete(name);
    w.deleted.push(name);
    if (entry.gen === 2) {
      w.bindings.delete(name);
      if (!options.leaveTrigger) {
        w.triggers.delete(triggerOf(name));
        w.topics.delete(topicOf(name));
      }
      if (!options.keepImage) w.packages.delete(name);
    }
  }

  function list(items, key, query) {
    const token = new URL(query).searchParams.get("pageToken");
    const start = token ? Number(token) : 0;
    const page = items.slice(start, start + 100);
    return reply(200, {
      [key]: page,
      ...(start + 100 < items.length ? { nextPageToken: String(start + 100) } : {}),
    });
  }

  function route(method, url, body) {
    const u = new URL(url);
    const path = u.pathname;
    if (u.host === "storage.googleapis.com") return gcs.send(method, url);
    if (u.host === "serviceusage.googleapis.com") {
      if (path.endsWith("/services/logging.googleapis.com")) {
        return reply(200, { state: options.loggingState ?? "ENABLED" });
      }
      return reply(200, {
        services: [
          "cloudfunctions",
          "cloudbuild",
          "artifactregistry",
          "run",
          "eventarc",
          "pubsub",
          "storage",
          "firebaseextensions",
        ].map((n) => ({ config: { name: `${n}.googleapis.com` } })),
      });
    }
    if (u.host === "firebase.googleapis.com") return reply(200, { projectId: PROJECT });
    if (u.host === "cloudresourcemanager.googleapis.com") return reply(200, { bindings: [] });
    if (u.host === "logging.googleapis.com")
      return reply(200, { entries: w.logEntries.slice(0, 200) });
    if (u.host === "eventarc.googleapis.com") {
      if (path.endsWith("/triggers"))
        return list(
          [...w.triggers].toSorted().map((name) => ({ name })),
          "triggers",
          url,
        );
      if (path.includes("/operations/")) return reply(200, { name: path.slice(4), done: true });
      if (method === "DELETE") {
        w.triggers.delete(path.slice(4));
        return reply(200, { name: `${REGION_PATH}/operations/ea-${++w.opN}`, done: false });
      }
    }
    if (u.host === "pubsub.googleapis.com") {
      if (path.endsWith("/topics"))
        return list(
          [...w.topics].toSorted().map((name) => ({ name })),
          "topics",
          url,
        );
      if (path.endsWith("/subscriptions")) return list([], "subscriptions", url);
      if (method === "DELETE") {
        w.topics.delete(path.slice(4));
        return reply(200, {});
      }
    }
    if (u.host === "cloudfunctions.googleapis.com") {
      const functionMatch = new RegExp(`^/v([12])/${REGION_PATH}/functions/([^/]+)$`, "u").exec(
        path,
      );
      const listMatch = new RegExp(`^/v2/${REGION_PATH}/functions$`, "u").exec(path);
      if (listMatch) {
        const names = [...w.functions.keys(), ...w.foreignFunctions].toSorted();
        return list(
          names.map((n) => ({
            name: fnResource(n),
            labels: w.functions.get(n) ? gen2Record(n).labels : {},
          })),
          "functions",
          url,
        );
      }
      if (path.startsWith("/v1/operations/"))
        return reply(200, { name: path.slice(4), done: true });
      if (/^\/v2\/projects\/.*\/operations\//u.test(path))
        return reply(200, { name: path.slice(4), done: true });
      if (functionMatch) {
        const [, version, name] = functionMatch;
        const entry = w.functions.get(name);
        if (method === "GET") {
          if (!entry || String(entry.gen) !== version) return reply(404);
          return reply(200, entry.gen === 2 ? gen2Record(name) : gen1Record(name));
        }
        if (method === "DELETE") {
          if (!entry || String(entry.gen) !== version) return reply(404);
          removeFunction(name);
          return version === "1"
            ? reply(200, {
                name: `operations/op${++w.opN}`,
                metadata: { target: fnResource(name) },
                done: false,
              })
            : reply(200, { name: `${REGION_PATH}/operations/op${++w.opN}`, done: false });
        }
      }
    }
    if (u.host === "run.googleapis.com") {
      if (path === `/v2/${REGION_PATH}/services`) {
        const names = [...w.functions].filter(([, e]) => e.gen === 2).map(([n]) => lowerOf(n));
        return list(
          names.toSorted().map((n) => ({ name: `${REGION_PATH}/services/${n}` })),
          "services",
          url,
        );
      }
      const m = new RegExp(
        `^/v2/${REGION_PATH}/services/([^/:]+)(:getIamPolicy|:setIamPolicy)?$`,
        "u",
      ).exec(path);
      if (m) {
        const name = [...w.functions.keys()].find((n) => lowerOf(n) === m[1]);
        const entry = name && w.functions.get(name);
        if (!entry || entry.gen !== 2) return reply(404);
        if (m[2] === ":getIamPolicy") return reply(200, { bindings: w.bindings.get(name) ?? [] });
        if (m[2] === ":setIamPolicy") {
          w.bindings.set(name, body.policy.bindings);
          return reply(200, body.policy);
        }
        return reply(200, {
          name: serviceOf(name),
          template: {
            containers: [{ image: `${targetResources(SPEC.get(name)).imagePrefix}@${DIGEST}` }],
          },
        });
      }
    }
    if (u.host === "artifactregistry.googleapis.com") {
      if (path === `/v1/${REGION_PATH}/repositories/gcf-artifacts`) {
        return reply(200, {
          name: `${REGION_PATH}/repositories/gcf-artifacts`,
          format: "DOCKER",
          mode: "STANDARD_REPOSITORY",
          cleanupPolicies: {
            "firebase-functions-cleanup": {
              id: "firebase-functions-cleanup",
              action: "DELETE",
              condition: { tagState: "ANY", olderThan: "86400s" },
            },
          },
        });
      }
      const name = GEN2_NAMES.find((n) => path.startsWith(`/v1/${packageOf(n)}`));
      if (name) {
        const pkg = packageOf(name);
        const hasImage = w.packages.has(name);
        if (path === `/v1/${pkg}`) return hasImage ? reply(200, { name: pkg }) : reply(404);
        if (path === `/v1/${pkg}%2Fcache`) return reply(404);
        if (path === `/v1/${pkg}/versions`) {
          return reply(200, hasImage ? { versions: [{ name: `${pkg}/versions/${DIGEST}` }] } : {});
        }
        if (path === `/v1/${pkg}/versions/${DIGEST}`) {
          if (method === "DELETE") {
            w.packages.delete(name);
            return reply(200, {});
          }
          return hasImage ? reply(200, { name: `${pkg}/versions/${DIGEST}` }) : reply(404);
        }
      }
      if (path.includes("/packages/") && method === "GET") return reply(404);
    }
    throw new Error(`unexpected request ${method} ${url}`);
  }

  /** The control client the run uses: counted against the budget like the real one, statuses checked. */
  w.control = async (method, url, body, kind = "control", allowed = [200]) => {
    budget.take(kind);
    w.requests.push({ method, url, kind });
    const result = await route(method, url, body);
    if (allowed !== "any" && !allowed.includes(result.status)) {
      throw new Error(`bounded ${kind} REST ${method} returned ${result.status}`);
    }
    return result;
  };

  /** The Firebase CLI: creates what a deploy makes, prints the debug lines the helper reads. */
  w.runCli = async (args, _adc, cliBudget, kind, _runDir, track) => {
    cliBudget.take(kind);
    const only = args[args.indexOf("--only") + 1] ?? "";
    const [, codebase, name] = only.split(":");
    const spec = SPEC.get(name);
    if (kind !== "cliDeploy" || args[0] !== "deploy" || !spec || codebase !== CODEBASE) {
      throw new Error(`unexpected CLI call ${args.join(" ")}`);
    }
    w.deploys.push(name);
    const lines = [];
    if (spec.generation === "gcfv2") {
      const object = `${String(++w.uploadN).padStart(8, "0")}-1111-4222-8333-444444444444.zip`;
      gcs.put(object);
      lines.push(
        `[2026-10-27T00:00:01.000Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/${REGION_PATH}/functions:generateUploadUrl ${JSON.stringify({ uploadUrl: `https://storage.googleapis.com/${FAKE_BUCKET}/${object}?X-Goog-Signature=SECRET-MARKER`, storageSource: { bucket: FAKE_BUCKET, object } })}`,
        `[2026-10-27T00:00:02.000Z] <<< [apiv2][status] PUT https://storage.googleapis.com/${FAKE_BUCKET}/${object} 200`,
      );
    } else {
      const object = `${String(++w.uploadN).padStart(8, "0")}-5555-4666-8777-888888888888.zip`;
      const bucket = "uploads-100000000001.us-central1.cloudfunctions.appspot.com";
      lines.push(
        `[2026-10-27T00:00:01.000Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v1/${REGION_PATH}/functions:generateUploadUrl ${JSON.stringify({ uploadUrl: `https://storage.googleapis.com/${bucket}/${object}?GoogleAccessId=sa&Signature=SECRET-MARKER` })}`,
        `[2026-10-27T00:00:02.000Z] <<< [apiv2][status] PUT https://storage.googleapis.com/${bucket}/${object} 200`,
      );
    }
    for (const line of lines) {
      const event = uploadEventFromLine(line);
      if (event) track.onEvent(event, line);
    }
    if (options.failDeploy === name) {
      track.exited = true;
      track.exitCode = 1;
      const failure = new Error("cliDeploy failed or attempted API enablement (exit 1)");
      failure.indeterminate = true;
      // the CLI got far enough to create the function before it failed
      w.functions.set(name, { gen: spec.generation === "gcfv2" ? 2 : 1 });
      throw failure;
    }
    w.functions.set(name, { gen: spec.generation === "gcfv2" ? 2 : 1 });
    if (spec.generation === "gcfv2") {
      w.packages.set(name, true);
      w.triggers.add(triggerOf(name));
      w.topics.add(topicOf(name));
    }
    track.exited = true;
    track.exitCode = 0;
    return { exitCode: 0 };
  };

  /** What the platform does for an item that changed: a frame in the log for each handler it delivers to. */
  w.deliver = (id, before, after) => {
    for (const name of w.functions.keys()) {
      const handler = HANDLER.get(name);
      if (!handler || !documentedFires(handler.event, before, after)) continue;
      if (options.dropEvents?.has(name)) continue;
      // a redelivery prints the same event id again, in a new log entry
      const eventId = `ev-${name}-${id}-${++w.eventN}`;
      const copies = options.duplicateEvents?.has(name) ? 2 : 1;
      for (let copy = 0; copy < copies; copy += 1) {
        const at = new Date(clock.now()).toISOString();
        const frame = frameForTransition(name, id, before, after, {
          seq: ++w.insertN,
          eventId,
          receivedAt: at,
        });
        const o = origin(handler);
        w.logEntries.push({
          logName: o.logName,
          resource: { type: o.resourceType, labels: o.labels },
          insertId: `ins-${++w.insertN}`,
          timestamp: at,
          textPayload: `${FRAME_MARKER}${JSON.stringify(frame)}`,
        });
      }
    }
  };

  w.projectNumber = FAKE_PROJECT_NUMBER;
  return w;
}
