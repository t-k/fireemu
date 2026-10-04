// The cleanup, always after the passes (and after any stop that happened once something was created).
// It sweeps everything the run owns, whether or not a step's own deletes ran: the documents of the
// three collections, the run's Auth users (by uid and by email), every object generation in both
// buckets, the retry markers (after the functions are gone), the versioning setting, the 22 functions
// (one CLI delete), the two topics and the control bucket. Each sweep reads, deletes what the read
// shows once, and reads again; only an own complete 2xx read that shows nothing left counts as clean.
// The preflight required the run's namespaces to be empty, so whatever a read shows there is the run's.
// It never touches anything outside those namespaces (no Artifact Registry version, no staging object,
// no IAM binding) and never retries a delete. A step that cannot be verified makes the run
// `needs-recovery`; the recovery is a separate approval.

import { readLists, summarize } from "./deploy.mjs";
import { iamDiff, iamPairs } from "./preflight.mjs";
import {
  CONTROL_BUCKET,
  CONTROL_COLLECTION,
  MARKER_COLLECTION,
  PRIMARY_BUCKET,
  PRIMARY_COLLECTION,
  PROJECT,
  REGION,
} from "./script.mjs";

const documents = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
const identity = `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}`;
const bucketUrl = (bucket) =>
  `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}`;
const read = (id, url, expect = [200], extra = {}) => ({
  id: `cleanup.${id}`,
  role: "cleanup-read",
  method: "GET",
  url,
  auth: "oauth",
  mutation: false,
  expect,
  ...extra,
});
const write = (id, spec) => ({
  id: `cleanup.${id}`,
  role: "cleanup",
  auth: "oauth",
  mutation: true,
  expect: [200, 204, 404],
  ...spec,
});
const readPost = (id, url, body) => ({ ...read(id, url), method: "POST", body });

export const DELETE_POLLS = 6;
export const DELETE_POLL_SECONDS = 30;
export const SWEEP_LIMIT = 100;

async function safely(steps, name, body) {
  try {
    const result = await body();
    steps[name] = { ok: result?.ok !== false, ...result };
  } catch (error) {
    // The guard, the ceiling and the credential end the cleanup too: nothing more may be sent.
    if (error?.constructor?.name !== "Error" && error?.constructor?.name !== "TypeError")
      throw error;
    steps[name] = { ok: false, error: error.message };
  }
  return steps[name];
}

const listedObjects = (json) =>
  (json?.items ?? []).map((item) => ({ name: item.name, generation: item.generation }));
const objectUrl = (bucket, name, generation) =>
  `${bucketUrl(bucket)}/o/${encodeURIComponent(name)}?generation=${generation}`;
const documentNames = (json) =>
  (Array.isArray(json) ? json : []).map((row) => row?.document?.name).filter(Boolean);

/** Reads the documents of one collection; `complete` only for an own 2xx answer that is a list. */
async function queryCollection(request, id, collection) {
  const answer = await request(
    readPost(id, `${documents}:runQuery`, {
      structuredQuery: { from: [{ collectionId: collection }], limit: SWEEP_LIMIT },
    }),
  );
  return {
    complete: answer.kind === "success" && Array.isArray(answer.json),
    names: documentNames(answer.json),
  };
}

/** Reads the users of the run by uid and by email: the users that still exist. */
async function lookupUsers(request, id, owned) {
  const found = new Set();
  let complete = true;
  for (const [kind, key, values] of [
    ["uids", "localId", [...owned.uids]],
    ["emails", "email", [...owned.emails]],
  ]) {
    if (values.length === 0) continue;
    const answer = await request(
      readPost(`${id}-${kind}`, `${identity}/accounts:lookup`, { [key]: values }),
    );
    if (answer.kind !== "success") {
      complete = false;
      continue;
    }
    for (const user of answer.json?.users ?? []) if (user?.localId) found.add(user.localId);
  }
  return { complete, uids: [...found] };
}

/**
 * `cli("delete")` is the one CLI delete of the 22 handlers. `ran` says how far the run got, so a run
 * that stopped before the deploy does not send a delete for functions that were never deployed.
 * `owned` lists what the run made or may have made: `uids`, `emails` (Sets).
 */
export async function runCleanup({
  transport,
  cli,
  sleep,
  ran,
  iamBefore = null,
  servicesBefore = null,
  owned = { uids: new Set(), emails: new Set() },
}) {
  const steps = {};
  const request = (spec, vars) => transport.request(spec, vars);

  // 1. Objects of the run in both buckets, every generation (a list is followed to its end).
  for (const [label, bucket] of [
    ["primary", PRIMARY_BUCKET],
    ["control", CONTROL_BUCKET],
  ]) {
    await safely(steps, `objects-${label}`, async () => {
      let removed = 0;
      let left = 0;
      for (const prefix of ["fe-events/", "other/"]) {
        const listUrl = `${bucketUrl(bucket)}/o?versions=true&prefix=${encodeURIComponent(prefix)}`;
        const answer = await request(read(`objects-${label}`, listUrl, [200, 404]));
        if (answer.status === 404 && answer.kind === "refusal")
          return { ok: label === "control", missing: true };
        if (answer.kind !== "success" || answer.json?.nextPageToken)
          return { ok: false, unreadable: true };
        for (const { name, generation } of listedObjects(answer.json).slice(0, SWEEP_LIMIT)) {
          const gone = await request(
            write(`object-delete-${label}`, {
              method: "DELETE",
              url: objectUrl(bucket, name, generation),
            }),
          );
          if (gone.kind === "unknown") left += 1;
          else removed += 1;
        }
        const after = await request(read(`objects-${label}-after`, listUrl));
        left +=
          after.kind === "success" && !after.json?.nextPageToken
            ? listedObjects(after.json).length
            : 1;
      }
      return { ok: left === 0, removed, left };
    });
  }

  // 2. Versioning of the primary bucket back to what it was (the preflight required it to be off).
  await safely(steps, "versioning", async () => {
    const answer = await request(
      read("versioning", `${bucketUrl(PRIMARY_BUCKET)}?fields=versioning`),
    );
    if (answer.kind !== "success") return { ok: false, unreadable: true };
    if (answer.json?.versioning?.enabled !== true) return { ok: true, restored: false };
    await request(
      write("versioning-restore", {
        method: "PATCH",
        url: `${bucketUrl(PRIMARY_BUCKET)}?fields=versioning`,
        body: { versioning: { enabled: false } },
      }),
    );
    const after = await request(
      read("versioning-after", `${bucketUrl(PRIMARY_BUCKET)}?fields=versioning`),
    );
    return {
      ok: after.kind === "success" && after.json?.versioning?.enabled !== true,
      restored: true,
    };
  });

  // 3. Documents of the two collections: read, delete what is shown, read again.
  await safely(steps, "documents", async () => {
    let removed = 0;
    let left = 0;
    for (const collection of [PRIMARY_COLLECTION, CONTROL_COLLECTION]) {
      const first = await queryCollection(request, `documents-${collection}`, collection);
      if (!first.complete) return { ok: false, unreadable: collection };
      for (const name of first.names) {
        const gone = await request(
          write("document-delete", {
            method: "DELETE",
            url: `https://firestore.googleapis.com/v1/${name}`,
          }),
        );
        if (gone.kind !== "unknown") removed += 1;
      }
      if (first.names.length > 0) {
        const after = await queryCollection(request, `documents-${collection}-after`, collection);
        left += after.complete ? after.names.length : SWEEP_LIMIT;
      }
    }
    return { ok: left === 0, removed, left };
  });

  // 4. The run's Auth users, by uid and by email (a sign-up whose answer was lost may have made one).
  await safely(steps, "users", async () => {
    const first = await lookupUsers(request, "users", owned);
    if (!first.complete) return { ok: false, unreadable: true };
    let removed = 0;
    for (const uid of first.uids) {
      const gone = await request(
        write("user-delete", {
          method: "POST",
          url: `${identity}/accounts:delete`,
          body: { localId: uid },
        }),
      );
      if (gone.kind !== "unknown") removed += 1;
    }
    if (first.uids.length === 0) return { ok: true, removed };
    const after = await lookupUsers(request, "users-after", owned);
    return { ok: after.complete && after.uids.length === 0, removed, left: after.uids.length };
  });

  // 5. The one CLI delete of the functions, then the lists until they are empty.
  await safely(steps, "functions", async () => {
    if (!ran.deployStarted) return { ok: true, skipped: "the deploy was never started" };
    const result = await cli("delete");
    let summary;
    for (let i = 1; i <= DELETE_POLLS; i += 1) {
      summary = summarize(await readLists(transport));
      if (summary.absent) return { ok: true, cli: result, polls: i, summary };
      if (i < DELETE_POLLS) await sleep(DELETE_POLL_SECONDS);
    }
    return { ok: false, cli: result, polls: DELETE_POLLS, summary };
  });

  // 6. Retry markers, after the functions are gone (a late retry can no longer write one), read back.
  await safely(steps, "markers", async () => {
    const first = await queryCollection(request, "markers", MARKER_COLLECTION);
    if (!first.complete) return { ok: false, unreadable: true };
    for (const name of first.names)
      await request(
        write("marker-delete", {
          method: "DELETE",
          url: `https://firestore.googleapis.com/v1/${name}`,
        }),
      );
    if (first.names.length === 0) return { ok: true, found: 0 };
    const after = await queryCollection(request, "markers-after", MARKER_COLLECTION);
    return {
      ok: after.complete && after.names.length === 0,
      found: first.names.length,
      left: after.names.length,
    };
  });

  // 7. Topics (after the functions that listen to them), then what is left of them.
  await safely(steps, "topics", async () => {
    for (const topic of ["fe-events-primary", "fe-events-control"]) {
      await request(
        write(`topic-delete-${topic}`, {
          method: "DELETE",
          url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${topic}`,
          expect: [200, 404],
        }),
      );
    }
    const topics = await request(
      read("topics", `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=100`),
    );
    const subscriptions = await request(
      read(
        "subscriptions",
        `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=100`,
      ),
    );
    const names = new Set((topics.json?.topics ?? []).map((t) => t.name.split("/").at(-1)));
    const left = ["fe-events-primary", "fe-events-control"].filter((t) => names.has(t));
    const complete = topics.kind === "success" && !topics.json?.nextPageToken;
    return {
      ok: complete && left.length === 0,
      left,
      subscriptions: (subscriptions.json?.subscriptions ?? []).map((s) =>
        s.name?.split("/").at(-1),
      ),
    };
  });

  // 8. The control bucket the run created: deleted, then a complete list that shows it gone.
  await safely(steps, "control-bucket", async () => {
    await request(
      write("control-bucket-delete", {
        method: "DELETE",
        url: bucketUrl(CONTROL_BUCKET),
        expect: [204, 404],
      }),
    );
    const after = await request(
      read(
        "control-bucket-after",
        `https://storage.googleapis.com/storage/v1/b?project=${PROJECT}&prefix=${encodeURIComponent(CONTROL_BUCKET)}`,
      ),
    );
    return {
      ok:
        after.kind === "success" &&
        !after.json?.nextPageToken &&
        (after.json?.items ?? []).length === 0,
    };
  });

  // 9. What the deploy left behind is only read and reported (the repository has a one-day cleanup policy).
  await safely(steps, "inventory", async () => {
    const packages = await request(
      read(
        "artifact-packages",
        `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages?pageSize=100`,
        [200, 404],
      ),
    );
    const iam = await request({
      ...readPost(
        "iam",
        `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
        {},
      ),
    });
    const services = await request(
      read(
        "services",
        `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services?filter=state:ENABLED&pageSize=200`,
      ),
    );
    const after = new Set((services.json?.services ?? []).map((s) => s?.config?.name));
    const before = servicesBefore ? new Set(servicesBefore) : null;
    return {
      ok: true,
      packages: (packages.json?.packages ?? []).map((p) => p.name?.split("/").at(-1)),
      iamBindings: iam.json?.bindings?.length ?? null,
      iamDiff: iamBefore && iam.kind === "success" ? iamDiff(iamBefore, iam.json) : null,
      iamAfter: iam.kind === "success" ? iamPairs(iam.json) : null,
      apiDiff:
        before && services.kind === "success"
          ? {
              added: [...after].filter((n) => !before.has(n)),
              removed: [...before].filter((n) => !after.has(n)),
            }
          : null,
    };
  });

  const problems = Object.entries(steps)
    .filter(([, s]) => !s.ok)
    .map(
      ([name, s]) => `${name}: ${s.error ?? JSON.stringify({ ...s, ok: undefined }).slice(0, 200)}`,
    );
  return { steps, verified: problems.length === 0, problems };
}
