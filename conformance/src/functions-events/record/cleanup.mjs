// The cleanup, always after the passes (and after any stop that happened once something was created).
// It removes what the run owns, in an order that keeps the functions' own events out of the way, and
// reads everything back. It never deletes anything it does not own (no Artifact Registry version, no
// staging object, no IAM binding) and never retries a delete. A step that cannot be verified makes the
// run `needs-recovery`; the recovery is a separate approval.

import { readLists, summarize } from "./deploy.mjs";
import { iamDiff, iamPairs } from "./preflight.mjs";
import { CONTROL_BUCKET, MARKER_COLLECTION, PRIMARY_BUCKET, PROJECT, REGION } from "./script.mjs";

const documents = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
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

export const DELETE_POLLS = 6;
export const DELETE_POLL_SECONDS = 30;

async function safely(steps, name, body) {
  try {
    const result = await body();
    steps[name] = { ok: result?.ok !== false, ...result };
  } catch (error) {
    steps[name] = { ok: false, error: error.message };
  }
  return steps[name];
}

const listedObjects = (json) =>
  (json?.items ?? []).map((item) => ({ name: item.name, generation: item.generation }));
const objectUrl = (bucket, name, generation) =>
  `${bucketUrl(bucket)}/o/${encodeURIComponent(name)}?generation=${generation}`;

/**
 * `cli("delete")` is the one CLI delete of the 22 handlers. `ran` says how far the run got, so a run
 * that stopped before the deploy does not send a delete for functions that were never deployed.
 */
export async function runCleanup({ transport, cli, sleep, ran, iamBefore = null }) {
  const steps = {};
  const request = (spec, vars) => transport.request(spec, vars);

  // 1. Retry markers left by the fail-once handler.
  await safely(steps, "markers", async () => {
    const answer = await request({
      ...read("markers", `${documents}:runQuery`, [200]),
      method: "POST",
      body: { structuredQuery: { from: [{ collectionId: MARKER_COLLECTION }], limit: 20 } },
    });
    const names = (Array.isArray(answer.json) ? answer.json : [])
      .map((row) => row?.document?.name)
      .filter(Boolean);
    for (const markerName of names)
      await request(
        write("marker-delete", {
          method: "DELETE",
          url: "https://firestore.googleapis.com/v1/${markerName}",
        }),
        { markerName },
      );
    return { ok: answer.kind === "success", found: names.length };
  });

  // 2. Objects of the run in both buckets, every generation.
  for (const [label, bucket] of [
    ["primary", PRIMARY_BUCKET],
    ["control", CONTROL_BUCKET],
  ]) {
    await safely(steps, `objects-${label}`, async () => {
      let removed = 0;
      let left = 0;
      for (const prefix of ["fe-events/", "other/"]) {
        const answer = await request(
          read(
            `objects-${label}`,
            `${bucketUrl(bucket)}/o?versions=true&prefix=${encodeURIComponent(prefix)}`,
            [200, 404],
          ),
        );
        if (answer.status === 404) return { ok: label === "control", missing: true };
        if (answer.kind !== "success") return { ok: false, unreadable: true };
        for (const { name, generation } of listedObjects(answer.json).slice(0, 20)) {
          const gone = await request(
            write(`object-delete-${label}`, {
              method: "DELETE",
              url: objectUrl(bucket, name, generation),
            }),
          );
          removed += gone.kind === "unknown" ? 0 : 1;
          if (gone.kind === "unknown") left += 1;
        }
        const after = await request(
          read(
            `objects-${label}-after`,
            `${bucketUrl(bucket)}/o?versions=true&prefix=${encodeURIComponent(prefix)}`,
          ),
        );
        left += after.kind === "success" ? listedObjects(after.json).length : 1;
      }
      return { ok: left === 0, removed, left };
    });
  }

  // 3. Versioning of the primary bucket back to what it was (the preflight required it to be off).
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

  // 4. The one CLI delete of the functions, then the lists until they are empty.
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

  // 5. Topics (after the functions that listen to them), then what is left of them.
  await safely(steps, "topics", async () => {
    for (const topic of ["fe-events-primary", "fe-events-control"])
      await request(
        write(`topic-delete-${topic}`, {
          method: "DELETE",
          url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${topic}`,
          expect: [200, 404],
        }),
      );
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
    return {
      ok: topics.kind === "success" && left.length === 0,
      left,
      subscriptions: (subscriptions.json?.subscriptions ?? []).map((s) =>
        s.name?.split("/").at(-1),
      ),
    };
  });

  // 6. The control bucket the run created.
  await safely(steps, "control-bucket", async () => {
    await request(
      write("control-bucket-delete", {
        method: "DELETE",
        url: bucketUrl(CONTROL_BUCKET),
        expect: [204, 404],
      }),
    );
    const after = await request(
      read("control-bucket-after", `${bucketUrl(CONTROL_BUCKET)}?fields=versioning`, [404]),
    );
    return { ok: after.status === 404 };
  });

  // 7. What the deploy left behind is only read and reported (the repository has a one-day cleanup policy).
  await safely(steps, "inventory", async () => {
    const packages = await request(
      read(
        "artifact-packages",
        `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages?pageSize=100`,
        [200, 404],
      ),
    );
    const iam = await request({
      ...read(
        "iam",
        `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      ),
      method: "POST",
      body: {},
    });
    return {
      ok: true,
      packages: (packages.json?.packages ?? []).map((p) => p.name?.split("/").at(-1)),
      iamBindings: iam.json?.bindings?.length ?? null,
      iamDiff: iamBefore && iam.kind === "success" ? iamDiff(iamBefore, iam.json) : null,
      iamAfter: iam.kind === "success" ? iamPairs(iam.json) : null,
    };
  });

  const problems = Object.entries(steps)
    .filter(([, s]) => !s.ok)
    .map(
      ([name, s]) => `${name}: ${s.error ?? JSON.stringify({ ...s, ok: undefined }).slice(0, 200)}`,
    );
  return { steps, verified: problems.length === 0, problems };
}
