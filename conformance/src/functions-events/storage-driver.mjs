import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { resourceId } from "./resource-id.mjs";

const primaryBucket = "demo-conformance-events-primary";
const controlBucket = "demo-conformance-events-control";

function loopbackStorageHost(host) {
  const match = /^(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$/.exec(host ?? "");
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) {
    throw new Error("a loopback Storage emulator host and port are required");
  }
  return host;
}

function isMissing(error) {
  return Number(error?.code) === 404 || Number(error?.statusCode) === 404;
}

async function metadataOrNull(file) {
  try {
    const [metadata] = await file.getMetadata();
    return metadata;
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

async function ownedGenerations(bucket, name) {
  const [files] = await bucket.getFiles({ prefix: name, versions: true, autoPaginate: true });
  return files.filter((file) => file.name === name);
}

async function deleteOwnedGenerations(bucket, name) {
  const generations = await ownedGenerations(bucket, name);
  for (const file of generations) {
    try {
      await file.delete({ ignoreNotFound: true });
    } catch (error) {
      if (!isMissing(error)) throw error;
    }
  }
  return (await ownedGenerations(bucket, name)).length === 0;
}

async function waitForSeed(capture, cursor, bucket, name) {
  const deadline = Date.now() + 5000;
  while (Date.now() <= deadline) {
    await capture.barrier();
    const frames = capture.since(cursor).map(({ frame }) => frame);
    if (
      ["storageFinalizedV1", "storageFinalizedV2"].every((handler) =>
        frames.some(
          (frame) =>
            frame.handler === handler &&
            frame.event?.data?.bucket === bucket &&
            frame.event?.data?.name === name,
        ),
      )
    )
      return;
    await delay(25);
  }
  throw new Error("Storage seed event did not drain before source mutation");
}

/**
 * The refused write of the failed-upload scenario, the one the production script sends: the same object, ifGenerationMatch=1
 * (a real generation is never 1, so production answers 412 and changes nothing), a short body of its own and no extra header.
 * It answers what the profile did: a 4xx is a typed refusal, a 2xx a typed success (the official emulator ignores upload
 * preconditions and completes the write); any other status is an error.
 */
export async function attemptPreconditionUpload({ host, bucket, name, request = fetch }) {
  loopbackStorageHost(host);
  const endpoint = new URL(`http://${host}/upload/storage/v1/b/${encodeURIComponent(bucket)}/o`);
  endpoint.searchParams.set("uploadType", "media");
  endpoint.searchParams.set("name", name);
  endpoint.searchParams.set("ifGenerationMatch", "1");
  const response = await request(endpoint.href, {
    method: "POST",
    headers: { authorization: "Bearer owner", "content-type": "text/plain" },
    body: "refused",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (response.status >= 400 && response.status < 500)
    return { status: response.status, sourceResult: "typed-refusal" };
  if (response.status >= 200 && response.status < 300)
    return { status: response.status, sourceResult: "typed-success" };
  throw new Error(`local precondition upload answered HTTP ${response.status}`);
}

/**
 * The metadata of the primary bucket, for the versioning readback of the archive scenario. The bucket has to exist: production's
 * does, and the strict profile answers 404 for a bucket nobody created (the recorded production shape), so an absent bucket is
 * created here, once, and read again. Any other failure of the read, a failed create, or a read that still fails afterwards is
 * the unavailable readback (the scenario stops before it mutates anything).
 */
export async function readBucketMetadata(bucket) {
  const unavailable = () =>
    new Error("Storage archive versioning configuration readback is unavailable");
  try {
    const [metadata] = await bucket.getMetadata();
    return metadata;
  } catch (error) {
    if (error?.code !== 404) throw unavailable();
  }
  try {
    await bucket.create();
    const [metadata] = await bucket.getMetadata();
    return metadata;
  } catch {
    throw unavailable();
  }
}

export async function runStorageScenario({ scenario, capture, storage, request = fetch }) {
  const bucketName = scenario.resource === "bucket-control" ? controlBucket : primaryBucket;
  const bucket = storage.bucket(bucketName);
  const id = resourceId(scenario.id, "obj");
  const name = scenario.objectRole === "other-prefix" ? `other/${id}.txt` : `fe-events/${id}.txt`;
  const file = bucket.file(name);
  let originalVersioning = null;
  let versioningChanged = false;
  let seedGeneration = null;
  const cleanup = async () => {
    const absent = await deleteOwnedGenerations(bucket, name);
    let versioningRestored = true;
    if (versioningChanged) {
      await bucket.setMetadata({ versioning: originalVersioning });
      const [metadata] = await bucket.getMetadata();
      versioningRestored =
        Boolean(metadata.versioning?.enabled) === Boolean(originalVersioning?.enabled);
    }
    return {
      checked: absent && versioningRestored,
      objectGenerationsAbsent: absent,
      versioningRestored,
    };
  };
  try {
    assert.equal(await metadataOrNull(file), null, "owned object must start absent");
    if (scenario.id === "storage-archive") {
      const metadata = await readBucketMetadata(bucket);
      originalVersioning = { enabled: Boolean(metadata.versioning?.enabled) };
      await bucket.setMetadata({ versioning: { enabled: true } });
      versioningChanged = true;
      const [updated] = await bucket.getMetadata();
      assert.equal(updated.versioning?.enabled, true, "versioning enablement requires readback");
    }
    if (
      [
        "storage-overwrite",
        "storage-delete",
        "storage-metadata",
        "storage-archive",
        "storage-failed-upload",
      ].includes(scenario.id)
    ) {
      const seedCursor = (await capture.barrier()).cursor;
      await file.save("before", { contentType: "text/plain", resumable: false });
      const seed = await metadataOrNull(file);
      assert.ok(seed?.generation, "Storage seed generation requires readback");
      seedGeneration = seed.generation;
      await waitForSeed(capture, seedCursor, bucketName, name);
    }
    const cursor = (await capture.barrier()).cursor;
    let sourceResult = "typed-success";
    switch (scenario.id) {
      case "storage-upload":
      case "storage-other-bucket":
      case "storage-other-prefix":
        await file.save("created", { contentType: "text/plain", resumable: false });
        break;
      case "storage-overwrite":
      case "storage-archive":
        await file.save("updated", { contentType: "text/plain", resumable: false });
        break;
      case "storage-metadata":
        await file.setMetadata({ metadata: { fixtureMarker: "updated" } });
        break;
      case "storage-delete":
        await file.delete();
        break;
      case "storage-delete-missing":
        try {
          await file.delete();
          throw new Error("missing Storage object deletion unexpectedly succeeded");
        } catch (error) {
          if (!isMissing(error)) throw error;
          sourceResult = "typed-refusal";
        }
        break;
      case "storage-failed-upload":
        ({ sourceResult } = await attemptPreconditionUpload({
          host: process.env.FIREBASE_STORAGE_EMULATOR_HOST,
          bucket: bucketName,
          name,
          request,
        }));
        break;
      default:
        throw new Error(`unknown Storage scenario: ${scenario.id}`);
    }
    const after = await metadataOrNull(file);
    if (scenario.id === "storage-failed-upload" && sourceResult === "typed-refusal") {
      assert.equal(
        after?.generation,
        seedGeneration,
        "a refused write changed the Storage object (its generation is not the seed's)",
      );
    } else if (sourceResult === "typed-refusal" || scenario.id === "storage-delete") {
      assert.equal(after, null, "refused/deleted Storage object requires typed absence");
    } else {
      assert.ok(after?.generation, "Storage source generation requires readback");
    }
    return {
      cursor,
      matchKey: { kind: "storage", bucket: bucketName, value: name },
      sourceResult,
      readback: after
        ? {
            exists: true,
            bucket: bucketName,
            name,
            generation: after.generation,
            metageneration: after.metageneration,
            contentType: after.contentType,
          }
        : { exists: false, bucket: bucketName, name },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
}
