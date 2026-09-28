import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Reduce a typed token field to a public existence flag without exposing its value. */
export function seedTokenPresent(metadata, service) {
  if (!["gcs-json", "firebase-storage"].includes(service))
    throw new Error("invalid seed observation service");
  const tokens =
    service === "firebase-storage"
      ? metadata.downloadTokens
      : metadata.metadata?.firebaseStorageDownloadTokens;
  if (tokens === undefined) return false;
  if (typeof tokens === "string") return tokens.length > 0;
  if (Array.isArray(tokens) && tokens.every((token) => typeof token === "string"))
    return tokens.some((token) => token.length > 0);
  throw new Error("initial Auth seed token observation is malformed");
}

function readSet(rows, { name, bucket, present }) {
  const [metadata, media, prefix] = rows;
  if (
    !metadata ||
    !media ||
    !prefix ||
    metadata.status !== (present ? 200 : 404) ||
    media.status !== (present ? 200 : 404) ||
    prefix.status !== 200
  )
    throw new Error("local Auth state readbacks failed");
  let list, object;
  try {
    list = JSON.parse(prefix.raw.toString("utf8"));
    if (present) object = JSON.parse(metadata.raw.toString("utf8"));
  } catch {
    throw new Error("local Auth state metadata is invalid");
  }
  if (
    !list ||
    typeof list !== "object" ||
    Array.isArray(list) ||
    Object.hasOwn(list, "error") ||
    (list.kind !== undefined && list.kind !== "storage#objects") ||
    (list.items === undefined ? list.kind !== "storage#objects" : !Array.isArray(list.items)) ||
    (list.nextPageToken !== undefined && list.nextPageToken !== null) ||
    (list.prefixes !== undefined && (!Array.isArray(list.prefixes) || list.prefixes.length !== 0))
  )
    throw new Error("local Auth prefix proof is invalid or incomplete");
  const items = list.items ?? [];
  if (
    items.length !== (present ? 1 : 0) ||
    (present &&
      (object?.bucket !== bucket ||
        object.name !== name ||
        !/^[1-9][0-9]{0,19}$/.test(object.generation) ||
        items[0]?.bucket !== bucket ||
        items[0].name !== name ||
        items[0].generation !== object.generation))
  )
    throw new Error("local Auth prefix contents differ from owned state");
  return { metadata: object, bytes: media.raw };
}

/** Replay one canonical local Auth program; credentials stay inside the counted sender. */
export async function replayLocalAuth({ sender, recipe, bucket, prefix, onCapture } = {}) {
  if (typeof onCapture !== "function") throw new Error("private Auth capture is required");
  const owned = new Set(),
    controls = [],
    initialSeedObservations = [],
    cleanupFailures = [];
  let failure = null,
    currentId = "initial-prefix-list",
    namespaceReady = false;
  function storageStep(row, operationId) {
    if (row.credential !== "owner") throw new Error("local owner readback is required");
    const collection = row.method === "GET" && row.path === `/storage/v1/b/${bucket}/o`;
    return {
      id: operationId,
      dialect: row.service === "gcs-json" ? "gcs" : "firebase",
      method: row.method,
      credential: "admin",
      path: row.path,
      query: row.query,
      headers: row.method === "POST" ? { "content-type": "application/octet-stream" } : {},
      ...(row.body ? { body: row.body } : {}),
      ...(collection ? { collection: true, scopePrefix: prefix } : { objectName: row.objectName }),
    };
  }
  async function capture(operationId, response) {
    await onCapture({
      operationId,
      status: response.status,
      headers: response.headers,
      bodyBase64: response.raw.toString("base64"),
    });
    return response;
  }
  const send = async (step) => capture(step.id, await sender.sendStep(step));
  async function reads(probe, rows, label, present) {
    const steps = rows.map((row) =>
      storageStep(row, `${recipe.id}/${probe.id}/${label}-${row.id}`),
    );
    const responses = [];
    for (const step of steps) {
      currentId = step.id;
      responses.push(await send(step));
    }
    return {
      steps,
      responses,
      proof: readSet(responses, { name: probe.objectName, bucket, present }),
    };
  }
  try {
    await sender.start();
    await sender.verifyLocalAuthRules();
    await sender.admitNamespace();
    namespaceReady = true;
    for (const probe of recipe.probes) sender.admitObject(probe.objectName);
    for (const [stepIndex, step] of recipe.accountSetup.entries()) {
      currentId = `${recipe.id}/${step.id}`;
      await capture(currentId, await sender.sendAuthStep({ recipe, stepIndex }));
    }
    for (const [probeIndex, probe] of recipe.probes.entries()) {
      await reads(probe, probe.initial, "initial", false);
      let mutationId = null;
      if (probe.seed) {
        const step = storageStep(probe.seed, `${recipe.id}/${probe.id}/owner-seed`);
        currentId = step.id;
        if ((await send(step)).status !== 200) throw new Error("local Auth seed failed");
        mutationId = step.id;
        const initial = [];
        for (const row of probe.seedReadbacks) {
          const observationStep = storageStep(row, `${recipe.id}/${probe.id}/${row.id}`);
          currentId = observationStep.id;
          const response = await send(observationStep);
          let metadata;
          try {
            metadata = JSON.parse(response.raw.toString("utf8"));
          } catch {
            throw new Error("initial Auth seed observation is malformed");
          }
          if (
            response.status !== 200 ||
            metadata?.bucket !== bucket ||
            metadata.name !== probe.objectName ||
            typeof metadata.metageneration !== "string" ||
            !/^[1-9][0-9]{0,19}$/.test(metadata.metageneration)
          )
            throw new Error("initial Auth seed observation differs");
          initial.push(metadata);
        }
        initialSeedObservations.push({
          probeId: probe.id,
          metagenerations: initial.map((metadata) => metadata.metageneration),
          hasDownloadToken: initial.map((metadata, index) =>
            seedTokenPresent(metadata, probe.seedReadbacks[index].service),
          ),
          gcsMetadataChanged: !isDeepStrictEqual(initial[0], initial[2]),
        });
      }
      const before = await reads(probe, probe.before, "before", probe.action === "read");
      if (probe.seed) {
        sender.confirmOwned({
          name: probe.objectName,
          uploadOperationId: mutationId,
          metadataOperationId: before.steps[0].id,
          mediaOperationId: before.steps[1].id,
          expectedBytesSha256: digest(Buffer.from(probe.seed.body.base64, "base64")),
        });
        owned.add(probe.objectName);
      }
      currentId = `${recipe.id}/${probe.id}/subject`;
      const subject = await capture(
        currentId,
        await sender.sendAuthSubject({ recipe, probeIndex }),
      );
      const subjectId = currentId,
        accepted = subject.status === 200;
      const expected = probe.credential === "valid";
      const after = await reads(probe, probe.after, "after", probe.action === "read" || accepted);
      if (probe.action === "read") {
        sender.assertOwnedReadbacks({
          name: probe.objectName,
          metadataOperationId: after.steps[0].id,
          mediaOperationId: after.steps[1].id,
        });
        if (
          !isDeepStrictEqual(before.proof.metadata, after.proof.metadata) ||
          !before.proof.bytes.equals(after.proof.bytes)
        )
          throw new Error("local Auth read changed the seed");
        if (accepted && !subject.raw.equals(before.proof.bytes))
          throw new Error("local Auth read returned different bytes");
        if (!accepted && subject.raw.equals(before.proof.bytes))
          throw new Error("local Auth denied read returned owned bytes");
      } else if (accepted) {
        sender.confirmOwned({
          name: probe.objectName,
          uploadOperationId: subjectId,
          metadataOperationId: after.steps[0].id,
          mediaOperationId: after.steps[1].id,
          expectedBytesSha256: digest(Buffer.from(probe.subject.body.base64, "base64")),
        });
        owned.add(probe.objectName);
      } else {
        await sender.confirmAbsent({
          name: probe.objectName,
          mutationOperationId: subjectId,
          metadataOperationId: after.steps[0].id,
          mediaOperationId: after.steps[1].id,
        });
      }
      if (
        accepted !== expected ||
        (!accepted && (subject.status < 400 || subject.status >= 500 || subject.status === 404))
      )
        throw new Error("local fixed Rules control outcome differs");
      controls.push({
        probeId: probe.id,
        credentialKind: probe.credential,
        action: probe.action,
        status: subject.status,
      });
    }
  } catch {
    failure = { id: currentId, reason: "LOCAL_AUTH_REQUEST_OR_PROOF_FAILED" };
  }
  if (namespaceReady && sender.snapshot().mode === "subject") {
    sender.beginCleanup();
    for (const probe of recipe.probes) {
      try {
        if (owned.has(probe.objectName)) {
          const fresh = await reads(probe, probe.before, "cleanup-fresh", true);
          const operationId = `${recipe.id}/${probe.id}/owned-delete`;
          await capture(
            operationId,
            await sender.cleanupOwned({
              name: probe.objectName,
              metadataOperationId: fresh.steps[0].id,
              mediaOperationId: fresh.steps[1].id,
              operationId,
            }),
          );
        }
        await reads(probe, probe.cleanup.slice(1), "cleanup", false);
      } catch {
        cleanupFailures.push({
          objectName: probe.objectName,
          reason: "LOCAL_AUTH_OBJECT_CLEANUP_FAILED",
        });
      }
    }
    for (const [cleanupIndex, step] of recipe.accountCleanup.entries()) {
      const kind = step.id.startsWith("valid-") ? "valid" : "competitor";
      const state = sender.authAccountSnapshot({ recipe })[kind];
      if (["unobserved", "absent", "absent-after-delete"].includes(state)) continue;
      const operationId = `${recipe.id}/${step.id}`;
      try {
        await capture(operationId, await sender.sendAuthStep({ recipe, cleanupIndex }));
      } catch {
        cleanupFailures.push({ accountKind: kind, reason: "LOCAL_AUTH_ACCOUNT_CLEANUP_FAILED" });
      }
    }
    if (sender.unresolved().length === 0 && cleanupFailures.length === 0) {
      try {
        await sender.verifyLocalAuthRules();
        await sender.verifyRunEmpty();
        sender.close();
      } catch {
        cleanupFailures.push({ reason: "LOCAL_AUTH_FINAL_ABSENCE_FAILED" });
      }
    }
  }
  const unresolved = sender.unresolved();
  return {
    recipeId: recipe.id,
    status:
      unresolved.length || cleanupFailures.length
        ? "LOCAL_NEEDS_RECOVERY"
        : failure
          ? "LOCAL_BLOCKED"
          : "LOCAL_COMPLETE",
    controls,
    initialSeedObservations,
    requests: sender.snapshot().total,
    failure,
    cleanupFailures,
    unresolved,
  };
}
