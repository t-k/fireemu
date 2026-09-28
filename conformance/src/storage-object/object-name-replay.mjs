import { createHash } from "node:crypto";
import {
  assertAcceptedNamesListed,
  assertNameScopePageExhaustion,
  listedNameScopeEntries,
} from "./name-scope.mjs";

/** Replay the existing object-name sequence through its supplied counted sender. */
export async function replayLocalObjectNames({ sender, recipe, bucket } = {}) {
  function listBody(response) {
    if (response.status !== 200) throw new Error("name-scope list failed");
    let parsed;
    try {
      parsed = JSON.parse(response.raw.toString("utf8"));
    } catch {
      throw new Error("name-scope list was not JSON");
    }
    if (
      !parsed ||
      typeof parsed !== "object" ||
      Array.isArray(parsed) ||
      (parsed.items !== undefined && !Array.isArray(parsed.items)) ||
      (parsed.prefixes !== undefined && !Array.isArray(parsed.prefixes))
    )
      throw new Error("name-scope list has invalid entries");
    return parsed;
  }

  function boundedToken(body, cap) {
    const token = body.nextPageToken;
    if (token === undefined) return null;
    if (
      typeof token !== "string" ||
      !token ||
      Buffer.byteLength(token) > cap ||
      [...token].some((character) => {
        const code = character.codePointAt(0);
        return code < 32 || code === 127;
      })
    )
      throw new Error("name-scope continuation token is invalid");
    return token;
  }

  const nextTokenByStep = new Map();
  const listedNamesByChain = new Map();
  const listSummaries = [];
  const preflightStatuses = [];
  let states = new Map();
  async function sendList(step) {
    let query = step.query;
    if (step.continuation) {
      const token = nextTokenByStep.get(step.continuation.sourceStep);
      if (token === null || token === undefined) return false;
      query = { ...query, [step.continuation.targetQuery]: token };
    }
    const response = await sender.sendStep({ ...step, query });
    if (response.status !== 200) {
      listSummaries.push({
        id: step.id,
        status: response.status,
        bodySha256: createHash("sha256").update(response.raw).digest("hex"),
      });
      if (
        !/^(firebase|gcs)-list-(linefeed|oversized)-prefix$/.test(step.id) ||
        response.status < 400 ||
        response.status > 499
      )
        throw new Error(`name-scope list ${step.id} was ${response.status}`);
      return null;
    }
    const body = listBody(response);
    const token = boundedToken(body, step.continuation?.maxTokenBytes ?? 4096);
    assertNameScopePageExhaustion(step, token, recipe.nameScopePagination);
    const entries = listedNameScopeEntries(body, {
      bucket,
      scopePrefix: recipe.nameScopePagination.scopePrefix,
    });
    const chain = step.id.replace(/-page-\d+$/, "");
    const listedNames = listedNamesByChain.get(chain) ?? new Set();
    for (const name of entries.names) {
      if (listedNames.has(name)) throw new Error("name-scope list repeats an object across pages");
      listedNames.add(name);
    }
    listedNamesByChain.set(chain, listedNames);
    if (token === null && /-page-\d+$/.test(step.id))
      assertAcceptedNamesListed(
        listedNames,
        [...states].filter(([, state]) => state.owned).map(([name]) => name),
      );
    nextTokenByStep.set(step.id, token);
    listSummaries.push({
      id: step.id,
      status: response.status,
      items: entries.names.length,
      namesBase64: entries.names.map((name) => Buffer.from(name).toString("base64")),
      prefixes: entries.prefixes.length,
      prefixesBase64: entries.prefixes.map((name) => Buffer.from(name).toString("base64")),
      hasNextPageToken: token !== null,
    });
    return body;
  }

  await sender.start();
  await sender.admitNamespace();
  for (const name of recipe.objects) sender.admitObject(name);
  for (const step of recipe.preflight) {
    if (step.collection) {
      const body = await sendList(step);
      if (body && ((body.items?.length ?? 0) !== 0 || (body.prefixes?.length ?? 0) !== 0))
        throw new Error(`${recipe.id}: preflight list was not empty`);
    } else {
      const response = await sender.sendStep(step);
      preflightStatuses.push({ id: step.id, status: response.status });
      if (![400, 404, 414].includes(response.status))
        throw new Error(`${recipe.id}: preflight ${step.id} was ${response.status}`);
    }
  }

  states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        uploadId: null,
        status: null,
        expectedBytesSha256: null,
        metadataId: null,
        confirmed: false,
        owned: false,
      },
    ]),
  );
  const mutationStatuses = [];
  const cleanupStatuses = [];
  for (const step of recipe.steps) {
    if (step.collection) {
      await sendList(step);
      continue;
    }
    const state = states.get(step.objectName);
    if (!state) throw new Error(`${recipe.id}: undeclared object`);
    const response = await sender.sendStep(step);
    if (step.method === "POST") {
      if (state.uploadId !== null || !step.body?.base64)
        throw new Error(`${recipe.id}: repeated or unknown upload`);
      state.uploadId = step.id;
      state.status = response.status;
      state.expectedBytesSha256 = createHash("sha256")
        .update(Buffer.from(step.body.base64, "base64"))
        .digest("hex");
      mutationStatuses.push({ id: step.id, status: response.status });
    } else if (step.method === "GET" && Object.keys(step.query).length === 0) {
      if (!state.confirmed) state.metadataId = step.id;
    } else if (step.method === "GET" && step.query.alt === "media") {
      if (!state.confirmed && state.uploadId !== null) {
        if (state.status >= 400) {
          await sender.confirmRefusedInvalidName({
            name: step.objectName,
            mutationOperationId: state.uploadId,
            metadataOperationId: state.metadataId,
            mediaOperationId: step.id,
          });
        } else {
          sender.confirmOwned({
            name: step.objectName,
            uploadOperationId: state.uploadId,
            metadataOperationId: state.metadataId,
            mediaOperationId: step.id,
            expectedBytesSha256: state.expectedBytesSha256,
          });
          state.owned = true;
          state.mediaId = step.id;
        }
        state.confirmed = true;
      }
    }
  }
  if ([...states.values()].some((state) => !state.confirmed))
    throw new Error(`${recipe.id}: attempted names were not resolved`);
  sender.beginCleanup();
  for (const [name, state] of states) {
    const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
    if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
      throw new Error(`${recipe.id}: invalid cleanup declaration`);
    if (state.owned) {
      const deletion = await sender.cleanupOwned({
        name,
        metadataOperationId: state.metadataId,
        mediaOperationId: state.mediaId,
        operationId: cleanup[0].id,
      });
      if (deletion.status !== 204) throw new Error(`${recipe.id}: cleanup delete failed`);
    }
    for (const step of cleanup.slice(1)) {
      const response = await sender.sendStep(step);
      cleanupStatuses.push({ id: step.id, status: response.status });
      if (![400, 404, 414].includes(response.status))
        throw new Error(`${recipe.id}: cleanup ${step.id} was ${response.status}`);
    }
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error(`${recipe.id}: unresolved objects`);
  return {
    recipeId: recipe.id,
    status: "LOCAL_COMPLETE",
    cleanupFailures: [],
    unresolved: sender.unresolved(),
    requests: sender.snapshot().total,
    preflightStatuses,
    mutationStatuses,
    cleanupStatuses,
    listSummaries,
  };
}
