import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { buildCorpus } from "./corpus.mjs";
import {
  captureResponse,
  fixtureDigest,
  managementSteps,
  sha256,
  validateBinding,
} from "./management-compare.mjs";

/** Capture local effects through an injected transport. Importing this module sends nothing. */
export async function collectManagement({ binding, profile, provenance, transport }) {
  validateBinding(binding);
  if (!["strict", "emulator"].includes(profile) || typeof transport !== "function")
    throw new Error("invalid local management input");
  const [compile, switched, noRelease] = buildCorpus(binding).managementPrograms;
  const sources = new Map([...compile.validSources, compile.invalidSource].map((s) => [s.ref, s]));
  const artifact = {
    schemaVersion: 1,
    kind: "local-management",
    profile,
    binding,
    provenance,
    rows: [],
    errors: [],
    localOnly: [],
  };
  const specs = new Map(managementSteps(binding).map((s) => [s.id, s]));
  const owned = new Set();
  let ordinal = 0;
  async function send(action) {
    return transport(action);
  }
  async function row(id, action, effect = null) {
    const spec = specs.get(id);
    if (!spec) throw new Error(`undeclared management step ${id}`);
    const response = await send(action);
    const captured = captureResponse(response);
    const resolved = typeof effect === "function" ? effect(response) : effect;
    artifact.rows.push({
      ...spec,
      sourceSha256: spec.sourceRef ? sources.get(spec.sourceRef).sha256 : null,
      response: captured,
      effect: resolved,
      evidence: { ordinal: ++ordinal },
    });
    return response;
  }
  const storage = (name, media, caller = "admin", method = "GET", query = {}) => ({
    kind: "storage",
    name,
    media,
    caller,
    method,
    query,
  });
  const metaEffect = (r) => ({ stateSha256: sha256(r.bytes) });
  const snapshot = async () => {
    const r = await send({ kind: "snapshot" });
    if (r.status !== 200) throw new Error("rules snapshot unavailable");
    return { response: r, state: JSON.parse(r.bytes.toString("utf8")) };
  };
  async function identity(id, source) {
    const activation = await send({ kind: "activate", source });
    const { response, state } = await snapshot();
    if (activation.status !== 200 || state.source !== source || state.loaded !== true)
      throw new Error(`source identity failed ${id}`);
    await row(id, { kind: "captured", response }, { sourceAccepted: true });
  }
  const names = new Map([
    [3, switched.objectA],
    [4, switched.objectB],
    [5, noRelease.objectName],
  ]);
  async function cleanupOwned() {
    for (const [index, name] of names)
      if (owned.has(name)) {
        try {
          const metadata = await row(
            `management/control-${index}/cleanup-metadata`,
            storage(name, false),
            metaEffect,
          );
          const generation = JSON.parse(metadata.bytes.toString("utf8")).generation;
          if (metadata.status !== 200 || !/^\d+$/.test(generation ?? ""))
            throw new Error("owned cleanup generation unavailable");
          const deleted = await row(
            `management/control-${index}/delete`,
            storage(name, false, "admin", "DELETE", { ifGenerationMatch: generation }),
          );
          if (deleted.status !== 204) throw new Error("owned cleanup delete refused");
          for (const media of [false, true]) {
            const response = await row(
              `management/control-${index}/absence-${media ? "media" : "metadata"}`,
              storage(name, media),
              media ? null : metaEffect,
            );
            if (response.status !== 404) throw new Error("owned cleanup absence unavailable");
          }
          owned.delete(name);
        } catch (error) {
          artifact.errors.push({ kind: "OWNED_CLEANUP_FAILED", message: error.message });
        }
      }
  }
  async function observe(prefix, name, stages) {
    for (const stage of stages)
      await row(
        `${prefix}/${stage}`,
        storage(
          name,
          stage !== "before-metadata" && stage !== "after-metadata",
          stage === "subject" ? "user-a" : "admin",
        ),
        stage.includes("metadata") ? metaEffect : null,
      );
  }
  async function absence(id) {
    const { response, state } = await snapshot();
    await row(id, { kind: "captured", response }, { absent: state.loaded === false });
  }
  try {
    for (const scope of ["bucket", "bucketless"]) await absence(`preflight/release/entry/${scope}`);
    await absence("compile/release/before");
    for (const [index, name] of names) {
      for (const media of [false, true]) {
        const before = await row(
          `management/control-${index}/baseline-${media ? "media" : "metadata"}`,
          storage(name, media),
          media ? null : metaEffect,
        );
        if (before.status !== 404) throw new Error("owned object not initially absent");
      }
      const seeded = await row(
        `management/control-${index}/seed`,
        { kind: "seed", name },
        metaEffect,
      );
      if (seeded.status !== 200) throw new Error("seed refused");
      owned.add(name);
      await row(`management/control-${index}/seed-metadata`, storage(name, false), metaEffect);
      await row(`management/control-${index}/seed-media`, storage(name, true));
    }
    await observe("management/no-release/entry", noRelease.objectName, [
      "subject",
      "after-metadata",
      "after-media",
    ]);
    for (const source of compile.validSources)
      await identity(`compile/${source.ref}`, source.content);
    await send({ kind: "clear" });
    await row(
      "compile/invalid/storage-expression",
      { kind: "activate", source: compile.invalidSource.content },
      (r) => ({ rejected: r.status === 400 }),
    );
    await absence("compile/release/after-invalid");
    await send({ kind: "activate", source: switched.sourceA });
    for (const phase of ["before", "after"]) {
      const { response, state } = await snapshot();
      artifact.localOnly.push({
        id: `${phase}-identity`,
        scope: "LOCAL_ONLY",
        response: captureResponse(response),
        sourceSha256: typeof state.source === "string" ? sha256(state.source) : null,
      });
      for (const [label, name] of [
        ["allow", switched.objectA],
        ["deny", switched.objectB],
      ])
        artifact.localOnly.push({
          id: `${phase}-${label}`,
          scope: "LOCAL_ONLY",
          response: captureResponse(await send(storage(name, true, "user-a"))),
          sourceSha256: null,
        });
      if (phase === "before")
        artifact.localOnly.push({
          id: "invalid",
          scope: "LOCAL_ONLY",
          response: captureResponse(
            await send({ kind: "activate", source: compile.invalidSource.content }),
          ),
          sourceSha256: compile.invalidSource.sha256,
        });
    }
    for (const source of ["A", "B"]) {
      await identity(`release/${source}/after`, switched[`source${source}`]);
      for (const [index, name] of [
        [3, switched.objectA],
        [4, switched.objectB],
      ])
        await observe(`management/${source}/control-${index}`, name, [
          "before-metadata",
          "before-media",
          "subject",
          "after-metadata",
          "after-media",
        ]);
    }
    await row("release/restore/delete", { kind: "clear" }, (r) => ({ cleared: r.status === 200 }));
    for (const scope of ["bucket", "bucketless"]) await absence(`release/restore/${scope}-absence`);
    await observe("management/no-release/final", noRelease.objectName, [
      "before-metadata",
      "before-media",
      "subject",
      "after-metadata",
      "after-media",
    ]);
    for (const scope of ["bucket", "bucketless"]) await absence(`release/final/${scope}`);
  } catch (error) {
    artifact.errors.push({ kind: "COLLECTION_FAILED", message: error.message });
  } finally {
    try {
      await send({ kind: "clear" });
    } catch {
      artifact.errors.push({ kind: "RULES_CLEANUP_FAILED" });
    }
    await cleanupOwned();
    try {
      await row("management/prefix-empty", { kind: "list" });
    } catch {
      artifact.errors.push({ kind: "PREFIX_CLEANUP_FAILED" });
    }
  }
  if (artifact.rows.length !== specs.size)
    artifact.errors.push({
      kind: "MISSING_STEPS",
      expected: specs.size,
      actual: artifact.rows.length,
    });
  return artifact;
}

/** The only HTTP implementation; all targets are validated loopback URLs. */
export function localTransport({
  storageHost,
  authHost,
  controlUrl,
  controlToken,
  userToken,
  binding,
  fetchImpl = fetch,
}) {
  const loopbackHost = /^(?:127\.0\.0\.1:\d+|\[::1\]:\d+)$/;
  if (!loopbackHost.test(storageHost ?? "") || (authHost && !loopbackHost.test(authHost)))
    throw new Error("local hosts must be loopback");
  const control = new URL("storage/rules", controlUrl);
  if (
    !["127.0.0.1", "[::1]"].includes(control.hostname) ||
    control.protocol !== "http:" ||
    control.username ||
    control.password ||
    !controlToken ||
    !userToken
  )
    throw new Error("invalid local control/token input");
  const base = `http://${storageHost}`;
  const request = async (url, init) => {
    const response = await fetchImpl(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    return {
      status: response.status,
      bytes: Buffer.from(await response.arrayBuffer()),
      headers: response.headers,
    };
  };
  return async (action) => {
    if (action.kind === "captured") return action.response;
    if (action.kind === "snapshot" || action.kind === "clear")
      return request(control, {
        method: action.kind === "clear" ? "DELETE" : "GET",
        headers: { authorization: `Bearer ${controlToken}` },
      });
    if (action.kind === "activate")
      return request(new URL("/internal/setRules", base), {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          rules: { files: [{ name: "storage.rules", content: action.source }] },
        }),
      });
    if (action.kind === "list") {
      const url = new URL(`/storage/v1/b/${binding.bucket}/o`, base);
      url.searchParams.set("prefix", binding.prefix);
      url.searchParams.set("maxResults", "1");
      return request(url, { headers: { authorization: "Bearer owner" } });
    }
    if (!["storage", "seed"].includes(action.kind) || !action.name.startsWith(binding.prefix))
      throw new Error("invalid owned local action");
    const user = action.caller === "user-a";
    const url =
      action.kind === "seed"
        ? new URL(`/upload/storage/v1/b/${binding.bucket}/o`, base)
        : new URL(
            `${user ? "/v0" : "/storage/v1"}/b/${binding.bucket}/o/${encodeURIComponent(action.name)}`,
            base,
          );
    const query =
      action.kind === "seed"
        ? { uploadType: "media", name: action.name, ifGenerationMatch: "0" }
        : { ...(action.media ? { alt: "media" } : {}), ...action.query };
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    return request(url, {
      method: action.kind === "seed" ? "POST" : action.method,
      headers: {
        authorization: user ? `Firebase ${userToken}` : "Bearer owner",
        ...(action.kind === "seed" ? { "content-type": "text/plain" } : {}),
      },
      ...(action.kind === "seed" ? { body: "next" } : {}),
    });
  };
}

async function main() {
  const [receiptPath, outputPath] = process.argv.slice(2);
  if (!outputPath) throw new Error("usage: management-local.mjs receipt.json output.json");
  const receipt = JSON.parse(readFileSync(receiptPath));
  const { binding } = receipt;
  validateBinding(binding);
  const provenance = receipt.localProvenance;
  for (const [key, url] of [
    ["collectorSha256", import.meta.url],
    ["judgeSha256", new URL("./management-compare.mjs", import.meta.url)],
    ["corpusSha256", new URL("./corpus.mjs", import.meta.url)],
  ])
    if (sha256(readFileSync(new URL(url))) !== provenance[key]) throw new Error(`stale ${key}`);
  if (
    !process.env.STORAGE_RULES_MANAGEMENT_BINARY ||
    sha256(readFileSync(process.env.STORAGE_RULES_MANAGEMENT_BINARY)) !== provenance.binarySha256 ||
    !process.env.STORAGE_RULES_MANAGEMENT_CONFIG ||
    sha256(readFileSync(process.env.STORAGE_RULES_MANAGEMENT_CONFIG)) !== provenance.configSha256
  )
    throw new Error("stale binary/config");
  const config = JSON.parse(readFileSync(process.env.STORAGE_RULES_MANAGEMENT_CONFIG));
  if (
    config.profile !== "strict" ||
    receipt.profile !== "strict" ||
    fixtureDigest(binding) !== provenance.fixtureSha256
  )
    throw new Error("wrong profile/fixture");
  const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  if (!/^(?:127\.0\.0\.1:\d+|\[::1\]:\d+)$/.test(authHost ?? ""))
    throw new Error("local Auth required");
  const identityBase = `http://${authHost}/identitytoolkit.googleapis.com/v1`;
  async function identity(path, body, owner = false) {
    const response = await fetch(`${identityBase}${path}`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(30000),
      headers: {
        "content-type": "application/json",
        ...(owner ? { authorization: "Bearer owner" } : {}),
      },
      body: JSON.stringify(body),
    });
    if (response.status !== 200) throw new Error("local Auth fixture failed");
    return response.json();
  }
  const email = "management-local@example.test",
    password = "Local-Management-Password-1";
  let created = false;
  try {
    await identity(
      `/projects/fireemu-oracle-query/accounts`,
      { localId: binding.uidA, email, password, emailVerified: true },
      true,
    );
    created = true;
    const user = await identity("/accounts:signInWithPassword?key=local", {
      email,
      password,
      returnSecureToken: true,
    });
    const transport = localTransport({
      storageHost: process.env.FIREBASE_STORAGE_EMULATOR_HOST,
      authHost,
      controlUrl: process.env.FIREEMU_CONTROL_URL,
      controlToken: process.env.FIREEMU_CONTROL_TOKEN,
      userToken: user.idToken,
      binding,
    });
    const result = await collectManagement({ binding, profile: "strict", provenance, transport });
    writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.errors.length ? 1 : 0;
  } finally {
    if (created)
      await identity(
        `/projects/fireemu-oracle-query/accounts:delete`,
        { localId: binding.uidA },
        true,
      );
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
