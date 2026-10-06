/** Checklist section 3 is stricter than the legacy transport's 501 exception. */
export function hUnknown(reply) {
  return (
    !reply ||
    reply.unknown === true ||
    !Number.isInteger(reply.status) ||
    reply.status < 200 ||
    (reply.status >= 300 && reply.status < 400) ||
    reply.status >= 500 ||
    reply.body === undefined ||
    reply.body === null ||
    typeof reply.body !== "object" ||
    typeof reply.body.raw === "string"
  );
}

/** Apply to each own request, never overwrite an earlier unknown with a later conflict. */
export function hDisposition({ create, deletion, read, mode = "run", ageMs = 0 }) {
  const confirmed =
    create === "confirmed" || (read === "present" && ["unknown", "pending"].includes(create));
  const later = mode === "a2" && ageMs >= 600_000;
  const pendingDelete = ["unknown", "pending"].includes(deletion);
  const closed =
    create === "failed" || (confirmed && read === "absent" && (deletion === "confirmed" || later));
  return {
    confirmed,
    closed,
    canDelete: confirmed && read === "present" && !pendingDelete && deletion !== "confirmed",
    unconfirmed: !confirmed && ["unknown", "pending"].includes(create),
  };
}

import { spawn, execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  realpathSync,
  readdirSync,
  lstatSync,
} from "node:fs";
import { dirname, join } from "node:path";

export const H_FE_PIN = "773a37fc930d753b70e5bf14f9ed15b8fccc064f";

/** FE's private source preparation, narrowed to H's three tracked fixture files. */
export function prepareHSource({ manifest: m, source, target, depsDir }) {
  mkdirSync(target, { recursive: true, mode: 0o700 });
  for (const name of ["package.json", "index.js", "firebase.json"])
    cpSync(join(source, name), join(target, name));
  writeFileSync(join(target, `.env.${m.project}`), `EVENTARC_H_RUN_ID=${m.runId}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  cpSync(realpathSync(depsDir), join(target, "node_modules"), {
    recursive: true,
    verbatimSymlinks: true,
  });
  const root = realpathSync(join(target, "node_modules"));
  const visit = (path) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) {
        const resolved = realpathSync(child);
        if (resolved !== root && !resolved.startsWith(`${root}/`))
          throw new Error("H dependencies escape the private source");
      } else if (stat.isDirectory()) visit(child);
    }
  };
  visit(root);
  for (const [name, version] of [
    ["firebase-functions", "7.3.2"],
    ["firebase-admin", "14.3.0"],
    ["@google-cloud/functions-framework", "5.0.5"],
  ]) {
    if (JSON.parse(readFileSync(join(root, name, "package.json"), "utf8")).version !== version)
      throw new Error(`H dependency mismatch: ${name}`);
  }
  return { fixtureDir: target, configPath: join(target, "firebase.json") };
}

/** SDK discovery is local; it starts no listening server and reads no credential. */
export function discoverH({ manifest: m, fixtureDir, node, directory }) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const output = join(directory, "functions-manifest.json");
  execFileSync(
    node,
    [join(fixtureDir, "node_modules/firebase-functions/lib/bin/firebase-functions.js"), fixtureDir],
    {
      cwd: fixtureDir,
      timeout: 60_000,
      stdio: ["ignore", "ignore", "pipe"],
      env: {
        PATH: dirname(node),
        HOME: directory,
        EVENTARC_H_RUN_ID: m.runId,
        GCLOUD_PROJECT: m.project,
        FIREBASE_CONFIG: JSON.stringify({ projectId: m.project }),
        FUNCTIONS_MANIFEST_OUTPUT_PATH: output,
      },
    },
  );
  const endpoints = JSON.parse(readFileSync(output, "utf8")).endpoints;
  const problems = hManifestProblems(endpoints, m);
  if (problems.length) throw new Error(problems.join("; "));
  return endpoints;
}

export function hManifestProblems(endpoints, m) {
  if (
    !endpoints ||
    JSON.stringify(Object.keys(endpoints).toSorted()) !==
      JSON.stringify([m.observe, m.filtered].toSorted())
  )
    return ["H discovery must contain exactly the two exports"];
  const problems = [];
  for (const name of [m.observe, m.filtered]) {
    const e = endpoints[name];
    const t = e.eventTrigger;
    const filters = name === m.observe ? {} : { source: m.source, tenant: m.tenant };
    if (
      e.platform !== "gcfv2" ||
      JSON.stringify(e.region) !== '["us-central1"]' ||
      t?.eventType !== m.type ||
      t?.channel !== "locations/us-central1/channels/firebase" ||
      t?.retry !== (name === m.observe) ||
      JSON.stringify(t?.eventFilters) !== JSON.stringify(filters) ||
      e.minInstances !== 0 ||
      e.maxInstances !== 2
    )
      problems.push(`${name}: unreviewed H manifest`);
  }
  return problems;
}

/** The FE invocation pattern: one selected export, --force, --debug, no interactive fallback. */
export function hCliPlan({ manifest: m, name, fixtureDir, configPath, env }) {
  if (![m.observe, m.filtered].includes(name)) throw new Error("not an H export");
  return {
    cwd: fixtureDir,
    env,
    args: [
      "deploy",
      "--project",
      m.project,
      "--config",
      configPath,
      "--only",
      `functions:eventarc-h:${name}`,
      "--non-interactive",
      "--force",
      "--debug",
    ],
  };
}

export function hCliFailed(result) {
  const summaries = [
    ...`${result?.stdout ?? ""}\n${result?.stderr ?? ""}`.matchAll(
      /^(?:\[[^\]]*\] )?(\d+) Functions? Errored[ \t]*$/gm,
    ),
  ];
  return (
    result?.exitCode !== 0 ||
    result?.timedOut === true ||
    result?.processCleanupUnknown === true ||
    Boolean(result?.error) ||
    summaries.length === 0 ||
    summaries.some((s) => Number(s[1]) !== 0)
  );
}

/** FE process-group lifecycle and raw stdout/stderr capture; no retry or REST deploy fallback. */
export async function runHCli({ node, firebaseJs, plan, save, spawnFn = spawn }) {
  return new Promise((resolve) => {
    const child = spawnFn(node, [firebaseJs, ...plan.args], {
      cwd: plan.cwd,
      env: plan.env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let forced = false;
    let processCleanupUnknown = false;
    let killTimer;
    const started = Date.now();
    const terminate = (signal) => {
      if (signal === "SIGKILL") forced = true;
      try {
        process.kill(-child.pid, signal);
        return false;
      } catch (error) {
        if (error.code === "ESRCH") return true;
        processCleanupUnknown = true;
        return false;
      }
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate("SIGTERM");
      killTimer = setTimeout(() => terminate("SIGKILL"), 60_000);
    }, 20 * 60_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      save("stdout", chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      save("stderr", chunk);
    });
    let finished = false;
    const finish = (exitCode, error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      clearTimeout(killTimer);
      const answer = () =>
        resolve({
          exitCode,
          error: error ? "spawn-failed" : null,
          timedOut,
          processCleanupUnknown,
          stdout,
          stderr,
          durationMs: Date.now() - started,
        });
      if (!Number.isInteger(child.pid) || forced) return answer();
      // Keep escalation after parent exit: a descendant may ignore SIGTERM.
      if (terminate("SIGTERM")) return answer();
      killTimer = setTimeout(() => {
        terminate("SIGKILL");
        answer();
      }, 60_000);
    };
    child.once("error", (error) => finish(null, error));
    child.once("close", (code) => finish(code));
  });
}

/** Complete list reads, as in FE; pagination consumes the same H phase meter. */
export async function hReadList(transport, { path, key, phase }, meter) {
  const items = [];
  let pageToken;
  for (let page = 0; page < 5; page++) {
    meter();
    const reply = await transport.request({
      method: "GET",
      path: `${path}${pageToken ? `${path.includes("?") ? "&" : "?"}pageToken=${encodeURIComponent(pageToken)}` : ""}`,
      op: `h.${key}.list`,
      label: { case: `h-${phase}` },
    });
    if (
      hUnknown(reply) ||
      reply.status !== 200 ||
      (reply.body[key] !== undefined && !Array.isArray(reply.body[key])) ||
      (reply.body.nextPageToken !== undefined && typeof reply.body.nextPageToken !== "string")
    )
      throw new Error(`incomplete H ${key} list`);
    items.push(...(reply.body[key] ?? []));
    pageToken = reply.body.nextPageToken;
    if (!pageToken) return items;
  }
  throw new Error(`truncated H ${key} list`);
}

/** FE readiness uses case-exact function names and actual managed names, never prefix guesses. */
export function hReady({
  manifest: m,
  functions,
  services,
  triggers,
  topics,
  subscriptions,
  names = [m.observe, m.filtered],
}) {
  const identities = [];
  for (const name of names) {
    const full = `projects/${m.project}/locations/us-central1/functions/${name}`;
    const f = functions.find((f) => f.name === full);
    const service = services.find((s) => s.name === f?.serviceConfig?.service);
    const trigger = triggers.find((t) => t.name === f?.eventTrigger?.trigger);
    if (
      f?.environment !== "GEN_2" ||
      f?.state !== "ACTIVE" ||
      f?.eventTrigger?.triggerRegion !== m.location ||
      !service ||
      !trigger ||
      trigger.destination?.cloudFunction !== full
    )
      return { ready: false, identities };
    // Explicit declared placement, including source/build/AR and global managed Pub/Sub names.
    if (
      !service.name.startsWith(`projects/${m.project}/locations/us-central1/services/`) ||
      !trigger.name.startsWith(`projects/${m.project}/locations/us-central1/triggers/`) ||
      !/\/locations\/us-central1\/builds\//.test(f.buildConfig?.build ?? "") ||
      f.buildConfig?.dockerRepository !==
        `projects/${m.project}/locations/us-central1/repositories/gcf-artifacts` ||
      !/^(gcf-v2-sources-\d+-us-central1|uploads-\d+\.us-central1\.cloudfunctions\.appspot\.com)$/.test(
        f.buildConfig?.source?.storageSource?.bucket ?? "",
      )
    )
      return { ready: false, identities };
    for (const [key, collection] of [
      ["topic", "topics"],
      ["subscription", "subscriptions"],
    ]) {
      const resource = trigger.transport?.pubsub?.[key];
      if (
        typeof resource !== "string" ||
        !resource.startsWith(`projects/${m.project}/${collection}/`) ||
        !(key === "topic" ? topics : subscriptions)?.some((item) => item.name === resource)
      )
        return { ready: false, identities };
    }
    identities.push({
      handler: name,
      function: full,
      service: service.name,
      trigger: trigger.name,
      topic: trigger.transport.pubsub.topic,
      subscription: trigger.transport.pubsub.subscription,
      build: f.buildConfig.build,
      source: f.buildConfig.source.storageSource,
      repository: f.buildConfig.dockerRepository,
    });
  }
  return { ready: true, identities };
}
