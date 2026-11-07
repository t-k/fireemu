export { endpoint, boundedRequest } from "./corpus.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export function verifyResources(actual) {
  for (const [key, expected] of Object.entries({ memory: "4294967296", swap: "0", pids: "256" })) {
    assert.equal(actual[key], expected, `resource ${key} is not bounded as required`);
  }
}

export function verifyIdentity(actual, id, owner) {
  assert.match(id, /^[a-f0-9]{64}$/, "ownership requires a full container ID");
  assert.equal(actual.Id, id, "ownership container ID mismatch");
  assert.equal(
    actual.Config?.Labels?.["fireemu.dataconnect.run"],
    owner,
    "ownership label mismatch",
  );
}

export function compareFixture(expected, actual) {
  assert.deepEqual(
    actual,
    expected,
    "fixture differs: cases, order and semantic values must match",
  );
}

export function verifyDigest(bytes, expected) {
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    expected,
    "artifact checksum mismatch",
  );
}

import { spawn, spawnSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  copyFileSync,
  cpSync,
  readdirSync,
  openSync,
  closeSync,
  chownSync,
  appendFileSync,
  existsSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";

export const pins = {
  cli: "15.28.2",
  sdk: "12.18.0",
  pglite: "0.3.16",
  node: "24.14.0",
  toolkit: "3.4.18",
  toolkitSha256: "bb381de594485653812bee518ddae025c13e1050670d6fa186f6003c3c9b71ec",
  postgresBase: "sha256:73bedc9eaa0121b92b9b26bb52e5141b3f6f37479c7ef913c0160455763ca80a",
};
const here = path.dirname(fileURLToPath(import.meta.url));
const inputFiles = [
  "firebase.json",
  "dataconnect.yaml",
  "schema/schema.gql",
  "connector/connector.yaml",
  "connector/operations.gql",
];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function command(binary, args, options = {}) {
  const { includeStderr = false, ...spawnOptions } = options;
  const result = spawnSync(binary, args, {
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
    ...spawnOptions,
  });
  if (result.error || result.status !== 0)
    throw new Error(
      `${binary} ${args[0]} failed: ${result.error?.message ?? result.status}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    );
  return includeStderr ? `${result.stdout}${result.stderr}` : result.stdout;
}

async function offlineControl() {
  assert.deepEqual(
    readdirSync("/sys/class/net"),
    ["lo"],
    "offline namespace must have only loopback",
  );
  const routes = readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1);
  assert.equal(routes.length, 0, "offline namespace must have no IPv4 routes");
  const ipv6 = readFileSync("/proc/net/ipv6_route", "utf8").trim().split("\n").filter(Boolean);
  assert.ok(
    ipv6.every((line) => line.trim().split(/\s+/).at(-1) === "lo"),
    "offline IPv6 interface",
  );
  for (const address of ["192.0.2.1", "2001:db8::1"]) {
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: address, port: 9 });
      socket.setTimeout(1000);
      socket.once("connect", () => {
        socket.destroy();
        reject(new Error("offline egress unexpectedly succeeded"));
      });
      socket.once("timeout", () => {
        socket.destroy();
        reject(new Error("offline denial was inconclusive"));
      });
      socket.once("error", (error) => {
        socket.destroy();
        if (["ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL"].includes(error.code)) resolve();
        else reject(error);
      });
    });
  }
  const server = net.createServer((socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: server.address().port });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", reject);
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise((resolve) => child.once("close", resolve));
  child.kill("SIGTERM");
  const graceful = await Promise.race([closed.then(() => true), delay(8000).then(() => false)]);
  if (!graceful && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  await Promise.race([
    closed,
    delay(2000).then(() => {
      throw new Error("owned CLI did not stop");
    }),
  ]);
}

async function inside(mode) {
  assert.ok(["pglite", "postgres"].includes(mode));
  mkdirSync("/out", { recursive: true });
  mkdirSync("/work/home", { recursive: true });
  const resources = Object.fromEntries(
    Object.entries({ memory: "memory.max", swap: "memory.swap.max", pids: "pids.max" }).map(
      ([key, file]) => [key, readFileSync(`/sys/fs/cgroup/${file}`, "utf8").trim()],
    ),
  );
  verifyResources(resources);
  await offlineControl();
  assert.equal(process.versions.node, pins.node, "Node pin");
  for (const [pkg, version] of [
    ["firebase", pins.sdk],
    ["firebase-tools", pins.cli],
    ["@electric-sql/pglite", pins.pglite],
  ]) {
    const packagePath = pkg.startsWith("@")
      ? `/suite/node_modules/.pnpm/${pkg.replace("/", "+")}@${version}/node_modules/${pkg}/package.json`
      : `/suite/node_modules/${pkg}/package.json`;
    assert.equal(JSON.parse(readFileSync(packagePath, "utf8")).version, version, `${pkg} pin`);
  }
  verifyDigest(readFileSync(`/oracle/dataconnect-emulator-${pins.toolkit}`), pins.toolkitSha256);
  const inputs = Object.fromEntries(
    [...inputFiles, "run.mjs", "corpus.mjs"].map((file) => [
      file,
      hash(readFileSync(path.join(here, file))),
    ]),
  );
  inputs["conformance/pnpm-lock.yaml"] = hash(readFileSync("/suite/pnpm-lock.yaml"));
  writeFileSync(
    "/out/environment.json",
    JSON.stringify({ pins, resources, inputs, offline: true }, null, 2),
  );
  for (const file of inputFiles) {
    const destination = path.join("/work/config", file);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(here, file), destination);
  }
  const env = {
    ...process.env,
    HOME: "/work/home",
    XDG_CONFIG_HOME: "/work/home/config",
    FIREBASE_EMULATORS_PATH: "/oracle",
    CI: "true",
    FIREBASE_CLI_DISABLE_TELEMETRY: "1",
  };
  const cli = "/suite/node_modules/firebase-tools/lib/bin/firebase.js";
  const common = [
    "--project",
    "demo-fireemu-dataconnect",
    "--config",
    "/work/config/firebase.json",
    "--non-interactive",
  ];
  let child;
  let databaseStarted = false;
  const fd = openSync("/out/cli.log", "a");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    const response = await originalFetch(...args);
    const url = typeof args[0] === "string" ? args[0] : (args[0].url ?? String(args[0]));
    appendFileSync(
      "/out/wire.jsonl",
      `${JSON.stringify({ url, status: response.status, body: await response.clone().text() })}\n`,
    );
    return response;
  };
  const start = async (importPath) => {
    child = spawn(
      process.execPath,
      [
        cli,
        "emulators:start",
        "--only",
        "dataconnect",
        ...common,
        ...(importPath ? ["--import", importPath] : []),
      ],
      { env, cwd: "/work/config", stdio: ["ignore", fd, fd] },
    );
    const deadline = Date.now() + 60_000;
    let configured = false;
    while (Date.now() < deadline) {
      if (child.exitCode !== null || child.signalCode !== null)
        throw new Error("official CLI exited before ready");
      if (!configured) {
        try {
          const response = await originalFetch("http://127.0.0.1:9399/emulator/info", {
            signal: AbortSignal.timeout(1000),
          });
          if (response.ok) configured = readyService(await response.json());
        } catch {
          /* The local listener may not have bound yet. */
        }
      }
      if (configured) {
        const name =
          "projects/demo-fireemu-dataconnect/locations/us-central1/services/fixture/connectors/fixture";
        const response = await originalFetch(
          `http://127.0.0.1:9399/v1/${name}:executeQuery?key=synthetic-key`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name, operationName: "ListItems", variables: {} }),
            signal: AbortSignal.timeout(Math.max(1, Math.min(1000, deadline - Date.now()))),
          },
        );
        const body = await response.json();
        appendFileSync(
          "/out/readiness.jsonl",
          `${JSON.stringify({ status: response.status, body })}\n`,
        );
        if (readyQuery(response.status, body)) return;
      }
      await delay(250);
    }
    throw new Error("official CLI readiness deadline");
  };
  try {
    const build = spawnSync(
      `/oracle/dataconnect-emulator-${pins.toolkit}`,
      ["--logtostderr", "-v=2", "build", "--config_dir=/work/config"],
      { env, cwd: "/work/config", encoding: "utf8", timeout: 30000, maxBuffer: 4 * 1024 * 1024 },
    );
    writeFileSync("/out/build.stdout.json", build.stdout ?? "");
    writeFileSync("/out/build.stderr.log", build.stderr ?? "");
    verifyBuild(build);
    if (mode === "postgres") {
      mkdirSync("/work/pg", { recursive: true });
      chownSync("/work/pg", 999, 999);
      command("gosu", ["postgres", "initdb", "-D", "/work/pg", "-A", "trust", "-U", "postgres"]);
      command("gosu", [
        "postgres",
        "pg_ctl",
        "-D",
        "/work/pg",
        "-o",
        "-h 127.0.0.1 -p 5432 -c shared_buffers=64MB -c max_connections=20",
        "-l",
        "/work/pg/server.log",
        "-w",
        "start",
      ]);
      databaseStarted = true;
      env.FIREBASE_DATACONNECT_POSTGRESQL_STRING =
        "postgresql://postgres@127.0.0.1:5432/postgres?sslmode=disable";
    }
    await start();
    const { runCorpus, readPersistence } = await import("./corpus.mjs");
    const results = await runCorpus("http://127.0.0.1:9399", (row) =>
      appendFileSync("/out/cases.jsonl", `${JSON.stringify(row)}\n`),
    );
    const exportResult = spawnSync(
      process.execPath,
      [cli, "emulators:export", "/work/export", "--only", "dataconnect", ...common],
      { env, cwd: "/work/config", encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
    );
    writeFileSync("/out/export.log", `${exportResult.stdout ?? ""}\n${exportResult.stderr ?? ""}`);
    assert.equal(
      exportResult.error,
      undefined,
      "export must complete without timeout or spawn failure",
    );
    if (mode === "pglite") {
      assert.equal(exportResult.status, 0, "PGlite export succeeds");
      await stopChild(child);
      await start("/work/export");
      const after = await readPersistence("http://127.0.0.1:9399");
      assert.deepEqual(after, results.at(-1).data, "PGlite snapshot restores data");
      results.push({ id: "export-import", data: after });
    } else {
      assert.notEqual(exportResult.status, 0, "external PostgreSQL export is refused");
      const clientMessage = "Export request failed, see emulator logs for more information.";
      const hubMessage =
        "Skipping export for SQL Connect because FIREBASE_DATACONNECT_POSTGRESQL_STRING is set.";
      assert.ok(`${exportResult.stdout}${exportResult.stderr}`.includes(clientMessage));
      assert.ok(readFileSync("/out/cli.log", "utf8").includes(hubMessage));
      results.push({
        id: "external-export-refused",
        error: { exitCode: exportResult.status, message: clientMessage, reason: hubMessage },
      });
    }
    await stopChild(child);
    child = undefined;
    if (databaseStarted) {
      command("gosu", ["postgres", "pg_ctl", "-D", "/work/pg", "-m", "fast", "-w", "stop"]);
      databaseStarted = false;
    }
    writeFileSync("/out/results.json", `${JSON.stringify(results, null, 2)}\n`);
  } finally {
    globalThis.fetch = originalFetch;
    if (child) await stopChild(child);
    if (databaseStarted)
      command("gosu", ["postgres", "pg_ctl", "-D", "/work/pg", "-m", "fast", "-w", "stop"]);
    closeSync(fd);
    for (const file of ["dataconnect-debug.log", "firebase-debug.log"]) {
      const source = path.join("/work/config", file);
      if (existsSync(source)) copyFileSync(source, path.join("/out", file));
    }
    if (existsSync("/work/pg/server.log")) copyFileSync("/work/pg/server.log", "/out/postgres.log");
    for (const file of ["memory.current", "memory.peak", "memory.events"]) {
      writeFileSync(`/out/${file}`, readFileSync(`/sys/fs/cgroup/${file}`));
    }
  }
}

export function cleanupOwned(
  { id, owner, directory, podman, absent, save = writeFileSync },
  primaryFailure,
) {
  const failures = [];
  const report = () => {
    if (failures.length)
      throw new AggregateError(
        primaryFailure ? [primaryFailure, ...failures] : failures,
        "owned cleanup or diagnostics failed",
        { cause: primaryFailure },
      );
  };
  const attempt = (operation) => {
    try {
      operation();
    } catch (error) {
      failures.push(error);
    }
  };
  let info;
  try {
    info = JSON.parse(podman(["inspect", id]))[0];
    verifyIdentity(info, id, owner);
  } catch (error) {
    if (!primaryFailure) throw error;
    failures.push(error);
    report();
  }
  attempt(() => save(path.join(directory, "final-inspect.json"), JSON.stringify(info, null, 2)));
  if (info.State.Running) attempt(() => podman(["stop", "--time", "5", id]));
  attempt(() =>
    save(path.join(directory, "container.log"), podman(["logs", id], { includeStderr: true })),
  );
  attempt(() => podman(["rm", "--volumes", id]));
  attempt(() => assert.ok(absent("container", id), "owned container must be absent"));
  for (const mount of info.Mounts ?? []) {
    if (mount.Type === "volume")
      attempt(() =>
        assert.ok(absent("volume", mount.Name), "owned anonymous volume must be absent"),
      );
  }
  report();
}

async function host(action, connection, image, toolkit, output) {
  assert.ok(["record", "check"].includes(action), "use record or check");
  assert.ok(
    connection && output && toolkit,
    "explicit connection, image, toolkit and fresh output directory required",
  );
  assert.match(image, /^(sha256:)?[a-f0-9]{64}$/, "use an immutable local image ID");
  verifyDigest(readFileSync(toolkit), pins.toolkitSha256);
  mkdirSync(output, { recursive: false });
  const podman = (args, options = {}) =>
    command("podman", ["--connection", connection, ...args], options);
  const imageInfo = JSON.parse(podman(["image", "inspect", image]))[0];
  assert.equal(imageInfo.Architecture, "amd64");
  const records = {};
  for (const mode of ["pglite", "postgres"]) {
    const owner = `dataconnect-${mode}-${process.pid}-${Date.now()}`;
    let id;
    let primaryFailure;
    const directory = path.join(output, mode);
    mkdirSync(directory);
    try {
      id = podman([
        "create",
        "--label",
        `fireemu.dataconnect.run=${owner}`,
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--pull",
        "never",
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
        "--cpus",
        "2",
        "--pids-limit",
        "256",
        "--timeout",
        "240",
        "--env",
        "HOME=/work/home",
        image,
        "/suite/dataconnect/run.mjs",
        "--inside",
        mode,
      ]).trim();
      writeFileSync(path.join(directory, "cid"), `${id}\n`);
      const info = JSON.parse(podman(["inspect", id]))[0];
      verifyIdentity(info, id, owner);
      assert.equal(info.HostConfig.NetworkMode, "none");
      assert.equal(Object.keys(info.HostConfig.PortBindings ?? {}).length, 0);
      writeFileSync(path.join(directory, "launch.json"), JSON.stringify(info, null, 2));
      podman(["cp", here, `${id}:/suite/dataconnect`]);
      podman(["cp", toolkit, `${id}:/tmp/dataconnect-emulator-3.4.18`]);
      // The verified toolkit remains separate from the locally built image.
      podman(["start", id]);
      const wait = podman(["wait", id], { timeout: 250_000 }).trim();
      podman(["cp", `${id}:/out/.`, directory]);
      writeFileSync(
        path.join(directory, "container.log"),
        podman(["logs", id], { includeStderr: true }),
      );
      assert.equal(wait, "0", `${mode} oracle failed; see captured output`);
      records[mode] = JSON.parse(readFileSync(path.join(directory, "results.json"), "utf8"));
      if (action === "check")
        compareFixture(
          JSON.parse(readFileSync(path.join(here, "fixtures", `${mode}.json`), "utf8")),
          records[mode],
        );
    } catch (error) {
      primaryFailure = error;
      throw error;
    } finally {
      if (id)
        cleanupOwned(
          {
            id,
            owner,
            directory,
            podman,
            absent: (kind, name) =>
              spawnSync("podman", ["--connection", connection, kind, "exists", name]).status === 1,
          },
          primaryFailure,
        );
    }
  }
  if (action === "record") {
    for (const mode of ["pglite", "postgres"])
      writeFileSync(
        path.join(output, `${mode}.json`),
        `${JSON.stringify(records[mode], null, 2)}\n`,
      );
    const environment = JSON.parse(
      readFileSync(path.join(output, "pglite/environment.json"), "utf8"),
    );
    writeFileSync(
      path.join(output, "provenance.json"),
      `${JSON.stringify({ ...environment, imageId: imageInfo.Id, postgresVersion: "17.11", cases: Object.fromEntries(Object.entries(records).map(([mode, rows]) => [mode, rows.map((row) => row.id)])), productionObserved: false }, null, 2)}\n`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === "--check-corpus") {
      const corpus = await import("./corpus.mjs");
      assert.equal(typeof corpus.runCorpus, "function");
      console.log("corpus module ready");
    } else if (process.argv[2] === "--inside") {
      mkdirSync("/oracle", { recursive: true });
      cpSync("/tmp/dataconnect-emulator-3.4.18", "/oracle/dataconnect-emulator-3.4.18");
      await inside(process.argv[3]);
    } else {
      await host(...process.argv.slice(2));
    }
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}

export function readyService(info) {
  return Boolean(
    info.services?.some((service) => service.serviceId === "fixture" && service.connectionString),
  );
}

export function readyQuery(status, body) {
  if (status === 200 && Array.isArray(body?.data?.items)) return true;
  if (
    status === 404 &&
    body?.code === 5 &&
    body.message === 'no schema found for service "fixture". No service has a schema.' &&
    Array.isArray(body.details) &&
    body.details.length === 0
  )
    return false;
  throw new Error(`readiness failed: ${status} ${JSON.stringify(body)}`);
}
export function verifyBuild(result) {
  assert.equal(result.error, undefined, "toolkit build process error");
  assert.equal(result.status, 0, "toolkit build process failed");
  let body;
  try {
    body = JSON.parse(result.stdout);
  } catch {
    throw new Error("toolkit build returned invalid JSON");
  }
  assert.ok(
    body && typeof body === "object" && !Array.isArray(body),
    "toolkit build object required",
  );
  assert.ok(
    body.errors === undefined || (Array.isArray(body.errors) && body.errors.length === 0),
    `toolkit build errors: ${JSON.stringify(body.errors)}`,
  );
  return body;
}
