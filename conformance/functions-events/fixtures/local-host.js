function isLoopbackHostPort(value) {
  if (typeof value !== "string") return false;
  const match = /^(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$/.exec(value);
  if (!match) return false;
  const port = Number(match[2]);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function requireLoopbackService(name, env = process.env) {
  if (!isLoopbackHostPort(env[name])) {
    throw new Error(`${name} must name a loopback emulator host and port`);
  }
  return env[name];
}

function assertLocalEnvironment(env = process.env) {
  for (const name of [
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_STORAGE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "PUBSUB_EMULATOR_HOST",
  ]) {
    requireLoopbackService(name, env);
  }
  if (env.STORAGE_EMULATOR_HOST !== undefined) {
    let endpoint;
    try {
      endpoint = new URL(env.STORAGE_EMULATOR_HOST);
    } catch {
      throw new Error("STORAGE_EMULATOR_HOST must name a loopback emulator host and port");
    }
    if (
      endpoint.protocol !== "http:" ||
      !isLoopbackHostPort(endpoint.host) ||
      endpoint.pathname !== "/" ||
      endpoint.search ||
      endpoint.hash
    ) {
      throw new Error("STORAGE_EMULATOR_HOST must name a loopback emulator host and port");
    }
  }
}

function assertFixtureEnvironment(env = process.env) {
  if (env.FE_EVENTS_MODE === undefined || env.FE_EVENTS_MODE === "local") {
    assertLocalEnvironment(env);
    return "local";
  }
  if (env.FE_EVENTS_MODE !== "production") {
    throw new Error("FE_EVENTS_MODE must be local or production");
  }
  const project = env.FE_EVENTS_PROJECT_ID;
  if (
    !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project ?? "") ||
    env.GCLOUD_PROJECT !== project ||
    (env.GCP_PROJECT !== undefined && env.GCP_PROJECT !== project) ||
    (env.GOOGLE_CLOUD_PROJECT !== undefined && env.GOOGLE_CLOUD_PROJECT !== project)
  ) {
    throw new Error("production fixture project does not match GCLOUD_PROJECT");
  }
  for (const name of Object.keys(env)) {
    if (name.endsWith("_EMULATOR_HOST")) {
      throw new Error("production fixture cannot use emulator hosts");
    }
  }
  if (env.FIREBASE_CONFIG !== undefined) {
    let config;
    try {
      config = JSON.parse(env.FIREBASE_CONFIG);
    } catch {
      throw new Error("production FIREBASE_CONFIG must be valid JSON");
    }
    if (config?.projectId !== project) {
      throw new Error("production FIREBASE_CONFIG project mismatch");
    }
  }
  if (!/^fe_events_[a-z0-9_]+$/.test(env.FE_EVENTS_PRIMARY_COLLECTION ?? "")) {
    throw new Error("production fixture collection is missing or invalid");
  }
  if (env.FE_EVENTS_PRIMARY_BUCKET !== `${project}.firebasestorage.app`) {
    throw new Error("production fixture bucket is not the default bucket");
  }
  if (!/^fe-events-[a-z0-9-]+$/.test(env.FE_EVENTS_PRIMARY_TOPIC ?? "")) {
    throw new Error("production fixture topic is missing or invalid");
  }
  if (env.FE_EVENTS_CAPTURE_MODE !== "reject-canary" || env.FE_EVENTS_CAPTURE_SOCKET) {
    throw new Error("production canary must reject unexpected events");
  }
  return "production";
}

function requireRetryFirestoreHost() {
  if (!isLoopbackHostPort(process.env.FIRESTORE_EMULATOR_HOST)) {
    throw new Error("retry requires a loopback Firestore emulator before Admin initialization");
  }
}

module.exports = {
  assertFixtureEnvironment,
  assertLocalEnvironment,
  isLoopbackHostPort,
  requireLoopbackService,
  requireRetryFirestoreHost,
};
