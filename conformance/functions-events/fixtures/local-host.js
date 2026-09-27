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

function requireRetryFirestoreHost() {
  if (!isLoopbackHostPort(process.env.FIRESTORE_EMULATOR_HOST)) {
    throw new Error("retry requires a loopback Firestore emulator before Admin initialization");
  }
}

module.exports = {
  assertLocalEnvironment,
  isLoopbackHostPort,
  requireLoopbackService,
  requireRetryFirestoreHost,
};
