// The production-send guard. The flag is read from the process environment every time a client is about
// to send (HTTPS, gRPC, credentials), never cached and never replaced by an option or an injected
// dependency: a loopback destination needs nothing, every other destination needs the flag the launch
// script exports. A test or a mutation run never sets it.

export const SEND_FLAG = "PUBSUB_NEGCACHE_PRODUCTION_SEND";
export const SEND_FLAG_VALUE = "launch-script";
export const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

/** A refusal is fatal to a run (nothing was sent): the runner never turns it into an ordinary failure. */
export const SEND_REFUSED = "SEND_REFUSED";
const refusal = (message) => Object.assign(new Error(message), { code: SEND_REFUSED });

export const productionSendApproved = (env = process.env) => env[SEND_FLAG] === SEND_FLAG_VALUE;

/** Throws unless `host` is loopback or the flag is set. `env` is a parameter only so the predicate can be tested. */
export function assertSendAllowed(host, env = process.env) {
  if (LOOPBACK_HOSTS.has(host)) return;
  if (!productionSendApproved(env))
    throw refusal(
      `refusing to send to ${host}: the production send flag ${SEND_FLAG} is not set (only the launch script sets it)`,
    );
}

/** Throws unless the flag is set: the gcloud credential helper is a production client. */
export function assertCredentialsAllowed(env = process.env) {
  if (!productionSendApproved(env))
    throw refusal(
      `refusing to read credentials: the production send flag ${SEND_FLAG} is not set (only the launch script sets it)`,
    );
}
