// The guard that keeps every test, mutation pass and dry run of the Hosting recorder away from
// production. Whatever reaches a credential, the private ledger and run directories, or a network
// host other than loopback, refuses unless the process was started by the launch script, which sets
// FIREEMU_HOSTING_ALLOW_SEND=1 (nothing else sets it, and a test must never run with it set).
//
// It was added after a mutation pass of another lane reached real production APIs.

export const SEND_FLAG = "FIREEMU_HOSTING_ALLOW_SEND";

/** Whether this process was explicitly armed to send. */
export const isArmed = (env = process.env) => env[SEND_FLAG] === "1";

/** Throws unless the process is armed; `what` names the effect that was refused. */
export function assertMaySend(what, env = process.env) {
  if (!isArmed(env)) {
    throw new Error(
      `${what} refused: ${SEND_FLAG}=1 is not set (only the launch script arms a send)`,
    );
  }
}

/** A host that is this machine: the only host an unarmed process may talk to. */
export const isLoopback = (host) =>
  ["localhost", "127.0.0.1", "::1", "[::1]"].includes(String(host).toLowerCase());
