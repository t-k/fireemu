import { createAdmission } from "./admission.mjs";
import { withProjectLocks } from "./project-locks.mjs";

// The project locks and the live admission as one. The lock set must be exactly this packet's; every request's admission
// then also proves the locks are still this run's, the run's only transport goes through the lease, and the locks are
// released only when the caller confirms a clean terminal state (a finished or recovered result, no outbound failure).
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const KEYS = ["locks", "readLedger", "packet", "review"];

export async function withLockedAdmission(options, run) {
  if (!plain(options) || Reflect.ownKeys(options).length !== KEYS.length || !KEYS.every((key) => Object.hasOwn(options, key)) || typeof run !== "function") throw new Error("invalid locked run options");
  const { locks, readLedger, packet, review } = options;
  if (!plain(locks) || !plain(packet) || !Array.isArray(locks.projects) || !Array.isArray(packet.projects)) throw new Error("invalid locked run options");
  const sorted = (projects) => JSON.stringify([...projects].sort());
  if (sorted(locks.projects) !== sorted(packet.projects) || locks.taskId !== packet.taskId || locks.packetId !== packet.packetName || locks.sourceCommit !== packet.sourceCommit) throw new Error("lock set does not match the packet");
  return withProjectLocks(locks, async (lease) => {
    const admission = createAdmission({ readLedger, packet, review, locks: { verify: () => lease.verifyHeld() } });
    return run({ admission, lease });
  });
}

/** The gate's real transport, sent through the lease so the locks know a request left and whether one failed. */
export function leaseTransport(lease, transport) {
  if (typeof lease?.dispatch !== "function" || typeof transport?.send !== "function" || typeof transport?.validate !== "function") throw new Error("invalid lease transport");
  return Object.freeze({ send: (spec) => lease.dispatch(() => transport.send(spec)), validate: (spec) => transport.validate(spec) });
}

/** Confirm the close to the lease only for a result that ended clean; anything else keeps the locks. */
export function confirmCleanClose(lease, result) {
  if (typeof lease?.confirmClosed !== "function") throw new Error("invalid lease");
  if (!plain(result) || !["finished", "recovered"].includes(result.status)) throw new Error("not a clean close");
  lease.confirmClosed();
}
