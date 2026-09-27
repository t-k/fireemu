const TRANSPORTS = new Set(['grpc', 'auth', 'admin', 'browser', 'http', 'https']);

/** Claim one outbound request before the transport starts it. */
export const createWireBudget = ({ maxRequests, cleanupReserve }) => {
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 2 || maxRequests > 12000 ||
      !Number.isSafeInteger(cleanupReserve) || cleanupReserve < 1 ||
      cleanupReserve >= maxRequests) {
    throw new Error('invalid wire request bounds');
  }
  let phase = 'observation';
  let observation = 0;
  let cleanup = 0;
  let exhausted = false;
  const transports = {};
  return Object.freeze({
    claim(requestPhase, transport) {
      if (requestPhase !== phase) throw new Error('invalid wire request phase');
      if (!TRANSPORTS.has(transport)) throw new Error('invalid wire transport');
      if (requestPhase === 'observation' && observation >= maxRequests - cleanupReserve ||
          requestPhase === 'cleanup' && observation + cleanup >= maxRequests ||
          requestPhase === 'cleanup' && cleanup >= cleanupReserve) {
        exhausted = true;
        throw new Error('wire request budget exhausted');
      }
      if (requestPhase === 'observation') observation++;
      else cleanup++;
      transports[transport] = (transports[transport] ?? 0) + 1;
      return observation + cleanup;
    },
    beginCleanup() {
      if (phase !== 'observation') throw new Error('invalid wire request phase');
      phase = 'cleanup';
    },
    snapshot() {
      return { maxRequests, cleanupReserve, phase, observation, cleanup,
        total: observation + cleanup, transports: { ...transports }, exhausted };
    },
  });
};
