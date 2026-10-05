import { BudgetExceeded } from "./capture.mjs";

export class TimeLimit extends BudgetExceeded {
  constructor() {
    super(0);
    this.name = "TimeLimit";
    this.message = "the phase time budget is spent";
  }
}

/** A phase uses one monotonic clock, including transport deadlines and sleeps. */
export function createPhaseLimit(ms, now = () => performance.now()) {
  if (!Number.isSafeInteger(ms) || ms < 1)
    throw new Error("phase limit must be a positive integer");
  let end;
  const remaining = () => {
    end ??= now() + ms;
    const left = Math.floor(end - now());
    if (left < 1) throw new TimeLimit();
    return left;
  };
  return {
    remaining,
    transport(transport) {
      const wrap = (send) => (call) =>
        send.call(transport, {
          ...call,
          timeoutMs: Math.min(call.timeoutMs ?? 30_000, remaining()),
        });
      return {
        ...transport,
        ...(transport.request ? { request: wrap(transport.request) } : {}),
        ...(transport.call ? { call: wrap(transport.call) } : {}),
        ...(transport.stream ? { stream: wrap(transport.stream) } : {}),
      };
    },
    sleep: (sleep) => async (delay) => {
      if (delay >= remaining()) throw new TimeLimit();
      await sleep(delay);
      remaining();
    },
  };
}
