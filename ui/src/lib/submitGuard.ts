import { createSignal, type Accessor } from "solid-js";

/**
 * Double-submit protection for asynchronous actions: a synchronous flag refuses re-entry
 * before the reactive `pending` signal has propagated, and `pending` disables the button.
 */
export const createSubmitGuard = (): {
  pending: Accessor<boolean>;
  run: <T>(action: () => Promise<T>) => Promise<T | undefined>;
} => {
  let inFlight = false;
  const [pending, setPending] = createSignal(false);
  const run = async <T>(action: () => Promise<T>): Promise<T | undefined> => {
    if (inFlight) {
      return undefined;
    }
    inFlight = true;
    setPending(true);
    try {
      return await action();
    } finally {
      inFlight = false;
      setPending(false);
    }
  };
  return { pending, run };
};
