// A clock that only the test moves. The tests that run a recording and then an A2 against it decide by
// time (the A2 refuses to start within ten minutes of the newest capture), and the recorder stamps its
// captures with `new Date()`. Installing this clock makes every `Date.now()` and `new Date()` in the test
// process the test's own virtual instant, so that no decision depends on the wall clock (a fixed date in
// the A2 tests failed once the wall clock passed it, and a date computed from the wall clock only moves
// that failure later).

export function installVirtualClock(start) {
  const Real = globalThis.Date;
  let current = start;
  class VirtualDate extends Real {
    constructor(...args) {
      if (args.length === 0) super(current);
      else super(...args);
    }
    static now() {
      return current;
    }
  }
  globalThis.Date = VirtualDate;
  return {
    set: (instant) => {
      current = instant;
    },
    get: () => current,
    restore: () => {
      globalThis.Date = Real;
    },
  };
}
