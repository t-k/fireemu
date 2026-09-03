export const requireNode20 = (version = process.versions.node) => {
  const major = Number.parseInt(version.split(".", 1)[0], 10);
  if (!Number.isInteger(major) || major < 20) {
    throw new Error(
      `The listener replacement smoke requires Node.js 20 or newer; found ${version}`,
    );
  }
};

export const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};
