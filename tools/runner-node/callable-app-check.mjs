// Version-bounded loader instrumentation for the callable App Check options of
// `firebase-functions` (docs/specifications/firebase-app-check.md, section 13.4).
//
// `enforceAppCheck` and `consumeAppCheckToken` never reach the deployed endpoint: both v1 and
// v2 keep them inside the callable wrapper's closure, and `__endpoint.callableTrigger` is an
// empty object. Reading them therefore means observing a callable as it is declared, which is
// what this module does -- before any user code loads.
//
// It hooks three functions rather than the `onCall` exports, because that is the one place
// every spelling passes through:
//
//   v2 onCall / onCallGenkit  ->  onCallHandler -> withInit -> wrapTraceContext
//   v1 onCall / _onCallWithOptions / runWith(...).https.onCall / region(...).https.onCall
//                             ->  onCallHandler -> wrapTraceContext
//
// The `onCall` exports themselves are not reachable everywhere: `firebase-functions/v1`
// re-exports `https` through non-configurable getters, and `onCallGenkit` calls the module's
// own `onCall` binding rather than the export. `onCallHandler` has no such escape hatch, and
// the options it receives are already resolved (global options folded in, `Expression`
// parameters evaluated), which is exactly what the daemon needs to see.
//
// Everything here is bounded by an explicit supported version range plus structural and
// behavioural probes. When any of them fails the answer is "undetermined", never a guess: the
// daemon then refuses to start Functions with App Check enabled.

import { readFileSync } from "node:fs";
import { createRequire, register } from "node:module";
import { dirname, join, parse as parsePath } from "node:path";
import { pathToFileURL } from "node:url";

/// `firebase-functions` majors whose callable internals this instrumentation is written for.
const SUPPORTED_MAJORS = [6, 7];

/// The one debug feature the trusted callable protocol turns on.
const REQUIRED_DEBUG_FEATURE = "skipTokenVerification";

/// The internal modules the hooks patch, relative to the package root.
const MODULES = {
  commonHttps: "lib/common/providers/https.js",
  trace: "lib/v2/trace.js",
  onInit: "lib/common/onInit.js",
  debug: "lib/common/debug.js",
};

const ESM_MODULES = {
  commonHttps: "lib/esm/common/providers/https.mjs",
  trace: "lib/esm/v2/trace.mjs",
  onInit: "lib/esm/common/onInit.mjs",
};

const REGISTRY_SYMBOL = Symbol.for("fireemu.callableAppCheck");

/// The directory of the `firebase-functions` package that owns `entry`.
function packageRootOf(entry) {
  let dir = dirname(entry);
  const { root: filesystemRoot } = parsePath(dir);
  for (;;) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      if (pkg.name === "firebase-functions") return dir;
    } catch {
      // Not a package directory; keep walking up.
    }
    if (dir === filesystemRoot) break;
    dir = dirname(dir);
  }
  throw new Error(`no firebase-functions package directory above ${entry}`);
}

function unsupported(reason) {
  return {
    supported: false,
    reason,
    version: null,
    debugFeatures: reason,
    authHeaders: [],
    optionsOf: () => undefined,
    graphs: { commonjs: "unsupported", esm: "not-loaded" },
  };
}

/// Whether `name` is an own data property of `target` that may be replaced.
function isPatchable(target, name) {
  const d = Object.getOwnPropertyDescriptor(target, name);
  return !!d && typeof d.value === "function" && d.writable !== false && d.configurable !== false;
}

/// Checks that the installed package reads the debug switches the way the trusted protocol
/// relies on. `debugMode` is captured when `debug.js` is first required, so this observes the
/// environment the daemon actually handed to this process.
function probeDebugFeatures(debug) {
  if (typeof debug.isDebugFeatureEnabled !== "function" || typeof debug.debugFeatureValue !== "function") {
    return "the installed firebase-functions does not expose isDebugFeatureEnabled / debugFeatureValue";
  }
  let declared = {};
  try {
    declared = JSON.parse(process.env.FIREBASE_DEBUG_FEATURES ?? "{}") ?? {};
  } catch {
    declared = {};
  }
  const wanted = process.env.FIREBASE_DEBUG_MODE === "true" && declared[REQUIRED_DEBUG_FEATURE] === true;
  if (debug.isDebugFeatureEnabled(REQUIRED_DEBUG_FEATURE) !== wanted) {
    return `the installed firebase-functions reads ${REQUIRED_DEBUG_FEATURE} differently from FIREBASE_DEBUG_MODE / FIREBASE_DEBUG_FEATURES`;
  }
  if (debug.isDebugFeatureEnabled("ftdFeatureThatDoesNotExist") !== false) {
    return "the installed firebase-functions enables debug features it was not asked for";
  }
  return "verified";
}

/// How a declared `consumeAppCheckToken` maps onto the three-valued manifest field.
function consumeState(value) {
  if (value === true) return "enabled";
  if (value === false || value === undefined || value === null) return "disabled";
  // A shape this instrumentation does not understand (an unevaluated parameter, say) is not
  // evidence of `false`.
  return "undetermined";
}

/// Installs the hooks and returns what the runner should report.
export function instrumentCallables(sourceDir) {
  const require = createRequire(join(sourceDir, "package.json"));
  let root;
  let version;
  try {
    // `firebase-functions` does not publish `./package.json` in its `exports` map, so the
    // package root is found from its resolved entry point instead of asked for by subpath.
    root = packageRootOf(require.resolve("firebase-functions"));
    version = String(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version ?? "");
  } catch (e) {
    return unsupported(`firebase-functions is not installed in ${sourceDir}: ${e?.message ?? e}`);
  }
  const major = Number.parseInt(version.split(".")[0], 10);
  if (!SUPPORTED_MAJORS.includes(major)) {
    return unsupported(
      `firebase-functions ${version} is outside the supported range (major ${SUPPORTED_MAJORS.join(", ")})`,
    );
  }

  const loaded = {};
  for (const [key, relative] of Object.entries(MODULES)) {
    try {
      // Required by absolute path on purpose: these are internal modules the package's
      // `exports` map does not publish, and the realpath is the same module instance the
      // provider modules themselves hold.
      loaded[key] = require(join(root, relative));
    } catch (e) {
      return unsupported(
        `firebase-functions ${version} has no ${relative}: ${e?.message ?? e}`,
      );
    }
  }

  const debugFeatures = probeDebugFeatures(loaded.debug);
  for (const [key, name] of [
    ["commonHttps", "onCallHandler"],
    ["trace", "wrapTraceContext"],
    ["onInit", "withInit"],
  ]) {
    if (!isPatchable(loaded[key], name)) {
      return {
        ...unsupported(`firebase-functions ${version} does not export a patchable ${name}`),
        version,
        debugFeatures,
      };
    }
  }
  for (const name of ["unsafeDecodeAppCheckToken", "CALLABLE_AUTH_HEADER", "ORIGINAL_AUTH_HEADER"]) {
    if (!(name in loaded.commonHttps)) {
      return {
        ...unsupported(
          `firebase-functions ${version} no longer defines ${name}; the callable trust boundary assumes it does`,
        ),
        version,
        debugFeatures,
      };
    }
  }
  // The *values*, not just the names. These are the fields the callable wrapper honours under
  // `skipTokenVerification` to override v1 auth context, and the daemon strips them by name
  // from every forwarded request. If a supported minor release renames one, the daemon's list
  // silently goes stale, so the daemon compares this report against its own and refuses to
  // start rather than forwarding a channel it no longer strips.
  const authHeaders = [
    loaded.commonHttps.CALLABLE_AUTH_HEADER,
    loaded.commonHttps.ORIGINAL_AUTH_HEADER,
  ].map((v) => String(v ?? "").toLowerCase());

  const options = new WeakMap();
  const observe = (fn, opts) => {
    if (typeof fn !== "function" || options.has(fn)) return;
    options.set(
      fn,
      Object.freeze({
        enforceAppCheck: (opts ?? {}).enforceAppCheck === true,
        consumeAppCheckToken: consumeState((opts ?? {}).consumeAppCheckToken),
      }),
    );
  };
  const carry = (from, to) => {
    if (typeof to === "function" && !options.has(to) && options.has(from)) {
      options.set(to, options.get(from));
    }
  };

  const originalOnCallHandler = loaded.commonHttps.onCallHandler;
  loaded.commonHttps.onCallHandler = function onCallHandler(opts, handler, version_) {
    const fn = originalOnCallHandler.call(this, opts, handler, version_);
    observe(fn, opts);
    return fn;
  };

  const originalWrapTrace = loaded.trace.wrapTraceContext;
  loaded.trace.wrapTraceContext = function wrapTraceContext(handler) {
    const fn = originalWrapTrace.call(this, handler);
    carry(handler, fn);
    return fn;
  };

  const originalWithInit = loaded.onInit.withInit;
  loaded.onInit.withInit = function withInit(func) {
    const fn = originalWithInit.call(this, func);
    carry(func, fn);
    return fn;
  };

  const esmLoaded = new Set();
  const esmFailed = new Map();
  const registry = Object.freeze({
    observe,
    carry,
    moduleLoaded(name) {
      esmLoaded.add(name);
    },
    moduleFailed(name, reason) {
      esmFailed.set(name, reason);
    },
  });
  Object.defineProperty(globalThis, REGISTRY_SYMBOL, {
    value: registry,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  const esmTargets = Object.fromEntries(
    Object.entries(ESM_MODULES).map(([name, relative]) => [
      pathToFileURL(join(root, relative)).href,
      name,
    ]),
  );
  register(new URL("./callable-app-check-loader.mjs", import.meta.url), {
    data: { targets: esmTargets },
  });

  const esmStatus = () => {
    if (esmFailed.size > 0) {
      return `failed: ${[...esmFailed.entries()]
        .map(([name, reason]) => `${name} (${reason})`)
        .join(", ")}`;
    }
    if (esmLoaded.size === 0) return "not-loaded";
    if (esmLoaded.size !== Object.keys(ESM_MODULES).length) {
      return `partial: ${[...esmLoaded].sort().join(", ")}`;
    }
    return "instrumented";
  };

  return {
    get supported() {
      const status = esmStatus();
      return status === "not-loaded" || status === "instrumented";
    },
    get reason() {
      const status = esmStatus();
      return status === "not-loaded" || status === "instrumented"
        ? null
        : `firebase-functions ${version} ESM callable instrumentation ${status}`;
    },
    version,
    debugFeatures,
    authHeaders,
    optionsOf: (fn) => options.get(fn),
    get graphs() {
      return { commonjs: "instrumented", esm: esmStatus() };
    },
  };
}
