// Node ESM loader hook for the version-bounded firebase-functions callable instrumentation.
// Only the exact internal module URLs resolved by callable-app-check.mjs are transformed.

const REGISTRY = 'globalThis[Symbol.for("fireemu.callableAppCheck")]';

let targets = new Map();

export function initialize(data) {
  targets = new Map(Object.entries(data?.targets ?? {}));
}

function replaceOnce(source, before, after, name) {
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error(`expected exactly one ${name} declaration`);
  }
  return source.slice(0, first) + after + source.slice(first + before.length);
}

function transform(source, name) {
  if (name === "commonHttps") {
    let next = replaceOnce(
      source,
      "function onCallHandler(options, handler, version) {",
      "function fireemuOriginalOnCallHandler(options, handler, version) {",
      "onCallHandler",
    );
    next = replaceOnce(
      next,
      "function encodeSSE(data) {",
      `function onCallHandler(options, handler, version) {\n\tconst fn = fireemuOriginalOnCallHandler(options, handler, version);\n\t${REGISTRY}.observe(fn, options);\n\treturn fn;\n}\nfunction encodeSSE(data) {`,
      "encodeSSE",
    );
    return next;
  }
  if (name === "trace") {
    let next = replaceOnce(
      source,
      "function wrapTraceContext(handler) {",
      "function fireemuOriginalWrapTraceContext(handler) {",
      "wrapTraceContext",
    );
    next = replaceOnce(
      next,
      "//#endregion\nexport { wrapTraceContext };",
      `function wrapTraceContext(handler) {\n\tconst fn = fireemuOriginalWrapTraceContext(handler);\n\t${REGISTRY}.carry(handler, fn);\n\treturn fn;\n}\n\n//#endregion\nexport { wrapTraceContext };`,
      "wrapTraceContext export",
    );
    return next;
  }
  if (name === "onInit") {
    let next = replaceOnce(
      source,
      "function withInit(func) {",
      "function fireemuOriginalWithInit(func) {",
      "withInit",
    );
    next = replaceOnce(
      next,
      "//#endregion\nexport { onInit, withInit };",
      `function withInit(func) {\n\tconst fn = fireemuOriginalWithInit(func);\n\t${REGISTRY}.carry(func, fn);\n\treturn fn;\n}\n\n//#endregion\nexport { onInit, withInit };`,
      "withInit export",
    );
    return next;
  }
  throw new Error(`unknown callable instrumentation module ${name}`);
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  const name = targets.get(url);
  if (!name) return result;
  const source = Buffer.isBuffer(result.source)
    ? result.source.toString("utf8")
    : String(result.source ?? "");
  try {
    const transformed = transform(source, name);
    return {
      ...result,
      source: `${REGISTRY}.moduleLoaded(${JSON.stringify(name)});\n${transformed}`,
    };
  } catch (error) {
    return {
      ...result,
      source: `${REGISTRY}.moduleFailed(${JSON.stringify(name)}, ${JSON.stringify(
        error?.message ?? String(error),
      )});\n${source}`,
    };
  }
}
