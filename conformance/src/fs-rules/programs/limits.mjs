// FS-RULES/compile-limits and FS-RULES/runtime-limits.
//
// Compile rows offer a whole ruleset source for compilation only (production `rulesets.create`,
// never released; fireemu's ruleset load, after which the harness restores the ruleset in
// force) and record whether it compiled. Runtime rows are gets of literal cases in `main`.

import { allow, FRESH, get, integer, seedDocs } from "./common.mjs";

const DB = "/databases/$(database)/documents";

const wrap = (inner, { version = "rules_version = '2';\n", service = "cloud.firestore" } = {}) =>
  `${version}service ${service} {\n  match /databases/{database}/documents {\n${inner}\n  }\n}\n`;

const matchGet = (condition, path = "/fsr-c/{d}") =>
  `    match ${path} {\n      allow get: if ${condition};\n    }`;

/** `f0()` calls `f1()` ... `f<depth-1>()`, which returns true: a static call chain of `depth`. */
function chain(depth) {
  const fns = Array.from({ length: depth }, (_, i) =>
    i === depth - 1
      ? `    function f${i}() { return true; }`
      : `    function f${i}() { return f${i + 1}(); }`,
  );
  return `${fns.join("\n")}\n${matchGet("f0()")}`;
}

const argsFn = (n) => {
  const params = Array.from({ length: n }, (_, i) => `a${i}`);
  return `    function g(${params.join(", ")}) { return a0 == 0; }\n${matchGet(`g(${params.map(() => "0").join(", ")})`)}`;
};

const lets = (n) => {
  const bindings = Array.from({ length: n }, (_, i) => `      let v${i} = ${i};`);
  return `    function h() {\n${bindings.join("\n")}\n      return v0 == 0;\n    }\n${matchGet("h()")}`;
};

const nested = (depth) => {
  let inner = "allow get: if true;";
  for (let i = depth - 1; i >= 0; i -= 1) inner = `match /n${i}/{c${i}} { ${inner} }`;
  return `    ${inner}`;
};

const captures = (n) =>
  matchGet("true", `/${Array.from({ length: n }, (_, i) => `s${i}/{c${i}}`).join("/")}`);

const padded = (bytes) => {
  const base = wrap(matchGet("true"));
  const comment = `// ${"x".repeat(Math.max(0, bytes - base.length - 4))}\n`;
  return comment + base;
};

/** `n` copies of `leaf` joined by `op` as a left-leaning chain (depth n). */
const chainOf = (n, leaf = "true", op = " && ") => Array.from({ length: n }, () => leaf).join(op);
/** `n` leaves combined by `&&` as a balanced tree (depth about log2 n). */
const balanced = (n, leaf = "true") =>
  n === 1
    ? leaf
    : `(${balanced(Math.floor(n / 2), leaf)} && ${balanced(n - Math.floor(n / 2), leaf)})`;

export const COMPILE_CASES = [
  ["valid", wrap(matchGet("true"))],
  ["syntax-error", wrap("    allow get: if ;")],
  ["unknown-function", wrap(matchGet("nosuch(1)"))],
  ["exists-after", wrap(matchGet(`existsAfter(${DB}/x/y)`))],
  ["unused-function", wrap(`    function unused() { return true; }\n${matchGet("true")}`)],
  ["arity-mismatch", wrap(`    function one(a) { return a; }\n${matchGet("one(true, false)")}`)],
  [
    "duplicate-function",
    wrap(
      `    function d() { return true; }\n    function d() { return false; }\n${matchGet("d()")}`,
    ),
  ],
  ["recursion", wrap(`    function r(n) { return n <= 0 || r(n - 1); }\n${matchGet("r(3)")}`)],
  [
    "mutual-recursion",
    wrap(`    function p() { return q(); }\n    function q() { return p(); }\n${matchGet("p()")}`),
  ],
  ["call-depth-20", wrap(chain(20))],
  ["call-depth-21", wrap(chain(21))],
  ["arguments-7", wrap(argsFn(7))],
  ["arguments-8", wrap(argsFn(8))],
  ["let-10", wrap(lets(10))],
  ["let-11", wrap(lets(11))],
  ["match-nesting-10", wrap(nested(10))],
  ["match-nesting-11", wrap(nested(11))],
  ["captures-20", wrap(captures(20))],
  ["captures-21", wrap(captures(21))],
  ["source-256k-minus", padded(256 * 1024 - 64)],
  ["source-256k-plus", padded(256 * 1024 + 64)],
  [
    "version-1-recursive-last",
    wrap(matchGet("true", "/fsr-c/{rest=**}"), { version: "rules_version = '1';\n" }),
  ],
  [
    "version-1-recursive-middle",
    wrap(matchGet("true", "/{rest=**}/fsr-c/{d}"), { version: "rules_version = '1';\n" }),
  ],
  ["version-2-recursive-middle", wrap(matchGet("true", "/{rest=**}/fsr-c/{d}"))],
  ["two-recursive-wildcards", wrap(matchGet("true", "/{a=**}/fsr-c/{b=**}"))],
  ["version-3", wrap(matchGet("true"), { version: "rules_version = '3';\n" })],
  ["no-version", wrap(matchGet("true"), { version: "" })],
  ["unknown-method", wrap("    match /fsr-c/{d} {\n      allow fetch: if true;\n    }")],
  ["wrong-service", wrap(matchGet("true"), { service: "firebase.storage" })],
  ["type-error-literal", wrap(matchGet("1 + 'a' == 2"))],
  ["regex-invalid-literal", wrap(matchGet("'a'.matches('(')"))],
  ["undefined-variable", wrap(matchGet("nosuchvar == 1"))],
  ["math-is-infinite", wrap(matchGet("math.isInfinite(1.0) == false"))],
  ["unknown-namespace-function", wrap(matchGet("math.nosuch(1) == 1"))],
  ["missing-semicolon", wrap("    match /fsr-c/{d} {\n      allow get: if true\n    }")],
  ["and-chain-98", wrap(matchGet(chainOf(98)))],
  ["and-chain-99", wrap(matchGet(chainOf(99)))],
  ["or-chain-98", wrap(matchGet(chainOf(98, "false", " || ").replace(/false$/, "true")))],
  ["or-chain-99", wrap(matchGet(chainOf(99, "false", " || ").replace(/false$/, "true")))],
  ["plus-chain-98", wrap(matchGet(`${chainOf(98, "1", " + ")} > 0`))],
  ["plus-chain-99", wrap(matchGet(`${chainOf(99, "1", " + ")} > 0`))],
  ["not-98", wrap(matchGet(`${"!".repeat(98)}true`))],
  ["not-99", wrap(matchGet(`${"!".repeat(99)}true`))],
  ["parentheses-98", wrap(matchGet(`${"(".repeat(98)}true${")".repeat(98)}`))],
  ["parentheses-99", wrap(matchGet(`${"(".repeat(99)}true${")".repeat(99)}`))],
  ["list-nesting-98", wrap(matchGet(`${"[".repeat(98)}${"]".repeat(98)} != null`))],
  ["list-nesting-99", wrap(matchGet(`${"[".repeat(99)}${"]".repeat(99)} != null`))],
  ["balanced-1000", wrap(matchGet(balanced(1000)))],
  // How the nesting depth is counted when constructs mix, and for the constructs not above.
  ["not-parentheses-49", wrap(matchGet(`${"!(".repeat(49)}true${")".repeat(49)}`))],
  ["not-parentheses-50", wrap(matchGet(`${"!(".repeat(50)}true${")".repeat(50)}`))],
  ["map-nesting-98", wrap(matchGet(`${"{'a': ".repeat(98)}1${"}".repeat(98)} != null`))],
  ["map-nesting-99", wrap(matchGet(`${"{'a': ".repeat(99)}1${"}".repeat(99)} != null`))],
  [
    "call-nesting-98",
    wrap(
      `    function id(x) { return x; }\n${matchGet(`${"id(".repeat(98)}true${")".repeat(98)}`)}`,
    ),
  ],
  [
    "call-nesting-99",
    wrap(
      `    function id(x) { return x; }\n${matchGet(`${"id(".repeat(99)}true${")".repeat(99)}`)}`,
    ),
  ],
  ["and-chain-97", wrap(matchGet(chainOf(97)))],
  ["let-20", wrap(lets(20))],
  ["let-50", wrap(lets(50))],
];

/** A shallow conjunction of `n` true leaves: many evaluated expressions, little depth. */
const terms = (n) => balanced(n);

/** `f0(x)` ... a runtime call chain of `depth` evaluated calls. */
const runtimeChain = (name, depth) =>
  Array.from({ length: depth }, (_, i) =>
    i === depth - 1
      ? `    function ${name}${i}() { return true; }`
      : `    function ${name}${i}() { return ${name}${i + 1}(); }`,
  ).join("\n");

/** `[case, rules]`: each case is one or more allow statements on `/fsr-rt/<case>`. */
const RUNTIME_CASES = [
  ["terms-100", [terms(100)]],
  ["terms-250", [terms(250)]],
  ["terms-333", [terms(333)]],
  ["terms-334", [terms(334)]],
  ["terms-335", [terms(335)]],
  ["terms-400", [terms(400)]],
  ["terms-500", [terms(500)]],
  ["terms-501", [terms(501)]],
  ["terms-999", [terms(999)]],
  ["terms-1000", [terms(1000)]],
  ["terms-1001", [terms(1001)]],
  ["terms-2000", [terms(2000)]],
  ["call-chain-20", ["cc0()"]],
  ["true-then-error", ["true", `get(${DB}/fsr-rt-src/missing).data.n == 1`]],
  ["error-then-true", [`get(${DB}/fsr-rt-src/missing).data.n == 1`, "true"]],
  [
    "true-then-budget",
    ["true", Array.from({ length: 11 }, (_, i) => `exists(${DB}/fsr-rt-src/m${i})`).join(" || ")],
  ],
  ["true-then-bad-regex", ["true", "'a'.matches(resource.data.pattern)"]],
  ["true-then-get-after", ["true", `getAfter(${DB}/fsr-rt-src/present).data.n == 1`]],
  [
    "budget-then-true",
    [Array.from({ length: 11 }, (_, i) => `exists(${DB}/fsr-rt-src/m${i})`).join(" || "), "true"],
  ],
  ["bad-regex-then-true", ["'a'.matches(resource.data.pattern)", "true"]],
  ["terms-500-then-true", [terms(500), "true"]],
  ["true-then-terms-500", ["true", terms(500)]],
  ["terms-500-or-true", [`${terms(500)} || true`]],
  ["error-or-true", [`get(${DB}/fsr-rt-src/missing).data.n == 1 || true`]],
  ["true-or-error", [`true || get(${DB}/fsr-rt-src/missing).data.n == 1`]],
  ["error-and-false", [`!(get(${DB}/fsr-rt-src/missing).data.n == 1 && false)`]],
  ["false-and-error", [`!(false && get(${DB}/fsr-rt-src/missing).data.n == 1)`]],
  ["missing-member", ["resource.data.nosuch == 1"]],
  ["missing-member-default", ["resource.data.get('nosuch', 0) == 0"]],
  ["missing-member-in", ["!('nosuch' in resource.data)"]],
  ["bad-regex-dynamic", ["'a'.matches(resource.data.pattern)"]],
  ["int-overflow", ["9223372036854775807 + 1 > 0"]],
  ["int-division", ["7 / 2 == 3"]],
  ["float-division", ["7.0 / 2 == 3.5"]],
  ["int-float-equality", ["1 == 1.0"]],
  ["math-is-infinite", ["math.isInfinite(1.0) == false"]],
  ["debug-returns-value", ["debug(true)"]],
  ["unknown-function-runtime", ["nosuch(1)"]],
  ["exists-after-runtime-read", [`existsAfter(${DB}/fsr-rt-src/present)`]],
  ["null-comparison", ["resource.data.nullField == null"]],
  ["string-size-bytes", ["'é'.size() == 1"]],
  ["timestamp-date", ["request.time.date() is timestamp"]],
  ["duration-value", ["duration.value(1, 's') == duration.value(1000, 'ms')"]],
];

export const FRAGMENTS = [
  [
    runtimeChain("cc", 20),
    ...RUNTIME_CASES.flatMap(([name, conditions]) =>
      conditions.map((condition) => allow(`/fsr-rt/${name}`, "get", condition)),
    ),
  ].join("\n"),
];

export const PROGRAMS = [
  {
    id: "fs-rules/compile/acceptance",
    // Compilation needs no ruleset in force; run without one, so fireemu, where a compile probe
    // is a load, restores nothing but an empty slot.
    ruleset: null,
    steps: COMPILE_CASES.map(([name, source]) => ({ id: name, compile: source })),
  },
  {
    id: "fs-rules/runtime-limits/evaluation",
    ruleset: "main",
    refresh: FRESH,
    seed: seedDocs([
      ["fsr-rt-src/present", { n: integer(1) }],
      ...RUNTIME_CASES.map(([name]) => [
        `fsr-rt/${name}`,
        { n: integer(1), pattern: { stringValue: "(" }, nullField: { nullValue: null } },
      ]),
    ]),
    steps: [
      ...RUNTIME_CASES.map(([name]) => get(name, "a", `fsr-rt/${name}`)),
      get("terms-1000-grpc", "a", "fsr-rt/terms-1000", { transport: "grpc" }),
      get("true-then-error-grpc", "a", "fsr-rt/true-then-error", { transport: "grpc" }),
    ],
  },
];
