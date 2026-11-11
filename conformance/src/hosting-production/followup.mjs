// The corpus of the Hosting follow-up observation (packet v1): five site versions that answer the
// open To-Dos of the HOSTING closure record. Like `corpus.mjs` it performs no I/O; the recorder
// deploys one version at a time to its own preview channel, sends the version's requests, and
// deletes it. The recorder runs it under `FIREEMU_HOSTING_PROFILE=followup` (see `record.mjs`).
//
//   v11  the default 404 page, the hosted /__/auth/handler page (both bodies kept), dot-segment
//        and backslash paths
//   v12  redirect sources with digit-bearing parameter names (the `:id2` readings)
//   v13  a redirect source that repeats a parameter name (the deploy may be refused)
//   v14  precompressed files whose `headers` rule sets Content-Encoding (the deploy may be refused)
//   v15  which sizes and content types production gzips, and how it reads Accept-Encoding
import { corpusManifest } from "./corpus.mjs";
import { FOLLOWUP_CORPUS_SHA256 } from "./pins.mjs";

export const FOLLOWUP_CORPUS_ID = "hosting-followup-v1";

export const FOLLOWUP_CONDITIONS = [
  "default-404",
  "auth-handler",
  "dot-segments",
  "redirect-names",
  "precompressed",
  "gzip-sizes",
  "gzip-types",
  "gzip-negotiation",
];

const text = (value) => Buffer.from(value, "utf8");
const LINE = "The quick brown fox jumps over the lazy dog.\n";
/** `size` bytes of the repeated line: compressible at any size. */
const sized = (size) => text(LINE.repeat(Math.ceil(size / LINE.length)).slice(0, size));
const BIG = sized(4500);
const READY = text("ready\n");
const HOME = text("<h1>home</h1>\n");

/**
 * BIG packed once, with the bytes fixed here so that the corpus digest does not depend on the
 * compressor of the Node that builds it: brotli quality 11 and gzip level 9 (header OS 3).
 */
export const PRECOMPRESSED = {
  br: Buffer.from(
    "G5MRiCwO7JgyeGHDdOprBaoyNElmxtYgZ3h6KuytQVzm8sIGHDgkkDca3KDTCmceHieqKTjCCUkA2KeBAQ==",
    "base64",
  ),
  gzip: Buffer.from(
    "H4sIAAAAAAACE+3KyQFAMBRF0b0qXgWqSQOGEIRPiKl6TVjesz4ueG15aCbVya5Fnd0a87zustMnHcErVu+j1vqycGQymUwmk8lkMplMJpPJ5D/yB44gUHOUEQAA",
    "base64",
  ),
};

const base = (extra = {}) => ({ "index.html": HOME, "ready.txt": READY, ...extra });

const R = (version, slug, condition, method, target, extra = {}) => ({
  id: `${version}.${slug}`,
  condition,
  method,
  target,
  headers: {},
  ...extra,
});
const G = (version, slug, condition, target, extra) =>
  R(version, slug, condition, "GET", target, extra);

function pathsVersion() {
  const v = "v11";
  const dot = (slug, target) => G(v, slug, "dot-segments", target);
  return {
    id: v,
    name: "pages-and-paths",
    hosting: {},
    // no 404.html: the default page answers /missing
    files: base({
      "a/index.html": text("<h1>a</h1>\n"),
      "a/b": text("file b\n"),
      "a/c.txt": text("file c\n"),
    }),
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: [
      G(v, "default-404", "default-404", "/missing", { keepBody: true }),
      G(v, "default-404-json", "default-404", "/missing.json"),
      G(v, "default-404-nested", "default-404", "/a/missing/deeper"),
      G(v, "auth-handler", "auth-handler", "/__/auth/handler", { keepBody: true }),
      G(v, "auth-handler-query", "auth-handler", "/__/auth/handler?mode=signIn"),
      dot("dot-end-parent", "/a/b/.."),
      dot("dot-mid-current", "/a/./b"),
      dot("dot-end-current", "/a/b/."),
      dot("dot-dir-current", "/a/."),
      dot("dot-dir-parent", "/a/.."),
      dot("dot-mid-parent", "/a/../a/b"),
      dot("dot-lead-current", "/./a/b"),
      dot("dot-encoded-current", "/a/%2e/b"),
      dot("dot-encoded-end", "/a/b/%2e%2e"),
      dot("backslash-mid", "/a\\b"),
      dot("backslash-after-dot", "/a/./\\evil.example"),
      dot("backslash-dot-first", "/.\\b"),
      dot("backslash-lead", "/./\\evil"),
      dot("backslash-encoded-after-dot", "/a/./%5cevil.example"),
      dot("backslash-in-name", "/a/\\b"),
      dot("dot-end-parent-slash", "/a/b/../"),
      dot("dot-mid-current-slash", "/a/./b/"),
    ],
  };
}

function digitNamesVersion() {
  const v = "v12";
  const r = (slug, target) => G(v, slug, "redirect-names", target);
  return {
    id: v,
    name: "redirect-digit-names",
    hosting: {
      redirects: [
        { source: "/capture/:id/:id2", destination: "/new/:id2/:id", type: 301 },
        { source: "/p/:a1", destination: "/to-p/:a1", type: 302 },
        { source: "/s/:a1/x", destination: "/to-s/:a1", type: 302 },
        { source: "/t/:a1/:a2", destination: "/to-t/:a2/:a1", type: 302 },
      ],
    },
    files: base(),
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: [
      r("cap-two2", "/capture/one/two2"),
      r("cap-two", "/capture/one/two"),
      r("cap-literal-id2", "/capture/x/:id2"),
      r("cap-literal-first", "/capture/:id2/two"),
      r("p-x", "/p/x"),
      r("p-x1", "/p/x1"),
      r("p-literal", "/p/:a1"),
      r("s-v", "/s/v/x"),
      r("s-literal", "/s/:a1/x"),
      r("t-pair", "/t/u/v"),
      r("t-digits", "/t/1/2"),
    ],
  };
}

function repeatedNameVersion() {
  const v = "v13";
  return {
    id: v,
    name: "redirect-repeated-name",
    hosting: { redirects: [{ source: "/q/:id/:id", destination: "/to-q/:id", type: 302 }] },
    files: base(),
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    // production may refuse a repeated name when the version is finalized: that answer is the observation
    mayRefuse: true,
    requests: [
      G(v, "q-distinct", "redirect-names", "/q/a/b"),
      G(v, "q-same", "redirect-names", "/q/a/a"),
      G(v, "q-short", "redirect-names", "/q/a"),
    ],
  };
}

function precompressedVersion() {
  const v = "v14";
  const browser = { "accept-encoding": "gzip, deflate, br" };
  const rule = (source, value) => ({ source, headers: [{ key: "Content-Encoding", value }] });
  const P = (slug, target, headers, method = "GET") =>
    R(v, slug, "precompressed", method, target, { headers });
  return {
    id: v,
    name: "precompressed-files",
    hosting: {
      headers: [
        rule("/pre/*.br", "br"),
        rule("/pre/*.gz", "gzip"),
        rule("/pre/script.js", "gzip"),
        rule("/pre/plain.txt", "identity"),
      ],
    },
    files: base({
      "pre/big.txt.br": PRECOMPRESSED.br,
      "pre/big.txt.gz": PRECOMPRESSED.gzip,
      "pre/script.js": PRECOMPRESSED.gzip,
      "pre/plain.txt": BIG,
      "pre/free.txt": BIG,
    }),
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    // production may refuse a Content-Encoding header rule when the version is finalized
    mayRefuse: true,
    requests: [
      P("br-browser", "/pre/big.txt.br", browser),
      P("br-gzip-only", "/pre/big.txt.br", { "accept-encoding": "gzip" }),
      P("br-none", "/pre/big.txt.br", {}),
      P("gz-browser", "/pre/big.txt.gz", browser),
      P("gz-none", "/pre/big.txt.gz", {}),
      P("js-browser", "/pre/script.js", browser),
      P("js-none", "/pre/script.js", {}),
      P("identity-browser", "/pre/plain.txt", browser),
      P("free-browser", "/pre/free.txt", browser),
      P("br-head", "/pre/big.txt.br", { "accept-encoding": "gzip" }, "HEAD"),
    ],
  };
}

const SIZES = [1, 10, 100, 500, 1000, 1024, 1500, 2048, 4500];
/** [slug, file name]: thirteen content types, each 4,500 bytes. */
const TYPES = [
  ["html", "t/page.html"],
  ["css", "t/style.css"],
  ["js", "t/app.js"],
  ["svg", "t/image.svg"],
  ["xml", "t/data.xml"],
  ["wasm", "t/module.wasm"],
  ["noext", "t/noext"],
  ["unknownext", "t/file.unknownext"],
  ["png", "t/image.png"],
  ["zip", "t/archive.zip"],
  ["woff2", "t/font.woff2"],
  ["csv", "t/data.csv"],
  ["md", "t/readme.md"],
];

function gzipMatrixVersion() {
  const v = "v15";
  const gzip = { "accept-encoding": "gzip" };
  const sizeName = (size) => `sz/s${String(size).padStart(4, "0")}.txt`;
  const N = (slug, headers, extra = {}) =>
    G(v, `ae-${slug}`, "gzip-negotiation", `/${sizeName(4500)}`, { headers, ...extra });
  return {
    id: v,
    name: "gzip-matrix",
    hosting: {},
    files: base({
      ...Object.fromEntries(SIZES.map((size) => [sizeName(size), sized(size)])),
      ...Object.fromEntries(TYPES.map(([, name]) => [name, BIG])),
    }),
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: [
      ...SIZES.map((size) =>
        G(v, `size-${String(size).padStart(4, "0")}`, "gzip-sizes", `/${sizeName(size)}`, {
          headers: gzip,
        }),
      ),
      ...TYPES.map(([slug, name]) =>
        G(v, `type-${slug}`, "gzip-types", `/${name}`, { headers: gzip }),
      ),
      N("plain", {}),
      N("star", { "accept-encoding": "*" }),
      N("xgzip", { "accept-encoding": "x-gzip" }),
      N("gzip-q0", { "accept-encoding": "gzip;q=0" }),
      N("identity", { "accept-encoding": "identity" }),
      N("deflate", { "accept-encoding": "deflate" }),
      N("upper", { "accept-encoding": "GZIP" }),
      N("browser", { "accept-encoding": "gzip, deflate, br" }),
      N("range", { "accept-encoding": "gzip", range: "bytes=0-9" }),
      N("cond", gzip, {
        headersFrom: [
          { header: "if-none-match", fromRequest: `${v}.ae-plain`, fromHeader: "etag" },
        ],
      }),
    ],
  };
}

/** The five versions in recording order. */
export function buildFollowupCorpus() {
  return {
    schemaVersion: 1,
    corpusId: FOLLOWUP_CORPUS_ID,
    versions: [
      pathsVersion(),
      digitNamesVersion(),
      repeatedNameVersion(),
      precompressedVersion(),
      gzipMatrixVersion(),
    ],
  };
}

/**
 * The follow-up profile of the recorder: its own task, envelope, attempts and money, the corpus
 * pinned by digest, the budget of one attempt and no file listing (the reserved files were
 * recorded in the HOSTING closure).
 */
export const FOLLOWUP_PROFILE = {
  name: "followup",
  taskId: "HOSTING-FOLLOWUP",
  envelopePattern: /^HOSTING-FOLLOWUP-[A-Z0-9-]{3,60}$/,
  envelopeHint: "HOSTING-FOLLOWUP-...",
  maxAttempts: 3,
  maxCumulativeUsd: 3,
  reservedUsdPerAttempt: 1,
  caps: { token: 3, control: 60, cleanup: 30, upload: 20, edge: 150 },
  build: buildFollowupCorpus,
  corpusSha256: FOLLOWUP_CORPUS_SHA256,
  listFilesVersion: null,
  manifest: () => corpusManifest(buildFollowupCorpus()),
};

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  if (process.argv[2] === "manifest")
    console.log(JSON.stringify(FOLLOWUP_PROFILE.manifest(), null, 2));
  else throw new Error("usage: followup.mjs manifest");
}
