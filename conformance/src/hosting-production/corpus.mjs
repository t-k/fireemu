// The frozen corpus of the Hosting production observation (HOSTING parent): ten site versions,
// each with a public tree, a firebase.json `hosting` object (without `public`) and the requests
// that are sent to its own preview channel. Nothing here performs I/O; the recorder deploys a
// version, sends its requests, deletes it, and the local dry run replays the same requests against
// fireemu. `corpusManifest()` is the pinned, hashable form (file sizes and digests, not bytes).
//
// Scope (owner ledger 2435, coordinator ruling 2026-11-10): no `function` or `run` rewrite, no
// deployed upstream. `ignore` is a deploy-tool property and is not observable through the REST
// API that carries a file manifest.
import { createHash } from "node:crypto";

export const CORPUS_ID = "hosting-production-v1";
export const SCHEMA_VERSION = 1;

/** Closure conditions (HOSTING/<id>) a request belongs to; `path-safety` is information only. */
export const CONDITIONS = [
  "static-files",
  "redirects",
  "rewrites",
  "glob-matching",
  "headers-cache",
  "clean-urls",
  "trailing-slash",
  "i18n",
  "reserved-paths",
  "not-found",
  "content-types",
  "compression-vary",
  "app-association",
  "path-safety",
];

const text = (value) => Buffer.from(value, "utf8");

const HOME = text("<h1>home</h1>\n");
const PAGE = text("<h1>page</h1>\n");
const DIR_INDEX = text("<h1>directory</h1>\n");
const NOT_FOUND_PAGE = text("<h1>not found</h1>\n");
const FIRST = text("first\n");
const SECOND = text("second\n");
const DATA = text('{"fixture":true}\n');
const READY = text("ready\n");
/** A compressible body well above any compression threshold (4,500 bytes). */
const BIG = text("The quick brown fox jumps over the lazy dog.\n".repeat(100));
/** One shared body for every content-type probe, so the version uploads it once. */
const SMALL = text("x\n");

const TREE_BASE = {
  "index.html": HOME,
  "page.html": PAGE,
  "dir/index.html": DIR_INDEX,
  "ready.txt": READY,
};

const I18N_TREE = {
  "locales/fr/page.html": text("bonjour\n"),
  "locales/fr_CA/page.html": text("bonjour canada\n"),
  "locales/ALL_CA/page.html": text("canada\n"),
  "locales/en_ALL/page.html": text("hello\n"),
};

/** Extensions probed for Content-Type: one file `ct/file.<ext>` each (all 27 share one body). */
export const CONTENT_TYPE_EXTENSIONS = [
  "html",
  "css",
  "js",
  "mjs",
  "json",
  "map",
  "xml",
  "svg",
  "txt",
  "md",
  "csv",
  "ico",
  "png",
  "jpg",
  "gif",
  "webp",
  "avif",
  "woff",
  "woff2",
  "ttf",
  "pdf",
  "wasm",
  "zip",
  "webmanifest",
  "mp4",
  "mp3",
  "ts",
];

/** Further content-type probes: upper-case extension, none, unknown, double, dotfile. */
export const CONTENT_TYPE_ODDITIES = [
  ["upper", "ct/UPPER.HTML"],
  ["noext", "ct/noext"],
  ["unknown", "ct/file.unknownext"],
  ["double", "ct/archive.tar.gz"],
  ["dotfile", "ct/.dotfile"],
];

/** The 16 glob patterns of the glob-matching version, in rule order (index = header X-G<nn>). */
export const GLOB_PATTERNS = [
  "/**",
  "/a/*",
  "/a/**",
  "/a/?",
  "/{a,b}/x",
  "/a/[ab]",
  "/a/!(x)",
  "/a/@(x|y)",
  "/a/+(x|y)",
  "/a/?(x)",
  "/a/*(x)",
  "!/a/x",
  "/a/\\*",
  "/a/.hidden",
  "/a/**/x",
  "/{a,{b,c}}/x",
];

/** The 11 request paths of the glob-matching version. */
export const GLOB_PATHS = [
  "/a/x",
  "/a/y",
  "/a/xx",
  "/a/a",
  "/b/x",
  "/a/",
  "/a/n/x",
  "/a/.hidden",
  "/a/*",
  "/c/x",
  "/d/x",
];

export const globHeader = (index) => `x-g${String(index).padStart(2, "0")}`;

/** Redirect-edge capture paths (a subset of conformance/hosting-fixtures/redirect-edges.json). */
export const REDIRECT_EDGE_SUFFIXES = [
  "",
  "%5cevil.example",
  "%255cevil.example",
  "%2fevil.example",
  "a%20b",
  "a%09b",
  "%E6%97%A5",
  "a:b",
  "%3Aother",
  "a%25b",
  "a%3Fb",
  "plain?x=%5c",
  "\\evil.example",
];

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

function contentTypeFiles() {
  const files = {};
  for (const ext of CONTENT_TYPE_EXTENSIONS) files[`ct/file.${ext}`] = SMALL;
  for (const [, path] of CONTENT_TYPE_ODDITIES) files[path] = SMALL;
  return files;
}

function routingVersion() {
  const v = "v01";
  const requests = [
    G(v, "root", "static-files", "/"),
    G(v, "static", "static-files", "/data.json", { also: ["headers-cache"] }),
    G(v, "query", "static-files", "/data.json?q=1"),
    G(v, "encoded-static", "static-files", "/%64ata.json"),
    G(v, "directory", "static-files", "/dir"),
    G(v, "directory-slash", "static-files", "/dir/"),
    G(v, "index-file", "static-files", "/index.html"),
    G(v, "page", "static-files", "/page?q=1"),
    G(v, "page-slash", "trailing-slash", "/page/?q=1"),
    G(v, "page-html", "static-files", "/page.html?q=1"),
    G(v, "dir-index-html", "static-files", "/dir/index.html?q=1"),
    R(v, "head-static", "static-files", "HEAD", "/data.json"),
    R(v, "head-root", "static-files", "HEAD", "/"),
    R(v, "post-static", "static-files", "POST", "/data.json", {
      headers: { "content-type": "text/plain" },
      body: "post\n",
    }),
    R(v, "put-static", "static-files", "PUT", "/data.json", {
      headers: { "content-type": "text/plain" },
      body: "put\n",
    }),
    R(v, "delete-static", "static-files", "DELETE", "/data.json"),
    R(v, "options-static", "static-files", "OPTIONS", "/data.json"),
    R(v, "post-missing", "not-found", "POST", "/missing", {
      headers: { "content-type": "text/plain" },
      body: "post\n",
    }),
    G(v, "range", "static-files", "/data.json", { headers: { range: "bytes=0-3" } }),
    G(v, "range-suffix", "static-files", "/data.json", { headers: { range: "bytes=-3" } }),
    G(v, "cond-etag", "static-files", "/data.json", {
      headersFrom: [{ header: "if-none-match", fromRequest: `${v}.static`, fromHeader: "etag" }],
    }),
    G(v, "cond-etag-wrong", "static-files", "/data.json", {
      headers: { "if-none-match": '"fireemu-no-such-etag"' },
    }),
    G(v, "cond-since-future", "static-files", "/data.json", {
      headers: { "if-modified-since": "Fri, 01 Jan 2100 00:00:00 GMT" },
    }),
    G(v, "cond-since-past", "static-files", "/data.json", {
      headers: { "if-modified-since": "Mon, 01 Jan 2001 00:00:00 GMT" },
    }),
    G(v, "missing", "not-found", "/missing", { also: ["headers-cache"] }),
    G(v, "not-found-direct", "not-found", "/404.html"),
    R(v, "head-missing", "not-found", "HEAD", "/missing"),
    G(v, "rewrite-first", "rewrites", "/rewrite/a", { also: ["headers-cache"] }),
    G(v, "cond-etag-rewrite", "static-files", "/rewrite/a", {
      headersFrom: [
        { header: "if-none-match", fromRequest: `${v}.rewrite-first`, fromHeader: "etag" },
      ],
    }),
    G(v, "rewrite-query", "rewrites", "/rewrite/a/b?q=1"),
    G(v, "redirect-first", "redirects", "/old/a?q=1", { also: ["headers-cache"] }),
    R(v, "head-redirect", "redirects", "HEAD", "/old/a"),
    G(v, "redirect-capture", "redirects", "/capture/name"),
    G(v, "redirect-capture-prefix", "redirects", "/capture/one/two"),
    G(v, "redirect-capture-literal", "redirects", "/capture/:id2/two"),
    G(v, "header-index", "headers-cache", "/index.html"),
    G(v, "header-not-found-direct", "headers-cache", "/404.html"),
    G(v, "reserved-json", "reserved-paths", "/__/firebase/init.json"),
    G(v, "reserved-js", "reserved-paths", "/__/firebase/init.js"),
    G(v, "reserved-emulator-js", "reserved-paths", "/__/firebase/init.js?useEmulator=true"),
    G(v, "reserved-unknown", "reserved-paths", "/__/missing"),
    R(v, "reserved-sdk-10", "reserved-paths", "HEAD", "/__/firebase/10.14.1/firebase-app.js"),
    R(v, "reserved-sdk-12", "reserved-paths", "HEAD", "/__/firebase/12.0.0/firebase-app-compat.js"),
    R(v, "reserved-auth-handler", "reserved-paths", "HEAD", "/__/auth/handler"),
    // Compression and Vary.
    G(v, "gz-none", "compression-vary", "/compress/big.txt"),
    G(v, "gz-identity", "compression-vary", "/compress/big.txt", {
      headers: { "accept-encoding": "identity" },
    }),
    G(v, "gz-gzip", "compression-vary", "/compress/big.txt", {
      headers: { "accept-encoding": "gzip" },
    }),
    G(v, "gz-br", "compression-vary", "/compress/big.txt", {
      headers: { "accept-encoding": "br" },
    }),
    G(v, "gz-gzip-br", "compression-vary", "/compress/big.txt", {
      headers: { "accept-encoding": "gzip, br" },
    }),
    G(v, "gz-br-refused", "compression-vary", "/compress/big.txt", {
      headers: { "accept-encoding": "br;q=0, gzip" },
    }),
    R(v, "gz-head-gzip", "compression-vary", "HEAD", "/compress/big.txt", {
      headers: { "accept-encoding": "gzip" },
    }),
    G(v, "gz-json-gzip", "compression-vary", "/compress/big.json", {
      headers: { "accept-encoding": "gzip" },
    }),
    G(v, "gz-json-br", "compression-vary", "/compress/big.json", {
      headers: { "accept-encoding": "br" },
    }),
    G(v, "gz-png-gzip", "compression-vary", "/ct/file.png", {
      headers: { "accept-encoding": "gzip" },
    }),
    // Path safety (information only, not a closure condition).
    G(v, "safety-parent", "path-safety", "/../outside.txt", { infoOnly: true }),
    G(v, "safety-encoded-parent", "path-safety", "/%2e%2e/outside.txt", { infoOnly: true }),
    G(v, "safety-bad-percent", "path-safety", "/%GG", { infoOnly: true }),
  ];
  for (const ext of CONTENT_TYPE_EXTENSIONS) {
    requests.push(G(v, `ct-${ext}`, "content-types", `/ct/file.${ext}`));
  }
  for (const [slug, path] of CONTENT_TYPE_ODDITIES) {
    requests.push(G(v, `ct-${slug}`, "content-types", `/${path}`));
  }
  for (const [n, destination] of ["go1", "go2", "go3"].entries()) {
    for (const [index, suffix] of REDIRECT_EDGE_SUFFIXES.entries()) {
      requests.push(
        G(
          v,
          `edge-${n + 1}-${String(index).padStart(2, "0")}`,
          "redirects",
          `/${destination}/${suffix}`,
        ),
      );
    }
  }
  return {
    id: v,
    name: "routing",
    hosting: {
      redirects: [
        { source: "/old/**", destination: "/page.html", type: 302 },
        { source: "/old/**", destination: "/second.html", type: 301 },
        { source: "/capture/:name", destination: "/new/:name", type: 301 },
        { source: "/capture/:id/:id2", destination: "/new/:id2/:id", type: 301 },
        { source: "/go1/:name", destination: "/:name", type: 302 },
        { source: "/go2/:name", destination: "/next/:name", type: 302 },
        { source: "/go3/:name", destination: "https://example.test/:name", type: 302 },
      ],
      rewrites: [
        { source: "/rewrite/**", destination: "/first.html" },
        { source: "/rewrite/**", destination: "/second.html" },
      ],
      headers: [
        { source: "/**", headers: [{ key: "X-Fixture", value: "first" }] },
        {
          source: "/data.json",
          headers: [
            { key: "X-Fixture", value: "second" },
            { key: "Cache-Control", value: "public, max-age=123" },
          ],
        },
      ],
    },
    files: {
      ...TREE_BASE,
      "404.html": NOT_FOUND_PAGE,
      "first.html": FIRST,
      "second.html": SECOND,
      "data.json": DATA,
      "compress/big.txt": BIG,
      "compress/big.json": BIG,
      ...contentTypeFiles(),
    },
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests,
  };
}

const URL_GRID = [
  ["page", "/page?q=1"],
  ["page-slash", "/page/?q=1"],
  ["page-html", "/page.html?q=1"],
  ["dir", "/dir?q=1"],
  ["dir-slash", "/dir/?q=1"],
  ["dir-index-html", "/dir/index.html?q=1"],
];

function gridVersion(id, name, hosting, condition, { extra = [], optionalConfig = [] } = {}) {
  return {
    id,
    name,
    hosting,
    files: { ...TREE_BASE, "data.json": DATA },
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig,
    requests: [
      ...URL_GRID.map(([slug, target]) => G(id, slug, condition, target)),
      G(id, "root", condition, "/"),
      ...extra,
    ],
  };
}

function i18nRequests(v) {
  const page = (slug, headers) => G(v, slug, "i18n", "/page.html", { headers });
  return [
    page("language", { "accept-language": "fr" }),
    page("country-header", { "accept-language": "fr", "x-country-code": "CA" }),
    page("country-header-only", { "x-country-code": "CA" }),
    page("language-cookie", { "accept-language": "en", cookie: "firebase-language-override=fr" }),
    page("fallback", { "accept-language": "de" }),
    page("country-cookie", { "accept-language": "fr", cookie: "firebase-country-override=CA" }),
    page("country-cookie-only", { cookie: "firebase-country-override=CA" }),
    page("both-cookies", {
      cookie: "firebase-language-override=fr; firebase-country-override=CA",
    }),
    page("none", {}),
    page("region-tag", { "accept-language": "fr-CA" }),
    page("quality", { "accept-language": "de;q=0.9, fr;q=0.8" }),
    G(v, "root", "i18n", "/", { headers: { "accept-language": "fr" } }),
    R(v, "head-language", "i18n", "HEAD", "/page.html", { headers: { "accept-language": "fr" } }),
  ];
}

function i18nVersion() {
  const v = "v07";
  return {
    id: v,
    name: "i18n",
    hosting: { i18n: { root: "locales" } },
    files: { ...TREE_BASE, ...I18N_TREE },
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: i18nRequests(v),
  };
}

function i18nCombinedVersion() {
  const v = "v08";
  const fr = { "accept-language": "fr" };
  return {
    id: v,
    name: "i18n-clean-slash",
    hosting: { i18n: { root: "locales" }, cleanUrls: true, trailingSlash: true },
    files: { ...TREE_BASE, ...I18N_TREE },
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: [
      G(v, "page-html", "i18n", "/page.html", { headers: fr }),
      G(v, "page", "i18n", "/page", { headers: fr }),
      G(v, "page-slash", "i18n", "/page/", { headers: fr }),
      G(v, "dir", "trailing-slash", "/dir", { headers: fr }),
      G(v, "page-country-cookie", "i18n", "/page/", {
        headers: { ...fr, cookie: "firebase-country-override=CA" },
      }),
    ],
  };
}

function reservedPrecedenceVersion() {
  const v = "v09";
  return {
    id: v,
    name: "reserved-precedence",
    hosting: { redirects: [{ source: "**", destination: "/page.html", type: 302 }] },
    files: { ...TREE_BASE },
    readiness: { path: "/ready.txt", accept: [302] },
    optionalConfig: [],
    requests: [
      G(v, "reserved-json", "reserved-paths", "/__/firebase/init.json"),
      G(v, "reserved-js", "reserved-paths", "/__/firebase/init.js"),
      G(v, "reserved-unknown", "reserved-paths", "/__/missing"),
      R(v, "reserved-auth-handler", "reserved-paths", "HEAD", "/__/auth/handler"),
      G(v, "control", "redirects", "/other"),
      G(v, "control-static", "redirects", "/index.html"),
    ],
  };
}

function globVersion() {
  const v = "v10";
  return {
    id: v,
    name: "glob-matrix",
    hosting: {
      rewrites: [{ source: "**", destination: "/index.html" }],
      headers: GLOB_PATTERNS.map((source, index) => ({
        source,
        headers: [{ key: `X-G${String(index).padStart(2, "0")}`, value: "1" }],
      })),
    },
    files: { ...TREE_BASE },
    readiness: { path: "/ready.txt", accept: [200] },
    optionalConfig: [],
    requests: [
      ...GLOB_PATHS.map((path, index) =>
        G(v, `path-${String(index).padStart(2, "0")}`, "glob-matching", path),
      ),
      // A file wins over the catch-all rewrite.
      G(v, "static-over-rewrite", "rewrites", "/ready.txt"),
    ],
  };
}

/** The ten versions in recording order. */
export function buildCorpus() {
  return {
    schemaVersion: SCHEMA_VERSION,
    corpusId: CORPUS_ID,
    versions: [
      routingVersion(),
      gridVersion("v02", "clean-urls", { cleanUrls: true, appAssociation: "AUTO" }, "clean-urls", {
        // appAssociation is dropped by the recorder if the API rejects it (optionalConfig).
        extra: [
          G("v02", "assetlinks", "app-association", "/.well-known/assetlinks.json"),
          G(
            "v02",
            "apple-app-site-association",
            "app-association",
            "/.well-known/apple-app-site-association",
          ),
        ],
        optionalConfig: ["appAssociation"],
      }),
      gridVersion("v03", "trailing-slash-true", { trailingSlash: true }, "trailing-slash"),
      gridVersion("v04", "trailing-slash-false", { trailingSlash: false }, "trailing-slash"),
      gridVersion(
        "v05",
        "clean-urls-slash",
        { cleanUrls: true, trailingSlash: true },
        "trailing-slash",
      ),
      gridVersion(
        "v06",
        "clean-urls-noslash",
        { cleanUrls: true, trailingSlash: false },
        "trailing-slash",
      ),
      i18nVersion(),
      i18nCombinedVersion(),
      reservedPrecedenceVersion(),
      globVersion(),
    ],
  };
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * The pinned form: per version the config, the file list with sizes and digests, readiness and
 * every request. The digest covers exactly this object.
 */
export function corpusManifest(corpus = buildCorpus()) {
  const versions = corpus.versions.map((version) => ({
    id: version.id,
    name: version.name,
    hosting: version.hosting,
    optionalConfig: version.optionalConfig,
    // only the follow-up corpus sets it (a refused finalize is then an observation): absent keeps the pinned digest
    ...(version.mayRefuse ? { mayRefuse: true } : {}),
    readiness: version.readiness,
    files: Object.fromEntries(
      Object.entries(version.files)
        .toSorted(([a], [b]) => (a < b ? -1 : 1))
        .map(([path, bytes]) => [path, { bytes: bytes.length, sha256: sha256(bytes) }]),
    ),
    requests: version.requests,
  }));
  const manifest = { schemaVersion: corpus.schemaVersion, corpusId: corpus.corpusId, versions };
  return { ...manifest, corpusSha256: sha256(JSON.stringify(manifest)) };
}

/** Counts used by the budget: requests per version and in all, distinct file digests. */
export function corpusCounts(corpus = buildCorpus()) {
  const perVersion = Object.fromEntries(corpus.versions.map((v) => [v.id, v.requests.length]));
  const distinct = new Set(corpus.versions.flatMap((v) => Object.values(v.files).map(sha256)));
  return {
    versions: corpus.versions.length,
    requests: Object.values(perVersion).reduce((a, b) => a + b, 0),
    perVersion,
    distinctBodies: distinct.size,
  };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const mode = process.argv[2];
  if (mode === "manifest") console.log(JSON.stringify(corpusManifest(), null, 2));
  else if (mode === "counts") console.log(JSON.stringify(corpusCounts(), null, 2));
  else throw new Error("usage: corpus.mjs manifest|counts");
}
