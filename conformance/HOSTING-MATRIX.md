# Hosting compatibility matrix

Hosting is a new implementation surface. Its parent remains `IMPLEMENTING`; no condition in this matrix establishes production parity. The fixture manifest closes the HTTP configuration, public file and glob inputs. Each test condition reads those fixtures.

The offline oracle is firebase-tools 15.28.2 and its locked superstatic dependency. The harness invokes the actual strict middleware stack, Hosting initialization middleware, Functions rewriter and Run rewriter. It supplies synthetic initialization data and registers a loopback Functions endpoint. It does not invoke configuration discovery, read credentials, fetch a web configuration, resolve a production Run URL or allow live Functions fallback. This is an implementation-stack comparison, not a claim that the full Firebase CLI has been exercised.

| Condition | Fixture coverage | Official agreement | Production |
| --- | --- | --- | --- |
| Static files and index | Exact JSON, root and directory index, query, GET/HEAD/POST | Shared 80-case differential passes | Unobserved |
| Redirects | First match, 301/302, capture and query | Shared 80-case differential passes | Unobserved |
| Rewrites | Overlapping rules, first match, static destination | Shared 80-case differential passes | Unobserved |
| Glob matching | Slash, globstar, braces, classes, extglobs, negation, escaping, dotfiles | 135/135 matcher observations agree | Unobserved |
| Headers | Multiple matches, last value, custom cache control | Shared 80-case differential passes | Unobserved |
| cleanUrls and trailingSlash | Configurations with absent/false/true values and directory/HTML paths | Shared 80-case differential passes | Unobserved |
| i18n | Language, country, language cookie, fallback | Shared 80-case differential passes | Unobserved |
| Reserved paths | Synthetic init JSON/JS and emulator query; unknown reserved path | JSON/status agree; JS initialization effects agree | Unobserved |
| 404 | Missing path and direct custom 404 file | Shared 80-case differential passes | Unobserved |
| Functions and Run | Actual official rewriters target a registered local handler | Shared 80-case differential passes | Unobserved |
| Lifecycle | CLI selection, readiness, listener release | Not an official differential claim | Local concern |

The generated PICT cases are materialized in the shared corpus, including the mandatory seed combinations. The property corpus uses the pinned official matcher; it is not a second hand-written matcher used as an oracle. Official observations must be generated inside an inspected network-none container with a separate empty home directory. Each run also records an external literal-address connection refusal. Raw traversal requests use `http.request` with the literal request target rather than a URL constructor that might remove dot segments.

Outstanding production work includes all serving conditions, default error-page rendering, external reserved SDK resources, deployment metadata and routing to real Functions/Run resources. A version's `fileCount` is a string in the public API schema, not proof that it equals the number of uploaded user files. The unsent packet describes the finite observations needed; neither documentation nor local tests count as production recordings.

Agreement is limited to the committed `official.json` and `official-globs.json` observations and selected response headers. Initialization JavaScript is compared by its `initializeApp` effects, not source text. Dynamic Date headers and ephemeral ports are excluded. Missing local upstreams and external SDK resources fail locally without production fallback; this boundary is not an approved equivalence to production. Capability confinement rejects escaping links and malformed private paths even where upstream permissiveness has not been measured.

Filesystem tests cover retained-handle replacement, relative symlinks, escape rejection, FIFO refusal and bounded large-file streaming on Linux. Windows uses the same capability API and includes native symlink/junction tests, but no native Windows result is available from this task. This is not a cross-platform parity claim. The root capability confines name resolution; it does not freeze file contents against concurrent writes or treat administrator-created hard links and mounts as untrusted pathname input.
