# Hosting compatibility matrix

Hosting is a new implementation surface. Its parent remains `IMPLEMENTING`; no condition in this matrix establishes production parity. The fixture manifest closes the HTTP configuration, public file and glob inputs. Each test condition reads those fixtures.

The offline oracle is firebase-tools 15.28.2 and its locked superstatic dependency. The harness invokes the actual strict middleware stack, Hosting initialization middleware, Functions rewriter and Run rewriter. It supplies synthetic initialization data and registers a loopback Functions endpoint. It does not invoke configuration discovery, read credentials, fetch a web configuration, resolve a production Run URL or allow live Functions fallback. This is an implementation-stack comparison, not a claim that the full Firebase CLI has been exercised.

| Condition | Fixture coverage | Production |
| --- | --- | --- |
| Static files and index | Exact JSON, root and directory index, query, GET/HEAD/POST | Unobserved |
| Redirects | First match, 301/302, capture and query | Unobserved |
| Rewrites | Overlapping rules, first match, static destination | Unobserved |
| Glob matching | Slash, globstar, braces, classes, extglobs, negation, escaping, dotfiles | Unobserved |
| Headers | Multiple matches, last value, custom cache control | Unobserved |
| cleanUrls and trailingSlash | Configurations with absent/false/true values and directory/HTML paths | Unobserved |
| i18n | Language, country, language cookie, fallback | Unobserved |
| Reserved paths | Synthetic init JSON/JS and emulator query; unknown reserved path | Unobserved |
| 404 | Missing path and direct custom 404 file | Unobserved |
| Functions and Run | Actual official rewriters target a registered local handler | Unobserved |
| Lifecycle | CLI selection, readiness, listener release | Local concern |

The generated PICT cases are materialized in the shared corpus, including the mandatory seed combinations. The property corpus uses the pinned official matcher; it is not a second hand-written matcher used as an oracle. Official observations must be generated inside an inspected network-none container with a separate empty home directory. Each run also records an external literal-address connection refusal. Raw traversal requests use `http.request` with the literal request target rather than a URL constructor that might remove dot segments.

Outstanding production work includes all serving conditions, default error-page rendering, external reserved SDK resources, deployment metadata and routing to real Functions/Run resources. A version's `fileCount` is a string in the public API schema, not proof that it equals the number of uploaded user files. The unsent packet describes the finite observations needed; neither documentation nor local tests count as production recordings.
