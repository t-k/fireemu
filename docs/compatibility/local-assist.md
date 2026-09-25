# local-assist: bounded read-only tasks for a loopback local model

`tools/local-assist` hands one small, well-defined task to a local
`llama-server` (OpenAI-compatible chat API on a loopback port) and returns a
schema-validated JSON result whose every finding points at lines the tool
itself read. It exists to save cloud tokens on candidate-finding work; it is
not an oracle, not a reviewer, and its output is never compatibility
evidence. The model gets no tools, no network, no credentials and no way to
write. The short operating instruction for agents that call it is
[`tools/local-assist/AGENT_PROMPT.md`](../../tools/local-assist/AGENT_PROMPT.md).

## Usage

```sh
# one task
python3 tools/local-assist/main.py --packet /abs/private/task.json --output /abs/private/result.json

# the same, without contacting the server: validates, hashes, budgets and
# records the request metadata (never the prompt text)
python3 tools/local-assist/main.py --packet /abs/private/task.json --output /abs/private/plan.json --dry-run

# deterministic log reduction (no model involved)
python3 tools/local-assist/main.py parse-log --format nextest \
  --input /abs/private/gate.log --output /abs/private/failures.json --excerpt /abs/private/failures.txt

# operator reset after a timed-out run, once the server is confirmed idle
python3 tools/local-assist/main.py --reset-lock --state-dir /abs/private/state
```

`parse-log` never guesses a terminal verdict. When the log carries a nextest
or pytest final summary, `summary.{run,passed,failed,skipped}` are the
summary's own counts. When there is no final summary (a truncated log, or
`-q`/`--tb=no` output cut before the footer), `summary.failed` and the other
counts are `null` rather than the number of failure blocks the parser
happened to see; `summary.observedFailureBlocks` carries that block count
separately, so a caller can't mistake "the parser found this many failure
blocks" for "the run failed this many tests". pytest's `errors` (collection,
setup and teardown failures) are counted apart from `failed`, and when
`errors` is present `summary.run` is `null` too, since a teardown error can
be reported alongside the same test's pass or fail and there is no way to
derive a unique executed-test count from the summary line alone.

Each pytest failure carries `idResolved` (default `true`). pytest does not
escape `[`/`]` inside a parametrize id, so a raised message containing its
own `[...] - ...` can make a short-summary line's id/message boundary
genuinely ambiguous from the line's text alone; when that happens (and no
detail block or verbose progress line names the real id), `idResolved` is
`false`, `name` is the raw, unsplit short-summary line, and `message` is
empty rather than a guess.

Standard library only. Tests:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest -q -p no:cacheprovider tools/local-assist
```

### Packet

```json
{
  "taskId": "LOCAL-AUTH-TESTMAP-001",
  "kind": "find-test-candidates",
  "repoRoot": "/abs/path/of/a/fixed/checkout",
  "baseCommit": "<40-hex sha of that checkout>",
  "question": "which existing tests cover the tenant refresh positive control and the cross-tenant refusal?",
  "inputs": [{"path": "crates/fireemu-adapter-http/tests/auth_tenant_isolation.rs", "startLine": 1, "endLine": 200}],
  "maxFindings": 5,
  "maxOutputTokens": 1200,
  "endpoint": "http://127.0.0.1:8011/v1/chat/completions",
  "deadlineSeconds": 120
}
```

`endpoint` and `deadlineSeconds` are optional. The endpoint falls back to
the config file, then to `http://127.0.0.1:8011/v1/chat/completions`. Kinds:

| kind | input | finding fields beyond `claim/path/startLine/endLine/evidence` |
|---|---|---|
| `find-test-candidates` | test source excerpts | none; the claim names the test function |
| `classify-log` | the `--excerpt` file written by `parse-log` | `category` (environment, missing-dependency, assertion, timeout, flaky-suspect, regression, unknown) |
| `propose-tests` | a fixed specification excerpt | `positiveControl`, `refusalPostState`; `path/startLine/endLine` is the source reference |

### Config (optional)

`~/.config/fireemu-local-assist/config.json`, or `--config <file>`:

```json
{"endpoint": "http://127.0.0.1:8011/v1/chat/completions", "alias": "fireemu-local",
 "contextTokens": 16384, "responseFormat": "json_schema", "stateDir": "/abs/private/state"}
```

`apiKeyFile` (absolute path, not a symlink, mode 600: a group- or
world-readable file is refused) holds the bearer token for a server started
with `--api-key`/`--api-key-file`; the key is sent only to the loopback
endpoint and never written to results, logs or the cache key. `responseFormat` is `json_schema` (the schema is sent as
`response_format`) or `prompt` (the schema is appended to the user message;
use it for servers without grammar-constrained output). `modelId`/`quant`
pin the runtime identity and skip the `/v1/models` probe.

`alias` pins the model the server must be serving (llama-server's
`--alias`). With it set, the probe requires `/v1/models` to list exactly that
id and `/props` (when the server exposes it) to report it as `model_alias`;
anything else is `runtime-mismatch` and no prompt is sent. The completion
must also report that `model` (or the pinned `modelId` when no alias is
set); a reply naming another model is refused. `/props` additionally
supplies the quant (`model_ftype`, normalized to the `Q4_K_M` spelling) when
the model id does not carry it, and its `n_ctx`, `total_slots` and
`build_info` are recorded under `runtime.meta.props`.

Every request sets `temperature: 0`, `stream: false`, `enable_thinking:
false` and `chat_template_kwargs: {"enable_thinking": false}`; the last two
are harmless when the model or the server has reasoning off already.

### Result

The output is a new file (an existing path is refused) with `taskId`,
`kind`, `promptVersion`, `baseCommit`, `inputHashes` (per input: effective
line range, `requestedEndLine`, `lineCount`, `fileSha256`, `rangeSha256`),
`findings`, `unknowns`, `runtime` (endpoint, alias, model id reported by the
server, quant when it can be read from the model name or `/props`),
`runtimeIdentityVerified`, `usage` (prompt and completion tokens,
llama-server timings when present), `elapsedSeconds`, `finishStatus` and
`reason`. Findings carry `evidenceVerified`: whether the quoted evidence is
a whitespace-normalized substring of the cited lines.

`runtimeIdentityVerified` is true only when the config pins an `alias`, the
server was probed, and `/v1/models` plus `/props` (if available) reported
that alias. It stays false for a pinned `modelId` (no probe), for a config
without an alias, and for a dry run.

A dry run (`--dry-run`) writes the same file with `finishStatus: dry-run`
and a `request` object: endpoint, model, `maxTokens`, `temperature`,
`responseFormat`, `enableThinking`, per-message role, character count and
sha256, and the body's byte size and sha256. The prompt text itself is
never written to the result or stdout. A dry run takes no lock, makes no
request and reads no cache; `cache.key` is null because the runtime
identity has not been probed.

| finishStatus | exit code | meaning |
|---|---|---|
| `ok` | 0 | schema-valid reply; findings outside the packet inputs were dropped and listed in `unknowns` |
| `dry-run` | 0 | `--dry-run`: context read, hashes and budget computed, request described, nothing sent |
| `needs-narrower-input` | 2 | the conservative token estimate (bytes/3 plus a template reserve) exceeds `contextTokens - maxOutputTokens` and nothing was sent; or the server answered with `truncated: true` (context overflow), in which case the reply is discarded |
| `busy` | 3 | another local inference holds the lock; no queueing |
| `timeout` | 4 | the per-task deadline passed; no retry; the in-flight marker is kept (see below) |
| `schema-invalid` | 5 | the reply (after one repair attempt) still fails the schema, was cut off by `max_tokens`, or carried `tool_calls` |
| `server-error` | 6 | HTTP error, connection failure, redirect, malformed body, or a model probe failure |
| `runtime-mismatch` | 7 | the server does not serve the pinned alias (`/v1/models`, `/props`), or the completion names another model; nothing from that reply is used |
| `server-state-unknown` | 8 | an earlier run was never answered and its marker is still present; nothing was sent, not even the probe |

Packet, path and output-path refusals exit 1 before any request. stdout is
a few summary lines (status, counts, usage, cited ranges, output path); the
claims themselves are only in the file. Failures log a status word and a
short reason; prompts and response bodies are never printed.

### Lock state after a timeout

Before a request goes out, the run writes `inflight.json` (task id,
endpoint, start time, pid, output path) next to `inference.lock` in the
state dir; it is removed only when the server has answered completely,
whatever the answer was. If the deadline passes or the connection drops
after the request was sent, the server may still be generating, so the
marker stays, the partial result is written with `serverStateUnknown:
true` and `inflightMarker`, and every later run against that state dir
exits 8 without contacting the server. The tool never removes the marker
on its own.

Operator reset: confirm the server is idle first (`GET /health` answers
`{"status":"ok"}`, `GET /slots` shows `is_processing: false` on every
slot, or restart the server you own), then run
`main.py --reset-lock --state-dir <state>` (or `--config <file>` for its
`stateDir`). The reset records that confirmation; it does not check the
server itself, and it refuses with `busy` while another run holds the
flock. Do not put it in a retry loop.

## Limits and refusals

- Inputs are relative, normalized paths under `repoRoot`; `..`, absolute
  paths, symlinked components and anything whose real path leaves the root
  are refused. Only allowlisted text extensions are read; binary content and
  non-UTF-8 files are refused; files over 4 MiB and selections over 2000
  lines are refused.
- `.env*`, key/certificate/credential-looking names, `docs.local/`, `.git/`,
  and data files named after tokens, secrets, receipts or service accounts
  are refused. Selected lines containing private-key blocks or well-known
  token formats are refused.
- An `endLine` past the end of the file is clamped; the result records both
  the requested and effective range.
- The endpoint must be `http` on `127.0.0.1`, `localhost` or `::1`. Proxy
  environment variables are ignored and redirects are refused. The deadline
  is wall-clock and covers the whole exchange: connect, send, status line,
  headers and body. Every socket read, including the ones made while parsing
  the status line and headers, gets only the time that remains, so a server
  trickling header fragments cannot extend the call past the deadline; the
  socket is closed at the deadline and the request abandoned.
- A reply counts only when the HTTP response was received in full: a
  fixed-length body must deliver every byte of its `Content-Length` and a
  chunked body must end with the terminating chunk. A body that happens to
  parse as JSON but is short of the declared length is refused as
  `server-error` ("incomplete body") with the server state marked unknown,
  the same as after a timeout. A declared length above the 8 MiB response
  cap is refused before the body is read.
- One inference at a time (flock in the state dir, plus the in-flight
  marker above). One request, plus at most one repair round-trip for a
  schema-invalid reply. The lock only coordinates local-assist processes
  that share the state dir; it cannot stop other clients of the same
  server.
- Results are cached under the state dir by kind, question, limits, the
  sha256 of every selected range with its line selection, the prompt
  version and the runtime identity; only exact key matches are reused.
- The model's self-reported confidence is not part of the schema and is
  never used for acceptance. Findings are candidates for a human or cloud
  reviewer to verify; "not found" in the excerpts is never "does not exist".

The transport accepts exactly one body framing (a single `Content-Length`, a single `Transfer-Encoding: chunked`, or close-delimited), refuses a chunked reply whose terminator was cut short, connects to `localhost` as the literal `127.0.0.1` (IPv6 loopback is written `[::1]`) without a resolver, and refuses an invalid method, port, deadline (non-finite, non-positive or above 900 s) or credential string before opening a socket.
