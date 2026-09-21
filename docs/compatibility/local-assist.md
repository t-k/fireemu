# local-assist: bounded read-only tasks for a loopback local model

`tools/local-assist` hands one small, well-defined task to a local
`llama-server` (OpenAI-compatible chat API on a loopback port) and returns a
schema-validated JSON result whose every finding points at lines the tool
itself read. It exists to save cloud tokens on candidate-finding work; it is
not an oracle, not a reviewer, and its output is never compatibility
evidence. The model gets no tools, no network, no credentials and no way to
write.

## Usage

```sh
# one task
python3 tools/local-assist/main.py --packet /abs/private/task.json --output /abs/private/result.json

# deterministic log reduction (no model involved)
python3 tools/local-assist/main.py parse-log --format nextest \
  --input /abs/private/gate.log --output /abs/private/failures.json --excerpt /abs/private/failures.txt
```

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

`responseFormat` is `json_schema` (the schema is sent as
`response_format`) or `prompt` (the schema is appended to the user message;
use it for servers without grammar-constrained output). `modelId`/`quant`
pin the runtime identity and skip the `/v1/models` probe.

### Result

The output is a new file (an existing path is refused) with `taskId`,
`kind`, `promptVersion`, `baseCommit`, `inputHashes` (per input: effective
line range, `requestedEndLine`, `lineCount`, `fileSha256`, `rangeSha256`),
`findings`, `unknowns`, `runtime` (endpoint, alias, model id reported by the
server, quant when it can be read from the model name), `usage` (prompt and
completion tokens, llama-server timings when present), `elapsedSeconds`,
`finishStatus` and `reason`. Findings carry `evidenceVerified`: whether the
quoted evidence is a whitespace-normalized substring of the cited lines.

| finishStatus | exit code | meaning |
|---|---|---|
| `ok` | 0 | schema-valid reply; findings outside the packet inputs were dropped and listed in `unknowns` |
| `needs-narrower-input` | 2 | the conservative token estimate (bytes/3 plus a template reserve) exceeds `contextTokens - maxOutputTokens`; nothing was truncated, nothing was sent |
| `busy` | 3 | another local inference holds the lock; no queueing |
| `timeout` | 4 | the per-task deadline passed; no retry |
| `schema-invalid` | 5 | the reply (after one repair attempt) still fails the schema, or was cut off by `max_tokens` |
| `server-error` | 6 | HTTP error, connection failure, redirect, malformed body, or a model probe failure |

Packet, path and output-path refusals exit 1 before any request. stdout is
a few summary lines (status, counts, usage, cited ranges, output path); the
claims themselves are only in the file. Failures log a status word and a
short reason; prompts and response bodies are never printed.

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
  environment variables are ignored and redirects are refused.
- One inference at a time (flock in the state dir). One request, plus at
  most one repair round-trip for a schema-invalid reply.
- Results are cached under the state dir by kind, question, limits, the
  sha256 of every selected range with its line selection, the prompt
  version and the runtime identity; only exact key matches are reused.
- The model's self-reported confidence is not part of the schema and is
  never used for acceptance. Findings are candidates for a human or cloud
  reviewer to verify; "not found" in the excerpts is never "does not exist".
