# STORAGE-OBJECT production comparison

Compares a local fireemu (strict profile) with the two production recordings of the STORAGE-OBJECT
corpus (26 recipes, 2,436 exchanges each, run IDs in `fixtures/storage-object-production/index.json`).
It judges against recorded production values, never against a shape fitted to a simulator.

## What is compared

For each recipe, the exchanges are aligned in order by method, masked path and the names of the query
parameters. A pair is judged on:

- the HTTP status;
- the exact `content-type` string (`application/json; charset=UTF-8` is not
  `application/json; charset=utf-8`);
- every response header that is not infrastructure, both ways: a header production sends and fireemu
  does not (`missingHeader`), the reverse (`extraHeader`), and a different value (`headerValue`).
  Infrastructure headers (`date`, `server`, `alt-svc`, `x-guploader-uploadid`, `x-goog-gcs-base-ts`,
  `content-length`, transport framing) are left out, each with its reason in `normalize.mjs`;
  `content-length` is left out because it depends on masked names and is absent on compressed and
  chunked responses, and the body's layout is judged on its own (below);
- the body: parsed JSON member by member, **in production's member order** (`memberOrder` when the
  same members come in another order; only the user metadata map is sorted, because production does
  not keep its order stable), text, or bytes by length and SHA-256;
- the body's **layout**: the recorder stores a JSON answer re-serialized compactly and keeps the
  length it received, so the bytes beyond the compact form (production pretty-prints its JSON) are
  known for each side and compared (`bodyLayout`). The exact whitespace is not stored, only how much
  there was; a row whose length is unknown is counted as layout-unjudged in the report.

Outcomes: `MATCH`; `DIVERGENCE` (with the differences); `LOCAL_UNIMPLEMENTED` (fireemu answered 501,
or the rehearsal stand-in answered in its place: neither a match nor a divergence); `TAINTED` (an
exchange after a stand-in answer that disagrees with production in the same recipe: the object's
state is no longer fireemu's, so it is neither); `ONLY_PRODUCTION` and `ONLY_LOCAL` (an exchange the
other side has no counterpart for); `NOT_RUN` (the rows of a recipe the rehearsal did not reach).

## Normalization

Only run-specific values are masked, each with a reason (`NORMALIZATIONS`), and **a mask never hides a
format**: the run ID, the bucket and project; generations and download tokens and opaque etags (by
order of first appearance, so equal and different values stay distinguishable; a local value that is
not 16 digits, such as a counter, is not masked and is a difference); timestamps (with their number of
fractional digits: `<TIME:3>` is not `<TIME:9>`); epoch times (with their JSON type and digit count);
HTTP dates (only when they are one); the origin (`scheme://host:port`) of the `selfLink` and `mediaLink` members, which point at the server that answered, by design: only production's own host for that member (`www.googleapis.com` for `selfLink`, `storage.googleapis.com` for `mediaLink`) and a loopback address are masked, so a swap of the two hosts is a difference, and the path and the query stay exact; upload IDs, page tokens, credentials, account ids, the copied
object's `owner.entity`; and, in a recipe whose objects' bytes carry the run ID, the digests of those
bytes. Deterministic values (sizes, `md5Hash`, `crc32c`, `metageneration`, error messages, object
bytes, a quoted md5 etag) are compared exactly.

The fixture is built from private run directories that are never committed. `scan.mjs` refuses to
write anything that carries a credential, a project number, an unmasked run value, an email outside
`example.com`, or an identifier from the private list given with `--forbidden-file` (inline base64
bodies are decoded and scanned too). The index records that the list was used, its entry count (not a
digest of it: a hash of a short list can be guessed), not the path or the entries.

## Commands

```
node src/storage-object-compare/run.mjs normalize --run <private run dir> --run <dir> \
  --bucket <production bucket> --project <production project> \
  --out fixtures/storage-object-production [--forbidden-file <file>]

node src/storage-object-compare/run.mjs rehearse --fireemu <binary> --fireemu-commit <40-hex sha> \
  --recorder <recorder checkout> --rules <fixed Rules file> \
  --fixture fixtures/storage-object-production --out <dir>

node src/storage-object-compare/run.mjs compare --fixture fixtures/storage-object-production \
  --journal <dir>/journal.jsonl --receipt <dir>/receipt.json [--report <file>]
```

`rehearse` runs the recorder's local aggregate (the same 26 recipes through the lean wire) against the
binary, with a stand-in (`rehearsal-standin.mjs`) that answers a GCS object `PUT` fireemu answers 501
to, in the recorded shape and marked `x-compare-standin`. It refuses a recorder directory that is not
a clean git checkout with a commit, and writes a receipt that binds the fireemu commit (as given), the
SHA-256 of the binary, the recorder commit, the stand-in, the fixture's index, the Rules file and the
journal.

`compare` enforces the receipt: it must describe this journal, this fixture and the current stand-in,
bind a fireemu commit and binary digest, a 40-hex recorder commit and a Rules digest, and describe a
finished rehearsal (`LOCAL_COMPLETE`, exit 0; `--allow-incomplete yes` overrides, and the recipes not
reached are then counted as `NOT_RUN`). The fireemu commit is an operator's statement: nothing checks
it against the binary.

The recorder checkout and its pinned files are not part of this tool and are not changed by it.
