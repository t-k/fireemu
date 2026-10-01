# STORAGE-OBJECT production comparison

Compares a local fireemu (strict profile) with the two production recordings of the STORAGE-OBJECT
corpus (26 recipes, 2,436 exchanges each, project `fireemu-oracle-query`, run IDs in
`fixtures/storage-object-production/index.json`). It judges against recorded production values, never
against a shape fitted to a simulator.

## What is compared

For each recipe, the exchanges are aligned in order by method, masked path and the names of the query
parameters. A pair is judged on:

- the HTTP status;
- the exact `content-type` string (`application/json; charset=UTF-8` is not
  `application/json; charset=utf-8`);
- every response header that is not infrastructure (`date`, `server`, `alt-svc`,
  `x-guploader-uploadid`, `x-goog-gcs-base-ts`, `content-length`, transport framing; each with its
  reason in `normalize.mjs`), both ways: a header production sends and fireemu does not
  (`missingHeader`), the reverse (`extraHeader`), and a different value (`headerValue`);
- the body: parsed JSON member by member, text, or bytes by length and SHA-256.

Outcomes: `MATCH`, `DIVERGENCE` (with the differences), `LOCAL_UNIMPLEMENTED` (fireemu answered 501,
or the rehearsal stand-in answered in its place; neither a match nor a divergence), `ONLY_PRODUCTION`
and `ONLY_LOCAL` (an exchange the other side has no counterpart for).

## Normalization

Only run-specific values are masked, each with a reason (`NORMALIZATIONS`): the run ID, the bucket and
project, generations and download tokens (by order of first appearance, so equal and different values
stay distinguishable), timestamps and HTTP dates, opaque etags, upload IDs, page tokens, credentials,
account times and ids, the copied object's `owner.entity`, and, in a recipe whose objects' bytes carry
the run ID, the digests of those bytes. Deterministic values (sizes, `md5Hash`, `crc32c`,
`metageneration`, error messages, object bytes) are compared exactly.

The fixture is built from private run directories that are never committed. `scan.mjs` refuses to write
anything that carries a credential, a project number, an unmasked run value, an email outside
`example.com` or an identifier from the private list given with `--forbidden-file`.

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
to, in the recorded shape and marked `x-compare-standin`. It writes a receipt that binds the
comparison to the fireemu commit, the SHA-256 of the binary, the recorder commit (clean tree), the
stand-in and the journal. `compare` refuses a journal the receipt does not describe.

The recorder checkout and its pinned files are not part of this tool and are not changed by it.
