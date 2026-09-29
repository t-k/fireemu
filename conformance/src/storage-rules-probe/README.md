# Stage 2d: a read-only shape probe of the query project

Stage 3's first recording stopped on a response shape no earlier stage had seen: production lists each Ruleset with `metadata.services`, and the
closed schema of the list classifier did not allow it. This directory holds the one small program that sends, once each, the read requests stage
3 sends before its first write and in its cleanup, and records every answer in the private journal, so stage 3's classifiers can be checked against
real bodies before another recording is spent. It writes nothing, judges nothing about a body and stores nothing outside the journals. It sends
nothing unless it is run through `record.mjs` with an approval; it is built and tested against a fake `https.request` only.

The eight requests (two preflight, six probe reads): the owner's token, the owner's identity (userinfo), the Rulesets list (`pageSize=100`), the
metadata and the media of an object no run creates (`STORAGE-RULES/probe-2d/absent-object.bin`), Rules `:test` with stage 3's first valid compile
source and with its invalid source (a test stores nothing), and a Firestore GET of a document no run creates. Each has exactly the method, URL and
body stage 3 builds for the same route (a test compares them with stage 3's own target builder).

- `probe.mjs`: the fixed names and the six requests. `plan.mjs`: the request IDs and the corpus digest the approval pins. `targets.mjs`: builds each
  request from an exact source (a caller hands in only an ID). `run.mjs`: the flow through the dispatch gate; a fact per answer notes status, size,
  digest and content type. `probe-entry.mjs`: the entry (paths of the main checkout, a closed options record, pins recomputed before anything is
  created, the query project's lock for the run only, one recording). `record.mjs`, `print-pins.mjs`: the command and the pin printer.
- `approval.mjs`, `admission.mjs`, `pins.mjs`, `transport.mjs`: copies of the stage 3 modules with the stage 2d limits (one recording, US$0.01, 8
  requests, a packet name that starts with `stage2d-probe-`), pins over this directory and the stage 3 directory, and a transport narrowed to
  seven exact routes with their exact query strings, so the stage 3 modules, which the stage 3 pins hash, stay untouched.
