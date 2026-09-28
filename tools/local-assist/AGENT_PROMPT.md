# local-assist: operating instruction for the commander and workers

Scope: `tools/local-assist/main.py` only. The cloud session stays the orchestrator
and production gap closure keeps priority. Local output is a candidate, never an
oracle, a review or an approval. Reference: `docs/compatibility/local-assist.md`.
1. Narrow first with `rg` or another deterministic index. Put only the question,
   the path/line selectors, the kind and the current HEAD into the packet; the
   CLI reads the excerpts itself. Do not read a whole file in the cloud and then
   hand the same text to the local model.
2. Keep packet, config and results in a private directory outside the
   repository (for example `docs.local/local-assist/packets/`). Every result is a
   NEW file; an existing path is refused. Runs:
   `python3 tools/local-assist/main.py --packet <packet.json> --config <config.json> --state-dir <state> --output <new-result.json> [--dry-run]`
   `python3 tools/local-assist/main.py parse-log --format nextest --input <log> --output <new.json> --excerpt <new.txt>`
   Use `--dry-run` first for a new packet shape: it validates, hashes and budgets
   without contacting the server and records the request metadata only.
3. Three kinds only: `find-test-candidates` (test source excerpts),
   `classify-log` (the `--excerpt` file that `parse-log` wrote), `propose-tests`
   (a settled specification excerpt). Inputs are committed, publishable source or
   sanitized logs; never raw receipts, tokens, `.env`, key files, `docs.local`
   evidence or anything credential-shaped. The CLI refuses these; do not work around it.
4. Read only the short result file afterwards. Path, range and quote are checked
   textually (`evidenceVerified`); whether a claim is correct, complete, or touches
   Auth, Rules, atomicity or a comparator is still the cloud reviewer's call.
   Check `runtimeIdentityVerified` and `runtime` before trusting a run at all.
5. `busy` (exit 3): move on to independent work; never queue or poll in a loop.
   `timeout` (exit 4) or `server-state-unknown` (exit 8): do not resend and do not
   delete anything under the state dir. The in-flight marker stays until an
   operator has confirmed the server is idle (`GET /health`, `GET /slots` with
   `is_processing: false`) and runs `main.py --reset-lock --state-dir <state>`.
   `runtime-mismatch` (exit 7): the server is not serving the pinned alias; stop
   and report, do not edit the config to match.
6. Confirm `finishStatus` is `ok` before using findings; never reuse an older
   output file as this run's result. Empty findings mean "not found in the
   excerpts", not "does not exist". A local `ok` is never compatibility evidence,
   never `COMPAT_VERIFIED`, and never promotes a lane; production observation
   and independent review do that, as before.
7. Model, speed and quality are still under evaluation: use the local model only
   for kinds that measurably save cloud reading, and record each real run in
   `docs.local/local-assist/first-runs.md`.
