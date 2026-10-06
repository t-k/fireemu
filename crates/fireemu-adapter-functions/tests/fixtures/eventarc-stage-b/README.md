# EVENTARC stage B recording: the replayed rows

`rows.json` holds every Eventarc and Eventarc Publishing exchange of the stage B recording of
`fireemu-oracle-idp` (2026-10-05, run `43a83839852f`, 233 requests; the Service Usage read is a different
product and is not here). Each row: the capture's number, case, step and operation, the credential mode,
the time the answer was captured (`at`) and the request's latency in milliseconds (`ms`), the request
(method, path, the body with its members in the order they were written; a text the capture omitted as
over 4 KiB is `{"omitted": {"length": ..., "sha256": ...}}`) and the response (status, `rawBody`: the exact
bytes production wrote as text, `bodyBytes`, content type).

Derivation: the capture rows of the run, with the response bytes decoded from `bodyBase64`, and the one
mask applied to the file: the project number of the sandbox project, which appears in the path of two
rows (35 and 36) and in their answers, is replaced by `123456789012` (the same number of digits).
Nothing else is changed. The project number must never be written into a committed file.

`../eventarc_strict_stage_b.rs` replays the rows in order through one server's state and names the rows
the strict surface does not reproduce, each with its reason.
