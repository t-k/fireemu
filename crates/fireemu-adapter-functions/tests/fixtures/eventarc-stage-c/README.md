# EVENTARC stage C recording: the replayed rows

`rows.json` holds every Eventarc and Eventarc Publishing exchange of the stage C recording of
`fireemu-oracle-idp` (2026-10-05, run `fe404dee592e`, 425 requests; the Service Usage read is a different
product and is not here, so 424 rows). The rows have the form of `../eventarc-stage-b/rows.json`; see its
README for the fields.

Derivation: the capture rows of the run (the recording's own capture, not the A2 read-back), the response bytes
decoded from `bodyBase64`, and one mask: the project number of the sandbox project, which appears in the path of
some rows and in their answers, is replaced by `123456789012` (the same number of digits), **including the copy
that a page token carries** (a token holds the project number as a protobuf varint; it is re-encoded with the
mask number, which has the same varint length, so the token keeps its length and alphabet). Nothing else is
changed. The project number must never be written into a committed file, encoded or not;
`eventarc_strict_stage_c.rs` decodes every token of both fixtures and refuses any number but the mask.

`../eventarc_strict_stage_c.rs` replays the rows in order through one server's state and names the rows the
strict surface does not reproduce, each with its reason.
