# Stage 2c: moving the query project's bucket release out of the way and back

The Storage Rules observation needs the query project's bucket to have no Firebase Rules release (`firebase.storage/<bucket>`), but that
release points at a ruleset another lane (STORAGE-OBJECT) depends on. This directory holds the two small programs that move the release
aside before the recordings and publish it again, with the same ruleset, after them. Nothing deletes the ruleset: only the release is
deleted and created again. Nothing is sent unless a program is run through `record.mjs` with an approval; both are built and tested against a
fake `https.request` only.

- `pre`: reads the owner's identity, the ruleset the release must point at, the bucket release and the bucketless release; requires that the
  bucket release points at the expected ruleset, the bucketless release is absent and the ruleset exists; writes the saved record
  (`saved-release.json`, mode 600, into its own run directory, flushed before anything is deleted); deletes the bucket release; reads both releases
  back as absent. If the deletion's result is wrong or unknown, the recovery reads the bucket release: unchanged means nothing to undo, absent
  means it is published again from the saved record and read back, anything else is left alone and the run ends as needs-recovery.
- `post`: takes the saved record from its local inputs, requires that the ruleset still exists with the saved source digest, that the bucket release
  is absent (or already the saved one, which makes the run a no-op and lets it run again as a recovery) and that the bucketless release is absent,
  publishes the release from the saved record and reads it back. If the publication's result is wrong or unknown, one read decides.
- `release.mjs`: names, what a release or ruleset response is, and the saved record. `plan.mjs`: the request IDs of each mode (11 at most for `pre`, 8
  for `post`) and the corpus digest an approval pins. `targets.mjs`: builds each request from an exact source; the body of a publication is computed
  from the saved record, never handed in. `run.mjs`: the two flows through the dispatch gate. `release-entry.mjs`: the entry (paths of the main
  checkout, a closed options record, pins recomputed before anything is created, the query project's lock for the run only, one recording).
  `record.mjs`, `print-pins.mjs`: the command and the pin printer (`node record.mjs <pre|post> <local inputs> <approval> <run ID>`).
- `approval.mjs`, `admission.mjs`, `pins.mjs`, `transport.mjs`: copies of the stage 3 modules with the stage 2c limits (one recording, US$0.5, a packet
  name that names its mode), pins over this directory and the stage 3 directory, and a transport narrowed to exact routes: no origin is allowed as a
  whole, so the stage 3 modules, which the stage 3 pins hash, stay untouched.

The lock is taken for a run and released at its clean end; the time between `pre` and `post` is held by the owner ledger (no lane records on the
query project between them except the STORAGE-RULES chain), not by a lock. A lost attempt keeps the lock even when the recovery proves the state.
