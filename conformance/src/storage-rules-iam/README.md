# Stage 2b: the IAM grant for Storage Rules that read Firestore

Storage Rules that call `firestore.get` or `firestore.exists` work only when the project's Cloud Storage for Firebase service agent
(`service-<project number>@gcp-sa-firebasestorage.iam.gserviceaccount.com`) holds `roles/firebaserules.firestoreServiceAgent`. This
directory holds the one small program that adds that grant to the query sandbox project's IAM policy, only when it is absent, reads it
back, and takes it out again if the result is wrong. It sends nothing unless it is run through `record.mjs` with an approval; it is
built and tested against a fake `https.request` only.

- `policy.mjs`: what a policy is (etag, version, bindings with members and an optional condition), whether the grant is absent, present
  once or ambiguous (conditional, or more than once), the policy with the grant added or removed, and when two policies are the same
  apart from the grant. Only `bindings` and `etag` are ever written (`updateMask: "bindings,etag"`), at policy version 3.
- `plan.mjs`: the eight request IDs (three preflight: token, owner identity, policy before; two normal: grant, policy after; three
  recovery: policy now, removal of the grant this run added, policy after the removal) and the corpus digest the approval pins.
- `targets.mjs`: builds each request from an exact source. A caller never hands in a body: the grant and the removal are computed from
  the policy a read returned, and refused unless the grant is absent (or present once) in that policy.
- `run.mjs`: the flow through the dispatch gate. The owner must be who the packet says (verified address, digest match) before the
  policy is read; an ambiguous grant stops the run before anything is written; after the grant is attempted, a result that is not the
  policy before with the grant added, or a lost answer, goes to the recovery: read the policy now; if it equals the policy before there
  is nothing to undo; if it is the policy before with exactly this grant, remove exactly it and read it back; anything else is left
  untouched and the run ends as needs-recovery.
- `iam-grant.mjs`: the entry. Paths of the main checkout, a closed options record, pins recomputed before anything is created (code,
  schema, corpus, commit, no untracked or ignored runner file), the query project's lock alone, one recording, at most 8 requests.
- `record.mjs`, `print-pins.mjs`: the command and the pin printer.
- `approval.mjs`, `admission.mjs`, `pins.mjs`, `transport.mjs`: copies of the stage 3 modules with the stage 2b limits (one project, 8
  requests, US$1, one recording), pins over this directory and the stage 3 directory, and one added exact route (`setIamPolicy`), so the
  stage 3 modules, which the stage 3 pins hash, stay untouched.

A lost attempt keeps the project lock even when the recovery proves the grant absent again: the lock is released by hand after the
journal is read. Removing the grant after the recordings is a separate packet.
