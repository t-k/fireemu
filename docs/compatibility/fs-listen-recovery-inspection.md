# Read-only inspection of an interrupted local Listen run

`local_recovery_inspect.py` is the **offline first stage** of recovery. It reads
an existing `local_supervisor.py` run and writes a new private inspection. It
neither executes recovery nor authorizes a restart, deletion, credential lookup
or network request. It does not load the Firebase SDK, probe an endpoint, signal
a PID, change permissions, repair a journal or rewrite the original evidence.

## Invocation

Run from a complete source checkout with Python 3.12 or newer on POSIX:

```sh
python -I -S -B tools/compat-broad/fs-listen-resume/local_recovery_inspect.py \
  --run /absolute/path/to/existing-supervised-run \
  --output /absolute/path/to/new-private-inspection
```

The output parent must exist and the final output directory must be new, outside
the input run and source checkout. Paths must not traverse symlink components.
The original supervisor output is private (directories 0700 and files 0600) and
must retain those permissions. The tool does not silently fix unsafe permissions
or follow symlinks, hard-linked files, FIFOs or non-regular evidence. Each input
is bounded to 1 MiB; each checkpoint to 32 KiB, and at most five checkpoints are
accepted. These are local defensive limits, not Firebase quotas.

`inspection.json` contains private run identifiers, the acknowledged UID if one
exists, candidate document paths, source/input hashes, and the verified journal
prefix. Standard output contains only counts, fixed diagnostics and flags. The
tool never reads token-bearing `stdout.bin` or `stderr.bin` from the original run.

Exit codes: 0 = internally intact evidence inspected, 1 = incomplete or invalid
evidence (a diagnostic report may preserve a valid prefix), 2 = invalid usage,
unsafe output, or report publication failure. **Exit 0 is not successful cleanup.**
Every report keeps `authorizesCleanup`, `currentResourceStateVerified`,
`processStateVerified` and `currentArtifactVerified` false, with
`requiresLiveRevalidation` true.

## How uncertainty is represented

| Recorded state | Inspection result |
|---|---|
| Launch but no ready checkpoint | No creation is recorded; neither process inactivity nor resource absence is proved. |
| Signup intent without a valid UID acknowledgement | Creation outcome stays unknown, including after an incomplete/failed terminal record. No UID is invented or discovered. |
| A valid same-run UID and exact path checkpoint | The candidate account/document scope is retained. It is not proof that every document was created; no document version is recorded in this journal. |
| Invalid/truncated tail or missing inputs | Keep only the previously validated prefix; report uncertainty. Missing/currently changed inputs never erase an earlier usable UID checkpoint. |
| Source or generated-input drift | Show that the source/inputs are not current. Do not rebase old hashes or discard the historical responsibility. |
| Complete parent and lifecycle flags | Report a *historical completion claim*, not current absence, producer termination, or a deletion capability. |

Each directory and file is read through an anchored descriptor. Metadata,
identity and recorded absences are rechecked at the end. Ordinary concurrent
changes cause rejection rather than a success claim. A descriptor pins the
original input directory if an ancestor is renamed. This is **not** protection
against an adversary with the same UID, nor a filesystem snapshot or a signed
attestation. A coherent hash chain can be forged by its owner; live authority
must never be inferred from it.

## Completion checkpoint consistency

The writer, supervisor and inspector reject `complete: true` unless the full
ready → signup-intent → account-acknowledged → documents-at-risk prefix exists
and all account/document/client cleanup flags are true. `complete: false` with
all cleanup flags true remains valid: failed observations can have successful
cleanup. An invalid writer call permanently latches that journal and cannot be
followed by a success checkpoint.

## What a later recovery executor still needs

There is no automatic recovery executor in this change. Before any mutation,
a later tool/operator must independently establish all of the following:

1. The producer is stopped using current identity, not a potentially reused PID.
2. The current emulator is the intended instance, not merely a service which
   now occupies an old loopback port. The v14/v15 launch does not contain an
   authoritative server-instance identity or a reusable recovery capability.
3. Fresh, scope-bound, bounded recovery authority is available. Unknown creates
   are not resolved by an arbitrary later absence read.
4. The current account UID/email and each document's owner marker and version
   match the declared scope. All writes use appropriate conditions; the account
   is not deleted while unresolved document obligations need its identity.
5. New typed final readbacks and durable evidence record the recovery outcome.

Do not turn `candidateScope` into a blind deletion loop. This inspection closes
the evidence-reading stage, not these live-state and authorization requirements.
Real native/SDK runs, source/binary bindings, saved-reference replay and independent
review remain separate obligations. No old receipt or approval is modified.
