# FS-CONFIG-LIFECYCLE management-contract campaign preparation

Status: `PREPARATION_ONLY`. Parent group `FS-CONFIG-LIFECYCLE` stays `WAITING_ORACLE`. Production-unobserved conditions reduced: **0**. Parent promotions: **0**. The campaign described here has not run, no credential was acquired, and no existing receipt, manifest, index configuration or comparison count changed.

This page prepares the second half of the blocking condition on the `FS-CONFIG-LIFECYCLE` row of [the parent table](ip-fs-production-compatibility.md): a bounded, cheap and reversible observation of representative management behavior. The classification that answers the first half is in [the surface classification](fs-config-lifecycle-classification.md). Nothing here is an owner permission; the permission is a separate artifact this repository does not contain.

## What the campaign would observe

25 abstract cases, compiled by `tools/compat-broad/fs-config-lifecycle/cases.py` from one 32-character hexadecimal nonce. They cover the database inventory contract, one full create and delete lifecycle for a throwaway named database, the two field-configuration transitions that change data-plane behavior, the error shapes for identities that must be refused, and one conditional cleanup for each identity that production might unexpectedly accept. Every case's request keys are checked against the parameters and request body the pinned Discovery document declares for that method, so a request carrying a parameter the API does not have cannot reach a run.

| Group | Cases | What it separates |
| --- | --- | --- |
| Inventory controls | OC-01, OC-02 | The default database projection and the enumeration that decides whether the run may start at all. |
| Named database lifecycle | OC-03, OC-04, OC-05, OC-06 | Creation, readback, appearance in enumeration, and deletion. OC-06 is the revert for OC-03. |
| Identity refusals | OC-07, OC-08, OC-09, OC-10, OC-11 | An uncreated database, an uppercase and underscored id, an id below the minimum length, an id above sixty-three characters, and the invalid-id shape the local runtime deliberately answers `NOT_FOUND` for. |
| Project boundary | OC-12 | A project the caller cannot see, to learn whether production refuses without disclosing existence. |
| Time-to-live | OC-13, OC-14, OC-15, OC-16 | Baseline capture, the patch that enables a time-to-live policy, the readback, and the revert. |
| Single-field exemption | OC-17, OC-18, OC-19, OC-20 | Baseline capture, the patch that exempts a field from single-field indexing, the readback, and the revert. |
| Enumeration and operations | OC-21, OC-22 | The filtered field listing and one bounded long-running-operation poll. |
| Conditional cleanup | OC-23, OC-24, OC-25 | One delete for each refused identity, executed only if production accepted the create that was expected to fail. |

Every case carries the expected local result, read from the classification matrix rather than from a running process. Only `databases.get` and `databases.list` are served locally today, so the campaign is expected to show a served result for those cases and a refusal for the rest. That expectation is a statement about this source tree, not about production.

## Scope, cost and isolation

The run creates exactly one database, patches exactly two field configurations, and performs zero document operations. No document is read, written or deleted, so the created database holds zero bytes for its whole lifetime and the time-to-live and exemption patches build single-field index entries over an empty collection group. The estimated cost is US$0.00. The hard ceiling is US$1.0, and it exists only so that an unexpected metered charge stops the run rather than letting it continue.

Every create call counts as possibly allocating, including the three that are expected to be refused. Each has a ledger entry and a conditional delete, so an unexpected acceptance is recovered rather than left behind.

Isolation comes from the nonce. The created database is named `fsconfig-<first twelve nonce characters>`, and the two patched collection groups are named `fsconfig_ttl_<nonce>` and `fsconfig_exempt_<nonce>`, so no collection group another lane uses is touched. The default database is never created, patched, deleted, restored or cloned; only those nonce-owned field configurations under it are changed, and each is reverted in the same run. The one case that cannot carry the nonce is the too-short database id in OC-09, which declares that exemption explicitly because an id short enough to be refused cannot also carry a prefix.

## Owner preconditions

The owner confirms all of the following before the run starts. The collector never establishes any of them itself.

1. The project is on a pay-as-you-go billing plan. Creating a database beyond the default one is refused on the free plan, and the collector does not enable billing.
2. The free-tier allowance covers the default database alone, so the second database has no allowance of its own. That is why it holds no data and is deleted in the same run.
3. `databases.list` returns exactly the expected set. An unexpected database means another session owns this project, and the run does not start.
4. The created database is requested with delete protection disabled, so the delete that ends the run cannot be blocked by protection state.
5. The default database's unique id, edition, type and location match the approved baseline. Identity drift stops the run and is never normalized away.
6. The run has exclusive use of the oracle project for its duration. It enumerates databases before and after, so another lane creating or deleting a database while it runs would fail its reconciliation.

## Permission envelope

10 permissions are required, all of them configuration reads and writes: create, delete, get, read metadata for, list and update databases, get and list indexes, and get and list operations. 14 permissions are explicitly excluded, including every document permission, export, import, restore and all three backup permissions, along with service-account key creation and project deletion or policy changes. A collector defect therefore cannot read or destroy data, because it never holds a permission that would let it.

## Abort rules and cleanup

The run aborts, rather than retrying, on identity drift, an unexpected database, any billing, quota or permission refusal from the create call, a long-running operation that has not finished within its deadline, or a field configuration that does not match its captured baseline after a revert. A retry is a new run with a new nonce and a new owner permission, never an automatic repeat.

Cleanup runs in a fixed order: revert the field configurations, verify each against the baseline captured before its patch, delete the created database, delete any database a refused create unexpectedly produced, verify absence, reconcile the enumeration, then write the final ledger. The reconciliation compares against the enumeration OC-02 captured before the run and fails closed: any database present now that was absent then fails the run, and any database carrying the owned prefix fails the run even if a ledger entry claims it was recovered. A run with any unrecovered resource exits non-zero and is not a valid observation, even if every case otherwise completed.

The long-running-operation poll is bounded by 600 seconds and sixty attempts per operation, with backoff from two to fifteen seconds. A checkpoint is written and flushed after every poll, so an interrupted run resumes from the owned-resource ledger and recovers what was already created instead of starting over.

`tools/compat-broad/fs-config-lifecycle/rehearsal.py` replays that path offline under eight injected failures: none, an unexpected pre-existing database, a refused create, a poll deadline, an interrupt after the create, a refused revert, a negative create that production unexpectedly accepted, and a reconciliation that finds a database cleanup missed. It issues no request. Only the clean outcome exits zero, an unrecovered resource is always reported as such, the interrupted case still deletes the database it created, and the unexpectedly accepted create is deleted through its conditional cleanup.

## Comparator contract

`tools/compat-broad/fs-config-lifecycle/comparator.py` accepts preparation receipts only and always returns `PREPARATION_ONLY` with no rows. It rejects observation-shaped fields, a forged source binding, a receipt claiming execution, a receipt bound to a different manifest, and a drifted manifest. The nonce is a required argument, so the manifest is recompiled and compared on every call; there is no way to reach the receipt checks with an unverified manifest.

It also states the rules a future measurement version must apply. Presence and JSON type are compared but values are not for `earliestVersionTime`, `etag`, `createTime`, `updateTime`, `deleteTime`, `uid` and `snapshotTime`, because those either advance on their own or identify one provisioning instance. The nonce inside any database id, collection group id or operation name is normalized on both sides. Field presence and absence, JSON types, array order, enum spelling, and the status and canonical error code are all significant. Error message prose, operation progress counters and latency are reported but are not required to match. A non-terminal configuration state read before the deadline, a transport or authentication failure, and an incomplete revert are indeterminate rather than mismatches.

## What is still missing

No typed collector exists. The request, wall-clock and cost limits are declared, not enforced. No owner permission, nonce reservation or validity window is supplied. Production error shapes for every refusal case remain unknown. The long-running-operation metadata shapes are declared from the method and schema names in the pinned Discovery input, not from any response: that input carries locators only, with no types, descriptions or output-only markers, so it can supply an enumeration of names but never a message shape.

## Reproduction

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-config-lifecycle
uv run --python 3.12 -m ruff check tools/compat-broad/fs-config-lifecycle
```
