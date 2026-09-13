# Second45 production connection preparation

The second production connection reuses the first batch's credential, quota, configuration and recovery mechanisms. Its closed manifest still contains 32 Auth diagnostics and 13 Firestore steps. The explicit production entry runs mapped operations only. Neither this preparation nor its fixtures executed a Cloud request. The local-only entry continues to reject external origins; it does not use approval or credential environment variables to fall back to production.

## Comparison and safety

The new production/local contract is separate from the original direct/mapped contract. Every setup, baseline, readback, diagnostic and cleanup request is checked against independent recipes. Ordered query pairs preserve repeated mask arguments. Stale delete uses the same execution's original readback version and verifies that it differs from the updated version. A real API key is resolved only at the transport boundary after its independent project ownership check; client diagnostics carry no administrator Authorization or quota header.

Diagnostic success and refusal are recorded without forcing local expected statuses. A successful stale delete can produce an absent after-readback and a two-request absence cleanup; a retained document uses version-bound deletion and final absence confirmation. Protected Auth changes or rejected Firestore operations that changed state stop observation and retain the result. Missing readbacks remain indeterminate. Recording, state validation, cleanup and compatibility are separate fields. Complete but different responses produce mismatches, not collection failures.

The comparator also binds the remote permission, approval validation time, nonce, frozen execution commit, observer and metadata evidence. It validates historical permission at the recorded validation time rather than expiring a saved observation at comparison time. This is consistency checking, not a signature or an independently verified owner identity. Permission cannot be inferred from this preparation.

Non-JSON production responses retain their complete or partial receipt digest, length, status, media type and truncation/failure fields. Differences are detectable without treating two absent JSON bodies as equal. Raw non-JSON content is not retained by that production wire path, so later textual inspection is unavailable. Present-document and account readbacks still require JSON, identity and state fields.

## Request and cost proposal

Normal complete observation needs 330 data requests: Auth302 and Firestore28, including recovery 17. Eight successful metadata GETs cover preflight and postflight. One credential command plus one tokeninfo request gives 340 budget units: 339 HTTP requests and one subprocess command. At most two acquisitions give 342 budget units: 340 HTTP requests and two commands. Recovery is a subset of service counts and is never added again to their sum. These production totals were exercised through an offline communication fixture; the actual local run has no metadata/credential requests.

The unchanged caps are Auth400, Firestore100, metadata100, recovery60 and total660; at most four requests per second, one at a time, 1200 seconds including 300 reserved for recovery. There are two owned accounts, three seeds, one simultaneously owned document, no queries or collection scans. Terminal recovery for two accounts and one document reserves up to 11 resource requests plus credential refresh and four postflight requests. Under the 12-second per-request limit and 0.25-second pacing assumption, this is 270 seconds, within the 300-second reserve. An absolute permission deadline also gates each reservation. Exhaustion leaves unresolved resources recorded, with no automatic rerun.

The proposed USD1 ceiling uses conservative unit ceilings, not asserted current tariffs. The operation component is bounded by `100*(readUSD+writeUSD+deleteUSD)+2*AuthMauUSD`, deliberately charging all 100 allowed Firestore requests at each operation category; with the planning ceilings it is USD0.024. Separately accepted document/index storage and network bounds must be added and the total must remain at or below USD1. Normal-path counts are 16 reads, 8 writes and 4 deletes; they are distinct from that ceiling calculation. Response retention limits do not prove a billed-network bound after interruption. Current location/tariffs, index storage, egress and numerical cost approval remain unset.

The permission proposal caps unresolved-resource retention at 24 hours and requires an explicit positive owner-accepted duration within that cap. This is a new proposal condition, not a claim that delayed recovery is currently approved or automatically scheduled. No daemon is installed. An owner must accept a manual recovery plan and the associated storage/network estimate before issuing permission.

## One remaining owner decision

The generated input package binds the fixed checkout, observer, production manifest, comparison and Database projectionv2 contracts, project `fireemu-35fe6`, project number `592603257417`, database `(default)`, and the limits above. Owner identity, permission reference, permission window, production nonce, approved current Database projection/Auth digest and current location/pricing assumptions remain null. Previous successful environment reads and tariffs remain historical reference only.

The requested future decision is one bounded execution: read-only preflight, then only if all approved conditions match run these 45 rows once, followed by owned cleanup, postflight and comparison with the fixed local receipt. A permission for reads alone does not authorize the data phase. A fresh unused nonce and new permission kind are mandatory; previous batches' permissions are not inherited. Mismatch stops do not rewrite the approved baseline or retry automatically.

No new runtime gap was established by these offline connection tests. The first46 saved-production regression, old35/11 result, later46matches, old193 comparisons,26 local checks,23 historical indeterminate cases, SDK/Rules/Listen results and lifetime revisions remain separate historical evidence. Revision3, GAP-AUTH-007 and AUTH-U03 remain independent work.

## Fixed verification and results

The fixed implementation/execution commit is `b0c1f3ef9646cdee400d25a5a61ec818e32daa1f`. Publication commits do not replace it. The [execution input package](../../spec/compatibility/broad-runs/b0c1f3ef-second45-execution-inputs.json) and [sanitized result](../../spec/compatibility/broad-runs/b0c1f3ef-second45-production-preparation.json) carry the exact manifest, observer and comparison identifiers.

The new mapped local recording collected 45 rows in 330 requests (Auth302, Firestore28; recovery 17 already included), with collection, safety and cleanup complete. Independent recipes and transport trace validated. It used artifact SHA256 `4736579f44e710da8255612051cfa1e0087a1cb558b01af51a100b7d12cb0d58` and took 86.75 seconds including build and cleanup. This is a local recording for the new observer, not a production compatibility result.

The first 46 regression at the same source commit used artifact `c82c03a20571cf7103558f4b0ef109c2134c6f2123e4e6eb0443396b8f17e282`: all 46 matched the preserved production reference. It took 25.22 seconds including build/cleanup. Both owned runtime processes stopped and listeners closed. No admitted account/document, process or port reservation remains unrecovered.

The fixed `tools/compat-broad` suite passed 203 tests, with 0 failures/skips, in 57.56 seconds. Ruff and ty passed on changed modules. Four process-local mutations were killed at their stated frozen revisions: removing actual API-key binding, attaching administrator credentials to client requests, bypassing explicit cost confirmation, and bypassing independent repeated-query admission. These are finite checks, not a complete formal verification. There was no Rust runtime change and no full workspace nextest run.

Independent security/correctness review initially found that an invalid or missing permission/execution binding could still compare as a match. Both reproductions now produce indeterminate. Final review of `b0c1f3ef` has no remaining Must Fix or Should Fix. The approval is technical review only. The earlier `2422a6ff` smoke remains private and is not relabeled as the final execution.

Commands actually executed for the final frozen source were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production.py --write-inputs <private-input-package.json>
/usr/bin/time -p uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production.py --local-output <fresh-private-local-directory>
/usr/bin/time -p uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <fresh-private-first46-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local <first46-directory>/batch/result.json --output <private-comparison.json> --check
```

After a separately granted permission, the prepared production entry is `second_production.py --execute-permission <owner-permission.json> --manifest <bound-manifest.json> --output <fresh-private-directory>`. It was not executed against production. The comparison entry is `second_production_pair.py --production <private-production-result.json> --local <fixed-private-local-result.json> --output <comparison.json>`; add `--check` to require compatibility matches. This comparison mode was exercised using fixtures. A mismatch is a valid collected observation; incomplete or invalid inputs return nonzero even without `--check`.

The next local queue item is nearby mask/precondition/transform or listener coverage, outside this closed manifest. Production 45 remains pending the single explicit decision and input conditions above. Do not resume MFA/TTL or rebuild the evidence framework as a prerequisite.

The comparison CLI was also executed on four private fixture inputs: matching `--check` exited0, complete mismatch without `--check` exited0, mismatch with `--check` exited1, and incomplete cleanup exited1. These fixtures are not published as production observations.
