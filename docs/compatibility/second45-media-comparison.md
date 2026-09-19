# Second45 JSON Content-Type comparison revision

The fixed implementation and execution commit is `774e9d8bf4ec56db47c8f1f4bdabd71ed8bc3ceb`. Only the production comparison changed; runtime, the closed 45 manifest, transport, authentication and recovery remain unchanged. The new comparison contract is `second45-production-local-comparison-v2`. The [input package](../../spec/compatibility/broad-runs/774e9d8b-second45-execution-inputs.json) binds that contract and observer to the [new local record](../../spec/compatibility/broad-runs/774e9d8b-second45-media-comparison.json). The prior `b0c1f3ef` record, artifact identifiers and contracts remain intact.

## Scoped equivalence and verification

`application/json` and the same media type with one optional UTF-8 charset compare equally, including ASCII case, SP/HTAB whitespace and quoted charset spellings. All other headers retain exact comparison. Unknown parameters, non-UTF-8 declarations, duplicate parameters, malformed values, absent headers and other media types are not erased. Bodies still distinguish values, types, absent/additional fields and order. Raw headers stay in the immutable input receipt. Legacy direct/mapped `comparable()` remains unchanged. JSON's registered media type defines no charset parameter; this implementation deliberately adopts a narrower equivalence class than ignoring every charset or parameter. [RFC8259, section11](https://www.rfc-editor.org/rfc/rfc8259.html#section-11)

The existing whole communication fixture exercises the actual `compare()` entry. Contrasts cover charset omission, case, quoting and whitespace versus changed bodies, missing fields, different media types, unknown parameters and malformed headers. Tests also assert that both input receipts and the raw header are unchanged and the legacy comparator still sees the original difference. The charset-only test failed before the fix and passed afterward. Removing the new normalization in one Python process killed the same test; no source was edited during that mutation.

At the frozen source: 69 targeted tests passed; the full broad suite passed 210 with 0 failures/skips in 62.26 seconds; Ruff and ty passed. Independent review approved with no Must Fix or Should Fix and independently passed the 20 comparator tests. No Rust runtime change or full workspace nextest run occurred.

The fresh local 45 record uses artifact `e6a5a347cf7eea5afa879f60c5f3b47dc4c02b1fc8797060fccf683de5e93843`: 45 rows, Auth 302 + Firestore 28 = 330 requests, including recovery 17 as a subset. Collection, state validation, recovery and owned process/listener shutdown completed. The local run took 89.11 seconds including build. Independent admission/trace validation passed against the new observer and contract. This is local evidence; production45 compatibility remains unobserved.

The first 46 regression at the same fixed source used artifact `6b482ac96ea94e207327a6359a68ce43690050926851d2e6d282b068a00cc77c`, matched all 46 preserved production-reference rows and completed process/listener cleanup in 25.16 seconds. The old 35/11 result and repaired 46 results are not replaced. Other historical/SDK/Rules/Listen/lifetime evidence is unchanged.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production.py --write-inputs <private-package.json>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production.py --local-output <fresh-private-local>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <fresh-private-first46>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local <first46>/batch/result.json --output <comparison.json> --check
```

## One concrete pending execution decision

The package's `ownerDecisionProposal` contains the full historical Database projection, its digest and Auth digest as **proposed exact conditions**, not as current acquisitions or inherited permission. It proposes `fireemu-35fe6`/number`592603257417`, database`(default)`, UID`dc7a48b3-ee80-4d2e-964b-0d475c35a47a`, `us-central1`, Standard Native and disabled PITR, with every other projection field retained. Database digest is `31957f98b7ec76e9c2e7a04803772f7270763a8ed62037fbdefa74c2c8f71d33`; Auth digest is `7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2`. The owner must accept this baseline or supply an alternative before execution. No value returned by preflight becomes approved automatically.

The single requested scope is: authorized read-only preflight; only if project/key ownership, approved settings, credential expiry, contract, permission and nonce checks succeed, one mapped45 batch; then owned recovery, postflight and comparison with the fixed local receipt. A mismatch stops before data operations, and there is no automatic retry. No per-case permission is needed inside that explicitly accepted scope. A read-only authorization by itself is insufficient for the data phase.

Limits remain Auth400/Firestore100/metadata100/recovery60/total660; recovery is already included in service totals. Wall time1200seconds includes recovery300seconds. Requests are serial and spaced at least0.25seconds. Two accounts and at most one live document are owned; queries and external messaging are excluded. Normal production-path accounting remains340 budget units with one credential acquisition, or342 with two; this is fixture/calculation evidence, not production measurement.

Public tariffs checked on2026-09-13 for the proposed Iowa location are USD0.03/0.09/0.01 per100000 reads/writes/deletes, storage USD0.000205479/GiB-hour, and a conservative published destination egress maximum USD0.23/GiB. [Firestore pricing](https://cloud.google.com/firestore/pricing) Email/password's maximum published paid Tier1 rate is USD0.0055/MAU. [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing) Free quotas and discounts are not deducted. Live location and owner tariff acceptance remain unconfirmed.

At those reference rates, normal 16/8/4 document operations plus two MAU calculate to USD0.0110124 before storage/network. Charging all 100 Firestore requests at each operation category plus two MAU gives USD0.01113. The permission validator keeps its existing more conservative USD0.024 planning base.

A concrete **unapproved** cost proposal is retention 24 hours, incremental document/index storage USD0.01, network USD0.05, total USD0.084, within the unchanged USD1 ceiling. For scale, one GiB retained 24 hours costs USD0.004931496 at the reference storage rate; 0.2 GiB network costs USD0.046. These are conditional allowances requiring owner acceptance, not proven billed-usage bounds. The client 64 KiB retention limit cannot prove how much an interrupted server response is billed. Index/backup effects and total billed transfer must fit the accepted assumptions; unknowns are not marked confirmed.

The owner must also assign manual recovery responsibility and accept the 24-hour maximum retention proposal. If automatic recovery is incomplete, observation stops and the private ownership journal identifies the unresolved resources. Only verified owned resources may be recovered, with valid credentials and applicable permission, followed by absence checks. There is no recursive reset, new background worker or automatic execution extension. If this response arrangement cannot be accepted, execution stays pending.

Owner identity, permission reference, validity interval, new production nonce, accepted baseline and cost confirmation remain unset in executable inputs. Old approval/nonce cannot be reused. No oracle read, authentication check or data operation occurred in this revision. Once these concrete conditions are decided, use the frozen checkout rather than restarting comparator or evidence-framework design. Separate local exploration may continue without enlarging the 45 manifest.
