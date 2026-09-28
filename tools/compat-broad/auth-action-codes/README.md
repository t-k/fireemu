# AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01 preparation

Status: `PREPARATION`. `productionExecuted=false`, `productionExecutable=false`, and no owner input is supplied here. This directory prepares one bounded production observation of out-of-band (OOB) action codes; it does not authorize, schedule or perform it.

## What this lane asks

The `AUTH-ACTION` row of the production-compatibility table stays `WAITING_ORACLE` because the delivery boundary and the representative code transitions are unobserved. The finite matrix here asks, for one owned account pair:

- does a `PASSWORD_RESET` code describe itself on lookup without being consumed, and is it consumed exactly once,
- does a refused password policy leave the same code usable,
- does a code issued before a password change still apply after it,
- what happens to a code whose owning account was deleted,
- do `VERIFY_EMAIL` and `EMAIL_SIGNIN` codes refuse reuse and refuse a mismatched address,
- and does privileged link generation for an address that never existed return a code.

Expiry is declared unobserved rather than waited for. Delivered messages, the hosted action page, `continueUrl` rewriting, tenants and blocking functions are named out of scope.

## Delivery boundary

Every code is obtained through the privileged `accounts:sendOobCode` call with `returnOobLink: true`, so the response carries the code and no message enters a delivery network. Owned addresses live under the reserved `example.invalid` domain, so even an unexpected delivery would be undeliverable. The manifest records `deliveredMessages: 0` and the collector records the same on every run.

## Files

| File | Role |
| --- | --- |
| `action_codes_plan.py` | The frozen matrix, owned accounts, recovery, budget, owner preconditions and the unobserved conditions. |
| `action_codes_collector.py` | The bounded loopback collector: request, rate and wall-clock budgets, a separate recovery reserve, secret redaction and an address-keyed recovery finalizer. |
| `action_codes_comparator.py` | The fail-closed comparison contract: `MATCH`, `SEMANTIC_MISMATCH` or `INDETERMINATE`. |
| `action_codes_shadow.py` | Owns one local fireemu artifact, runs the collector as its child and proves the process and its listeners are gone. |

## Recovery

Recovery is keyed on the owned address. One privileged lookup discovers whatever exists under both addresses, the deletes follow, and a second lookup must show both absent. A create whose response was lost still left an account behind that no runtime identifier names, so only the address can find it. `cleanupComplete` requires `absenceProven`, and the comparator refuses a verdict without both.

## Secrets

Action codes, links, ID tokens, refresh tokens, password hashes and every generated password stay in process memory. They never reach a receipt, a log line or a process argument. The collector refuses to return a receipt that contains one, and the comparator refuses a receipt that carries a secret field name in a key position. A recorded `keys` list may still name `oobCode`: that is the response shape this campaign compares.

## Commands

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-action-codes
uv run --python 3.12 python tools/compat-broad/auth-action-codes/action_codes_plan.py --nonce <32 hex>
uv run --python 3.12 python tools/compat-broad/auth-action-codes/action_codes_shadow.py \
  --output /absolute/private/action-codes-shadow --artifact /absolute/path/to/fireemu --nonce <32 hex>
```

The shadow test is skipped unless `FIREEMU_ACTION_CODES_ARTIFACT` names a fireemu binary, because this package does not build one. An artifact supplied that way is recorded as `retained-external`: its digest is bound, but the package never claims it was built from the current source commit.

There is no production command. Adding one is a separate reviewed change that must supply the owner permission, the fresh nonce, the project identity and a credential source, none of which exist here.
