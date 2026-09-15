# Next Auth refresh and ListCollectionIds campaign

This package targets a smallest-operation production-observation slice in denominator `ip-fs-standard-2026-09-14.v2-auth-time-listcollectionids.v1`: the two Secure Token refresh bindings whose bounded `authTime` comparison remains a mismatch, plus the eight partial `listCollectionIds` bindings represented by the root, missing-parent and one-page continuation cases. The package is based on source commit `fc75cfc1feb020b55a76f9afb911b2e8bd034ad8`.

The five accepted cases are `auth/refresh/changed-refresh@0`, `auth/refresh/reference-refresh`, `firestore/list-collection-ids/root`, `firestore/list-collection-ids/missing-document-parent`, and `firestore/list-collection-ids/page-size-one`. The Firestore paged case consumes exactly one continuation token. Each owned resource is namespaced by a fresh 32-character lowercase hexadecimal nonce. MFA, tenants, Rules, configuration changes, SAML, and other Auth methods are outside this campaign.

The bounded plan uses one worker, 16 observation requests, 16 recovery requests over six logical owned targets, a 300-second wall limit, a 240-second recovery reserve, and an 8,000 micro-USD ceiling (USD0.008). This is a planning ceiling and does not grant billing or production authorization.

The package remains `productionExecuted: false`, `productionExecutable: false`, and `approval: null`. Owner, permission, time window, nonce and current-environment inputs are deliberately unset. No expected production response is embedded.

No local shadow result is included. At the requested base commit the hardened `tools/compat-broad/auth-list/` runner and gate are absent, so running the shadow would require restoring executable code outside this docs/spec-only change. After that adapter is available, the exact entry point is `python tools/compat-broad/auth-list/campaign_auth_list_shadow.py`; the local loopback run must complete before any production admission is considered. Historical campaign files remain immutable and are listed only as references.
