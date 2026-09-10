# Unicode password upper boundary: corrected artifact recheck

Candidate only: eight generated inputs have identical redacted public results on the new local artifact and the retained production observation. No human approval is granted or inherited.

Review subject (unapproved): `5f13dcc611017940756158cbf225cc2efd85ffeed4d40fca4445039d7088a885`.
Local runtime source: `ed7156fd720145871cc3e11f9aca64449d11a005`; artifact SHA-256: `93abc07e5bbc43623a6859acfadda37d8a361b28777bc3f50909184cf0560fd3`.
Local capture: `2026-09-10T14:31:25.646604+00:00`. Production capture: `2026-09-10T14:22:14.663890+00:00` (reused unchanged; not a new production run).

| Input | Scalars | UTF-8 bytes | UTF-16 units | Both targets | Error |
| --- | ---: | ---: | ---: | --- | --- |
| ascii-at | 4096 | 4096 | 4096 | accepted | none |
| ascii-over | 4097 | 4097 | 4097 | refused | PASSWORD_DOES_NOT_MEET_REQUIREMENTS |
| bmp-byte-at | 2064 | 4096 | 2064 | accepted | none |
| bmp-byte-over | 2065 | 4098 | 2065 | accepted | none |
| astral-unit-at | 2064 | 8160 | 4096 | accepted | none |
| astral-unit-over | 2065 | 8164 | 4098 | refused | PASSWORD_DOES_NOT_MEET_REQUIREMENTS |
| bmp-scalar-at | 4096 | 8160 | 4096 | accepted | none |
| bmp-scalar-over | 4097 | 8162 | 4097 | refused | PASSWORD_DOES_NOT_MEET_REQUIREMENTS |

The end-user update cap now counts UTF-16 units. These eight outcomes fit a 4096-unit cap, not a universal proof of Unicode behavior. The change does not alter signup, Admin/import/reset or minimum-length validation. No claims about normalization, grapheme clusters, isolated surrogates, all strings, SDK/Rules, expiry or fault recovery follow.

Each input has a separate dedicated account and private random prefix. Acceptance includes signin with the generated password and update-issued ID/refresh use. Refusal includes continued use of the fixed baseline ID/refresh/password and selected account fields. These controls do not independently exclude truncation or normalization of all alternative passwords. All accounts have UID/email absence confirmation; the owned process exited zero with listeners closed. Production settings and policy are the original recorded settings, not freshly read back for this local recheck.

[New receipt](../../spec/compatibility/evidence/auth-password-unicode-recheck/receipt.json) · [Original mismatch](auth-password-unicode.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-password-unicode/source-review.json). The original mismatch, source review, production observation and all earlier approvals remain unchanged. This new artifact does not rewrite or retroactively resolve the old artifact's result.
