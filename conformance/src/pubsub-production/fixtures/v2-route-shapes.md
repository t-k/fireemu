# Recorded v2 route shapes

`recorded-v2-routes.json` contains13 sanitized REST request/response shapes from the checksum-verified production capture148026092d56. Each item identifies its original physical line and exchange sequence. Project paths and the run prefix use demo identities. Opaque ACK/cursor values use equal-length replacement strings; no original token or project number is retained. Member order and other field formats are preserved.

These original rows did not record physical `bodyBytes` or `content-length`. They support same-route parsed-shape replay for the recorder builders and cleanup, not production byte-layout equivalence. The actual v2 REST transport records physical bytes before compact serialization; the dedicated subscription-create/Pull/actual-ACK/Seek producer acquires the missing layout observations. Tests use explicitly constructed wire text to check measurement without claiming that it is the original physical production body.

No production IAM get/set response was present in either parent capture. IAM unit fixtures follow the documented Policy schema and are explicitly synthetic. Presend review must decide that evidence debt; no IAM recorded-shape parity claim follows from these tests.
