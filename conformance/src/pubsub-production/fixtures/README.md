# Recorded production answers

- `lane7-shape-001/`: the 16 exchanges of the shape-001 run on fireemu-oracle-idp (2026-09-30): method, URL, status, the body as recorded, its `bodyBytes` and content type. The members that other tools wrote around them (base64 copies, times) are dropped.
- `lane8-recorded-shape/`: ten raw response bodies recorded on fireemu-oracle-sbx by the scheduled-functions shape run. The files hold the body only; the status each answered is in the test that replays them (a read of a missing resource is 404, everything else 200).
