"""Finite, in-memory local shadow of the TOTP enrollment retry boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path


def _code(secret: str, now: int) -> str:
    counter = now // 30
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


class TotpShadow:
    def __init__(self, uid: str, *, secret: str, now: int, tenant: str = "demo-app") -> None:
        self.uid, self.secret, self.now, self.tenant = uid, secret, now, tenant
        self.pending: dict[str, bool] = {}
        self.enrollments: list[str] = []
        self._session_counter = 0
        self.cleaned = False
        self.events = 0
        self.consumptions = 0

    def start(self, *, email_verified: bool, tenant: str = "demo-app") -> dict:
        if tenant != self.tenant:
            return {"status": 400, "error": {"code": "TENANT_MISMATCH"}}
        if not email_verified:
            return {"status": 400, "error": {"code": "EMAIL_NOT_VERIFIED"}}
        self._session_counter += 1
        session = f"session-{self._session_counter}"
        self.pending[session] = True
        self.events += 1
        return {"status": 200, "sessionId": session, "secretDigest": hashlib.sha256(self.secret.encode()).hexdigest()}

    def current_code(self, session: str) -> str:
        if session not in self.pending:
            raise ValueError("unknown session")
        return _code(self.secret, self.now)

    def finalize(self, session: str, otp: str) -> dict:
        if session not in self.pending:
            return {"status": 400, "error": {"code": "SESSION_ALREADY_FINALIZED"}}
        if not isinstance(otp, str) or len(otp) != 6 or not otp.isdecimal():
            return {"status": 400, "error": {"code": "INVALID_TOTP_FORMAT"}}
        if not hmac.compare_digest(otp, _code(self.secret, self.now)):
            return {"status": 400, "error": {"code": "INVALID_TOTP"}}
        del self.pending[session]
        enrollment_id = f"enrollment-{len(self.enrollments) + 1}"
        self.enrollments.append(enrollment_id)
        self.consumptions += 1
        self.events += 1
        return {"status": 200, "enrollment": {"id": enrollment_id, "factor": "totp"}}

    def state(self) -> dict:
        return {"pendingSessions": len(self.pending), "enrollments": len(self.enrollments), "codeConsumptions": self.consumptions, "events": self.events}

    def cleanup(self, nonce: str) -> dict:
        if not nonce or self.cleaned or self.uid != f"uid-{nonce}":
            return {"complete": False, "reason": "ownership-or-recovery-invalid"}
        self.pending.clear()
        self.enrollments.clear()
        self.cleaned = True
        return {"complete": True, "owner": f"uid-{nonce}", "deleted": True, "remainingState": self.state()}


def run(output: Path, *, nonce: str) -> dict:
    """Run the bounded shadow and checkpoint before returning the secret-free receipt."""
    shadow = TotpShadow(f"uid-{nonce}", secret="JBSWY3DPEHPK3PXP", now=1_700_000_000)
    start = shadow.start(email_verified=True)
    wrong = shadow.finalize(start["sessionId"], "000000")
    correct = shadow.current_code(start["sessionId"])
    success = shadow.finalize(start["sessionId"], correct)
    replay = shadow.finalize(start["sessionId"], correct)
    before_cleanup = shadow.state()
    recovery = shadow.cleanup(nonce)
    result = {"status": "completed" if recovery["complete"] else "incomplete", "recordingComplete": True, "cleanupComplete": recovery["complete"], "productionExecuted": False, "rows": [start, wrong, success, replay], "state": before_cleanup, "recovery": recovery}
    output.mkdir(parents=True, exist_ok=False)
    (output / "checkpoint.json").write_text(json.dumps({"stage": "C4", "nonce": nonce}, indent=2) + "\n")
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "recovery-receipt.json").write_text(json.dumps(recovery, indent=2) + "\n")
    return result
