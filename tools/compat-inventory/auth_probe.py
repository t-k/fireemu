"""Observe rejection-only Auth cases without creating users or delivering messages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from probe import NUMBER, PROJECT, endpoint, request, require_status


def negative_cases() -> list[tuple[str, str, dict]]:
    email = f"compat-{uuid.uuid4().hex}@example.test"
    return [
        (
            "password-unknown-account",
            "v1/accounts:signInWithPassword",
            {"email": email, "password": uuid.uuid4().hex, "returnSecureToken": True},
        ),
        (
            "password-missing-email",
            "v1/accounts:signInWithPassword",
            {"password": "not-a-credential"},
        ),
        (
            "password-missing-password",
            "v1/accounts:signInWithPassword",
            {"email": email},
        ),
        (
            "mfa-enrollment-invalid-token",
            "v2/accounts/mfaEnrollment:start",
            {"idToken": "invalid"},
        ),
    ]


def run(target: str, origin: str | None, output: Path) -> None:
    if target == "local":
        base = endpoint(
            target, origin or f"http://{os.environ['FIREBASE_AUTH_EMULATOR_HOST']}"
        )
    else:
        if origin is not None:
            raise ValueError("production endpoint overrides are forbidden")
        base = "https://identitytoolkit.googleapis.com"
    with output.open("x") as destination:
        report = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "target": target,
            "recordedAt": datetime.now(UTC).isoformat(),
            "project": PROJECT,
            "sourceCommit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "probeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "cases": [],
            "resourceMutations": 0,
            "status": "inconclusive",
            "limitations": [
                "Rejection-only cases have no positive controls and do not attest MFA eligibility, enrollment or sign-in."
            ],
        }
        try:
            key = "local-test-key"
            if target == "production":
                token = subprocess.check_output(
                    ["gcloud", "auth", "application-default", "print-access-token"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
                status, project = request(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
                    token,
                )
                require_status(status, 200)
                if (
                    not isinstance(project, dict)
                    or project.get("projectId") != PROJECT
                    or str(project.get("projectNumber")) != NUMBER
                ):
                    raise ValueError("wrong production project")
                report["projectNumberVerified"] = True
                keys = subprocess.check_output(
                    [
                        "gcloud",
                        "services",
                        "api-keys",
                        "list",
                        f"--project={PROJECT}",
                        "--format=value(name)",
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).splitlines()
                if not keys or any(
                    not name.startswith(f"projects/{NUMBER}/locations/global/keys/")
                    for name in keys
                ):
                    raise ValueError("no project-bound API key")
                key = subprocess.check_output(
                    [
                        "gcloud",
                        "services",
                        "api-keys",
                        "get-key-string",
                        keys[0],
                        f"--project={PROJECT}",
                        "--format=value(keyString)",
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
                if not key:
                    raise ValueError("empty API key")
                status, config = request(
                    f"{base}/admin/v2/projects/{PROJECT}/config", token
                )
                report["configReadback"] = {
                    "httpStatus": status,
                    "available": status == 200,
                }
                require_status(status, 200)
                report["configSha256"] = hashlib.sha256(
                    json.dumps(config, sort_keys=True).encode()
                ).hexdigest()
            for case, path, body in negative_cases():
                status, value = request(f"{base}/{path}?key={key}", None, body)
                error = value.get("error", {}) if isinstance(value, dict) else {}
                # Only a bounded error identifier is retained. Never serialize full Auth responses.
                message = str(error.get("message", ""))
                code = message.split(" : ", 1)[0]
                if (
                    not code
                    or len(code) > 100
                    or any(not (c.isupper() or c.isdigit() or c == "_") for c in code)
                ):
                    code = "UNCLASSIFIED_ERROR"
                report["cases"].append(
                    {
                        "id": case,
                        "httpStatus": status,
                        "code": code,
                        "rejected": status == 400,
                    }
                )
            report["status"] = (
                "observed"
                if len(report["cases"]) == 4
                and all(row["rejected"] for row in report["cases"])
                else "inconclusive"
            )
        except Exception as error:  # noqa: BLE001 -- never expose credential-bearing errors.
            report["failure"] = type(error).__name__
        finally:
            destination.write(json.dumps(report, indent=2) + "\n")
        if report["status"] != "observed":
            raise SystemExit("Auth observation inconclusive; see sanitized candidate")
        print(f"{target}: 4 rejection observations; no accounts created")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["local", "production"], required=True)
    parser.add_argument("--origin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.target, args.origin, args.output)


if __name__ == "__main__":
    main()
