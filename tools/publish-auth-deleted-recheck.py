"""Publish a fresh local artifact compared with the unchanged production observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "deleted_original", ROOT / "tools/publish-auth-deleted.py"
)
if spec is None or spec.loader is None:
    raise ImportError("Original deleted-account publisher is unavailable")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
PREVIOUS_SUBJECT = "04f8ac7d63ee9e34eab54057a03c876dce2d75bc8e0e5eb0430b1f7cb5faedc1"
BUNDLE = ROOT / "spec/compatibility/evidence/auth-deleted-recheck/receipt.json"
PAGE = ROOT / "docs/compatibility/auth-deleted-recheck.md"


def publication_hash():
    return old.hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def validate(value):
    old.require(
        set(value)
        == {
            "schemaVersion",
            "previousSubject",
            "publicationContractSha256",
            "observation",
        }
    )
    old.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    previous = json.loads(old.BUNDLE.read_bytes())
    old.require(value["previousSubject"] == PREVIOUS_SUBJECT == old.digest(previous))
    old.require(value["publicationContractSha256"] == publication_hash())
    observation = value["observation"]
    old.validate(observation)
    old.require(observation["production"] == previous["production"])
    old.require(
        observation["local"]["privateReceiptSha256"]
        != previous["local"]["privateReceiptSha256"]
    )
    old.require(
        observation["local"]["artifact"]["sha256"]
        != previous["local"]["artifact"]["sha256"]
    )
    old.require(
        old.semantic_rows(observation["local"]["cases"])
        == old.semantic_rows(observation["production"]["cases"])
    )
    for row in observation["local"]["cases"]:
        deleted_target = row["id"].startswith("deleted-a-")
        old.require(row["outcome"] == ("refused" if deleted_target else "accepted"))
        old.require(
            row["observedError"]
            == (
                (
                    "INVALID_LOGIN_CREDENTIALS"
                    if row["id"].endswith("-signin")
                    else "USER_NOT_FOUND"
                )
                if deleted_target
                else None
            )
        )


def render(value):
    validate(value)
    observation = value["observation"]
    local = observation["local"]
    lines = [
        "# Deleted-account credentials: corrected artifact recheck",
        "",
        "Candidate only: 12 redacted REST observations match between the corrected local artifact and the retained production observation. No approval is granted or inherited.",
        "",
        f"Review subject (unapproved): `{old.digest(value)}`.",
        f"Local runtime source: `{local['runtimeSourceCommit']}`; artifact SHA-256: `{local['artifact']['sha256']}`.",
        f"Local capture: `{local['recordedAt']}`. Production capture: `{observation['production']['recordedAt']}` (reused unchanged; not a new production run).",
        "",
        "| Phase / account / route | Both targets | Error | Local / production elapsed ms |",
        "| --- | --- | --- | --- |",
    ]
    for row, production in zip(
        local["cases"], observation["production"]["cases"], strict=True
    ):
        lines.append(
            f"| {row['id']} | {row['outcome']} | {row['observedError'] or 'none'} | {row['elapsedMs']} / {production['elapsedMs']} |"
        )
    lines.extend(
        [
            "",
            "Scope: tenant-free REST, local strict profile and recorded production authentication and password-policy settings. A is deleted using its own fixed ID token; B is the independent unaffected control. Each phase observes password signin, fixed original ID-token lookup, then fixed original refresh-token use and derived lookup. Deleted A returns INVALID_LOGIN_CREDENTIALS for signin and USER_NOT_FOUND for lookup and refresh. All other nine observations succeed.",
            "",
            "The correction preserves validation-before-user-lookup ordering and distinguishes known deleted refresh credentials from unknown input using rejection-only digests. It does not accept deleted credentials or broaden other ID-token API error mappings. Local unit/model tests cover refresh UID-reuse rejection and snapshot/reset handling; those are not new production account-recreation observations. [Retention and verification details](../../tools/auth-deleted-recheck/README.md).",
            "",
            "The two dedicated accounts have UID/email absence confirmation. The owned local process exited zero with listeners closed. Production settings were not read back again, and no new production requests were made for this recheck. The original captures read project configuration and password policy before and after execution, but did not independently read API-key restrictions. Source references remain locator mappings, not newly hash-bound full-page reviews.",
            "",
            "Elapsed times are bounded request-start offsets from sequential phase readback, not exact server-side state-change times. Only elapsedMs is excluded from semantic equality. These separate runs use the same input classifications and controls, not identical secret credentials. No claim covers long-term validity, expiry, all session series, SDK/checkRevoked, Rules, fault recovery or every deletion path or account-recreation sequence.",
            "",
            "[New receipt](../../spec/compatibility/evidence/auth-deleted-recheck/receipt.json) · [Original mismatch](auth-deleted.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-deleted/source-review.json). Original observations and previous approvals remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.local:
        old.require(not args.check and not BUNDLE.exists())
        observation = json.loads(old.BUNDLE.read_bytes())
        old.require(old.digest(observation) == PREVIOUS_SUBJECT)
        observation["local"] = old.project(json.loads(args.local.read_bytes()), "local")
        value = {
            "schemaVersion": 1,
            "previousSubject": PREVIOUS_SUBJECT,
            "publicationContractSha256": publication_hash(),
            "observation": observation,
        }
        validate(value)
        BUNDLE.parent.mkdir(parents=True, exist_ok=True)
        BUNDLE.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    value = json.loads(BUNDLE.read_bytes())
    page = render(value)
    if args.check:
        old.require(PAGE.read_text() == page)
    else:
        PAGE.write_text(page)
    print(
        "Deleted-account artifact recheck candidate checked; subject "
        + old.digest(value)
    )
