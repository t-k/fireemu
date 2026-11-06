"""Publish a fresh local artifact compared with the unchanged production observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "disabled_original", ROOT / "tools/publish-auth-disabled.py"
)
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
PREVIOUS_SUBJECT = "ff502af7fc37542347394d0f28e8df1b9b1566b64a5acb496a41402f040cf3de"
BUNDLE = ROOT / "spec/compatibility/evidence/auth-disabled-recheck/receipt.json"
PAGE = ROOT / "docs/compatibility/auth-disabled-recheck.md"


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
        disabled_target = row["id"].startswith("disabled-a-")
        old.require(row["outcome"] == ("refused" if disabled_target else "accepted"))
        old.require(
            row["observedError"] == ("USER_DISABLED" if disabled_target else None)
        )


def render(value):
    validate(value)
    observation = value["observation"]
    local = observation["local"]
    lines = [
        "# Account disable and re-enable: corrected artifact recheck",
        "",
        "Candidate only: 18 redacted REST observations match between the corrected local artifact and the retained production observation. No approval is granted or inherited.",
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
            "Scope: tenant-free REST, local strict profile, recorded production authentication and password-policy settings. A is disabled then re-enabled; B is the independent unaffected control. Fixed original ID and refresh tokens are reused, and successful refresh results include derived ID-token lookup. The three disabled-A routes each return USER_DISABLED. All other 15 observations succeed.",
            "",
            "Disable-only strict updates retain existing credentials but refuse their use while disabled. Password/email changes and explicit revocation remain independent; re-enabling does not undo them. The runtime unit tests cover a two-second separation between issuance and disablement; this record does not establish same-second boundary behavior or universal propagation timing.",
            "",
            "The two dedicated accounts have UID/email absence confirmation. The owned local process exited zero with listeners closed. Production settings were not read back again, and no new production requests were made for this recheck. The original captures read project configuration and password policy before and after execution, but did not independently read API-key restrictions. Source references remain locator mappings, not newly hash-bound full-page reviews.",
            "",
            "Elapsed times are bounded request-start offsets from sequential phase readback, not exact server-side state-change times. Only elapsedMs is excluded from semantic equality. These separate runs use the same input classifications and controls, not identical secret credentials. No claim covers long-term validity, expiry, all session series, SDK/checkRevoked, Rules, fault recovery or every disablement path.",
            "",
            "[New receipt](../../spec/compatibility/evidence/auth-disabled-recheck/receipt.json) · [Original mismatch](auth-disabled.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-disabled/source-review.json). Original observations and previous approvals remain unchanged.",
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
        "Disable/re-enable artifact recheck candidate checked; subject "
        + old.digest(value)
    )
