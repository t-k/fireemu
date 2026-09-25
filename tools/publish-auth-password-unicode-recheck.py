"""Publish a fresh local artifact compared with the unchanged production observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "unicode_original", ROOT / "tools/publish-auth-password-unicode.py"
)
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
PREVIOUS_SUBJECT = "9c0364b6cabdf9497c243db1956655e9d455a08578b0ce1f58bd39d5aa9dcfbf"
BUNDLE = ROOT / "spec/compatibility/evidence/auth-password-unicode-recheck/receipt.json"
PAGE = ROOT / "docs/compatibility/auth-password-unicode-recheck.md"


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
    old.require(observation["local"]["cases"] == observation["production"]["cases"])


def render(value):
    validate(value)
    observation = value["observation"]
    local = observation["local"]
    lines = [
        "# Unicode password upper boundary: corrected artifact recheck",
        "",
        "Candidate only: eight generated inputs have identical redacted public results on the new local artifact and the retained production observation. No human approval is granted or inherited.",
        "",
        f"Review subject (unapproved): `{old.digest(value)}`.",
        f"Local runtime source: `{local['runtimeSourceCommit']}`; artifact SHA-256: `{local['artifact']['sha256']}`.",
        f"Local capture: `{local['recordedAt']}`. Production capture: `{observation['production']['recordedAt']}` (reused unchanged; not a new production run).",
        "",
        "| Input | Scalars | UTF-8 bytes | UTF-16 units | Both targets | Error |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ]
    for row in local["cases"]:
        shape = row["inputShape"]
        lines.append(
            f"| {row['id']} | {shape['scalars']} | {shape['utf8Bytes']} | {shape['utf16Units']} | {row['outcome']} | {row['observedError'] or 'none'} |"
        )
    lines.extend(
        [
            "",
            "The end-user update cap now counts UTF-16 units. These eight outcomes fit a 4096-unit cap, not a universal proof of Unicode behavior. The change does not alter signup, Admin/import/reset or minimum-length validation. No claims about normalization, grapheme clusters, isolated surrogates, all strings, SDK/Rules, expiry or fault recovery follow.",
            "",
            "Each input has a separate dedicated account and private random prefix. Acceptance includes signin with the generated password and update-issued ID/refresh use. Refusal includes continued use of the fixed baseline ID/refresh/password and selected account fields. These controls do not independently exclude truncation or normalization of all alternative passwords. All accounts have UID/email absence confirmation; the owned process exited zero with listeners closed. Production settings and policy are the original recorded settings, not freshly read back for this local recheck.",
            "",
            "[New receipt](../../spec/compatibility/evidence/auth-password-unicode-recheck/receipt.json) · [Original mismatch](auth-password-unicode.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-password-unicode/source-review.json). The original mismatch, source review, production observation and all earlier approvals remain unchanged. This new artifact does not rewrite or retroactively resolve the old artifact's result.",
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
    print("Unicode artifact recheck candidate checked; subject " + old.digest(value))
