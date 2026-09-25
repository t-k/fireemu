"""Compare independently admitted mapped receipts without inventing oracle results."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from broad_contract import digest
from second_admission import equal
from second_mapping import comparable, expected_ids, validate_rows, validate_trace


PINNED_PRODUCTION_CANDIDATE_SHA256 = (
    "8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73"
)
PARENT_RUNTIME_ANCHOR = (
    "spec/compatibility/broad-runs/second45-parent-runtime-anchor-v4.json"
)


def observed_value(row, bindings):
    value = comparable(row, bindings)
    http = row["observation"]["http"]
    # Scope equivalence to JSON and its conventional UTF-8 spelling only.
    # Unknown parameters and other media types keep their full header value.
    if re.fullmatch(
        r'[ \t]*application/json[ \t]*(?:;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8")[ \t]*)?',
        http["contentType"],
        flags=re.IGNORECASE | re.ASCII,
    ):
        value["observation"]["wire"]["contentType"] = "application/json"
    if http["bodyKind"] != "json":
        value["observation"]["rawBody"] = {
            k: http[k] for k in ("bodySha256", "receivedBytes")
        }
    return value


def compare(production, local):
    from second_production_contract import (
        binding,
        manifest,
        observer_digest,
        validate_receipt_environment,
    )

    errors = []
    safety = []
    for target, result in (("production", production), ("local", local)):
        try:
            if result.get("target") != target or result.get("mode") != "mapped":
                raise ValueError("distinct production/local mapped targets required")
            manifest_digest = (
                result.get("manifestDigest")
                if target == "production"
                else result.get("comparisonManifestDigest")
            )
            if (
                manifest_digest != digest(manifest())
                or result.get("comparisonContractDigest") != digest(binding())
                or result.get("observerDigest") != observer_digest()
            ):
                raise ValueError("manifest, comparison contract, or observer not bound")
            if not validate_receipt_environment(result):
                raise ValueError("environment evidence incomplete")
            validate_rows(result, observed_outcomes=True)
            safety.append(validate_trace(result, observed_outcomes=True))
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            errors.append({"side": target, "reason": str(error)})
    identity = local.get("runtimeIdentity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"artifactSha256", "executionCommit", "configurationDigest"}
        or not all(isinstance(v, str) and v for v in identity.values())
    ):
        errors.append({"side": "local", "reason": "fixed runtime identity unavailable"})
    complete = all(r.get("recordingComplete") is True for r in (production, local))
    cleanup = all(r.get("cleanupComplete") is True for r in (production, local))
    rows = []
    if not errors:
        for left, right in zip(production["rows"], local["rows"], strict=True):
            rows.append(
                {
                    "id": left["id"],
                    "compatibility": "match"
                    if equal(
                        observed_value(left, production["bindings"]),
                        observed_value(right, local["bindings"]),
                    )
                    else "mismatch",
                }
            )
    return {
        "kind": "second45-production-local-comparison-v2",
        "comparisonContractDigest": digest(binding()),
        "inputDigests": [digest(r) for r in (production, local)],
        "recordingComplete": complete,
        "cleanupComplete": cleanup,
        "stateValidation": False
        if False in safety or any(r.get("safety") is False for r in (production, local))
        else (True if len(safety) == 2 and all(safety) else None),
        "compatibility": "indeterminate"
        if errors or not complete or not cleanup
        else (
            "match" if all(r["compatibility"] == "match" for r in rows) else "mismatch"
        ),
        "rows": rows,
        "errors": errors,
    }


def load_saved_candidate(path, *, expected_sha256=PINNED_PRODUCTION_CANDIDATE_SHA256):
    """Load the immutable published candidate, checking its file bytes first."""
    raw = path.read_bytes()
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if source_sha256 != expected_sha256:
        raise ValueError("saved production candidate file hash mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("saved production candidate must be an object")
    return value, source_sha256


def load_parent_manifest(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("parent execution manifest must be an object")
    return value


def compare_saved(candidate_path, local, parent_path, *, local_source_sha256=None):
    """Compare a saved normalized production candidate with one current local receipt."""
    from second_production_contract import binding, manifest, observer_digest

    candidate, candidate_source_sha256 = load_saved_candidate(candidate_path)
    parent = load_parent_manifest(parent_path)
    errors = []
    state_validation = None
    repo_root = Path(__file__).parents[2]
    evaluator_head = ""
    anchor_sha256 = ""
    parent_hash = parent.get("parentManifestSha256")
    try:
        evaluator_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
        ).strip()
        anchor_raw = subprocess.check_output(
            ["git", "show", f"HEAD:{PARENT_RUNTIME_ANCHOR}"], cwd=repo_root
        )
        anchor_sha256 = hashlib.sha256(anchor_raw).hexdigest()
    except (OSError, subprocess.CalledProcessError):
        errors.append({"side": "evaluator", "reason": "evaluator source identity unavailable"})
    try:
        if candidate.get("kind") != "second45-production-candidate-summary-v1":
            raise ValueError("saved production candidate kind is not supported")
        if candidate.get("manifestDigest") != digest(manifest()):
            raise ValueError("saved production manifest is not bound")
        if candidate.get("comparisonContractDigest") != digest(binding()):
            raise ValueError("saved production comparison contract is not bound")
        if not isinstance(candidate.get("observerDigest"), str) or not candidate[
            "observerDigest"
        ]:
            raise ValueError("saved production observer is not bound")
        rows = candidate.get("rows")
        if not isinstance(rows, list) or [r.get("id") for r in rows] != expected_ids() or any(
            not isinstance(r, dict) or not isinstance(r.get("production"), dict)
            for r in rows
        ):
            raise ValueError("saved production rows are incomplete")
        if not isinstance(candidate_source_sha256, str) or not candidate_source_sha256:
            raise ValueError("saved production source hash is unavailable")
    except (ValueError, KeyError, TypeError) as error:
        errors.append({"side": "production", "reason": str(error)})

    try:
        unsigned_parent = {
            key: value for key, value in parent.items() if key != "parentManifestSha256"
        }
        if (
            not isinstance(parent_hash, str)
            or parent_hash != digest(unsigned_parent)
        ):
            raise ValueError("parent manifest integrity binding is invalid")
        evaluator_commit = parent.get("executionCommit")
        def git_ok(arguments):
            process = subprocess.Popen(
                arguments,
                cwd=repo_root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return process.wait() == 0

        if (
            not isinstance(evaluator_commit, str)
            or not re.fullmatch(r"[0-9a-f]{40}", evaluator_commit)
            or not git_ok(["git", "cat-file", "-e", f"{evaluator_commit}^{{commit}}"])
            or not git_ok(["git", "diff", "--quiet", evaluator_commit, "--", "tools/compat-broad"])
        ):
            raise ValueError("parent execution commit does not bind evaluator source")
        anchor = json.loads(anchor_raw)
        if (
            not isinstance(anchor, dict)
            or anchor.get("parentManifestSha256") != parent_hash
            or anchor.get("mappedReceiptFileSha256")
            != parent.get("mappedReceiptFileSha256")
            or anchor.get("runtimeIdentity") != {
                "artifactSha256": parent.get("artifactSha256"),
                "executionCommit": parent.get("executionCommit"),
                "configurationDigest": parent.get("configurationDigest"),
            }
        ):
            raise ValueError("parent evidence is not bound to immutable source anchor")
        if parent.get("status") != "completed":
            raise ValueError("parent execution manifest is incomplete")
        if parent.get("productionExecuted") is not False:
            raise ValueError("parent execution manifest is not local-only")
        observations = parent.get("localObservations")
        parent_local = observations.get("mapped") if isinstance(observations, dict) else None
        if parent_local is not None and parent_local != local:
            raise ValueError("current local receipt differs from parent mapped observation")
        if not isinstance(local_source_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", local_source_sha256
        ):
            raise ValueError("current local receipt byte hash is unavailable")
        if parent.get("mappedReceiptFileSha256") != local_source_sha256:
            raise ValueError("current local receipt byte hash differs from parent")
        if parent.get("mappedReceiptKind") != "second45-local-run-v1":
            raise ValueError("parent mapped receipt kind is unsupported")
        parent_identity = {
            "artifactSha256": parent.get("artifactSha256"),
            "executionCommit": parent.get("executionCommit"),
            "configurationDigest": parent.get("configurationDigest"),
        }
        if parent.get("mappedReceiptRuntimeIdentity") != parent_identity:
            raise ValueError("parent mapped receipt identity is not bound")
        identity = local.get("runtimeIdentity")
        if identity != parent_identity:
            raise ValueError("current local runtime identity differs from parent")
        if (
            local.get("target") != "local"
            or local.get("mode") != "mapped"
            or local.get("productionExecuted") is not False
        ):
            raise ValueError("current local mapped target required")
        from second_admission import manifest as local_manifest

        if (
            local.get("kind") != "second45-local-run-v1"
            or local.get("manifestDigest") != digest(local_manifest())
            or local.get("admissionDigest") != digest(local_manifest())
            or local.get("comparisonManifestDigest") != digest(manifest())
        ):
            raise ValueError("current local receipt manifest bindings are invalid")
        if (
            local.get("comparisonManifestDigest") != digest(manifest())
            or local.get("comparisonContractDigest") != digest(binding())
            or local.get("observerDigest") != observer_digest()
        ):
            raise ValueError(
                "current local manifest, comparison contract, or observer not bound"
            )
        identity = local.get("runtimeIdentity")
        if (
            not isinstance(identity, dict)
            or set(identity)
            != {"artifactSha256", "executionCommit", "configurationDigest"}
            or re.fullmatch(r"[0-9a-f]{64}", identity["artifactSha256"]) is None
            or re.fullmatch(r"[0-9a-f]{40}", identity["executionCommit"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", identity["configurationDigest"])
            is None
        ):
            raise ValueError("fixed current local runtime identity unavailable")
        validate_rows(local, observed_outcomes=True)
        state_validation = validate_trace(local, observed_outcomes=True)
        if state_validation is not True or local.get("safety") is False:
            raise ValueError("current local trace or state validation failed")
        if (
            local.get("recordingComplete") is not True
            or local.get("cleanupComplete") is not True
        ):
            raise ValueError("current local recording or cleanup incomplete")
    except (ValueError, KeyError, TypeError, StopIteration) as error:
        errors.append({"side": "local", "reason": str(error)})

    rows = []
    if not errors:
        if len(candidate["rows"]) != len(local["rows"]):
            errors.append(
                {"side": "comparison", "reason": "saved/current row count differs"}
            )
        else:
            for saved_row, local_row in zip(candidate["rows"], local["rows"], strict=True):
                if saved_row["id"] != local_row["id"]:
                    errors.append(
                        {
                            "side": "comparison",
                            "reason": "saved/current row order differs",
                        }
                    )
                    break
                rows.append(
                    {
                        "id": saved_row["id"],
                        "compatibility": "match"
                        if equal(
                            saved_row["production"],
                            observed_value(local_row, local["bindings"]),
                        )
                        else "mismatch",
                    }
                )
    complete = all(
        value is True
        for value in (
            candidate.get("recordingComplete"),
            candidate.get("cleanupComplete"),
            local.get("recordingComplete"),
            local.get("cleanupComplete"),
        )
    )
    return {
        "kind": "second45-production-local-comparison-v2",
        "mode": "saved-production-versus-local",
        "comparisonContractDigest": digest(binding()),
        "historicalObserverDigest": candidate.get("observerDigest"),
        "currentObserverDigest": local.get("observerDigest"),
        "productionObserverDigest": candidate.get("observerDigest"),
        "localObserverDigest": local.get("observerDigest"),
        "productionCandidateSourceSha256": candidate_source_sha256,
        "currentLocalSourceSha256": digest(local),
        "productionSourceSha256": candidate_source_sha256,
        "localSourceSha256": digest(local),
        "historicalProductionReceiptSha256": candidate.get("productionReceiptFileSha256"),
        "historicalLocalReceiptSha256": candidate.get("localReceiptFileSha256"),
        "runtimeSourceCommit": parent.get("executionCommit"),
        "evaluatorCommit": evaluator_head,
        "evaluatorAnchorSha256": anchor_sha256,
        "parentManifestSha256": parent_hash,
        "mappedReceiptFileSha256": parent.get("mappedReceiptFileSha256"),
        "recordingComplete": candidate.get("recordingComplete") is True
        and local.get("recordingComplete") is True,
        "cleanupComplete": candidate.get("cleanupComplete") is True
        and local.get("cleanupComplete") is True,
        "stateValidation": False if state_validation is False else state_validation,
        "compatibility": (
            "indeterminate"
            if errors or not complete
            else (
                "match" if all(r["compatibility"] == "match" for r in rows) else "mismatch"
            )
        ),
        "rows": rows,
        "errors": errors,
        "limitations": [
            "Raw historical production receipts are unavailable; comparison uses the pinned normalized candidate production rows."
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("live", "saved"), default="live")
    parser.add_argument("--production", type=Path)
    parser.add_argument("--saved-production-candidate", type=Path)
    parser.add_argument("--parent-manifest", type=Path)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.mode == "saved":
        if args.saved_production_candidate is None:
            parser.error("--saved-production-candidate is required in saved mode")
        if args.parent_manifest is None:
            parser.error("--parent-manifest is required in saved mode")
        result = compare_saved(
            args.saved_production_candidate,
            json.loads(args.local.read_text()),
            args.parent_manifest,
            local_source_sha256=hashlib.sha256(args.local.read_bytes()).hexdigest(),
        )
    else:
        if args.production is None:
            parser.error("--production is required in live mode")
        result = compare(
            json.loads(args.production.read_text()), json.loads(args.local.read_text())
        )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return (
        1
        if not result["recordingComplete"]
        or not result["cleanupComplete"]
        or result["compatibility"] == "indeterminate"
        or (args.check and result["compatibility"] != "match")
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
