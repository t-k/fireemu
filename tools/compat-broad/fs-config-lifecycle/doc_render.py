"""Render the FS-CONFIG-LIFECYCLE classification document from the compiled matrix.

The document and the checked-in specification are produced from one source, so a row
cannot appear in one and not the other.
"""

from __future__ import annotations

import sys
from typing import Any

from .surface_matrix import (
    DATA_PLANE,
    LOCAL_SAFETY,
    MANAGED,
    build_matrix,
    repo_root,
)

DOC_PATH = "docs/compatibility/fs-config-lifecycle-classification.md"


def _doc(*paragraphs: str) -> str:
    """Join paragraphs without wrapping any of them."""
    return "\n".join(paragraphs)


_INTRO = _doc(
    *[
        "# FS-CONFIG-LIFECYCLE surface classification",
        "",
        (
            "Status: `PREPARATION_ONLY`. Parent group `FS-CONFIG-LIFECYCLE` stays "
            "`WAITING_ORACLE`. Production-unobserved conditions reduced: **0**. No "
            "production request was issued, no credential was acquired, and no existing "
            "receipt, manifest or comparison count changed."
        ),
        "",
        (
            "This page answers the first half of the blocking condition on the "
            "`FS-CONFIG-LIFECYCLE` row of [the parent table]"
            "(ip-fs-production-compatibility.md): the data-plane contract and the "
            "managed-infrastructure responsibilities are separated, every management "
            "surface is placed in exactly one class with a stated reason, and each row "
            "names where the behavior lives in this checkout or records that it does not "
            "exist."
        ),
        "",
    ]
)

_DENOMINATOR = _doc(
    *[
        "## Denominator",
        "",
        (
            "The enumeration is taken from the Discovery document already pinned in this "
            "repository at `{path}`, definition `{id}`, revision `{revision}`, SHA-256 "
            "`{sha}`. Nothing was fetched to produce this page."
        ),
        "",
        (
            "That file carries locators only: a method, parameter, schema or field name "
            "with no type, description, required marker or output-only marker. It "
            "therefore supports an enumeration of names, which is what this page relies "
            "on, and it cannot supply a message shape. Any claim below about what a "
            "response contains comes from reading this checkout, not from that input."
        ),
        "",
        (
            "That definition declares {total} methods. {excluded} of them are the document "
            "methods under `{prefix}`; they are the Firestore data plane itself and belong "
            "to the `FS-DATA-WRITE`, `FS-QUERY-INDEX`, `FS-TRANSACTION` and "
            "`FS-LISTEN-SDK` rows. They are listed in the machine-readable specification "
            "so the management denominator is provably the complement of a published set "
            "rather than an unstated selection. The remaining {classified} methods are "
            "classified below."
        ),
        "",
        (
            "The machine-readable form is [`{spec}`](../../{spec}), compiled and checked "
            "by `tools/compat-broad/fs-config-lifecycle/surface_matrix.py`."
        ),
        "",
    ]
)

_CLASSES = _doc(
    *[
        "## Classes",
        "",
        (
            "A **data-plane contract** surface changes what an ordinary Firestore request "
            "returns, so fireemu has to match production even when the surface itself is "
            "a management call. A **local-safety extension** is a surface fireemu offers "
            "that production does not, or offers differently, so that a local run stays "
            "isolated and reproducible; it must never be mistaken for production "
            "behavior. A **managed-infrastructure** surface allocates, retains, bills or "
            "schedules something only Google operates, and fireemu is not obliged to "
            "serve it. A managed row still records the data-plane consequence that "
            "survives it, because classifying a call out of scope never removes an "
            "obligation the data plane keeps."
        ),
        "",
    ]
)

_BOUNDARY = _doc(
    *[
        "## What this page does not establish",
        "",
        (
            "The classification was derived from the pinned Discovery document and from "
            "reading this checkout. It is not a production observation. Whether "
            "production agrees with any local behavior recorded here is unknown, and the "
            "local column describes only what this source tree does today."
        ),
        "",
        (
            "The repair tickets above are reproductions. Where one is marked fixed, the "
            "fix landed in the cited commit; no runtime file was changed by the work "
            "that produced this page."
        ),
        "",
        (
            "The bounded observation that would begin answering the second half of the "
            "blocking condition is prepared separately in [the campaign preparation]"
            "(fs-config-lifecycle-campaign-preparation.md). It has not run."
        ),
        "",
    ]
)


def _escape(text: str) -> str:
    return text.replace("|", "\\|")


def _citations(row: dict[str, Any]) -> str:
    citations = row["local"]["citations"]
    if not citations:
        return "not implemented"
    return " ".join(f"`{citation}`" for citation in citations)


def _method_table(rows: list[dict[str, Any]], klass: str) -> str:
    selected = [row for row in rows if row["class"] == klass]
    lines = [
        "| Method | Rationale | Data-plane consequence | Local |",
        "| --- | --- | --- | --- |",
    ]
    for row in selected:
        locator = row["locator"].removeprefix("firestore.projects.")
        lines.append(
            f"| `{locator}` | {_escape(row['rationale'])} | "
            f"{_escape(row['dataPlaneConsequence'])} | {_citations(row)} |"
        )
    return "\n".join(lines)


def _local_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Local surface | Rationale | Data-plane consequence | Where |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| `{row['id']}` | {_escape(row['rationale'])} | "
            f"{_escape(row['dataPlaneConsequence'])} | {_citations(row)} |"
        )
    return "\n".join(lines)


def _field_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Field | Class | Rationale | Data-plane consequence | Local |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        name = f"`{row['field']}`"
        if not row["presentInPinnedDiscovery"]:
            name += " (absent from the pinned Discovery document)"
        lines.append(
            f"| {name} | {row['class']} | {_escape(row['rationale'])} | "
            f"{_escape(row['dataPlaneConsequence'])} | {_citations(row)} |"
        )
    return "\n".join(lines)


def _ticket_section(tickets: list[dict[str, Any]]) -> str:
    parts = ["## Repair tickets", ""]
    parts.append(
        "Each ticket was an open local runtime gap when the matrix was first built. "
        "None was fixed by the work that renders this page; a ticket marked FIXED or "
        "PARTIALLY_FIXED cites the commit that changed the runtime, and its summary and "
        "reproduction are kept as the historical statement of the gap."
    )
    for ticket in tickets:
        citations = " ".join(f"`{c}`" for c in ticket["citations"])
        parts.extend(
            [
                "",
                f"### {ticket['id']}: {ticket['title']}",
                "",
                ticket["summary"],
                "",
                f"Reproduction: {ticket['reproduction']}",
                "",
                (
                    f"Class: {ticket['class']}. Status: {ticket['status']}. "
                    f"Evidence: {citations}"
                ),
            ]
        )
        if ticket["fixedAt"] is not None:
            parts.extend(
                ["", f"Resolution (`{ticket['fixedAt'][:9]}`): {ticket['resolution']}"]
            )
    return "\n".join(parts)


def render() -> str:
    matrix = build_matrix()
    summary = matrix["summary"]
    discovery = matrix["discovery"]
    counts = summary["methodsByClass"]
    field_counts = summary["databaseFieldsByClass"]
    parts = [
        _INTRO,
        _DENOMINATOR.format(
            path=discovery["path"],
            id=discovery["id"],
            revision=discovery["revision"],
            sha=discovery["sha256"],
            total=summary["discoveryMethods"],
            excluded=summary["excludedDataPlaneMethods"],
            prefix=matrix["excludedPrefix"],
            classified=summary["classifiedManagementMethods"],
            spec="spec/compatibility/fs-config-lifecycle-surfaces.json",
        ),
        _CLASSES,
        "## Summary\n",
        (
            "| Population | data-plane contract | local-safety extension | "
            "managed-infrastructure | Total |"
        ),
        "| --- | --- | --- | --- | --- |",
        (
            f"| Admin v1 management methods | {counts.get(DATA_PLANE, 0)} | "
            f"{counts.get(LOCAL_SAFETY, 0)} | {counts.get(MANAGED, 0)} | "
            f"{summary['classifiedManagementMethods']} |"
        ),
        (
            f"| Local-only surfaces | 0 | {len(matrix['localSurfaces'])} | 0 | "
            f"{len(matrix['localSurfaces'])} |"
        ),
        (
            f"| Database resource fields | {field_counts.get(DATA_PLANE, 0)} | "
            f"{field_counts.get(LOCAL_SAFETY, 0)} | {field_counts.get(MANAGED, 0)} | "
            f"{len(matrix['databaseFields'])} |"
        ),
        "",
        "## Data-plane contract methods\n",
        _method_table(matrix["methods"], DATA_PLANE),
        "",
        "## Managed-infrastructure methods\n",
        _method_table(matrix["methods"], MANAGED),
        "",
        "## Local-safety extensions\n",
        _local_table(matrix["localSurfaces"]),
        "",
        "## Database resource fields\n",
        _field_table(matrix["databaseFields"]),
        "",
        _ticket_section(matrix["repairTickets"]),
        "",
        _BOUNDARY,
    ]
    return "\n".join(parts).rstrip() + "\n"


def _write() -> int:
    (repo_root() / DOC_PATH).write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_write() if "--write" in sys.argv else 1)
