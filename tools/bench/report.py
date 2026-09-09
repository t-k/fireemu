#!/usr/bin/env python3
"""Paired benchmark reports: canonical units, explicit direction, baseline percentages.

Raw durations retain their precision in ms; raw memory remains bytes. Markdown uses
ms / MiB / req/s consistently. Percentages and confidence intervals derive from the
same paired geometric-mean ratio, not from a ratio of displayed medians.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any

REPORT_SCHEMA_VERSION = 2
# source unit -> (canonical unit, multiplier to canonical). No magnitude-based guessing.
UNIT_SPECS = {
    "ns": ("ms", 1e-6), "us": ("ms", 1e-3), "µs": ("ms", 1e-3),
    "ms": ("ms", 1.0), "s": ("ms", 1000.0),
    "bytes": ("bytes", 1.0), "B": ("bytes", 1.0),
    "KiB": ("bytes", 1024.0), "MiB": ("bytes", 1024.0**2),
    "GiB": ("bytes", 1024.0**3), "req/s": ("req/s", 1.0),
}
DISPLAY_UNITS = {"ms": "ms", "bytes": "MiB", "req/s": "req/s"}
DIRECTIONS = {False: "lower-is-better", True: "higher-is-better"}
MetricMap = dict[str, tuple[float | None, bool, str]]


def finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def convert_unit(value: float, source: str, target: str) -> float:
    """Convert only explicitly declared, dimension-compatible units."""
    if not finite_number(value):
        raise ValueError("finite measurement required")
    if source not in UNIT_SPECS or target not in UNIT_SPECS:
        raise ValueError(f"unknown unit: {source!r} or {target!r}")
    dimension, scale = UNIT_SPECS[source]
    target_dimension, target_scale = UNIT_SPECS[target]
    if dimension != target_dimension:
        raise ValueError(f"incompatible units: {source} -> {target}")
    converted = value * (scale / target_scale)
    if not math.isfinite(converted):
        raise ValueError("unit conversion overflow")
    return converted


def paired_ratio(official, fireemu, higher_is_better=False, seed=90210, draws=3000):
    """Preserves the v1 API: benefit > 1 always favors fireemu."""
    if len(official) != len(fireemu) or not official:
        raise ValueError("matched nonempty paired samples required")
    if any(not finite_number(x) or x <= 0 for x in [*official, *fireemu]):
        raise ValueError("positive finite measurements required; null is not zero")
    if not isinstance(draws, int) or draws < 100:
        raise ValueError("at least 100 bootstrap draws required")
    def log_ratio(a, b):
        ratio = a / b
        # Preserve the v1 ordinary-value calculation, with an overflow/underflow fallback.
        return math.log(ratio) if math.isfinite(ratio) and ratio > 0 else math.log(a) - math.log(b)
    logs = [log_ratio(f, o) if higher_is_better else log_ratio(o, f)
            for o, f in zip(official, fireemu)]
    estimate = math.exp(statistics.mean(logs))
    if len(logs) < 3:
        return estimate, None, None
    rng = random.Random(seed)
    values = sorted(math.exp(statistics.mean(rng.choices(logs, k=len(logs)))) for _ in range(draws))
    return estimate, values[int(.025 * draws)], values[min(draws - 1, int(.975 * draws))]


def percentages(benefit: float | None, low: float | None, high: float | None,
                higher_is_better: bool) -> dict[str, float | None]:
    """F/O baseline percentage, signed change, and direction-normalized improvement.

    A 2x benefit means -50% time/memory, but +100% throughput. It does NOT mean
    +100% improvement for both. CI endpoints are reversed when taking a reciprocal.
    """
    keys = ["relative_percent", "relative_ci95_low", "relative_ci95_high",
            "change_percent", "change_ci95_low", "change_ci95_high",
            "improvement_percent", "improvement_ci95_low", "improvement_ci95_high"]
    if benefit is None:
        return dict.fromkeys(keys)
    if not finite_number(benefit) or benefit <= 0:
        raise ValueError("positive finite benefit required")
    relative = benefit if higher_is_better else 1.0 / benefit
    result = dict.fromkeys(keys)
    result["relative_percent"] = 100.0 * relative
    result["change_percent"] = 100.0 * (relative - 1.0)
    result["improvement_percent"] = result["change_percent"] * (1 if higher_is_better else -1)
    if low is not None and high is not None:
        if not all(finite_number(x) and x > 0 for x in (low, high)) or low > high:
            raise ValueError("ordered, positive finite confidence bounds required")
        rlow, rhigh = (low, high) if higher_is_better else (1.0 / high, 1.0 / low)
        result.update(relative_ci95_low=100 * rlow, relative_ci95_high=100 * rhigh,
                      change_ci95_low=100 * (rlow - 1), change_ci95_high=100 * (rhigh - 1))
        result["improvement_ci95_low"] = 100 * (rlow - 1) if higher_is_better else 100 * (1 - rhigh)
        result["improvement_ci95_high"] = 100 * (rhigh - 1) if higher_is_better else 100 * (1 - rlow)
    return result


def plateau(samples, phase, key):
    rows = [r for r in samples if r.get("phase") == phase and r.get("complete") and r.get(key) is not None]
    if not rows:
        return None
    values = [r[key] for r in rows[len(rows) // 2:]]
    if any(not finite_number(x) or x < 0 for x in values):
        return None
    return statistics.median(values)


def trial_metrics(trial, samples) -> MetricMap:
    metrics: MetricMap = {
        "startup/sdk-usable-ms": (trial.get("usable_ready_ms"), False, "ms"),
        "startup/tcp-ready-ms": (trial.get("tcp_ready_ms"), False, "ms"),
        "shutdown/wall-ms": (trial.get("stop_ms"), False, "ms"),
        "runtime/cgroup-memory-peak-through-prestop": (
            trial.get("pre_stop", {}).get("cgroup_memory_peak_bytes"), False, "bytes"),
    }
    for name in ["idle-empty", "idle-loaded", "before-release", "idle-after-delete", "idle-after-delete-long"]:
        for key in ["pss_bytes", "uss_bytes", "rss_bytes", "cgroup_memory_current_bytes"]:
            metrics[f"{name}/{key}"] = (plateau(samples, name, key), False, "bytes")
    for case in trial.get("cases", []):
        name = case["spec"]["id"]
        for key in ["p50_ms", "p95_ms", "p99_ms", "throughput_rps"]:
            value = case.get(key)
            if key == "p99_ms" and len(case.get("latency_ms", [])) < 1000:
                value = None
            metrics[f"{name}/{key}"] = (value, key == "throughput_rps", "req/s" if key == "throughput_rps" else "ms")
        first = case.get("first_result_ms", [])
        if first:
            value = statistics.median(first) if all(finite_number(x) and x >= 0 for x in first) else None
            metrics[f"{name}/first-result-median-ms"] = (value, False, "ms")
    return metrics


def load(root):
    meta = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    trials = []
    for path in sorted(root.glob("block-*/trial.json")):
        trial = json.loads(path.read_text(encoding="utf-8"))
        sf = path.parent / "samples.jsonl"
        samples = [json.loads(line) for line in sf.read_text(encoding="utf-8").splitlines() if line.strip()] if sf.exists() else []
        trials.append((trial, trial_metrics(trial, samples)))
    return meta, trials


def aggregate_metric(name: str, blocks: dict, expected: int, eligible: bool) -> dict:
    descriptors = [m[name] for block in blocks.values() for _, m in block.values() if name in m]
    first = descriptors[0]
    hb = first[1]
    unit = UNIT_SPECS[first[2]][0]
    display_unit = DISPLAY_UNITS[unit]
    # Keep descriptive values when one side is missing; never generate a partial-pair ratio.
    values: dict[str, list[float]] = {"official": [], "fireemu": []}
    paired: dict[str, list[float]] = {"official": [], "fireemu": []}
    reason = None
    for block in sorted(blocks):
        pair = {}
        for engine in ("official", "fireemu"):
            if engine not in blocks[block]:
                reason = reason or "missing-trial"
                continue
            metric = blocks[block][engine][1].get(name)
            if metric is None:
                reason = reason or "missing-metric"
                continue
            value, direction, source_unit = metric
            if direction != hb or source_unit not in UNIT_SPECS or UNIT_SPECS[source_unit][0] != unit:
                reason = "incompatible-unit-or-direction"
                continue
            if value is None:
                reason = reason or ("p99-needs-1000-samples-per-trial" if name.endswith("/p99_ms") else "missing-measurement")
                continue
            if not finite_number(value) or value < 0:
                reason = "invalid-measurement"
                continue
            value = convert_unit(value, source_unit, unit)
            values[engine].append(value)
            pair[engine] = value
        if len(pair) == 2:
            for engine in paired:
                paired[engine].append(pair[engine])
    ratio = low = high = None
    n_pairs = len(paired["official"])
    if eligible and reason is None and n_pairs == expected:
        try:
            ratio, low, high = paired_ratio(paired["official"], paired["fireemu"], hb)
        except (ValueError, OverflowError):
            reason = "zero-or-invalid-ratio-input"
    if not eligible:
        reason = "run-not-comparable"
    elif n_pairs != expected:
        reason = reason or "incomplete-metric-pairs"
    omed = statistics.median(values["official"]) if values["official"] else None
    fmed = statistics.median(values["fireemu"]) if values["fireemu"] else None
    return dict(metric=name, unit=unit, display_unit=display_unit,
                direction=DIRECTIONS[hb], n_pairs=n_pairs, expected_pairs=expected,
                official_n=len(values["official"]), fireemu_n=len(values["fireemu"]),
                official_median=omed, fireemu_median=fmed,
                official_display_median=convert_unit(omed, unit, display_unit) if omed is not None else None,
                fireemu_display_median=convert_unit(fmed, unit, display_unit) if fmed is not None else None,
                benefit_ratio=ratio, ci95_low=low, ci95_high=high,
                **percentages(ratio, low, high, hb),
                status="paired" if ratio is not None else "not-comparable", reason=reason)


def md(value: Any) -> str:
    """Prevent names and errors from breaking GFM tables or injecting HTML."""
    text = html.escape(str(value), quote=False).replace("\r\n", "\n").replace("\r", "\n")
    for character in ("\\", "`", "*", "_", "[", "]"):
        text = text.replace(character, "\\" + character)
    return text.replace("|", "&#124;").replace("\n", "<br>")


def number(value: float | None, decimals: int = 3) -> str:
    if value is None or not finite_number(value):
        return "N/A"
    if value != 0 and abs(value) < 10 ** (-decimals):
        # Preserve tiny nonzero results; never change the unit to ns/us just for one cell.
        return f"{value:.3g}"
    if abs(value) >= 1e12:
        return f"{value:.3e}"
    return f"{value:,.{decimals}f}"


def percent(value: float | None, signed=False) -> str:
    if value is None or not finite_number(value):
        return "N/A"
    if abs(value) < 1e-10:
        value = 0.0
    magnitude = number(abs(value), 1)
    prefix = ("+" if value > 0 else "−" if value < 0 else "") if signed else ("−" if value < 0 else "")
    return f"{prefix}{magnitude}%"


def metric_label(metric: str) -> str:
    labels = {
        "startup/sdk-usable-ms": "SDK usable",
        "startup/tcp-ready-ms": "TCP ready", "shutdown/wall-ms": "Shutdown",
        "runtime/cgroup-memory-peak-through-prestop": "cgroup peak (whole trial)",
    }
    if metric in labels:
        return labels[metric]
    stage, key = metric.rsplit("/", 1)
    labels = {"pss_bytes": "PSS", "uss_bytes": "USS", "rss_bytes": "RSS",
              "cgroup_memory_current_bytes": "cgroup current", "p50_ms": "p50",
              "p95_ms": "p95", "p99_ms": "p99", "throughput_rps": "throughput",
              "first-result-median-ms": "first result (median)"}
    return f"{stage} · {labels.get(key, key)}"


def table(rows: list[dict], title: str) -> list[str]:
    lines = [f"## {title}", "",
             "| Metric | Direction | Official (median) | fireemu (median) | Official = 100% | Δ vs Official | Benefit × [95% CI] | Pairs |",
             "|:---|:---|---:|---:|---:|---:|---:|:---:|"]
    for row in rows:
        direction = "Higher is better" if row["direction"] == "higher-is-better" else "Lower is better"
        def value(engine):
            v = row[f"{engine}_display_median"]
            return "N/A" if v is None else f"{number(v)} {row['display_unit']}"
        benefit = "N/A"
        if row["benefit_ratio"] is not None:
            ci = "CI unavailable (<3 pairs)" if row["ci95_low"] is None else f"[{number(row['ci95_low'])}, {number(row['ci95_high'])}]"
            benefit = f"{number(row['benefit_ratio'])}× {ci}"
        lines.append(f"| {md(metric_label(row['metric']))} | {direction} | {value('official')} | {value('fireemu')} | "
                     f"{percent(row['relative_percent'])} | {percent(row['change_percent'], signed=True)} | "
                     f"{benefit} | {row['n_pairs']}/{row['expected_pairs']} |")
    return lines + [""]


def markdown(meta, rows, eligible, expected, invalid, reasons) -> str:
    synthetic = meta.get("synthetic") is True
    lines = [f"# Firestore emulator benchmark — {md(str(meta['commit'])[:12])}", ""]
    if synthetic:
        lines += ["> **SYNTHETIC EXAMPLE — formatting test data, not measured performance. Do not cite these numbers as benchmark results.**", ""]
    verdict = "RUN INPUT CHECKS PASSED (see per-metric availability)" if eligible else "NOT COMPARABLE — ratios and percentages withheld"
    if synthetic:
        verdict = "EXAMPLE ONLY — " + verdict
    lines += [f"**{verdict}**", "",
              "| Configuration | Value |", "|:---|:---|",
              f"| Profile / tier | {md(meta['profile'])} / {md(meta['tier'])} |",
              f"| Expected measured pairs | {expected} |",
              f"| Failed trials, including prelude | {len(invalid)} |",
              "| Display units | Time: ms · memory: MiB (1 MiB = 1,048,576 bytes) · throughput: req/s |",
              "| Baseline | Official = 100%; Δ = (paired fireemu/Official ratio − 1) × 100% |", "",
              "**Reading the table:** Lower is better for time/memory (negative Δ is favorable). "
              "Higher is better for throughput (positive Δ is favorable). Benefit > 1 always favors fireemu.", "",
              "Absolute values are medians across trials (latency rows: median of each trial's percentile), not pooled-request percentiles. "
              "Percentages and benefit intervals use the same **paired geometric-mean ratio**; they may differ from dividing the displayed medians. "
              "They are computed before rounding. Pairs below 3 have no bootstrap interval.", ""]
    if reasons:
        lines += ["## Comparison withheld", "", *[f"- {md(reason)}" for reason in reasons], ""]
    groups = [
        ("Startup / shutdown — ms", sorted(
            [r for r in rows if r["metric"].startswith(("startup/", "shutdown/"))],
            key=lambda r: ["startup/sdk-usable-ms", "startup/tcp-ready-ms", "shutdown/wall-ms"].index(r["metric"]))),
        ("Memory — MiB", sorted([r for r in rows if r["unit"] == "bytes"], key=lambda r: (
            ["idle-empty", "idle-loaded", "before-release", "idle-after-delete", "idle-after-delete-long", "runtime"].index(r["metric"].split("/")[0]),
            r["metric"]))),
        ("Firestore latency — ms", [r for r in rows if r["unit"] == "ms" and not r["metric"].startswith(("startup/", "shutdown/"))]),
        ("Firestore throughput — req/s", [r for r in rows if r["unit"] == "req/s"]),
    ]
    for title, group in groups:
        # No all-empty memory phases in startup-only reports. Unavailable p99 stays explicit below.
        visible = [r for r in group if r["official_median"] is not None or r["fireemu_median"] is not None]
        if not visible:
            continue
        if len(visible) > 16:
            lines += ["<details>", f"<summary>{title} ({len(visible)} metrics)</summary>", ""]
            lines += table(visible, title) + ["</details>", ""]
        else:
            lines += table(visible, title)
    unavailable = [r for r in rows if r["status"] != "paired"]
    if unavailable:
        lines += ["<details>", f"<summary>Unavailable / non-comparable metrics ({len(unavailable)})</summary>", "",
                  "N/A is missing, inapplicable, insufficient, or undefined — never an invented zero. "
                  "Zero baselines do not produce percentages or a speedup claim.", "",
                  "| Metric | Reason | Valid pairs |", "|:---|:---|:---:|"]
        for row in unavailable:
            lines.append(f"| {md(row['metric'])} | {md(row['reason'])} | {row['n_pairs']}/{expected} |")
        lines += ["", "</details>", ""]
    if invalid:
        lines += ["## Failed trials", "", "| Block | Engine | Error |", "|:---|:---|:---|"]
        for trial in invalid:
            error = trial.get("error") or trial.get("cleanup_error") or "trial validation / cleanup failure"
            lines.append(f"| {md(trial.get('block'))} | {md(trial.get('engine'))} | {md(str(error)[:1500])} |")
        lines += [""]
    lines += ["<details>", "<summary>Definitions, precision and interpretation</summary>", "",
              "Let G = exp(mean(log(fireemuᵢ) − log(Officialᵢ))). Official=100% is 100G; Δ is 100(G−1)%. "
              "Benefit is 1/G for time/memory and G for throughput. JSON/CSV also include direction-normalized "
              "improvement: 100(1−G)% for lower-is-better, 100(G−1)% for higher-is-better.", "",
              "A 2× time benefit means **50% less time**, whereas 2× throughput means **100% more requests/s**. "
              "Benefit and percentage confidence intervals are transformed from the same paired block bootstrap. "
              "An interval crossing 1× (or 100% / 0% for the corresponding columns) does not establish a clear direction. "
              "These intervals describe repetitions on this runner, not all hardware. Smoke is wiring validation, not a performance conclusion.", "",
              "Display uses ms / MiB / req/s without per-cell unit switching. JSON/CSV keep canonical ms / bytes / req/s "
              "in `unit` and explicitly separate `display_unit` and converted display medians. Raw monotonic timestamps stay in ns. "
              "Tiny nonzero results use extra significant figures instead of becoming 0.000; displayed precision is not measurement accuracy.", "",
              "SDK usable includes set → get with value verification → delete. Assets preinstalled; fresh processes; "
              "OS file cache uncontrolled. Admin gRPC unless a case is rules-*. "
              "Pinned SDK defaults include automatic retries. Throughput includes client validation overhead; batch/listen workloads "
              "count logical operations, not physical RPCs or documents. Compare within one workload, not across unlike operations.", "",
              "PSS/RSS/USS are sampled process-tree sums. cgroup peak covers the whole runtime through pre-stop and includes file cache. "
              "Retained RSS after SDK deletes is not automatically a leak: allocator/JVM caches and MVCC history may remain.", "",
              "No blended overall speedup is produced. No p99 comparison uses fewer than 1,000 samples per trial. "
              "Hosted CI does not fail on small speed differences. Incorrect results, incomplete required measurements, "
              "timeouts and cleanup failures invalidate the run. Full precision and percentage CIs are in summary.json / summary.csv.", "",
              "</details>", ""]
    return "\n".join(lines)


def render(root: Path) -> bool:
    meta, trials = load(root)
    expected = meta["config"]["pairs"]
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
        raise ValueError("positive integer expected pairs required")
    used = [(t, m) for t, m in trials if not t["discard"]]
    blocks: dict = {}
    duplicates = []
    for trial, metrics in used:
        block = blocks.setdefault(trial["block"], {})
        if trial["engine"] in block:
            duplicates.append(f"block={trial['block']}, engine={trial['engine']}")
        block[trial["engine"]] = (trial, metrics)
    complete = len(blocks) == expected and all(set(b) == {"official", "fireemu"} for b in blocks.values())
    invalid = [t for t, _ in trials if t.get("ok") is not True or any(c.get("ok") is False for c in t.get("cases", []))]
    path = root / "run-status.json"
    status = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    reasons = []
    if not complete: reasons.append("Expected complete official/fireemu pairs are missing.")
    if duplicates: reasons.append("Duplicate trial identities: " + "; ".join(duplicates))
    if invalid: reasons.append("At least one measured or prelude trial failed validation or cleanup.")
    if status is None: reasons.append("run-status.json is absent; execution may have been interrupted.")
    elif status.get("failures") != 0 or status.get("asset_hashes_unchanged") is not True:
        reasons.append("Run status reports failures or changed/unverified asset hashes.")
    if meta.get("supervisor") != "systemd": reasons.append("Diagnostic process supervisor is not a publishable cgroup comparison.")
    if any(t.get("profile", meta["profile"]) != meta["profile"] for t, _ in trials):
        reasons.append("Trial profiles do not match the manifest.")
    dataset_mismatch = []
    def digest(trial):
        return next((p["data"].get("dataset_sha256") for p in trial.get("phases", [])
                     if p["name"] == "seed-and-verify"), None)
    for index, block in blocks.items():
        if set(block) != {"official", "fireemu"}: continue
        if digest(block["official"][0]) != digest(block["fireemu"][0]): dataset_mismatch.append(index)
    if dataset_mismatch: reasons.append("Dataset mismatch in blocks: " + ", ".join(map(str, dataset_mismatch)))
    eligible = not reasons
    names = sorted(set().union(*(m.keys() for _, m in used))) if used else []
    rows = [aggregate_metric(name, blocks, expected, eligible) for name in names]
    fields = list(rows[0]) if rows else ["metric", "unit", "display_unit", "direction", "status"]
    with (root / "summary.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    result = dict(schema_version=REPORT_SCHEMA_VERSION, synthetic=meta.get("synthetic") is True,
                  eligible=eligible, expected_pairs=expected, failed_trials=len(invalid),
                  dataset_mismatch=dataset_mismatch, withholding_reasons=reasons,
                  percentage_estimator="paired geometric mean of fireemu/official, not ratio of medians",
                  canonical_units={"time": "ms", "memory": "bytes", "throughput": "req/s"},
                  display_units={"time": "ms", "memory": "MiB", "throughput": "req/s"}, rows=rows)
    (root / "summary.json").write_text(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + "\n", encoding="utf-8")
    (root / "summary.md").write_text(markdown(meta, rows, eligible, expected, invalid, reasons), encoding="utf-8")
    return eligible


def append_job_summary(report: Path, destination: Path, max_bytes=1024 * 1024) -> None:
    """Keep the complete artifact, but never silently exceed GitHub's per-step 1 MiB cap."""
    content = report.read_bytes()
    current = destination.stat().st_size if destination.exists() else 0
    if current + len(content) > max_bytes:
        content = ("# Benchmark summary exceeds the GitHub step size limit\n\n"
                   "No table was truncated mid-row. Download summary.md / summary.json / summary.csv "
                   "from this run's benchmark artifact for the complete report.\n").encode()
        if current + len(content) > max_bytes:
            raise ValueError("GITHUB_STEP_SUMMARY has no remaining space")
    with destination.open("ab") as output:
        output.write(content)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--github-summary", help="Append GFM report to this GITHUB_STEP_SUMMARY file")
    args = parser.parse_args(argv)
    root = Path(args.directory)
    root.mkdir(parents=True, exist_ok=True)
    exit_code = 0
    try:
        if not (root / "manifest.json").exists():
            (root / "summary.md").write_text("# Benchmark did not reach preflight\n\n"
                "No performance claim is available. See workflow logs.\n", encoding="utf-8")
        else:
            render(root)
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        # Still surface a readable failure on Actions, instead of leaving a blank Summary.
        for name in ("summary.csv", "summary.json"):
            (root / name).unlink(missing_ok=True)
        (root / "summary.md").write_text("# Benchmark report could not be generated\n\n"
            "**NOT COMPARABLE. No ratios or percentages are claimed.**\n\n" + md(error) + "\n", encoding="utf-8")
        print(f"Report error: {error}", file=sys.stderr)
        exit_code = 1
    if args.github_summary:
        append_job_summary(root / "summary.md", Path(args.github_summary))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
