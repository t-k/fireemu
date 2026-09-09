#!/usr/bin/env python3
"""Linux cgroup-v2 + /proc accounting. No silent substitution of missing data by zero."""
from __future__ import annotations
import os
import time
from pathlib import Path


def keyed(text: str) -> dict[str, int]:
    return {p[0].rstrip(":"): int(p[1]) for line in text.splitlines()
            if len(p := line.split()) >= 2 and p[1].isdigit()}


def proc_stat(text: str) -> dict[str, int | str]:
    # comm may contain whitespace and parentheses; split only after the final ')'.
    end = text.rfind(")")
    fields = text[end + 2:].split()
    return {"comm": text[text.index("(")+1:end], "state": fields[0],
            "ppid": int(fields[1]), "pgrp": int(fields[2]),
            "cpu_ticks": int(fields[11]) + int(fields[12]),
            "threads": int(fields[17]), "start_ticks": int(fields[19])}


def members(cgroup: Path | None, pgid: int | None = None) -> list[int]:
    if cgroup is not None:
        pids = set()
        for file in [cgroup / "cgroup.procs", *cgroup.glob("**/cgroup.procs")]:
            try:
                pids.update(map(int, file.read_text().split()))
            except FileNotFoundError:
                continue
        return sorted(pids)
    out = []
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            s = proc_stat(path.read_text())
            if s["pgrp"] == pgid:
                out.append(int(path.parent.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return sorted(out)


def snapshot(cgroup: Path | None, pgid: int | None = None) -> dict:
    started = time.monotonic_ns()
    result = {"monotonic_ns": started, "mode": "cgroup-v2" if cgroup else "process-group",
              "errors": [], "complete": True}
    try:
        pids = members(cgroup, pgid)
    except (OSError, ValueError) as exc:
        result.update(complete=False, errors=[f"enumeration: {exc}"], processes=[])
        return result
    processes = []
    totals = dict(rss_bytes=0, pss_bytes=0, uss_bytes=0, swap_pss_bytes=0, threads=0, fds=0)
    for pid in pids:
        root = Path("/proc") / str(pid)
        try:
            stat1 = proc_stat((root / "stat").read_text())
            if stat1["state"] == "Z":
                continue
            smaps = keyed((root / "smaps_rollup").read_text())
            stat2 = proc_stat((root / "stat").read_text())
            if stat1["start_ticks"] != stat2["start_ticks"]:
                continue  # PID was reused while sampling; not the same process.
            row = {"pid": pid, "start_ticks": stat1["start_ticks"], "comm": stat1["comm"],
                   "rss_bytes": smaps["Rss"] * 1024, "pss_bytes": smaps["Pss"] * 1024,
                   "uss_bytes": (smaps["Private_Clean"] + smaps["Private_Dirty"]
                                 + smaps.get("Private_Hugetlb", 0)) * 1024,
                   "swap_pss_bytes": smaps.get("SwapPss", 0) * 1024,
                   "threads": stat1["threads"], "fds": len(list((root / "fd").iterdir())),
                   "cpu_ticks": stat1["cpu_ticks"]}
            processes.append(row)
            for key in totals:
                totals[key] += row[key]
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process exited; cgroup CPU/peak still accounts for it.
        except (OSError, KeyError, ValueError) as exc:
            result["errors"].append(f"pid={pid}: {type(exc).__name__}: {exc}")
    result["processes"] = processes
    result["process_count"] = len(processes)
    result.update(totals if not result["errors"] else {k: None for k in totals})
    if cgroup:
        for fname, key in [("memory.current", "cgroup_memory_current_bytes"),
                           ("memory.peak", "cgroup_memory_peak_bytes"),
                           ("memory.swap.current", "cgroup_swap_current_bytes")]:
            try:
                result[key] = int((cgroup / fname).read_text())
            except (OSError, ValueError) as exc:
                result[key] = None
                result["errors"].append(f"{fname}: {exc}")
        for fname, key in [("memory.stat", "memory_stat"), ("cpu.stat", "cpu_stat"),
                           ("memory.events", "memory_events")]:
            try:
                result[key] = keyed((cgroup / fname).read_text())
            except (OSError, ValueError) as exc:
                result[key] = None
                result["errors"].append(f"{fname}: {exc}")
        for fname in ["memory.max", "memory.high", "cpu.max"]:
            try:
                result[fname] = (cgroup / fname).read_text().strip()
            except OSError:
                result[fname] = None
    else:
        for key in ["cgroup_memory_current_bytes", "cgroup_memory_peak_bytes",
                    "cgroup_swap_current_bytes", "memory_stat", "cpu_stat", "memory_events"]:
            result[key] = None
    result["complete"] = not result["errors"]
    result["sampler_wall_ms"] = (time.monotonic_ns() - started) / 1e6
    return result
