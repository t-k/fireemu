---
title: Performance
description: Startup time, memory and throughput compared with the official Firestore emulator.
---

Fireemu is compared with the official Firestore emulator using the same SDK workloads. Both run one after the other on the same GitHub Actions Linux runner, with Fireemu using the `emulator` profile. The benchmark also checks the results of each operation.

The following results come from one `standard` run at commit `f3b942c`. Ratios are calculated from five measured pairs; absolute values depend on the environment.

| Metric | Official emulator | Fireemu | Comparison |
|---|---:|---:|---:|
| Startup until the SDK can use Firestore | 3,043 ms | 140 ms | 21.6× faster |
| Idle memory with an empty database (PSS) | 390 MiB | 11 MiB | About 1/34 the memory |
| Peak memory during a trial (cgroup) | 849 MiB | 79 MiB | About 1/10.7 the memory |
| Firestore throughput across 22 workloads | — | — | 1.1× to 5.2× higher |

The 95% confidence interval for the startup-time ratio is [21.4, 21.8]. For the peak-memory ratio (official emulator divided by Fireemu) it is [10.2, 11.1].

See [benchmark.yml](https://github.com/t-k/fireemu/blob/main/.github/workflows/benchmark.yml) for the workflow and [`tools/bench/`](https://github.com/t-k/fireemu/tree/main/tools/bench) for the benchmark.


## Comparing a change

The Linux runner also accepts a caller-supplied baseline Fireemu binary. Both binaries use the same compatibility profile, fixture shape, service selection and SDK installation. Each paired trial starts a fresh process; the manifest records absolute binary paths, SHA-256 digests, versions and harness hashes. Binary changes during a run, invalid results or unsuccessful cleanup invalidate the comparison.

```sh
python3 tools/bench/bench.py --fireemu /path/to/candidate/fireemu --baseline-fireemu /path/to/baseline/fireemu --sdk-root conformance --tier standard --profile emulator --out .bench-candidate
python3 tools/bench/report.py .bench-candidate
```

The default remains the official emulator versus Fireemu, with report schema version 2. Binary comparisons use schema version 3, explicit `baseline-fireemu`/`candidate-fireemu` labels and `baseline_*`/`candidate_*` measurement fields. Use at least five measured fresh-process pairs for a performance claim. An identical binary comparison is a useful control; an interval containing 1 does not establish an improvement.

`--fixture-shape tiny` selects scalar documents; `--fixture-shape wide-map` selects 32 nested map fields. The default fixture retains its existing payload. Query oracle fields and full SDK readback validation apply to every shape. Compare each shape separately.

`--mixed-services` loads Auth, Storage and Firestore in both the isolated and overlapping phases. It performs 8 validated operations per class with concurrency 2, a fixed seed, a 64 KiB Storage upload/readback/delete operation and actual Auth configuration, Hub registry and Firestore read probes. The report retains separate class latency and throughput distributions. A mixed trial requires observed overlap between Storage and another service; this establishes overlap at the client boundary, not simultaneous execution inside the server. Storage operation latency includes upload, readback and delete; it cannot separate queue time, execution time or lock wait. Existing 16-handler/2-Glob-slot limits remain the measurement baseline. Cancellation permit recovery requires runtime tests, and RSS/PSS belong to the complete loaded engine. Pre-download the pinned Storage emulator with `pnpm -C conformance exec firebase setup:emulators:storage` for official comparisons. Startup readiness also validates each loaded service. No Functions runner participates.

## Applying results to a test suite

Use measured startup and loaded-memory values to estimate only the portion of your own workflow that starts these engines. Fill this template from one validated run and your own process counts:

| Quantity | Baseline | Candidate |
|---|---:|---:|
| SDK-usable startup, seconds | measured milliseconds / 1000 | measured milliseconds / 1000 |
| Loaded idle PSS, MiB per engine | measured bytes / 1048576 | measured bytes / 1048576 |
| Fresh engine starts in your job | observed count | observed count |
| Concurrent engines at the observed plateau | observed count | observed count |

For sequential starts, the startup contribution is the measured seconds per start multiplied by the observed start count. For a stable concurrent plateau, the engine memory contribution is measured MiB multiplied by the observed concurrent engine count. Report these contributions separately from dependency installation, builds, SDK setup and test execution. They do not establish whole-job CI savings; measure the complete job to make that claim.
