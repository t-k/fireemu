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
