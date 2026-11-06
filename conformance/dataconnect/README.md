# Offline Data Connect fixtures

This opt-in development tool records the same synthetic named-operation corpus against firebase-tools 15.28.2 with PGlite and with PostgreSQL 17.11. It does not implement Data Connect in fireemu or establish production parity. The PostgreSQL/podman approach has been selected for future implementation; this directory provides its common fixture foundation.

## Dependencies and preparation

Use an explicit Podman connection with Linux amd64 execution and cgroup v2. The official toolkit has no pinned Linux arm64 build, so an arm64 host needs verified amd64 emulation or an amd64 executor. Do not change another user's default connection or reconfigure a shared VM. Allocate one 4 GiB container at a time, no swap, two CPUs and 256 PIDs; provision the VM with sufficient separate headroom. Budget at most 10 GiB for this tool's dependencies and stop provisioning if available host disk is below 80 GiB.

Preparation may access public package registries; recording and checking cannot. In a fresh build context, place this directory's `Containerfile`, the parent conformance directory's `package.json` and `pnpm-lock.yaml`, and the official [Node 24.14.0 Linux x64 archive](https://nodejs.org/dist/v24.14.0/node-v24.14.0-linux-x64.tar.xz). The Node archive SHA256 is `41cd79bb7877c81605a9e68ec4c91547774f46a40c67a17e34d7179ef11729df`, from the official [checksum list](https://nodejs.org/dist/v24.14.0/SHASUMS256.txt). The Containerfile checks it before extraction and checks effective cgroup limits before dependency installation.

Build only through the allocated connection and bounded executor:

```sh
podman --connection "$CONNECTION" build --platform linux/amd64 --memory 4g --memory-swap 4g --cpu-quota 200000 --cpu-period 100000 --tag localhost/fireemu-dataconnect-oracle:15.28.2 "$CONTEXT"
podman --connection "$CONNECTION" image inspect --format '{{.Id}}' localhost/fireemu-dataconnect-oracle:15.28.2
```

The base is the immutable amd64 PostgreSQL 17.11 image digest in `Containerfile`. The worktree's lock installs firebase 12.18.0, firebase-tools 15.28.2 and PGlite 0.3.16. No host or other worktree's `node_modules` is reused. The older version advertised by the PGlite gateway is not the installed package version.

Separately obtain the [official Linux amd64 toolkit 3.4.18](https://storage.googleapis.com/firemat-preview-drop/emulator/dataconnect-emulator-linux-amd64-v3.4.18), verify SHA256 `bb381de594485653812bee518ddae025c13e1050670d6fa186f6003c3c9b71ec` against the [pinned CLI manifest](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/downloadableEmulatorInfo.json), and make it executable. The runner checks the bytes again. Never use a toolkit-version override.

The toolkit is an independently acquired development oracle, not part of the fireemu distribution or the image built here. Do not publish an image containing it. The CLI source's MIT license does not determine the binary's redistribution terms. Node, PostgreSQL and the base image retain their own licenses and notices; preparation does not authorize redistributing the Google toolkit.

## Record and check

From the repository root, supply the explicit connection, immutable local image ID, verified executable and a fresh output directory:

```sh
node conformance/dataconnect/run.mjs record "$CONNECTION" "$IMAGE_ID" "$TOOLKIT" "$FRESH_OUTPUT"
node conformance/dataconnect/run.mjs check "$CONNECTION" "$IMAGE_ID" "$TOOLKIT" "$ANOTHER_FRESH_OUTPUT"
```

`record` writes candidate fixtures into the output directory only after both modes succeed and their owned containers are removed. Review those files before copying `pglite.json`, `postgres.json` and `provenance.json` into `fixtures/`. It never overwrites checked-in expectations automatically. `check` compares each mode against its checked-in expectations; changed or missing cases fail.

Each container has a private network namespace with no external interfaces, no published ports, no host socket or credential mounts, and no automatic image pulls. The runner copies only its fixture directory and toolkit into the owned container. It checks cgroup memory/swap/PID limits, namespace interfaces/routes, rejected IPv4/IPv6 egress and successful loopback communication before launching the CLI. No production endpoint is used to test egress. All clients, CLI processes and PostgreSQL traffic stay inside the same namespace. A remote container lifetime limit bounds failure even if the host launcher dies; normal cleanup checks the exact ID and ownership label before removal. If the host launcher is forcibly killed, the remote lifetime limit stops its processes, but its stopped container may need removal using the recorded CID and verified ownership label. The shared Podman VM is never stopped by this runner.

The corpus uses the official JS SDK with explicit loopback routing, server-only queries and per-request deadlines. Raw CLI, case, wire and resource logs remain in the chosen output directory. A timeout is a harness failure, never an expected server rejection. The `runCorpus` and `readPersistence` exports accept a loopback target so a later fireemu adapter can run the same cases without changing expectations; no adapter is supplied here.

## Scope and remaining gaps

Cases include empty reads, scalar writes/reads, nulls, invalid inputs, relationships, explicit ordering, unauthenticated access denial, unknown operations, updates/deletes and transaction rollback with readback. The small three-factor matrix covers both backends, query/mutation and valid/missing/null variables. PGlite export/import must restore the seeded row; external PostgreSQL export must be refused as the pinned CLI specifies. Those lifecycle outcomes are deliberately distinct.

Authenticated identities, App Check, concurrent isolation, schema migration, remote resolvers, embeddings, SDK generation and production management APIs are outside this fixture slice. Official-emulator observations do not prove production authorization, transaction or error semantics. No production project, credentials or captured production data are used.

Unit tests for the runner's decision logic use only Node built-ins:

```sh
node --test conformance/dataconnect/run.test.mjs
```
