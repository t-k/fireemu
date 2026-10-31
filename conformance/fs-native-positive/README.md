# Finite native positive function evidence

`production.json` contains 27 positive request shapes, recorded twice over native gRPC: 19 generic fields, six integer numeric fields, and 12 fields in two packed numeric requests. The 54 responses retain all typed fields and execution metadata. Journal, codec, projection and recorder-source hashes identify the private primary custody without publishing raw wire, credentials, project numbers, database identifiers or configuration. No recording commit is invented. The original 1,951-row R21 fixture and denominator are unchanged. Bit-function INTERNAL responses and the Geo SELECT-placement refusal are outside this positive fixture.

`program.json` is the production-derived structured request corpus. The pure input generator substitutes only the complete canonical database resource prefix with the existing harness's `{db}` placeholder. It retains pipeline order, arguments, options, relative collection references and the typed `n=1` seed. This is semantic input reuse, not a claim of equal REST and gRPC wire bytes.

## Existing local producer

Use one final installed binary, source commit and build custody for all eight sessions: strict/emulator × grpc/rest × rounds 1/2. No production recorder is invoked. Generate each transport input with:

```sh
node conformance/src/fs-ent-pipeline/native-positive.mjs programs grpc /absolute/local/grpc-input.json
node conformance/src/fs-ent-pipeline/native-positive.mjs programs rest /absolute/local/rest-input.json
```

For each profile, transport and round, use the existing producer command (inside the existing network-isolated, memory-capped lifecycle):

```sh
env FIREEMU_SANDBOX_LANE=fs-ent-pipeline \
  FS_QUERY_INDEX_IN="$input" FS_QUERY_INDEX_OUT="$output" FS_QUERY_INDEX_RUN="$local_run" \
  "$binary" exec --config "$profile_config" --project "$harness_project" --only firestore \
  --firestore-port 0 --http-port 0 --storage-port 0 --ui-port 0 --hub-port 0 --logging-port 0 \
  --firebase-json conformance/fs-ent-pipeline.firebase.json \
  -- node conformance/src/fs-query-index/run.mjs session-local
```

The two profile configurations are the existing `conformance/fs-ent-pipeline.fireemu.json` and `conformance/fs-ent-pipeline.emulator.fireemu.json`. The project and named database are those of the existing FS-PIPELINE harness/lane, used locally only. Root records the actual invocation context and installed-binary/source custody; this module does not launch servers or fabricate that receipt. Retain the original raw session files and the invocation receipt before daemon cleanup.

Each invocation receipt is JSON containing `sourceCommit`, `binarySha256`, `namespace` (`projects/<local-project>/databases/<local-database>`), `origin` (the actual loopback HTTP origin) and the exact hashes returned by `producerInputs(transport, profile)`: `inputSha256`, `seedSha256`, `configSha256`, `harnessSha256`, `sessionSha256`, and `driverSha256`. The input hash is over the generated file including its final newline. Bind the receipt to the actual command/config/input and environment; deriving expected hashes alone is not proof that an invocation happened.

The existing session captures resolved structured bodies for both transports, but does not capture the REST URL or native database field. The comparator checks the entire captured body against the production-derived program, and deterministically reconstructs targets with the unchanged `buildRestRequest`/`buildGrpcRequest`. Exported path/database fields are explicitly **DERIVED_FROM_BOUND_HARNESS_AND_CONTEXT**, never observed wire paths. Root's hash-bound invocation receipt and the isolated same-binary producer supply this limited producer binding. Do not represent this as full wire observation or request/response byte equality.

## Pure comparison and finite export

A manifest contains `sourceCommit`, `binarySha256`, and exactly eight `runs`. Each run names `profile`, `transport`, `round`, `namespace`, `sourceCommit`, `binarySha256`, `path`, `sha256`, `invocationPath`, and `invocationSha256`. Paths point to existing local raw session and actual invocation receipt files. The exporter hashes the installed binary and each file before comparing:

```sh
node conformance/src/fs-ent-pipeline/native-positive.mjs export-comparison \
  --binary "$binary" --manifest "$manifest" --out "$new_evidence"
```

The output is an additive `fs-ent-pipeline-native-positive-observation-v1` finite leaf. It is produced only from complete matching sessions, never from placeholders or this fixture alone. It binds the fixture/corpus/policy/manifest/session/receipt hashes and the actual binary hash. The source commit and build custody still require Root's independent producer verification. Root owns registration in `finiteContractEvidence`; no public closure is issued by this module.

The comparison requires zero native status or REST200, exact response/result counts, full result and field sets, typed values, and explicit null versus missing/extra fields. Each of the 37 fields is checked in all eight sessions (296 typed comparisons). Only complete canonical database prefixes are equated; embedded or partial prefixes remain different. Autogenerated IDs must be 20 ASCII alphanumeric characters and differ between the two rounds of each local profile/transport. This finite predicate does not establish entropy, global uniqueness or distribution.

All production/local message metadata is retained in the finite artifact and raw files. The declared metadata policy checks matching metadata keys and RFC3339 execution-time type/presence, including calendar validity; it does **not** assert absolute-time equality, a run-window clock proof, or whole-body parity. The separate same-binary time evidence and historical R21 remain responsible for their own clock/metadata obligations. The finite leaf claims value-and-shape plus the declared producer binding only.
