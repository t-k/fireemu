//! Regenerates `crates/ftd-proto-firestore/src/generated/` from the vendored protos
//! (ADR-008). A normal build never runs this; the generated files are checked in and
//! `check` mode fails CI on drift.
//!
//! ```text
//! proto-gen generate   # needs protoc on PATH (or PROTOC)
//! proto-gen check
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const PROTO_ROOT: &str = "crates/ftd-proto-firestore/proto";
const OUT_DIR: &str = "crates/ftd-proto-firestore/src/generated";
const FILES: &[&str] = &[
    "google/firestore/v1/firestore.proto",
    "google/firestore/v1/pipeline.proto",
    "google/firestore/v1/explain_stats.proto",
];

fn generate(out: &Path) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let files: Vec<PathBuf> = FILES
        .iter()
        .map(|f| Path::new(PROTO_ROOT).join(f))
        .collect();
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(false)
        .out_dir(out)
        .emit_rerun_if_changed(false)
        .compile_protos(&files, &[Path::new(PROTO_ROOT)])
        .map_err(|e| format!("protoc failed: {e}"))?;
    // Stamp the upstream commit so that drift between protos and generated code is visible.
    let commit = fs::read_to_string(Path::new(PROTO_ROOT).join("UPSTREAM_COMMIT"))
        .map_err(|e| e.to_string())?;
    fs::write(out.join("UPSTREAM_COMMIT"), format!("{}\n", commit.trim()))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn read_dir_sorted(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        fs::read(e.path()).unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries
}

fn main() -> ExitCode {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "check".to_owned());
    let out = Path::new(OUT_DIR);
    match mode.as_str() {
        "generate" => match generate(out) {
            Ok(()) => {
                println!("generated into {OUT_DIR}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        "check" => {
            let tmp = std::env::temp_dir().join(format!("ftd-proto-gen-{}", std::process::id()));
            let outcome = generate(&tmp).and_then(|()| {
                let expected = read_dir_sorted(&tmp);
                let actual = read_dir_sorted(out);
                if expected == actual {
                    Ok(())
                } else {
                    Err("generated protobuf code differs from the vendored protos; run `cargo run -p proto-gen -- generate`".to_owned())
                }
            });
            let _ = fs::remove_dir_all(&tmp);
            match outcome {
                Ok(()) => {
                    println!("generated protobuf code is up to date");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("error: unknown mode {other}; use generate or check");
            ExitCode::FAILURE
        }
    }
}
