//! Measures an import in a fresh process. Run under an external hard memory limit.

use std::{fs, hint::black_box, time::Instant};

use fireemu_adapter_database::rest::{prepare_import, Database, RestOptions};
use fireemu_core_database::{Content, Node, Priority};

fn memory() -> String {
    fs::read_to_string("/proc/self/status").map_or_else(
        |_| "RSS unavailable: use a platform process meter".to_owned(),
        |status| {
            status
                .lines()
                .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                .collect::<Vec<_>>()
                .join("; ")
        },
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || !matches!(args[0].as_str(), "import" | "export") {
        return Err("expected import|export FIXTURE (maximum 80 MiB)".into());
    }
    let bytes = fs::metadata(&args[1])?.len();
    if bytes == 0 || bytes > 80 * 1024 * 1024 {
        return Err("fixture size must be between 1 byte and 80 MiB".into());
    }
    let clock = Instant::now();
    eprintln!("before: {}", memory());
    let text = fs::read_to_string(&args[1])?;
    let options = RestOptions::default();
    let prepared = prepare_import("demo-footprint", text, &options.limits)?;
    eprintln!("prepared: {}", memory());
    let mut database = Database::new(options, 0);
    database.install_import(prepared, 0)?;
    eprintln!("installed: {}", memory());
    println!(
        "input_bytes={bytes} node_bytes={} content_bytes={} priority_bytes={} elapsed_ms={}",
        size_of::<Node>(),
        size_of::<Content>(),
        size_of::<Priority>(),
        clock.elapsed().as_millis()
    );
    if args[0] == "export" {
        for (_, text) in database.export_texts() {
            println!("{text}");
        }
        eprintln!("exported: {}", memory());
    }
    black_box(&database);
    drop(database);
    eprintln!("dropped: {}", memory());
    Ok(())
}
