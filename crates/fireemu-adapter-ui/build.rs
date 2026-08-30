//! Copies the built single-page app (`ui/dist`, produced by `pnpm -C ui build`) into
//! `OUT_DIR/ui` for `include_dir!`. Without a build the directory holds one placeholder page
//! that explains how to produce it, so `cargo build` never needs Node.

use std::fs;
use std::path::{Path, PathBuf};

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>fireemu UI (not bundled)</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 48rem; margin: 4rem auto; padding: 0 1rem; color: #1f2937; }
code, pre { background: #f3f4f6; padding: 0.15rem 0.35rem; border-radius: 0.25rem; }
pre { padding: 0.75rem; overflow-x: auto; }
</style>
</head>
<body>
<h1>fireemu UI is not bundled in this build</h1>
<p>This binary was compiled without the single-page app. Build it and compile again:</p>
<pre>pnpm -C ui install
pnpm -C ui build
cargo build --release -p fireemu</pre>
<p>The UI API under <code>/ui/api/</code> is available regardless; <code>GET /ui/api/config</code> describes this runtime.</p>
</body>
</html>
"#;

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dist = manifest_dir.join("../../ui/dist");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("ui");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", dist.display());
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).expect("create OUT_DIR/ui");
    let bundled = dist.join("index.html").is_file();
    if bundled {
        copy_dir(&dist, &out).expect("copy ui/dist");
    } else {
        fs::write(out.join("index.html"), PLACEHOLDER).expect("write placeholder");
    }
    fs::write(
        out.join("fireemu-ui.json"),
        format!("{{\"bundled\": {bundled}}}\n"),
    )
    .expect("write fireemu-ui.json");
}
