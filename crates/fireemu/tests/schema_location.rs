//! Generated schema locations are hosted by the repository owner; old configs still load.
use std::process::{Command, Stdio};

#[test]
fn init_uses_repository_schema_and_capabilities_accepts_old_and_new_locations() {
    let dir = std::env::temp_dir().join(format!("fireemu-schema-location-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let result = std::panic::catch_unwind(|| {
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .current_dir(&dir)
            .args(["init", "--yes"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let generated = std::fs::read_to_string(dir.join("fireemu.toml")).unwrap();
        let canonical =
            "https://raw.githubusercontent.com/t-k/fireemu/main/spec/config/fireemu.schema.json";
        assert!(generated.starts_with(&format!("#:schema {canonical}\n")));
        for schema in [
            canonical,
            "https://fireemu.dev/spec/config/fireemu.schema.json",
        ] {
            let path = dir.join("explicit.json");
            std::fs::write(
                &path,
                serde_json::json!({"schemaVersion":1,"$schema":schema}).to_string(),
            )
            .unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
                .current_dir(&dir)
                .args(["capabilities", "--config"])
                .arg(path)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        }
    });
    std::fs::remove_dir_all(&dir).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
