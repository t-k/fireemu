//! Hosting starts through the shipped CLI and consumes the shared HTTP fixture corpus.

mod scratch;
use scratch::Scratch;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.0.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() { return; }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn hosting_cli_serves_shared_fixture_and_withdraws_readiness_on_shutdown() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures/hosting");
    let corpus: serde_json::Value = serde_json::from_slice(&std::fs::read(fixture.join("cases.json")).unwrap()).unwrap();
    let dir = Scratch::new("hosting", "cli");
    let mut hosting = corpus["configs"]["default"].clone();
    hosting["public"] = fixture.join("public").to_string_lossy().to_string().into();
    let firebase = serde_json::json!({"hosting":hosting,"emulators":{"hosting":{"port":0},"ui":{"enabled":false},"logging":{"port":0},"hub":{"port":0}}});
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    let ready = dir.join("ready.json");
    let mut child = OwnedChild(Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["up", "--only", "hosting", "--project", "demo-hosting", "--firebase-json"])
        .arg(dir.join("firebase.json"))
        .arg("--ready-file").arg(&ready).args(["--owner-stdin", "--quiet"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    let descriptor = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr=String::new(); child.0.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
            panic!("Hosting must start through --only hosting; {status}: {stderr}");
        }
        if let Ok(bytes) = std::fs::read(&ready) {
            break serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        }
        assert!(Instant::now()<deadline,"Hosting readiness deadline");
        std::thread::sleep(Duration::from_millis(20));
    };
    let address=descriptor["hostingUrl"].as_str().unwrap().strip_prefix("http://").unwrap().trim_end_matches('/');
    let case=corpus["cases"].as_array().unwrap().iter().find(|case|case["id"]=="static").unwrap();
    let mut stream=TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream,"GET {} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",case["path"].as_str().unwrap()).unwrap();
    let mut reply=String::new();stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"),"{reply}");
    assert!(reply.ends_with(&std::fs::read_to_string(fixture.join("public/data.json")).unwrap()),"{reply}");
    drop(child);
    assert!(!ready.exists(),"shutdown withdraws the owned readiness descriptor");
    assert!(TcpStream::connect(address).is_err(),"shutdown releases the Hosting listener");
}
