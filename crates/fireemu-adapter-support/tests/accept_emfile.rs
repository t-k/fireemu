//! A listener served through `accept_with_backoff` survives the process running out of file
//! descriptors, and answers the waiting client once descriptors are free again.
//!
//! This test lowers `RLIMIT_NOFILE` for its own process, so it lives in a test binary of its
//! own with no other test in it.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io;
use std::time::Duration;

use fireemu_adapter_support::accept::accept_with_backoff;
use rustix::io::Errno;
use rustix::process::{getrlimit, setrlimit, Resource};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

fn open_descriptors() -> u64 {
    std::fs::read_dir("/proc/self/fd").unwrap().count() as u64
}

#[tokio::test]
async fn a_listener_out_of_descriptors_waits_and_then_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async move {
        loop {
            let (mut stream, _) = accept_with_backoff("test", || listener.accept()).await?;
            stream.write_all(b"ok").await?;
        }
    });

    // The client connects before descriptors run out, without yielding to the runtime, so the
    // server has not accepted it yet: its connection waits in the backlog.
    let client = std::net::TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();

    let original = getrlimit(Resource::Nofile);
    let mut lowered = original;
    lowered.current = Some(open_descriptors() + 16);
    setrlimit(Resource::Nofile, lowered).unwrap();
    let mut filler = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => filler.push(file),
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(Errno::MFILE.raw_os_error()),
                    "{error}"
                );
                break;
            }
        }
    }

    // Every accept now fails with EMFILE.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let still_serving = !server.is_finished();

    drop(filler);
    setrlimit(Resource::Nofile, original).unwrap();
    assert!(
        still_serving,
        "the server stopped on EMFILE: {:?}",
        server.await
    );

    let mut client = TcpStream::from_std(client).unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer))
        .await
        .expect("the server answers once descriptors are free")
        .unwrap();
    assert_eq!(answer, b"ok");
    server.abort();
}
