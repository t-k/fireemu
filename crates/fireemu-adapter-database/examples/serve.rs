//! Serves the Realtime Database REST API alone, for side-by-side comparison with the official
//! emulator: `cargo run -p fireemu-adapter-database --example serve -- 127.0.0.1:9000`.

use std::sync::{Arc, Mutex};

use fireemu_adapter_database::rest::{Database, RestOptions};
use fireemu_adapter_database::server::{serve, ServerConfig};

#[tokio::main]
async fn main() {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9000".to_owned());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .unwrap_or_else(|err| panic!("cannot listen on {address}: {err}"));
    println!("listening on {address}");
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 0)));
    serve(listener, database, ServerConfig::default()).await;
}
