//! Hosting multisite listener binding and port allocation tests.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

static FORCED_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(0);
static FORCE_CONFIGURED_PORT_ONCE: AtomicBool = AtomicBool::new(false);

fn configured_port_collision_pick(addr: &str) -> std::io::Result<std::net::TcpListener> {
    let port = FORCED_EPHEMERAL_PORT.load(Ordering::Relaxed);
    if port != 0 && FORCE_CONFIGURED_PORT_ONCE.swap(false, Ordering::Relaxed) {
        std::net::TcpListener::bind(format!("127.0.0.1:{port}"))
    } else {
        kernel_pick(addr)
    }
}

fn hosting_only(addr: String, explicit: bool) -> RuntimeConfig {
    RuntimeConfig {
        hosting_addr: addr,
        hosting_addr_explicit: explicit,
        hosting: Some(vec![crate::hosting::Config::parse(
            &serde_json::json!({"public": "public"}),
            std::path::Path::new("/project"),
        )
        .unwrap()]),
        hub_addr: "127.0.0.1:0".to_owned(),
        hub_addr_explicit: true,
        logging_enabled: false,
        ..RuntimeConfig::default()
    }
}

fn multisite(mut cfg: RuntimeConfig) -> RuntimeConfig {
    cfg.hosting = Some(vec![
        crate::hosting::Config::parse(
            &serde_json::json!({"site":"demo-a","public":"a"}),
            std::path::Path::new("/project"),
        )
        .unwrap(),
        crate::hosting::Config::parse(
            &serde_json::json!({"site":"demo-b","public":"b"}),
            std::path::Path::new("/project"),
        )
        .unwrap(),
    ]);
    cfg
}

// firebase-tools 15.28.2 searches upward from the default Hosting port (5000 is often
// taken on macOS) and never lands on 5001, the Functions default.
#[tokio::test]
async fn a_busy_default_hosting_port_moves_up_and_skips_the_functions_port() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let cfg = hosting_only(format!("127.0.0.1:{port}"), false);
    let only = Selection::parse("hosting").unwrap();
    let listeners = bind_listeners(&cfg, &only).await.unwrap();
    let bound = listeners
        .hosting
        .first()
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_ne!(bound, port);
    assert!(bound > port);
    let avoided = bind_relocatable_listener(
        &format!("127.0.0.1:{}", 5000),
        false,
        "Hosting emulator",
        &[5000, 5001],
    )
    .await
    .unwrap();
    assert!(avoided.local_addr().unwrap().port() > 5001);
}

// Holding 5000 (or finding it already held, as macOS AirPlay does) forces the search.
#[tokio::test]
async fn the_default_hosting_search_never_takes_5001() {
    let _held = std::net::TcpListener::bind("127.0.0.1:5000");
    let cfg = hosting_only("127.0.0.1:5000".to_owned(), false);
    let only = Selection::parse("hosting").unwrap();
    let listener = bind_hosting(&cfg, &only).await.unwrap().remove(0);
    assert_ne!(listener.local_addr().unwrap().port(), 5000);
    assert_ne!(listener.local_addr().unwrap().port(), 5001);
}

#[tokio::test]
async fn hosting_left_out_of_only_binds_nothing_even_when_configured() {
    let cfg = hosting_only("127.0.0.1:0".to_owned(), false);
    let only = Selection::parse("auth").unwrap();
    assert!(bind_hosting(&cfg, &only).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_configured_hosting_port_is_never_moved() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let cfg = hosting_only(format!("127.0.0.1:{port}"), true);
    let only = Selection::parse("hosting").unwrap();
    let error = bind_listeners(&cfg, &only).await.err().unwrap();
    assert!(error.contains("bind"), "{error}");
}

#[tokio::test]
async fn a_secondary_site_port_is_based_on_the_relocated_primary_port() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let requested = busy.local_addr().unwrap().port();
    let cfg = multisite(hosting_only(format!("127.0.0.1:{requested}"), false));
    let listeners = bind_hosting(&cfg, &Selection::parse("hosting").unwrap())
        .await
        .unwrap();
    let primary = listeners[0].local_addr().unwrap().port();
    let secondary = listeners[1].local_addr().unwrap().port();
    assert_ne!(primary, requested);
    assert_eq!(secondary, primary + 5);
}

#[tokio::test]
async fn secondary_port_zero_skips_a_configured_service_port() {
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured = free.local_addr().unwrap().port();
    drop(free);
    let mut cfg = multisite(hosting_only("127.0.0.1:0".to_owned(), false));
    cfg.functions_addr = format!("127.0.0.1:{configured}");
    FORCED_EPHEMERAL_PORT.store(configured, Ordering::Relaxed);
    FORCE_CONFIGURED_PORT_ONCE.store(true, Ordering::Relaxed);
    let listeners = bind_hosting_with(
        &cfg,
        &Selection::parse("hosting").unwrap(),
        configured_port_collision_pick,
    )
    .await
    .unwrap();
    assert!(!FORCE_CONFIGURED_PORT_ONCE.load(Ordering::Relaxed));
    assert_ne!(listeners[1].local_addr().unwrap().port(), configured);
    drop(listeners);
    assert!(std::net::TcpListener::bind(format!("127.0.0.1:{configured}")).is_ok());
    FORCED_EPHEMERAL_PORT.store(0, Ordering::Relaxed);
}

#[tokio::test]
async fn an_overflowing_secondary_port_releases_the_primary_listener() {
    let primary_port = 65_534;
    let cfg = multisite(hosting_only(format!("127.0.0.1:{primary_port}"), true));
    let result = bind_hosting(&cfg, &Selection::parse("hosting").unwrap()).await;
    assert!(result
        .unwrap_err()
        .contains("no available Hosting site port"));
    assert!(std::net::TcpListener::bind(format!("127.0.0.1:{primary_port}")).is_ok());
}

#[tokio::test]
async fn a_secondary_site_skips_a_configured_service_port() {
    let mut cfg = multisite(hosting_only("127.0.0.1:49000".to_owned(), true));
    cfg.firestore_addr = "127.0.0.1:49005".to_owned();
    let listeners = bind_hosting(&cfg, &Selection::parse("hosting").unwrap())
        .await
        .unwrap();
    assert_eq!(listeners[0].local_addr().unwrap().port(), 49000);
    assert_eq!(listeners[1].local_addr().unwrap().port(), 49006);
}

#[tokio::test]
async fn a_busy_secondary_site_port_retries_the_next_candidate() {
    let _busy = std::net::TcpListener::bind("127.0.0.1:65534").unwrap();
    let cfg = multisite(hosting_only("127.0.0.1:65529".to_owned(), true));
    let listeners = bind_hosting(&cfg, &Selection::parse("hosting").unwrap())
        .await
        .unwrap();
    assert_eq!(listeners[1].local_addr().unwrap().port(), 65535);
}

#[tokio::test]
async fn a_busy_maximum_secondary_site_port_preserves_the_bind_error() {
    let _busy = std::net::TcpListener::bind("127.0.0.1:65535").unwrap();
    let bind_error = std::net::TcpListener::bind("127.0.0.1:65535").unwrap_err();
    assert_eq!(bind_error.kind(), std::io::ErrorKind::AddrInUse);
    let cfg = multisite(hosting_only("127.0.0.1:65530".to_owned(), true));
    let error = bind_hosting(&cfg, &Selection::parse("hosting").unwrap())
        .await
        .unwrap_err();
    assert_eq!(error, format!("bind 127.0.0.1:65535: {bind_error}"));
    assert!(std::net::TcpListener::bind("127.0.0.1:65530").is_ok());
}

#[test]
fn hub_reserved_ports_belong_only_to_multisite_hosting() {
    let primary = "127.0.0.1:5000".parse().unwrap();
    let secondary = "127.0.0.1:5005".parse().unwrap();
    for sites in [vec![], vec![primary], vec![primary, secondary]] {
        let addrs = BoundAddrs {
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            hosting: Some(primary),
            hosting_sites: sites.clone(),
            eventarc: None,
            tasks: None,
            pubsub: None,
            database: None,
            hub: Some("127.0.0.1:4400".parse().unwrap()),
            ui: None,
            logging: None,
            control: "127.0.0.1:9000".parse().unwrap(),
        };
        let entries = hub_emulators(&addrs);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "hosting");
        assert_eq!(entries[0].addr, primary);
        assert_eq!(
            entries[0].reserved_ports,
            (sites.len() > 1).then(|| vec![5005])
        );
        assert_eq!(entries[1].name, "hub");
        assert_eq!(entries[1].reserved_ports, None);
    }
}
