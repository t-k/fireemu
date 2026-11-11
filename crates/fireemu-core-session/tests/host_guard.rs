//! The DNS-rebinding `Host` guard every product HTTP listener applies.
//!
//! A page on a name its owner controls (`evil.example`) can re-point that name at 127.0.0.1
//! after it loaded; the browser then treats requests to the emulator as same-origin and sends
//! no `Origin`. The only thing that still gives such a request away is its `Host`, which names
//! the attacker's domain. The guard admits only names an attacker cannot serve a page from.

use fireemu_core_session::host_guard::{
    admits, default_names, default_suffixes, AllowedHost, HostPolicy, RefusalLog, DOCS_URL,
};
use proptest::prelude::*;

fn policy(entries: &[&str], single_label: bool) -> HostPolicy {
    let entries = entries
        .iter()
        .map(|entry| AllowedHost::parse(entry).unwrap_or_else(|e| panic!("{entry}: {e}")))
        .collect();
    HostPolicy::new(entries, single_label)
}

fn one(policy: &HostPolicy, host: &str) -> bool {
    admits(policy, false, [host.as_bytes()]).is_ok()
}

#[test]
fn loopback_names_and_ip_literals_are_admitted_by_default() {
    let default = HostPolicy::default();
    for host in [
        "localhost",
        "LOCALHOST:9199",
        "localhost.:9199",
        "ns.localhost:9000",
        "demo-proj.LocalHost",
        "127.0.0.1:9199",
        "127.0.0.2",
        "[::1]:9199",
        "[::1]",
        "10.0.2.2:9099",
        "192.168.1.10:8080",
        "0.0.0.0:9199",
        "[fd00::1]:8080",
        "[::ffff:127.0.0.1]:8080",
        "host.docker.internal:9199",
        "HOST.CONTAINERS.INTERNAL:8080",
        "gateway.docker.internal",
        "host.lima.internal:9199",
        "host.orb.internal",
        "8080-firebase-demo-1234.cluster-abc.cloudworkstations.dev",
        "demo-proj-default-rtdb.firebaseio.com",
        "demo-proj-default-rtdb.europe-west1.firebasedatabase.app:9000",
    ] {
        assert!(one(&default, host), "{host}");
    }
}

#[test]
fn a_public_name_and_malformed_authorities_are_refused_by_default() {
    let default = HostPolicy::default();
    for host in [
        "evil.example",
        "evil.example:9199",
        "evil.example.:9199",
        "127.0.0.1.evil.example",
        "localhost.evil.example",
        "evil-localhost",
        "localhostx",
        "firebaseio.com.evil.example",
        "evilfirebaseio.com",
        "internal",
        "evil.internal.example",
        "internal.evil.example",
        "evilinternal",
        "cloudworkstations.dev",
        "evilcloudworkstations.dev",
        "cloudworkstations.dev.evil.example",
        "fireemu",
        "fireemu:8080",
        "",
        ":9199",
        "localhost:",
        "localhost:65536",
        "localhost:12a",
        "localhost:+80",
        "user@localhost",
        "localhost/path",
        "local host",
        "loc\u{e4}lhost",
        "b\u{fc}cher.example",
        "[::1",
        "[::1]x",
        "::1",
        "[fe80::1%25en0]",
        "a..b",
        ".localhost",
        "localhost..",
        "-",
    ] {
        assert!(!one(&default, host), "{host:?}");
    }
}

#[test]
fn a_missing_host_is_admitted_and_a_repeated_one_refused() {
    let default = HostPolicy::default();
    assert!(admits(&default, false, std::iter::empty::<&[u8]>()).is_ok());
    assert!(admits(&default, false, [b"localhost".as_slice(), b"localhost"]).is_err());
    assert!(admits(&default, false, [b"localhost".as_slice(), b"evil.example"]).is_err());
}

#[test]
fn http2_is_not_checked_because_no_browser_speaks_cleartext_http2() {
    let default = HostPolicy::default();
    assert!(admits(&default, true, [b"evil.example".as_slice()]).is_ok());
    assert!(admits(&default, true, [b"a".as_slice(), b"b"]).is_ok());
}

#[test]
fn a_single_label_name_needs_the_non_loopback_opt_in() {
    for host in ["fireemu", "fireemu:8080", "FireEmu_1:9199", "fireemu.:8080"] {
        assert!(!one(&HostPolicy::default(), host), "{host}");
        assert!(one(&policy(&[], true), host), "{host}");
    }
    // The opt-in does not reach names with a dot.
    assert!(!one(&policy(&[], true), "evil.example"));
}

#[test]
fn allowed_hosts_match_exactly_by_suffix_or_all() {
    let exact = policy(&["emulator.ci.example"], false);
    assert!(one(&exact, "emulator.ci.example:9199"));
    assert!(one(&exact, "EMULATOR.ci.example."));
    assert!(!one(&exact, "x.emulator.ci.example"));
    assert!(!one(&exact, "ci.example"));
    assert!(!one(&exact, "emulator.ci.example.evil"));

    let suffix = policy(&[".svc.corp.example"], false);
    assert!(one(&suffix, "svc.corp.example"));
    assert!(one(&suffix, "fireemu.ns.svc.corp.example:8080"));
    assert!(!one(&suffix, "evilsvc.corp.example"));
    assert!(!one(&suffix, "corp.example"));

    let all = policy(&["*"], false);
    for host in ["evil.example", "fireemu", "a.b.c:1"] {
        assert!(one(&all, host), "{host}");
    }
    // "*" still refuses what is not an authority at all.
    assert!(!one(&all, "user@evil.example"));
    assert!(!one(&all, "evil.example:99999"));
}

#[test]
fn allowed_host_entries_are_validated() {
    for entry in [
        "*",
        "fireemu",
        "host.example",
        ".example.com",
        "MiXed.Example",
        "a_b.c",
        "trailing.dot.",
    ] {
        assert!(AllowedHost::parse(entry).is_ok(), "{entry}");
    }
    for entry in [
        "",
        ".",
        "..x",
        "*.example.com",
        "fireemu:8080",
        "http://fireemu",
        "fire emu",
        "b\u{fc}cher.example",
        "a..b",
        "[::1]",
        "**",
        "user@host",
    ] {
        assert!(AllowedHost::parse(entry).is_err(), "{entry:?}");
    }
    assert_eq!(AllowedHost::parse("*").unwrap().to_string(), "*");
    assert_eq!(
        AllowedHost::parse("Trailing.Dot.").unwrap().to_string(),
        "trailing.dot"
    );
}

#[test]
fn the_refusal_names_the_host_and_the_setting() {
    let refusal = admits(
        &HostPolicy::default(),
        false,
        [b"Evil.Example:9199".as_slice()],
    )
    .expect_err("refused");
    let message = refusal.message();
    assert!(message.contains("\"evil.example\""), "{message}");
    assert!(message.contains("network.allowedHosts"), "{message}");
    // A malformed value is never echoed back.
    let message = admits(&HostPolicy::default(), false, [b"<script>".as_slice()])
        .expect_err("refused")
        .message();
    assert!(!message.contains("<script>"), "{message}");
    assert!(message.contains("network.allowedHosts"), "{message}");
}

/// The PICT table (docs.local/pict/host-guard, 2-way over host shape x opt-in x allowlist x
/// surface x profile) evaluated against an oracle written independently of the guard. Surface
/// and profile change nothing but the HTTP version (the h2 surfaces are not checked).
#[test]
fn the_pairwise_table_matches_the_oracle() {
    let table = include_str!("data/host_guard_pict.tsv");
    let mut rows = 0;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [shape, opt_in, allowlist, surface, _profile] = fields[..] else {
            panic!("bad row {line:?}");
        };
        let entries: &[&str] = match allowlist {
            "empty" => &[],
            "exact" => &["emulator.ci.example"],
            "suffix" => &[".ci.example"],
            "star" => &["*"],
            other => panic!("{other}"),
        };
        let single_label = opt_in == "on";
        let policy = policy(entries, single_label);
        let http2 = surface.ends_with("-h2");
        let values: Vec<&[u8]> = match shape {
            "missing" => vec![],
            "duplicate" => vec![b"localhost:9199", b"localhost:9199"],
            "localhost" => vec![b"localhost:9199"],
            "localhost-upper" => vec![b"LocalHost:9199"],
            "ns-localhost" => vec![b"demo.localhost:9000"],
            "loopback-v4" => vec![b"127.0.0.1:9199"],
            "loopback-v6" => vec![b"[::1]:9199"],
            "android-10-0-2-2" => vec![b"10.0.2.2:9099"],
            "lan-v4" => vec![b"192.168.1.10:8080"],
            "lan-v6" => vec![b"[fd00::5]:8080"],
            "docker-internal" => vec![b"host.docker.internal:9199"],
            "containers-internal" => vec![b"host.containers.internal:9199"],
            "single-label" => vec![b"fireemu:9199"],
            "single-label-trailing-dot" => vec![b"fireemu.:9199"],
            "public-name" => vec![b"evil.example:9199"],
            "public-name-trailing-dot" => vec![b"evil.example.:9199"],
            "allowlisted-exact" => vec![b"emulator.ci.example:9199"],
            "allowlisted-sub" => vec![b"x.ci.example:9199"],
            "firebaseio-ns" => vec![b"demo-default-rtdb.firebaseio.com:9000"],
            "bad-port" => vec![b"localhost:70000"],
            "non-ascii" => vec!["b\u{fc}cher.example".as_bytes()],
            "userinfo" => vec![b"user@localhost:9199"],
            "empty" => vec![b""],
            other => panic!("{other}"),
        };
        let any = allowlist == "star";
        let expected = http2
            || match shape {
                "missing"
                | "localhost"
                | "localhost-upper"
                | "ns-localhost"
                | "loopback-v4"
                | "loopback-v6"
                | "android-10-0-2-2"
                | "lan-v4"
                | "lan-v6"
                | "docker-internal"
                | "containers-internal"
                | "firebaseio-ns" => true,
                "duplicate" | "bad-port" | "non-ascii" | "userinfo" | "empty" => false,
                "single-label" | "single-label-trailing-dot" => single_label || any,
                "public-name" | "public-name-trailing-dot" => any,
                "allowlisted-exact" => matches!(allowlist, "exact" | "suffix" | "star"),
                "allowlisted-sub" => matches!(allowlist, "suffix" | "star"),
                other => panic!("{other}"),
            };
        assert_eq!(
            admits(&policy, http2, values.iter().copied()).is_ok(),
            expected,
            "{line}"
        );
        rows += 1;
    }
    assert!(rows > 250, "{rows}");
}

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9-]{0,10}"
}

fn public_name() -> impl Strategy<Value = String> {
    (prop::collection::vec(label(), 1..3), "[a-z]{2,6}").prop_filter_map(
        "reserved suffixes are admitted on purpose",
        |(labels, tld)| {
            let name = format!("{}.{tld}", labels.join("."));
            let reserved = [
                "localhost",
                "internal",
                "com",
                "app",
                "test",
                "local",
                "arpa",
                "dev",
            ];
            (!reserved.contains(&tld.as_str())).then_some(name)
        },
    )
}

fn port() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        any::<u16>().prop_map(|p| format!(":{p}"))
    ]
}

proptest! {
    /// Any IPv4 or bracketed IPv6 literal, with or without a port, is admitted: a page cannot
    /// be served from a name that is an address, so no rebinding attack uses one.
    #[test]
    fn ip_literals_are_admitted(v4 in any::<std::net::Ipv4Addr>(), v6 in any::<std::net::Ipv6Addr>(), port in port()) {
        let default = HostPolicy::default();
        let v4_host = format!("{v4}{port}");
        let v6_host = format!("[{v6}]{port}");
        prop_assert!(one(&default, &v4_host));
        prop_assert!(one(&default, &v6_host));
    }

    /// A multi-label public name is refused whatever its case, port or trailing dot, unless it
    /// is listed; listing it admits exactly it.
    #[test]
    fn public_names_are_refused_unless_listed(name in public_name(), port in port(), upper in any::<bool>(), dot in any::<bool>()) {
        let mut host = if upper { name.to_ascii_uppercase() } else { name.clone() };
        if dot { host.push('.'); }
        host.push_str(&port);
        prop_assert!(!one(&HostPolicy::default(), &host));
        prop_assert!(!one(&policy(&[], true), &host));
        prop_assert!(one(&policy(&[&name], false), &host));
        let listed_suffix = format!(".{name}");
        let sub = format!("sub.{host}");
        let glued = format!("x{host}");
        prop_assert!(one(&policy(&[&listed_suffix], false), &sub));
        prop_assert!(!one(&policy(&[&listed_suffix], false), &glued));
    }

    /// `localhost` and its subdomains are admitted in any case, with any port.
    #[test]
    fn localhost_names_are_admitted(sub in prop::option::of(label()), port in port(), upper in any::<bool>()) {
        let name = sub.map_or_else(|| "localhost".to_owned(), |sub| format!("{sub}.localhost"));
        let name = if upper { name.to_ascii_uppercase() } else { name };
        let host = format!("{name}{port}");
        prop_assert!(one(&HostPolicy::default(), &host));
    }

    /// A port that is not a u16 in plain digits is refused, whatever the name.
    #[test]
    fn bad_ports_are_refused(port in prop_oneof![
        (65_536u32..10_000_000).prop_map(|p| p.to_string()),
        "[0-9]{0,3}[^0-9\\]]{1,2}[0-9]{0,3}",
        Just(String::new()),
    ]) {
        let host = format!("localhost:{port}");
        prop_assert!(!one(&policy(&["*"], true), &host));
    }

    /// An entry prints as configuration spells it, normalized, and parses back to itself.
    #[test]
    fn entries_round_trip_through_their_spelling(name in public_name(), suffix in any::<bool>(), upper in any::<bool>()) {
        let spelled = if upper { name.to_ascii_uppercase() } else { name.clone() };
        let spelled = if suffix { format!(".{spelled}") } else { spelled };
        let entry = AllowedHost::parse(&spelled).unwrap();
        let printed = entry.to_string();
        prop_assert_eq!(&printed, &if suffix { format!(".{name}") } else { name });
        prop_assert_eq!(AllowedHost::parse(&printed).unwrap(), entry);
    }

    /// The decision is total: arbitrary bytes never panic, and anything admitted by default is
    /// admitted by every wider policy.
    #[test]
    fn wider_policies_admit_a_superset(bytes in prop::collection::vec(any::<u8>(), 0..40)) {
        let narrow = admits(&HostPolicy::default(), false, [bytes.as_slice()]).is_ok();
        let wide = admits(&policy(&["*"], true), false, [bytes.as_slice()]).is_ok();
        prop_assert!(!narrow || wide);
    }
}

#[test]
fn a_name_up_to_the_dns_limit_is_parsed_and_a_longer_one_refused() {
    // 63 + 1 + 63 + 1 + 63 + 1 + 51 + ".localhost" (10) = 253 bytes.
    let label = |n: usize| "a".repeat(n);
    let longest = format!(
        "{}.{}.{}.{}.localhost",
        label(63),
        label(63),
        label(63),
        label(51)
    );
    assert_eq!(longest.len(), 253);
    assert!(one(&HostPolicy::default(), &longest));
    assert!(one(&HostPolicy::default(), &format!("{longest}.:9199")));
    let too_long = format!("b{longest}");
    assert_eq!(too_long.len(), 254);
    assert!(!one(&HostPolicy::default(), &too_long));
    assert!(!one(&policy(&["*"], true), &too_long));
    assert!(AllowedHost::parse(&longest).is_ok());
    assert!(AllowedHost::parse(&too_long).is_err());
}

#[test]
fn the_refusal_body_is_the_google_rpc_error_shape() {
    let body = admits(&HostPolicy::default(), false, [b"evil.example".as_slice()])
        .expect_err("refused")
        .body();
    assert!(
        body.starts_with(
            r#"{"error":{"code":403,"message":"fireemu does not answer Host \"evil.example\": "#
        ),
        "{body}"
    );
    assert!(
        body.ends_with(r#"","status":"PERMISSION_DENIED"}}"#),
        "{body}"
    );
    // The only quotes inside the message are the escaped ones around the name.
    let message = &body[r#"{"error":{"code":403,"message":""#.len()
        ..body.len() - r#"","status":"PERMISSION_DENIED"}}"#.len()];
    assert_eq!(
        message.matches('"').count(),
        message.matches("\\\"").count(),
        "{message}"
    );
}

fn refusal(host: &str) -> fireemu_core_session::host_guard::HostRefusal {
    admits(&HostPolicy::default(), false, [host.as_bytes()]).expect_err("refused")
}

#[test]
fn the_refusal_says_where_the_setting_lives_and_links_the_docs() {
    let message = refusal("evil.example").message();
    assert!(
        message.contains("[network] section of fireemu.toml"),
        "{message}"
    );
    assert!(message.contains("fireemu.json"), "{message}");
    assert!(message.contains(DOCS_URL), "{message}");
    assert!(DOCS_URL.ends_with("/guides/ci-and-containers/#host-names-the-emulators-answer"));
    let warning = refusal("evil.example").warning();
    assert!(
        warning.starts_with("warning: refused Host \"evil.example\""),
        "{warning}"
    );
    assert!(
        warning.contains("[network] section of fireemu.toml"),
        "{warning}"
    );
    assert!(warning.contains(DOCS_URL), "{warning}");
    let malformed = refusal("user@evil").warning();
    assert!(malformed.contains("a malformed Host header"), "{malformed}");
    assert!(!malformed.contains("user@evil"), "{malformed}");
}

#[test]
fn each_refused_name_is_logged_once_up_to_a_bound() {
    let log = RefusalLog::new(2);
    let first = log.first_warning(&refusal("a.example:1")).expect("logged");
    assert!(first.contains("\"a.example\""), "{first}");
    // The same name, whatever its case or port, is not logged again.
    assert_eq!(log.first_warning(&refusal("A.EXAMPLE:2")), None);
    let malformed = log.first_warning(&refusal("x@y")).expect("logged");
    assert!(malformed.contains("malformed"), "{malformed}");
    assert_eq!(log.first_warning(&refusal("z@w")), None);
    // The bound is reached: one closing line, then silence.
    let closing = log
        .first_warning(&refusal("b.example"))
        .expect("closing line");
    assert!(closing.contains("2 Host names were refused"), "{closing}");
    assert!(closing.contains("not logged"), "{closing}");
    assert_eq!(log.first_warning(&refusal("c.example")), None);
    assert_eq!(log.first_warning(&refusal("a.example")), None);
}

#[test]
fn entries_that_turn_the_defence_off_are_warned_about() {
    assert!(HostPolicy::default().warnings().is_empty());
    assert!(policy(
        &["emulator.ci.example", ".svc.cluster.local", ".ci.example"],
        true
    )
    .warnings()
    .is_empty());
    let all = policy(&["*"], false).warnings();
    assert_eq!(all.len(), 1, "{all:?}");
    assert!(
        all[0].starts_with("warning: network.allowedHosts contains \"*\""),
        "{all:?}"
    );
    let tld = policy(&[".com", "x.example", ".Dev."], false).warnings();
    assert_eq!(tld.len(), 2, "{tld:?}");
    assert!(
        tld[0].contains("\".com\"") && tld[0].contains("top-level domain"),
        "{tld:?}"
    );
    assert!(tld[1].contains("\".dev\""), "{tld:?}");
}

/// Owner decision 2401: the special-use suffixes `.test`, `.local` and `.home.arpa` (RFC 6761,
/// RFC 6762, RFC 8375; public DNS answers none of them) and GitHub Codespaces' `.app.github.dev`
/// are admitted by default, on a label boundary only.
#[test]
fn special_use_names_and_codespaces_are_admitted_on_a_label_boundary() {
    let default = HostPolicy::default();
    for host in [
        "myapp.test",
        "api.myapp.test:8080",
        "MyApp.TEST.",
        "my-mac.local:9199",
        "MY-MAC.LOCAL.",
        "printer.home.arpa",
        "nas.lan.home.arpa:9000",
        "fluffy-space-8080.app.github.dev",
        "Fluffy-Space-9099.APP.GITHUB.DEV.:443",
    ] {
        assert!(one(&default, host), "{host}");
    }
    for host in [
        "test",
        "local",
        "home.arpa",
        "arpa",
        "app.github.dev",
        "github.dev",
        "x.github.dev",
        "evil-test",
        "eviltest",
        "evil-local",
        "evil.home-arpa",
        "evilhome.arpa",
        "x.evilapp.github.dev",
        "evil-app.github.dev",
        "local.example",
        "test.evil.example",
        "home.arpa.evil.example",
        "app.github.dev.evil.example",
        "x.app.github.dev.evil.example",
        "x.test.evil",
    ] {
        assert!(!one(&default, host), "{host}");
    }
}

/// The PICT table of the new defaults (docs.local/pict/host-allowlist-defaults, 2-way over
/// suffix x name shape x spelling x non-loopback opt-in) against an independent oracle.
#[test]
fn the_default_suffix_table_matches_the_oracle() {
    let table = include_str!("data/host_guard_defaults_pict.tsv");
    let mut rows = 0;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [suffix, shape, form, opt_in] = fields[..] else {
            panic!("bad row {line:?}");
        };
        let name = match shape {
            "subdomain" => format!("x.{suffix}"),
            "deep-subdomain" => format!("a.b.{suffix}"),
            "bare" => suffix.to_owned(),
            "glued-prefix" => format!("evil{suffix}"),
            "embedded-label" => format!("{suffix}.evil.example"),
            "hyphen-label" => format!("evil-{suffix}"),
            other => panic!("{other}"),
        };
        let host = match form {
            "plain" => name.clone(),
            "upper" => name.to_ascii_uppercase(),
            "trailing-dot" => format!("{name}."),
            "port" => format!("{name}:9199"),
            "upper-dot-port" => format!("{}.:9199", name.to_ascii_uppercase()),
            other => panic!("{other}"),
        };
        let single_label = opt_in == "on";
        let expected = match shape {
            "subdomain" | "deep-subdomain" => true,
            "embedded-label" => false,
            // Without a dot these are single-label names, admitted only with the opt-in.
            "bare" | "glued-prefix" | "hyphen-label" => single_label && !name.contains('.'),
            other => panic!("{other}"),
        };
        assert_eq!(
            one(&policy(&[], single_label), &host),
            expected,
            "{line} -> {host}"
        );
        rows += 1;
    }
    assert!(rows >= 30, "{rows}");
}

/// Spellings of the new default suffixes that are not the suffix: percent-encoding, a Unicode
/// look-alike and its punycode form, repeated dots and invalid ports are all refused.
#[test]
fn look_alikes_of_the_special_use_suffixes_are_refused() {
    let default = HostPolicy::default();
    for host in [
        "x%2Etest",
        "x.%74est",
        "x.app.github%2Edev",
        "x.te\u{17f}t",
        "x.\u{442}est",
        "x.xn--est-j2c",
        "x.app.githu\u{0432}.dev",
        "x.app.xn--githu-mvf.dev",
        "x..test",
        "x.test..",
        "x.local..:9199",
        ".test",
        "..local",
        "x.home..arpa",
        "x.test:",
        "x.test:65536",
        "x.local:9x",
        "x.app.github.dev:-1",
        "x.home.arpa:+80",
    ] {
        assert!(!one(&default, host), "{host:?}");
    }
    // The genuine spellings next to them are admitted.
    for host in [
        "x.test",
        "x.test.",
        "x.local:9199",
        "x.home.arpa:80",
        "x.app.github.dev:65535",
    ] {
        assert!(one(&default, host), "{host:?}");
    }
}

#[test]
fn the_listed_defaults_are_exactly_what_the_default_policy_admits() {
    let default = HostPolicy::default();
    assert!(!default_names().is_empty() && !default_suffixes().is_empty());
    for name in default_names() {
        assert!(one(&default, name), "{name}");
        assert!(one(&default, &name.to_ascii_uppercase()), "{name}");
    }
    for suffix in default_suffixes() {
        assert!(suffix.starts_with('.'), "{suffix}");
        assert!(one(&default, &format!("app{suffix}:3000")), "{suffix}");
        assert!(one(&default, &format!("a.b{suffix}")), "{suffix}");
        // The domain itself is not a subdomain: only `localhost` is a default name.
        let bare = &suffix[1..];
        assert_eq!(
            one(&default, bare),
            default_names().contains(&bare),
            "{suffix}"
        );
        // A look-alike that merely ends in the same letters is not under the domain.
        assert!(!one(&default, &format!("evil{bare}")), "{suffix}");
        assert!(!one(&default, &format!("{bare}.evil.example")), "{suffix}");
    }
}
