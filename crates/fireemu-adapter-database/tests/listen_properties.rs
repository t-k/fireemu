//! Model-based property tests of realtime listens: a client that applies every pushed data
//! message to its cache, the way the SDKs do, always ends up with what the server holds.

use std::collections::BTreeMap;

use fireemu_adapter_database::json_parse::parse;
use fireemu_adapter_database::json_text::{render, Style};
use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, RestOptions};
use fireemu_core_database::{Json, Number};
use proptest::prelude::*;

const NOW: i64 = 1_792_417_166_902;

fn open(db: &mut Database) -> Session {
    match db.open_realtime("/.ws?v=5&ns=prop", Some("127.0.0.1:9000"), NOW) {
        Ok(Opened::Session(session, _)) => session,
        other => panic!("{other:?}"),
    }
}

fn frame(r: u64, action: &str, body: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#)
}

/// A write by another connection.
#[derive(Debug, Clone)]
enum Write {
    Put(String, Json),
    Merge(String, Vec<(String, Json)>),
}

fn value() -> impl Strategy<Value = Json> {
    prop_oneof![
        Just(Json::Null),
        (0i64..3).prop_map(Json::int),
        (proptest::option::of(0i64..3), proptest::option::of(0i64..3)).prop_map(|(x, y)| {
            let mut map = BTreeMap::new();
            if let Some(x) = x {
                map.insert("x".to_owned(), Json::int(x));
            }
            if let Some(y) = y {
                map.insert("y".to_owned(), Json::int(y));
            }
            if map.is_empty() {
                Json::Null
            } else {
                Json::Object(map)
            }
        }),
    ]
}

fn child() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "c", "d"]).prop_map(str::to_owned)
}

fn path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/s".to_owned()),
        child().prop_map(|k| format!("/s/{k}")),
        (child(), prop::sample::select(vec!["x", "y"])).prop_map(|(k, l)| format!("/s/{k}/{l}")),
    ]
}

fn write() -> impl Strategy<Value = Write> {
    let entries = prop_oneof![
        // Distinct children of the base.
        prop::collection::vec((child(), value()), 1..4),
        // Distinct grandchildren `k/x`.
        prop::collection::vec(
            (child(), value()).prop_map(|(k, v)| (format!("{k}/x"), v)),
            1..4
        ),
    ]
    .prop_map(|entries| {
        let mut seen = Vec::new();
        entries
            .into_iter()
            .filter(|(k, _)| {
                let fresh = !seen.contains(k);
                seen.push(k.clone());
                fresh
            })
            .collect::<Vec<_>>()
    });
    prop_oneof![
        3 => (path(), value()).prop_map(|(p, v)| Write::Put(p, v)),
        2 => (prop::sample::select(vec!["/s", "/"]), entries).prop_map(|(base, entries)| {
            let entries = if base == "/" {
                entries.into_iter().map(|(k, v)| (format!("s/{k}"), v)).collect()
            } else {
                entries
            };
            Write::Merge(base.to_owned(), entries)
        }),
    ]
}

fn write_frame(r: u64, write: &Write) -> String {
    match write {
        Write::Put(path, value) => frame(
            r,
            "p",
            &format!(r#"{{"p":"{path}","d":{}}}"#, render(value, Style::Compact)),
        ),
        Write::Merge(base, entries) => {
            let members: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!(r#""{k}":{}"#, render(v, Style::Compact)))
                .collect();
            frame(
                r,
                "m",
                &format!(r#"{{"p":"{base}","d":{{{}}}}}"#, members.join(",")),
            )
        }
    }
}

/// Sets `value` at `keys` below `tree`, pruning what becomes empty.
fn set_at(tree: &mut Json, keys: &[String], value: Json) {
    let Some((first, rest)) = keys.split_first() else {
        *tree = value;
        return;
    };
    if !matches!(tree, Json::Object(_)) {
        // Null below a leaf leaves it, as the SDK's leaf nodes ignore it.
        if value == Json::Null {
            return;
        }
        *tree = Json::Object(BTreeMap::new());
    }
    let Json::Object(map) = tree else {
        unreachable!()
    };
    let mut child = map.remove(first).unwrap_or(Json::Null);
    set_at(&mut child, rest, value);
    if child != Json::Null {
        map.insert(first.clone(), child);
    }
    if map.is_empty() {
        *tree = Json::Null;
    }
}

fn keys(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A client's cache of one listen at `location`, fed the pushed messages.
struct Client {
    location: Vec<String>,
    cache: Json,
}

impl Client {
    fn apply(&mut self, message: &str) {
        let Ok(Json::Object(envelope)) = parse(message) else {
            panic!("{message}")
        };
        let Some(Json::Object(data)) = envelope.get("d") else {
            panic!("{message}")
        };
        let (Some(Json::Object(body)), Some(Json::String(action))) = (data.get("b"), data.get("a"))
        else {
            panic!("{message}")
        };
        let Some(Json::String(path)) = body.get("p") else {
            panic!("{message}")
        };
        let at = keys(path);
        assert!(
            at.starts_with(&self.location),
            "{message} outside {:?}",
            self.location
        );
        let relative = at[self.location.len()..].to_vec();
        let value = body.get("d").cloned().unwrap_or(Json::Null);
        match action.as_str() {
            "d" => set_at(&mut self.cache, &relative, value),
            "m" => {
                let Json::Object(entries) = value else {
                    panic!("{message}")
                };
                for (key, entry) in entries {
                    let mut target = relative.clone();
                    target.extend(keys(&key));
                    set_at(&mut self.cache, &target, entry);
                }
            }
            other => panic!("action {other} in {message}"),
        }
    }
}

/// A window the client keeps: the query applied to its cache, as the SDK filters it.
#[derive(Debug, Clone)]
enum Window {
    First(usize),
    Last(usize),
    Range(&'static str, &'static str),
    /// `orderByChild("x")` with a limit to the first `n`.
    ChildFirst(usize),
}

impl Window {
    fn wire(&self) -> String {
        match self {
            Self::First(n) => format!(r#"{{"i":".key","l":{n},"vf":"l"}}"#),
            Self::Last(n) => format!(r#"{{"i":".key","l":{n},"vf":"r"}}"#),
            Self::Range(start, end) => format!(r#"{{"i":".key","sp":"{start}","ep":"{end}"}}"#),
            Self::ChildFirst(n) => format!(r#"{{"i":"x","l":{n},"vf":"l"}}"#),
        }
    }

    fn trim(&self, cache: &Json) -> Json {
        let Json::Object(map) = cache else {
            return Json::Null;
        };
        let kept: BTreeMap<String, Json> = match self {
            Self::First(n) => map
                .iter()
                .take(*n)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            Self::Last(n) => map
                .iter()
                .rev()
                .take(*n)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            Self::Range(start, end) => map
                .iter()
                .filter(|(k, _)| k.as_str() >= *start && k.as_str() <= *end)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            Self::ChildFirst(n) => {
                // Children without `x` first, then numbers, then objects, each by key.
                let mut sorted: Vec<(&String, &Json)> = map.iter().collect();
                sorted.sort_by_key(|(k, v)| {
                    let x = match v {
                        Json::Object(child) => child.get("x"),
                        _ => None,
                    };
                    let rank = match x {
                        None | Some(Json::Null) => (0, 0),
                        Some(Json::Number(Number::Int(x))) => (1, *x),
                        Some(_) => (2, 0),
                    };
                    (rank, (*k).clone())
                });
                sorted
                    .into_iter()
                    .take(*n)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }
        };
        if kept.is_empty() {
            Json::Null
        } else {
            Json::Object(kept)
        }
    }
}

fn window() -> impl Strategy<Value = Window> {
    prop_oneof![
        (1usize..4).prop_map(Window::First),
        (1usize..4).prop_map(Window::Last),
        Just(Window::Range("b", "c")),
        (1usize..4).prop_map(Window::ChildFirst),
    ]
}

/// What a `g` answers at `location` (with `q` for a window), `{}` read as nothing.
fn server(db: &mut Database, reader: &mut Session, location: &str, query: Option<&str>) -> Json {
    let q = query.map_or_else(String::new, |q| format!(r#","q":{q}"#));
    let replies = reader
        .receive(
            db,
            &frame(1, "g", &format!(r#"{{"p":"{location}"{q}}}"#)),
            NOW,
        )
        .replies;
    let Ok(Json::Object(envelope)) = parse(&replies[0]) else {
        panic!("{replies:?}")
    };
    let Some(Json::Object(data)) = envelope.get("d") else {
        panic!("{replies:?}")
    };
    let Some(Json::Object(body)) = data.get("b") else {
        panic!("{replies:?}")
    };
    match body.get("d") {
        Some(Json::Object(map)) if map.is_empty() => Json::Null,
        Some(value) => value.clone(),
        None => Json::Null,
    }
}

fn initial() -> impl Strategy<Value = Json> {
    prop::collection::btree_map(child(), value(), 0..4).prop_map(|map| {
        let map: BTreeMap<String, Json> =
            map.into_iter().filter(|(_, v)| *v != Json::Null).collect();
        if map.is_empty() {
            Json::Null
        } else {
            Json::Object(map)
        }
    })
}

fn pushes_for(db: &mut Database, client: u64) -> Vec<String> {
    db.drain_pushes()
        .into_iter()
        .filter(|(to, _)| *to == client)
        .map(|(_, message)| message)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn a_plain_listener_tracks_the_location(
        start in initial(),
        location in prop::sample::select(vec!["/s", "/s/a", "/s/a/x"]),
        writes in prop::collection::vec(write(), 1..12),
    ) {
        let mut db = Database::new(RestOptions::default(), 1);
        let mut listener = open(&mut db);
        let mut writer = open(&mut db);
        let mut reader = open(&mut db);
        writer.receive(&mut db, &frame(1, "p", &format!(r#"{{"p":"/s","d":{}}}"#, render(&start, Style::Compact))), NOW);
        let mut client = Client { location: keys(location), cache: Json::Null };
        for message in listener.receive(&mut db, &frame(1, "q", &format!(r#"{{"p":"{location}","h":""}}"#)), NOW).replies {
            if message.contains(r#""a":"d""#) {
                client.apply(&message);
            }
        }
        for (r, write) in writes.iter().enumerate() {
            writer.receive(&mut db, &write_frame(r as u64 + 2, write), NOW);
            for message in pushes_for(&mut db, listener.client()) {
                client.apply(&message);
            }
            let held = server(&mut db, &mut reader, location, None);
            prop_assert_eq!(&client.cache, &held, "after {:?}", write);
        }
    }

    #[test]
    fn a_window_listener_tracks_its_window(
        start in initial(),
        window in window(),
        writes in prop::collection::vec(write(), 1..12),
    ) {
        let mut db = Database::new(RestOptions::default(), 1);
        db.declare_index("prop", &fireemu_core_database::Path::from_keys(["s"]), "x");
        let mut listener = open(&mut db);
        let mut writer = open(&mut db);
        let mut reader = open(&mut db);
        writer.receive(&mut db, &frame(1, "p", &format!(r#"{{"p":"/s","d":{}}}"#, render(&start, Style::Compact))), NOW);
        let q = window.wire();
        let mut client = Client { location: keys("/s"), cache: Json::Null };
        for message in listener.receive(&mut db, &frame(1, "q", &format!(r#"{{"p":"/s","q":{q},"t":1,"h":""}}"#)), NOW).replies {
            if message.contains(r#""a":"d""#) {
                client.apply(&message);
            }
        }
        for (r, write) in writes.iter().enumerate() {
            writer.receive(&mut db, &write_frame(r as u64 + 2, write), NOW);
            for message in pushes_for(&mut db, listener.client()) {
                prop_assert!(message.contains(r#","t":1}"#), "untagged {message}");
                client.apply(&message);
            }
            // The client keeps only its window, as the SDK's filters do.
            client.cache = window.trim(&client.cache);
            let held = server(&mut db, &mut reader, "/s", Some(&q));
            prop_assert_eq!(&client.cache, &held, "after {:?}", write);
        }
    }
}
