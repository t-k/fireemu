//! Bounded, local-only Tree snapshot measurement. Run each case in a fresh release process.

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_database::Format;

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(16))]
        #[test]
        fn snapshot_count_boundary(count in 0usize..12, shape in 0usize..4) {
            let names = ["deep", "wide", "strings", "numbers"];
            let count_text = count.to_string();
            let parsed = Config::parse(&[names[shape], "clone", &count_text]);
            proptest::prop_assert_eq!(parsed.is_ok(), (1..=8).contains(&count));
        }
    }

    #[test]
    fn guards_reject_unbounded_inputs() {
        assert!(Config::parse(&["deep", "clone", "9"]).is_err());
        assert!(Config::parse(&["unknown", "clone", "1"]).is_err());
        assert!(Config::parse(&["wide", "invalid", "1"]).is_err());
        assert!(Config::parse(&["wide", "clone", "0"]).is_err());
        assert!(Config::parse(&["wide", "clone", "1", "extra"]).is_err());
    }

    #[test]
    fn deterministic_fixture_and_snapshot_isolation() {
        for shape in ["deep", "wide", "strings", "numbers"] {
            let config = Config::parse(&[shape, "clone", "2"]).unwrap();
            let a = fixture(config.shape);
            let b = fixture(config.shape);
            assert!(a
                .get_json(&Path::default(), Format::Export)
                .same_form(&b.get_json(&Path::default(), Format::Export)));
            let mut direct = a.clone();
            let mut shared = Arc::new(a.clone());
            let snapshot = Arc::clone(&shared);
            mutate(&mut direct, config.shape);
            mutate(Arc::make_mut(&mut shared), config.shape);
            assert_eq!(direct, *shared);
            assert_eq!(*snapshot, a);
            assert!(
                direct != a,
                "negative control: mutation must change the fixture"
            );
            assert_eq!(stats(a.root().unwrap()).0, config.shape.nodes());
        }
    }
}

use std::{collections::BTreeMap, hint::black_box, sync::Arc, time::Instant};

use fireemu_core_database::{
    Content, Json, Leaf, Limits, Node, Number, Path, ServerValueContext, Tree,
};
use serde_json::json;

const MAX_SNAPSHOTS: usize = 8;
const RSS_CAP_KIB: u64 = 512 * 1024;
const SEED: i64 = 24_025;

#[derive(Clone, Copy)]
struct Shape {
    depth: u32,
    fanout: u32,
    string_bytes: usize,
}

impl Shape {
    fn nodes(self) -> u64 {
        (0..=self.depth)
            .map(|level| u64::from(self.fanout).pow(level))
            .sum()
    }
}

struct Config<'a> {
    name: &'a str,
    mode: &'a str,
    shape: Shape,
    snapshots: usize,
}

impl<'a> Config<'a> {
    fn parse(args: &[&'a str]) -> Result<Self, &'static str> {
        if args.len() != 3 {
            return Err("expected SHAPE MODE SNAPSHOTS");
        }
        let shape = match args[0] {
            "deep" => Shape {
                depth: 12,
                fanout: 2,
                string_bytes: 0,
            },
            "wide" => Shape {
                depth: 1,
                fanout: 4096,
                string_bytes: 0,
            },
            "strings" => Shape {
                depth: 4,
                fanout: 8,
                string_bytes: 128,
            },
            "numbers" => Shape {
                depth: 4,
                fanout: 8,
                string_bytes: 0,
            },
            _ => return Err("shape must be deep, wide, strings or numbers"),
        };
        if !matches!(args[1], "clone" | "root-cow") {
            return Err("mode must be clone or root-cow");
        }
        let snapshots = args[2].parse().map_err(|_| "invalid snapshot count")?;
        if !(1..=MAX_SNAPSHOTS).contains(&snapshots) {
            return Err("snapshot count must be 1..8");
        }
        Ok(Self {
            name: args[0],
            mode: args[1],
            shape,
            snapshots,
        })
    }
}

fn fixture(shape: Shape) -> Tree {
    fn build(shape: Shape, depth: u32, sequence: &mut i64) -> Json {
        if depth == 0 {
            *sequence += 1;
            return if shape.string_bytes == 0 {
                Json::Number(Number::Int(*sequence))
            } else {
                Json::String(format!("{:0128}", *sequence))
            };
        }
        Json::Object(
            (0..shape.fanout)
                .map(|i| (format!("k{i:04}"), build(shape, depth - 1, sequence)))
                .collect::<BTreeMap<_, _>>(),
        )
    }
    let mut tree = Tree::default();
    let mut seed = SEED;
    tree.set(
        &Path::default(),
        &build(shape, shape.depth, &mut seed),
        ServerValueContext { now_millis: 0 },
    )
    .unwrap();
    tree
}

fn mutate(tree: &mut Tree, shape: Shape) {
    let path = Path::parse(
        &vec!["k0000"; shape.depth as usize].join("/"),
        &Limits::default(),
    )
    .unwrap();
    tree.set(
        &path,
        &Json::Bool(true),
        ServerValueContext { now_millis: 0 },
    )
    .unwrap();
}

// Logical structural counts, not allocation counts or allocator-resident bytes.
fn stats(node: &Node) -> (u64, u64) {
    match &node.content {
        Content::Leaf(Leaf::String(value)) => (1, value.len() as u64),
        Content::Leaf(_) => (1, 0),
        Content::Children(children) => {
            children
                .iter()
                .fold((1, 0), |(nodes, bytes), (key, child)| {
                    let (n, b) = stats(child);
                    (nodes + n, bytes + key.len() as u64 + b)
                })
        }
    }
}

// ps reports current resident KiB on macOS and Linux; subprocess memory is excluded.
fn rss_kib() -> Result<u64, String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("ps RSS query failed".into());
    }
    String::from_utf8(output.stdout)
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "invalid ps RSS".into())
}

fn checkpoint(start: Instant) -> Result<u64, String> {
    let rss = rss_kib()?;
    if start.elapsed().as_secs() >= 10 || rss > RSS_CAP_KIB {
        return Err("bounded time/RSS guard exceeded".into());
    }
    Ok(rss)
}

fn run(config: &Config<'_>) -> Result<serde_json::Value, String> {
    let start = Instant::now();
    let rss_before = checkpoint(start)?;
    let tree = fixture(config.shape);
    let rss_fixture = checkpoint(start)?;
    let structural = stats(tree.root().unwrap());
    assert_eq!(structural.0, config.shape.nodes());
    let retained_estimate = tree.retained_bytes();
    let snapshot_ns;
    let first_write_ns;
    let rss_snapshots;
    let rss_written;
    if config.mode == "clone" {
        let mut live = tree;
        let clock = Instant::now();
        let snapshots: Vec<_> = (0..config.snapshots)
            .map(|_| black_box(live.clone()))
            .collect();
        snapshot_ns = clock.elapsed().as_nanos();
        rss_snapshots = checkpoint(start)?;
        let clock = Instant::now();
        mutate(&mut live, config.shape);
        first_write_ns = clock.elapsed().as_nanos();
        rss_written = checkpoint(start)?;
        black_box((&snapshots, &live));
        if snapshots.iter().any(|saved| saved == &live) {
            return Err("mutation did not distinguish saved state".into());
        }
    } else {
        let mut live = Arc::new(tree);
        let clock = Instant::now();
        let snapshots: Vec<_> = (0..config.snapshots)
            .map(|_| black_box(Arc::clone(&live)))
            .collect();
        snapshot_ns = clock.elapsed().as_nanos();
        rss_snapshots = checkpoint(start)?;
        let clock = Instant::now();
        mutate(Arc::make_mut(&mut live), config.shape);
        first_write_ns = clock.elapsed().as_nanos();
        rss_written = checkpoint(start)?;
        black_box((&snapshots, &live));
        if snapshots.iter().any(|saved| **saved == *live) {
            return Err("mutation did not distinguish saved state".into());
        }
    }
    let rss_after_drop = checkpoint(start)?;
    Ok(
        json!({"schema":1,"shape":config.name,"mode":config.mode,"seed":SEED,"depth":config.shape.depth,"fanout":config.shape.fanout,"string_bytes":config.shape.string_bytes,"snapshots":config.snapshots,"nodes_per_tree":structural.0,"key_and_string_payload_bytes":structural.1,"retained_bytes_estimate_per_tree":retained_estimate,"snapshot_total_ns":snapshot_ns.to_string(),"first_small_write_ns":first_write_ns.to_string(),"rss_kib":{"before":rss_before,"fixture":rss_fixture,"snapshots":rss_snapshots,"first_write":rss_written,"after_drop":rss_after_drop},"caps":{"seconds":10,"rss_kib":RSS_CAP_KIB,"max_snapshots":MAX_SNAPSHOTS},"limitations":"RSS includes process/allocator state; drops may retain allocator pages. Logical node counts and retained_bytes are not measured allocation counts. Root COW is example-only; first write deep-clones Tree. No runtime/import benchmark."}),
    )
}

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let refs: Vec<_> = args.iter().map(String::as_str).collect();
    let config = Config::parse(&refs)?;
    let output = run(&config)?.to_string();
    if output.len() > 8192 {
        return Err("output exceeds 8KiB".into());
    }
    println!("{output}");
    Ok(())
}
