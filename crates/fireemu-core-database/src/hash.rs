//! Node hashes: the `ETag`s of the REST API and the compare-and-set hashes of transactions.
//!
//! The hash is the one the SDKs compute (`LeafNode.hash` / `ChildrenNode.hash` in
//! `@firebase/database`), and the official emulator answers it as the `ETag`: the base64
//! SHA-1 of a text that names the priority, the type and the value of a leaf, or the keys and
//! hashes of the children in priority order. Numbers enter it as the hexadecimal IEEE 754
//! bits of their double value.

use std::fmt::Write as _;

use crate::node::{Content, Leaf, Node, Priority};
use crate::number::Number;
use crate::query::{OrderBy, QueryParams};

/// The `ETag` of an absent value.
pub const NULL_ETAG: &str = "null_etag";

/// The `ETag` of `node`: its hash, or [`NULL_ETAG`] when it is absent.
pub fn etag(node: Option<&Node>) -> String {
    node.map_or_else(|| NULL_ETAG.to_owned(), |n| node_hash(Some(n)))
}

/// The hash of `node`; the empty string when it is absent.
pub fn node_hash(node: Option<&Node>) -> String {
    let Some(node) = node else {
        return String::new();
    };
    let mut text = String::new();
    if let Some(priority) = &node.priority {
        text.push_str("priority:");
        text.push_str(&priority_text(priority));
        text.push(':');
    }
    match &node.content {
        Content::Leaf(leaf) => text.push_str(&leaf_text(leaf)),
        Content::Children(children) => {
            let order = QueryParams::ordered_by(OrderBy::Priority);
            let mut sorted: Vec<(&String, &Node)> = children.iter().collect();
            sorted.sort_by(|(ka, a), (kb, b)| order.compare_children(ka, a, kb, b));
            for (key, child) in sorted {
                // A stored child is never empty, so its hash is never the empty string.
                let _ = write!(text, ":{key}:{}", node_hash(Some(child)));
            }
        }
    }
    base64(&sha1(text.as_bytes()))
}

fn priority_text(priority: &Priority) -> String {
    match priority {
        Priority::Number(n) => number_text(*n),
        Priority::String(s) => format!("string:{s}"),
    }
}

fn leaf_text(leaf: &Leaf) -> String {
    match leaf {
        Leaf::Bool(b) => format!("boolean:{b}"),
        Leaf::Number(n) => number_text(*n),
        Leaf::String(s) => format!("string:{s}"),
    }
}

/// `number:` and the big-endian IEEE 754 bits of the double value in lowercase hex.
fn number_text(number: Number) -> String {
    format!("number:{:016x}", number.as_f64().to_bits())
}

/// Standard base64 with padding.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// SHA-1 (RFC 3174) of `data`. The same algorithm as `fireemu-core-auth`'s, kept here so
/// the core stays dependency-free.
#[allow(clippy::many_single_char_names)] // RFC 3174 notation
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
