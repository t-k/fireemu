//! Verification of password hashes imported through `accounts:batchCreate`.
//!
//! Production accepts fourteen hash algorithms. The conventions below are the ones production
//! Identity Toolkit was observed to accept in the 2026-09-23 sandbox exploration, not the ones
//! a reader of the reference might assume:
//!
//! - `MD5`: `x = md5(salt || password)`, then `rounds` times `x = md5(x || password)`; the
//!   stored hash is the lowercase hex of `x`. `passwordHashOrder` is not consulted.
//! - `SHA1`/`SHA256`/`SHA512`: `x = H(salt || password)` (or `password || salt` for
//!   `PASSWORD_AND_SALT`), then `x = H(x)` until `max(rounds, 1)` applications.
//! - `HMAC_*`: `HMAC(signerKey, password || salt)` by default, `salt || password` for
//!   `SALT_AND_PASSWORD`.
//! - `PBKDF_SHA1`/`PBKDF2_SHA256`: PBKDF2 with `rounds` iterations and the stored hash's length.
//! - `SCRYPT` (Firebase): `AES-256-CTR(scrypt(password, salt || saltSeparator, 2^memoryCost,
//!   rounds, 1)[..32], iv = 0)` applied to `signerKey`.
//! - `STANDARD_SCRYPT`: scrypt with `cpuMemCost`, `blockSize`, `parallelization`, `dkLen`.
//! - `BCRYPT`: a modular-crypt `$2a$`/`$2b$`/`$2y$` string.
//! - `ARGON2`: the raw Argon2 output for `argon2Parameters`.

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Digest;
use subtle::ConstantTimeEq;

/// The digest family of a SHA, HMAC or PBKDF algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

/// Which of salt and password comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Order {
    SaltFirst,
    PasswordFirst,
}

/// One import's hash algorithm and parameters, as production validated them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HashSpec {
    Md5 {
        rounds: u32,
    },
    Sha {
        family: Family,
        rounds: u32,
        order: Order,
    },
    Hmac {
        family: Family,
        key: Vec<u8>,
        order: Order,
    },
    Pbkdf {
        family: Family,
        rounds: u32,
    },
    FirebaseScrypt {
        key: Vec<u8>,
        separator: Vec<u8>,
        rounds: u32,
        memory_cost: u8,
    },
    StandardScrypt {
        log_n: u8,
        block_size: u32,
        parallelization: u32,
        dk_len: usize,
    },
    Bcrypt,
    Argon2 {
        variant: argon2::Algorithm,
        version: argon2::Version,
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
        hash_len: usize,
        associated_data: Vec<u8>,
    },
}

fn digest(family: Family, input: &[u8]) -> Vec<u8> {
    match family {
        Family::Md5 => md5::Md5::digest(input).to_vec(),
        Family::Sha1 => sha1::Sha1::digest(input).to_vec(),
        Family::Sha256 => sha2::Sha256::digest(input).to_vec(),
        Family::Sha512 => sha2::Sha512::digest(input).to_vec(),
    }
}

fn hmac(family: Family, key: &[u8], message: &[u8]) -> Vec<u8> {
    fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }
    match family {
        Family::Md5 => run::<Hmac<md5::Md5>>(key, message),
        Family::Sha1 => run::<Hmac<sha1::Sha1>>(key, message),
        Family::Sha256 => run::<Hmac<sha2::Sha256>>(key, message),
        Family::Sha512 => run::<Hmac<sha2::Sha512>>(key, message),
    }
}

fn joined(order: Order, salt: &[u8], password: &[u8]) -> Vec<u8> {
    match order {
        Order::SaltFirst => [salt, password].concat(),
        Order::PasswordFirst => [password, salt].concat(),
    }
}

fn to_hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])
        .collect()
}

/// The hash this spec derives from `password` and `salt`, or `None` when the stored hash
/// itself carries the derivation (bcrypt) or the parameters cannot derive one.
fn derive(spec: &HashSpec, password: &[u8], salt: &[u8], stored_len: usize) -> Option<Vec<u8>> {
    Some(match spec {
        HashSpec::Md5 { rounds } => {
            let mut x = digest(Family::Md5, &[salt, password].concat());
            for _ in 0..*rounds {
                x = digest(Family::Md5, &[x.as_slice(), password].concat());
            }
            to_hex(&x)
        }
        HashSpec::Sha {
            family,
            rounds,
            order,
        } => {
            let mut x = digest(*family, &joined(*order, salt, password));
            for _ in 1..(*rounds).max(1) {
                x = digest(*family, &x);
            }
            x
        }
        HashSpec::Hmac { family, key, order } => {
            hmac(*family, key, &joined(*order, salt, password))
        }
        HashSpec::Pbkdf { family, rounds } => {
            let mut out = vec![0; stored_len];
            match family {
                Family::Sha1 => {
                    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, *rounds, &mut out);
                }
                Family::Sha256 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, *rounds, &mut out);
                }
                Family::Md5 | Family::Sha512 => return None,
            }
            out
        }
        HashSpec::FirebaseScrypt {
            key,
            separator,
            rounds,
            memory_cost,
        } => {
            let params = scrypt::Params::new(*memory_cost, *rounds, 1, 64).ok()?;
            let mut derived = [0_u8; 64];
            scrypt::scrypt(password, &[salt, separator].concat(), &params, &mut derived).ok()?;
            let mut out = key.clone();
            ctr::Ctr128BE::<aes::Aes256>::new(derived[..32].into(), &[0_u8; 16].into())
                .apply_keystream(&mut out);
            out
        }
        HashSpec::StandardScrypt {
            log_n,
            block_size,
            parallelization,
            dk_len,
        } => {
            let params =
                scrypt::Params::new(*log_n, *block_size, *parallelization, *dk_len).ok()?;
            let mut out = vec![0; *dk_len];
            scrypt::scrypt(password, salt, &params, &mut out).ok()?;
            out
        }
        HashSpec::Argon2 {
            variant,
            version,
            iterations,
            memory_kib,
            parallelism,
            hash_len,
            associated_data,
        } => {
            let params = argon2::ParamsBuilder::new()
                .m_cost(*memory_kib)
                .t_cost(*iterations)
                .p_cost(*parallelism)
                .output_len(*hash_len)
                .data(argon2::AssociatedData::new(associated_data).ok()?)
                .build()
                .ok()?;
            let mut out = vec![0; *hash_len];
            argon2::Argon2::new(*variant, *version, params)
                .hash_password_into(password, salt, &mut out)
                .ok()?;
            out
        }
        HashSpec::Bcrypt => return None,
    })
}

/// Whether `password` matches an imported `hash` under `spec`.
pub(crate) fn verify(spec: &HashSpec, password: &str, salt: &[u8], hash: &[u8]) -> bool {
    if let HashSpec::Bcrypt = spec {
        return std::str::from_utf8(hash)
            .ok()
            .and_then(|text| bcrypt::verify(password, text).ok())
            .unwrap_or(false);
    }
    derive(spec, password.as_bytes(), salt, hash.len())
        .is_some_and(|derived| derived.len() == hash.len() && bool::from(derived.ct_eq(hash)))
}

/// The core store's view of this module: an imported hash matches when its spec decodes and
/// the password derives the stored hash.
pub(crate) struct ImportedHashes;

impl fireemu_core_auth::store::ImportedHashVerifier for ImportedHashes {
    fn verify(
        &self,
        imported: &fireemu_core_auth::store::ImportedPasswordHash,
        password: &str,
    ) -> bool {
        decode(&imported.spec)
            .is_some_and(|spec| verify(&spec, password, &imported.salt, &imported.hash))
    }
}

/// The spec as a canonical JSON string, which is what the core store keeps (it has no
/// cryptography of its own).
pub(crate) fn encode(spec: &HashSpec) -> String {
    let b64 = |bytes: &[u8]| fireemu_core_types::hash::base64_standard(bytes);
    let family = |family: &Family| match family {
        Family::Md5 => "MD5",
        Family::Sha1 => "SHA1",
        Family::Sha256 => "SHA256",
        Family::Sha512 => "SHA512",
    };
    let order = |order: &Order| match order {
        Order::SaltFirst => "SALT_AND_PASSWORD",
        Order::PasswordFirst => "PASSWORD_AND_SALT",
    };
    let value = match spec {
        HashSpec::Md5 { rounds } => json!({"algorithm": "MD5", "rounds": rounds}),
        HashSpec::Sha {
            family: f,
            rounds,
            order: o,
        } => json!({"algorithm": "SHA", "family": family(f), "rounds": rounds, "order": order(o)}),
        HashSpec::Hmac {
            family: f,
            key,
            order: o,
        } => json!({"algorithm": "HMAC", "family": family(f), "key": b64(key), "order": order(o)}),
        HashSpec::Pbkdf { family: f, rounds } => {
            json!({"algorithm": "PBKDF", "family": family(f), "rounds": rounds})
        }
        HashSpec::FirebaseScrypt {
            key,
            separator,
            rounds,
            memory_cost,
        } => json!({"algorithm": "SCRYPT", "key": b64(key), "separator": b64(separator),
                    "rounds": rounds, "memoryCost": memory_cost}),
        HashSpec::StandardScrypt {
            log_n,
            block_size,
            parallelization,
            dk_len,
        } => json!({"algorithm": "STANDARD_SCRYPT", "logN": log_n, "blockSize": block_size,
                    "parallelization": parallelization, "dkLen": dk_len}),
        HashSpec::Bcrypt => json!({"algorithm": "BCRYPT"}),
        HashSpec::Argon2 {
            variant,
            version,
            iterations,
            memory_kib,
            parallelism,
            hash_len,
            associated_data,
        } => json!({"algorithm": "ARGON2", "variant": variant.as_str(),
                    "version": u32::from(*version), "iterations": iterations,
                    "memoryKib": memory_kib, "parallelism": parallelism, "hashLen": hash_len,
                    "associatedData": b64(associated_data)}),
    };
    value.to_string()
}

/// The inverse of [`encode`].
pub(crate) fn decode(text: &str) -> Option<HashSpec> {
    let value: Value = serde_json::from_str(text).ok()?;
    let u32_of = |key: &str| value.get(key)?.as_u64().and_then(|n| u32::try_from(n).ok());
    let bytes_of = |key: &str| base64_decode(value.get(key)?.as_str()?);
    let family = || match value.get("family")?.as_str()? {
        "MD5" => Some(Family::Md5),
        "SHA1" => Some(Family::Sha1),
        "SHA256" => Some(Family::Sha256),
        "SHA512" => Some(Family::Sha512),
        _ => None,
    };
    let order = || match value.get("order")?.as_str()? {
        "SALT_AND_PASSWORD" => Some(Order::SaltFirst),
        "PASSWORD_AND_SALT" => Some(Order::PasswordFirst),
        _ => None,
    };
    Some(match value.get("algorithm")?.as_str()? {
        "MD5" => HashSpec::Md5 {
            rounds: u32_of("rounds")?,
        },
        "SHA" => HashSpec::Sha {
            family: family()?,
            rounds: u32_of("rounds")?,
            order: order()?,
        },
        "HMAC" => HashSpec::Hmac {
            family: family()?,
            key: bytes_of("key")?,
            order: order()?,
        },
        "PBKDF" => HashSpec::Pbkdf {
            family: family()?,
            rounds: u32_of("rounds")?,
        },
        "SCRYPT" => HashSpec::FirebaseScrypt {
            key: bytes_of("key")?,
            separator: bytes_of("separator")?,
            rounds: u32_of("rounds")?,
            memory_cost: u8::try_from(u32_of("memoryCost")?).ok()?,
        },
        "STANDARD_SCRYPT" => HashSpec::StandardScrypt {
            log_n: u8::try_from(u32_of("logN")?).ok()?,
            block_size: u32_of("blockSize")?,
            parallelization: u32_of("parallelization")?,
            dk_len: usize::try_from(u32_of("dkLen")?).ok()?,
        },
        "BCRYPT" => HashSpec::Bcrypt,
        "ARGON2" => HashSpec::Argon2 {
            variant: value.get("variant")?.as_str()?.parse().ok()?,
            version: argon2::Version::try_from(u32_of("version")?).ok()?,
            iterations: u32_of("iterations")?,
            memory_kib: u32_of("memoryKib")?,
            parallelism: u32_of("parallelism")?,
            hash_len: usize::try_from(u32_of("hashLen")?).ok()?,
            associated_data: bytes_of("associatedData")?,
        },
        _ => return None,
    })
}

/// The hash spec of a `batchCreate` request, or the Identity Toolkit error code production
/// answers for its parameters. Codes not yet observed in production are provisional
/// (`INVALID_HASH_ALGORITHM` and friends) and follow the sandbox recording.
pub(crate) fn spec_from_options(options: &Value) -> Result<HashSpec, &'static str> {
    let text = |key: &str| options.get(key).and_then(Value::as_str);
    let int = |key: &str| options.get(key).and_then(Value::as_u64);
    let bytes = |key: &str| text(key).and_then(base64_decode);
    let rounds = || int("rounds").and_then(|n| u32::try_from(n).ok());
    let order = |default: Order| match text("passwordHashOrder") {
        Some("SALT_AND_PASSWORD") => Order::SaltFirst,
        Some("PASSWORD_AND_SALT") => Order::PasswordFirst,
        _ => default,
    };
    let family_of = |name: &str| match name {
        "MD5" => Family::Md5,
        "SHA1" => Family::Sha1,
        "SHA256" => Family::Sha256,
        _ => Family::Sha512,
    };
    let algorithm = text("hashAlgorithm").ok_or("MISSING_HASH_ALGORITHM")?;
    Ok(match algorithm {
        "MD5" => HashSpec::Md5 {
            rounds: rounds().unwrap_or(0),
        },
        "SHA1" | "SHA256" | "SHA512" => HashSpec::Sha {
            family: family_of(algorithm),
            rounds: rounds().unwrap_or(0),
            order: order(Order::SaltFirst),
        },
        "HMAC_MD5" | "HMAC_SHA1" | "HMAC_SHA256" | "HMAC_SHA512" => {
            let key = bytes("signerKey").unwrap_or_default();
            // Production refuses a missing key for every HMAC but HMAC_SHA512, which it
            // accepts at import and then fails at sign-in.
            if key.is_empty() && algorithm != "HMAC_SHA512" {
                return Err("EMPTY_HASH_KEY");
            }
            HashSpec::Hmac {
                family: family_of(&algorithm["HMAC_".len()..]),
                key,
                order: order(Order::PasswordFirst),
            }
        }
        "PBKDF_SHA1" | "PBKDF2_SHA256" => HashSpec::Pbkdf {
            family: if algorithm == "PBKDF_SHA1" {
                Family::Sha1
            } else {
                Family::Sha256
            },
            rounds: rounds().filter(|n| *n > 0).ok_or("INVALID_HASH_ROUNDS")?,
        },
        "SCRYPT" => HashSpec::FirebaseScrypt {
            key: bytes("signerKey").unwrap_or_default(),
            separator: bytes("saltSeparator").unwrap_or_default(),
            rounds: rounds()
                .filter(|n| (1..=8).contains(n))
                .ok_or("INVALID_HASH_ROUNDS")?,
            memory_cost: int("memoryCost")
                .and_then(|n| u8::try_from(n).ok())
                .filter(|n| (1..=14).contains(n))
                .ok_or("INVALID_HASH_MEMORY_COST")?,
        },
        "STANDARD_SCRYPT" => standard_scrypt_spec(options)?,
        "BCRYPT" => HashSpec::Bcrypt,
        "ARGON2" => argon2_spec(options)?,
        _ => return Err("INVALID_HASH_ALGORITHM"),
    })
}

fn standard_scrypt_spec(options: &Value) -> Result<HashSpec, &'static str> {
    let int = |key: &str| options.get(key).and_then(Value::as_u64);
    let positive_u32 = |key: &str| {
        int(key)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
    };
    let cost = int("cpuMemCost").filter(|n| n.is_power_of_two() && *n > 1);
    Ok(HashSpec::StandardScrypt {
        log_n: cost
            .and_then(|n| u8::try_from(n.trailing_zeros()).ok())
            .ok_or("INVALID_HASH_CPU_MEM_COST")?,
        block_size: positive_u32("blockSize").ok_or("INVALID_HASH_BLOCK_SIZE")?,
        parallelization: positive_u32("parallelization").ok_or("INVALID_HASH_PARALLELIZATION")?,
        dk_len: int("dkLen")
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("INVALID_HASH_DERIVED_KEY_LENGTH")?,
    })
}

fn argon2_spec(options: &Value) -> Result<HashSpec, &'static str> {
    let params = options.get("argon2Parameters");
    let text = |key: &str| params.and_then(|p| p.get(key)).and_then(Value::as_str);
    let within = |key: &str, range: std::ops::RangeInclusive<u32>| {
        params
            .and_then(|p| p.get(key))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| range.contains(n))
    };
    let memory_kib = within("memoryCostKib", 1..=32768).ok_or("INVALID_ARGON2_MEMORY_COST")?;
    let iterations = within("iterations", 1..=16).ok_or("INVALID_ARGON2_ITERATIONS")?;
    let parallelism = within("parallelism", 1..=16).ok_or("INVALID_ARGON2_PARALLELISM")?;
    let hash_len = within("hashLengthBytes", 4..=1024).ok_or("INVALID_ARGON2_HASH_LENGTH")?;
    let variant = match text("hashType") {
        Some("ARGON2_ID") => argon2::Algorithm::Argon2id,
        Some("ARGON2_I") => argon2::Algorithm::Argon2i,
        Some("ARGON2_D") => argon2::Algorithm::Argon2d,
        _ => return Err("INVALID_ARGON2_HASH_TYPE"),
    };
    let version = match text("version") {
        Some("VERSION_10") => argon2::Version::V0x10,
        _ => argon2::Version::V0x13,
    };
    let associated_data = text("associatedData")
        .map(|s| base64_decode(s).ok_or("INVALID_ARGON2_ASSOCIATED_DATA"))
        .transpose()?
        .unwrap_or_default();
    Ok(HashSpec::Argon2 {
        variant,
        version,
        iterations,
        memory_kib,
        parallelism,
        hash_len: usize::try_from(hash_len).map_err(|_| "INVALID_ARGON2_HASH_LENGTH")?,
        associated_data,
    })
}

/// Standard or URL-safe base64, padded or not: what proto3 JSON accepts for `bytes`.
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut count = 0_u8;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let trimmed = text.trim_end_matches('=');
    for c in trimmed.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    if trimmed.len() % 4 == 1 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus vectors (conformance/src/auth-account/hash-vectors.json): every one was
    /// accepted by production with the password `password123`.
    fn vectors() -> serde_json::Map<String, Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/src/auth-account/hash-vectors.json"
        );
        serde_json::from_str::<Value>(&std::fs::read_to_string(path).expect("vectors"))
            .expect("json")
            .as_object()
            .expect("object")
            .clone()
    }

    #[test]
    fn every_production_vector_verifies_only_its_password() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 29);
        for (name, vector) in &vectors {
            let spec =
                spec_from_options(&vector["options"]).unwrap_or_else(|e| panic!("{name}: {e}"));
            let user = &vector["user"];
            let hash = base64_decode(user["passwordHash"].as_str().unwrap()).unwrap();
            let salt = user
                .get("salt")
                .and_then(Value::as_str)
                .map(|s| base64_decode(s).unwrap())
                .unwrap_or_default();
            assert!(
                verify(&spec, "password123", &salt, &hash),
                "{name} accepts its password"
            );
            assert!(
                !verify(&spec, "password124", &salt, &hash),
                "{name} refuses another"
            );
            assert_eq!(decode(&encode(&spec)), Some(spec), "{name} round-trips");
        }
    }

    #[test]
    fn base64_accepts_standard_and_url_safe_forms() {
        assert_eq!(base64_decode("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(base64_decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(base64_decode("not base64!"), None);
        assert_eq!(base64_decode("A"), None);
    }
}
