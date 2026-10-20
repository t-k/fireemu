//! Push ids: the keys `POST` creates.
//!
//! A push id is 20 characters: 8 encode the milliseconds since the epoch, most significant
//! first, and 12 are random. Within one millisecond the random part is incremented, so ids
//! sort in creation order. The alphabet is in ASCII order, so the string order is the
//! creation order. The randomness comes from a seeded generator, so a session seed makes
//! the ids reproducible.

/// The push id alphabet, in ascending ASCII order.
pub const PUSH_CHARS: &str = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

/// Generates strictly increasing push ids.
#[derive(Debug, Clone)]
pub struct PushIdGenerator {
    last_time: u64,
    last_random: [u8; 12],
    rng: u64,
}

impl PushIdGenerator {
    /// A generator whose random characters come from `seed`.
    pub fn new(seed: u64) -> Self {
        Self::from_state(0, [0; 12], seed)
    }

    /// A generator that last produced an id at `last_time` with `last_random`.
    pub fn from_state(last_time: u64, last_random: [u8; 12], rng: u64) -> Self {
        Self {
            last_time,
            last_random,
            rng,
        }
    }

    /// The id the generator produced last.
    pub fn current(&self) -> String {
        let alphabet = PUSH_CHARS.as_bytes();
        let mut id = String::with_capacity(20);
        let mut time = self.last_time;
        let mut stamp = [0u8; 8];
        for slot in stamp.iter_mut().rev() {
            *slot = alphabet[(time % 64) as usize];
            time /= 64;
        }
        id.extend(stamp.iter().map(|b| char::from(*b)));
        id.extend(
            self.last_random
                .iter()
                .map(|r| char::from(alphabet[usize::from(*r)])),
        );
        id
    }

    /// The next id at `now_millis`. A clock that went back, or a millisecond whose random
    /// part is exhausted, continues from the last id, so ids always increase.
    pub fn next(&mut self, now_millis: u64) -> String {
        if now_millis > self.last_time {
            self.last_time = now_millis;
            self.fresh_random();
        } else if !self.increment_random() {
            self.last_time += 1;
            self.fresh_random();
        }
        self.current()
    }

    fn fresh_random(&mut self) {
        for index in 0..self.last_random.len() {
            // The top six bits of a SplitMix64 output.
            self.last_random[index] = (self.split_mix() >> 58) as u8;
        }
    }

    /// Adds one to the random part; `false` when every character was already the last one.
    fn increment_random(&mut self) -> bool {
        for slot in self.last_random.iter_mut().rev() {
            if *slot == 63 {
                *slot = 0;
            } else {
                *slot += 1;
                return true;
            }
        }
        false
    }

    fn split_mix(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
