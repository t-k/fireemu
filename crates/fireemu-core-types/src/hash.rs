//! Dependency-free digest and byte encoding primitives shared by the core crates.

const CRC32C_TABLES: [[u32; 256]; 8] = crc32c_tables();

#[allow(clippy::cast_possible_truncation)]
const fn crc32c_tables() -> [[u32; 256]; 8] {
    const POLYNOMIAL: u32 = 0x82f6_3b78;
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ POLYNOMIAL
            } else {
                value >> 1
            };
            bit += 1;
        }
        tables[0][i] = value;
        i += 1;
    }
    let mut table = 1;
    while table < 8 {
        i = 0;
        while i < 256 {
            let previous = tables[table - 1][i];
            tables[table][i] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            i += 1;
        }
        table += 1;
    }
    tables
}

/// Incremental CRC32C (Castagnoli) digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32c {
    state: u32,
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// Creates an empty digest.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: u32::MAX }
    }

    /// Adds bytes to the digest.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let value = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]) ^ u64::from(self.state);
            self.state = CRC32C_TABLES[7][(value & 0xff) as usize]
                ^ CRC32C_TABLES[6][((value >> 8) & 0xff) as usize]
                ^ CRC32C_TABLES[5][((value >> 16) & 0xff) as usize]
                ^ CRC32C_TABLES[4][((value >> 24) & 0xff) as usize]
                ^ CRC32C_TABLES[3][((value >> 32) & 0xff) as usize]
                ^ CRC32C_TABLES[2][((value >> 40) & 0xff) as usize]
                ^ CRC32C_TABLES[1][((value >> 48) & 0xff) as usize]
                ^ CRC32C_TABLES[0][(value >> 56) as usize];
        }
        for &byte in chunks.remainder() {
            let index = ((self.state ^ u32::from(byte)) & 0xff) as usize;
            self.state = (self.state >> 8) ^ CRC32C_TABLES[0][index];
        }
    }

    /// Returns the final digest without mutating the state.
    #[must_use]
    pub const fn finalize(self) -> u32 {
        !self.state
    }
}

/// CRC32C (Castagnoli, reflected).
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut digest = Crc32c::new();
    digest.update(bytes);
    digest.finalize()
}

const MD5_SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_CONSTANT: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// Incremental MD5 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Md5 {
    state: [u32; 4],
    tail: [u8; 64],
    tail_len: usize,
    byte_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Creates an empty digest.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            tail: [0; 64],
            tail_len: 0,
            byte_len: 0,
        }
    }

    /// Adds bytes to the digest.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.byte_len = self.byte_len.wrapping_add(bytes.len() as u64);
        if self.tail_len != 0 {
            let take = (64 - self.tail_len).min(bytes.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&bytes[..take]);
            self.tail_len += take;
            bytes = &bytes[take..];
            if self.tail_len < 64 {
                return;
            }
            md5_compress(&mut self.state, &self.tail);
            self.tail_len = 0;
        }
        let mut blocks = bytes.chunks_exact(64);
        for block in &mut blocks {
            md5_compress(&mut self.state, block);
        }
        let remainder = blocks.remainder();
        self.tail[..remainder.len()].copy_from_slice(remainder);
        self.tail_len = remainder.len();
    }

    /// Returns the final digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        let mut final_blocks = [0u8; 128];
        final_blocks[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
        final_blocks[self.tail_len] = 0x80;
        let final_len = if self.tail_len < 56 { 64 } else { 128 };
        final_blocks[final_len - 8..final_len]
            .copy_from_slice(&self.byte_len.wrapping_mul(8).to_le_bytes());
        for block in final_blocks[..final_len].chunks_exact(64) {
            md5_compress(&mut self.state, block);
        }
        let mut output = [0u8; 16];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}

#[allow(clippy::many_single_char_names)]
fn md5_compress(state: &mut [u32; 4], block: &[u8]) {
    let mut words = [0u32; 16];
    for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    macro_rules! round {
        ($range:expr, $index:ident, $function:expr, $word:expr) => {
            for $index in $range {
                let function = $function;
                let word = $word;
                let rotated = function
                    .wrapping_add(a)
                    .wrapping_add(MD5_CONSTANT[$index])
                    .wrapping_add(words[word])
                    .rotate_left(MD5_SHIFT[$index]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(rotated);
            }
        };
    }
    round!(0..16, i, (b & c) | (!b & d), i);
    round!(16..32, i, (d & b) | (!d & c), (5 * i + 1) & 15);
    round!(32..48, i, b ^ c ^ d, (3 * i + 5) & 15);
    round!(48..64, i, c ^ (b | !d), (7 * i) & 15);
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// MD5 (RFC 1321).
#[must_use]
pub fn md5(bytes: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(bytes);
    digest.finalize()
}

const SHA256_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Incremental SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256 {
    state: [u32; 8],
    tail: [u8; 64],
    tail_len: usize,
    byte_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Creates an empty digest.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            tail: [0; 64],
            tail_len: 0,
            byte_len: 0,
        }
    }

    /// Adds bytes to the digest.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.byte_len = self.byte_len.wrapping_add(bytes.len() as u64);
        if self.tail_len != 0 {
            let take = (64 - self.tail_len).min(bytes.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&bytes[..take]);
            self.tail_len += take;
            bytes = &bytes[take..];
            if self.tail_len < 64 {
                return;
            }
            sha256_compress(&mut self.state, &self.tail, &SHA256_CONSTANTS);
            self.tail_len = 0;
        }
        let mut blocks = bytes.chunks_exact(64);
        for block in &mut blocks {
            sha256_compress(&mut self.state, block, &SHA256_CONSTANTS);
        }
        let remainder = blocks.remainder();
        self.tail[..remainder.len()].copy_from_slice(remainder);
        self.tail_len = remainder.len();
    }

    /// Returns the final digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let mut final_blocks = [0u8; 128];
        final_blocks[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
        final_blocks[self.tail_len] = 0x80;
        let final_len = if self.tail_len < 56 { 64 } else { 128 };
        final_blocks[final_len - 8..final_len]
            .copy_from_slice(&self.byte_len.wrapping_mul(8).to_be_bytes());
        for block in final_blocks[..final_len].chunks_exact(64) {
            sha256_compress(&mut self.state, block, &SHA256_CONSTANTS);
        }
        let mut output = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}

/// SHA-256 (FIPS 180-4).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize()
}

#[allow(clippy::many_single_char_names)]
fn sha256_compress(state: &mut [u32; 8], block: &[u8], constants: &[u32; 64]) {
    let mut words = [0u32; 64];
    for (word, bytes) in words[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for i in 16..64 {
        let s0 =
            words[i - 15].rotate_right(7) ^ words[i - 15].rotate_right(18) ^ (words[i - 15] >> 3);
        let s1 =
            words[i - 2].rotate_right(17) ^ words[i - 2].rotate_right(19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for i in 0..64 {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let first = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(constants[i])
            .wrapping_add(words[i]);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    for (word, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(addition);
    }
}

fn base64_with_alphabet(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut output = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut bytes = [0u8; 3];
        bytes[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        output.push(alphabet[((bits >> 18) & 0x3f) as usize] as char);
        output.push(alphabet[((bits >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            alphabet[((bits >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            alphabet[(bits & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

/// Standard base64 with padding.
#[must_use]
pub fn base64_standard(data: &[u8]) -> String {
    base64_with_alphabet(
        data,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    )
}

/// URL-safe base64 with padding.
#[must_use]
pub fn base64_url_safe(data: &[u8]) -> String {
    base64_with_alphabet(
        data,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    )
}

fn hex_with_alphabet(data: &[u8], alphabet: &[u8; 16]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for &byte in data {
        output.push(alphabet[usize::from(byte >> 4)] as char);
        output.push(alphabet[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// Lowercase hexadecimal.
#[must_use]
pub fn hex_lower(data: &[u8]) -> String {
    hex_with_alphabet(data, b"0123456789abcdef")
}

/// Uppercase hexadecimal.
#[must_use]
pub fn hex_upper(data: &[u8]) -> String {
    hex_with_alphabet(data, b"0123456789ABCDEF")
}
