//! Deterministic language-neutral lexical-v1 Unicode analysis. No morphology or production-equivalence claims.
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// Normalize NFKC, full default case fold, NFKC again, then UAX29 words with individual CJK ideographs.
#[must_use]
pub fn tokenize(input: &str) -> Vec<String> {
    let normalized: String = input.nfkc().case_fold().nfkc().collect();
    let mut result = Vec::new();
    for word in normalized.unicode_words() {
        let mut buffer = String::new();
        for c in word.chars() {
            if matches!(c as u32,0x3400..=0x4dbf|0x4e00..=0x9fff|0xf900..=0xfaff|0x20000..=0x323af)
            {
                if !buffer.is_empty() {
                    result.push(std::mem::take(&mut buffer));
                }
                result.push(c.to_string());
            } else {
                buffer.push(c);
            }
        }
        if !buffer.is_empty() {
            result.push(buffer);
        }
    }
    result
}
