//! A bounded "report once per name" set for operator warnings whose names come from clients.

use std::collections::BTreeSet;

/// What a [`NoticeLimit`] lets the caller report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeEvent<'a> {
    /// The first occurrence of this name.
    First(&'a str),
    /// [`NoticeLimit::LIMIT`] names were reported and another one occurred; nothing more is
    /// reported.
    Suppressed,
}

/// The names reported so far, at most [`NoticeLimit::LIMIT`] of them, so that a client naming
/// ever new resources can grow neither the set nor the log without bound.
#[derive(Debug, Default)]
pub struct NoticeLimit {
    reported: BTreeSet<String>,
    suppressed: bool,
}

impl NoticeLimit {
    /// How many distinct names are reported before further ones are suppressed.
    pub const LIMIT: usize = 32;

    /// What an occurrence of `name` reports, if anything.
    pub fn observe<'a>(&mut self, name: &'a str) -> Option<NoticeEvent<'a>> {
        if self.reported.contains(name) {
            None
        } else if self.reported.len() < Self::LIMIT {
            self.reported.insert(name.to_owned());
            Some(NoticeEvent::First(name))
        } else if self.suppressed {
            None
        } else {
            self.suppressed = true;
            Some(NoticeEvent::Suppressed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Against a reference model: the first occurrences of the first `LIMIT` distinct names,
        /// then a single suppression line at the first further distinct name.
        #[test]
        fn reports_match_the_reference_model(
            names in proptest::collection::vec(0..80usize, 0..300)
        ) {
            let mut limit = NoticeLimit::default();
            let mut seen: Vec<usize> = Vec::new();
            let mut suppressed = false;
            for n in names {
                let name = format!("n{n}");
                let expected = if seen.contains(&n) {
                    None
                } else if seen.len() < NoticeLimit::LIMIT {
                    seen.push(n);
                    Some(NoticeEvent::First(name.as_str()))
                } else if suppressed {
                    None
                } else {
                    suppressed = true;
                    Some(NoticeEvent::Suppressed)
                };
                prop_assert_eq!(limit.observe(&name), expected);
            }
            prop_assert!(limit.reported.len() <= NoticeLimit::LIMIT);
        }
    }

    #[test]
    fn a_hundred_distinct_names_give_the_limit_plus_one_reports() {
        let mut limit = NoticeLimit::default();
        let reports = (0..100)
            .filter_map(|i| {
                limit
                    .observe(&format!("b{i}"))
                    .map(|e| e == NoticeEvent::Suppressed)
            })
            .collect::<Vec<_>>();
        assert_eq!(reports.len(), NoticeLimit::LIMIT + 1);
        assert_eq!(reports.iter().filter(|s| **s).count(), 1);
        assert!(reports[NoticeLimit::LIMIT]);
    }
}
