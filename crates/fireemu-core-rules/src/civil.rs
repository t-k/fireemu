//! Proleptic Gregorian calendar arithmetic in UTC for the `timestamp` namespace and the
//! `Timestamp` methods (days-from-civil / civil-from-days, Howard Hinnant's algorithms).

pub use fireemu_core_types::time::{civil_from_days, days_from_civil};

/// Whether `(year, month, day)` is a real date.
#[must_use]
pub fn is_valid_date(year: i64, month: i64, day: i64) -> bool {
    (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// ISO day of the week (Monday = 1 ... Sunday = 7) of a day count since 1970-01-01 (a
/// Thursday).
#[must_use]
pub fn iso_weekday(days: i64) -> i64 {
    (days + 3).rem_euclid(7) + 1
}

/// Day of the year (1-366).
#[must_use]
pub fn day_of_year(days: i64) -> i64 {
    let (y, _, _) = civil_from_days(days);
    days - days_from_civil(y, 1, 1) + 1
}
