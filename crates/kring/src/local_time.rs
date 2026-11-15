//! Local time display of RFC 3339 UTC timestamps.
//!
//! The local UTC offset can only be read safely while the process has a
//! single thread, so [`init`] must run first thing in `main`; later calls of
//! [`offset`] return the captured value (UTC if it could not be read).

use std::sync::OnceLock;

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// Local UTC offset captured at startup.
static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// Captures the local UTC offset; call before any thread is started.
pub fn init() {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    // A second call keeps the first value.
    let _ = LOCAL_OFFSET.set(offset);
}

/// Returns the offset captured by [`init`], or UTC when it never ran.
pub fn offset() -> UtcOffset {
    LOCAL_OFFSET.get().copied().unwrap_or(UtcOffset::UTC)
}

/// Formats an RFC 3339 timestamp as `YYYY-MM-DD HH:MM` at `offset`; an
/// unparsable value is returned unchanged.
pub fn format_rfc3339(value: &str, offset: UtcOffset) -> String {
    let Ok(parsed) = OffsetDateTime::parse(value, &Rfc3339) else {
        return value.to_string();
    };
    let t = parsed.to_offset(offset);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

/// Formats unix seconds as `YYYY-MM-DD HH:MM` at `offset`; `-` when zero
/// (unknown) or out of range.
pub fn format_unix(secs: u64, offset: UtcOffset) -> String {
    if secs == 0 {
        return "-".to_string();
    }
    let parsed = i64::try_from(secs)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok());
    let Some(t) = parsed.map(|t| t.to_offset(offset)) else {
        return "-".to_string();
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

/// Returns today's date at `offset` as `YYYYmmdd`.
pub fn today_compact(offset: UtcOffset) -> String {
    let d = OffsetDateTime::now_utc().to_offset(offset).date();
    format!("{:04}{:02}{:02}", d.year(), u8::from(d.month()), d.day())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UTC timestamps are shifted to the offset; garbage is kept verbatim.
    #[test]
    fn formats_at_offset() {
        let utc = "2026-11-15T23:30:05Z";
        assert_eq!(format_rfc3339(utc, UtcOffset::UTC), "2026-11-15 23:30");
        let cet = UtcOffset::from_hms(1, 0, 0).unwrap();
        assert_eq!(format_rfc3339(utc, cet), "2026-11-16 00:30");
        assert_eq!(format_rfc3339("yesterday", cet), "yesterday");
    }

    /// Unix seconds are shown at the offset; zero and out of range are unknown.
    #[test]
    fn formats_unix_seconds() {
        let cet = UtcOffset::from_hms(1, 0, 0).unwrap();
        assert_eq!(format_unix(1_759_363_200, cet), "2025-10-02 01:00");
        assert_eq!(format_unix(0, cet), "-");
        assert_eq!(format_unix(u64::MAX, cet), "-");
    }

    /// Today's date has eight digits.
    #[test]
    fn today_is_compact() {
        let d = today_compact(UtcOffset::UTC);
        assert_eq!(d.len(), 8);
        assert!(d.chars().all(|c| c.is_ascii_digit()));
    }
}
