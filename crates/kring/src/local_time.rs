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

    /// Today's date has eight digits.
    #[test]
    fn today_is_compact() {
        let d = today_compact(UtcOffset::UTC);
        assert_eq!(d.len(), 8);
        assert!(d.chars().all(|c| c.is_ascii_digit()));
    }
}
