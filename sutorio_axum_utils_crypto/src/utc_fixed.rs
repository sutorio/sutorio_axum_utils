use chrono::FixedOffset;

use crate::{Error, Result};

/// Gets the current datetime as a FixedOffset value (rather than just UTC).
/// NOTE: the unwrap is safe because 0 seconds will never point at an
/// out-of-bounds location.
pub fn now() -> chrono::DateTime<chrono::FixedOffset> {
    chrono::Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
}

pub fn format(time: chrono::DateTime<chrono::FixedOffset>) -> String {
    time.to_rfc3339()
}

pub fn add_seconds_and_format(seconds: f64) -> String {
    format(now() + chrono::Duration::seconds(seconds as i64))
}

pub fn parse(moment: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(moment)
        .map_err(|_| Error::UTCParsingFailure(moment.to_string()))
}
