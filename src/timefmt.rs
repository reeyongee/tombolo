//! Epoch → display timestamp, without pulling in a date crate.

/// Format epoch seconds as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn fmt_epoch(epoch: f64) -> String {
    let secs = epoch as i64;
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Days-from-civil algorithm (Howard Hinnant), inverted.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_renders() {
        assert_eq!(fmt_epoch(0.0), "1970-01-01 00:00:00");
    }

    #[test]
    fn known_timestamp() {
        // 1780000012 == 2026-05-28 20:26:52 UTC (verified against
        // `datetime.fromtimestamp(1780000012, timezone.utc)`)
        assert_eq!(fmt_epoch(1_780_000_012.0), "2026-05-28 20:26:52");
    }

    #[test]
    fn fractional_seconds_truncate() {
        assert_eq!(fmt_epoch(1_780_000_012.9), "2026-05-28 20:26:52");
    }
}
