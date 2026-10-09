//! JSONL ingest — the `labtrace` event schema.
//!
//! Kept source-compatible with `labtrace::event::Event`: identical field names,
//! `#[serde(default)]` on everything required, unknown keys preserved via
//! `#[serde(flatten)]`. This is what makes `engine_cases.jsonl` (labtrace's own
//! three unit cases) loadable unchanged.

use crate::model::Event;

/// Parse a JSONL stream into events, preserving order; bad lines are reported
/// but never abort ingestion.
pub fn parse_jsonl(input: &str) -> (Vec<Event>, Vec<String>) {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(mut ev) => {
                if ev.seq == 0 {
                    ev.seq = (i + 1) as u64;
                }
                if ev.row_kind.is_empty() {
                    ev.row_kind = ev.kind.clone();
                }
                events.push(ev);
            }
            Err(e) => errors.push(format!("line {}: {e}", i + 1)),
        }
    }
    events.sort_by(|a, b| {
        let ea = a.epoch.unwrap_or(0.0);
        let eb = b.epoch.unwrap_or(0.0);
        ea.partial_cmp(&eb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.seq.cmp(&b.seq))
    });
    (events, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_event() {
        let line =
            r#"{"pid":100,"ppid":1,"kind":"exec","exe":"/bin/sh","cmdline":"sh -c id","success":true}"#;
        let (evs, errs) = parse_jsonl(line);
        assert!(errs.is_empty(), "unexpected parse errors: {errs:?}");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "exec");
        assert_eq!(evs[0].seq, 1);
    }

    #[test]
    fn orders_by_epoch() {
        let input = r#"
{"seq":1,"epoch":10.0,"pid":1,"kind":"exec","exe":"/a","success":true}
{"seq":2,"epoch":5.0,"pid":2,"kind":"exec","exe":"/b","success":true}
"#;
        let (evs, _) = parse_jsonl(input);
        assert_eq!(evs[0].exe, "/b");
    }

    #[test]
    fn bad_lines_do_not_abort() {
        let input = "{\"pid\":1}\nnot json\n{\"pid\":2,\"kind\":\"file\"}\n";
        let (evs, errs) = parse_jsonl(input);
        assert_eq!(evs.len(), 2);
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn extra_fields_are_preserved() {
        let line = r#"{"pid":1,"kind":"exec","success":true,"host":"web01","tty":"pts/0"}"#;
        let (evs, _) = parse_jsonl(line);
        assert_eq!(evs[0].extra.get("host").and_then(|v| v.as_str()), Some("web01"));
    }
}
