//! Plain-text table output (`--plain`) and a rotation-safe live tailer
//! (`--follow`), matching the upstream parser's operator interface.

use crate::model::Event;
use std::io::{Read, Seek, SeekFrom};

/// Columns for the plain table: (header, width, extractor).
type Row<'a> = Vec<String>;

const HEADERS: [&str; 10] = [
    "#", "type", "time", "exe", "commandline", "key", "result", "uid", "pid", "ppid",
];
const WIDTHS: [usize; 10] = [6, 10, 19, 26, 44, 16, 10, 16, 8, 8];

fn row(e: &Event) -> Row<'static> {
    let uid = if e.uid_name.is_empty() {
        e.uid.to_string()
    } else {
        format!("{} ({})", e.uid, e.uid_name)
    };
    vec![
        if e.danger.is_empty() {
            e.seq.to_string()
        } else {
            format!("! {}", e.seq)
        },
        e.kind.clone(),
        e.ts.clone(),
        e.exe.clone(),
        e.cmdline.clone(),
        e.audit_key.clone(),
        if e.auth.as_deref() == Some("failed") {
            "auth failed".to_string()
        } else if e.success {
            "success".to_string()
        } else {
            "failed".to_string()
        },
        uid,
        e.pid.to_string(),
        e.ppid.to_string(),
    ]
}

fn cell(text: &str, width: usize) -> String {
    let t = text.replace(['\t', '\n'], " ");
    if t.chars().count() > width {
        t.chars().take(width.saturating_sub(1)).collect::<String>() + "…"
    } else {
        format!("{t:<width$}")
    }
}

/// Render an aligned table. `flagged_only` mirrors the parser's `--flagged`.
pub fn table(events: &[Event], flagged_only: bool, full: bool) -> String {
    let rows: Vec<Row<'static>> = events
        .iter()
        .filter(|e| !flagged_only || !e.danger.is_empty() || e.auth.as_deref() == Some("failed"))
        .map(row)
        .collect();

    let widths: Vec<usize> = if full {
        (0..HEADERS.len())
            .map(|i| {
                rows.iter()
                    .map(|r| r[i].chars().count())
                    .chain(std::iter::once(HEADERS[i].len()))
                    .max()
                    .unwrap_or(WIDTHS[i])
            })
            .collect()
    } else {
        WIDTHS.to_vec()
    };

    let mut out = String::new();
    out.push_str(
        &HEADERS
            .iter()
            .enumerate()
            .map(|(i, h)| cell(h, widths[i]))
            .collect::<Vec<_>>()
            .join(" | "),
    );
    out.push('\n');
    out.push_str(&"-".repeat(widths.iter().sum::<usize>() + 3 * (HEADERS.len() - 1)));
    out.push('\n');
    for r in &rows {
        out.push_str(
            &r.iter()
                .enumerate()
                .map(|(i, c)| cell(c, widths[i]))
                .collect::<Vec<_>>()
                .join(" | "),
        );
        out.push('\n');
    }
    let flagged = events.iter().filter(|e| !e.danger.is_empty()).count();
    if flagged > 0 && !flagged_only {
        out.push_str(&format!(
            "\n{flagged} flagged (potentially dangerous) event(s)\n"
        ));
    }
    out
}

/// Aggregated auth-failure view: one row per (account, source, reason) so a
/// brute force reads as a single line with a count, not 200 rows.
pub fn auth_failure_table(failures: &[crate::ingest::AuthFailure]) -> String {
    use std::collections::BTreeMap;
    /// (count, first ts, last ts)
    type Agg = (u64, String, String);
    let mut groups: BTreeMap<(String, String, String, String), Agg> = BTreeMap::new();
    for f in failures {
        let src = if !f.addr.is_empty() {
            f.addr.clone()
        } else if !f.host.is_empty() {
            f.host.clone()
        } else if !f.terminal.is_empty() {
            f.terminal.clone()
        } else {
            "-".to_string()
        };
        let key = (f.acct.clone(), src, f.reason.clone(), f.exe.clone());
        let e = groups.entry(key).or_insert((0, f.ts.clone(), f.ts.clone()));
        e.0 += 1;
        if f.ts < e.1 {
            e.1 = f.ts.clone();
        }
        if f.ts > e.2 {
            e.2 = f.ts.clone();
        }
    }

    let headers = ["acct", "from", "via", "reason", "count", "first", "last"];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for ((acct, src, reason, exe), (count, first, last)) in groups {
        let via = exe.rsplit('/').next().unwrap_or("-").to_string();
        let last_cell = if last == first { String::new() } else { last };
        rows.push(vec![
            if acct.is_empty() { "-".into() } else { acct },
            src,
            via,
            reason,
            count.to_string(),
            first,
            last_cell,
        ]);
    }

    let widths: Vec<usize> = (0..headers.len())
        .map(|i| {
            rows.iter()
                .map(|r| r[i].chars().count())
                .chain(std::iter::once(headers[i].len()))
                .max()
                .unwrap_or(6)
        })
        .collect();

    let mut out = format!(
        "\nAUTH FAILURES  ({} total, {} distinct source(s))\n",
        failures.len(),
        rows.len()
    );
    out.push_str(
        &headers
            .iter()
            .enumerate()
            .map(|(i, h)| cell(h, widths[i]))
            .collect::<Vec<_>>()
            .join(" | "),
    );
    out.push('\n');
    out.push_str(&"-".repeat(widths.iter().sum::<usize>() + 3 * (headers.len() - 1)));
    out.push('\n');
    for r in &rows {
        out.push_str(
            &r.iter()
                .enumerate()
                .map(|(i, c)| cell(c, widths[i]))
                .collect::<Vec<_>>()
                .join(" | "),
        );
        out.push('\n');
    }
    out
}

/// Follow a growing log file, tolerating logrotate's rename/create and
/// truncation (inode change or size shrink ⇒ reopen from the start).
pub struct Follower {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    inode: u64,
    pos: u64,
    buf: String,
}

impl Follower {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let mut f = Follower {
            path: std::path::PathBuf::from(path),
            file: None,
            inode: 0,
            pos: 0,
            buf: String::new(),
        };
        f.reopen(true)?;
        Ok(f)
    }

    #[cfg(unix)]
    fn stat_ino(path: &std::path::Path) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    fn stat_ino(_path: &std::path::Path) -> Option<u64> {
        None
    }

    fn reopen(&mut self, seek_end: bool) -> std::io::Result<()> {
        let mut file = std::fs::File::open(&self.path)?;
        if seek_end {
            self.pos = file.seek(SeekFrom::End(0))?;
        } else {
            self.pos = 0;
        }
        self.inode = Self::stat_ino(&self.path).unwrap_or(0);
        self.file = Some(file);
        Ok(())
    }

    /// Read whatever is new; returns complete lines only.
    pub fn poll(&mut self) -> Vec<String> {
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let ino = Self::stat_ino(&self.path).unwrap_or(0);
        if self.file.is_none() || (self.inode != 0 && ino != self.inode) || size < self.pos {
            let _ = self.reopen(false);
        }
        let mut lines = Vec::new();
        if let Some(f) = self.file.as_mut() {
            let _ = f.seek(SeekFrom::Start(self.pos));
            let mut chunk = String::new();
            if f.read_to_string(&mut chunk).is_ok() {
                self.pos += chunk.len() as u64;
                self.buf.push_str(&chunk);
                while let Some(nl) = self.buf.find('\n') {
                    let line: String = self.buf.drain(..=nl).collect();
                    let t = line.trim_end();
                    if !t.is_empty() {
                        lines.push(t.to_string());
                    }
                }
            }
        }
        lines
    }
}

/// Run `--follow`: parse incrementally and hand each batch to `on_batch`.
/// Returns when `should_stop` reports true (set by the signal handler), so a
/// Ctrl-C ends the tail cleanly and the caller can print a final summary.
pub fn follow<F, S>(path: &str, mut on_batch: F, should_stop: S) -> std::io::Result<()>
where
    F: FnMut(&[String]),
    S: Fn() -> bool,
{
    let mut follower = Follower::open(path)?;
    loop {
        if should_stop() {
            return Ok(());
        }
        let lines = follower.poll();
        if !lines.is_empty() {
            on_batch(&lines);
        }
        // sleep in short slices so a signal is noticed promptly
        for _ in 0..4 {
            if should_stop() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ev(seq: u64, kind: &str) -> Event {
        Event {
            seq,
            kind: kind.into(),
            row_kind: kind.into(),
            ts: "2026-05-28 20:26:52".into(),
            exe: "/bin/cat".into(),
            cmdline: "cat /etc/shadow".into(),
            uid: 1000,
            uid_name: "alice".into(),
            pid: 100,
            ppid: 1,
            success: true,
            ..Default::default()
        }
    }

    #[test]
    fn table_renders_headers_and_rows() {
        let out = table(&[ev(1, "exec")], false, false);
        assert!(out.contains("commandline"));
        assert!(out.contains("cat /etc/shadow"));
        assert!(out.contains("1000 (alice)"), "ENRICHED name must appear");
    }

    #[test]
    fn flagged_only_filters() {
        let mut a = ev(1, "exec");
        let b = ev(2, "exec");
        a.danger.push("recursive rm".into());
        let out = table(&[a, b], true, false);
        assert!(out.contains("! 1"));
        assert!(!out.contains("  2 "), "unflagged row must be filtered out");
    }

    #[test]
    fn auth_failed_shows_in_result_column() {
        let mut a = ev(1, "exec");
        a.auth = Some("failed".into());
        a.success = true;
        let out = table(&[a], false, false);
        // the result column is 10 wide, so the label is elided
        assert!(out.contains("auth fail"), "result column must show the auth verdict: {out}");
    }

    #[test]
    fn full_mode_widens_columns() {
        let mut a = ev(1, "exec");
        a.cmdline = "x".repeat(200);
        let out = table(&[a], false, true);
        assert!(out.contains(&"x".repeat(200)), "--full must not truncate");
    }

    #[test]
    fn follower_reads_appended_lines() {
        let dir = std::env::temp_dir().join(format!("tombolo-follow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        std::fs::write(&path, "line one\n").unwrap();

        let mut f = Follower::open(path.to_str().unwrap()).unwrap();
        // opening seeks to end, so pre-existing content is not replayed
        assert!(f.poll().is_empty());

        let mut handle = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(handle, "line two").unwrap();
        handle.flush().unwrap();

        let got = f.poll();
        assert_eq!(got, vec!["line two".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn follower_survives_truncation() {
        let dir = std::env::temp_dir().join(format!("tombolo-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        std::fs::write(&path, "aaaa\nbbbb\n").unwrap();

        let mut f = Follower::open(path.to_str().unwrap()).unwrap();
        // simulate logrotate truncate + rewrite
        std::fs::write(&path, "cccc\n").unwrap();
        let got = f.poll();
        assert!(
            got.iter().any(|l| l.contains("cccc")),
            "truncated file must be re-read from the start; got {got:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
