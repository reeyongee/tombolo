//! Raw `auditd` ingest — a Rust port of `lab5terr/auditd-log-parser`, minus its
//! curses TUI (replaced by `tui.rs`) and with arch-exact syscall typing.
//!
//! Faithful behaviours carried over:
//!   * multi-record event correlation keyed on the *full* audit id
//!     (`epoch:serial`), never on record adjacency;
//!   * hex field decoding and `ENRICHED` (`0x1D`-separated) name fields;
//!   * `EXECVE` argv reconstruction including split `a1[k]` chunks;
//!   * `proctitle` fallback;
//!   * per-arch `arch=`/`syscall=` resolution (syscall-typing fix);
//!   * danger heuristics (recursive rm, pipe-to-shell, auditd disable, …);
//!   * the sudo/su/doas `execve success=yes` + later PAM denial join.

use crate::model::Event;
use crate::syscall::{self, SysKind};
use crate::timefmt::fmt_epoch;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btype=(\S+)").unwrap());
static MSG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)").unwrap());
static FIELD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([^\s=]+)=("(?:[^"\\]|\\.)*"|\([^)]*\)|\S+)"#).unwrap());
static PAM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bmsg='([^']*)'").unwrap());
static SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\):\s*").unwrap());
static AINDEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^a(\d+)$").unwrap());
static ASPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^a(\d+)\[(\d+)\]$").unwrap());
static HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-Fa-f]+$").unwrap());
static DANGER_RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    // NOTE: the `regex` crate has no lookbehind. An earlier revision used
    // `(?<!\S)-c\s+` for "after -c", which fails to compile and was silently
    // dropped — taking the whole rule with it. Replaced with an explicit
    // `\s-c\s+` (whitespace before `-c`), and `add` now panics on a bad
    // pattern instead of skipping it.
    let cmd_pos = r"(?:^|[;|&]\s*|\b(?:sudo|xargs|env)\s+|\s-c\s+)";
    let mut v: Vec<(Regex, &'static str)> = Vec::new();
    let mut add = |pat: String, label: &'static str| {
        let rx = Regex::new(&pat).unwrap_or_else(|e| panic!("bad danger regex {pat:?}: {e}"));
        v.push((rx, label));
    };
    add(
        format!(r"{cmd_pos}rm\s+(?:-\S+\s+)*(?:-[a-zA-Z]*r|--recursive\b)"),
        "recursive rm",
    );
    add(
        format!(r"{cmd_pos}(?:useradd|userdel|usermod|groupadd|passwd|chpasswd)\b"),
        "account/password change",
    );
    add(r"\bmkfs(?:\.\w+)?\s".into(), "filesystem format");
    add(r"\bdd\s[^|;&]*\bof=/dev/(?:sd|nvme|vd|hd|mmcblk)".into(), "dd to raw disk");
    add(
        r"(?:curl|wget|fetch)\s[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|perl|ruby)(?:\s|$)".into(),
        "pipe download to interpreter",
    );
    add(
        r"\b(?:base64|xxd|openssl enc)\b[^|]*\|\s*(?:sh|bash)(?:\s|$)".into(),
        "decode then execute",
    );
    add(r"/dev/(?:tcp|udp)/[\w.\-]+/\d+".into(), "shell network socket");
    add(r"\b(?:nc|ncat|netcat)\s[^|;]*\s-[a-zA-Z]*e[a-zA-Z]*\s".into(), "netcat with -e");
    add(r"/etc/sudoers\b".into(), "sudoers change");
    add(r"/etc/(?:shadow|gshadow)\b".into(), "credential file access");
    add(r"\bauthorized_keys\b".into(), "authorized_keys change");
    add(r"\bsetenforce\s+0\b|\bselinux=0\b|\benforcing=0\b".into(), "SELinux disabled");
    add(
        r"\b(?:iptables|ip6tables)\s[^|;]*?(?:-F\b|--flush\b)|\bnft\s+flush\b".into(),
        "firewall flush",
    );
    add(
        r"\bauditctl\s+-e\s*0\b|\bpkill\s+\S*auditd\b|\bservice\s+auditd\s+stop\b".into(),
        "auditd disabled",
    );
    add(r"\bauditctl\b".into(), "audit config change");
    add(r"/etc/audit\b".into(), "audit config file touched");
    add(
        r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*\S*\.bash_history\b".into(),
        "shell history cleared",
    );
    add(
        r"(?:>|truncate\s[^;|]*|rm\s[^;|]*)\s*/var/log/".into(),
        "log files wiped",
    );
    add(r"\bcrontab\s+-r\b".into(), "crontab removed");
    add(
        r"\bsudo\s+(?:-i|-s|su|bash|sh)(?:\s|$)|\bsudo\s+-u\s+root\s+(?:sh|bash)\b".into(),
        "root shell via sudo",
    );
    add(
        r"\b(?:tar|zip|7z)\b[^|;]*\s(?:.*)(?:\.aws|\.ssh|/etc/|\.kube|\.gnupg)".into(),
        "archive of sensitive scope",
    );
    v
});

const INTERP_SEP: char = '\x1d';

const EXEC_RECORD_TYPES: [&str; 6] =
    ["SYSCALL", "EXECVE", "CWD", "PROCTITLE", "PATH", "SOCKADDR"];
const SESSION_RECORD_TYPES: [&str; 7] = [
    "LOGIN",
    "USER_LOGIN",
    "USER_START",
    "USER_END",
    "USER_ACCT",
    "USER_AUTH",
    "USER_ERR",
];
const ACCOUNT_RECORD_TYPES: [&str; 14] = [
    "USER_MGMT",
    "GRP_MGMT",
    "ADD_USER",
    "DEL_USER",
    "ADD_GROUP",
    "DEL_GROUP",
    "CHGRP_ID",
    "CHUSER_ID",
    "USER_CHAUTHTOK",
    "USER_ADD",
    "GRP_ADD",
    "GRP_DEL",
    "GRP_CHAUTHTOK",
    "ACCT_LOCK",
];
const SERVICE_RECORD_TYPES: [&str; 2] = ["SERVICE_START", "SERVICE_STOP"];
const ANOM_RECORD_TYPES: [&str; 3] = ["ANOM_PROMISCUOUS", "ANOM_LOGIN_FAILURES", "ANOM_ABEND"];
/// Account records that mean "a user was created" for rule LT003.
const USER_ADD_TYPES: [&str; 3] = ["ADD_USER", "USER_ADD", "USER_MGMT"];

const ESCALATION_TOOLS: [&str; 4] = ["sudo", "su", "sudo-rs", "doas"];
/// Network-facing danger strings reused by the TUI/flag column.
const AUTH_FAILED_FLAG: &str = "authentication failed";
/// Window (seconds) in which a PAM outcome is attributed to an escalation exec.
const AUTH_WINDOW: f64 = 30.0;

// --------------------------------------------------------------------------- //
// field / hex helpers
// --------------------------------------------------------------------------- //

/// Unquote a field value and normalise auditd placeholders.
pub fn unq(val: &str) -> String {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        return val[1..val.len() - 1].to_string();
    }
    if val == "(null)" || val == "(none)" {
        return String::new();
    }
    val.to_string()
}

/// Decode an auditd string field: quoted literal, or hex-encoded bytes.
pub fn audit_decode(raw: &str, nul_to_space: bool) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return raw[1..raw.len() - 1].to_string();
    }
    if raw == "(null)" || raw == "(none)" || raw == "?" {
        return String::new();
    }
    if HEX_RE.is_match(raw) && raw.len().is_multiple_of(2) {
        let mut bytes = Vec::with_capacity(raw.len() / 2);
        let b = raw.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            let hi = (b[i] as char).to_digit(16);
            let lo = (b[i + 1] as char).to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => bytes.push((h * 16 + l) as u8),
                _ => return raw.to_string(),
            }
            i += 2;
        }
        let text = String::from_utf8_lossy(&bytes).to_string();
        return if nul_to_space {
            text.replace('\u{0}', " ").trim().to_string()
        } else {
            text
        };
    }
    raw.to_string()
}

fn clean(v: &str) -> String {
    let u = unq(v);
    match u.as_str() {
        "?" | "unset" | "none" | "(none)" | "(null)" | "(unknown)" => String::new(),
        _ => u,
    }
}

fn field_str(v: &str) -> String {
    clean(&audit_decode(v, true))
}

fn parse_fields(blob: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for c in FIELD_RE.captures_iter(blob) {
        out.insert(c[1].to_string(), c[2].to_string());
    }
    out
}

fn to_int(v: &str, default: i64) -> i64 {
    v.trim().parse::<i64>().unwrap_or(default)
}

/// Reconstruct argv from an `EXECVE` record (`a0`, `a1`, …, and split `a1[k]`).
fn build_cmdline(fields: &BTreeMap<String, String>) -> String {
    let mut args: BTreeMap<u32, String> = BTreeMap::new();
    let mut chunks: BTreeMap<u32, BTreeMap<u32, String>> = BTreeMap::new();
    for (k, v) in fields {
        if let Some(c) = AINDEX_RE.captures(k) {
            if let Ok(i) = c[1].parse::<u32>() {
                args.insert(i, audit_decode(v, false));
            }
            continue;
        }
        if let Some(c) = ASPLIT_RE.captures(k) {
            let i: u32 = c[1].parse().unwrap_or(0);
            let j: u32 = c[2].parse().unwrap_or(0);
            chunks.entry(i).or_default().insert(j, v.clone());
        }
    }
    for (i, parts) in chunks {
        let joined: String = parts.values().map(|p| audit_decode(p, false)).collect();
        args.insert(i, joined);
    }
    args.values().cloned().collect::<Vec<_>>().join(" ")
}

// --------------------------------------------------------------------------- //
// danger heuristics (ported subset of classify_danger)
// --------------------------------------------------------------------------- //

fn danger_exe(base: &str) -> Option<&'static str> {
    Some(match base {
        "shred" => "secure file wipe",
        "wipefs" => "disk signature wipe",
        "blkdiscard" => "disk discard",
        "useradd" | "userdel" | "usermod" => "user/group change",
        "groupadd" | "groupdel" => "user/group change",
        "passwd" | "chpasswd" => "password change",
        "visudo" => "sudoers change",
        "setenforce" => "SELinux mode change",
        "insmod" => "kernel module insert",
        "auditctl" => "audit config change",
        _ => return None,
    })
}

/// Paths whose access is analytically interesting regardless of noise rules:
/// credential stores, keys, history files, persistence locations. Mirrors the
/// taint engine's source list so the two agree on what matters.
pub fn is_sensitive_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        ".aws/credentials",
        ".config/gcloud",
        ".azure/",
        ".kube/config",
        "/.ssh/",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        ".ssh/authorized_keys",
        ".gnupg",
        ".kdbx",
        ".env",
        ".bash_history",
        ".mysql_history",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/cron",
        "/etc/systemd/system",
        "cookies",
        "login-data",
        ".p12",
        ".pfx",
    ];
    NEEDLES.iter().any(|n| p.contains(n))
}

/// High-churn system paths that carry no data-flow signal. `/proc` and `/sys`
/// are read constantly by every monitoring agent; `/dev` and `/run` are socket
/// and device plumbing; the dynamic loader map churns on every process start.
/// Built-in noise prefixes: paths read constantly by every monitoring agent and
/// carrying no data-flow signal. Overridable with `--exclude`/`--replace-noise`.
pub const DEFAULT_NOISE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/run/",
    "/tmp/.X11-unix/",
    "/usr/lib/locale/",
    "/etc/ld.so.cache",
    "/usr/lib/",
    "/lib/",
    "/usr/share/",
];

/// Tunable filters for ingest. `include_noise` disables the system-path filter
/// entirely (audit everything); `extra_noise` adds operator-supplied prefixes;
/// `replace_noise` drops the built-ins so only `extra_noise` applies.
#[derive(Debug, Clone, Default)]
pub struct IngestConfig {
    pub include_noise: bool,
    pub extra_noise: Vec<String>,
    pub replace_noise: bool,
}

impl IngestConfig {
    /// True when the operator *explicitly* named this path as noise. An explicit
    /// `--exclude` overrides the sensitive-path protection, because the operator
    /// asked for it by name (e.g. excluding a noisy monitoring agent that reads
    /// credential files every minute).
    pub fn is_explicitly_excluded(&self, path: &str) -> bool {
        !self.include_noise
            && self
                .extra_noise
                .iter()
                .any(|pre| path.starts_with(pre.as_str()))
    }

    /// Is this path noise under the current configuration?
    pub fn is_noise(&self, path: &str) -> bool {
        if self.include_noise {
            return false;
        }
        let builtin: &[&str] = if self.replace_noise {
            &[]
        } else {
            DEFAULT_NOISE_PREFIXES
        };
        if builtin.iter().any(|pre| path.starts_with(pre)) {
            return true;
        }
        if self
            .extra_noise
            .iter()
            .any(|pre| path.starts_with(pre.as_str()))
        {
            return true;
        }
        // loader/library map files, unless the operator replaced the list
        !self.replace_noise
            && (path.ends_with(".so") || path.contains(".so.") || path.ends_with("ld.so.cache"))
    }
}

/// Convenience wrapper using the default configuration.
pub fn is_system_noise(path: &str) -> bool {
    IngestConfig::default().is_noise(path)
}

/// Reasons a command looks dangerous (mirrors the parser's `classify_danger`).
pub fn classify_danger(exe: &str, cmd: &str) -> Vec<String> {
    let text = format!("{cmd} {exe}");
    let mut seen: Vec<String> = Vec::new();
    let base = exe.rsplit('/').next().unwrap_or(exe);
    if let Some(label) = danger_exe(base) {
        seen.push(label.to_string());
    } else if base.starts_with("mkfs") {
        seen.push("filesystem format".to_string());
    }
    for (rx, lab) in DANGER_RULES.iter() {
        if !seen.iter().any(|s| s == lab) && rx.is_match(&text) {
            seen.push((*lab).to_string());
        }
    }
    for w in ["/tmp/", "/dev/shm/", "/var/tmp/"] {
        if exe.starts_with(w) {
            seen.push("binary in world-writable dir".to_string());
            break;
        }
    }
    seen
}

// --------------------------------------------------------------------------- //
// ingest model
// --------------------------------------------------------------------------- //

/// A rejected authentication, as reported by auditd's PAM records.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthFailure {
    pub ts: String,
    pub epoch: f64,
    pub acct: String,
    pub addr: String,
    pub host: String,
    pub terminal: String,
    pub exe: String,
    pub reason: String,
}

#[derive(Default)]
struct Builder {
    /// Which feed batch last touched this builder. A builder untouched for more
    /// than one batch is considered complete and is finalized, so a tailing
    /// session emits events without waiting for `finish()`.
    gen: u64,
    epoch: f64,
    types: Vec<String>,
    fields: BTreeMap<String, BTreeMap<String, String>>,
    raw: Vec<String>,
}

impl Builder {
    fn add(&mut self, rec_type: &str, fields: BTreeMap<String, String>, raw: &str) {
        if !self.types.iter().any(|t| t == rec_type) {
            self.types.push(rec_type.to_string());
        }
        self.fields
            .entry(rec_type.to_string())
            .or_default()
            .extend(fields);
        self.raw.push(raw.to_string());
    }
}

#[derive(Default)]
pub struct Ingest {
    config: IngestConfig,
    pending: BTreeMap<String, Builder>,
    order: Vec<String>,
    events: Vec<Event>,
    errors: Vec<String>,
    /// pid -> (epoch, ok) of the LAST `USER_AUTH` outcome seen.
    auth_last: BTreeMap<u32, (f64, bool)>,
    /// Rejected authentications, in arrival order.
    auth_failures: Vec<AuthFailure>,
    /// Monotonic feed-batch counter, used to age out completed builders.
    gen: u64,
}

impl Ingest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest with operator-tunable filters.
    pub fn with_config(config: IngestConfig) -> Self {
        Ingest {
            config,
            ..Default::default()
        }
    }

    fn record_fields(line: &str) -> BTreeMap<String, String> {
        let body = match SPLIT_RE.splitn(line, 2).nth(1) {
            Some(b) => b,
            None => line,
        };
        let mut fields = BTreeMap::new();
        for chunk in body.split(INTERP_SEP) {
            fields.extend(parse_fields(chunk));
        }
        if let Some(c) = PAM_RE.captures(body) {
            fields.extend(parse_fields(&c[1]));
        }
        fields
    }

    /// Feed one line, keeping all accumulator state for the next call. This is
    /// the streaming entry point used by `--follow`: state persists across
    /// batches, so no window needs re-parsing and no duplicate events are
    /// produced.
    pub fn feed_line(&mut self, line: &str) {
        self.gen += 1;
        let l = line.trim_end();
        if l.is_empty() || l.trim_start().starts_with('#') {
            return;
        }
        if !l.contains("type=") && !l.contains("msg=audit(") {
            let preview: String = l.chars().take(60).collect();
            self.errors.push(format!("unparseable line: {preview}"));
            return;
        }
        self.feed(l);
    }

    /// Drain the events completed so far (call after each batch). Pending
    /// builders stay pending, so a record split across batches is still joined.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Finalize builders that this batch did not touch.
    ///
    /// auditd writes all records of one event with the same audit id, normally
    /// adjacent, so a builder quiet for a whole batch is complete. One
    /// generation of grace keeps a record split across two reads (a buffer
    /// boundary) joinable. Returns nothing; call `take_events` afterwards.
    pub fn flush_idle(&mut self) {
        let current = self.gen;
        let stale: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, b)| b.gen + 1 < current)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.finalize(&k);
        }
    }

    /// Completed events, for streaming output.
    pub fn auth_failures(&self) -> &[AuthFailure] {
        &self.auth_failures
    }

    pub fn feed(&mut self, line: &str) {
        let rec_type = TYPE_RE
            .captures(line)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "?".to_string());

        if SESSION_RECORD_TYPES.contains(&rec_type.as_str()) {
            self.session_record(&rec_type, line);
            return;
        }
        if ACCOUNT_RECORD_TYPES.contains(&rec_type.as_str())
            || SERVICE_RECORD_TYPES.contains(&rec_type.as_str())
            || ANOM_RECORD_TYPES.contains(&rec_type.as_str())
            || rec_type == "CONFIG_CHANGE"
        {
            self.system_record(&rec_type, line);
            return;
        }
        if !EXEC_RECORD_TYPES.contains(&rec_type.as_str()) {
            return;
        }
        let Some(msg) = MSG_RE.captures(line) else {
            return;
        };
        let epoch: f64 = msg[1].parse().unwrap_or(0.0);
        let key = format!("{}:{}", &msg[1], &msg[2]);
        let fields = Self::record_fields(line);
        let gen = self.gen;
        let entry = self.pending.entry(key.clone()).or_insert_with(|| {
            Builder {
                gen,
                epoch,
                ..Default::default()
            }
        });
        entry.gen = gen;
        if !self.order.contains(&key) {
            self.order.push(key.clone());
        }
        entry.add(&rec_type, fields, line.trim_end());
    }

    fn session_record(&mut self, rec_type: &str, line: &str) {
        let Some(msg) = MSG_RE.captures(line) else {
            return;
        };
        let epoch: f64 = msg[1].parse().unwrap_or(0.0);
        let f = Self::record_fields(line);
        let res = f.get("res").map(|v| unq(v)).unwrap_or_default();
        let pid = to_int(f.get("pid").map(String::as_str).unwrap_or(""), -1);
        if rec_type == "USER_AUTH" && pid >= 0 {
            // last outcome wins: a typo-then-retry must not stay "failed"
            self.auth_last.insert(pid as u32, (epoch, res != "failed"));
        }
        // Record every rejection for the auth-failure view. `USER_ERR` carries
        // PAM's bad_ident etc.; `USER_LOGIN` failures are remote rejections.
        let failed = match rec_type {
            "USER_AUTH" | "USER_LOGIN" => res == "failed",
            "USER_ACCT" => res == "failed" || res == "0",
            "USER_ERR" => true,
            _ => false,
        };
        if failed {
            self.auth_failures.push(AuthFailure {
                ts: fmt_epoch(epoch),
                epoch,
                acct: field_str(f.get("acct").map(String::as_str).unwrap_or("")),
                addr: clean(f.get("addr").map(String::as_str).unwrap_or("")),
                host: field_str(f.get("hostname").map(String::as_str).unwrap_or("")),
                terminal: field_str(f.get("terminal").map(String::as_str).unwrap_or("")),
                exe: field_str(f.get("exe").map(String::as_str).unwrap_or("")),
                reason: if rec_type == "USER_ERR" {
                    clean(f.get("op").map(String::as_str).unwrap_or("")).replace("PAM:", "")
                } else {
                    "auth failed".to_string()
                },
            });
        }
    }

    fn system_record(&mut self, rec_type: &str, line: &str) {
        let Some(msg) = MSG_RE.captures(line) else {
            return;
        };
        let epoch: f64 = msg[1].parse().unwrap_or(0.0);
        let f = Self::record_fields(line);
        let res = f.get("res").map(|v| unq(v)).unwrap_or_else(|| "-".into());
        let pid = to_int(f.get("pid").map(String::as_str).unwrap_or(""), 0) as u32;
        let uid = to_int(f.get("auid").map(String::as_str).unwrap_or(""), -1);

        let (kind, row_kind, exe, cmd, target) =
            if ACCOUNT_RECORD_TYPES.contains(&rec_type) {
                let op = clean(f.get("op").map(String::as_str).unwrap_or(""));
                let id = clean(f.get("id").map(String::as_str).unwrap_or(""));
                let target = if id.is_empty() {
                    field_str(f.get("acct").map(String::as_str).unwrap_or(""))
                } else {
                    id
                };
                let tool = field_str(f.get("exe").map(String::as_str).unwrap_or(""));
                let tool = tool.rsplit('/').next().unwrap_or(&tool).to_string();
                let k = if USER_ADD_TYPES.contains(&rec_type) {
                    "user-add"
                } else {
                    "account"
                };
                (
                    k.to_string(),
                    "account".to_string(),
                    tool,
                    format!("{} {}", if op.is_empty() { rec_type.to_lowercase() } else { op }, target),
                    target,
                )
            } else if SERVICE_RECORD_TYPES.contains(&rec_type) {
                let unit = field_str(f.get("unit").map(String::as_str).unwrap_or(""));
                let action = if rec_type == "SERVICE_START" { "started" } else { "stopped" };
                ("service".to_string(), "service".to_string(), "-".to_string(),
                 format!("{unit} {action}"), unit)
            } else if rec_type == "CONFIG_CHANGE" {
                let op = clean(f.get("op").map(String::as_str).unwrap_or(""));
                let detail = if op == "add_rule" || op == "remove_rule" {
                    clean(f.get("key").map(String::as_str).unwrap_or(""))
                } else {
                    op.clone()
                };
                ("config".to_string(), "config".to_string(), "-".to_string(),
                 format!("{op}: {detail}"), detail)
            } else {
                ("anomaly".to_string(), "anomaly".to_string(), "-".to_string(),
                 rec_type.to_lowercase(), String::new())
            };

        let success = res == "success" || res == "1" || res == "-";
        let mut danger = Vec::new();
        if res == "failed" || res == "0" {
            danger.push("failed account/group change".to_string());
        }
        if kind == "config" || cmd.contains("audit") {
            danger.push("audit config change".to_string());
        }

        self.events.push(Event {
            seq: 0,
            ts: fmt_epoch(epoch),
            epoch: Some(epoch),
            pid,
            ppid: 0,
            uid,
            kind,
            row_kind,
            exe,
            cmdline: cmd,
            target,
            success,
            audit_id: format!("{}:{}", &msg[1], &msg[2]),
            uid_name: unq(f.get("UID").map(String::as_str).unwrap_or("")),
            danger,
            raw: vec![line.trim_end().to_string()],
            auth: None,
            ..Default::default()
        });
    }

    fn finalize(&mut self, key: &str) {
        let Some(b) = self.pending.remove(key) else {
            return;
        };
        if !b.types.iter().any(|t| t == "SYSCALL") {
            return;
        }
        let sysf = b.fields.get("SYSCALL").cloned().unwrap_or_default();
        let arch = unq(sysf.get("arch").map(String::as_str).unwrap_or(""));
        let nr = unq(sysf.get("syscall").map(String::as_str).unwrap_or(""));
        let is_execve = b.types.iter().any(|t| t == "EXECVE") || syscall::is_execve(&arch, &nr);
        let has_key = !clean(sysf.get("key").map(String::as_str).unwrap_or("")).is_empty();
        let sys_kind = syscall::classify(&arch, &nr);

        // Target (needed by the noise filter below, so computed early).
        let raw_target = b
            .fields
            .get("PATH")
            .and_then(|p| p.get("name"))
            .map(|v| field_str(v))
            .filter(|s| !s.is_empty());

        // DECISION: upstream's parser drops every untagged non-execve
        // syscall to keep its table quiet. That starves the taint engine, which
        // needs file and socket events to follow data flow — so content-bearing
        // syscalls are kept without a `-k` key. Two guard rails keep real logs
        // from flooding:
        //   * metadata syscalls (stat/access/readlink/…) are kept only when
        //     keyed or on a sensitive path;
        //   * paths under /proc, /sys, /dev, /run and the dynamic loader are
        //     noise for data-flow purposes and are dropped unless keyed.
        let explicitly_excluded = raw_target
            .as_deref()
            .map(|p| self.config.is_explicitly_excluded(p))
            .unwrap_or(false);
        let sensitive = raw_target
            .as_deref()
            .map(is_sensitive_path)
            .unwrap_or(false);
        let noisy = raw_target
            .as_deref()
            .map(|p| self.config.is_noise(p))
            .unwrap_or(false);

        let taint_relevant = matches!(
            sys_kind,
            Some(SysKind::File) | Some(SysKind::NetConnect) | Some(SysKind::NetAccept)
                | Some(SysKind::NetSend) | Some(SysKind::NetRecv) | Some(SysKind::Socket)
        );
        let metadata_only = matches!(sys_kind, Some(SysKind::FileMeta));

        if !is_execve {
            if !has_key {
                if !taint_relevant {
                    return; // Other / metadata / unknown: not analytically useful
                }
                // an explicit --exclude beats even the sensitive-path protection
                if explicitly_excluded || (noisy && !sensitive) {
                    return;
                }
            }
            // keyed metadata is kept even though it is noisy — the operator asked
            if metadata_only && !has_key && !sensitive {
                return;
            }
        }

        let exf = b.fields.get("EXECVE").cloned().unwrap_or_default();
        let ptf = b.fields.get("PROCTITLE").cloned().unwrap_or_default();
        let mut exe = unq(sysf.get("exe").map(String::as_str).unwrap_or(""));
        let mut cmd = build_cmdline(&exf);
        if cmd.is_empty() {
            if let Some(p) = ptf.get("proctitle") {
                cmd = audit_decode(p, true);
            }
        }
        if exe.is_empty() {
            exe = cmd
                .split(' ')
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| unq(sysf.get("comm").map(String::as_str).unwrap_or("")));
        }
        if cmd.is_empty() {
            cmd = unq(sysf.get("comm").map(String::as_str).unwrap_or(""));
        }

        let pid = to_int(sysf.get("pid").map(String::as_str).unwrap_or(""), 0) as u32;
        let ppid = to_int(sysf.get("ppid").map(String::as_str).unwrap_or(""), 0) as u32;
        let uid = to_int(unq(sysf.get("uid").map(String::as_str).unwrap_or("")).as_str(), -1);
        let audit_key = unq(sysf.get("key").map(String::as_str).unwrap_or(""))
            .replace('\u{1}', ", ");
        let ses = to_int(sysf.get("ses").map(String::as_str).unwrap_or(""), -1) as i32;
        // ENRICHED carries the originating host's resolved names; prefer them
        // over any local lookup (the latter is wrong for remote logs).
        let uid_name = unq(sysf.get("UID").map(String::as_str).unwrap_or(""));

        let sys_kind = syscall::classify(&arch, &nr);
        let (kind, row_kind) = if is_execve {
            ("exec".to_string(), "exec".to_string())
        } else {
            let k = match sys_kind {
                Some(SysKind::File) => "file",
                Some(SysKind::FileMeta) => "file-meta",
                Some(SysKind::NetConnect) => "net-connect",
                Some(SysKind::NetAccept) => "net-accept",
                Some(SysKind::NetSend) => "net-send",
                Some(SysKind::NetRecv) => "net-recv",
                Some(SysKind::Socket) => "socket",
                _ => "watch",
            };
            (k.to_string(), "watch".to_string())
        };

        // Target: PATH record name, else decoded socket address.
        let target = raw_target
            .clone()
            .or_else(|| {
                if kind.starts_with("net-") || kind == "socket" {
                    b.fields
                        .get("SOCKADDR")
                        .and_then(|s| s.get("saddr"))
                        .and_then(|v| decode_sockaddr(v))
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let success = sysf.get("success").map(|v| unq(v)).unwrap_or_default();
        let exit = to_int(sysf.get("exit").map(String::as_str).unwrap_or(""), 0);
        let ok = match success.as_str() {
            "no" => false,
            "yes" => true,
            _ => exit >= 0,
        };

        let mut danger = classify_danger(&exe, &cmd);

        // Escalation join: a sudo/su/doas execve always "succeeds"; the password
        // check lands later under the same pid. Flag it when the LAST same-pid
        // USER_AUTH denied — and only then (reversible by construction: a later
        // success simply overwrites auth_last, so the flag never appears).
        let base = exe.rsplit('/').next().unwrap_or(&exe).to_string();
        let mut auth = None;
        if is_execve && ESCALATION_TOOLS.contains(&base.as_str()) {
            if let Some((epoch, ok_auth)) = self.auth_last.get(&pid) {
                let within = *epoch - b.epoch;
                if !*ok_auth && (0.0..AUTH_WINDOW).contains(&within) {
                    auth = Some("failed".to_string());
                    danger.push(AUTH_FAILED_FLAG.to_string());
                }
            }
        }
        danger.sort();
        danger.dedup();

        let syscall_name =
            syscall::name(&arch, &nr).unwrap_or("").to_string();

        self.events.push(Event {
            seq: 0,
            ts: fmt_epoch(b.epoch),
            epoch: Some(b.epoch),
            pid,
            ppid,
            uid,
            kind,
            row_kind,
            exe,
            cmdline: cmd,
            target,
            success: ok,
            arch,
            syscall_nr: nr.clone(),
            syscall_name,
            audit_key,
            audit_id: key.to_string(),
            ses,
            uid_name,
            auth,
            danger,
            raw: b.raw,
            extra: BTreeMap::new(),
        });
    }

    pub fn finish(mut self) -> (Vec<Event>, Vec<String>) {
        let keys: Vec<String> = self.order.clone();
        for k in &keys {
            self.finalize(k);
        }
        self.auth_failures.sort_by(|a, b| {
            a.epoch.partial_cmp(&b.epoch).unwrap_or(std::cmp::Ordering::Equal)
        });
        self.events.sort_by(|a, b| {
            let ea = a.epoch.unwrap_or(0.0);
            let eb = b.epoch.unwrap_or(0.0);
            ea.partial_cmp(&eb)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.pid.cmp(&b.pid))
        });
        for (i, e) in self.events.iter_mut().enumerate() {
            e.seq = (i + 1) as u64;
        }
        (self.events, self.errors)
    }
}

/// Decode an auditd `saddr=` hex blob into `ip:port` (AF_INET) or `ip6:port`.
pub fn decode_sockaddr(raw: &str) -> Option<String> {
    let hex = unq(raw);
    if !HEX_RE.is_match(&hex) || !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() < 4 {
        return None;
    }
    // struct sockaddr: u16 family in host byte order (little-endian on x86)
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        2 if bytes.len() >= 8 => {
            // sockaddr_in: port big-endian, then 4 address bytes
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(format!("{ip}:{port}"))
        }
        10 if bytes.len() >= 24 => {
            // sockaddr_in6: port big-endian, then 16 address bytes
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let segs: Vec<String> = (0..8)
                .map(|i| {
                    let o = 8 + i * 2;
                    format!("{:x}", u16::from_be_bytes([bytes[o], bytes[o + 1]]))
                })
                .collect();
            Some(format!("[{}]:{port}", segs.join(":")))
        }
        _ => None,
    }
}

/// Parse a raw `/var/log/audit/audit.log` body (events + parse errors only).
pub fn parse_audit_log(input: &str) -> (Vec<Event>, Vec<String>) {
    let full = parse_audit_log_full(input);
    (full.events, full.errors)
}

/// Parse with operator-tunable filters.
pub fn parse_audit_log_with(input: &str, config: IngestConfig) -> (Vec<Event>, Vec<String>) {
    let full = parse_audit_log_full_with(input, config);
    (full.events, full.errors)
}

/// Everything the ingest produces.
pub struct Ingested {
    pub events: Vec<Event>,
    pub errors: Vec<String>,
    pub auth_failures: Vec<AuthFailure>,
}

/// Parse a raw `/var/log/audit/audit.log` body, retaining auth failures.
pub fn parse_audit_log_full(input: &str) -> Ingested {
    parse_audit_log_full_with(input, IngestConfig::default())
}

/// Parse a raw log with filters applied, retaining auth failures.
pub fn parse_audit_log_full_with(input: &str, config: IngestConfig) -> Ingested {
    let mut ing = Ingest::with_config(config);
    for line in input.lines() {
        let l = line.trim_end();
        if l.is_empty() || l.trim_start().starts_with('#') {
            continue; // comments are documentation, not malformed records
        }
        if !l.contains("type=") && !l.contains("msg=audit(") {
            // Truncate by *characters*, never by bytes: a hostile log can place a
            // multibyte codepoint at the cut point, and byte-slicing panics.
            let preview: String = l.chars().take(60).collect();
            ing.errors.push(format!("unparseable line: {preview}"));
            continue;
        }
        ing.feed(l);
    }
    let auth_failures = ing.auth_failures.clone();
    let (events, errors) = ing.finish();
    Ingested {
        events,
        errors,
        auth_failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_quoted_decode() {
        assert_eq!(audit_decode("\"ls\"", true), "ls");
        assert_eq!(audit_decode("2f62696e2f7368", true), "/bin/sh");
        // NULs become spaces
        assert_eq!(audit_decode("610062", true), "a b");
    }

    #[test]
    fn argv_rebuild_with_split_chunks() {
        // auditd writes split `a1[k]` chunks as bare hex (no quoting), e.g. a
        // long argument broken across records.
        let mut f = BTreeMap::new();
        f.insert("a0".to_string(), "\"cat\"".to_string());
        f.insert("a1[0]".to_string(), "2f657463".to_string()); // "/etc"
        f.insert("a1[1]".to_string(), "2f73686164".to_string()); // "/shad"
        f.insert("a1[2]".to_string(), "6f77".to_string()); // "ow"
        assert_eq!(build_cmdline(&f), "cat /etc/shadow");
    }

    #[test]
    fn argv_rebuild_plain_args() {
        let mut f = BTreeMap::new();
        f.insert("a0".to_string(), "\"tar\"".to_string());
        f.insert("a1".to_string(), "\"-czf\"".to_string());
        f.insert("a2".to_string(), "\"/tmp/out.tar.gz\"".to_string());
        assert_eq!(build_cmdline(&f), "tar -czf /tmp/out.tar.gz");
    }

    #[test]
    fn danger_flags_recursive_rm() {
        assert!(classify_danger("/bin/rm", "rm -rf /var/tmp/x")
            .iter()
            .any(|d| d.contains("recursive rm")));
    }

    #[test]
    fn noise_filter_default_drops_proc_and_loader() {
        let cfg = IngestConfig::default();
        assert!(cfg.is_noise("/proc/1234/status"));
        assert!(cfg.is_noise("/sys/kernel/notes"));
        assert!(cfg.is_noise("/usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!cfg.is_noise("/home/u/.aws/credentials"));
        assert!(!cfg.is_noise("/tmp/.sysupdate.tar.gz"));
    }

    #[test]
    fn include_noise_keeps_everything() {
        let cfg = IngestConfig {
            include_noise: true,
            ..Default::default()
        };
        assert!(!cfg.is_noise("/proc/1/maps"));
        assert!(!cfg.is_noise("/usr/lib/libc.so.6"));
    }

    #[test]
    fn extra_excludes_are_honoured() {
        let cfg = IngestConfig {
            extra_noise: vec!["/opt/vendor/".to_string()],
            ..Default::default()
        };
        assert!(cfg.is_noise("/opt/vendor/noisy.log"));
        assert!(cfg.is_noise("/proc/1/maps"), "built-ins still apply");
        assert!(!cfg.is_noise("/home/u/file"));
    }

    #[test]
    fn replace_noise_keeps_only_operator_list() {
        let cfg = IngestConfig {
            extra_noise: vec!["/opt/".to_string()],
            replace_noise: true,
            ..Default::default()
        };
        assert!(!cfg.is_noise("/proc/1/maps"), "built-ins dropped");
        assert!(!cfg.is_noise("/usr/lib/libc.so.6"), "loader rule dropped");
        assert!(cfg.is_noise("/opt/x"));
    }

    #[test]
    fn noise_filter_applies_during_parse() {
        let log = r#"
type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=257 success=yes exit=3 pid=10 ppid=1 uid=0 comm="m" exe="/bin/m" key=(null)
type=PATH msg=audit(1.0:1): item=0 name="/proc/1/maps"
type=SYSCALL msg=audit(2.0:2): arch=c000003e syscall=257 success=yes exit=3 pid=10 ppid=1 uid=0 comm="m" exe="/bin/m" key=(null)
type=PATH msg=audit(2.0:2): item=0 name="/home/u/secret"
"#;
        let (quiet, _) = parse_audit_log_with(log, IngestConfig::default());
        let (noisy, _) = parse_audit_log_with(
            log,
            IngestConfig {
                include_noise: true,
                ..Default::default()
            },
        );
        assert_eq!(quiet.len(), 1, "/proc event must be filtered by default");
        assert_eq!(noisy.len(), 2, "--include-noise must keep it");
        assert_eq!(quiet[0].target, "/home/u/secret");
    }

    /// Regression: cargo-fuzz found a panic at `parse_audit_log` truncating a
    /// malformed line by *bytes*. The input below ends in a multibyte codepoint
    /// straddling byte 60, so `&l[..60]` panicked on a char boundary. Input is
    /// attacker-controlled (an unprivileged process owns `comm`), so this was a
    /// trivially reachable denial of service.
    #[test]
    fn multibyte_truncation_does_not_panic() {
        let crash: Vec<u8> = vec![
            58, 58, 0, 58, 58, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
            117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
            117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
            117, 117, 117, 117, 0, 0, 0, 58, 214, 174,
        ];
        let text = String::from_utf8_lossy(&crash).to_string();
        let out = parse_audit_log_full_with(&text, IngestConfig::default());
        assert!(out.events.is_empty());
        assert!(!out.errors.is_empty());
    }

    /// Any byte sequence must be survivable, not just this one case.
    #[test]
    fn arbitrary_bytes_never_panic() {
        for n in 0..=64usize {
            for byte in [0u8, 0x3a, 0x7f, 0xc3, 0xd6, 0xae, 0xff] {
                let data: Vec<u8> = std::iter::repeat_n(byte, n).collect();
                let text = String::from_utf8_lossy(&data).to_string();
                let _ = parse_audit_log_full_with(&text, IngestConfig::default());
                let _ = parse_audit_log_full_with(
                    &text,
                    IngestConfig {
                        include_noise: true,
                        ..Default::default()
                    },
                );
            }
        }
    }

    #[test]
    fn unparseable_line_is_reported_not_fatal() {
        let (ev, errs) = parse_audit_log("garbage\n");
        assert!(ev.is_empty());
        assert_eq!(errs.len(), 1);
    }
}
