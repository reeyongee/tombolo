//! Data-flow taint tracking (port of `labtrace::taint`) **with carrier-keyed adoption**.
//!
//! Upstream keeps a trail only while process ancestry holds: the `file` arm
//! records taint on a written carrier only when the writing pid *already* holds
//! taint, and never consults `tainted` on read. A staged drop-and-pickup —
//! attacker writes `/tmp/stage.bin`, an unrelated cron/backup pid later reads it
//! and connects out — is therefore invisible.
//!
//! CORRECTNESS FIX #2 (`carrier-keyed adoption`): when a process reads a path that
//! already carries taint, it adopts those kinds. Carriers are the join key, so
//! the trail crosses process trees.

use crate::model::{Event, TaintFlow, TaintId};
use crate::proctree::ProcTree;
use std::collections::{BTreeMap, BTreeSet};

/// Kinds of sensitive data we track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintKind {
    Credentials,
    CryptoKey,
    SessionToken,
    CloudCredentials,
    DatabaseDump,
    PersonalData,
}

impl TaintKind {
    pub fn label(self) -> &'static str {
        match self {
            TaintKind::Credentials => "credentials",
            TaintKind::CryptoKey => "crypto-key",
            TaintKind::SessionToken => "session-token",
            TaintKind::CloudCredentials => "cloud-credentials",
            TaintKind::DatabaseDump => "database-dump",
            TaintKind::PersonalData => "personal-data",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "credentials" => TaintKind::Credentials,
            "crypto-key" => TaintKind::CryptoKey,
            "session-token" => TaintKind::SessionToken,
            "cloud-credentials" => TaintKind::CloudCredentials,
            "database-dump" => TaintKind::DatabaseDump,
            "personal-data" => TaintKind::PersonalData,
            _ => return None,
        })
    }
}

/// Upper bound on remembered carriers in a streaming session. Credential
/// carriers are few and long-lived, but a hostile or merely busy host can touch
/// thousands of `.so`/`.env` paths; without a cap the state grows without bound
/// over a multi-day tail.
pub const DEFAULT_CARRIER_CAP: usize = 4096;

#[derive(Debug)]
pub struct TaintState {
    pub carriers: BTreeMap<String, BTreeSet<TaintKind>>,
    pub tainted_pids: BTreeMap<u32, BTreeSet<TaintKind>>,
    /// pid that first introduced taint onto each carrier (for provenance).
    pub origin: BTreeMap<String, u32>,
    /// The most recent carrier that conferred taint on a pid. This is what the
    /// flow report should name: for a staged exfil it is the *staging file*, not
    /// the original credentials file.
    pub tainted_by: BTreeMap<u32, String>,
    /// Insertion order of `carriers`, used to evict oldest-first at the cap.
    order: Vec<String>,
    /// Maximum remembered carriers.
    pub carrier_cap: usize,
}

impl Default for TaintState {
    fn default() -> Self {
        TaintState {
            carriers: BTreeMap::new(),
            tainted_pids: BTreeMap::new(),
            origin: BTreeMap::new(),
            tainted_by: BTreeMap::new(),
            order: Vec::new(),
            carrier_cap: DEFAULT_CARRIER_CAP,
        }
    }
}

impl TaintState {
    /// Construct with a specific carrier cap.
    pub fn with_carrier_cap(cap: usize) -> Self {
        TaintState {
            carrier_cap: cap,
            ..Default::default()
        }
    }

    /// Record a carrier, evicting the oldest entries once the cap is exceeded.
    fn note_carrier(&mut self, path: &str, kinds: impl IntoIterator<Item = TaintKind>) {
        if !self.carriers.contains_key(path) {
            self.order.push(path.to_string());
        }
        self.carriers
            .entry(path.to_string())
            .or_default()
            .extend(kinds);
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.carriers.len() > self.carrier_cap {
            // oldest-first; skip anything not present (already evicted)
            let mut victim = None;
            while let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                if self.carriers.contains_key(&oldest) {
                    victim = Some(oldest);
                    break;
                }
            }
            match victim {
                Some(path) => {
                    self.carriers.remove(&path);
                    self.origin.remove(&path);
                }
                None => break,
            }
        }
    }

    pub fn carrier_count(&self) -> usize {
        self.carriers.len()
    }

    pub fn tainted_pid_count(&self) -> usize {
        self.tainted_pids.len()
    }

    /// Drop pids that are no longer seen, so a multi-day tail does not
    /// accumulate dead process ids. `live` is the set of pids in the window.
    pub fn retain_live_pids(&mut self, live: &std::collections::BTreeSet<u32>) {
        self.tainted_pids.retain(|pid, _| live.contains(pid));
        self.tainted_by.retain(|pid, _| live.contains(pid));
    }
}

/// Paths that are sources of sensitive data.
pub fn source_kinds_for_path(path: &str) -> Vec<TaintKind> {
    let p = path.to_ascii_lowercase();
    let mut out = Vec::new();
    if p.contains("/id_rsa")
        || p.contains("/id_ed25519")
        || p.ends_with(".pem")
        || p.contains(".ssh/authorized_keys")
    {
        out.push(TaintKind::Credentials);
    }
    if p.contains("/.ssh/control") || p.contains("/ssh-agent") || p.ends_with(".gnupg") {
        out.push(TaintKind::Credentials);
    }
    if p.contains(".aws/credentials")
        || p.contains(".config/gcloud")
        || p.contains(".azure/")
        || p.contains(".kube/config")
    {
        out.push(TaintKind::CloudCredentials);
    }
    if p.ends_with(".kdbx")
        || p.contains(".gnupg/")
        || p.contains("/keystore")
        || p.ends_with(".p12")
        || p.ends_with(".pfx")
    {
        out.push(TaintKind::CryptoKey);
    }
    if p.contains(".env") && !p.contains("/proc/") {
        out.push(TaintKind::Credentials);
    }
    if p.contains("cookies")
        || p.contains("/login-data")
        || p.contains(".mozilla/")
        || p.contains(".config/google-chrome")
    {
        out.push(TaintKind::SessionToken);
    }
    if p.ends_with(".sql") || p.contains(".mysql/history") || (p.contains("dump") && p.ends_with(".gz")) {
        out.push(TaintKind::DatabaseDump);
    }
    if p.contains(".csv") && (p.contains("customer") || p.contains("user") || p.contains("klient")) {
        out.push(TaintKind::PersonalData);
    }
    out
}

fn is_network_sink(target: &str) -> bool {
    target.contains(':')
}

fn is_archive_sink(target: &str) -> bool {
    let t = target.to_ascii_lowercase();
    t.ends_with(".tar")
        || t.ends_with(".tar.gz")
        || t.ends_with(".tgz")
        || t.ends_with(".zip")
        || t.ends_with(".7z")
}

fn carriers_in_cmdline(cmdline: &str) -> Vec<String> {
    cmdline
        .split_whitespace()
        .filter(|tok| tok.contains('/') && !source_kinds_for_path(tok).is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Run taint propagation over the event stream.
/// Stateless convenience wrapper: fresh state, whole event slice.
pub fn analyze(events: &[Event], tree: &ProcTree) -> Vec<TaintFlow> {
    let mut st = TaintState::default();
    analyze_with_state(events, tree, &mut st)
}

/// Incremental analyzer. `st` is carried across calls so a streaming session
/// does not need to replay history: taint recorded in an earlier batch (for
/// example a carrier written an hour ago) is still known when the pickup event
/// arrives in a later batch.
pub fn analyze_with_state(
    events: &[Event],
    tree: &ProcTree,
    st: &mut TaintState,
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    for e in events {
        if !e.success {
            continue;
        }
        // Fresh process identity: a reused pid must not inherit stale taint.
        // Without this, an untrusted pid could appear tainted because an
        // unrelated earlier process with the same pid touched a secret.
        if e.kind == "exec" {
            // A fresh exec is a fresh process identity for this pid.
            st.tainted_by.remove(&e.pid);
        }
        match e.kind.as_str() {
            "exec" => {
                // inherit from parent, then from any tainted carrier named in argv
                let mut kinds: BTreeSet<TaintKind> = st
                    .tainted_pids
                    .get(&e.ppid)
                    .cloned()
                    .unwrap_or_default();
                for carrier in carriers_in_cmdline(&e.cmdline) {
                    if let Some(ks) = st.carriers.get(&carrier) {
                        kinds.extend(ks.iter().copied());
                    }
                    let direct = source_kinds_for_path(&carrier);
                    if !direct.is_empty() {
                        kinds.extend(direct.iter().copied());
                        st.note_carrier(&carrier, direct.iter().copied());
                        st.origin.entry(carrier).or_insert(e.pid);
                    }
                }
                if !kinds.is_empty() {
                    st.tainted_pids.entry(e.pid).or_default().extend(kinds);
                }
            }
            "file" => {
                let path = e.target.clone();
                let src_kinds = source_kinds_for_path(&path);
                if !src_kinds.is_empty() {
                    // reading a sensitive source taints the reader and the carrier
                    st.note_carrier(&path, src_kinds.iter().copied());
                    st.origin.entry(path.clone()).or_insert(e.pid);
                    st.tainted_pids
                        .entry(e.pid)
                        .or_default()
                        .extend(src_kinds.iter().copied());
                    st.tainted_by.insert(e.pid, path.clone());
                    // a tainted process writing here stains the output too
                    if let Some(held) = st.tainted_pids.get(&e.pid).cloned() {
                        st.note_carrier(&path, held);
                    }
                } else if let Some(adopted) = adopt_from_carrier(st, &path, e.pid) {
                    // CORRECTNESS FIX #2: a clean process picked up an already-tainted
                    // carrier (staged drop-and-pickup across unrelated trees).
                    let mut all = adopted;
                    if let Some(held) = st.tainted_pids.get(&e.pid).cloned() {
                        all = held;
                    }
                    st.tainted_pids.insert(e.pid, all.clone());
                    st.tainted_by.insert(e.pid, path.clone());
                    if is_archive_sink(&path) {
                        for k in &all {
                            let origin = st.origin.get(&path).copied().unwrap_or(e.pid);
                            flows.push(flow_carrier(e, tree, *k, path.clone(), "archive-write", &path, origin));
                        }
                    }
                } else if let Some(held) = st.tainted_pids.get(&e.pid).cloned() {
                    // tainted process wrote a file -> the file is tainted (staging)
                    st.note_carrier(&path, held.iter().copied());
                    st.origin.entry(path.clone()).or_insert(e.pid);
                    st.tainted_by.insert(e.pid, path.clone());
                    if is_archive_sink(&path) {
                        for k in &held {
                            let origin = st.origin.get(&path).copied().unwrap_or(e.pid);
                            flows.push(flow_carrier(e, tree, *k, path.clone(), "archive-write", &path, origin));
                        }
                    }
                }
            }
            // Any egress primitive that carries a remote address is an
            // exfiltration sink: connect, sendto/sendmsg, and accept (a
            // reverse shell receives on an accepted socket).
            "net-connect" | "net-send" | "net-accept" => {
                let held = st
                    .tainted_pids
                    .get(&e.pid)
                    .cloned()
                    .or_else(|| st.tainted_pids.get(&e.ppid).cloned())
                    .unwrap_or_default();
                if !held.is_empty() && is_network_sink(&e.target) {
                    let sink_kind = if e.kind == "net-accept" {
                        "net-accept"
                    } else {
                        "net-exfil"
                    };
                    // name the carrier that actually brought the data here
                    let carrier = st.tainted_by.get(&e.pid).cloned().unwrap_or_default();
                    let origin = st.origin.get(&carrier).copied().unwrap_or(e.pid);
                    for k in held {
                        flows.push(flow_carrier(
                            e,
                            tree,
                            k,
                            e.target.clone(),
                            sink_kind,
                            &carrier,
                            origin,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    flows
}

/// CORRECTNESS FIX #2 — adopt taint from a carrier this path already holds.
fn adopt_from_carrier(
    st: &mut TaintState,
    path: &str,
    pid: u32,
) -> Option<BTreeSet<TaintKind>> {
    let kinds = st.carriers.get(path).cloned().unwrap_or_default();
    if kinds.is_empty() {
        return None;
    }
    st.tainted_pids.entry(pid).or_default().extend(kinds.iter().copied());
    Some(kinds)
}

fn flow_carrier(
    e: &Event,
    tree: &ProcTree,
    kind: TaintKind,
    target: String,
    sink_kind: &str,
    carrier: &str,
    origin_pid: u32,
) -> TaintFlow {
    let origin = origin_pid;
    TaintFlow {
        taint: TaintId {
            kind: kind.label().to_string(),
            origin_pid: origin,
            carrier: carrier.to_string(),
        },
        sink_pid: e.pid,
        origin_pid: origin,
        sink_seq: e.seq,
        sink_kind: sink_kind.into(),
        sink_target: target,
        chain: tree.chain_str(e.pid),
        carrier: carrier.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, pid: u32, ppid: u32, kind: &str, exe: &str, target: &str, cmdline: &str) -> Event {
        Event {
            seq,
            pid,
            ppid,
            kind: kind.into(),
            exe: exe.into(),
            cmdline: cmdline.into(),
            target: target.into(),
            success: true,
            ..Default::default()
        }
    }

    #[test]
    fn exfiltration_chain_detected() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/bin/sh", "", "sh"),
            ev(2, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat ~/.aws/credentials"),
            ev(3, 100, 1, "file", "/bin/tar", "/tmp/staging.tar.gz", "tar -czf /tmp/staging.tar.gz"),
            ev(4, 100, 1, "net-connect", "/usr/bin/curl", "185.199.108.153:443", "curl https://evil.example"),
        ];
        let tree = ProcTree::build(&evs);
        let flows = analyze(&evs, &tree);
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == "net-exfil" && f.taint.kind == "cloud-credentials"));
        assert!(flows.iter().any(|f| f.sink_kind == "archive-write"));
    }

    #[test]
    fn clean_activity_has_no_flows() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/usr/bin/curl", "", "curl example.com"),
            ev(2, 100, 1, "net-connect", "/usr/bin/curl", "93.184.216.34:443", "curl example.com"),
        ];
        let tree = ProcTree::build(&evs);
        assert!(analyze(&evs, &tree).is_empty());
    }

    #[test]
    fn taint_inherits_to_child() {
        let evs = vec![
            ev(1, 50, 1, "file", "/bin/cat", "/home/u/.ssh/id_rsa", "cat id_rsa"),
            ev(2, 60, 50, "net-connect", "/usr/bin/wget", "10.0.0.9:8080", "wget"),
        ];
        let tree = ProcTree::build(&evs);
        let flows = analyze(&evs, &tree);
        assert!(flows.iter().any(|f| f.sink_pid == 60));
    }

    /// CORRECTNESS FIX #2 regression: the staged hop across unrelated process trees.
    /// pid 100 (child of 1) stages; pid 1100 (child of init, a cron job) picks
    /// it up and exfiltrates. Upstream labtrace reports zero flows here.
    #[test]
    fn staged_carrier_crosses_unrelated_trees() {
        let evs = vec![
            ev(1, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat ~/.aws/credentials"),
            ev(2, 100, 1, "file", "/bin/tar", "/tmp/.sysupdate.tar.gz", "tar -czf /tmp/.sysupdate.tar.gz"),
            // unrelated tree: init's child picks the staged file up
            ev(3, 1100, 1, "file", "/usr/bin/backup", "/tmp/.sysupdate.tar.gz", "backup --nightly"),
            ev(4, 1100, 1, "net-connect", "/usr/bin/backup", "185.199.108.153:443", "backup --nightly"),
        ];
        let tree = ProcTree::build(&evs);
        assert!(!tree.is_ancestor(100, 1100), "trees must be unrelated for this test");
        let flows = analyze(&evs, &tree);
        assert!(
            flows.iter().any(|f| f.sink_kind == "net-exfil" && f.sink_pid == 1100),
            "cross-tree staged exfil must be detected; got {flows:#?}"
        );
        let cross = flows
            .iter()
            .find(|f| f.sink_pid == 1100 && f.sink_kind == "net-exfil")
            .expect("cross-tree net-exfil flow");
        assert_eq!(
            cross.carrier, "/tmp/.sysupdate.tar.gz",
            "flow must name the STAGING file, not the original credential source"
        );
    }

    /// The carrier set must not grow without bound across a long streaming run.
    #[test]
    fn carrier_set_is_capped_oldest_first() {
        let mut st = TaintState::with_carrier_cap(3);
        for i in 0..10 {
            st.note_carrier(&format!("/home/u/secret{i}/.aws/credentials"), [TaintKind::CloudCredentials]);
        }
        assert_eq!(st.carrier_count(), 3, "cap must hold");
        // the newest survive, the oldest are evicted
        assert!(st.carriers.contains_key("/home/u/secret9/.aws/credentials"));
        assert!(!st.carriers.contains_key("/home/u/secret0/.aws/credentials"));
    }

    /// Incremental analysis must reach the same flows as a single pass, so a
    /// streaming session does not lose a staged hop that spans two batches.
    #[test]
    fn incremental_state_matches_single_pass() {
        let batch1 = vec![
            ev(1, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat creds"),
            ev(2, 100, 1, "file", "/bin/cp", "/tmp/.stage.bin", "stage"),
        ];
        let batch2 = vec![
            ev(3, 1100, 2000, "file", "/usr/bin/backup", "/tmp/.stage.bin", "pickup"),
            ev(4, 1100, 2000, "net-connect", "/usr/bin/backup", "evil.example:443", "exfil"),
        ];

        // single pass over everything
        let all: Vec<Event> = batch1.iter().chain(batch2.iter()).cloned().collect();
        let tree = ProcTree::build(&all);
        let one_pass = analyze(&all, &tree);

        // incremental: state carried across batches, tree over the full set
        let mut st = TaintState::default();
        let mut inc = analyze_with_state(&batch1, &tree, &mut st);
        inc.extend(analyze_with_state(&batch2, &tree, &mut st));

        let key = |f: &TaintFlow| (f.sink_pid, f.sink_kind.clone(), f.carrier.clone());
        let mut a: Vec<_> = one_pass.iter().map(key).collect();
        let mut b: Vec<_> = inc.iter().map(key).collect();
        a.sort();
        b.sort();
        assert_eq!(a, b, "incremental analysis must match a single pass");
        assert!(
            inc.iter().any(|f| f.sink_pid == 1100 && f.sink_kind == "net-exfil"),
            "the cross-batch staged hop must still be found"
        );
    }

    #[test]
    fn stale_pids_are_pruned() {
        let mut st = TaintState::default();
        st.tainted_pids.insert(1, [TaintKind::Credentials].into_iter().collect());
        st.tainted_pids.insert(2, [TaintKind::Credentials].into_iter().collect());
        st.tainted_by.insert(1, "/tmp/a".into());
        st.tainted_by.insert(2, "/tmp/b".into());
        // uid 1 only survives
        st.retain_live_pids(&[1u32].into_iter().collect());
        assert!(st.tainted_pids.contains_key(&1));
        assert!(!st.tainted_pids.contains_key(&2));
        assert!(st.tainted_by.contains_key(&1));
        assert!(!st.tainted_by.contains_key(&2));
    }

    #[test]
    fn carrier_recorded_on_flow() {
        let evs = vec![
            ev(1, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat x"),
            ev(2, 100, 1, "net-connect", "/usr/bin/curl", "1.2.3.4:443", "curl"),
        ];
        let tree = ProcTree::build(&evs);
        let flows = analyze(&evs, &tree);
        let f = flows.iter().find(|f| f.sink_kind == "net-exfil").expect("flow");
        assert!(!f.carrier.is_empty(), "flow must name its carrier file");
    }
}
