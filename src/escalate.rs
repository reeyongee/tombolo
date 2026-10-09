//! Reversible failed-escalation annotation (escalation fix).
//!
//! `sudo`/`su`/`doas`'s own `execve()` succeeds no matter what password follows
//! it — the kernel only loaded the binary. A plain "success" row therefore looks
//! like the privileged action went through. The ingest layer already joins the
//! later same-pid `USER_AUTH` verdict (keeping only the LAST outcome, so a
//! typo-then-retry is not permanently marked denied); this module surfaces that
//! join as a finding so it reaches the incident report instead of staying a
//! decoration on one row.

use crate::model::{Event, Finding, Severity};
use std::collections::BTreeMap;

/// Rule id used for the annotation.
pub const RULE_ID: &str = "ESC-001";

/// Attach a finding to every escalation exec whose PAM check ultimately failed,
/// and record the confirmed taint kinds on the matching findings.
///
/// Findings are matched by `(pid, seq)`. Because ingest keeps only the last
/// `USER_AUTH` outcome, a retry that succeeds simply leaves `auth = None`, so
/// this is reversible by construction rather than by mutation.
pub fn annotate(events: &[Event], findings: &mut Vec<Finding>) {
    for e in events {
        if e.auth.as_deref() != Some("failed") {
            continue;
        }
        findings.push(Finding {
            rule_id: RULE_ID,
            title: "Privilege escalation attempted and denied",
            severity: Severity::High,
            seq: e.seq,
            pid: e.pid,
            exe: e.exe.clone(),
            detail: format!(
                "execve succeeded (kernel loaded the binary) but the same-pid PAM check was rejected: `{}`",
                e.cmdline
            ),
            taints: Vec::new(),
        });
    }
}

/// Confirm taint kinds onto findings whose pid holds taint, so the incident
/// summary can say *what* leaked, not just that a rule fired.
pub fn confirm_taints(
    findings: &mut [Finding],
    flows: &[crate::model::TaintFlow],
) {
    let mut by_pid: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for f in flows {
        by_pid
            .entry(f.sink_pid)
            .or_default()
            .push(f.taint.kind.clone());
    }
    for finding in findings.iter_mut() {
        if let Some(kinds) = by_pid.get(&finding.pid) {
            let mut v = kinds.clone();
            v.sort();
            v.dedup();
            finding.taints = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, pid: u32, exe: &str, auth: Option<&str>) -> Event {
        Event {
            seq,
            pid,
            kind: "exec".into(),
            row_kind: "exec".into(),
            exe: exe.into(),
            cmdline: format!("{} systemctl restart nginx", exe.trim_start_matches('/')),
            success: true,
            auth: auth.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn denied_escalation_becomes_finding() {
        let evs = vec![ev(4, 1000, "/usr/bin/sudo", Some("failed"))];
        let mut findings = Vec::new();
        annotate(&evs, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn successful_retry_is_not_flagged() {
        // ingest keeps only the LAST USER_AUTH outcome, so a retry that succeeded
        // leaves auth = None and nothing to un-flag.
        let evs = vec![ev(4, 1000, "/usr/bin/sudo", None)];
        let mut findings = Vec::new();
        annotate(&evs, &mut findings);
        assert!(findings.is_empty());
    }
}
