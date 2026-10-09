//! Correlation layer (port of `labtrace::correlate`) with graph edges.
//!
//! An incident is born when multiple findings share a process-chain root, **or**
//! when a taint flow reaches a sink — or both.
//!
//! CORRECTNESS FIX (P0): upstream built its incident buckets from *findings* only and
//! merely *looked up* flows by root. A taint flow whose sink lives in a process
//! tree with no rule hit — precisely the staged drop-and-pickup case, where the
//! unrelated picker-up trips no rule — was therefore recorded in `stats` but
//! emitted **no incident at all**, silently discarding the headline capability.
//! The loop now iterates the union of finding-roots and flow-roots.

use crate::model::{Finding, GraphEdge, Incident, Severity, TaintFlow};
use crate::proctree::ProcTree;
use std::collections::{BTreeMap, BTreeSet};

fn raise(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::Critical,
        Severity::High => Severity::Critical,
        Severity::Medium => Severity::High,
        Severity::Low => Severity::Medium,
        Severity::Info => Severity::Low,
    }
}

fn max_sev(a: Severity, b: Severity) -> Severity {
    if a >= b {
        a
    } else {
        b
    }
}

pub fn correlate(
    tree: &ProcTree,
    findings: &[Finding],
    flows: &[TaintFlow],
) -> Vec<Incident> {
    let mut buckets: BTreeMap<u32, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        buckets.entry(tree.root(f.pid)).or_default().push(f);
    }

    let mut taint_by_root: BTreeMap<u32, Vec<&TaintFlow>> = BTreeMap::new();
    for fl in flows {
        taint_by_root.entry(tree.root(fl.sink_pid)).or_default().push(fl);
    }

    // union of both key sets — a flow-only root must still produce an incident
    let roots: BTreeSet<u32> = buckets
        .keys()
        .chain(taint_by_root.keys())
        .copied()
        .collect();

    let mut incidents = Vec::new();
    for root in roots {
        let fs: Vec<&Finding> = buckets.get(&root).cloned().unwrap_or_default();
        let tainted = taint_by_root.get(&root);
        let chained_taint = tainted.map(|v| !v.is_empty()).unwrap_or(false);
        let multi = fs.len() > 1;

        // A lone low/info finding with no taint confirmation is noise. A root
        // with no findings at all is *not* noise — it is a flow-only incident.
        if fs.len() == 1 && !multi && !chained_taint {
            let lone = fs[0];
            if matches!(lone.severity, Severity::Info | Severity::Low) {
                continue;
            }
        }

        // Baseline severity. A taint-confirmed flow with no rule finding is not
        // "Info": the confirmed exfiltration *is* the finding, so it starts at
        // High and the taint raise below lifts it to Critical.
        let mut sev = if fs.is_empty() {
            if chained_taint {
                Severity::High
            } else {
                Severity::Info
            }
        } else {
            fs.iter().map(|f| f.severity).fold(Severity::Info, max_sev)
        };
        // A confirmed exfiltration is never less than Critical: taint reaching a
        // sink is the strongest signal this tool produces, so a Low-severity
        // rule that happens to share the tree must not drag it down to Medium
        // (one `raise()` step), which is what upstream's arithmetic did.
        if chained_taint {
            sev = raise(max_sev(sev, Severity::High));
        } else if multi {
            sev = raise(sev);
        }

        let flow_seqs = tainted
            .into_iter()
            .flatten()
            .map(|t| t.sink_seq)
            .collect::<Vec<_>>();
        let seq_from = fs
            .iter()
            .map(|f| f.seq)
            .chain(flow_seqs.iter().copied())
            .min()
            .unwrap_or(0);
        let seq_to = fs
            .iter()
            .map(|f| f.seq)
            .chain(flow_seqs.iter().copied())
            .max()
            .unwrap_or(0);

        let mut actors: Vec<u32> = fs.iter().map(|f| f.pid).collect();
        if let Some(v) = tainted {
            actors.extend(v.iter().map(|t| t.sink_pid));
            actors.extend(v.iter().filter(|t| t.origin_pid != 0).map(|t| t.origin_pid));
            actors.extend(v.iter().map(|t| t.taint.origin_pid));
        }
        actors.sort_unstable();
        actors.dedup();

        // Primary actor: the most severe finding, else the flow sink.
        let primary_pid = fs
            .iter()
            .max_by_key(|f| f.severity)
            .map(|f| f.pid)
            .or_else(|| tainted.and_then(|v| v.first()).map(|t| t.sink_pid))
            .unwrap_or(root);
        let chain = tree.chain_str(primary_pid);

        let mut taints: Vec<String> = tainted
            .into_iter()
            .flatten()
            .map(|t| t.taint.kind.clone())
            .collect();
        taints.sort();
        taints.dedup();

        let mut carriers: Vec<String> = tainted
            .into_iter()
            .flatten()
            .map(|t| t.carrier.clone())
            .filter(|c| !c.is_empty())
            .collect();
        carriers.sort();
        carriers.dedup();

        let finding_titles: Vec<&str> = fs.iter().map(|f| f.title).collect();
        let title = if chained_taint {
            let who = finding_titles
                .first()
                .map(|t| (*t).to_string())
                .unwrap_or_else(|| "Sensitive data".to_string());
            format!("Data theft chain: {who} → exfiltration of {}", taints.join(" + "))
        } else if multi {
            format!(
                "Suspicious activity chain: {} + {} more signal(s)",
                finding_titles[0],
                fs.len() - 1
            )
        } else {
            finding_titles
                .first()
                .map(|t| (*t).to_string())
                .unwrap_or_else(|| "Finding".to_string())
        };

        let signals = if fs.is_empty() {
            "none (taint-only)".to_string()
        } else {
            fs.iter().map(|f| f.rule_id).collect::<Vec<_>>().join(", ")
        };

        let summary = format!(
            "actor(s) [{}]; evidence seq {}–{}; signals: {}; {}",
            actors
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            seq_from,
            seq_to,
            signals,
            if chained_taint {
                let c = if carriers.is_empty() {
                    String::new()
                } else {
                    format!(" via {}", carriers.join(", "))
                };
                format!("taint flows confirmed: {}{}", taints.join(", "), c)
            } else {
                "no taint confirmation".into()
            }
        );

        let edges = build_edges(tree, &actors, tainted);

        incidents.push(Incident {
            title,
            severity: sev,
            actors,
            chain,
            findings: fs.iter().map(|f| f.rule_id.to_string()).collect(),
            taints,
            carriers,
            seq_from,
            seq_to,
            summary,
            edges,
        });
    }

    incidents.sort_by_key(|i| std::cmp::Reverse(i.severity));
    incidents
}

/// Graph-view edge list: ancestry edges between incident actors (solid in the
/// TUI) plus one "flow" edge per taint hop, including carrier-mediated hops that
/// cross process trees (dashed, labelled with the carrier target).
fn build_edges(
    tree: &ProcTree,
    actors: &[u32],
    tainted: Option<&Vec<&TaintFlow>>,
) -> Vec<GraphEdge> {
    let mut edges = Vec::new();
    let actor_set: BTreeSet<u32> = actors.iter().copied().collect();

    // ancestry: link each actor to its nearest ancestor that is also an actor
    for &pid in actors {
        for &candidate in tree.chain(pid).iter().rev().skip(1) {
            if actor_set.contains(&candidate) {
                edges.push(GraphEdge {
                    from_pid: candidate,
                    to_pid: pid,
                    label: String::new(),
                    edge_kind: "fork".into(),
                });
                break;
            }
        }
    }

    // data flow: the taint origin → sink, labelled with the sink target. When
    // the origin and sink are the same pid (no staging hop) the edge is emitted
    // as origin→sink anyway so the pane can show "this pid reached a sink".
    if let Some(flows) = tainted {
        for fl in flows {
            let from = if fl.origin_pid == 0 { fl.sink_pid } else { fl.origin_pid };
            edges.push(GraphEdge {
                from_pid: from,
                to_pid: fl.sink_pid,
                label: fl.sink_target.clone(),
                edge_kind: "flow".into(),
            });
        }
    }

    edges.sort_by(|a, b| (a.from_pid, a.to_pid, &a.label).cmp(&(b.from_pid, b.to_pid, &b.label)));
    edges.dedup();
    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Event;
    use crate::rules::run as run_rules;
    use crate::taint::analyze as run_taint;

    fn ev(seq: u64, pid: u32, ppid: u32, kind: &str, exe: &str, target: &str, cmdline: &str) -> Event {
        Event {
            seq,
            pid,
            ppid,
            uid: 1000,
            kind: kind.into(),
            exe: exe.into(),
            cmdline: cmdline.into(),
            target: target.into(),
            success: true,
            ..Default::default()
        }
    }

    #[test]
    fn full_chain_becomes_critical_incident() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/bin/sh", "", "sh"),
            ev(2, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat ~/.aws/credentials"),
            ev(3, 100, 1, "exec", "/bin/tar", "/tmp/s.tar.gz", "tar -czf /tmp/s.tar.gz .aws"),
            ev(4, 100, 1, "net-connect", "curl", "185.199.108.153:443", "curl https://x"),
        ];
        let tree = ProcTree::build(&evs);
        let findings = run_rules(&evs);
        let flows = run_taint(&evs, &tree);
        let incidents = correlate(&tree, &findings, &flows);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
        assert!(incidents[0].title.contains("exfiltration"));
        assert!(!incidents[0].taints.is_empty());
        assert!(!incidents[0].edges.is_empty());
    }

    #[test]
    fn lone_low_finding_is_noise() {
        let evs = vec![ev(1, 100, 1, "net-connect", "curl", "93.184.216.34:443", "curl")];
        let tree = ProcTree::build(&evs);
        let findings = run_rules(&evs);
        let incidents = correlate(&tree, &findings, &[]);
        assert!(incidents.is_empty());
    }

    /// A taint-confirmed exfiltration must be Critical even when the only rule
    /// that fired in that tree is Low severity (LT006, a raw-IP connect).
    /// Upstream's single `raise()` left this at Medium.
    #[test]
    fn taint_confirmed_exfil_with_low_rule_is_still_critical() {
        let evs = vec![
            ev(1, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "read creds"),
            ev(2, 100, 1, "file", "/bin/cp", "/tmp/.stage.bin", "stage"),
            // sink tree with no findings of its own
            ev(3, 1100, 2000, "file", "/usr/bin/backup", "/tmp/.stage.bin", "backup"),
            ev(4, 1100, 2000, "net-connect", "/usr/bin/backup", "1.2.3.4:443", "backup"),
        ];
        let tree = ProcTree::build(&evs);
        let findings = run_rules(&evs);
        let flows = run_taint(&evs, &tree);
        let incidents = correlate(&tree, &findings, &flows);
        for inc in &incidents {
            if !inc.taints.is_empty() {
                assert_eq!(
                    inc.severity,
                    Severity::Critical,
                    "taint-confirmed incident {:?} must be critical, got {:?}",
                    inc.title,
                    inc.severity
                );
            }
        }
    }

    /// P0 REGRESSION: a taint flow whose sink tree has NO rule finding must
    /// still produce an incident. Before the fix this emitted nothing.
    #[test]
    fn taint_only_root_still_produces_an_incident() {
        let evs = vec![
            // tree A (root 1): reads creds, stages them
            ev(1, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "read creds"),
            ev(2, 100, 1, "file", "/bin/cp", "/tmp/.stage.bin", "stage"),
            // tree B (root 2000): picks them up and exfiltrates. No rule fires here.
            ev(3, 1100, 2000, "file", "/usr/bin/backup", "/tmp/.stage.bin", "backup"),
            ev(4, 1100, 2000, "net-connect", "/usr/bin/backup", "backup.evil.example:443", "backup"),
        ];
        let tree = ProcTree::build(&evs);
        assert_ne!(tree.root(100), tree.root(1100), "trees must be unrelated");
        let findings = run_rules(&evs);
        let flows = run_taint(&evs, &tree);
        assert!(!flows.is_empty(), "taint must flow across the carrier");

        let incidents = correlate(&tree, &findings, &flows);
        let exfil = incidents
            .iter()
            .find(|i| i.actors.contains(&1100))
            .expect("flow-only root must yield an incident naming the sink pid");
        assert!(
            exfil.title.contains("exfiltration"),
            "title should describe the exfiltration, got {:?}",
            exfil.title
        );
        assert_eq!(exfil.severity, Severity::Critical, "taint-confirmed exfil is critical");
        assert!(exfil.carriers.contains(&"/tmp/.stage.bin".to_string()));
    }
}
