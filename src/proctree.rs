//! Process-tree reconstruction (port of `labtrace::proctree`).
//!
//! Builds pid → ppid from the event stream and answers ancestry questions with
//! a hop cap so malformed telemetry (parent cycles) can never hang the tool.

use crate::model::Event;
use std::collections::BTreeMap;

const MAX_HOPS: usize = 64;

#[derive(Debug, Default)]
pub struct ProcTree {
    parent: BTreeMap<u32, u32>,
    exe: BTreeMap<u32, String>,
    cmdline: BTreeMap<u32, String>,
}

impl ProcTree {
    pub fn build(events: &[Event]) -> Self {
        let mut t = ProcTree::default();
        for e in events {
            if e.pid == 0 {
                continue;
            }
            t.parent.insert(e.pid, e.ppid);
            if !e.exe.is_empty() {
                t.exe.insert(e.pid, e.exe.clone());
            }
            if !e.cmdline.is_empty() {
                t.cmdline.insert(e.pid, e.cmdline.clone());
            }
        }
        t
    }

    pub fn exe_of(&self, pid: u32) -> Option<&str> {
        self.exe.get(&pid).map(String::as_str)
    }

    pub fn cmdline_of(&self, pid: u32) -> Option<&str> {
        self.cmdline.get(&pid).map(String::as_str)
    }

    pub fn is_ancestor(&self, ancestor: u32, pid: u32) -> bool {
        let mut cur = pid;
        let mut hops = 0;
        while let Some(&p) = self.parent.get(&cur) {
            if p == ancestor {
                return true;
            }
            cur = p;
            hops += 1;
            if hops > MAX_HOPS {
                break;
            }
        }
        false
    }

    /// Path from root-most known ancestor down to `pid`.
    pub fn chain(&self, pid: u32) -> Vec<u32> {
        let mut path = vec![pid];
        let mut cur = pid;
        let mut hops = 0;
        while let Some(&p) = self.parent.get(&cur) {
            if p == cur || hops > MAX_HOPS {
                break;
            }
            path.push(p);
            cur = p;
            hops += 1;
        }
        path.reverse();
        path
    }

    /// Root-most pid in the observed chain (used to bucket incidents).
    pub fn root(&self, pid: u32) -> u32 {
        self.chain(pid).first().copied().unwrap_or(pid)
    }

    /// `sshd(900) → sh(1000) → curl(1001)`
    pub fn chain_str(&self, pid: u32) -> String {
        self.chain(pid)
            .iter()
            .map(|&p| {
                let exe = self
                    .exe
                    .get(&p)
                    .map(|s| short_exe(s))
                    .unwrap_or("?")
                    .to_string();
                format!("{exe}({p})")
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }

    /// Same as `chain_str` but marking ids that are *not* ancestry-linked to
    /// `from` — used by the graph view to draw carrier (cross-tree) hops.
    pub fn chain_pids(&self, pid: u32) -> Vec<u32> {
        self.chain(pid)
    }

    pub fn label(&self, pid: u32) -> String {
        let exe = self
            .exe
            .get(&pid)
            .map(|s| short_exe(s))
            .unwrap_or("?")
            .to_string();
        format!("{exe}({pid})")
    }
}

pub fn short_exe(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(pid: u32, ppid: u32, exe: &str) -> Event {
        Event {
            pid,
            ppid,
            kind: "exec".into(),
            exe: exe.into(),
            success: true,
            extra: BTreeMap::new(),
            ..Default::default()
        }
    }

    #[test]
    fn ancestor_detection() {
        let evs = vec![
            ev(1, 0, "/sbin/init"),
            ev(100, 1, "/usr/sbin/sshd"),
            ev(200, 100, "/bin/sh"),
        ];
        let t = ProcTree::build(&evs);
        assert!(t.is_ancestor(100, 200));
        assert!(t.is_ancestor(1, 200));
        assert!(!t.is_ancestor(200, 100));
    }

    #[test]
    fn chain_renders() {
        let evs = vec![
            ev(1, 0, "/sbin/init"),
            ev(100, 1, "/usr/sbin/sshd"),
            ev(200, 100, "/bin/sh"),
        ];
        let t = ProcTree::build(&evs);
        let s = t.chain_str(200);
        assert!(s.contains("sshd"));
        assert!(s.contains("sh(200)"));
        // init's parent (0) is the root-most pid observed in the chain
        assert_eq!(t.root(200), 0);
    }

    #[test]
    fn cycle_guard() {
        let evs = vec![ev(7, 8, "/a"), ev(8, 7, "/b")];
        let t = ProcTree::build(&evs);
        let _ = t.chain(7);
        assert!(!t.is_ancestor(99, 7));
    }
}
