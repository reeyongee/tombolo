//! Unified event model.
//!
//! `kind` uses the engine vocabulary (exec / file / net-connect / net-accept /
//! socket / user-add / account / service / config / anomaly) so rules and taint
//! can match it directly. `row_kind` keeps the ingest vocabulary
//! (exec / watch / account / service / config / anomaly) so the TUI can filter
//! rows the way `auditd-log-parser` did.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Event {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub epoch: Option<f64>,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub ppid: u32,
    #[serde(default)]
    pub uid: i64,
    /// Engine vocabulary.
    #[serde(default)]
    pub kind: String,
    /// Ingest vocabulary (TUI row filter).
    #[serde(default)]
    pub row_kind: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub success: bool,
    /// Audit architecture token, e.g. `c000003e` (x86-64).
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub syscall_nr: String,
    #[serde(default)]
    pub syscall_name: String,
    #[serde(default)]
    pub audit_key: String,
    #[serde(default)]
    pub audit_id: String,
    #[serde(default)]
    pub ses: i32,
    /// Human name resolved by auditd's ENRICHED log format
    /// (`log_format = ENRICHED`), e.g. `alice`. Preferred over a local
    /// passwd lookup, which is wrong when the log came from another host.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid_name: String,
    /// Outcome of the userspace PAM check that followed an escalation exec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default)]
    pub danger: Vec<String>,
    #[serde(default)]
    pub raw: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn label(&self) -> String {
        match self.kind.as_str() {
            "exec" => format!("exec {}", self.exe),
            "file" => format!("file {}", self.target),
            "net-connect" => format!("connect {}", self.target),
            "net-accept" => format!("accept {}", self.target),
            "socket" => format!("socket {}", self.target),
            "user-add" => format!("useradd {}", self.target),
            other => format!("{other} {}", self.target),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub seq: u64,
    pub pid: u32,
    pub exe: String,
    pub detail: String,
    /// Taint kinds confirmed for this finding's process, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintFlow {
    pub taint: TaintId,
    pub sink_pid: u32,
    /// pid that originally introduced the taint (the reader of the secret).
    /// Distinct from `sink_pid` when the data was staged and picked up later.
    #[serde(default)]
    pub origin_pid: u32,
    pub sink_seq: u64,
    pub sink_kind: String,
    pub sink_target: String,
    pub chain: String,
    /// The file/socket that carried the taint into the sink (carrier-adoption fix).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub carrier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TaintId {
    pub kind: String,
    pub origin_pid: u32,
    pub carrier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub title: String,
    pub severity: Severity,
    pub actors: Vec<u32>,
    pub chain: String,
    pub findings: Vec<String>,
    pub taints: Vec<String>,
    pub carriers: Vec<String>,
    pub seq_from: u64,
    pub seq_to: u64,
    pub summary: String,
    /// Edge list for the graph view: (from_pid, to_pid, label)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub from_pid: u32,
    pub to_pid: u32,
    pub label: String,
    /// "fork" for ancestry, "flow" for a data-flow hop (incl. cross-tree carrier hops).
    pub edge_kind: String,
}
