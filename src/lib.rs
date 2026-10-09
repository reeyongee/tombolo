//! tombolo — Linux `auditd` ingest with cross-tree data provenance.
//!
//! The ingest layer and the rule/taint engine began as ports of two
//! upstream projects (see README "Credits"):
//!   * `lab5terr/auditd-log-parser` — raw `audit.log` ingest (field/hex/ENRICHED
//!     decoding, EXECVE argv rebuild, danger heuristics, failed-escalation join).
//!   * `Hartwell-Labs/labtrace`     — process tree, single-event rules, data-flow
//!     taint, incident correlation, JSON/SARIF output.
//!
//! Three problems were solved that neither reference implementation handles:
//!   1. arch-exact syscall typing (`syscall.rs`) so `kind` is never guessed
//!      from a flat multi-architecture syscall set;
//!   2. carrier-keyed taint adoption (`taint.rs`) so a staged file picked up by
//!      an *unrelated* process still links to its origin;
//!   3. a ratatui TUI with a process-chain / taint-flow graph view (`tui.rs`).

pub mod correlate;
pub mod escalate;
pub mod ingest;
pub mod jsonl;
pub mod model;
pub mod plain;
pub mod proctree;
pub mod report;
pub mod rules;
pub mod syscall;
pub mod syscall_table;
pub mod taint;
pub mod timefmt;
pub mod tui;

use model::{Event, Incident};

/// The whole pipeline: normalised events in, correlated incidents out.
pub struct Analysis {
    pub events: Vec<Event>,
    pub findings: Vec<model::Finding>,
    pub flows: Vec<model::TaintFlow>,
    pub incidents: Vec<Incident>,
    pub parse_errors: Vec<String>,
    /// Rejected authentications from the ingest (empty for JSONL input).
    pub auth_failures: Vec<ingest::AuthFailure>,
}

/// Run ingest-result events through the full engine.
pub fn analyze(events: Vec<Event>, parse_errors: Vec<String>) -> Analysis {
    analyze_with_auth(events, parse_errors, Vec::new())
}

/// Full entry point: retains auth failures for the sessions view.
pub fn analyze_with_auth(
    events: Vec<Event>,
    parse_errors: Vec<String>,
    auth_failures: Vec<ingest::AuthFailure>,
) -> Analysis {
    let tree = proctree::ProcTree::build(&events);
    let mut findings = rules::run(&events);
    escalate::annotate(&events, &mut findings);
    let flows = taint::analyze(&events, &tree);
    let incidents = correlate::correlate(&tree, &findings, &flows);
    Analysis {
        events,
        findings,
        flows,
        incidents,
        parse_errors,
        auth_failures,
    }
}

/// A long-lived streaming ingest + analysis session for `--follow`.
///
/// State that must survive across batches:
///   * the parser accumulators (a record split across reads is still joined);
///   * taint state (a carrier written hours ago is still followed); and
///   * a bounded window of recent events, so the process tree and the rule
///     engine stay correct without replaying the whole run.
///
/// `window` caps retained events. When it is exceeded the oldest are dropped and
/// taint state is pruned to the pids still present — otherwise a multi-day tail
/// on a busy host grows without bound.
pub struct StreamSession {
    ing: ingest::Ingest,
    /// Taint state carried across batches.
    taint: taint::TaintState,
    /// Bounded, newest-last window of retained events.
    events: std::collections::VecDeque<Event>,
    window: usize,
    /// Events evicted so far (reported for operator visibility).
    evicted: u64,
    /// How many events of the window have already been replayed by the taint
    /// analyzer (so each event is analysed exactly once).
    analyzed_upto: usize,
}

impl StreamSession {
    /// Default retained-event window. Sized so a full day of a busy host's
    /// credential-adjacent activity fits while memory stays bounded.
    pub const DEFAULT_WINDOW: usize = 200_000;

    pub fn new(config: ingest::IngestConfig) -> Self {
        Self::with_window(config, Self::DEFAULT_WINDOW)
    }

    pub fn with_window(config: ingest::IngestConfig, window: usize) -> Self {
        let window = window.max(1_000);
        StreamSession {
            ing: ingest::Ingest::with_config(config),
            taint: taint::TaintState::with_carrier_cap(taint::DEFAULT_CARRIER_CAP),
            events: std::collections::VecDeque::with_capacity(window.min(4096)),
            window,
            evicted: 0,
            analyzed_upto: 0,
        }
    }

    /// Feed raw lines; returns incidents discovered as a result.
    pub fn push_lines(&mut self, lines: &[String]) -> Vec<Incident> {
        for line in lines {
            self.ing.feed_line(line);
        }
        // Age out builders this batch did not touch.
        self.ing.flush_idle();

        let known: std::collections::BTreeSet<String> =
            self.events.iter().map(|e| e.audit_id.clone()).collect();
        let fresh: Vec<Event> = self
            .ing
            .take_events()
            .into_iter()
            .filter(|e| !known.contains(&e.audit_id))
            .collect();
        if fresh.is_empty() {
            return Vec::new();
        }
        self.events.extend(fresh);
        self.enforce_window();

        self.analyze_window()
    }

    /// Drop the oldest events past the window and prune taint state.
    ///
    /// Pruning pids is safe: a pid absent from the window has not acted
    /// recently, so it cannot be the sink of a new flow. Carrier *paths* are
    /// kept (bounded by their own cap) because a staged file legitimately
    /// outlives the process that wrote it.
    fn enforce_window(&mut self) {
        if self.events.len() <= self.window {
            return;
        }
        let excess = self.events.len() - self.window;
        for _ in 0..excess {
            self.events.pop_front();
            self.evicted += 1;
        }
        let live: std::collections::BTreeSet<u32> = self.events.iter().map(|e| e.pid).collect();
        self.taint.retain_live_pids(&live);
    }

    /// Analyze the current window. Taint is incremental (only the events added
    /// since the last call are replayed through the analyzer), so this is linear
    /// in the batch size, not in the window size.
    fn analyze_window(&mut self) -> Vec<Incident> {
        let snapshot: Vec<Event> = self.events.iter().cloned().collect();
        let tree = proctree::ProcTree::build(&snapshot);
        let mut findings = rules::run(&snapshot);
        escalate::annotate(&snapshot, &mut findings);

        // Replay only the newest slice through the incremental analyzer.
        let start = self.analyzed_upto.min(snapshot.len());
        let delta = &snapshot[start..];
        let flows = taint::analyze_with_state(delta, &tree, &mut self.taint);
        self.analyzed_upto = snapshot.len();

        escalate::confirm_taints(&mut findings, &flows);
        correlate::correlate(&tree, &findings, &flows)
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    pub fn carrier_count(&self) -> usize {
        self.taint.carrier_count()
    }

    pub fn retained_events(&self) -> usize {
        self.events.len()
    }

    /// The effective window (clamped to a sane minimum at construction).
    pub fn window(&self) -> usize {
        self.window
    }
}

impl Analysis {
    pub fn stats(&self) -> String {
        format!(
            "{} events ingested · {} rule signals · {} taint flows · {} incidents",
            self.events.len(),
            self.findings.len(),
            self.flows.len(),
            self.incidents.len()
        )
    }
}
