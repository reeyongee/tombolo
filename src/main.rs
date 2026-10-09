//! tombolo CLI.
//!
//! Reads either a raw `/var/log/audit/audit.log` (default) or normalised JSONL
//! (`--jsonl`), runs the engine, and prints terminal / JSON / SARIF.
//! Exit code 2 when incidents are found, for CI.

use anyhow::{Context, Result};
use tombolo::{analyze_with_auth, ingest, jsonl, plain, report, tui};
use clap::{Parser, ValueEnum};
use std::io::Read;
use std::path::PathBuf;

/// Linux auditd ingest with cross-tree data provenance.
#[derive(Parser, Debug)]
#[command(name = "tombolo", version, about, long_about = None)]
struct Args {
    /// Input file (`-` for stdin)
    input: PathBuf,

    /// Treat the input as normalised labtrace JSONL instead of a raw audit log
    #[arg(long)]
    jsonl: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Alias for --format (alias kept for the verification contract)
    #[arg(long, value_enum, hide = true)]
    emit: Option<Format>,

    /// Print an aligned table of events and exit (no incident correlation)
    #[arg(long)]
    plain: bool,

    /// With --plain: do not truncate long columns
    #[arg(long)]
    full: bool,

    /// With --plain: only potentially-dangerous / auth-failed events
    #[arg(long)]
    flagged: bool,

    /// Tail the log and report new incidents as they appear
    #[arg(short = 'F', long)]
    follow: bool,

    /// Keep events on /proc, /sys, /dev and the dynamic loader (very noisy)
    #[arg(long)]
    include_noise: bool,

    /// Extra path prefix to treat as noise (repeatable)
    #[arg(long = "exclude", value_name = "PREFIX")]
    exclude: Vec<String>,

    /// Drop the built-in noise prefixes, keeping only --exclude ones
    #[arg(long)]
    replace_noise: bool,

    /// With --follow: retained event window (default 200000). Older events are
    /// evicted and taint state pruned, bounding memory on a long tail.
    #[arg(long, default_value_t = 200_000)]
    window: usize,

    /// Only emit incidents at or above this severity
    #[arg(short, long, value_enum, default_value_t = MinSeverity::Low)]
    min_severity: MinSeverity,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Sarif,
    Tui,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum MinSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<MinSeverity> for tombolo::model::Severity {
    fn from(m: MinSeverity) -> Self {
        use tombolo::model::Severity::*;
        match m {
            MinSeverity::Info => Info,
            MinSeverity::Low => Low,
            MinSeverity::Medium => Medium,
            MinSeverity::High => High,
            MinSeverity::Critical => Critical,
        }
    }
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

/// Tail the log; each batch of new lines is folded into a running parse and the
/// resulting incidents are emitted (JSON) as they change, exit 2 while any
/// incident stands. Ctrl-C to stop, which is the normal way to end a tail.
/// Tail the log using a persistent streaming session.
///
/// The parser keeps its accumulators between reads, so:
///   * a record split across two polls is still joined (no overlap window);
///   * no batch is ever parsed twice, so nothing is re-emitted;
///   * the taint engine sees every event for the whole run, so a carrier written
///     hours earlier is still followed.
///
/// Incidents are emitted once, as JSON, as they appear.
fn follow_mode(
    args: &Args,
    min: tombolo::model::Severity,
    cfg: ingest::IngestConfig,
) -> Result<()> {
    use tombolo::StreamSession;
    use std::collections::BTreeSet;

    let path = args.input.to_string_lossy().to_string();
    eprintln!("following {path} — Ctrl-C to stop");

    // Ctrl-C (or SIGTERM from a supervisor) must report state rather than
    // dying silently: a tail is normally ended by a signal.
    static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn handle_signal(_: libc::c_int) {
        STOP.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    // fn item -> pointer -> integer, the form clippy accepts
    let handler = handle_signal as *const () as libc::sighandler_t;
    for sig in [libc::SIGINT, libc::SIGTERM] {
        unsafe {
            libc::signal(sig, handler);
        }
    }

    let mut session = StreamSession::with_window(cfg, args.window);
    eprintln!("retaining up to {} events (--window)", session.window());
    let mut reported: BTreeSet<String> = BTreeSet::new();
    let mut emitted = 0usize;

    // Seed with existing content once, so the tail starts from a known state.
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if !existing.is_empty() {
        let lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
        for mut inc in session.push_lines(&lines) {
            if inc.severity >= min {
                inc.title.truncate(500);
                if reported.insert(format!("{}|{}|{}", inc.title, inc.seq_to, inc.actors.len())) {
                    emit_incident(&inc);
                    emitted += 1;
                }
            }
        }
    }

    let _ = plain::follow(
        &path,
        |batch| {
        let incidents = session.push_lines(batch);
        for inc in incidents.iter().filter(|i| i.severity >= min) {
            if reported.insert(format!("{}|{}|{}", inc.title, inc.seq_to, inc.actors.len())) {
                emit_incident(inc);
                emitted += 1;
            }
        }
        },
        || STOP.load(std::sync::atomic::Ordering::SeqCst),
    );
    eprintln!(
        "follow ended after {emitted} incident(s); retained {} event(s), evicted {}, {} carrier(s)",
        session.retained_events(),
        session.evicted(),
        session.carrier_count()
    );
    Ok(())
}

fn emit_incident(inc: &tombolo::model::Incident) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stdout(),
        "{}",
        serde_json::to_string(inc).unwrap_or_default()
    );
    let _ = std::io::stdout().flush();
}

fn main() -> Result<()> {
    let args = Args::parse();
    let format = args.emit.unwrap_or(args.format);
    let input = read_input(&args.input)?;

    let cfg = ingest::IngestConfig {
        include_noise: args.include_noise,
        extra_noise: args.exclude.clone(),
        replace_noise: args.replace_noise,
    };
    let (events, errors, auth_failures) = if args.jsonl {
        let (e, errs) = jsonl::parse_jsonl(&input);
        (e, errs, Vec::new())
    } else {
        let ing = ingest::parse_audit_log_full_with(&input, cfg.clone());
        (ing.events, ing.errors, ing.auth_failures)
    };
    for e in &errors {
        eprintln!("warn: {e}");
    }
    if events.is_empty() {
        eprintln!("no events parsed — nothing to do");
        std::process::exit(1);
    }

    let mut analysis = analyze_with_auth(events, errors, auth_failures);
    let min: tombolo::model::Severity = args.min_severity.into();
    analysis.incidents.retain(|i| i.severity >= min);
    let stats = analysis.stats();

    // --plain prints the event table (no correlation), matching upstream.
    if args.plain {
        print!("{}", plain::table(&analysis.events, args.flagged, args.full));
        if !analysis.auth_failures.is_empty() {
            print!("\n{}", plain::auth_failure_table(&analysis.auth_failures));
        }
        return Ok(());
    }

    // --follow re-runs the engine over the appended tail and reports deltas.
    if args.follow {
        return follow_mode(&args, min, cfg);
    }

    if format == Format::Tui {
        return tui::run_with_auth(
            analysis.incidents,
            analysis.events,
            stats,
            analysis.auth_failures,
        );
    }

    let out = match format {
        Format::Terminal => report::terminal(&analysis.incidents, &stats),
        Format::Json => report::json(&analysis.incidents, &stats),
        Format::Sarif => report::sarif(&analysis.incidents),
        Format::Tui => unreachable!(),
    };
    println!("{out}");

    if !analysis.incidents.is_empty() {
        std::process::exit(2); // findings present — CI-friendly
    }
    Ok(())
}
