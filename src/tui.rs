//! ratatui TUI: incident table + a process-chain / taint-flow **graph view**.
//!
//! Layout: incidents on the left, the selected incident's graph on the right,
//! detail pane at the bottom. `Tab` cycles panes, `j/k` move the selection,
//! `q` quits. The graph is a layered (Sugiyama-style) render of the incident's
//! edge list: ancestry edges are solid (`──`), data-flow edges dashed (`╌╌`)
//! and labelled with the carrier / sink target.

use crate::model::{Event, GraphEdge, Incident};
use crate::proctree::ProcTree;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::BTreeMap;

pub struct App {
    pub incidents: Vec<Incident>,
    pub events: Vec<Event>,
    pub stats: String,
    pub tree: ProcTree,
    pub auth_failures: Vec<crate::ingest::AuthFailure>,
    pub selected: usize,
    pub pane: Pane,
    pub show_sessions: bool,
    pub should_quit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Incidents,
    Graph,
    Detail,
}

impl App {
    pub fn new(incidents: Vec<Incident>, events: Vec<Event>, stats: String) -> Self {
        Self::with_auth(incidents, events, stats, Vec::new())
    }

    pub fn with_auth(
        incidents: Vec<Incident>,
        events: Vec<Event>,
        stats: String,
        auth_failures: Vec<crate::ingest::AuthFailure>,
    ) -> Self {
        let tree = ProcTree::build(&events);
        Self {
            incidents,
            events,
            stats,
            tree,
            auth_failures,
            selected: 0,
            pane: Pane::Incidents,
            show_sessions: false,
            should_quit: false,
        }
    }

    pub fn next(&mut self) {
        if self.incidents.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.incidents.len();
    }

    pub fn prev(&mut self) {
        if self.incidents.is_empty() {
            return;
        }
        self.selected = (self.selected + self.incidents.len() - 1) % self.incidents.len();
    }

    pub fn cycle_pane(&mut self) {
        self.pane = match self.pane {
            Pane::Incidents => Pane::Graph,
            Pane::Graph => Pane::Detail,
            Pane::Detail => Pane::Incidents,
        };
    }

    pub fn selected_incident(&self) -> Option<&Incident> {
        self.incidents.get(self.selected)
    }

    /// Layered layout for the graph: assign each actor a depth = longest
    /// ancestry distance from a root, then order within the layer.
    pub fn graph_layers(inc: &Incident) -> Vec<Vec<u32>> {
        let parents: BTreeMap<u32, u32> = inc
            .edges
            .iter()
            .filter(|e| e.edge_kind == "fork")
            .map(|e| (e.to_pid, e.from_pid))
            .collect();

        let mut depth: BTreeMap<u32, usize> = BTreeMap::new();
        for &p in &inc.actors {
            let mut d = 0usize;
            let mut cur = p;
            let mut hops = 0;
            while let Some(&par) = parents.get(&cur) {
                d += 1;
                cur = par;
                hops += 1;
                if hops > 64 {
                    break;
                }
            }
            depth.insert(p, d);
        }

        let max_depth = depth.values().copied().max().unwrap_or(0);
        let mut layers: Vec<Vec<u32>> = vec![Vec::new(); max_depth + 1];
        let mut sorted: Vec<u32> = inc.actors.clone();
        sorted.sort_unstable();
        for p in sorted {
            let d = depth.get(&p).copied().unwrap_or(0);
            layers[d].push(p);
        }
        layers
    }
}

fn node_label(tree: &ProcTree, pid: u32) -> String {
    match tree.exe_of(pid) {
        Some(exe) => format!("{}({pid})", crate::proctree::short_exe(exe)),
        None => format!("pid {pid}"),
    }
}

/// Render the graph as text lines (pure function — snapshot-testable).
pub fn render_graph(app: &App, inc: &Incident, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![Span::styled(
        format!("{} [{}]", inc.title, inc.severity.label().to_uppercase()),
        Style::default()
            .fg(severity_color(inc.severity))
            .add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(""));

    let layers = App::graph_layers(inc);
    for (depth, layer) in layers.iter().enumerate() {
        let indent = "  ".repeat(depth);
        for (i, pid) in layer.iter().enumerate() {
            let branch = if layer.len() > 1 && i + 1 < layer.len() { "├─" } else { "└─" };
            let mut spans = vec![
                Span::raw(format!("{indent}{branch} ")),
                Span::styled(node_label(&app.tree, *pid), Style::default().fg(Color::Cyan)),
            ];
            // annotate outgoing flow edges from this node
            for e in inc.edges.iter().filter(|e| e.from_pid == *pid && e.edge_kind == "flow") {
                spans.push(Span::styled(
                    format!("  ╌╌▶ {}", if e.label.is_empty() { "sink".into() } else { e.label.clone() }),
                    Style::default().fg(Color::Yellow),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    // carrier-mediated (cross-tree) hops get their own legend block, because
    // they are exactly what upstream labtrace cannot express.
    let cross: Vec<&GraphEdge> = inc
        .edges
        .iter()
        .filter(|e| e.edge_kind == "flow" && !app.tree.is_ancestor(e.from_pid, e.to_pid))
        .collect();
    if !cross.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "carrier-mediated hops (cross-tree):",
            Style::default().add_modifier(Modifier::BOLD),
        )]));
        for e in cross {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "  {} ╌[{}]╌▶ {}",
                    node_label(&app.tree, e.from_pid),
                    if e.label.is_empty() { "file" } else { e.label.as_str() },
                    node_label(&app.tree, e.to_pid)
                ),
                Style::default().fg(Color::Magenta),
            )]));
        }
    }

    if !inc.carriers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!("carriers: {}", inc.carriers.join(", ")),
            Style::default().fg(Color::Yellow),
        )]));
    }

    // clip every line to the pane width
    let maxw = width.saturating_sub(2) as usize;
    lines
        .into_iter()
        .map(|l| {
            let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
            if text.len() <= maxw {
                l
            } else {
                Line::from(text.chars().take(maxw).collect::<String>())
            }
        })
        .collect()
}

fn severity_color(s: crate::model::Severity) -> Color {
    use crate::model::Severity::*;
    match s {
        Info => Color::Cyan,
        Low => Color::Green,
        Medium => Color::Yellow,
        High => Color::LightRed,
        Critical => Color::Red,
    }
}

/// Draw one frame.
pub fn draw(f: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(6),
            Constraint::Length(1),
        ])
        .split(f.area());

    // header
    let header = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            " tombolo ",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Black).bg(Color::Cyan),
        )]),
        Line::from(Span::styled(app.stats.clone(), Style::default().fg(Color::DarkGray))),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, outer[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(outer[1]);

    // incident list
    let items: Vec<ListItem> = app
        .incidents
        .iter()
        .map(|i| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<8}", i.severity.label().to_uppercase()),
                    Style::default().fg(severity_color(i.severity)),
                ),
                Span::raw(i.title.clone()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" incidents ")
                .border_style(active_border(app.pane == Pane::Incidents)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.incidents.is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, mid[0], &mut state);

    // graph
    let graph_block = Block::default()
        .borders(Borders::ALL)
        .title(" chain / taint graph ")
        .border_style(active_border(app.pane == Pane::Graph));
    let inner = graph_block.inner(mid[1]);
    f.render_widget(graph_block, mid[1]);
    if let Some(inc) = app.selected_incident() {
        let lines = render_graph(app, inc, inner.width);
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    } else {
        f.render_widget(
            Paragraph::new("no incidents — nothing to graph"),
            inner,
        );
    }

    // detail
    let detail_text = match app.selected_incident() {
        Some(inc) => vec![
            Line::from(vec![
                Span::styled("chain:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(inc.chain.clone()),
            ]),
            Line::from(vec![
                Span::styled("signals: ", Style::default().fg(Color::DarkGray)),
                Span::raw(inc.findings.join(", ")),
            ]),
            Line::from(vec![
                Span::styled("taints:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(if inc.taints.is_empty() { "—".into() } else { inc.taints.join(", ") }),
            ]),
            Line::from(vec![
                Span::styled("summary: ", Style::default().fg(Color::DarkGray)),
                Span::raw(inc.summary.clone()),
            ]),
        ],
        None => vec![Line::from("no incidents")],
    };
    f.render_widget(
        Paragraph::new(detail_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" detail ")
                    .border_style(active_border(app.pane == Pane::Detail)),
            )
            .wrap(Wrap { trim: false }),
        outer[2],
    );

    // help
    let hint = if app.show_sessions {
        format!(
            " SESSIONS: {} auth failure(s) — 's' to hide · j/k · Tab · q",
            app.auth_failures.len()
        )
    } else {
        " j/k move · Tab pane · s sessions · q quit".to_string()
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray)))),
        outer[3],
    );

    // Sessions/auth overlay replaces the graph pane when toggled.
    if app.show_sessions {
        let lines = sessions_lines(app);
        f.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" sessions & auth failures ")
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .wrap(Wrap { trim: false }),
            mid[1],
        );
    }
}

/// Auth-failure lines for the sessions overlay, grouped by (acct, source, reason).
fn sessions_lines(app: &App) -> Vec<Line<'static>> {
    use std::collections::BTreeMap;
    if app.auth_failures.is_empty() {
        return vec![Line::from(Span::styled(
            "no authentication failures recorded in this log",
            Style::default().fg(Color::DarkGray),
        ))];
    }
    let mut groups: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for f in &app.auth_failures {
        let src = if !f.addr.is_empty() {
            f.addr.clone()
        } else if !f.host.is_empty() {
            f.host.clone()
        } else {
            f.terminal.clone()
        };
        *groups.entry((f.acct.clone(), src, f.reason.clone())).or_insert(0) += 1;
    }
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("{} rejection(s)", app.auth_failures.len()),
        Style::default().add_modifier(Modifier::BOLD),
    )])];
    for ((acct, src, reason), n) in groups {
        lines.push(Line::from(vec![
            Span::styled(format!("{n:>4}× "), Style::default().fg(Color::Red)),
            Span::raw(format!(
                "{:<12} from {:<20} {reason}",
                if acct.is_empty() { "-" } else { &acct },
                if src.is_empty() { "-" } else { &src },
            )),
        ]));
    }
    lines
}

fn active_border(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// Run the interactive TUI until `q`. Returns Ok on a clean exit.
///
/// Works over a pty and under CI (non-tty stdin makes crossterm's `poll`
/// return immediately, so the loop exits rather than hanging).
pub fn run(incidents: Vec<Incident>, events: Vec<Event>, stats: String) -> anyhow::Result<()> {
    run_with_auth(incidents, events, stats, Vec::new())
}

pub fn run_with_auth(
    incidents: Vec<Incident>,
    events: Vec<Event>,
    stats: String,
    auth_failures: Vec<crate::ingest::AuthFailure>,
) -> anyhow::Result<()> {
    use crossterm::event::{self, Event as CtEvent, KeyCode};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;
    use std::io::stdout;
    use std::time::Duration;

    let mut app = App::with_auth(incidents, events, stats, auth_failures);

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| draw(f, &app))?;

            // A TUI whose input has gone away must exit rather than spin: an
            // error from poll/read means stdin is closed (e.g. a closed pty or
            // a CI harness), so treat it as quit instead of looping forever.
            match event::poll(Duration::from_millis(250)) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(_) => break, // input gone
            }
            match event::read() {
                Ok(CtEvent::Key(key)) => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('j') | KeyCode::Down => app.next(),
                    KeyCode::Char('k') | KeyCode::Up => app.prev(),
                    KeyCode::Tab => app.cycle_pane(),
                    KeyCode::Char('s') => app.show_sessions = !app.show_sessions,
                    _ => {}
                },
                Ok(_) => {}
                Err(_) => break, // input gone
            }
            if app.should_quit {
                break;
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GraphEdge, Incident, Severity};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn incident() -> Incident {
        Incident {
            title: "Data theft chain".into(),
            severity: Severity::Critical,
            actors: vec![900, 1000, 1100],
            chain: "sshd(900) → sh(1000)".into(),
            findings: vec!["LT005".into(), "ESC-001".into()],
            taints: vec!["cloud-credentials".into()],
            carriers: vec!["/tmp/.sysupdate.tar.gz".into()],
            seq_from: 1,
            seq_to: 4,
            summary: "actors [900, 1000, 1100]; taint flows confirmed".into(),
            edges: vec![
                GraphEdge { from_pid: 900, to_pid: 1000, label: String::new(), edge_kind: "fork".into() },
                GraphEdge { from_pid: 1000, to_pid: 1100, label: "/tmp/.sysupdate.tar.gz".into(), edge_kind: "flow".into() },
            ],
        }
    }

    fn app() -> App {
        let mut events = Vec::new();
        for (pid, ppid, exe) in [
            (900u32, 800u32, "/usr/sbin/sshd"),
            (1000, 900, "/bin/sh"),
            (1100, 1, "/usr/bin/backup"),
        ] {
            events.push(crate::model::Event {
                pid,
                ppid,
                kind: "exec".into(),
                exe: exe.into(),
                success: true,
                ..Default::default()
            });
        }
        App::new(vec![incident()], events, "4 events".into())
    }

    #[test]
    fn graph_layers_are_depths() {
        let inc = incident();
        let layers = App::graph_layers(&inc);
        // only 900→1000 is a fork edge, so 900 and 1100 (which has no fork
        // parent among the actors) sit at depth 0 and 1000 at depth 1.
        assert_eq!(layers[0], vec![900, 1100]);
        assert_eq!(layers[1], vec![1000]);
    }

    #[test]
    fn graph_text_names_nodes_and_carrier() {
        let a = app();
        let inc = a.selected_incident().unwrap();
        let lines = render_graph(&a, inc, 80);
        let text: String = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n")
            .collect();
        assert!(text.contains("sshd(900)"));
        assert!(text.contains("sh(1000)"));
        assert!(text.contains("/tmp/.sysupdate.tar.gz"));
        assert!(text.contains("carrier-mediated hops"));
    }

    #[test]
    fn draw_renders_full_frame() {
        let a = app();
        let backend = TestBackend::new(120, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let buf = term.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("tombolo"));
        assert!(content.contains("chain / taint graph"));
        assert!(content.contains("incidents"));
    }

    #[test]
    fn draw_then_quit_is_clean() {
        let mut a = app();
        a.should_quit = true;
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        assert!(term.draw(|f| draw(f, &a)).is_ok());
    }

    #[test]
    fn navigation_wraps() {
        let mut a = app();
        a.next();
        assert_eq!(a.selected, 0); // single incident wraps to itself
        a.next();
        assert_eq!(a.selected, 0);
        a.cycle_pane();
        assert_eq!(a.pane, Pane::Graph);
    }

    /// The pane must never be empty of graph content when an incident exists.
    #[test]
    fn empty_events_still_render_incident() {
        let a = App::new(vec![incident()], vec![], "0 events".into());
        let inc = a.selected_incident().unwrap();
        let lines = render_graph(&a, inc, 60);
        assert!(!lines.is_empty());
    }
}
