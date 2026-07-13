//use colored::Colorize;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
};
use reqwest::tls::Certificate;

use chrono::{DateTime, SecondsFormat, Utc};
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use admin_api_types::{
    ActorDescriptor, ApiKeySet, NodeRecordBrief, ServiceDescriptor, VisaDescriptor,
};

use thousands::Separable;

use crate::vsclient::{RoleFilter, VsClient};

/// Do not hit the VS ADMIN api more than this often.
const REFRESH_RATE: Duration = Duration::from_millis(2000);

/// Minimum sparkline width (bars) when shown; below this the sparkline is dropped.
const SPARK_MIN: usize = 8;
/// Maximum sparkline width (bars); history ring buffers hold this many samples.
const SPARK_MAX: usize = 16;

/// Render `vals` as unicode bars scaled to the slice max; all-min when idle.
fn sparkline(vals: &[u64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = vals.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return "▁".repeat(vals.len());
    }
    vals.iter()
        .map(|&v| BARS[((v * 7) / max) as usize])
        .collect()
}

/// Format seconds as "01d 04h 09m 22s", hours rolling into days.
fn fmt_uptime(secs: u64) -> String {
    format!(
        "{:02}d {:02}h {:02}m {:02}s",
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    )
}

/// Which content pane is currently selected for keyboard interaction.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Pane {
    Actors,
    Services,
    Visas,
    Details,
}

/// Clamp a scroll offset so the last content line can reach the pane bottom
/// but you can't scroll into empty space; 0 when content fits the viewport.
fn clamp_scroll(offset: u16, content_h: u16, viewport_h: u16) -> u16 {
    offset.min(content_h.saturating_sub(viewport_h))
}

/// Next selection index given current index, list length, and direction.
/// Clamps at 0 and len-1; None only for an empty list.
fn move_selection(current: Option<usize>, len: usize, down: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0);
    Some(if down {
        (cur + 1).min(len - 1)
    } else {
        cur.saturating_sub(1)
    })
}

/// One-line description of the entity feeding the details pane, e.g.
/// "visa 1001" or "actor (none selected)".
fn detail_line(source: Pane, id: Option<String>) -> String {
    let label = match source {
        Pane::Actors => "actor",
        Pane::Services => "service",
        Pane::Visas => "visa",
        Pane::Details => return String::new(),
    };
    match id {
        Some(id) => format!("{label} {id}"),
        None => format!("{label} (none selected)"),
    }
}

/// Width of the label column in the visa Details view. 13 = longest label
/// ("last contact"/"connect reqs", 12 chars) plus a one-space gutter.
const LABEL_W: u16 = 13;

/// Color for the labels/headings in the visa Details view (vs. plain values).
const HEADING_STYLE: Style = Style::new().fg(Color::Cyan);

/// Attribute key / value colors (distinct from each other and the heading).
const ATTR_KEY_STYLE: Style = Style::new().fg(Color::Yellow);
const ATTR_VAL_STYLE: Style = Style::new().fg(Color::White);

/// "Xh Ym" for a minute count, hours comma-separated (durations can be huge).
fn hm(total_mins: u64) -> String {
    format!(
        "{}h {:02}m",
        (total_mins / 60).separate_with_commas(),
        total_mins % 60
    )
}

/// Human-readable time remaining until `expires`, relative to `now`.
/// "EXPIRED" once past; otherwise "expires in Xh Ym" (or "expires in Xm"
/// under an hour). Rounds down.
fn remaining_str(expires: SystemTime, now: SystemTime) -> String {
    match expires.duration_since(now) {
        Err(_) => "EXPIRED".to_string(),
        Ok(d) => {
            let mins = d.as_secs() / 60;
            if mins >= 60 {
                format!("expires in {}", hm(mins))
            } else {
                format!("expires in {mins}m")
            }
        }
    }
}

/// The flow line: `[src]:sport  --PROTO-->  [dst]:dport`. Missing addr → `-`,
/// missing port → `0` (matches the visas list row convention).
fn flow_str(v: &VisaDescriptor) -> String {
    let src = v.source_addr.as_deref().unwrap_or("-");
    let dst = v.dest_addr.as_deref().unwrap_or("-");
    let sport = v.source_port.unwrap_or(0);
    let dport = v.dest_port.unwrap_or(0);
    let proto = v.proto.to_uppercase();
    format!("[{src}]:{sport}  --{proto}-->  [{dst}]:{dport}")
}

/// One-line session-key summary — never prints key material, only the key
/// format and the encrypted byte lengths.
fn session_key_summary(k: &ApiKeySet) -> String {
    format!(
        "fmt={:?} ingress={}B egress={}B",
        k.format,
        k.ingress_key.len(),
        k.egress_key.len()
    )
}

/// A labeled row: `label` (heading color) in a fixed `LABEL_W` column, `value`
/// wrapped to the remaining width with continuation lines indented under the
/// value column.
fn labeled(label: &str, value: &str, width: u16) -> Vec<Line<'static>> {
    let lw = LABEL_W as usize;
    // Column available for the value; keep at least 1 so we always progress.
    let vw = (width.saturating_sub(LABEL_W)).max(1) as usize;
    let wrapped = wrap_words(value, vw);
    let mut lines = Vec::with_capacity(wrapped.len().max(1));
    for (i, seg) in wrapped.iter().enumerate() {
        let label_span = if i == 0 {
            Span::from(format!("{label:<lw$}")).style(HEADING_STYLE)
        } else {
            Span::from(" ".repeat(lw))
        };
        lines.push(Line::from(vec![label_span, Span::from(seg.clone())]));
    }
    lines
}

/// Word-wrap `s` to `width` cols. Splits on spaces; a single word longer than
/// `width` is hard-split. Always returns at least one segment.
fn wrap_words(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        // Hard-split a word that can't fit on its own line.
        let mut word = word.to_string();
        while word.len() > width {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            let (head, tail) = word.split_at(width);
            out.push(head.to_string());
            word = tail.to_string();
        }
        if cur.is_empty() {
            cur = word;
        } else if cur.len() + 1 + word.len() <= width {
            cur.push(' ');
            cur.push_str(&word);
        } else {
            out.push(std::mem::take(&mut cur));
            cur = word;
        }
    }
    out.push(cur);
    out
}

/// Build the full multi-line visa detail view for the Details pane.
/// Pure: no `self`, no frame — `width` is the inner (border-excluded) width.
fn visa_detail_text(
    v: &VisaDescriptor,
    cn: Option<&str>,
    now: SystemTime,
    width: u16,
) -> Text<'static> {
    let w = width as usize;
    let mut lines: Vec<Line> = Vec::new();

    // Header: "visa <id>" left, remaining right-aligned, padded to width.
    let left = format!("visa {}", v.id);
    let right = remaining_str(v.expires, now);
    let pad = w.saturating_sub(left.len() + right.len());
    lines.push(Line::from(vec![
        Span::from("visa ").style(HEADING_STYLE),
        Span::from(v.id.to_string()),
        Span::from(" ".repeat(pad)),
        Span::from(right).style(HEADING_STYLE),
    ]));
    lines.push(Line::from(""));

    lines.extend(labeled("policy", &v.policy_id, width));
    lines.extend(labeled(
        "zpl",
        &format!("[{}] {}", v.direction, v.zpl),
        width,
    ));
    let requesting = match cn {
        Some(cn) => format!("{} ({cn})", v.requesting_node),
        None => v.requesting_node.clone(),
    };
    lines.extend(labeled("requesting", &requesting, width));
    lines.extend(labeled("flow", &flow_str(v), width));

    let created: DateTime<Utc> = v.created.into();
    let expires: DateTime<Utc> = v.expires.into();
    lines.extend(labeled(
        "created",
        &created.to_rfc3339_opts(SecondsFormat::Secs, true),
        width,
    ));
    let dur = v
        .expires
        .duration_since(v.created)
        .map(|d| hm(d.as_secs() / 60))
        .unwrap_or_else(|_| "0h 00m".to_string());
    lines.extend(labeled(
        "expires",
        &format!(
            "{}  (duration {dur})",
            expires.to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
        width,
    ));

    // Signals: first on the label line, the rest indented under it.
    if v.signals.is_empty() {
        lines.extend(labeled("signals", "(none)", width));
    } else {
        for (i, sig) in v.signals.iter().enumerate() {
            let label = if i == 0 { "signals" } else { "" };
            lines.extend(labeled(label, sig, width));
        }
    }

    lines.extend(labeled(
        "session key",
        &session_key_summary(&v.session_key),
        width,
    ));

    Text::from(lines)
}

/// A `SystemTime` as RFC3339 (secs, UTC), or `fallback` when absent.
fn ts_or(t: Option<SystemTime>, fallback: &str) -> String {
    match t {
        Some(t) => {
            let dt: DateTime<Utc> = t.into();
            dt.to_rfc3339_opts(SecondsFormat::Secs, true)
        }
        None => fallback.to_string(),
    }
}

/// Header's right-hand auth text: "no auth" (None), "auth EXPIRED" (past),
/// or "auth in Xh Ym".
fn auth_hdr(auth_exp: Option<SystemTime>, now: SystemTime) -> String {
    match auth_exp {
        None => "no auth".to_string(),
        Some(e) => match e.duration_since(now) {
            Err(_) => "auth EXPIRED".to_string(),
            Ok(d) => format!("auth in {}", hm(d.as_secs() / 60)),
        },
    }
}

/// Relative " (Xm ago)" / " (Xh Ym ago)" suffix for a past time; empty if the
/// time is in the future or absent.
fn ago_suffix(t: SystemTime, now: SystemTime) -> String {
    match now.duration_since(t) {
        Ok(d) => {
            let mins = d.as_secs() / 60;
            if mins >= 60 {
                format!(" ({} ago)", hm(mins))
            } else {
                format!(" ({mins}m ago)")
            }
        }
        Err(_) => String::new(),
    }
}

/// The `-- node --` block for a node actor's `NodeRecordBrief`.
/// `width` is the inner (border-excluded) pane width.
fn node_detail_lines(nd: &NodeRecordBrief, now: SystemTime, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();

    // Full-width "-- node ----" divider.
    let mut divider = String::from("-- node ");
    let pad = (width as usize).saturating_sub(divider.len());
    divider.push_str(&"-".repeat(pad));
    lines.push(Line::from(Span::from(divider).style(HEADING_STYLE)));

    lines.extend(labeled(
        "sync",
        if nd.in_sync { "YES" } else { "NO" },
        width,
    ));
    let last_contact = format!(
        "{}{}",
        ts_or(nd.last_contact, "never"),
        nd.last_contact
            .map(|t| ago_suffix(t, now))
            .unwrap_or_default(),
    );
    lines.extend(labeled("last contact", &last_contact, width));
    lines.extend(labeled(
        "vss port",
        &nd.vss_port.map(|p| p.to_string()).unwrap_or("-".into()),
        width,
    ));
    lines.extend(labeled(
        "visa reqs",
        &format!(
            "{}  (approved {}, denied {})",
            nd.visa_requests.separate_with_commas(),
            nd.approved_vreqs.separate_with_commas(),
            nd.denied_vreqs.separate_with_commas(),
        ),
        width,
    ));
    let last_vreq = format!(
        "{}{}",
        ts_or(nd.last_vreq, "never"),
        nd.last_vreq.map(|t| ago_suffix(t, now)).unwrap_or_default(),
    );
    lines.extend(labeled("last vreq", &last_vreq, width));
    lines.extend(labeled(
        "connect reqs",
        &nd.connect_requests.separate_with_commas(),
        width,
    ));
    // installed = live visas, pending = awaiting install, revoking = pending
    // revocation. `visas_enqueued` (queued IDs) is not surfaced here.
    lines.extend(labeled(
        "installs",
        &format!(
            "{} installed, {} pending, {} revoking",
            nd.visas.len().separate_with_commas(),
            nd.pending_install.separate_with_commas(),
            nd.pending_revocation.separate_with_commas(),
        ),
        width,
    ));
    let adapters = if nd.adapters.is_empty() {
        "(none)".to_string()
    } else {
        nd.adapters.join(", ")
    };
    lines.extend(labeled("adapters", &adapters, width));
    let links = if nd.links.is_empty() {
        "(none)".to_string()
    } else {
        nd.links.join(", ")
    };
    lines.extend(labeled("links", &links, width));

    lines
}

/// Build the full multi-line actor detail view for the Details pane.
/// `services` is the CNs' bound service names (already filtered by caller).
/// Pure: no `self`, no frame — `width` is the inner (border-excluded) width.
fn actor_detail_text(
    a: &ActorDescriptor,
    services: &[&str],
    now: SystemTime,
    width: u16,
) -> Text<'static> {
    let w = width as usize;
    let mut lines: Vec<Line> = Vec::new();

    // Header: "actor <cn>" left; "[node]/[adapter]   <auth>" right, padded.
    let badge = if a.node { "[node]" } else { "[adapter]" };
    let right = format!("{badge}   {}", auth_hdr(a.auth_exp, now));
    let left = format!("actor {}", a.cn);
    let pad = w.saturating_sub(left.len() + right.len());
    lines.push(Line::from(vec![
        Span::from("actor ").style(HEADING_STYLE),
        Span::from(a.cn.clone()),
        Span::from(" ".repeat(pad)),
        Span::from(right).style(HEADING_STYLE),
    ]));
    lines.push(Line::from(""));

    lines.extend(labeled("identity", &a.ident, width));
    lines.extend(labeled("zpr addr", &a.zpr_addr, width));
    let created: DateTime<Utc> = a.ctime.into();
    lines.extend(labeled(
        "created",
        &created.to_rfc3339_opts(SecondsFormat::Secs, true),
        width,
    ));
    // auth exp: timestamp plus a relative "(in Xh Ym)"/"(EXPIRED)" suffix.
    let auth_suffix = match a.auth_exp {
        Some(e) => match e.duration_since(now) {
            Err(_) => "  (EXPIRED)".to_string(),
            Ok(d) => format!("  (in {})", hm(d.as_secs() / 60)),
        },
        None => String::new(),
    };
    lines.extend(labeled(
        "auth exp",
        &format!("{}{auth_suffix}", ts_or(a.auth_exp, "no auth")),
        width,
    ));

    // attributes: first "key=values" on the label line, rest indented.
    // Sort by key so the order is stable across refreshes (attrs arrive unordered).
    if a.attrs.is_empty() {
        lines.extend(labeled("attributes", "(none)", width));
    } else {
        let mut attrs: Vec<&_> = a.attrs.iter().collect();
        attrs.sort_by(|x, y| x.key.cmp(&y.key));
        let lw = LABEL_W as usize;
        for (i, attr) in attrs.iter().enumerate() {
            let label = if i == 0 { "attributes" } else { "" };
            // Colored key = value; one line per attribute.
            // ponytail: no wrap — attr values are short; long ones clip at the
            // right edge (vertical scroll won't help). Widen if that bites.
            lines.push(Line::from(vec![
                Span::from(format!("{label:<lw$}")).style(HEADING_STYLE),
                Span::from(attr.key.clone()).style(ATTR_KEY_STYLE),
                Span::from(" = "),
                Span::from(attr.value.join(", ")).style(ATTR_VAL_STYLE),
            ]));
        }
    }

    // services: one bound service name per line, or (none).
    if services.is_empty() {
        lines.extend(labeled("services", "(none)", width));
    } else {
        for (i, s) in services.iter().enumerate() {
            let label = if i == 0 { "services" } else { "" };
            lines.extend(labeled(label, s, width));
        }
    }

    // node block only for node actors.
    if let Some(nd) = &a.node_details {
        lines.extend(node_detail_lines(nd, now, width));
    }

    Text::from(lines)
}

/// Full multi-line detail view for a selected service. Header is the service
/// name; body is one labeled row per field. All fields are plain strings.
fn service_detail_text(s: &ServiceDescriptor, width: u16) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::from("service ").style(HEADING_STYLE),
        Span::from(s.service_name.clone()),
    ]));
    lines.push(Line::from(""));
    lines.extend(labeled("cn", &s.actor_cn, width));
    lines.extend(labeled("zpr addr", &s.zpr_addr, width));
    lines.extend(labeled("dock addr", &s.dock_zpr_addr, width));
    lines.extend(labeled("kind", &s.service_kind, width));
    lines.extend(labeled("endpoints", &s.service_endpoints, width));
    Text::from(lines)
}

/// Keep a stored selection in range after the row vec is rebuilt.
fn clamp_state(state: &mut TableState, len: usize) {
    state.select(match (state.selected(), len) {
        (_, 0) => None,
        (Some(i), _) if i >= len => Some(len - 1),
        (None, _) => Some(0),
        (some, _) => some,
    });
}

/// Bordered block for a pane; thick bold border when selected, and the
/// hot-key letter of the title underlined+bold.
fn pane_block<'a>(letter: &'a str, rest: &'a str, selected: bool) -> Block<'a> {
    let title = Line::from(vec![letter.underlined().bold(), rest.bold()]);
    let block = Block::default().borders(Borders::ALL).title(title);
    if selected {
        block
            .border_type(BorderType::Thick)
            .border_style(Style::default().bold())
    } else {
        block
    }
}

#[derive(Debug)]
struct Gui {
    exit: bool,
    err_msg: Option<String>,
    last_updated: Option<Instant>,
    vs_cli: VsClient,
    actors: Vec<ActorDescriptor>,
    services: Vec<ServiceDescriptor>,
    visas: Vec<VisaDescriptor>,
    selected: Pane,
    detail_source: Pane,
    detail_scroll: u16, // top line offset of the Details pane
    actor_state: TableState,
    service_state: TableState,
    visa_state: TableState,
    table_header_style: Style,
    zpr_addr_style: Style,
    cn_style: Style,
    visa_id_style: Style,
    uptime_secs: u64,
    approved_hist: VecDeque<u64>,
    denied_hist: VecDeque<u64>,
    last_approved: u64,
    last_denied: u64,
}

/// Fire up the terminal based gui which is just a simple dashboard.
/// Returns on terrible error or if user exits.
pub fn enter_gui(
    api_url: &str,
    cert: Certificate,
    api_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = ratatui::init();
    let mut g = Gui::new(api_url, cert, api_key);
    let result = g.run(&mut terminal);
    ratatui::restore();
    result
}

impl Gui {
    fn new(api_url: &str, cert: Certificate, api_key: String) -> Self {
        Self {
            exit: false,
            err_msg: None,
            vs_cli: VsClient::new(api_url.to_string(), cert, api_key, true),
            actors: Vec::new(),
            services: Vec::new(),
            visas: Vec::new(),
            selected: Pane::Actors,
            detail_source: Pane::Actors,
            detail_scroll: 0,
            actor_state: TableState::default().with_selected(Some(0)),
            service_state: TableState::default().with_selected(Some(0)),
            visa_state: TableState::default().with_selected(Some(0)),
            last_updated: None,
            table_header_style: Style::default().fg(Color::LightGreen).bg(Color::Black),
            zpr_addr_style: Color::Yellow.into(),
            cn_style: Color::White.into(),
            visa_id_style: Color::White.into(),
            uptime_secs: 0,
            // Pre-fill so sparklines render full-width immediately, new samples
            // pushing in from the right.
            approved_hist: VecDeque::from(vec![0u64; SPARK_MAX]),
            denied_hist: VecDeque::from(vec![0u64; SPARK_MAX]),
            last_approved: 0,
            last_denied: 0,
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn std::error::Error>> {
        while !self.exit {
            terminal.draw(|f| self.draw(f))?;
            self.handle_events()?;
            match self.refresh_state() {
                Ok(_) => {}
                Err(e) => {
                    self.err_msg = Some(e.to_string());
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        self.render_gui(frame, frame.area());
    }

    fn handle_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => self.exit = true,
                    KeyCode::Char('a') => {
                        self.selected = Pane::Actors;
                        self.detail_source = Pane::Actors;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('s') => {
                        self.selected = Pane::Services;
                        self.detail_source = Pane::Services;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('v') => {
                        self.selected = Pane::Visas;
                        self.detail_source = Pane::Visas;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('d') => self.selected = Pane::Details,
                    KeyCode::Tab => {
                        // Cycle Actors -> Services -> Visas -> Details -> Actors.
                        self.selected = match self.selected {
                            Pane::Actors => Pane::Services,
                            Pane::Services => Pane::Visas,
                            Pane::Visas => Pane::Details,
                            Pane::Details => Pane::Actors,
                        };
                        if self.selected != Pane::Details {
                            self.detail_source = self.selected;
                            self.detail_scroll = 0;
                        }
                    }
                    KeyCode::Up | KeyCode::Down => {
                        let down = key.code == KeyCode::Down;
                        if self.selected == Pane::Details {
                            // Scroll one line; bottom clamp is applied in render
                            // against the real content/viewport heights.
                            self.detail_scroll = if down {
                                self.detail_scroll.saturating_add(1)
                            } else {
                                self.detail_scroll.saturating_sub(1)
                            };
                        } else {
                            let (state, len) = match self.selected {
                                Pane::Actors => (&mut self.actor_state, self.actors.len()),
                                Pane::Services => (&mut self.service_state, self.services.len()),
                                Pane::Visas => (&mut self.visa_state, self.visas.len()),
                                Pane::Details => unreachable!(),
                            };
                            state.select(move_selection(state.selected(), len, down));
                            self.detail_scroll = 0; // row changed → reset Details scroll
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Call the VS-API to get data.
    fn refresh_state(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.last_updated.is_some() && self.last_updated.unwrap().elapsed() < REFRESH_RATE {
            return Ok(());
        }
        self.last_updated = Some(Instant::now()); // set first here in case we error out.
        self.err_msg = None;

        {
            let actor_cns = self.vs_cli.get_actors(RoleFilter::All)?;
            self.actors.clear();
            for cn in &actor_cns {
                match self.vs_cli.get_actor(cn) {
                    Ok(a) => {
                        self.actors.push(a);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.actors.sort(); // uses Ord trait
            clamp_state(&mut self.actor_state, self.actors.len());
        }
        self.last_updated = Some(Instant::now());

        {
            let service_ids = self.vs_cli.get_services()?;
            self.services.clear();
            for sid in &service_ids {
                match self.vs_cli.get_service(sid) {
                    Ok(s) => {
                        self.services.push(s);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.services.sort(); // uses Ord trait
            clamp_state(&mut self.service_state, self.services.len());
        }

        {
            let visa_ids = self.vs_cli.get_visas()?;
            self.visas.clear();
            for vid in &visa_ids {
                match self.vs_cli.get_visa(*vid) {
                    Ok(v) => {
                        self.visas.push(v);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.visas.sort(); // uses Ord trait
            self.visas.reverse();
            clamp_state(&mut self.visa_state, self.visas.len());
        }

        // Sample counters/uptime; non-fatal so a stats error never blanks the screen.
        if let Ok(stats) = self.vs_cli.get_stats() {
            let get = |k: &str| {
                stats
                    .stats
                    .get(k)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            self.uptime_secs = get("uptime");

            let approved = get("visa_requests_approved");
            self.approved_hist
                .push_back(approved.saturating_sub(self.last_approved));
            while self.approved_hist.len() > SPARK_MAX {
                self.approved_hist.pop_front();
            }
            self.last_approved = approved;

            let denied = get("visa_requests_denied");
            self.denied_hist
                .push_back(denied.saturating_sub(self.last_denied));
            while self.denied_hist.len() > SPARK_MAX {
                self.denied_hist.pop_front();
            }
            self.last_denied = denied;
        }

        self.last_updated = Some(Instant::now());
        Ok(())
    }

    /// Compose the header as three independently-aligned lines — title (left),
    /// counts (centered), uptime (right) — degrading to fit `width`: full →
    /// shrink sparklines (16→8 bars) → drop sparklines → drop counts → title only.
    fn build_header(&self, width: usize) -> (Line<'static>, Line<'static>, Line<'static>) {
        let title = Line::from("  ZPR Visa Service".bold());
        let uptime = Line::from(vec![
            "UPTIME ".cyan(),
            fmt_uptime(self.uptime_secs).cyan().bold(),
            " ".into(),
        ]);
        let approved = self.last_approved;
        let denied = self.last_denied;
        let a_hist: Vec<u64> = self.approved_hist.iter().copied().collect();
        let d_hist: Vec<u64> = self.denied_hist.iter().copied().collect();

        // One widget: `[LABEL:SPARKLINE:VALUE]` (value bold), colon+spark omitted
        // when `spark_n == 0`.
        let block = |label: &str, hist: &[u64], spark_n: usize, value: u64, color: Color| {
            let plain = Style::default().fg(color);
            let mut spans = vec![Span::styled(format!("[{label}:"), plain)];
            if spark_n > 0 {
                let s = &hist[hist.len().saturating_sub(spark_n)..];
                spans.push(Span::styled(sparkline(s), plain));
                spans.push(Span::styled(":", plain));
            }
            spans.push(Span::styled(format!("{value}"), plain.bold()));
            spans.push(Span::styled("]", plain));
            spans
        };

        // Centered counts: the two widgets side by side, `spark_n` bars each.
        let counts = |spark_n: usize| -> Line<'static> {
            let mut spans = block("APPROVED", &a_hist, spark_n, approved, Color::Green);
            spans.push(Span::raw(" "));
            spans.extend(block("DENIED", &d_hist, spark_n, denied, Color::Red));
            Line::from(spans)
        };

        // The centered block must clear the wider of title/uptime on both sides
        // (+2 for a visual gap), else it overlaps the pegged ends.
        let side = title.width().max(uptime.width());
        let avail = width.saturating_sub(2 * side + 2);

        // Widest → narrowest; first sparkline width that fits shows all three.
        for n in (SPARK_MIN..=SPARK_MAX).rev() {
            let c = counts(n);
            if c.width() <= avail {
                return (title, c, uptime);
            }
        }
        let c = counts(0); // no sparklines
        if c.width() <= avail {
            return (title, c, uptime);
        }
        if title.width() + uptime.width() <= width {
            return (title, Line::default(), uptime); // drop counts
        }
        (title, Line::default(), Line::default()) // title only
    }

    fn render_gui(&mut self, frame: &mut Frame, area: Rect) {
        let instructions = Line::from(vec![
            " a/s/v/d".blue().bold(),
            " select · ".into(),
            "↑/↓".blue().bold(),
            " move · ".into(),
            "q".blue().bold(),
            " quit ".into(),
        ]);

        let [header_area, content_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        let (title, counts, uptime) = self.build_header(header_area.width as usize);
        frame.render_widget(
            Paragraph::new(Text::from(title)).left_aligned(),
            header_area,
        );
        frame.render_widget(Paragraph::new(Text::from(counts)).centered(), header_area);
        frame.render_widget(
            Paragraph::new(Text::from(uptime)).right_aligned(),
            header_area,
        );
        frame.render_widget(
            Paragraph::new(Text::from(instructions)).centered(),
            footer_area,
        );

        if let Some(err) = &self.err_msg {
            frame.render_widget(
                Paragraph::new(Text::from(err.to_string().red())).block(Block::default()),
                content_area,
            );
            return;
        }

        // Else proceed with our layout.
        let [top, visa_area, detail_area] = Layout::vertical([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .areas(content_area);

        let [actor_area, service_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

        self.render_actors(frame, actor_area);
        self.render_services(frame, service_area);
        self.render_visas(frame, visa_area);
        self.render_details(frame, detail_area);
    }

    fn render_services(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Services;
        if self.services.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No services found.").red()).block(pane_block(
                    "S",
                    "ervices ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["Service Name", "CN", "ZPR Address", ""]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);
        let mut row_max_lens = (0u16, 0u16, 0u16); // (SERVICE_NAME, CN, ZPR_ADDR)
        for srec in &self.services {
            if row_max_lens.0 < srec.service_name.len() as u16 {
                row_max_lens.0 = srec.service_name.len() as u16;
            }
            if row_max_lens.1 < srec.actor_cn.len() as u16 {
                row_max_lens.1 = srec.actor_cn.len() as u16;
            }
            if row_max_lens.2 < srec.zpr_addr.len() as u16 {
                row_max_lens.2 = srec.zpr_addr.len() as u16;
            }
        }

        let rows = self.services.iter().map(|srec| {
            let cn = srec.actor_cn.clone();
            let zpr_addr = srec.zpr_addr.clone();
            let flag = "".to_string(); // Used to put "[node]" here
            let cells = [
                Cell::from(srec.service_name.clone()),
                Cell::from(cn).style(self.cn_style),
                Cell::from(zpr_addr).style(self.zpr_addr_style),
                Cell::from(flag),
            ];
            Row::new(cells)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(row_max_lens.2 + 3),
                Constraint::Length(6), // flag
            ],
        )
        .header(header)
        .block(pane_block("S", "ervices ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.service_state);
            self.render_list_scrollbar(
                frame,
                area,
                self.services.len(),
                self.service_state.offset(),
            );
        } else {
            frame.render_widget(table, area);
        }
    }

    // Overlay a scrollbar on a list pane when its rows overflow the visible area.
    fn render_list_scrollbar(&self, frame: &mut Frame, area: Rect, rows: usize, offset: usize) {
        let viewport = area.height.saturating_sub(3) as usize; // borders (2) + header row (1)
        if rows <= viewport {
            return; // everything fits — no indicator
        }
        let max = rows - viewport;
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(if offset > 0 { Some("▲") } else { None })
                .end_symbol(if offset < max { Some("▼") } else { None }),
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut ScrollbarState::new(rows).position(offset),
        );
    }

    fn render_actors(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Actors;
        if self.actors.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No actors found.").red()).block(pane_block(
                    "A",
                    "ctors ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["CN", "ZPR Address", "Join Date", ""]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);
        let mut row_max_lens = (0u16, 0u16); // (CN, ZPR_ADDR)
        for actor in &self.actors {
            if row_max_lens.0 < actor.cn.len() as u16 {
                row_max_lens.0 = actor.cn.len() as u16;
            }
            if row_max_lens.1 < actor.zpr_addr.len() as u16 {
                row_max_lens.1 = actor.zpr_addr.len() as u16;
            }
        }
        let rows = self.actors.iter().map(|actor| {
            let cn = actor.cn.clone();
            let zpr_addr = actor.zpr_addr.clone();
            let ts: DateTime<Utc> = actor.ctime.into();
            let join_date = ts.to_rfc3339_opts(SecondsFormat::Secs, true);
            let flag = if actor.node {
                "[node]".light_magenta()
            } else {
                "".into()
            };
            let cells = [
                Cell::from(cn).style(self.cn_style),
                Cell::from(zpr_addr).style(self.zpr_addr_style),
                Cell::from(join_date),
                Cell::from(flag),
            ];
            Row::new(cells)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(20), // join date
                Constraint::Length(6),  // flag
            ],
        )
        .header(header)
        .block(pane_block("A", "ctors ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.actor_state);
            self.render_list_scrollbar(frame, area, self.actors.len(), self.actor_state.offset());
        } else {
            frame.render_widget(table, area);
        }
    }

    fn render_visas(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Visas;
        if self.visas.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No visas found.").red()).block(pane_block(
                    "V",
                    "isas ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["ID", "Source", "", "Dest", "Expires"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);

        // Max column lengths does not include our "->" col.
        let mut row_max_lens = (0u16, 0u16, 0u16, 20u16); // (ID, SOURCE, DEST, EXPIRES)

        // Iterate once to figure out column widths
        for vrec in &self.visas {
            let idstr = format!("{}", vrec.id);
            if row_max_lens.0 < idstr.len() as u16 {
                row_max_lens.0 = idstr.len() as u16;
            }
            if row_max_lens.1 < vrec.source_addr.as_ref().unwrap_or(&"-".into()).len() as u16 {
                row_max_lens.1 = vrec.source_addr.as_ref().unwrap_or(&"-".into()).len() as u16;
            }
            if row_max_lens.2 < vrec.dest_addr.as_ref().unwrap_or(&"-".into()).len() as u16 {
                row_max_lens.2 = vrec.dest_addr.as_ref().unwrap_or(&"-".into()).len() as u16;
            }
        }

        let rows = self.visas.iter().map(|vrec| {
            let dt: DateTime<Utc> = vrec.expires.into();

            let source_addr = vrec.source_addr.as_ref().unwrap_or(&"-".into()).clone();
            let dest_addr = vrec.dest_addr.as_ref().unwrap_or(&"-".into()).clone();

            let idstr = format!("{}", vrec.id);
            let expstr = dt.to_rfc3339_opts(SecondsFormat::Secs, true);

            let cells = [
                Cell::from(idstr).style(self.visa_id_style),
                Cell::from(source_addr).style(self.zpr_addr_style),
                Cell::from("->".light_magenta()),
                Cell::from(dest_addr).style(self.zpr_addr_style),
                Cell::from(expstr),
            ];
            Row::new(cells)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(3), // for the "->" column
                Constraint::Length(row_max_lens.2 + 3),
                Constraint::Length(row_max_lens.3),
            ],
        )
        .header(header)
        .block(pane_block("V", "isas ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.visa_state);
            self.render_list_scrollbar(frame, area, self.visas.len(), self.visa_state.offset());
        } else {
            frame.render_widget(table, area);
        }
    }

    /// CN of the actor at `zpr_addr`, if known.
    // ponytail: linear scan, index by addr only if the actor list gets large.
    fn cn_for(&self, zpr_addr: &str) -> Option<&str> {
        self.actors
            .iter()
            .find(|a| a.zpr_addr == zpr_addr)
            .map(|a| a.cn.as_str())
    }

    /// Clamp `detail_scroll` to the content, render the scrolled paragraph, and
    /// overlay a scrollbar only when the content overflows the pane.
    fn render_detail_text(&mut self, frame: &mut Frame, area: Rect, text: Text<'static>) {
        let is_selected = self.selected == Pane::Details;
        let content = text.height() as u16;
        let viewport = area.height.saturating_sub(2); // minus borders
        self.detail_scroll = clamp_scroll(self.detail_scroll, content, viewport);
        let max = content.saturating_sub(viewport);
        frame.render_widget(
            Paragraph::new(text)
                .scroll((self.detail_scroll, 0))
                .block(pane_block("D", "etails ", is_selected)),
            area,
        );
        if max > 0 {
            // Content above/below the visible window → show the matching arrow.
            let above = self.detail_scroll > 0;
            let below = self.detail_scroll < max;
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(if above { Some("▲") } else { None })
                    .end_symbol(if below { Some("▼") } else { None }),
                area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut ScrollbarState::new(content as usize).position(self.detail_scroll as usize),
            );
        }
    }

    /// Render the details pane. For a selected visa (`detail_source ==
    /// Pane::Visas`) this shows the full descriptor; every other case shows
    /// the "<entity> <id>" placeholder.
    fn render_details(&mut self, frame: &mut Frame, area: Rect) {
        // Full visa detail when the Visas pane feeds Details and a row is set.
        if self.detail_source == Pane::Visas {
            if let Some(v) = self.visa_state.selected().and_then(|i| self.visas.get(i)) {
                let cn = self.cn_for(&v.requesting_node);
                // area.width - 2 excludes the block borders.
                let text = visa_detail_text(v, cn, SystemTime::now(), area.width.saturating_sub(2));
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        // Full actor detail when the Actors pane feeds Details and a row is set.
        if self.detail_source == Pane::Actors {
            if let Some(a) = self.actor_state.selected().and_then(|i| self.actors.get(i)) {
                let mut services: Vec<&str> = self
                    .services
                    .iter()
                    .filter(|s| s.actor_cn == a.cn)
                    .map(|s| s.service_name.as_str())
                    .collect();
                // Stable order across refreshes.
                services.sort_unstable();
                let text = actor_detail_text(
                    a,
                    &services,
                    SystemTime::now(),
                    area.width.saturating_sub(2),
                );
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        // Full service detail when the Services pane feeds Details and a row is set.
        if self.detail_source == Pane::Services {
            if let Some(s) = self
                .service_state
                .selected()
                .and_then(|i| self.services.get(i))
            {
                let text = service_detail_text(s, area.width.saturating_sub(2));
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        let id = match self.detail_source {
            Pane::Actors => self
                .actor_state
                .selected()
                .and_then(|i| self.actors.get(i))
                .map(|a| a.cn.clone()),
            Pane::Services => self
                .service_state
                .selected()
                .and_then(|i| self.services.get(i))
                .map(|s| s.service_name.clone()),
            Pane::Visas => self
                .visa_state
                .selected()
                .and_then(|i| self.visas.get(i))
                .map(|v| v.id.to_string()),
            Pane::Details => None,
        };
        let text = detail_line(self.detail_source, id);
        // Placeholder is short, so max == 0 → no scrollbar; same path is harmless.
        self.render_detail_text(frame, area, Text::from(text));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LABEL_W, Pane, actor_detail_text, auth_hdr, clamp_scroll, detail_line, flow_str,
        fmt_uptime, labeled, move_selection, remaining_str, service_detail_text,
        session_key_summary, sparkline, ts_or,
    };
    use admin_api_types::{
        ActorDescriptor, ApiAttribute, ApiKeySet, NodeRecordBrief, ServiceDescriptor,
        VisaDescriptor, VisaMatchDirection,
    };
    use std::time::{Duration, UNIX_EPOCH};

    /// A minimal ActorDescriptor; `node_details`/`attrs` set per-test.
    fn sample_actor() -> ActorDescriptor {
        ActorDescriptor {
            cn: "web-server-01".into(),
            ctime: UNIX_EPOCH,
            ident: "CN=web-server-01,O=ZPR".into(),
            node: false,
            zpr_addr: "fd5a:5052::b2".into(),
            attrs: vec![],
            auth_exp: None,
            node_details: None,
        }
    }

    /// A NodeRecordBrief fixture for the "-- node --" block.
    fn sample_node() -> NodeRecordBrief {
        NodeRecordBrief {
            pending_install: 3,
            last_contact: Some(UNIX_EPOCH + Duration::from_secs(600)),
            visa_requests: 1204,
            connect_requests: 5309,
            in_sync: true,
            approved_vreqs: 1180,
            denied_vreqs: 24,
            last_vreq: Some(UNIX_EPOCH + Duration::from_secs(500)),
            adapters: vec!["adapter-a".into(), "adapter-b".into()],
            links: vec!["node-2".into()],
            visas: vec![1, 2, 3],
            visas_enqueued: vec![4],
            pending_revocation: 0,
            vss_port: Some(8443),
        }
    }

    /// Join a Text's lines into one string for substring assertions.
    fn text_str(t: &super::Text<'static>) -> String {
        t.lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A minimal VisaDescriptor for helper tests.
    fn sample_visa() -> VisaDescriptor {
        VisaDescriptor {
            id: 1001,
            expires: UNIX_EPOCH + Duration::from_secs(3600),
            created: UNIX_EPOCH,
            policy_id: "v7".into(),
            zpl: "allow tcp alice -> web:443".into(),
            direction: VisaMatchDirection::Forward,
            requesting_node: "fd5a:5052::a1".into(),
            source_addr: Some("fd5a:5052::a1".into()),
            dest_addr: Some("fd5a:5052::b2".into()),
            source_port: Some(52344),
            dest_port: Some(443),
            proto: "tcp".into(),
            signals: vec![],
            session_key: ApiKeySet {
                format: Default::default(),
                ingress_key: vec![0u8; 48],
                egress_key: vec![0u8; 48],
            },
        }
    }

    /// move_selection clamps at both ends and handles the empty list.
    #[test]
    fn move_selection_clamps_and_steps() {
        assert_eq!(move_selection(None, 0, true), None);
        assert_eq!(move_selection(Some(0), 3, false), Some(0)); // clamp top
        assert_eq!(move_selection(Some(2), 3, true), Some(2)); // clamp bottom
        assert_eq!(move_selection(Some(0), 3, true), Some(1)); // step down
        assert_eq!(move_selection(Some(2), 3, false), Some(1)); // step up
    }

    /// detail_line formats "<entity> <id>" and falls back when nothing selected.
    #[test]
    fn detail_line_formats_and_falls_back() {
        assert_eq!(detail_line(Pane::Visas, Some("1001".into())), "visa 1001");
        assert_eq!(detail_line(Pane::Actors, None), "actor (none selected)");
    }

    /// remaining_str shows EXPIRED past, and hh/mm vs minutes-only.
    #[test]
    fn remaining_str_formats_and_expires() {
        let base = UNIX_EPOCH;
        // 1h02m ahead.
        let exp = base + Duration::from_secs(3720);
        assert_eq!(remaining_str(exp, base), "expires in 1h 02m");
        // 45m ahead → minutes only.
        let exp = base + Duration::from_secs(45 * 60);
        assert_eq!(remaining_str(exp, base), "expires in 45m");
        // already past.
        assert_eq!(
            remaining_str(base, base + Duration::from_secs(1)),
            "EXPIRED"
        );
    }

    /// flow_str renders full flows and uses -/0 for missing addr/port.
    #[test]
    fn flow_str_full_and_missing() {
        let v = sample_visa();
        assert_eq!(
            flow_str(&v),
            "[fd5a:5052::a1]:52344  --TCP-->  [fd5a:5052::b2]:443"
        );
        let mut v = sample_visa();
        v.source_addr = None;
        v.dest_port = None;
        assert_eq!(flow_str(&v), "[-]:52344  --TCP-->  [fd5a:5052::b2]:0");
    }

    /// session_key_summary reports format and byte lengths, never key bytes.
    #[test]
    fn session_key_summary_no_material() {
        let s = session_key_summary(&sample_visa().session_key);
        assert!(s.contains("fmt="));
        assert!(s.contains("ingress=48B"));
        assert!(s.contains("egress=48B"));
    }

    /// labeled wraps long values and indents continuation lines by LABEL_W.
    #[test]
    fn labeled_wraps_and_indents() {
        let lines = labeled("zpl", "alpha bravo charlie delta echo foxtrot", 24);
        assert!(lines.len() > 1, "expected wrapping");
        // Continuation line begins with LABEL_W spaces.
        let second = lines[1].to_string();
        assert!(second.starts_with(&" ".repeat(LABEL_W as usize)));
    }

    /// auth_hdr covers None, expired, and future cases.
    #[test]
    fn auth_hdr_none_expired_future() {
        let base = UNIX_EPOCH;
        assert_eq!(auth_hdr(None, base), "no auth");
        // 1s in the past → EXPIRED.
        assert_eq!(
            auth_hdr(Some(base), base + Duration::from_secs(1)),
            "auth EXPIRED"
        );
        // 1h02m ahead.
        let exp = base + Duration::from_secs(3720);
        assert_eq!(auth_hdr(Some(exp), base), "auth in 1h 02m");
    }

    /// ts_or renders RFC3339 when set, else the fallback word.
    #[test]
    fn ts_or_timestamp_or_fallback() {
        assert!(ts_or(Some(UNIX_EPOCH), "never").contains("1970-01-01"));
        assert_eq!(ts_or(None, "never"), "never");
    }

    /// A node actor shows the badge, the node block, and its bound services.
    #[test]
    fn actor_detail_text_node() {
        let mut a = sample_actor();
        a.node = true;
        a.attrs = vec![ApiAttribute {
            key: "role".into(),
            value: vec!["node".into()],
            expires_at: UNIX_EPOCH,
        }];
        a.node_details = Some(sample_node());
        let s = text_str(&actor_detail_text(&a, &["https-web"], UNIX_EPOCH, 78));
        assert!(s.contains("[node]"));
        assert!(s.contains("-- node"));
        assert!(s.contains("sync"));
        assert!(s.contains("role = node"));
        assert!(s.contains("https-web"));
    }

    /// An adapter (no node_details) omits the node block; empty attrs/services
    /// render "(none)".
    #[test]
    fn actor_detail_text_adapter_empty() {
        let a = sample_actor(); // node=false, no details/attrs
        let s = text_str(&actor_detail_text(&a, &[], UNIX_EPOCH, 78));
        assert!(s.contains("[adapter]"));
        assert!(!s.contains("-- node"));
        assert!(s.contains("attributes   (none)"));
        assert!(s.contains("services     (none)"));
    }

    /// service_detail_text: header carries the service name and every field
    /// value shows up in the rendered lines.
    #[test]
    fn service_detail_text_fields() {
        let sd = ServiceDescriptor {
            service_name: "webproxy".into(),
            actor_cn: "actor-7".into(),
            zpr_addr: "fd5a:5052::1".into(),
            dock_zpr_addr: "fd5a:5052::2".into(),
            service_kind: "https".into(),
            service_endpoints: "https://host:443".into(),
        };
        let s = text_str(&service_detail_text(&sd, 78));
        assert!(s.contains("service webproxy"));
        assert!(s.contains("actor-7"));
        assert!(s.contains("fd5a:5052::1"));
        assert!(s.contains("fd5a:5052::2"));
        assert!(s.contains("https"));
        assert!(s.contains("https://host:443"));
    }

    /// clamp_scroll: fits-in-view clamps to 0; past-end clamps to the max;
    /// in-range is untouched.
    #[test]
    fn clamp_scroll_bounds() {
        // Content shorter than viewport → no scroll.
        assert_eq!(clamp_scroll(5, 10, 20), 0);
        // Offset past the end → content_h - viewport_h.
        assert_eq!(clamp_scroll(100, 30, 10), 20);
        // Offset within range → unchanged.
        assert_eq!(clamp_scroll(3, 30, 10), 3);
        // Exactly fits → 0.
        assert_eq!(clamp_scroll(4, 10, 10), 0);
    }

    /// fmt_uptime rolls seconds into d/h/m/s with zero-padding.
    #[test]
    fn fmt_uptime_rolls_units() {
        assert_eq!(fmt_uptime(100162), "01d 03h 49m 22s");
        assert_eq!(fmt_uptime(0), "00d 00h 00m 00s");
    }

    /// sparkline: no activity is all-min; a monotonic rise maxes at the top bar.
    #[test]
    fn sparkline_idle_and_peak() {
        assert_eq!(sparkline(&[0, 0]), "▁▁");
        assert!(sparkline(&[1, 2, 3]).ends_with('█'));
    }
}
