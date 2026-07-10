//use colored::Colorize;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};
use reqwest::tls::Certificate;

use chrono::{DateTime, SecondsFormat, Utc};
use std::time::{Duration, Instant};

use admin_api_types::{ActorDescriptor, ServiceDescriptor, VisaDescriptor};

use crate::vsclient::{RoleFilter, VsClient};

/// Do not hit the VS ADMIN api more than this often.
const REFRESH_RATE: Duration = Duration::from_millis(2000);

/// Which content pane is currently selected for keyboard interaction.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Pane {
    Actors,
    Services,
    Visas,
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
    actor_state: TableState,
    service_state: TableState,
    visa_state: TableState,
    table_header_style: Style,
    zpr_addr_style: Style,
    cn_style: Style,
    visa_id_style: Style,
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
            actor_state: TableState::default().with_selected(Some(0)),
            service_state: TableState::default().with_selected(Some(0)),
            visa_state: TableState::default().with_selected(Some(0)),
            last_updated: None,
            table_header_style: Style::default().fg(Color::LightGreen).bg(Color::Black),
            zpr_addr_style: Color::Yellow.into(),
            cn_style: Color::White.into(),
            visa_id_style: Color::White.into(),
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
                    KeyCode::Char('a') => self.selected = Pane::Actors,
                    KeyCode::Char('s') => self.selected = Pane::Services,
                    KeyCode::Char('v') => self.selected = Pane::Visas,
                    KeyCode::Up | KeyCode::Down => {
                        let down = key.code == KeyCode::Down;
                        let (state, len) = match self.selected {
                            Pane::Actors => (&mut self.actor_state, self.actors.len()),
                            Pane::Services => (&mut self.service_state, self.services.len()),
                            Pane::Visas => (&mut self.visa_state, self.visas.len()),
                        };
                        state.select(move_selection(state.selected(), len, down));
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

        self.last_updated = Some(Instant::now());
        Ok(())
    }

    fn render_gui(&mut self, frame: &mut Frame, area: Rect) {
        let title = Line::from("  ZPR Visa Service  ".bold());
        let instructions = Line::from(vec![
            " a/s/v".blue().bold(),
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

        frame.render_widget(Paragraph::new(Text::from(title)).centered(), header_area);
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
        let [actor_area, service_area, visa_area] = Layout::vertical([
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(50),
        ])
        .areas(content_area);

        self.render_actors(frame, actor_area);
        self.render_services(frame, service_area);
        self.render_visas(frame, visa_area);
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
        } else {
            frame.render_widget(table, area);
        }
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
        let clock_unix = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        let clock = format!(" {}", clock_unix.to_rfc3339_opts(SecondsFormat::Secs, true));
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
        .block(
            pane_block("A", "ctors ", is_selected).title(Line::from(clock.cyan()).right_aligned()),
        );
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.actor_state);
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
        } else {
            frame.render_widget(table, area);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::move_selection;

    /// move_selection clamps at both ends and handles the empty list.
    #[test]
    fn move_selection_clamps_and_steps() {
        assert_eq!(move_selection(None, 0, true), None);
        assert_eq!(move_selection(Some(0), 3, false), Some(0)); // clamp top
        assert_eq!(move_selection(Some(2), 3, true), Some(2)); // clamp bottom
        assert_eq!(move_selection(Some(0), 3, true), Some(1)); // step down
        assert_eq!(move_selection(Some(2), 3, false), Some(1)); // step up
    }
}
