//! BORU TUI — Ratatui dashboard (Phase 1)
//!
//! Terminal UI for monitoring the cage, viewing logs, and managing execution.
//! Phase 1 only — Phase 2 will use the Tauri GUI.
//!
//! GATE 5: Phase Lock — Ratatui only, no Tauri deps

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    Frame, Terminal,
};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Keybindings:
/// - q: Quit
/// - ↑/↓: Navigate
/// - f: Filter
/// - c: Clear view
/// - p: Pause
/// - m: Toggle security mode display
/// - r: Refresh
///
/// Run the TUI dashboard
///
/// GATE 5: Phase Lock — Ratatui only, no Tauri deps
pub fn run(_socket_path: Option<PathBuf>) -> Result<()> {
    // Setup terminal
    let mut terminal = setup_terminal()?;

    // Create app state
    let mut app = App::new();

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    restore_terminal(&mut terminal)?;

    result
}

fn setup_terminal() -> Result<Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>>
{
    use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
    use crossterm::ExecutableCommand;

    io::stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;

    let terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))?;

    Ok(terminal)
}

fn restore_terminal(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
    use crossterm::ExecutableCommand;

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    let mut last_tick = std::time::Instant::now();
    let tick_rate = Duration::from_millis(250);

    loop {
        // Draw UI
        terminal.draw(|f| ui(f, app))?;

        // Handle events
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match app.mode {
                        AppMode::Normal => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Char('p') => app.paused = !app.paused,
                            KeyCode::Char('c') => {
                                app.clear_logs();
                                app.paused = true;
                                // Reset tick timer so refresh doesn't fire immediately
                                last_tick = std::time::Instant::now();
                                continue; // Skip tick check, go straight to redraw
                            }
                            KeyCode::Char('f') => app.mode = AppMode::Filtering,
                            KeyCode::Char('m') => {
                                app.cycle_security_mode_display()
                            }
                            KeyCode::Char('r') => app.refresh_logs()?,
                            KeyCode::Up => app.previous_row(),
                            KeyCode::Down => app.next_row(),
                            KeyCode::PageUp => app.scroll_up(10),
                            KeyCode::PageDown => app.scroll_down(10),
                            KeyCode::Home => app.scroll_top(),
                            KeyCode::End => app.scroll_bottom(),
                            _ => {}
                        },
                        AppMode::Filtering => match key.code {
                            KeyCode::Esc => {
                                app.filter.clear();
                                app.mode = AppMode::Normal;
                            }
                            KeyCode::Enter => app.mode = AppMode::Normal,
                            KeyCode::Char(c) => app.filter.push(c),
                            KeyCode::Backspace => {
                                app.filter.pop();
                            }
                            _ => {}
                        },
                    }
                }
            }
        }

        // Refresh logs periodically
        if last_tick.elapsed() >= tick_rate {
            if !app.paused {
                app.refresh_logs()?;
            }
            last_tick = std::time::Instant::now();
        }
    }
}


fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Security Mode Panel
            Constraint::Min(5),    // Logs
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Text::from(vec![
        Line::from(vec![
            Span::styled(
                "BORU",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Security Cage Dashboard "),
            Span::styled("Phase 1", Style::default().fg(Color::Yellow)),
        ]),
        Line::from("What runs here, stays here."),
    ]))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    // Security Mode Panel
    let mode_text = format!(
        "Security Mode: {} | Press 'm' to cycle display",
        app.security_mode
    );
    let mode_panel = Paragraph::new(Text::from(vec![
        Line::from(vec![
            Span::styled(
                "🔒 ",
                Style::default().fg(Color::Green),
            ),
            Span::raw(&mode_text),
        ]),
        Line::from(vec![
            Span::styled(
                "HARD",
                Style::default().fg(Color::Red),
            ),
            Span::raw(": Auto-block everything | "),
            Span::styled(
                "MID",
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(": Block network/spawn | "),
            Span::styled(
                "EASY",
                Style::default().fg(Color::Green),
            ),
            Span::raw(": Prompt on writes | "),
            Span::styled(
                "CUSTOM",
                Style::default().fg(Color::Blue),
            ),
            Span::raw(": User rules"),
        ]),
    ]))
    .block(
        Block::default()
            .title("Security Policy")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );
    f.render_widget(mode_panel, chunks[1]);

    // Logs table
    let header_cells = ["Time", "Severity", "Message"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header_row = Row::new(header_cells).style(Style::default()).height(1);

    let filtered_logs: Vec<_> = app
        .logs
        .iter()
        .filter(|log| {
            if app.filter.is_empty() {
                true
            } else {
                log.message
                    .to_lowercase()
                    .contains(&app.filter.to_lowercase())
            }
        })
        .collect();

    let rows = filtered_logs.iter().enumerate().map(|(idx, log)| {
        let color = match log.severity {
            crate::cage::Severity::Critical => Color::Red,
            crate::cage::Severity::High => Color::Magenta,
            crate::cage::Severity::Medium => Color::Yellow,
            crate::cage::Severity::Low => Color::Blue,
        };

        let style = if Some(idx) == app.table_state.selected() {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(log.timestamp.clone()),
            Cell::from(format!("{:?}", log.severity)).style(Style::default().fg(color)),
            Cell::from(log.message.clone()),
        ])
        .style(style)
        .height(1)
    });

    let logs_table = Table::new(
        rows,
        [
            Constraint::Length(25),
            Constraint::Length(10),
            Constraint::Percentage(100),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .title(if app.logs.is_empty() {
                "Audit Logs (empty - run 'boru cage' to generate logs)"
            } else {
                "Audit Logs"
            })
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );

    let mut table_state = app.table_state.clone();
    f.render_stateful_widget(logs_table, chunks[2], &mut table_state);

    // Scrollbar
    if !filtered_logs.is_empty() {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut scrollbar_state = ScrollbarState::new(filtered_logs.len())
            .position(table_state.selected().unwrap_or(0));
        f.render_stateful_widget(
            scrollbar,
            chunks[2].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }

    // Status bar
    let status_text = if app.paused {
        format!(
            " PAUSED | Total: {} | Press 'p' to resume | 'c' clears view",
            app.logs.len()
        )
    } else {
        format!(
            " Total: {} | Filter: '{}' | Security: {} | {}",
            app.logs.len(),
            if app.filter.is_empty() {
                "none"
            } else {
                &app.filter
            },
            app.security_mode,
            "q:quit p:pause c:clear f:filter m:mode r:refresh"
        )
    };

    let status_color = if app.paused {
        Color::Yellow
    } else {
        Color::Green
    };

    let status = Paragraph::new(status_text)
        .alignment(Alignment::Left)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(status_color)),
        );
    f.render_widget(status, chunks[3]);

    // Filter popup
    if app.mode == AppMode::Filtering {
        let area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(40),
                Constraint::Length(3),
                Constraint::Percentage(40),
            ])
            .split(f.area())[1];

        let popup = Paragraph::new(app.filter.clone()).block(
            Block::default()
                .title("Filter")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }
}

#[derive(Debug, Clone, PartialEq)]
enum AppMode {
    Normal,
    Filtering,
}

struct App {
    logs: Vec<LogEntry>,
    table_state: TableState,
    filter: String,
    paused: bool,
    mode: AppMode,
    log_path: PathBuf,
    security_mode: String,
}

impl App {
    fn new() -> Self {
        let log_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("boru")
            .join("audit.log");

        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            logs: Vec::new(),
            table_state,
            filter: String::new(),
            paused: false,
            mode: AppMode::Normal,
            log_path,
            security_mode: "🟠 MID".to_string(),
        }
    }

    fn refresh_logs(&mut self) -> Result<()> {
        // Ensure log directory exists (creates on first run)
        if let Some(parent) = self.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if !self.log_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.log_path)?;
        let new_logs: Vec<LogEntry> = content
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(Self::parse_log_line)
            .collect();

        self.logs = new_logs;

        // Adjust selection if needed
        if self.logs.is_empty() {
            self.table_state.select(None);
        } else if self.table_state.selected().unwrap_or(0) >= self.logs.len() {
            self.table_state.select(Some(self.logs.len() - 1));
        }

        Ok(())
    }

    fn parse_log_line(line: &str) -> Option<LogEntry> {
        // Parse format: [TIMESTAMP] [SEVERITY] [ACTION] [REASON]
        let parts: Vec<&str> = line.split("] ").collect();
        if parts.len() < 4 {
            return Some(LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: crate::cage::Severity::Low,
                message: line.to_string(),
            });
        }

        let timestamp = parts[0].trim_start_matches('[').to_string();
        let severity_str = parts[1].trim_start_matches('[');
        let severity = match severity_str {
            "Critical" => crate::cage::Severity::Critical,
            "High" => crate::cage::Severity::High,
            "Medium" => crate::cage::Severity::Medium,
            _ => crate::cage::Severity::Low,
        };

        let message = parts[2..].join("] ").trim_start_matches('[').to_string();

        Some(LogEntry {
            timestamp,
            severity,
            message,
        })
    }

    fn clear_logs(&mut self) {
        self.logs.clear();
        self.table_state.select(None);
    }

    fn next_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.logs.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous_row(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.logs.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn scroll_up(&mut self, amount: usize) {
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some(i.saturating_sub(amount)));
    }

    fn scroll_down(&mut self, amount: usize) {
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state
            .select(Some((i + amount).min(self.logs.len().saturating_sub(1))));
    }

    fn scroll_top(&mut self) {
        self.table_state.select(Some(0));
    }

    fn scroll_bottom(&mut self) {
        if !self.logs.is_empty() {
            self.table_state.select(Some(self.logs.len() - 1));
        }
    }

    fn cycle_security_mode_display(&mut self) {
        // Cycle through display modes for demonstration
        self.security_mode = match self.security_mode.as_str() {
            "🟠 MID" => "🔴 HARD".to_string(),
            "🔴 HARD" => "🟡 EASY".to_string(),
            "🟡 EASY" => "⚙️ CUSTOM".to_string(),
            _ => "🟠 MID".to_string(),
        };
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub severity: crate::cage::Severity,
    pub message: String,
}
