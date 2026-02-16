use std::sync::mpsc;
use std::io::{self, Stdout};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Terminal,
};

const MAX_LOG_LINES: usize = 200;

/// Events sent from the connection handler to the TUI.
pub enum TuiEvent {
    Connected(String),
    Disconnected,
    AuthAttempt(String),
    AuthSuccess(String),
    AuthFailed(String),
    Command { #[allow(dead_code)] peer: String, cmd_type: String, detail: String, tier: String },
    ConfirmRequest { id: usize, peer: String, description: String, responder: mpsc::Sender<bool> },
    CommandResult { cmd_type: String, success: bool },
    #[allow(dead_code)]
    Log(String),
}

pub struct Tui {
    pub rx: mpsc::Receiver<TuiEvent>,
    pub tx: mpsc::Sender<TuiEvent>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    pin: String,
    hostname: String,
    connected_peer: Option<String>,
    log_lines: Vec<LogEntry>,
    pending_confirm: Option<PendingConfirm>,
    stats: Stats,
    cleaned_up: bool,
}

struct PendingConfirm {
    #[allow(dead_code)]
    id: usize,
    description: String,
    peer: String,
    responder: mpsc::Sender<bool>,
}

#[derive(Clone, Copy)]
struct Stats {
    total_commands: u64,
    auto_approved: u64,
    confirmed: u64,
    denied: u64,
}

#[derive(Clone)]
struct LogEntry {
    text: String,
    level: LogLevel,
}

#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Command,
}

impl Tui {
    pub fn new(pin: &str) -> Self {
        // Set up panic hook to restore terminal on crash
        let original_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            crossterm::terminal::disable_raw_mode().ok();
            crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen).ok();
            original_hook(info);
        }));

        crossterm::terminal::enable_raw_mode().expect("enable raw mode");
        let mut stdout = io::stdout();
        crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)
            .expect("enter alternate screen");
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).expect("create terminal");

        let (tx, rx) = mpsc::channel();
        let hostname = std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());

        Tui {
            rx, tx, terminal,
            pin: pin.to_string(),
            hostname,
            connected_peer: None,
            log_lines: Vec::new(),
            pending_confirm: None,
            stats: Stats { total_commands: 0, auto_approved: 0, confirmed: 0, denied: 0 },
            cleaned_up: false,
        }
    }

    pub fn sender(&self) -> mpsc::Sender<TuiEvent> {
        self.tx.clone()
    }

    pub fn set_pin(&mut self, pin: &str) {
        self.pin = pin.to_string();
    }

    pub fn add_log_pub(&mut self, line: String) {
        self.add_log(line, LogLevel::Info);
    }

    pub fn has_pending(&self) -> bool {
        self.pending_confirm.is_some()
    }

    fn add_log(&mut self, text: String, level: LogLevel) {
        self.log_lines.push(LogEntry { text, level });
        if self.log_lines.len() > MAX_LOG_LINES {
            self.log_lines.remove(0);
        }
    }

    pub fn process_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                TuiEvent::Connected(peer) => {
                    self.add_log(format!("Connected: {}", peer), LogLevel::Success);
                    self.connected_peer = Some(peer);
                }
                TuiEvent::Disconnected => {
                    self.add_log("Disconnected".into(), LogLevel::Warning);
                    self.connected_peer = None;
                }
                TuiEvent::AuthAttempt(peer) => {
                    self.add_log(format!("Auth attempt from {}", peer), LogLevel::Info);
                }
                TuiEvent::AuthSuccess(peer) => {
                    self.add_log(format!("Paired with {}", peer), LogLevel::Success);
                }
                TuiEvent::AuthFailed(peer) => {
                    self.add_log(format!("Auth failed from {}", peer), LogLevel::Error);
                }
                TuiEvent::Command { peer: _, cmd_type, detail, tier } => {
                    self.stats.total_commands += 1;
                    let level = match tier.as_str() {
                        "auto" | "log" => { self.stats.auto_approved += 1; LogLevel::Command }
                        _ => LogLevel::Warning,
                    };
                    let display = if detail.len() > 60 {
                        format!("{}...", &detail[..60])
                    } else {
                        detail
                    };
                    self.add_log(format!("{} {}", cmd_type, display), level);
                }
                TuiEvent::ConfirmRequest { id, peer, description, responder } => {
                    self.pending_confirm = Some(PendingConfirm {
                        id, description: description.clone(), peer: peer.clone(), responder,
                    });
                    self.add_log(format!("CONFIRM? {} (from {})", description, peer), LogLevel::Warning);
                }
                TuiEvent::CommandResult { cmd_type, success } => {
                    let level = if success { LogLevel::Success } else { LogLevel::Error };
                    self.add_log(format!("{} completed", cmd_type), level);
                }
                TuiEvent::Log(msg) => {
                    self.add_log(msg, LogLevel::Info);
                }
            }
        }
    }

    pub fn render(&mut self) {
        let pin = self.pin.clone();
        let hostname = self.hostname.clone();
        let connected_peer = self.connected_peer.clone();
        let stats = self.stats;
        let log_entries = self.log_lines.clone();
        let pending = self.pending_confirm.as_ref()
            .map(|c| (c.description.clone(), c.peer.clone()));
        let log_dir = crate::logger::log_dir().display().to_string();

        self.terminal.draw(|frame| {
            let area = frame.area();
            let confirm_h = if pending.is_some() { 6 } else { 0 };

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(5),       // status
                    Constraint::Min(6),          // activity log
                    Constraint::Length(confirm_h), // confirm panel
                    Constraint::Length(1),        // footer
                ])
                .split(area);

            // ── Status Panel ──
            let status_block = Block::default()
                .title(Line::from(vec![
                    Span::styled(" drive-by-wire ",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled("· ", Style::default().fg(Color::DarkGray)),
                    Span::styled("passenger ", Style::default().fg(Color::White)),
                ]))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan));

            let mut line1 = vec![
                Span::raw("  Host: "),
                Span::styled(hostname.clone(),
                    Style::default().add_modifier(Modifier::BOLD)),
                Span::raw("    "),
            ];
            match &connected_peer {
                Some(p) => {
                    line1.push(Span::styled("● ",
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
                    line1.push(Span::styled(format!("Connected to {}", p),
                        Style::default().fg(Color::Green)));
                }
                None => {
                    line1.push(Span::styled("○ ",
                        Style::default().fg(Color::Yellow)));
                    line1.push(Span::styled("Waiting for connection",
                        Style::default().fg(Color::Yellow)));
                }
            }

            let status_text = vec![
                Line::from(line1),
                Line::from(vec![
                    Span::raw("  PIN:  "),
                    Span::styled(pin.clone(),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw("          "),
                    Span::styled(
                        format!("Cmds: {}  Auto: {}  OK: {}  Deny: {}",
                            stats.total_commands, stats.auto_approved,
                            stats.confirmed, stats.denied),
                        Style::default().fg(Color::DarkGray)),
                ]),
                Line::default(),
            ];
            frame.render_widget(Paragraph::new(status_text).block(status_block), chunks[0]);

            // ── Activity Log ──
            let log_block = Block::default()
                .title(Span::styled(" Activity ",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan));

            let inner_h = log_block.inner(chunks[1]).height as usize;
            let start = log_entries.len().saturating_sub(inner_h);

            let items: Vec<ListItem> = log_entries[start..].iter().map(|entry| {
                let (icon, color) = match entry.level {
                    LogLevel::Info    => ("  ", Color::White),
                    LogLevel::Success => ("✓ ", Color::Green),
                    LogLevel::Warning => ("⚠ ", Color::Yellow),
                    LogLevel::Error   => ("✗ ", Color::Red),
                    LogLevel::Command => ("→ ", Color::Cyan),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(icon, Style::default().fg(color)),
                    Span::styled(entry.text.clone(), Style::default().fg(color)),
                ]))
            }).collect();

            frame.render_widget(List::new(items).block(log_block), chunks[1]);

            // ── Confirmation Panel ──
            if let Some((desc, peer)) = &pending {
                let confirm_block = Block::default()
                    .title(Span::styled(" ⚠ Approval Required ",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Red));

                let confirm_text = vec![
                    Line::from(vec![
                        Span::raw("  From: "),
                        Span::styled(peer.clone(),
                            Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw("    Action: "),
                        Span::styled(desc.clone(),
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::default(),
                    Line::from(vec![
                        Span::raw("  Press "),
                        Span::styled("[Y]",
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                        Span::raw(" Approve   "),
                        Span::styled("[N]",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                        Span::raw(" Deny"),
                    ]),
                ];
                frame.render_widget(Paragraph::new(confirm_text).block(confirm_block), chunks[2]);
            }

            // ── Footer ──
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" Logs: ", Style::default().fg(Color::DarkGray)),
                Span::styled(log_dir.clone(), Style::default().fg(Color::DarkGray)),
                Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
                Span::styled("[Q]", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
                Span::styled("uit  ", Style::default().fg(Color::DarkGray)),
                Span::styled("[Ctrl+C]", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
                Span::styled(" Exit", Style::default().fg(Color::DarkGray)),
            ]));
            frame.render_widget(footer, chunks[3]);
        }).ok();
    }

    pub fn handle_key(&mut self, key: char) -> bool {
        if let Some(confirm) = self.pending_confirm.take() {
            match key {
                'y' | 'Y' => {
                    self.stats.confirmed += 1;
                    let _ = confirm.responder.send(true);
                    self.add_log(format!("APPROVED: {}", confirm.description), LogLevel::Success);
                    crate::logger::log_command(&confirm.peer, "confirm", &confirm.description, "APPROVED");
                    true
                }
                'n' | 'N' => {
                    self.stats.denied += 1;
                    let _ = confirm.responder.send(false);
                    self.add_log(format!("DENIED: {}", confirm.description), LogLevel::Error);
                    crate::logger::log_command(&confirm.peer, "confirm", &confirm.description, "DENIED");
                    true
                }
                _ => {
                    self.pending_confirm = Some(confirm);
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) {
        if self.cleaned_up { return; }
        self.cleaned_up = true;
        crossterm::terminal::disable_raw_mode().ok();
        crossterm::execute!(self.terminal.backend_mut(), crossterm::terminal::LeaveAlternateScreen).ok();
        self.terminal.show_cursor().ok();
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Poll for a keypress without blocking.
pub fn poll_key() -> Option<char> {
    if event::poll(std::time::Duration::ZERO).unwrap_or(false) {
        if let Ok(Event::Key(key)) = event::read() {
            return match key.code {
                KeyCode::Char(c) => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                        Some('\x03')
                    } else {
                        Some(c)
                    }
                }
                KeyCode::Esc => Some('\x1b'),
                _ => None,
            };
        }
    }
    None
}

/// No longer needed — terminal init handled by Tui::new().
pub fn enable_ansi() {}
