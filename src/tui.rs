use std::sync::mpsc;
use std::io::Write;

const MAX_LOG_LINES: usize = 100;

/// Events sent from the connection handler to the TUI.
pub enum TuiEvent {
    /// Connection status changed
    Connected(String),    // peer address
    Disconnected,
    /// Auth event
    AuthAttempt(String),  // peer
    AuthSuccess(String),  // peer
    AuthFailed(String),   // peer
    /// Command received
    Command { #[allow(dead_code)] peer: String, cmd_type: String, detail: String, tier: String },
    /// Command requires confirmation — includes response channel
    ConfirmRequest { id: usize, peer: String, description: String, responder: mpsc::Sender<bool> },
    /// Command result
    CommandResult { cmd_type: String, success: bool },
    /// General log message
    #[allow(dead_code)]
    Log(String),
}

/// The TUI state and renderer.
pub struct Tui {
    pub rx: mpsc::Receiver<TuiEvent>,
    pub tx: mpsc::Sender<TuiEvent>,
    pin: String,
    hostname: String,
    connected_peer: Option<String>,
    log_lines: Vec<String>,
    pending_confirm: Option<PendingConfirm>,
    stats: Stats,
}

struct PendingConfirm {
    #[allow(dead_code)]
    id: usize,
    description: String,
    peer: String,
    responder: mpsc::Sender<bool>,
}

struct Stats {
    total_commands: u64,
    auto_approved: u64,
    confirmed: u64,
    denied: u64,
}

impl Tui {
    pub fn new(pin: &str) -> Self {
        let (tx, rx) = mpsc::channel();
        let hostname = std::process::Command::new("hostname").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());

        Tui {
            rx, tx,
            pin: pin.to_string(),
            hostname,
            connected_peer: None,
            log_lines: Vec::new(),
            pending_confirm: None,
            stats: Stats { total_commands: 0, auto_approved: 0, confirmed: 0, denied: 0 },
        }
    }

    pub fn sender(&self) -> mpsc::Sender<TuiEvent> {
        self.tx.clone()
    }

    /// Update the PIN (after a successful pairing, a new one is generated).
    pub fn set_pin(&mut self, pin: &str) {
        self.pin = pin.to_string();
    }

    /// Add a line to the scrolling log (public).
    pub fn add_log_pub(&mut self, line: String) {
        self.add_log(line);
    }

    /// Add a line to the scrolling log.
    fn add_log(&mut self, line: String) {
        self.log_lines.push(line);
        if self.log_lines.len() > MAX_LOG_LINES {
            self.log_lines.remove(0);
        }
    }

    /// Process all pending events and redraw.
    pub fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                TuiEvent::Connected(peer) => {
                    self.add_log(format!("  ● Connected: {}", peer));
                    self.connected_peer = Some(peer);
                }
                TuiEvent::Disconnected => {
                    self.add_log("  ○ Disconnected".into());
                    self.connected_peer = None;
                }
                TuiEvent::AuthAttempt(peer) => {
                    self.add_log(format!("  🔑 Auth attempt from {}", peer));
                }
                TuiEvent::AuthSuccess(peer) => {
                    self.add_log(format!("  ✓ Paired with {}", peer));
                }
                TuiEvent::AuthFailed(peer) => {
                    self.add_log(format!("  ✗ Auth failed from {}", peer));
                }
                TuiEvent::Command { peer: _, cmd_type, detail, tier } => {
                    self.stats.total_commands += 1;
                    let icon = match tier.as_str() {
                        "auto" => { self.stats.auto_approved += 1; "→" },
                        "log" => { self.stats.auto_approved += 1; "▸" },
                        _ => "⚠",
                    };
                    let display = if detail.len() > 60 {
                        format!("{}…", &detail[..60])
                    } else {
                        detail
                    };
                    self.add_log(format!("  {} {} {}", icon, cmd_type, display));
                }
                TuiEvent::ConfirmRequest { id, peer, description, responder } => {
                    self.pending_confirm = Some(PendingConfirm {
                        id, description: description.clone(), peer: peer.clone(), responder,
                    });
                    self.add_log(format!("  ⚠ CONFIRM? {} (from {})", description, peer));
                }
                TuiEvent::CommandResult { cmd_type, success } => {
                    let icon = if success { "✓" } else { "✗" };
                    self.add_log(format!("  {} {} completed", icon, cmd_type));
                }
                TuiEvent::Log(msg) => {
                    self.add_log(format!("  {}", msg));
                }
            }
        }
    }

    /// Render the full TUI to stdout.
    pub fn render(&self) {
        let mut out = String::new();

        // Clear screen and move cursor to top
        out.push_str("\x1b[2J\x1b[H");

        // Header
        out.push_str("\x1b[1;36m╔══════════════════════════════════════════════════════════╗\x1b[0m\n");
        out.push_str("\x1b[1;36m║\x1b[0m  \x1b[1;37mdrive-by-wire\x1b[0m · passenger                              \x1b[1;36m║\x1b[0m\n");
        out.push_str("\x1b[1;36m╠══════════════════════════════════════════════════════════╣\x1b[0m\n");

        // Status line
        let conn_status = match &self.connected_peer {
            Some(peer) => format!("\x1b[1;32m● Connected\x1b[0m to {}", peer),
            None => "\x1b[1;33m○ Waiting for connection\x1b[0m".into(),
        };
        out.push_str(&format!("\x1b[1;36m║\x1b[0m  Host: \x1b[1m{:<20}\x1b[0m  {}  \x1b[1;36m\x1b[0m\n", self.hostname, conn_status));

        // Pairing PIN
        out.push_str(&format!("\x1b[1;36m║\x1b[0m  PIN:  \x1b[1;33m{}\x1b[0m                    ", self.pin));
        out.push_str(&format!("Cmds: {} (auto:{} ok:{} deny:{})\n",
            self.stats.total_commands, self.stats.auto_approved,
            self.stats.confirmed, self.stats.denied));

        out.push_str("\x1b[1;36m╠══════════════════════════════════════════════════════════╣\x1b[0m\n");

        // Confirmation prompt if pending
        if let Some(ref confirm) = self.pending_confirm {
            out.push_str(&format!("\x1b[1;31m║ ⚠ APPROVAL REQUIRED\x1b[0m\n"));
            out.push_str(&format!("\x1b[1;36m║\x1b[0m  From: {}\n", confirm.peer));
            out.push_str(&format!("\x1b[1;36m║\x1b[0m  Action: \x1b[1m{}\x1b[0m\n", confirm.description));
            out.push_str(&format!("\x1b[1;36m║\x1b[0m  Press \x1b[1;32m[Y]\x1b[0m to approve, \x1b[1;31m[N]\x1b[0m to deny\n"));
            out.push_str("\x1b[1;36m╠══════════════════════════════════════════════════════════╣\x1b[0m\n");
        }

        // Activity log header
        out.push_str("\x1b[1;36m║\x1b[0m  \x1b[1;37mActivity Log\x1b[0m\n");
        out.push_str("\x1b[1;36m╠══════════════════════════════════════════════════════════╣\x1b[0m\n");

        // Show last N log lines (fit terminal)
        let visible = 15;
        let start = if self.log_lines.len() > visible { self.log_lines.len() - visible } else { 0 };
        for line in &self.log_lines[start..] {
            out.push_str(&format!("\x1b[1;36m║\x1b[0m{}\n", line));
        }
        // Pad remaining lines
        for _ in self.log_lines[start..].len()..visible {
            out.push_str("\x1b[1;36m║\x1b[0m\n");
        }

        out.push_str("\x1b[1;36m╚══════════════════════════════════════════════════════════╝\x1b[0m\n");

        // Log directory info
        let log_dir = crate::logger::log_dir();
        out.push_str(&format!("\x1b[90mLogs: {}\x1b[0m\n", log_dir.display()));

        print!("{}", out);
        let _ = std::io::stdout().flush();
    }

    /// Handle a keypress. Returns true if a confirmation was answered.
    pub fn handle_key(&mut self, key: char) -> bool {
        if let Some(confirm) = self.pending_confirm.take() {
            match key {
                'y' | 'Y' => {
                    self.stats.confirmed += 1;
                    let _ = confirm.responder.send(true);
                    self.add_log(format!("  \x1b[32m✓ APPROVED\x1b[0m: {}", confirm.description));
                    crate::logger::log_command(&confirm.peer, "confirm", &confirm.description, "APPROVED");
                    true
                }
                'n' | 'N' => {
                    self.stats.denied += 1;
                    let _ = confirm.responder.send(false);
                    self.add_log(format!("  \x1b[31m✗ DENIED\x1b[0m: {}", confirm.description));
                    crate::logger::log_command(&confirm.peer, "confirm", &confirm.description, "DENIED");
                    true
                }
                _ => {
                    // Put it back
                    self.pending_confirm = Some(confirm);
                    false
                }
            }
        } else {
            false
        }
    }
}

/// Enable virtual terminal processing for ANSI escape codes on Windows.
pub fn enable_ansi() {
    #[cfg(windows)]
    {
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5u32;
        unsafe extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
        }
        unsafe {
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            GetConsoleMode(handle, &mut mode);
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

/// Read a single keypress without waiting for Enter (Windows).
pub fn read_key_nonblocking() -> Option<char> {
    #[cfg(windows)]
    {
        unsafe extern "C" {
            fn _kbhit() -> i32;
            fn _getch() -> i32;
        }
        unsafe {
            if _kbhit() != 0 {
                let ch = _getch();
                if ch > 0 && ch < 128 {
                    return Some(ch as u8 as char);
                }
            }
        }
    }
    None
}
