use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub struct Logger {
    log_dir: PathBuf,
}

/// Initialize the global logger. Call once at startup.
pub fn init() {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
    let log_dir = PathBuf::from(home).join(".drive-by-wire").join("logs");
    fs::create_dir_all(&log_dir).ok();
    *LOGGER.lock().unwrap() = Some(Logger { log_dir });
}

/// Log a message with timestamp to today's log file.
pub fn log(category: &str, message: &str) {
    let guard = LOGGER.lock().unwrap();
    let logger = match guard.as_ref() {
        Some(l) => l,
        None => return,
    };

    let now = std::time::SystemTime::now();
    let secs = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    // Convert to date/time components (UTC)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Simple date calculation from days since epoch
    let (year, month, day) = days_to_date(days);

    let date_str = format!("{:04}-{:02}-{:02}", year, month, day);
    let time_str = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
    let log_file = logger.log_dir.join(format!("{}.log", date_str));

    let line = format!("[{}Z] [{}] {}\n", time_str, category, message);

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_file) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Log a command request from a connected peer.
pub fn log_command(peer: &str, cmd_type: &str, detail: &str, decision: &str) {
    let sanitized = redact_sensitive(detail);
    log("CMD", &format!("{} | {} | {} | {}", peer, cmd_type, sanitized, decision));
}

/// Log a connection event.
pub fn log_connection(peer: &str, event: &str) {
    log("CONN", &format!("{} | {}", peer, event));
}

/// Log an auth event.
pub fn log_auth(peer: &str, event: &str) {
    log("AUTH", &format!("{} | {}", peer, event));
}

/// Redact passwords and other sensitive fields from log detail strings.
fn redact_sensitive(s: &str) -> String {
    let mut result = s.to_string();
    // Redact password fields
    for field in &["password", "Password"] {
        let pattern = format!("\"{}\":\"", field);
        if let Some(start) = result.find(&pattern) {
            let val_start = start + pattern.len();
            if let Some(end) = result[val_start..].find('"') {
                result = format!("{}***{}", &result[..val_start], &result[val_start + end..]);
            }
        }
    }
    result
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    // Simplified Gregorian calendar calculation
    let mut year = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let months: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    for &m in &months {
        if days < m { break; }
        days -= m;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Get the log directory path.
pub fn log_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
    PathBuf::from(home).join(".drive-by-wire").join("logs")
}

/// Get the config directory path.
pub fn config_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
    PathBuf::from(home).join(".drive-by-wire")
}
