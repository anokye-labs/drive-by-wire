use std::fs;
use std::path::PathBuf;

/// Manages pairing state: PIN generation, token storage, validation.
pub struct Auth {
    config_path: PathBuf,
    pin: String,
    paired_tokens: Vec<String>,
}

impl Auth {
    /// Load or initialize auth state. Generates a new PIN if none exists.
    pub fn init() -> Self {
        let config_dir = crate::logger::config_dir();
        fs::create_dir_all(&config_dir).ok();
        let config_path = config_dir.join("paired.json");

        let mut paired_tokens = Vec::new();
        if let Ok(contents) = fs::read_to_string(&config_path) {
            // Simple JSON array parsing: ["token1","token2"]
            paired_tokens = parse_string_array(&contents);
        }

        // Generate a 6-digit PIN
        let pin = generate_pin();

        Auth { config_path, pin, paired_tokens }
    }

    /// Get the current PIN for display in TUI.
    pub fn pin(&self) -> &str {
        &self.pin
    }

    /// Check if a token is already paired (trusted).
    pub fn is_paired(&self, token: &str) -> bool {
        self.paired_tokens.iter().any(|t| t == token)
    }

    /// Validate a PIN attempt and pair on success.
    /// Returns a new session token if PIN is correct.
    pub fn try_pair(&mut self, pin_attempt: &str) -> Option<String> {
        if pin_attempt.trim() == self.pin {
            let token = generate_token();
            self.paired_tokens.push(token.clone());
            self.save();
            // Generate a new PIN after successful pairing
            self.pin = generate_pin();
            Some(token)
        } else {
            None
        }
    }

    /// Revoke a paired token.
    #[allow(dead_code)]
    pub fn revoke(&mut self, token: &str) {
        self.paired_tokens.retain(|t| t != token);
        self.save();
    }

    /// Revoke all paired tokens.
    #[allow(dead_code)]
    pub fn revoke_all(&mut self) {
        self.paired_tokens.clear();
        self.save();
    }

    fn save(&self) {
        let tokens: Vec<String> = self.paired_tokens.iter()
            .map(|t| format!("\"{}\"", t))
            .collect();
        let json = format!("[{}]", tokens.join(","));
        let _ = fs::write(&self.config_path, json);
    }
}

fn generate_pin() -> String {
    // Use system time + process ID for entropy (no external deps)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() ^ (std::process::id() as u128) ^ (now.as_micros().wrapping_mul(7919));
    let pin = (seed % 900000 + 100000) as u32; // 6-digit, 100000-999999
    format!("{}", pin)
}

fn generate_token() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() ^ (std::process::id() as u128).wrapping_mul(31337);
    // Generate 32-char hex token
    let mut token = String::with_capacity(32);
    let mut state = seed;
    for _ in 0..32 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        token.push(char::from(b"0123456789abcdef"[((state >> 33) & 0xF) as usize]));
    }
    token
}

fn parse_string_array(json: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();
    let mut depth = 0;
    for ch in json.chars() {
        if escaped { escaped = false; current.push(ch); continue; }
        match ch {
            '\\' if in_string => { escaped = true; }
            '"' => {
                if in_string {
                    items.push(current.clone());
                    current.clear();
                }
                in_string = !in_string;
            }
            '[' if !in_string => { depth += 1; }
            ']' if !in_string => { depth -= 1; if depth == 0 { break; } }
            _ if in_string => { current.push(ch); }
            _ => {}
        }
    }
    items
}
