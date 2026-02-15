mod protocol;
mod executor;

use std::io::{Read, Write, BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};

const PORT: u16 = 7842;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("exec") if args.len() > 3 => {
            // exec <ip> <command>
            let cmd = args[3..].join(" ");
            pilot_exec(&args[2], &cmd);
        }
        Some("connect") if args.len() > 2 => {
            pilot_echo(&args[2]);
        }
        _ => {
            // Default: passenger mode (double-click friendly)
            print_local_ips();
            println!("\ndrive-by-wire passenger — listening on port {}", PORT);
            passenger_listen();
        }
    }
}

fn print_local_ips() {
    println!("=== drive-by-wire ===");
    if let Ok(h) = std::process::Command::new("hostname").output() {
        print!("Hostname: {}", String::from_utf8_lossy(&h.stdout).trim());
    }
    if let Ok(output) = std::process::Command::new("ipconfig").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("169.254.") {
                println!("  {}", line.trim());
            }
        }
    }
    println!();
}

fn add_firewall_rule() {
    let exe = std::env::current_exe().unwrap_or_default();
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
               "name=drive-by-wire", "dir=in", "action=allow",
               &format!("program={}", exe.display()),
               "protocol=tcp", &format!("localport={}", PORT)])
        .output();
}

fn passenger_listen() {
    add_firewall_rule();

    let addr = format!("0.0.0.0:{}", PORT);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", addr, e);
            eprintln!("Press Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
            return;
        }
    };

    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("Connection from {}", peer);
                handle_connection(stream);
                println!("Disconnected. Waiting for next connection...");
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }
}

fn handle_connection(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut writer = BufWriter::new(stream);

    loop {
        let msg = match protocol::read_message(&mut reader) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!("Read error: {}", e);
                }
                break;
            }
        };

        // Parse as simple JSON: {"type":"exec","cmd":"...","working_dir":"..."}
        // Minimal parsing without serde — just extract fields
        let response = dispatch(&msg);
        if let Err(e) = protocol::write_message(&mut writer, &response) {
            eprintln!("Write error: {}", e);
            break;
        }
    }
}

fn dispatch(msg: &str) -> String {
    // Parse type field
    let msg_type = json_str_field(msg, "type").unwrap_or_default();
    let id = json_str_field(msg, "id").unwrap_or_default();

    match msg_type.as_str() {
        "ping" => {
            format!(r#"{{"type":"pong","id":"{}"}}"#, id)
        }
        "exec" => {
            let cmd = json_str_field(msg, "cmd").unwrap_or_default();
            let working_dir = json_str_field(msg, "working_dir");
            println!("  exec: {}", cmd);
            let (code, stdout, stderr) = executor::exec(&cmd, working_dir.as_deref());
            format!(
                r#"{{"type":"exec_result","id":"{}","exit_code":{},"stdout":{},"stderr":{}}}"#,
                id, code, json_escape(&stdout), json_escape(&stderr)
            )
        }
        "push" => {
            let dest = json_str_field(msg, "dest_path").unwrap_or_default();
            let size = json_u64_field(msg, "size").unwrap_or(0) as usize;
            // Read raw file bytes from stream — but we need the reader here
            // For now, return an error since push needs special handling
            format!(r#"{{"type":"error","id":"{}","message":"push not yet implemented in dispatch"}}"#, id)
        }
        _ => {
            format!(r#"{{"type":"error","id":"{}","message":"unknown message type: {}"}}"#, id, msg_type)
        }
    }
}

// Minimal JSON helpers — no serde dependency
fn json_str_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!(r#""{}":""#, field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let mut end = 0;
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped { escaped = false; end += ch.len_utf8(); continue; }
        if ch == '\\' { escaped = true; end += 1; continue; }
        if ch == '"' { break; }
        end += ch.len_utf8();
    }
    Some(rest[..end].replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn json_u64_field(json: &str, field: &str) -> Option<u64> {
    let pattern = format!(r#""{}":"#, field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// --- Pilot-side commands ---

fn pilot_echo(ip: &str) {
    let addr = format!("{}:{}", ip, PORT);
    println!("Connecting to {}...", addr);
    let stream = TcpStream::connect(&addr).expect("connect failed");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    println!("Connected! Sending ping...");
    protocol::write_message(&mut writer, r#"{"type":"ping","id":"1"}"#).unwrap();
    let resp = protocol::read_message(&mut reader).unwrap();
    println!("Response: {}", resp);
}

fn pilot_exec(ip: &str, cmd: &str) {
    let addr = format!("{}:{}", ip, PORT);
    let stream = TcpStream::connect(&addr).expect("connect failed");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    let msg = format!(r#"{{"type":"exec","id":"1","cmd":"{}"}}"#, cmd.replace('\\', "\\\\").replace('"', "\\\""));
    protocol::write_message(&mut writer, &msg).unwrap();
    let resp = protocol::read_message(&mut reader).unwrap();
    
    // Print result
    let stdout = json_str_field(&resp, "stdout").unwrap_or_default();
    let stderr = json_str_field(&resp, "stderr").unwrap_or_default();
    let code = json_str_field(&resp, "exit_code").unwrap_or_default();
    
    if !stdout.is_empty() { print!("{}", stdout); }
    if !stderr.is_empty() { eprint!("{}", stderr); }
    if code != "0" && !code.is_empty() { eprintln!("[exit code: {}]", code); }
}
