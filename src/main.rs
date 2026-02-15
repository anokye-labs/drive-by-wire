mod protocol;
mod executor;
mod mcp;

use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};

const PORT: u16 = 7842;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("mcp") if args.len() > 2 => {
            // mcp <peer_ip> — run as MCP server on stdio
            mcp::run(&args[2]);
        }
        Some("exec") if args.len() > 3 => {
            let cmd = args[3..].join(" ");
            pilot_exec(&args[2], &cmd);
        }
        Some("push") if args.len() > 4 => {
            // push <ip> <local_path> <remote_path>
            pilot_push(&args[2], &args[3], &args[4]);
        }
        Some("pull") if args.len() > 4 => {
            // pull <ip> <remote_path> <local_path>
            pilot_pull(&args[2], &args[3], &args[4]);
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

        let msg_type = json_str_field(&msg, "type").unwrap_or_default();
        let id = json_str_field(&msg, "id").unwrap_or_default();

        let response = match msg_type.as_str() {
            "ping" => {
                format!(r#"{{"type":"pong","id":"{}"}}"#, id)
            }
            "exec" => {
                let cmd = json_str_field(&msg, "cmd").unwrap_or_default();
                let working_dir = json_str_field(&msg, "working_dir");
                println!("  exec: {}", cmd);
                let (code, stdout, stderr) = executor::exec(&cmd, working_dir.as_deref());
                format!(
                    r#"{{"type":"exec_result","id":"{}","exit_code":{},"stdout":{},"stderr":{}}}"#,
                    id, code, json_escape(&stdout), json_escape(&stderr)
                )
            }
            "push" => {
                let dest = json_str_field(&msg, "dest_path").unwrap_or_default();
                let size = json_u64_field(&msg, "size").unwrap_or(0) as usize;
                println!("  push: {} ({} bytes)", dest, size);
                match handle_push(&mut reader, &dest, size) {
                    Ok(()) => format!(r#"{{"type":"ack","id":"{}"}}"#, id),
                    Err(e) => format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(&e.to_string())),
                }
            }
            "pull" => {
                let src = json_str_field(&msg, "src_path").unwrap_or_default();
                println!("  pull: {}", src);
                match std::fs::read(&src) {
                    Ok(data) => {
                        let header = format!(r#"{{"type":"file_data","id":"{}","size":{}}}"#, id, data.len());
                        if let Err(e) = protocol::write_message(&mut writer, &header) {
                            eprintln!("Write error: {}", e);
                            break;
                        }
                        if let Err(e) = protocol::write_raw_bytes(&mut writer, &data) {
                            eprintln!("Write error: {}", e);
                            break;
                        }
                        continue; // already sent response
                    }
                    Err(e) => format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(&e.to_string())),
                }
            }
            "ls" => {
                let path = json_str_field(&msg, "path").unwrap_or_else(|| ".".into());
                println!("  ls: {}", path);
                handle_ls(&id, &path)
            }
            "sysinfo" => {
                println!("  sysinfo");
                handle_sysinfo(&id)
            }
            _ => {
                format!(r#"{{"type":"error","id":"{}","message":"unknown message type: {}"}}"#, id, msg_type)
            }
        };

        if let Err(e) = protocol::write_message(&mut writer, &response) {
            eprintln!("Write error: {}", e);
            break;
        }
    }
}

fn handle_push(reader: &mut impl std::io::Read, dest: &str, size: usize) -> std::io::Result<()> {
    // Create parent directories
    if let Some(parent) = std::path::Path::new(dest).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = protocol::read_raw_bytes(reader, size)?;
    std::fs::write(dest, &data)?;
    println!("    wrote {} bytes to {}", size, dest);
    Ok(())
}

fn handle_ls(id: &str, path: &str) -> String {
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let mut items = Vec::new();
            for entry in entries.flatten() {
                let meta = entry.metadata();
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                items.push(format!(
                    r#"{{"name":{},"is_dir":{},"size":{}}}"#,
                    json_escape(&name), is_dir, size
                ));
            }
            format!(r#"{{"type":"dir_listing","id":"{}","entries":[{}]}}"#, id, items.join(","))
        }
        Err(e) => format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(&e.to_string())),
    }
}

fn handle_sysinfo(id: &str) -> String {
    let hostname = std::process::Command::new("hostname").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let (_, os_info, _) = executor::exec("(Get-CimInstance Win32_OperatingSystem).Caption", None);
    let (_, cpu_info, _) = executor::exec("(Get-CimInstance Win32_Processor).Name", None);
    let (_, ram_info, _) = executor::exec("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)", None);
    format!(
        r#"{{"type":"sysinfo_result","id":"{}","hostname":{},"os":{},"cpu":{},"ram_gb":{}}}"#,
        id,
        json_escape(&hostname),
        json_escape(os_info.trim()),
        json_escape(cpu_info.trim()),
        json_escape(ram_info.trim()),
    )
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

fn pilot_connect(ip: &str) -> (BufReader<TcpStream>, BufWriter<TcpStream>) {
    let addr = format!("{}:{}", ip, PORT);
    let stream = TcpStream::connect(&addr).expect("connect failed");
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    (reader, writer)
}

fn pilot_echo(ip: &str) {
    let (mut reader, mut writer) = pilot_connect(ip);
    println!("Connected! Sending ping...");
    protocol::write_message(&mut writer, r#"{"type":"ping","id":"1"}"#).unwrap();
    let resp = protocol::read_message(&mut reader).unwrap();
    println!("Response: {}", resp);
}

fn pilot_exec(ip: &str, cmd: &str) {
    let (mut reader, mut writer) = pilot_connect(ip);

    let msg = format!(r#"{{"type":"exec","id":"1","cmd":"{}"}}"#, cmd.replace('\\', "\\\\").replace('"', "\\\""));
    protocol::write_message(&mut writer, &msg).unwrap();
    let resp = protocol::read_message(&mut reader).unwrap();
    
    let stdout = json_str_field(&resp, "stdout").unwrap_or_default();
    let stderr = json_str_field(&resp, "stderr").unwrap_or_default();
    let code = json_str_field(&resp, "exit_code").unwrap_or_default();
    
    if !stdout.is_empty() { print!("{}", stdout); }
    if !stderr.is_empty() { eprint!("{}", stderr); }
    if code != "0" && !code.is_empty() { eprintln!("[exit code: {}]", code); }
}

fn pilot_push(ip: &str, local_path: &str, remote_path: &str) {
    let data = std::fs::read(local_path).expect("failed to read local file");
    let (mut reader, mut writer) = pilot_connect(ip);

    let msg = format!(
        r#"{{"type":"push","id":"1","dest_path":"{}","size":{}}}"#,
        remote_path.replace('\\', "\\\\").replace('"', "\\\""),
        data.len()
    );
    protocol::write_message(&mut writer, &msg).unwrap();
    protocol::write_raw_bytes(&mut writer, &data).unwrap();
    
    let resp = protocol::read_message(&mut reader).unwrap();
    let resp_type = json_str_field(&resp, "type").unwrap_or_default();
    if resp_type == "ack" {
        println!("Pushed {} bytes to {}", data.len(), remote_path);
    } else {
        let err = json_str_field(&resp, "message").unwrap_or_default();
        eprintln!("Push failed: {}", err);
    }
}

fn pilot_pull(ip: &str, remote_path: &str, local_path: &str) {
    let (mut reader, mut writer) = pilot_connect(ip);

    let msg = format!(
        r#"{{"type":"pull","id":"1","src_path":"{}"}}"#,
        remote_path.replace('\\', "\\\\").replace('"', "\\\"")
    );
    protocol::write_message(&mut writer, &msg).unwrap();
    
    let resp = protocol::read_message(&mut reader).unwrap();
    let resp_type = json_str_field(&resp, "type").unwrap_or_default();
    if resp_type == "file_data" {
        let size = json_u64_field(&resp, "size").unwrap_or(0) as usize;
        let data = protocol::read_raw_bytes(&mut reader, size).unwrap();
        std::fs::write(local_path, &data).expect("failed to write local file");
        println!("Pulled {} bytes to {}", size, local_path);
    } else {
        let err = json_str_field(&resp, "message").unwrap_or_default();
        eprintln!("Pull failed: {}", err);
    }
}
