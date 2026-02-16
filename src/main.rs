mod protocol;
mod executor;
mod mcp;
mod discover;
mod logger;
mod auth;
mod security;
mod tui;

use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};

const PORT: u16 = 7842;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("mcp") if args.len() > 2 => {
            // mcp <peer_ip> — run as MCP server on stdio
            mcp::run(&args[2]);
        }
        Some("mcp") => {
            // mcp (no IP) — auto-discover peer, then run MCP server
            match discover::find_peer() {
                Some(ip) => mcp::run(&ip),
                None => {
                    eprintln!("ERROR: Could not find passenger. Is the USB cable connected?");
                    std::process::exit(1);
                }
            }
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
        Some("deploy") if args.len() > 2 => {
            // deploy <ip> — push this binary to passenger and restart it
            pilot_deploy(&args[2]);
        }
        Some("discover") => {
            // discover — find peer on USB4/Thunderbolt P2P link
            match discover::find_peer() {
                Some(ip) => println!("Peer found: {}", ip),
                None => {
                    println!("No peer found. Is the USB cable connected?");
                    std::process::exit(1);
                }
            }
        }
        Some("pair") if args.len() > 3 => {
            // pair <ip> <pin> — pair with a passenger using its PIN
            pilot_pair(&args[2], &args[3]);
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
    logger::init();
    logger::log("STARTUP", "Passenger starting");

    let auth = Arc::new(Mutex::new(auth::Auth::init()));
    let pin = auth.lock().unwrap().pin().to_string();

    let mut tui_state = tui::Tui::new(&pin);
    let tui_tx = tui_state.sender();
    tui::enable_ansi();

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
    listener.set_nonblocking(true).ok();
    logger::log("STARTUP", &format!("Listening on port {}", PORT));
    tui_state.add_log_pub("Listening on port 7842...".into());
    tui_state.render();

    let confirm_counter = Arc::new(Mutex::new(0usize));

    loop {
        // Check for incoming connections (non-blocking)
        match listener.accept() {
            Ok((stream, peer)) => {
                let peer_str = peer.to_string();
                logger::log_connection(&peer_str, "incoming");
                let tx = tui_tx.clone();
                let auth_clone = Arc::clone(&auth);
                let counter = Arc::clone(&confirm_counter);

                std::thread::spawn(move || {
                    handle_connection_secure(stream, &peer_str, tx, auth_clone, counter);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection pending — normal
            }
            Err(e) => {
                logger::log("ERROR", &format!("Accept error: {}", e));
            }
        }

        // Process TUI events and redraw
        tui_state.process_events();
        // Update PIN in case it changed after pairing
        if let Ok(a) = auth.lock() {
            tui_state.set_pin(a.pin());
        }
        tui_state.render();

        // Check for keyboard input (Y/N for confirms)
        if let Some(key) = tui::read_key_nonblocking() {
            tui_state.handle_key(key);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn handle_connection_secure(
    stream: TcpStream,
    peer: &str,
    tx: mpsc::Sender<tui::TuiEvent>,
    auth: Arc<Mutex<auth::Auth>>,
    counter: Arc<Mutex<usize>>,
) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut writer = BufWriter::new(stream);

    tx.send(tui::TuiEvent::Connected(peer.to_string())).ok();

    // Auth handshake: first message must be "auth"
    let first_msg = match protocol::read_message(&mut reader) {
        Ok(m) => m,
        Err(_) => {
            tx.send(tui::TuiEvent::Disconnected).ok();
            return;
        }
    };

    let msg_type = json_str_field(&first_msg, "type").unwrap_or_default();
    let authenticated = match msg_type.as_str() {
        "auth" => {
            let token = json_str_field(&first_msg, "token");
            let pin = json_str_field(&first_msg, "pin");

            tx.send(tui::TuiEvent::AuthAttempt(peer.to_string())).ok();
            logger::log_auth(peer, "auth attempt");

            if let Some(tok) = token {
                // Token-based auth (previously paired)
                let ok = auth.lock().unwrap().is_paired(&tok);
                if ok {
                    let resp = r#"{"type":"auth_ok"}"#;
                    protocol::write_message(&mut writer, resp).ok();
                    tx.send(tui::TuiEvent::AuthSuccess(peer.to_string())).ok();
                    logger::log_auth(peer, "token accepted");
                    true
                } else {
                    let resp = r#"{"type":"auth_failed","message":"invalid token"}"#;
                    protocol::write_message(&mut writer, resp).ok();
                    tx.send(tui::TuiEvent::AuthFailed(peer.to_string())).ok();
                    logger::log_auth(peer, "invalid token");
                    false
                }
            } else if let Some(p) = pin {
                // PIN-based pairing
                let result = auth.lock().unwrap().try_pair(&p);
                if let Some(new_token) = result {
                    let resp = format!(r#"{{"type":"auth_ok","token":"{}"}}"#, new_token);
                    protocol::write_message(&mut writer, &resp).ok();
                    tx.send(tui::TuiEvent::AuthSuccess(peer.to_string())).ok();
                    logger::log_auth(peer, "PIN accepted, paired");
                    true
                } else {
                    let resp = r#"{"type":"auth_failed","message":"wrong PIN"}"#;
                    protocol::write_message(&mut writer, resp).ok();
                    tx.send(tui::TuiEvent::AuthFailed(peer.to_string())).ok();
                    logger::log_auth(peer, "wrong PIN");
                    false
                }
            } else {
                let resp = r#"{"type":"auth_failed","message":"provide token or pin"}"#;
                protocol::write_message(&mut writer, resp).ok();
                tx.send(tui::TuiEvent::AuthFailed(peer.to_string())).ok();
                false
            }
        }
        _ => {
            // Non-auth message received.
            // If no one has ever paired, allow the connection (TOFU model).
            let has_paired = auth.lock().unwrap().has_any_paired();
            if !has_paired {
                tx.send(tui::TuiEvent::AuthSuccess(peer.to_string())).ok();
                logger::log_auth(peer, "allowed (no paired devices yet — TOFU)");
                // Process this first message as a command after auth
                // We need to handle it inline since we already consumed it
                let msg_type_inner = json_str_field(&first_msg, "type").unwrap_or_default();
                let id = json_str_field(&first_msg, "id").unwrap_or_default();
                let tier = security::classify(&msg_type_inner);
                let tier_str = match tier {
                    security::Tier::Auto => "auto",
                    security::Tier::Log => "log",
                    security::Tier::Confirm => "confirm",
                };
                logger::log_command(peer, &msg_type_inner, &first_msg, tier_str);

                if msg_type_inner == "pull" {
                    let src = json_str_field(&first_msg, "src_path").unwrap_or_default();
                    if let Ok(data) = std::fs::read(&src) {
                        let header = format!(r#"{{"type":"file_data","id":"{}","size":{}}}"#, id, data.len());
                        let _ = protocol::write_message(&mut writer, &header);
                        let _ = protocol::write_raw_bytes(&mut writer, &data);
                    }
                } else {
                    let response = dispatch_command(&msg_type_inner, &id, &first_msg, &mut reader);
                    let _ = protocol::write_message(&mut writer, &response);
                }
                true // continue to process more commands
            } else {
                let resp = r#"{"type":"auth_required","message":"send auth first"}"#;
                protocol::write_message(&mut writer, resp).ok();
                tx.send(tui::TuiEvent::AuthFailed(peer.to_string())).ok();
                logger::log_auth(peer, "no auth message");
                false
            }
        }
    };

    if !authenticated {
        tx.send(tui::TuiEvent::Disconnected).ok();
        logger::log_connection(peer, "rejected (auth failed)");
        return;
    }

    // Authenticated — process commands with ACL
    loop {
        let msg = match protocol::read_message(&mut reader) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    logger::log("ERROR", &format!("Read error from {}: {}", peer, e));
                }
                break;
            }
        };

        let msg_type = json_str_field(&msg, "type").unwrap_or_default();
        let id = json_str_field(&msg, "id").unwrap_or_default();
        let tier = security::classify(&msg_type);

        // Log the command
        let detail = truncate_for_display(&msg, 120);
        let tier_str = match tier {
            security::Tier::Auto => "auto",
            security::Tier::Log => "log",
            security::Tier::Confirm => "confirm",
        };
        tx.send(tui::TuiEvent::Command {
            peer: peer.to_string(),
            cmd_type: msg_type.clone(),
            detail: detail.clone(),
            tier: tier_str.to_string(),
        }).ok();
        logger::log_command(peer, &msg_type, &detail, tier_str);

        // Check authorization
        if tier == security::Tier::Confirm {
            let description = security::describe_command(&msg_type, &msg);
            let (resp_tx, resp_rx) = mpsc::channel();
            let confirm_id = {
                let mut c = counter.lock().unwrap();
                *c += 1;
                *c
            };
            tx.send(tui::TuiEvent::ConfirmRequest {
                id: confirm_id,
                peer: peer.to_string(),
                description: description.clone(),
                responder: resp_tx,
            }).ok();

            // Wait for confirmation (blocks this connection's thread)
            match resp_rx.recv_timeout(std::time::Duration::from_secs(120)) {
                Ok(true) => { /* approved, continue */ }
                Ok(false) => {
                    let resp = format!(
                        r#"{{"type":"error","id":"{}","message":"denied by operator"}}"#, id
                    );
                    protocol::write_message(&mut writer, &resp).ok();
                    continue;
                }
                Err(_) => {
                    let resp = format!(
                        r#"{{"type":"error","id":"{}","message":"confirmation timed out (120s)"}}"#, id
                    );
                    protocol::write_message(&mut writer, &resp).ok();
                    continue;
                }
            }
        }

        // Dispatch the command
        // Pull needs special handling (writes directly to stream)
        if msg_type == "pull" {
            let src = json_str_field(&msg, "src_path").unwrap_or_default();
            match std::fs::read(&src) {
                Ok(data) => {
                    let header = format!(r#"{{"type":"file_data","id":"{}","size":{}}}"#, id, data.len());
                    if protocol::write_message(&mut writer, &header).is_err() { break; }
                    if protocol::write_raw_bytes(&mut writer, &data).is_err() { break; }
                    tx.send(tui::TuiEvent::CommandResult { cmd_type: "pull".into(), success: true }).ok();
                }
                Err(e) => {
                    let resp = format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(&e.to_string()));
                    if protocol::write_message(&mut writer, &resp).is_err() { break; }
                    tx.send(tui::TuiEvent::CommandResult { cmd_type: "pull".into(), success: false }).ok();
                }
            }
            continue;
        }

        let response = dispatch_command(&msg_type, &id, &msg, &mut reader);

        let success = !response.contains("\"type\":\"error\"");
        tx.send(tui::TuiEvent::CommandResult {
            cmd_type: msg_type.clone(),
            success,
        }).ok();

        if let Err(e) = protocol::write_message(&mut writer, &response) {
            logger::log("ERROR", &format!("Write error to {}: {}", peer, e));
            break;
        }
    }

    tx.send(tui::TuiEvent::Disconnected).ok();
    logger::log_connection(peer, "disconnected");
}

fn truncate_for_display(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}…", &s[..max]) }
}

/// Dispatch a command and return the response JSON.
/// Extracted from handle_connection so both secure and legacy paths can use it.
fn dispatch_command(
    msg_type: &str, id: &str, msg: &str,
    reader: &mut BufReader<TcpStream>,
) -> String {
    match msg_type {
        "ping" => format!(r#"{{"type":"pong","id":"{}"}}"#, id),
        "exec" => {
            let cmd = json_str_field(msg, "cmd").unwrap_or_default();
            let working_dir = json_str_field(msg, "working_dir");
            let (code, stdout, stderr) = executor::exec(&cmd, working_dir.as_deref());
            format!(
                r#"{{"type":"exec_result","id":"{}","exit_code":{},"stdout":{},"stderr":{}}}"#,
                id, code, json_escape(&stdout), json_escape(&stderr)
            )
        }
        "push" => {
            let dest = json_str_field(msg, "dest_path").unwrap_or_default();
            let size = json_u64_field(msg, "size").unwrap_or(0) as usize;
            match handle_push(reader, &dest, size) {
                Ok(()) => format!(r#"{{"type":"ack","id":"{}"}}"#, id),
                Err(e) => format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(&e.to_string())),
            }
        }
        "ls" => {
            let path = json_str_field(msg, "path").unwrap_or_else(|| ".".into());
            handle_ls(id, &path)
        }
        "sysinfo" => handle_sysinfo(id),
        "reg_read" => {
            let path = json_str_field(msg, "path").unwrap_or_default();
            let name = json_str_field(msg, "name").unwrap_or_default();
            let cmd = format!("(Get-ItemProperty '{}' -Name '{}' -ErrorAction Stop).'{}'", path, name, name);
            let (code, stdout, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"reg_result","id":"{}","value":{}}}"#, id, json_escape(stdout.trim()))
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "reg_write" => {
            let path = json_str_field(msg, "path").unwrap_or_default();
            let name = json_str_field(msg, "name").unwrap_or_default();
            let value = json_str_field(msg, "value").unwrap_or_default();
            let kind = json_str_field(msg, "kind").unwrap_or_else(|| "String".into());
            let ps_type = match kind.as_str() {
                "REG_DWORD" | "DWord" => "DWord",
                "REG_QWORD" | "QWord" => "QWord",
                "REG_EXPAND_SZ" | "ExpandString" => "ExpandString",
                "REG_MULTI_SZ" | "MultiString" => "MultiString",
                _ => "String",
            };
            let cmd = format!(
                "New-ItemProperty -Path '{}' -Name '{}' -Value '{}' -PropertyType {} -Force | Out-Null",
                path, name, value, ps_type
            );
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "reg_delete" => {
            let path = json_str_field(msg, "path").unwrap_or_default();
            let name = json_str_field(msg, "name").unwrap_or_default();
            let cmd = format!("Remove-ItemProperty -Path '{}' -Name '{}' -Force -ErrorAction Stop", path, name);
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "service" => {
            let svc_name = json_str_field(msg, "name").unwrap_or_default();
            let action = json_str_field(msg, "action").unwrap_or_default();
            let cmd = match action.as_str() {
                "start" => format!("Start-Service '{}' -ErrorAction Stop; Get-Service '{}'", svc_name, svc_name),
                "stop" => format!("Stop-Service '{}' -Force -ErrorAction Stop; Get-Service '{}'", svc_name, svc_name),
                "restart" => format!("Restart-Service '{}' -Force -ErrorAction Stop; Get-Service '{}'", svc_name, svc_name),
                "status" => format!("Get-Service '{}'", svc_name),
                _ => format!("echo 'unknown action: {}'", action),
            };
            let (code, stdout, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"exec_result","id":"{}","exit_code":0,"stdout":{},"stderr":""}}"#, id, json_escape(stdout.trim()))
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "env_set" => {
            let name = json_str_field(msg, "name").unwrap_or_default();
            let value = json_str_field(msg, "value").unwrap_or_default();
            let scope = json_str_field(msg, "scope").unwrap_or_else(|| "machine".into());
            let target = if scope == "user" { "User" } else { "Machine" };
            let cmd = format!("[Environment]::SetEnvironmentVariable('{}', '{}', '{}')", name, value, target);
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "reboot" => {
            let delay = json_u64_field(msg, "delay_secs").unwrap_or(5);
            let cmd = format!("shutdown /r /t {}", delay);
            let (_, _, _) = executor::exec(&cmd, None);
            format!(r#"{{"type":"ack","id":"{}"}}"#, id)
        }
        "enable_rdp" => {
            let cmd = concat!(
                "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Force; ",
                "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue; ",
                "Write-Output 'RDP enabled'"
            );
            let (code, _, stderr) = executor::exec(cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "enable_ssh" => {
            let cmd = concat!(
                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue; ",
                "Start-Service sshd -ErrorAction SilentlyContinue; ",
                "Set-Service -Name sshd -StartupType Automatic; ",
                "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue; ",
                "Write-Output 'SSH enabled'"
            );
            let (code, _, stderr) = executor::exec(cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "set_hostname" => {
            let name = json_str_field(msg, "name").unwrap_or_default();
            let cmd = format!("Rename-Computer -NewName '{}' -Force", name);
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}","message":"Reboot required for hostname change"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "set_power" => {
            let plan = json_str_field(msg, "plan").unwrap_or_default();
            let guid = match plan.as_str() {
                "high_performance" => "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                _ => "381b4222-f694-41f0-9685-ff5bb260df2e",
            };
            let cmd = format!("powercfg /setactive {}", guid);
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "create_user" => {
            let username = json_str_field(msg, "username").unwrap_or_default();
            let password = json_str_field(msg, "password").unwrap_or_default();
            let admin = msg.contains("\"admin\":true");
            let mut cmd = format!("net user '{}' '{}' /add", username, password);
            if admin {
                cmd.push_str(&format!("; net localgroup Administrators '{}' /add", username));
            }
            let (code, _, stderr) = executor::exec(&cmd, None);
            if code == 0 {
                format!(r#"{{"type":"ack","id":"{}"}}"#, id)
            } else {
                format!(r#"{{"type":"error","id":"{}","message":{}}}"#, id, json_escape(stderr.trim()))
            }
        }
        "winget_install" => {
            let package = json_str_field(msg, "package_id").unwrap_or_default();
            let cmd = format!("winget install '{}' --silent --accept-package-agreements --accept-source-agreements", package);
            let (code, stdout, stderr) = executor::exec(&cmd, None);
            format!(
                r#"{{"type":"exec_result","id":"{}","exit_code":{},"stdout":{},"stderr":{}}}"#,
                id, code, json_escape(stdout.trim()), json_escape(stderr.trim())
            )
        }
        "winget_list" => {
            let (code, stdout, stderr) = executor::exec("winget list", None);
            format!(
                r#"{{"type":"exec_result","id":"{}","exit_code":{},"stdout":{},"stderr":{}}}"#,
                id, code, json_escape(stdout.trim()), json_escape(stderr.trim())
            )
        }
        _ => {
            format!(r#"{{"type":"error","id":"{}","message":"unknown message type: {}"}}"#, id, msg_type)
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

fn pilot_token_path() -> std::path::PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
    std::path::PathBuf::from(home).join(".drive-by-wire").join("pilot-token")
}

fn load_pilot_token() -> Option<String> {
    std::fs::read_to_string(pilot_token_path()).ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_pilot_token(token: &str) {
    let path = pilot_token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, token).ok();
}

fn pilot_connect(ip: &str) -> (BufReader<TcpStream>, BufWriter<TcpStream>) {
    pilot_connect_with_auth(ip, true)
}

fn pilot_connect_with_auth(ip: &str, do_auth: bool) -> (BufReader<TcpStream>, BufWriter<TcpStream>) {
    let addr = format!("{}:{}", ip, PORT);
    let stream = TcpStream::connect(&addr).expect("connect failed");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    if !do_auth { return (reader, writer); }

    // Authenticate if we have a token
    if let Some(token) = load_pilot_token() {
        let auth_msg = format!(r#"{{"type":"auth","token":"{}"}}"#, token);
        protocol::write_message(&mut writer, &auth_msg).unwrap();
        match protocol::read_message(&mut reader) {
            Ok(resp) => {
                let resp_type = json_str_field(&resp, "type").unwrap_or_default();
                if resp_type == "auth_failed" || resp_type == "auth_required" {
                    let msg = json_str_field(&resp, "message").unwrap_or_default();
                    eprintln!("Auth failed: {}. Run 'pair <ip> <pin>' first.", msg);
                    std::process::exit(1);
                }
                // auth_ok or legacy error response — proceed
            }
            Err(_) => {
                // Connection dropped — maybe old passenger crashed on auth
                eprintln!("Connection lost during auth. Passenger may need restarting.");
                std::process::exit(1);
            }
        }
    }

    (reader, writer)
}

fn pilot_pair(ip: &str, pin: &str) {
    let addr = format!("{}:{}", ip, PORT);
    let stream = TcpStream::connect(&addr).expect("connect failed");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    let auth_msg = format!(r#"{{"type":"auth","pin":"{}"}}"#, pin);
    protocol::write_message(&mut writer, &auth_msg).unwrap();
    let resp = protocol::read_message(&mut reader).unwrap();

    let resp_type = json_str_field(&resp, "type").unwrap_or_default();
    if resp_type == "auth_ok" {
        if let Some(token) = json_str_field(&resp, "token") {
            save_pilot_token(&token);
            println!("Paired successfully! Token saved.");
        } else {
            println!("Paired (no token received — legacy passenger?)");
        }
    } else {
        let msg = json_str_field(&resp, "message").unwrap_or_default();
        eprintln!("Pairing failed: {}", msg);
        std::process::exit(1);
    }
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

fn pilot_deploy(ip: &str) {
    let exe_dir = std::env::current_exe().unwrap();
    let project_dir = exe_dir.parent().unwrap().parent().unwrap().parent().unwrap();
    let x64_path = project_dir.join("target").join("x86_64-pc-windows-msvc").join("release").join("drive-by-wire.exe");

    let src = if x64_path.exists() {
        x64_path
    } else {
        exe_dir.clone()
    };

    let data = std::fs::read(&src).expect("failed to read binary");
    println!("Deploying {} ({} bytes) to {}...", src.display(), data.len(), ip);

    let remote_tmp = r"C:\drive-by-wire\drive-by-wire-new.exe";
    let remote_exe = r"C:\drive-by-wire\drive-by-wire.exe";

    // Ensure directory exists
    {
        let (mut reader, mut writer) = pilot_connect(ip);
        let mkdir = r#"{"type":"exec","id":"1","cmd":"New-Item -ItemType Directory -Path C:\\drive-by-wire -Force | Out-Null"}"#;
        protocol::write_message(&mut writer, mkdir).unwrap();
        let _ = protocol::read_message(&mut reader);
    }

    // Push binary to temp location
    {
        let (mut reader, mut writer) = pilot_connect(ip);
        let msg = format!(
            r#"{{"type":"push","id":"1","dest_path":"{}","size":{}}}"#,
            remote_tmp.replace('\\', "\\\\"), data.len()
        );
        protocol::write_message(&mut writer, &msg).unwrap();
        protocol::write_raw_bytes(&mut writer, &data).unwrap();
        let resp = protocol::read_message(&mut reader).unwrap();
        if json_str_field(&resp, "type").unwrap_or_default() != "ack" {
            eprintln!("Push failed: {}", json_str_field(&resp, "message").unwrap_or_default());
            return;
        }
        println!("Binary pushed successfully.");
    }

    // Pre-provision auth: generate a token, push paired.json to passenger,
    // save the same token as our pilot token — so the new passenger trusts us
    let token = format!("{:016x}{:016x}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        std::process::id() as u128 * 31337
    );
    let paired_json = format!(r#"["{}"]"#, token);
    {
        let (mut reader, mut writer) = pilot_connect(ip);
        let home_cmd = r#"{"type":"exec","id":"1","cmd":"$env:USERPROFILE"}"#;
        protocol::write_message(&mut writer, home_cmd).unwrap();
        let resp = protocol::read_message(&mut reader).unwrap();
        let remote_home = json_str_field(&resp, "stdout").unwrap_or_else(|| r"C:\Users\Public".into());
        let remote_home = remote_home.trim().trim_end_matches('\r');
        let config_dir = format!(r"{}\.drive-by-wire", remote_home);

        // Create config dir and write paired.json
        let (mut r2, mut w2) = pilot_connect(ip);
        let mkdir_cmd = format!(
            r#"{{"type":"exec","id":"1","cmd":"New-Item -ItemType Directory -Path '{}' -Force | Out-Null"}}"#,
            config_dir.replace('\\', "\\\\")
        );
        protocol::write_message(&mut w2, &mkdir_cmd).unwrap();
        let _ = protocol::read_message(&mut r2);

        let paired_path = format!(r"{}\paired.json", config_dir);
        let paired_data = paired_json.as_bytes();
        let (mut r3, mut w3) = pilot_connect(ip);
        let push_msg = format!(
            r#"{{"type":"push","id":"1","dest_path":"{}","size":{}}}"#,
            paired_path.replace('\\', "\\\\"), paired_data.len()
        );
        protocol::write_message(&mut w3, &push_msg).unwrap();
        protocol::write_raw_bytes(&mut w3, paired_data).unwrap();
        let resp = protocol::read_message(&mut r3).unwrap();
        if json_str_field(&resp, "type").unwrap_or_default() == "ack" {
            save_pilot_token(&token);
            println!("Auth pre-provisioned (token saved).");
        } else {
            println!("Warning: could not pre-provision auth. You'll need to pair manually.");
        }
    }

    // Stop old passenger, swap binary, start new one
    println!("Restarting passenger...");
    {
        let (mut reader, mut writer) = pilot_connect(ip);
        let cmd = format!(
            "Stop-Process -Name drive-by-wire -Force -ErrorAction SilentlyContinue; Stop-Process -Name drive-by-wire-x64 -Force -ErrorAction SilentlyContinue; Start-Sleep 1; if (Test-Path '{}') {{ Remove-Item '{}' -Force }}; Move-Item '{}' '{}' -Force; Start-Process '{}'",
            remote_exe, remote_exe, remote_tmp, remote_exe, remote_exe
        );
        let msg = format!(
            r#"{{"type":"exec","id":"1","cmd":"{}"}}"#,
            cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        protocol::write_message(&mut writer, &msg).unwrap();
        // Will likely fail as we kill the process serving us
        let _ = protocol::read_message(&mut reader);
    }

    // Wait for new passenger
    println!("Waiting for new passenger...");
    for i in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let addr = format!("{}:{}", ip, PORT);
        if let Ok(s) = std::net::TcpStream::connect_timeout(
            &addr.parse::<std::net::SocketAddr>().unwrap(),
            std::time::Duration::from_secs(3),
        ) {
            drop(s);
            println!("New passenger is up! (attempt {})", i + 1);
            return;
        }
    }
    eprintln!("Passenger did not come back within 30 seconds.");
}
