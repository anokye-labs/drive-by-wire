use std::io::{self, BufRead, Write, BufReader, BufWriter};
use std::net::TcpStream;
use crate::protocol;
use crate::json_str_field;
use crate::json_u64_field;
use crate::json_escape;

pub fn run(peer_ip: &str) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    // Send server info on initialization
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // JSON-RPC: look for Content-Length header or raw JSON
        let json = if line.starts_with("Content-Length:") {
            // LSP-style framing: Content-Length: N\r\n\r\n{json}
            let len: usize = line.trim_start_matches("Content-Length:").trim().parse().unwrap_or(0);
            let mut empty = String::new();
            let _ = reader.read_line(&mut empty); // blank line
            let mut buf = vec![0u8; len];
            io::Read::read_exact(&mut reader, &mut buf).unwrap();
            String::from_utf8_lossy(&buf).to_string()
        } else if line.starts_with('{') {
            line.to_string()
        } else {
            continue;
        };

        if let Some(response) = handle_jsonrpc(&json, peer_ip) {
            let resp_bytes = response.as_bytes();
            write!(writer, "Content-Length: {}\r\n\r\n{}", resp_bytes.len(), response).unwrap();
            writer.flush().unwrap();
        }
    }
}

fn handle_jsonrpc(json: &str, peer_ip: &str) -> Option<String> {
    let method = json_str_field(json, "method")?;
    let id = extract_id(json);

    match method.as_str() {
        "initialize" => {
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{"listChanged":false}}}},"serverInfo":{{"name":"drive-by-wire","version":"0.2.0"}}}}}}"#,
                id
            ))
        }
        "notifications/initialized" => None,
        "tools/list" => {
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":{{"tools":{}}}}}"#,
                id, tools_list()
            ))
        }
        "tools/call" => {
            let tool_name = extract_tool_name(json);
            let arguments = extract_arguments(json);
            let result = call_tool(&tool_name, &arguments, peer_ip);
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":{{"content":[{{"type":"text","text":{}}}]}}}}"#,
                id, json_escape(&result)
            ))
        }
        _ => {
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32601,"message":"method not found: {}"}}}}"#,
                id, method
            ))
        }
    }
}

fn tools_list() -> String {
    r#"[
        {"name":"remote_ping","description":"Ping the remote device to check connectivity","inputSchema":{"type":"object","properties":{}}},
        {"name":"remote_exec","description":"Execute a command on the remote device","inputSchema":{"type":"object","properties":{"cmd":{"type":"string","description":"Command to execute"},"working_dir":{"type":"string","description":"Working directory"},"timeout_secs":{"type":"integer","description":"Timeout in seconds"}},"required":["cmd"]}},
        {"name":"remote_push","description":"Push a local file to the remote device","inputSchema":{"type":"object","properties":{"local_path":{"type":"string","description":"Local file path"},"remote_path":{"type":"string","description":"Remote destination path"}},"required":["local_path","remote_path"]}},
        {"name":"remote_pull","description":"Pull a file from the remote device","inputSchema":{"type":"object","properties":{"remote_path":{"type":"string","description":"Remote file path"},"local_path":{"type":"string","description":"Local destination path"}},"required":["remote_path","local_path"]}},
        {"name":"remote_sysinfo","description":"Get system information from the remote device","inputSchema":{"type":"object","properties":{}}},
        {"name":"remote_ls","description":"List directory contents on the remote device","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Directory path"}},"required":["path"]}},
        {"name":"remote_install","description":"Install a package on the remote device","inputSchema":{"type":"object","properties":{"package_id":{"type":"string","description":"Package identifier"}},"required":["package_id"]}},
        {"name":"remote_list_packages","description":"List installed packages on the remote device","inputSchema":{"type":"object","properties":{}}},
        {"name":"remote_reg_write","description":"Write a registry value on the remote device","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Registry path"},"name":{"type":"string","description":"Value name"},"value":{"type":"string","description":"Value data"},"kind":{"type":"string","description":"Value type (e.g. REG_SZ, REG_DWORD)"}},"required":["path","name","value","kind"]}},
        {"name":"remote_reg_read","description":"Read a registry value from the remote device","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Registry path"},"name":{"type":"string","description":"Value name"}},"required":["path","name"]}},
        {"name":"remote_reg_delete","description":"Delete a registry value on the remote device","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Registry path"},"name":{"type":"string","description":"Value name"}},"required":["path","name"]}},
        {"name":"remote_service","description":"Control a Windows service on the remote device","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Service name"},"action":{"type":"string","description":"Action (start, stop, restart, status)"}},"required":["name","action"]}},
        {"name":"remote_env","description":"Set an environment variable on the remote device","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Variable name"},"value":{"type":"string","description":"Variable value"},"scope":{"type":"string","description":"Scope (user, machine)"}},"required":["name","value","scope"]}},
        {"name":"remote_enable_rdp","description":"Enable Remote Desktop on the remote device","inputSchema":{"type":"object","properties":{}}},
        {"name":"remote_enable_ssh","description":"Enable SSH on the remote device","inputSchema":{"type":"object","properties":{}}},
        {"name":"remote_set_hostname","description":"Set the hostname of the remote device","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"New hostname"}},"required":["name"]}},
        {"name":"remote_set_power","description":"Set the power plan on the remote device","inputSchema":{"type":"object","properties":{"plan":{"type":"string","description":"Power plan","enum":["high_performance","balanced"]}},"required":["plan"]}},
        {"name":"remote_reboot","description":"Reboot the remote device","inputSchema":{"type":"object","properties":{"delay_secs":{"type":"integer","description":"Delay before reboot in seconds"}}}},
        {"name":"remote_create_user","description":"Create a user account on the remote device","inputSchema":{"type":"object","properties":{"username":{"type":"string","description":"Username"},"password":{"type":"string","description":"Password"},"admin":{"type":"boolean","description":"Grant admin privileges"}},"required":["username","password"]}},
        {"name":"remote_script","description":"Execute a sequence of commands on the remote device","inputSchema":{"type":"object","properties":{"commands":{"type":"array","items":{"type":"string"},"description":"Commands to execute"},"continue_on_error":{"type":"boolean","description":"Continue on error"}},"required":["commands"]}},
        {"name":"connect_status","description":"Check USB connection status and list connected devices","inputSchema":{"type":"object","properties":{}}}
    ]"#.to_string()
}

fn call_tool(name: &str, args: &str, peer_ip: &str) -> String {
    match name {
        "connect_status" => {
            let reachable = std::net::TcpStream::connect_timeout(
                &format!("{}:7842", peer_ip).parse().unwrap(),
                std::time::Duration::from_secs(3),
            ).is_ok();
            format!("Peer: {}\nReachable: {}\nTransport: USB4 P2P (TCP over direct cable)", peer_ip, reachable)
        }
        "remote_ping" => {
            match connect_peer(peer_ip) {
                Ok((mut r, mut w)) => {
                    let start = std::time::Instant::now();
                    protocol::write_message(&mut w, r#"{"type":"ping","id":"mcp"}"#).unwrap();
                    match protocol::read_message(&mut r) {
                        Ok(_) => format!("pong ({}ms)", start.elapsed().as_millis()),
                        Err(e) => format!("error: {}", e),
                    }
                }
                Err(e) => format!("connection failed: {}", e),
            }
        }
        "remote_exec" => {
            let cmd = json_str_field(args, "cmd").unwrap_or_default();
            let working_dir = json_str_field(args, "working_dir");
            match connect_peer(peer_ip) {
                Ok((mut r, mut w)) => {
                    let mut msg = format!(r#"{{"type":"exec","id":"mcp","cmd":"{}""#,
                        cmd.replace('\\', "\\\\").replace('"', "\\\""));
                    if let Some(wd) = working_dir {
                        msg.push_str(&format!(r#","working_dir":"{}""#, wd.replace('\\', "\\\\").replace('"', "\\\"")));
                    }
                    msg.push('}');
                    protocol::write_message(&mut w, &msg).unwrap();
                    match protocol::read_message(&mut r) {
                        Ok(resp) => {
                            let code = json_u64_field(&resp, "exit_code").unwrap_or(0);
                            let stdout = json_str_field(&resp, "stdout").unwrap_or_default();
                            let stderr = json_str_field(&resp, "stderr").unwrap_or_default();
                            let mut result = stdout.trim_end().to_string();
                            if !stderr.trim().is_empty() {
                                if !result.is_empty() { result.push('\n'); }
                                result.push_str("STDERR: ");
                                result.push_str(stderr.trim_end());
                            }
                            if code != 0 {
                                result.push_str(&format!("\n[exit code: {}]", code));
                            }
                            result
                        }
                        Err(e) => format!("read error: {}", e),
                    }
                }
                Err(e) => format!("connection failed: {}", e),
            }
        }
        "remote_push" => {
            let local_path = json_str_field(args, "local_path").unwrap_or_default();
            let remote_path = json_str_field(args, "remote_path").unwrap_or_default();
            match std::fs::read(&local_path) {
                Ok(data) => {
                    match connect_peer(peer_ip) {
                        Ok((mut r, mut w)) => {
                            let msg = format!(
                                r#"{{"type":"push","id":"mcp","dest_path":"{}","size":{}}}"#,
                                remote_path.replace('\\', "\\\\").replace('"', "\\\""),
                                data.len()
                            );
                            protocol::write_message(&mut w, &msg).unwrap();
                            protocol::write_raw_bytes(&mut w, &data).unwrap();
                            match protocol::read_message(&mut r) {
                                Ok(resp) => {
                                    let t = json_str_field(&resp, "type").unwrap_or_default();
                                    if t == "ack" {
                                        format!("Pushed {} bytes to {}", data.len(), remote_path)
                                    } else {
                                        let e = json_str_field(&resp, "message").unwrap_or_default();
                                        format!("Push failed: {}", e)
                                    }
                                }
                                Err(e) => format!("read error: {}", e),
                            }
                        }
                        Err(e) => format!("connection failed: {}", e),
                    }
                }
                Err(e) => format!("failed to read {}: {}", local_path, e),
            }
        }
        "remote_pull" => {
            let remote_path = json_str_field(args, "remote_path").unwrap_or_default();
            let local_path = json_str_field(args, "local_path").unwrap_or_default();
            match connect_peer(peer_ip) {
                Ok((mut r, mut w)) => {
                    let msg = format!(
                        r#"{{"type":"pull","id":"mcp","src_path":"{}"}}"#,
                        remote_path.replace('\\', "\\\\").replace('"', "\\\"")
                    );
                    protocol::write_message(&mut w, &msg).unwrap();
                    match protocol::read_message(&mut r) {
                        Ok(resp) => {
                            let t = json_str_field(&resp, "type").unwrap_or_default();
                            if t == "file_data" {
                                let size = json_u64_field(&resp, "size").unwrap_or(0) as usize;
                                match protocol::read_raw_bytes(&mut r, size) {
                                    Ok(data) => {
                                        match std::fs::write(&local_path, &data) {
                                            Ok(()) => format!("Pulled {} bytes to {}", size, local_path),
                                            Err(e) => format!("write error: {}", e),
                                        }
                                    }
                                    Err(e) => format!("read error: {}", e),
                                }
                            } else {
                                let e = json_str_field(&resp, "message").unwrap_or_default();
                                format!("Pull failed: {}", e)
                            }
                        }
                        Err(e) => format!("read error: {}", e),
                    }
                }
                Err(e) => format!("connection failed: {}", e),
            }
        }
        "remote_sysinfo" => {
            match connect_peer(peer_ip) {
                Ok((mut r, mut w)) => {
                    protocol::write_message(&mut w, r#"{"type":"sysinfo","id":"mcp"}"#).unwrap();
                    match protocol::read_message(&mut r) {
                        Ok(resp) => resp,
                        Err(e) => format!("read error: {}", e),
                    }
                }
                Err(e) => format!("connection failed: {}", e),
            }
        }
        "remote_ls" => {
            let path = json_str_field(args, "path").unwrap_or_else(|| "C:\\".into());
            send_simple(peer_ip, &format!(
                r#"{{"type":"ls","id":"mcp","path":"{}"}}"#,
                path.replace('\\', "\\\\").replace('"', "\\\"")
            ))
        }
        "remote_install" => {
            let pkg = json_str_field(args, "package_id").unwrap_or_default();
            send_simple(peer_ip, &format!(
                r#"{{"type":"winget_install","id":"mcp","package_id":"{}"}}"#,
                pkg.replace('"', "\\\"")
            ))
        }
        "remote_list_packages" => {
            send_simple(peer_ip, r#"{"type":"winget_list","id":"mcp"}"#)
        }
        "remote_reg_write" => {
            let path = json_str_field(args, "path").unwrap_or_default();
            let name = json_str_field(args, "name").unwrap_or_default();
            let value = json_str_field(args, "value").unwrap_or_default();
            let kind = json_str_field(args, "kind").unwrap_or_else(|| "REG_SZ".into());
            send_simple(peer_ip, &format!(
                r#"{{"type":"reg_write","id":"mcp","path":"{}","name":"{}","value":"{}","kind":"{}"}}"#,
                path.replace('\\', "\\\\").replace('"', "\\\""),
                name.replace('"', "\\\""),
                value.replace('\\', "\\\\").replace('"', "\\\""),
                kind
            ))
        }
        "remote_reg_read" => {
            let path = json_str_field(args, "path").unwrap_or_default();
            let name = json_str_field(args, "name").unwrap_or_default();
            send_simple(peer_ip, &format!(
                r#"{{"type":"reg_read","id":"mcp","path":"{}","name":"{}"}}"#,
                path.replace('\\', "\\\\").replace('"', "\\\""),
                name.replace('"', "\\\"")
            ))
        }
        "remote_reg_delete" => {
            let path = json_str_field(args, "path").unwrap_or_default();
            let name = json_str_field(args, "name").unwrap_or_default();
            send_simple(peer_ip, &format!(
                r#"{{"type":"reg_delete","id":"mcp","path":"{}","name":"{}"}}"#,
                path.replace('\\', "\\\\").replace('"', "\\\""),
                name.replace('"', "\\\"")
            ))
        }
        "remote_service" => {
            let name = json_str_field(args, "name").unwrap_or_default();
            let action = json_str_field(args, "action").unwrap_or_default();
            send_simple(peer_ip, &format!(
                r#"{{"type":"service","id":"mcp","name":"{}","action":"{}"}}"#,
                name.replace('"', "\\\""), action
            ))
        }
        "remote_env" => {
            let name = json_str_field(args, "name").unwrap_or_default();
            let value = json_str_field(args, "value").unwrap_or_default();
            let scope = json_str_field(args, "scope").unwrap_or_else(|| "machine".into());
            send_simple(peer_ip, &format!(
                r#"{{"type":"env_set","id":"mcp","name":"{}","value":"{}","scope":"{}"}}"#,
                name.replace('"', "\\\""),
                value.replace('\\', "\\\\").replace('"', "\\\""),
                scope
            ))
        }
        "remote_enable_rdp" => {
            send_simple(peer_ip, r#"{"type":"enable_rdp","id":"mcp"}"#)
        }
        "remote_enable_ssh" => {
            send_simple(peer_ip, r#"{"type":"enable_ssh","id":"mcp"}"#)
        }
        "remote_set_hostname" => {
            let name = json_str_field(args, "name").unwrap_or_default();
            send_simple(peer_ip, &format!(
                r#"{{"type":"set_hostname","id":"mcp","name":"{}"}}"#,
                name.replace('"', "\\\"")
            ))
        }
        "remote_set_power" => {
            let plan = json_str_field(args, "plan").unwrap_or_else(|| "balanced".into());
            send_simple(peer_ip, &format!(
                r#"{{"type":"set_power","id":"mcp","plan":"{}"}}"#, plan
            ))
        }
        "remote_reboot" => {
            let delay = json_u64_field(args, "delay_secs").unwrap_or(5);
            send_simple(peer_ip, &format!(
                r#"{{"type":"reboot","id":"mcp","delay_secs":{}}}"#, delay
            ))
        }
        "remote_create_user" => {
            let username = json_str_field(args, "username").unwrap_or_default();
            let password = json_str_field(args, "password").unwrap_or_default();
            let admin = args.contains("\"admin\":true");
            send_simple(peer_ip, &format!(
                r#"{{"type":"create_user","id":"mcp","username":"{}","password":"{}","admin":{}}}"#,
                username.replace('"', "\\\""),
                password.replace('"', "\\\""),
                admin
            ))
        }
        "remote_script" => {
            // Execute commands sequentially via exec
            let continue_on_error = args.contains("\"continue_on_error\":true");
            // Extract commands array — simple parsing
            let commands = extract_string_array(args, "commands");
            let mut results = Vec::new();
            for cmd in &commands {
                match connect_peer(peer_ip) {
                    Ok((mut r, mut w)) => {
                        let msg = format!(r#"{{"type":"exec","id":"mcp","cmd":"{}"}}"#,
                            cmd.replace('\\', "\\\\").replace('"', "\\\""));
                        protocol::write_message(&mut w, &msg).unwrap();
                        match protocol::read_message(&mut r) {
                            Ok(resp) => {
                                let code = json_u64_field(&resp, "exit_code").unwrap_or(0);
                                let stdout = json_str_field(&resp, "stdout").unwrap_or_default();
                                let stderr = json_str_field(&resp, "stderr").unwrap_or_default();
                                results.push(format!("$ {}\n{}{}", cmd, stdout.trim_end(),
                                    if stderr.trim().is_empty() { String::new() } else { format!("\nSTDERR: {}", stderr.trim_end()) }));
                                if code != 0 && !continue_on_error {
                                    results.push(format!("[stopped at exit code {}]", code));
                                    break;
                                }
                            }
                            Err(e) => {
                                results.push(format!("$ {}\nerror: {}", cmd, e));
                                if !continue_on_error { break; }
                            }
                        }
                    }
                    Err(e) => {
                        results.push(format!("$ {}\nconnection failed: {}", cmd, e));
                        if !continue_on_error { break; }
                    }
                }
            }
            results.join("\n\n")
        }
        _ => format!("unknown tool: {}", name),
    }
}

fn send_simple(peer_ip: &str, msg: &str) -> String {
    match connect_peer(peer_ip) {
        Ok((mut r, mut w)) => {
            protocol::write_message(&mut w, msg).unwrap();
            match protocol::read_message(&mut r) {
                Ok(resp) => resp,
                Err(e) => format!("read error: {}", e),
            }
        }
        Err(e) => format!("connection failed: {}", e),
    }
}

fn extract_string_array(json: &str, field: &str) -> Vec<String> {
    let pattern = format!(r#""{}":"#, field);
    let start = match json.find(&pattern) {
        Some(p) => p + pattern.len(),
        None => return Vec::new(),
    };
    let rest = &json[start..].trim_start();
    if !rest.starts_with('[') { return Vec::new(); }
    let mut items = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();
    let mut depth = 0;
    for ch in rest.chars() {
        if escaped { escaped = false; current.push(ch); continue; }
        match ch {
            '\\' if in_string => { escaped = true; }
            '"' => {
                in_string = !in_string;
                if !in_string && depth == 1 {
                    items.push(current.clone());
                    current.clear();
                }
            }
            '[' if !in_string => { depth += 1; }
            ']' if !in_string => { depth -= 1; if depth == 0 { break; } }
            _ if in_string => { current.push(ch); }
            _ => {}
        }
    }
    items
}

fn connect_peer(ip: &str) -> io::Result<(BufReader<TcpStream>, BufWriter<TcpStream>)> {
    let addr = format!("{}:7842", ip);
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        std::time::Duration::from_secs(5),
    )?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    // Authenticate
    let token = load_pilot_token();
    let auth_msg = if let Some(ref tok) = token {
        format!(r#"{{"type":"auth","token":"{}"}}"#, tok)
    } else {
        // No token — try without auth (for legacy passengers)
        return Ok((reader, writer));
    };

    crate::protocol::write_message(&mut writer, &auth_msg)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("auth write: {}", e)))?;

    let resp = crate::protocol::read_message(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("auth read: {}", e)))?;

    let resp_type = crate::json_str_field(&resp, "type").unwrap_or_default();
    match resp_type.as_str() {
        "auth_ok" => {
            // Check if passenger sent us a new token (from PIN pairing)
            if let Some(new_tok) = crate::json_str_field(&resp, "token") {
                save_pilot_token(&new_tok);
            }
            Ok((reader, writer))
        }
        "auth_required" | "auth_failed" => {
            let msg = crate::json_str_field(&resp, "message").unwrap_or_else(|| "auth failed".into());
            Err(io::Error::new(io::ErrorKind::PermissionDenied, msg))
        }
        _ => {
            // Legacy passenger that doesn't understand auth — treat response as data
            // Put the response back... actually we can't. For legacy compat, just proceed.
            Ok((reader, writer))
        }
    }
}

fn pilot_token_path() -> std::path::PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".into());
    std::path::PathBuf::from(home).join(".drive-by-wire").join("pilot-token")
}

fn load_pilot_token() -> Option<String> {
    std::fs::read_to_string(pilot_token_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn save_pilot_token(token: &str) {
    let path = pilot_token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, token).ok();
}

// JSON-RPC helpers
fn extract_id(json: &str) -> String {
    // id can be number or string
    if let Some(pos) = json.find("\"id\":") {
        let rest = &json[pos + 5..];
        let rest = rest.trim_start();
        if rest.starts_with('"') {
            // String id
            let inner = &rest[1..];
            let end = inner.find('"').unwrap_or(inner.len());
            format!("\"{}\"", &inner[..end])
        } else {
            // Number id
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
            rest[..end].to_string()
        }
    } else {
        "null".to_string()
    }
}

fn extract_tool_name(json: &str) -> String {
    // Find "name" inside "params"
    if let Some(params_pos) = json.find("\"params\"") {
        let params_rest = &json[params_pos..];
        json_str_field(params_rest, "name").unwrap_or_default()
    } else {
        String::new()
    }
}

fn extract_arguments(json: &str) -> String {
    // Find "arguments" object inside "params"
    if let Some(pos) = json.find("\"arguments\"") {
        let rest = &json[pos + 11..];
        // Skip to the opening brace
        if let Some(brace) = rest.find('{') {
            let obj_start = pos + 11 + brace;
            // Find matching close brace
            let mut depth = 0;
            for (i, ch) in json[obj_start..].chars().enumerate() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return json[obj_start..obj_start + i + 1].to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    "{}".to_string()
}
