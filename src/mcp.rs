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
            match connect_peer(peer_ip) {
                Ok((mut r, mut w)) => {
                    let msg = format!(
                        r#"{{"type":"ls","id":"mcp","path":"{}"}}"#,
                        path.replace('\\', "\\\\").replace('"', "\\\"")
                    );
                    protocol::write_message(&mut w, &msg).unwrap();
                    match protocol::read_message(&mut r) {
                        Ok(resp) => resp,
                        Err(e) => format!("read error: {}", e),
                    }
                }
                Err(e) => format!("connection failed: {}", e),
            }
        }
        _ => format!("unknown tool: {}", name),
    }
}

fn connect_peer(ip: &str) -> io::Result<(BufReader<TcpStream>, BufWriter<TcpStream>)> {
    let addr = format!("{}:7842", ip);
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        std::time::Duration::from_secs(5),
    )?;
    let reader = BufReader::new(stream.try_clone()?);
    let writer = BufWriter::new(stream);
    Ok((reader, writer))
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
