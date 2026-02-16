use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

const PORT: u16 = 7842;

/// Discover the peer IP on the USB4/Thunderbolt P2P link.
/// Returns the first reachable peer IP listening on port 7842.
pub fn find_peer() -> Option<String> {
    eprintln!("[discover] Looking for USB4/Thunderbolt P2P adapter...");

    // Step 1: Find the P2P adapter and our IP on it
    let (adapter_name, our_ip) = find_p2p_adapter()?;
    eprintln!("[discover] Found adapter: {} (our IP: {})", adapter_name, our_ip);

    // Step 2: Find peer candidates from ARP/neighbor table
    let candidates = find_arp_peers(&adapter_name, &our_ip);
    eprintln!("[discover] ARP candidates: {:?}", candidates);

    // Step 3: If no ARP entries, trigger discovery with a broadcast ping
    let candidates = if candidates.is_empty() {
        eprintln!("[discover] No ARP entries, sending broadcast ping...");
        broadcast_ping(&our_ip);
        std::thread::sleep(Duration::from_secs(2));
        find_arp_peers(&adapter_name, &our_ip)
    } else {
        candidates
    };

    // Step 4: Probe each candidate on port 7842
    for ip in &candidates {
        eprintln!("[discover] Probing {}:{}...", ip, PORT);
        let addr: SocketAddr = format!("{}:{}", ip, PORT).parse().ok()?;
        if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
            eprintln!("[discover] Found peer: {}", ip);
            return Some(ip.clone());
        }
    }

    // Step 5: Last resort — scan common link-local offsets
    if candidates.is_empty() {
        eprintln!("[discover] No candidates found, trying subnet scan...");
        return scan_subnet(&our_ip);
    }

    None
}

/// Find a network adapter whose description contains "USB4" or "Thunderbolt"
/// and has a 169.254.x.x IP address. Returns (adapter_name, ip).
fn find_p2p_adapter() -> Option<(String, String)> {
    // Parse ipconfig /all to find the adapter
    let output = std::process::Command::new("ipconfig")
        .arg("/all")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut current_adapter = String::new();
    let mut is_p2p = false;

    for line in text.lines() {
        // Adapter header: "Ethernet adapter Ethernet 5:"
        if line.ends_with(':') && !line.starts_with(' ') {
            // Extract adapter name between "adapter " and ":"
            if let Some(pos) = line.find("adapter ") {
                current_adapter = line[pos + 8..line.len() - 1].to_string();
                is_p2p = false;
            }
        }

        // Check description for USB4 or Thunderbolt
        if line.contains("Description") && (line.contains("USB4") || line.contains("Thunderbolt")) {
            is_p2p = true;
        }

        // If this is the P2P adapter, find its link-local IP
        if is_p2p && (line.contains("IPv4 Address") || line.contains("Autoconfiguration IPv4")) {
            if let Some(ip) = extract_ip(line) {
                if ip.starts_with("169.254.") {
                    return Some((current_adapter.clone(), ip));
                }
            }
        }
    }

    None
}

/// Extract IPv4 address from an ipconfig line like "   IPv4 Address. . . : 169.254.238.10(Preferred)"
fn extract_ip(line: &str) -> Option<String> {
    let colon_pos = line.rfind(':')?;
    let raw = line[colon_pos + 1..].trim();
    // Strip "(Preferred)" or "(Tentative)" suffix
    let ip = raw.split('(').next().unwrap_or(raw).trim();
    // Validate it looks like an IP
    if ip.split('.').count() == 4 && ip.split('.').all(|p| p.parse::<u8>().is_ok()) {
        Some(ip.to_string())
    } else {
        None
    }
}

/// Find peer IPs from the ARP table for the given adapter.
/// Filters to 169.254.x.x addresses with real MAC addresses (not 00-00-00 or ff-ff-ff).
fn find_arp_peers(_adapter_name: &str, our_ip: &str) -> Vec<String> {
    let output = match std::process::Command::new("arp").arg("-a").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);

    let mut in_our_interface = false;
    let mut peers = Vec::new();

    for line in text.lines() {
        // ARP output groups by interface: "Interface: 169.254.238.10 --- 0xNN"
        if line.starts_with("Interface:") {
            in_our_interface = line.contains(our_ip);
            continue;
        }

        if !in_our_interface {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let ip = parts[0];
            let mac = parts[1];

            // Skip our own IP, broadcast, multicast, and entries with null MACs
            if ip == our_ip { continue; }
            if !ip.starts_with("169.254.") { continue; }
            if ip == "169.254.255.255" { continue; }
            if ip.starts_with("224.") || ip.starts_with("239.") { continue; }
            if mac == "ff-ff-ff-ff-ff-ff" { continue; }
            if mac == "00-00-00-00-00-00" { continue; }

            peers.push(ip.to_string());
        }
    }

    // Deduplicate
    peers.sort();
    peers.dedup();
    peers
}

/// Send a broadcast ping to stimulate ARP entries
fn broadcast_ping(our_ip: &str) {
    // Ping the subnet broadcast (169.254.255.255)
    let _ = std::process::Command::new("ping")
        .args(["-n", "2", "-w", "500", "169.254.255.255"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Also try a directed broadcast based on our IP's /24
    let parts: Vec<&str> = our_ip.split('.').collect();
    if parts.len() == 4 {
        let broadcast = format!("{}.{}.{}.255", parts[0], parts[1], parts[2]);
        let _ = std::process::Command::new("ping")
            .args(["-n", "2", "-w", "500", &broadcast])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Last-resort scan: try connecting to port 7842 on nearby /24 subnets
fn scan_subnet(our_ip: &str) -> Option<String> {
    let parts: Vec<u8> = our_ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 { return None; }

    // Scan our own /24 first
    for i in 1..255u8 {
        if i == parts[3] { continue; }
        let ip = format!("169.254.{}.{}", parts[2], i);
        let addr: SocketAddr = format!("{}:{}", ip, PORT).parse().ok()?;
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Some(ip);
        }
    }

    None
}
