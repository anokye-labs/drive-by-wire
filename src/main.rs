use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const PORT: u16 = 7842;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 2 && args[1] == "connect" {
        connect(&args[2]);
    } else {
        // Default: listen mode (double-click friendly)
        print_local_ips();
        println!("\nListening on port {}... waiting for connection", PORT);
        listen();
    }
}

fn print_local_ips() {
    use std::net::UdpSocket;
    println!("=== Local IP addresses ===");
    // Bind a UDP socket to find routable interfaces
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        // Get all local addresses by iterating interfaces
        // Simple approach: just show what we can find
    }
    // Use hostname resolution to find all IPs
    if let Ok(hostname) = std::process::Command::new("hostname").output() {
        let name = String::from_utf8_lossy(&hostname.stdout).trim().to_string();
        println!("Hostname: {}", name);
    }
    // Run ipconfig and extract relevant info
    if let Ok(output) = std::process::Command::new("ipconfig").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        let mut capture = false;
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("usb4") || lower.contains("thunderbolt") || lower.contains("p2p") {
                capture = true;
                println!("{}", line.trim());
            } else if capture {
                if line.trim().is_empty() || (!line.starts_with(' ') && !line.starts_with('\t')) {
                    if !line.trim().is_empty() && !lower.contains("ipv") && !lower.contains("subnet") && !lower.contains("link-local") && !lower.contains("default") {
                        capture = false;
                    }
                }
                if capture {
                    println!("{}", line.trim());
                }
            }
        }
    }
    // Also print all 169.254.x.x addresses
    if let Ok(output) = std::process::Command::new("ipconfig").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("169.254.") {
                println!("Link-local: {}", line.trim());
            }
        }
    }
}

fn listen() {
    // Add firewall rule for this exe so connections aren't blocked
    let exe = std::env::current_exe().unwrap_or_default();
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
               "name=drive-by-wire", "dir=in", "action=allow",
               &format!("program={}", exe.display()),
               "protocol=tcp", &format!("localport={}", PORT)])
        .output();

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
    println!("Listening on {}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let peer = s.peer_addr().unwrap();
                println!("Connection from {}", peer);
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => { println!("Disconnected"); break; }
                        Ok(n) => {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            println!("Received: {}", msg.trim());
                            s.write_all(&buf[..n]).expect("write failed");
                        }
                        Err(e) => { eprintln!("Read error: {}", e); break; }
                    }
                }
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }
}

fn connect(ip: &str) {
    let addr = format!("{}:{}", ip, PORT);
    println!("Connecting to {}...", addr);
    let mut stream = TcpStream::connect(&addr).expect("connect failed");
    println!("Connected!");

    let msg = b"hello from pilot\n";
    stream.write_all(msg).expect("write failed");
    println!("Sent: hello from pilot");

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).expect("read failed");
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("Received: {}", response.trim());

    if &buf[..n] == msg {
        println!("SUCCESS: echo round-trip verified!");
    } else {
        println!("MISMATCH: sent != received");
    }
}
