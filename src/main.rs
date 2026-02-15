use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const PORT: u16 = 7842;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "listen" {
        listen();
    } else if args.len() > 2 && args[1] == "connect" {
        connect(&args[2]);
    } else {
        eprintln!("Usage:");
        eprintln!("  drive-by-wire listen              # run on target PC");
        eprintln!("  drive-by-wire connect <ip>         # run on this PC");
    }
}

fn listen() {
    let addr = format!("0.0.0.0:{}", PORT);
    let listener = TcpListener::bind(&addr).expect("bind failed");
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
