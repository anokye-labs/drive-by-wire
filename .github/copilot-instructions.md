# Drive By Wire

Direct PC-to-PC command and control over a USB-C cable. No network, no SSH, no TCP/IP stack — just two Windows machines and a cable.

## Tech Stack
- Rust (2024 edition)
- ratatui for terminal UI
- crossterm for terminal handling

## Development
```bash
cargo build
cargo test
cargo run
```

## Structure
One machine is the pilot (sends commands), the other is the passenger (executes them). The same binary auto-detects its role.

## Conventions
- Follow Rust idioms and conventions
- Use `cargo clippy` for linting
- Write doc comments for public items
