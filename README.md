# drive-by-wire

Direct PC-to-PC command & control over a USB-C cable. No network, no SSH, no TCP/IP stack — just two Windows machines and a cable.

One machine is the **pilot** (sends commands). The other is the **passenger** (executes them). The same binary runs on both sides; it auto-detects its role.

## ⚠️ Caveats — Read Before Using

### This is an experiment, not a product

This project was built in a weekend as a proof-of-concept. It was written by a human and an AI pair-programming over a live USB-C cable between a Surface Laptop 7 and a desktop workstation. It works. It is also held together with duct tape and optimism.

### It executes arbitrary commands on the passenger

The passenger runs PowerShell commands sent by the pilot. That is the entire point. If you run this binary and someone connects to it, they can do **anything** an admin PowerShell session can do: read files, install software, modify the registry, create users, reboot the machine. This is by design.

### The security model is "good enough for a cable"

- **PIN-based pairing**: The passenger shows a 6-digit PIN. The pilot must enter it to pair. Tokens are persisted so you only pair once.
- **TOFU (Trust On First Use)**: The first connection to a fresh passenger is allowed without a PIN. This is intentional — it enables bootstrapping. It also means anyone with physical cable access can pair on first run.
- **3-tier ACL**: Commands are classified as Auto (just run it), Log (run it but log it), or Confirm (require Y/N on the passenger's TUI). But the tier assignments are hardcoded and opinionated.
- **No encryption**: Traffic goes over a direct USB-C cable. There is no TLS, no encryption, no signing. If someone can tap your USB-C cable, they can see and modify everything. (If someone can tap your USB-C cable, you have bigger problems.)

### It only works on specific hardware

- Requires **USB4 or Thunderbolt 3/4** ports on both machines
- Both machines must run **Windows 11**
- The USB4 P2P Network Adapter must appear and get a link-local IP
- Not all USB-C cables support USB4 — you need an active 40Gbps cable, not a charging cable
- If the USB4 Host Router service isn't running, nothing works
- Link-local IPs change on every reconnect

### The auto-discovery is fragile

The pilot finds the passenger by parsing `ipconfig /all` output, matching adapter names containing "USB4" or "Thunderbolt", reading the ARP table, and probing port 7842. This works on the two machines it was tested on. It may not work on yours.

### The deploy mechanism can brick the passenger

`deploy` pushes a new binary to the passenger, kills the running process, and starts the new one. If the new binary is the wrong architecture (ask me how I know), corrupt, or crashes on startup, the passenger is dead and you need physical access to fix it.

### The TUI is decorative

The passenger runs a [ratatui](https://github.com/ratatui-org/ratatui) terminal UI showing connection status, a pairing PIN, and an activity log. It looks nice. It is not essential. If it crashes, the underlying listener still works. The confirmation prompts (Y/N for dangerous commands) require someone to be sitting at the passenger's keyboard, which somewhat defeats the purpose of remote control.

### No tests

There are no unit tests, no integration tests, no CI. The test suite is "plug in the cable and see if it works." If it breaks, you get to keep both pieces.

### MCP integration is experimental

The binary can run as an [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server, exposing 21 tools for AI assistants like GitHub Copilot to control the passenger. This is powerful and terrifying in equal measure. An AI can install software, edit the registry, create users, and reboot your machine. You've been warned.

### The protocol is hand-rolled JSON

Messages are length-prefixed JSON over TCP. The JSON parser is hand-written (no serde, no dependencies beyond ratatui/crossterm). It works for the messages we send. It will not survive adversarial input.

### Platform support

- **Windows 11 only.** No Linux, no macOS, no Windows 10.
- **ARM64 + x64.** The pilot was ARM64 (Snapdragon X), the passenger was x64 (Intel i9). Cross-compilation works but the build setup is bespoke.
- Requires running as **Administrator**. Many operations (firewall rules, service control, user creation) need elevation.

## How it works

```
┌─────────────┐     USB-C cable      ┌──────────────┐
│   Pilot     │◄────────────────────►│  Passenger    │
│ (ARM64)     │   USB4 P2P 20Gbps    │  (x64)       │
│             │   169.254.x.x        │              │
│ drive-by-   │   TCP port 7842      │ drive-by-    │
│ wire.exe    │                      │ wire.exe     │
│ exec/mcp    │                      │ (listener)   │
└─────────────┘                      └──────────────┘
```

The USB4/Thunderbolt controller creates a point-to-point network adapter with link-local addressing. We run TCP over that. It's ~20 Gbps with sub-millisecond latency.

## Quick start

```powershell
# On the passenger (the machine to be controlled):
.\drive-by-wire.exe
# Shows TUI with PIN, listens on port 7842

# On the pilot (the machine sending commands):
.\drive-by-wire.exe pair <passenger-ip> <pin>
.\drive-by-wire.exe exec <passenger-ip> "hostname"
.\drive-by-wire.exe push <passenger-ip> .\local-file.txt C:\remote\path.txt
.\drive-by-wire.exe pull <passenger-ip> C:\remote\file.txt .\local-copy.txt

# Auto-discover the passenger:
.\drive-by-wire.exe discover

# Deploy updated binary to passenger:
.\drive-by-wire.exe deploy <passenger-ip>

# Reset auth state (re-enables TOFU):
.\drive-by-wire.exe reset

# Run as MCP server (for AI assistant integration):
.\drive-by-wire.exe mcp
```

## MCP Tools

When running as an MCP server, 21 tools are exposed:

| Tool | Description |
|------|-------------|
| `remote_ping` | Latency test |
| `remote_exec` | Run PowerShell command |
| `remote_push` | Push file to passenger |
| `remote_pull` | Pull file from passenger |
| `remote_sysinfo` | System information |
| `remote_ls` | List directory |
| `remote_reg_read/write/delete` | Registry operations |
| `remote_service` | Windows service control |
| `remote_env_set` | Set environment variable |
| `remote_winget_install/list` | Package management |
| `remote_enable_rdp/ssh` | Enable remote access |
| `remote_set_hostname` | Rename computer |
| `remote_set_power` | Power plan control |
| `remote_reboot` | Schedule reboot |
| `remote_create_user` | Create local account |
| `remote_script` | Run command sequence |
| `connect_status` | Connection status |

## Building

```powershell
# ARM64 (Surface/Snapdragon):
cargo build --release --target aarch64-pc-windows-msvc

# x64 (Intel/AMD):
cargo build --release --target x86_64-pc-windows-msvc
```

Requires Rust 1.70+, MSVC build tools, and Windows SDK. The `.cargo/config.toml` has linker paths that are specific to the dev machine — you'll need to adjust them.

## Security tiers

| Tier | Commands | Behavior |
|------|----------|----------|
| **Auto** | ping, sysinfo, ls, reg_read, winget_list | Runs immediately |
| **Log** | exec, push, pull, winget_install, reg_write, env_set | Runs, logged |
| **Confirm** | reboot, rdp, ssh, create_user, hostname, service, reg_delete, power, script | Requires Y/N at passenger keyboard |

## License

This is an experiment. Use at your own risk. If it deletes your files, bricks your machine, or installs a cryptocurrency miner, that's on you.

MIT License. See [LICENSE](LICENSE) for details.
