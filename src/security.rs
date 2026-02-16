/// Command authorization tiers.
/// Determines what level of approval a command requires.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum Tier {
    /// Auto-approved, low risk (read-only or diagnostic)
    Auto,
    /// Executes immediately but logged prominently (moderate risk)
    Log,
    /// Requires interactive confirmation in TUI (high risk / destructive)
    Confirm,
}

/// Classify a command type into its authorization tier.
pub fn classify(cmd_type: &str) -> Tier {
    match cmd_type {
        // Tier 1: Auto-approve (read-only, diagnostic)
        "ping" | "sysinfo" | "ls" | "reg_read" | "winget_list" => Tier::Auto,

        // Tier 2: Log-and-execute (moderate risk, productive operations)
        "exec" | "push" | "pull" | "winget_install" | "reg_write" | "env_set" => Tier::Log,

        // Tier 3: Require confirmation (destructive / security-sensitive)
        "reboot" | "enable_rdp" | "enable_ssh" | "set_hostname" | "set_power"
        | "create_user" | "service" | "reg_delete" | "script" => Tier::Confirm,

        // Unknown commands default to require confirmation
        _ => Tier::Confirm,
    }
}

/// Human-readable description of what a command does, for the confirmation prompt.
pub fn describe_command(cmd_type: &str, msg: &str) -> String {
    // Import json helpers
    let field = |f| crate::json_str_field(msg, f).unwrap_or_default();

    match cmd_type {
        "reboot" => {
            let delay = crate::json_u64_field(msg, "delay_secs").unwrap_or(5);
            format!("Reboot this computer in {} seconds", delay)
        }
        "enable_rdp" => "Enable Remote Desktop and open firewall".into(),
        "enable_ssh" => "Install and enable OpenSSH Server".into(),
        "set_hostname" => format!("Rename computer to '{}'", field("name")),
        "set_power" => format!("Set power plan to '{}'", field("plan")),
        "create_user" => {
            let admin = msg.contains("\"admin\":true");
            format!("Create {} user '{}'", if admin { "admin" } else { "standard" }, field("username"))
        }
        "service" => format!("{} service '{}'", field("action"), field("name")),
        "reg_delete" => format!("Delete registry value '{}' in '{}'", field("name"), field("path")),
        "script" => "Execute a batch of commands".into(),
        _ => format!("{} command", cmd_type),
    }
}
