use std::process::Command;

/// Execute a command via PowerShell and return (exit_code, stdout, stderr)
pub fn exec(cmd: &str, working_dir: Option<&str>) -> (i32, String, String) {
    let mut ps = Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", cmd]);
    if let Some(dir) = working_dir {
        ps.current_dir(dir);
    }
    match ps.output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            (code, stdout, stderr)
        }
        Err(e) => (-1, String::new(), format!("Failed to execute: {}", e)),
    }
}
