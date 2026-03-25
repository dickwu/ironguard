use std::process::Command;

use anyhow::{Result, anyhow};

use super::system::{Os, System};

pub fn start(sys: &System, iface: &str) -> Result<()> {
    match sys.os {
        Os::Linux => {
            let out = Command::new("systemctl")
                .args(["start", &format!("ironguard@{iface}")])
                .output()?;
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                return Err(anyhow!("systemctl start failed: {err}"));
            }
            Ok(())
        }
        Os::MacOs => {
            let plist = format!("/Library/LaunchDaemons/com.ironguard.{iface}.plist");
            if std::path::Path::new(&plist).exists() {
                Command::new("launchctl").args(["load", &plist]).output()?;
                Ok(())
            } else {
                // fallback: start directly in background
                let config = sys.config_file();
                let bin = sys.ironguard_bin();
                Command::new(bin)
                    .args(["up", iface, "--config", &config, "--foreground"])
                    .env("RUST_LOG", "info")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()?;
                Ok(())
            }
        }
    }
}

pub fn stop(sys: &System, iface: &str) -> Result<()> {
    match sys.os {
        Os::Linux => {
            Command::new("systemctl")
                .args(["stop", &format!("ironguard@{iface}")])
                .output()?;
            Ok(())
        }
        Os::MacOs => {
            let plist = format!("/Library/LaunchDaemons/com.ironguard.{iface}.plist");
            if std::path::Path::new(&plist).exists() {
                Command::new("launchctl")
                    .args(["unload", &plist])
                    .output()?;
            }
            // also try ironguard down
            let bin = sys.ironguard_bin();
            Command::new(bin).args(["down", iface]).output().ok();
            Ok(())
        }
    }
}

pub fn status(_sys: &System) -> Result<String> {
    // check if ironguard process is running
    let output = Command::new("pgrep")
        .args(["-f", "ironguard up"])
        .output()?;

    let running = output.status.success();
    let pid = if running {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };

    if running {
        if let Some(pid) = pid {
            Ok(format!("running (pid {pid})"))
        } else {
            Ok("running".into())
        }
    } else {
        Ok("stopped".into())
    }
}

pub fn tail_logs(sys: &System) -> Result<()> {
    // determine interface from config
    let iface = match super::config::load_server_config() {
        Ok(cfg) => cfg.interface,
        Err(_) => sys.default_interface().to_owned(),
    };

    match sys.os {
        Os::Linux => {
            let status = Command::new("journalctl")
                .args(["-u", &format!("ironguard@{iface}"), "-f", "--no-pager"])
                .status()?;
            if !status.success() {
                return Err(anyhow!("journalctl failed"));
            }
        }
        Os::MacOs => {
            let log_file = sys.log_file(&iface);
            if std::path::Path::new(&log_file).exists() {
                let status = Command::new("tail").args(["-f", &log_file]).status()?;
                if !status.success() {
                    return Err(anyhow!("tail failed"));
                }
            } else {
                return Err(anyhow!("No log file at {log_file}. Is the server running?"));
            }
        }
    }
    Ok(())
}
