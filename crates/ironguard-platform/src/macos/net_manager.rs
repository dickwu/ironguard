use std::io::Write;
use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::debug;

use crate::net_manager::NetworkManager;

/// macOS network manager that shells out to `ifconfig`, `route`, and `pfctl`.
///
/// All operations are idempotent -- duplicate adds and missing-entry removes
/// are silently ignored by checking stderr for known benign messages.
pub struct MacosNetManager;

impl MacosNetManager {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosNetManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Known stderr patterns that indicate an idempotent no-op rather than
/// a real failure.
const BENIGN_ERRORS: &[&str] = &[
    "File exists",
    "not in table",
    "Can't assign requested address",
    "SIOCDIFADDR",
    "No such process",
    "entry not found",
];

fn is_benign(stderr: &str) -> bool {
    BENIGN_ERRORS.iter().any(|pat| stderr.contains(pat))
}

/// Run a command, returning `Ok(())` on success or if stderr contains a
/// benign error pattern.
fn run_idempotent(cmd: &mut Command) -> Result<()> {
    debug!("exec: {:?}", cmd);
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn: {:?}", cmd))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_benign(&stderr) {
        debug!("ignoring benign error: {}", stderr.trim());
        return Ok(());
    }

    anyhow::bail!(
        "command {:?} failed (exit {}): {}",
        cmd,
        output.status,
        stderr.trim()
    );
}

impl NetworkManager for MacosNetManager {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        match addr {
            IpAddr::V4(v4) => {
                run_idempotent(
                    Command::new("ifconfig")
                        .arg(iface)
                        .arg("inet")
                        .arg(format!("{}/{}", v4, prefix_len))
                        .arg(v4.to_string()),
                )
            }
            IpAddr::V6(v6) => {
                run_idempotent(
                    Command::new("ifconfig")
                        .arg(iface)
                        .arg("inet6")
                        .arg(v6.to_string())
                        .arg("prefixlen")
                        .arg(prefix_len.to_string()),
                )
            }
        }
    }

    fn remove_address(&self, iface: &str, addr: IpAddr, _prefix_len: u8) -> Result<()> {
        run_idempotent(
            Command::new("ifconfig")
                .arg(iface)
                .arg("delete")
                .arg(addr.to_string()),
        )
    }

    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        let family = match dest {
            IpAddr::V4(_) => "-inet",
            IpAddr::V6(_) => "-inet6",
        };
        run_idempotent(
            Command::new("route")
                .arg("-n")
                .arg("add")
                .arg(family)
                .arg("-net")
                .arg(format!("{}/{}", dest, prefix_len))
                .arg("-interface")
                .arg(iface),
        )
    }

    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        let family = match dest {
            IpAddr::V4(_) => "-inet",
            IpAddr::V6(_) => "-inet6",
        };
        run_idempotent(
            Command::new("route")
                .arg("-n")
                .arg("delete")
                .arg(family)
                .arg("-net")
                .arg(format!("{}/{}", dest, prefix_len))
                .arg("-interface")
                .arg(iface),
        )
    }

    fn add_masquerade(
        &self,
        tun_iface: &str,
        tun_subnet: &str,
        out_ifaces: &[String],
    ) -> Result<()> {
        // Build PF rules: one NAT line per egress interface.
        let mut rules = String::new();
        for out in out_ifaces {
            rules.push_str(&format!(
                "nat on {} from {} to any -> ({} 0)\n",
                out, tun_subnet, out
            ));
        }

        // Write to a temp file, then load via pfctl.
        let mut tmp = tempfile::NamedTempFile::new()
            .context("failed to create temp file for PF rules")?;
        tmp.write_all(rules.as_bytes())
            .context("failed to write PF rules")?;
        tmp.flush()?;

        let anchor = format!("com.ironguard.{}", tun_iface);

        debug!("loading PF anchor {}: {}", anchor, rules.trim());
        run_idempotent(
            Command::new("pfctl")
                .arg("-a")
                .arg(&anchor)
                .arg("-f")
                .arg(tmp.path()),
        )?;

        // Enable PF if not already enabled (idempotent -- pfctl -e prints
        // "pf already enabled" to stderr on duplicate calls, which we ignore).
        run_idempotent(Command::new("pfctl").arg("-e"))
    }

    fn remove_masquerade(&self, tun_iface: &str) -> Result<()> {
        let anchor = format!("com.ironguard.{}", tun_iface);
        debug!("flushing PF anchor {}", anchor);
        run_idempotent(
            Command::new("pfctl")
                .arg("-a")
                .arg(&anchor)
                .arg("-F")
                .arg("all"),
        )
    }

    fn run_hook(&self, command: &str, iface: &str) -> Result<()> {
        let expanded = command.replace("%i", iface);
        debug!("running hook: {}", expanded);
        run_idempotent(Command::new("sh").arg("-c").arg(&expanded))
    }
}
