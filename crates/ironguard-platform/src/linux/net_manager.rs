use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::debug;

use crate::net_manager::NetworkManager;

/// Linux network manager that shells out to `ip` and `nft`.
///
/// All operations are idempotent -- duplicate adds and missing-entry removes
/// are silently ignored by checking stderr for known benign messages.
pub struct LinuxNetManager;

impl LinuxNetManager {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxNetManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Known stderr patterns that indicate an idempotent no-op rather than
/// a real failure.
const BENIGN_ERRORS: &[&str] = &[
    "File exists",
    "RTNETLINK answers: File exists",
    "Cannot remove",
    "No such process",
    "No such file or directory",
    "RTNETLINK answers: No such process",
    "Error: No such table",
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

impl NetworkManager for LinuxNetManager {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        run_idempotent(
            Command::new("ip")
                .arg("addr")
                .arg("add")
                .arg(format!("{}/{}", addr, prefix_len))
                .arg("dev")
                .arg(iface),
        )
    }

    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        run_idempotent(
            Command::new("ip")
                .arg("addr")
                .arg("del")
                .arg(format!("{}/{}", addr, prefix_len))
                .arg("dev")
                .arg(iface),
        )
    }

    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        let family = match dest {
            IpAddr::V4(_) => "-4",
            IpAddr::V6(_) => "-6",
        };
        run_idempotent(
            Command::new("ip")
                .arg(family)
                .arg("route")
                .arg("add")
                .arg(format!("{}/{}", dest, prefix_len))
                .arg("dev")
                .arg(iface),
        )
    }

    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        let family = match dest {
            IpAddr::V4(_) => "-4",
            IpAddr::V6(_) => "-6",
        };
        run_idempotent(
            Command::new("ip")
                .arg(family)
                .arg("route")
                .arg("del")
                .arg(format!("{}/{}", dest, prefix_len))
                .arg("dev")
                .arg(iface),
        )
    }

    fn add_masquerade(
        &self,
        tun_iface: &str,
        tun_subnet: &str,
        out_ifaces: &[String],
    ) -> Result<()> {
        let table = format!("ironguard-{}", tun_iface);

        // Create the nftables table (idempotent -- "File exists" is benign).
        run_idempotent(
            Command::new("nft")
                .arg("add")
                .arg("table")
                .arg("ip")
                .arg(&table),
        )?;

        // Create the NAT chain.
        run_idempotent(
            Command::new("nft")
                .arg("add")
                .arg("chain")
                .arg("ip")
                .arg(&table)
                .arg("postrouting")
                .arg("{ type nat hook postrouting priority 100 ; }"),
        )?;

        // Flush existing rules in the chain before adding, so repeated calls
        // do not accumulate duplicate rules.
        run_idempotent(
            Command::new("nft")
                .arg("flush")
                .arg("chain")
                .arg("ip")
                .arg(&table)
                .arg("postrouting"),
        )?;

        // Add a masquerade rule per egress interface.
        for out in out_ifaces {
            run_idempotent(
                Command::new("nft")
                    .arg("add")
                    .arg("rule")
                    .arg("ip")
                    .arg(&table)
                    .arg("postrouting")
                    .arg(format!(
                        "ip saddr {} oifname \"{}\" masquerade",
                        tun_subnet, out
                    )),
            )?;
        }

        Ok(())
    }

    fn remove_masquerade(&self, tun_iface: &str) -> Result<()> {
        let table = format!("ironguard-{}", tun_iface);
        debug!("deleting nftables table {}", table);
        run_idempotent(
            Command::new("nft")
                .arg("delete")
                .arg("table")
                .arg("ip")
                .arg(&table),
        )
    }

    fn run_hook(&self, command: &str, iface: &str) -> Result<()> {
        let expanded = command.replace("%i", iface);
        debug!("running hook: {}", expanded);
        run_idempotent(Command::new("sh").arg("-c").arg(&expanded))
    }
}
