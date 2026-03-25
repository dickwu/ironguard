use std::process::Command;

use anyhow::{Result, anyhow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
}

#[derive(Debug, Clone)]
pub struct System {
    pub os: Os,
}

impl System {
    pub fn detect() -> Self {
        let os = if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        };
        Self { os }
    }

    pub fn default_interface(&self) -> &str {
        match self.os {
            Os::Linux => "wg0",
            Os::MacOs => "utun9",
        }
    }

    pub fn config_dir(&self) -> &str {
        "/etc/ironguard"
    }

    pub fn key_dir(&self) -> String {
        format!("{}/keys", self.config_dir())
    }

    pub fn client_dir(&self) -> String {
        format!("{}/clients", self.config_dir())
    }

    pub fn config_file(&self) -> String {
        format!("{}/wg.json", self.config_dir())
    }

    pub fn log_file(&self, iface: &str) -> String {
        match self.os {
            Os::Linux => "/var/log/ironguard/ironguard.log".into(),
            Os::MacOs => format!("/var/log/ironguard-{iface}.log"),
        }
    }

    pub fn ironguard_bin(&self) -> &str {
        "/usr/local/bin/ironguard"
    }
}

pub fn install_service(sys: &System, iface: &str) -> Result<()> {
    let config_file = sys.config_file();
    let bin = sys.ironguard_bin();

    match sys.os {
        Os::Linux => {
            let unit = format!(
                "[Unit]\n\
                 Description=IronGuard WireGuard Tunnel ({iface})\n\
                 After=network-online.target\n\
                 Wants=network-online.target\n\n\
                 [Service]\n\
                 Type=simple\n\
                 Environment=RUST_LOG=info\n\
                 ExecStart={bin} up {iface} --config {config_file} --foreground\n\
                 ExecStop={bin} down {iface}\n\
                 Restart=on-failure\n\
                 RestartSec=5\n\
                 LimitNOFILE=65536\n\n\
                 [Install]\n\
                 WantedBy=multi-user.target\n"
            );
            let path = format!("/etc/systemd/system/ironguard@{iface}.service");
            std::fs::write(&path, unit)?;
            Command::new("systemctl").arg("daemon-reload").output()?;
            Ok(())
        }
        Os::MacOs => {
            let label = format!("com.ironguard.{iface}");
            let log_file = sys.log_file(iface);
            let plist = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n\
                 <dict>\n\
                     <key>Label</key>\n\
                     <string>{label}</string>\n\
                     <key>ProgramArguments</key>\n\
                     <array>\n\
                         <string>{bin}</string>\n\
                         <string>up</string>\n\
                         <string>{iface}</string>\n\
                         <string>--config</string>\n\
                         <string>{config_file}</string>\n\
                         <string>--foreground</string>\n\
                     </array>\n\
                     <key>EnvironmentVariables</key>\n\
                     <dict>\n\
                         <key>RUST_LOG</key>\n\
                         <string>info</string>\n\
                     </dict>\n\
                     <key>RunAtLoad</key>\n\
                     <false/>\n\
                     <key>KeepAlive</key>\n\
                     <dict>\n\
                         <key>SuccessfulExit</key>\n\
                         <false/>\n\
                     </dict>\n\
                     <key>StandardOutPath</key>\n\
                     <string>{log_file}</string>\n\
                     <key>StandardErrorPath</key>\n\
                     <string>{log_file}</string>\n\
                 </dict>\n\
                 </plist>\n"
            );
            let path = format!("/Library/LaunchDaemons/{label}.plist");
            std::fs::write(&path, plist)?;
            Ok(())
        }
    }
}

pub fn configure_firewall(sys: &System, port: u16) -> Result<String> {
    match sys.os {
        Os::Linux => {
            // try ufw first
            if Command::new("which")
                .arg("ufw")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                Command::new("ufw")
                    .args(["allow", &format!("{port}/udp"), "comment", "IronGuard"])
                    .output()?;
                return Ok(format!("ufw: allowed {port}/udp"));
            }
            // try firewalld
            if Command::new("which")
                .arg("firewall-cmd")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                Command::new("firewall-cmd")
                    .args(["--permanent", &format!("--add-port={port}/udp")])
                    .output()?;
                Command::new("firewall-cmd").arg("--reload").output()?;
                return Ok(format!("firewalld: allowed {port}/udp"));
            }
            Ok(format!(
                "No firewall manager found. Open UDP port {port} manually."
            ))
        }
        Os::MacOs => Ok(
            "macOS: firewall typically allows outbound. Add ironguard to allowed apps if needed."
                .into(),
        ),
    }
}

pub fn enable_ip_forwarding(sys: &System) -> Result<()> {
    match sys.os {
        Os::Linux => {
            let conf = "/etc/sysctl.d/99-ironguard.conf";
            if !std::path::Path::new(conf).exists() {
                std::fs::write(
                    conf,
                    "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
                )?;
            }
            Command::new("sysctl").args(["-p", conf]).output()?;
            Ok(())
        }
        Os::MacOs => {
            Command::new("sysctl")
                .args(["-w", "net.inet.ip.forwarding=1"])
                .output()?;
            Ok(())
        }
    }
}

pub fn ensure_dirs(sys: &System) -> Result<()> {
    let dirs = [sys.config_dir().to_owned(), sys.key_dir(), sys.client_dir()];
    for dir in &dirs {
        std::fs::create_dir_all(dir)?;
    }
    // restrict key dir
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(sys.key_dir(), perms)?;
    }
    if sys.os == Os::Linux {
        std::fs::create_dir_all("/var/run/ironguard")?;
        std::fs::create_dir_all("/var/log/ironguard")?;
    }
    Ok(())
}

pub fn ironguard_installed(sys: &System) -> bool {
    std::path::Path::new(sys.ironguard_bin()).exists()
}

pub fn install_binary(sys: &System) -> Result<()> {
    if ironguard_installed(sys) {
        return Ok(());
    }
    Err(anyhow!(
        "ironguard binary not found at {}. Install it first:\n  \
         brew install ironguard  (macOS)\n  \
         Or download from GitHub releases\n  \
         Or build: cargo build --release",
        sys.ironguard_bin()
    ))
}
