use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// Privilege elevation (macOS / Linux)
// ---------------------------------------------------------------------------

/// Returns `true` if the current process is running as root (uid 0).
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: getuid() is always safe to call, no arguments.
    unsafe { libc::getuid() == 0 }
}

/// Re-executes the current binary under `sudo`, preserving arguments and
/// select environment variables (`RUST_LOG`). Does **not** return on success
/// — the current process is replaced. Returns an error only if `sudo` itself
/// cannot be launched.
#[cfg(unix)]
fn elevate_with_sudo() -> Result<()> {
    let exe =
        std::env::current_exe().map_err(|e| anyhow!("cannot determine executable path: {e}"))?;

    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut cmd = std::process::Command::new("sudo");

    // Forward RUST_LOG so tracing keeps working under sudo.
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        cmd.arg(format!("RUST_LOG={rust_log}"));
    }

    cmd.arg(&exe);
    cmd.args(&args);

    // Replace this process with the sudo'd version (Unix execvp).
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(anyhow!("failed to exec sudo: {err}"))
}

/// Ensures the process is running as root. If not, prints a notice and
/// re-executes itself via `sudo`. The `command` argument is used only for
/// the user-facing message (e.g. "up", "down").
#[cfg(unix)]
fn ensure_root(command: &str) -> Result<()> {
    if is_root() {
        return Ok(());
    }
    eprintln!("ironguard {command} requires root privileges, re-running with sudo...");
    elevate_with_sudo()
}

#[derive(Parser)]
#[command(
    name = "ironguard",
    about = "Modern cross-platform WireGuard implementation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a WireGuard interface
    Up {
        /// Interface name
        interface: String,
        /// Path to wg.json config file
        #[arg(short, long, default_value = "wg.json")]
        config: String,
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
        /// Enable mesh overlay forwarding
        #[arg(long)]
        mesh: bool,
    },
    /// Stop a WireGuard interface
    Down {
        /// Interface name
        interface: String,
    },
    /// Show interface status
    Status {
        /// Interface name (omit for all)
        interface: Option<String>,
        /// Path to wg.json config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Generate a private key
    Genkey,
    /// Derive public key from private key on stdin
    Pubkey,
    /// Generate a preshared key
    Genpsk,
    /// Generate a QUIC mTLS certificate with WireGuard public key in CN
    GenQuicCert {
        /// Path to WireGuard private key file
        #[clap(long)]
        key: String,
        /// Output certificate file path
        #[clap(long, default_value = "quic.crt")]
        out_cert: String,
        /// Output TLS private key file path
        #[clap(long, default_value = "quic.key")]
        out_key: String,
    },
    /// Validate a wg.json config file
    Validate {
        /// Path to wg.json
        config: String,
    },
    /// Import a standard WireGuard .conf file to wg.json
    Import {
        /// Path to .conf file
        #[arg(long)]
        conf: String,
        /// Output wg.json path
        #[arg(short, long, default_value = "wg.json")]
        output: String,
    },
    /// Export a wg.json interface to standard .conf format
    Export {
        /// Path to wg.json
        #[arg(long, default_value = "wg.json")]
        json: String,
        /// Interface name to export
        #[arg(long)]
        interface: String,
        /// Output .conf file path (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Up {
            interface,
            config,
            foreground,
            mesh,
        } => {
            cmd_up(&interface, &config, foreground, mesh).await?;
        }
        Commands::Down { interface } => {
            cmd_down(&interface)?;
        }
        Commands::Status { interface, config } => {
            cmd_status(interface.as_deref(), config.as_deref())?;
        }
        Commands::Genkey => {
            let key = ironguard_core::StaticSecret::random();
            let encoded = hex::encode(key.as_bytes());
            println!("{encoded}");
        }
        Commands::Pubkey => {
            cmd_pubkey()?;
        }
        Commands::Genpsk => {
            let mut psk = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut psk);
            println!("{}", hex::encode(psk));
        }
        Commands::GenQuicCert {
            key,
            out_cert,
            out_key,
        } => {
            cmd_gen_quic_cert(&key, &out_cert, &out_key)?;
        }
        Commands::Validate { config } => {
            cmd_validate(&config)?;
        }
        Commands::Import { conf, output } => {
            cmd_import(&conf, &output)?;
        }
        Commands::Export {
            json,
            interface,
            output,
        } => {
            cmd_export(&json, &interface, output.as_deref())?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// cmd_up — QUIC session-based startup path (v2)
// ---------------------------------------------------------------------------

/// Start a WireGuard interface using QUIC-based session management for key
/// exchange. For each configured peer:
/// 1. Resolve endpoint address.
/// 2. Connect via QUIC and derive data-plane keys.
/// 3. Add the peer to the WireGuard device.
/// 4. Install the derived keypair into the router.
/// 5. Bind raw UDP for the data plane and start pipeline workers.
#[cfg(target_os = "macos")]
async fn cmd_up(
    interface: &str,
    config_path: &str,
    foreground: bool,
    mesh_flag: bool,
) -> Result<()> {
    ensure_root("up")?;

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use ironguard_core::session::manager::SessionManager;
    use ironguard_core::session::quic::{QuicSessionConfig, make_test_server_config};
    use ironguard_core::session::tasks::{PeerLookup, quic_accept_loop, rekey_timer_task};
    use ironguard_platform::endpoint::Endpoint;
    use ironguard_platform::macos::endpoint::MacosEndpoint;
    use ironguard_platform::macos::tun::MacosTun;
    use ironguard_platform::macos::udp::MacosUdp;
    use ironguard_platform::tun::PlatformTun;
    use ironguard_platform::udp::PlatformUdp;

    // 1. Load and validate config
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow!("failed to read config file {config_path}: {e}"))?;
    let cfg: ironguard_config::Config = serde_json::from_str(&content)
        .map_err(|e| anyhow!("failed to parse config file {config_path}: {e}"))?;

    let iface_cfg = cfg
        .interfaces
        .get(interface)
        .ok_or_else(|| anyhow!("interface {interface} not found in config"))?;

    let warnings = ironguard_config::validate(&cfg)?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    // 2. Load private key -- used for static identity.
    let _sk_bytes = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    // 3. Create TUN device
    let iface_name = interface.to_string();
    let (tun_readers, tun_writer, _tun_status) =
        MacosTun::create(interface).map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

    // 3a. Create platform-specific network manager
    use ironguard_platform::net_manager::NetworkManager;
    let net_mgr = ironguard_platform::macos::net_manager::MacosNetManager::new();

    // Crash recovery: clean stale state from previous run
    for addr_str in &iface_cfg.address {
        if let Ok((ip, prefix_len)) = parse_cidr_u8(addr_str) {
            let _ = net_mgr.remove_address(&iface_name, ip, prefix_len);
        }
    }
    let _ = net_mgr.remove_masquerade(&iface_name);

    // Assign addresses to TUN interface
    for addr_str in &iface_cfg.address {
        let (ip, prefix_len) = parse_cidr_u8(addr_str)?;
        net_mgr.add_address(&iface_name, ip, prefix_len)?;
        tracing::info!("assigned {addr_str} to {iface_name}");
    }

    // Add routes for each peer's allowed_ips
    for peer_cfg in &iface_cfg.peers {
        for allowed_ip in &peer_cfg.allowed_ips {
            let (dest, prefix_len) = parse_cidr_u8(allowed_ip)?;
            if prefix_len == 0 {
                tracing::warn!(
                    "skipping default route {allowed_ip} -- use post_up for catch-all routing"
                );
                continue;
            }
            net_mgr.add_route(&iface_name, dest, prefix_len)?;
            tracing::info!("route {allowed_ip} via {iface_name}");
        }
    }

    // Enable masquerade if configured
    if !iface_cfg.masquerade.is_disabled() {
        if let Some(tun_subnet) = iface_cfg.address.first() {
            match &iface_cfg.masquerade {
                ironguard_config::Masquerade::All => {
                    net_mgr.add_masquerade(&iface_name, tun_subnet, &[])?;
                }
                ironguard_config::Masquerade::Interfaces(ifaces) => {
                    net_mgr.add_masquerade(&iface_name, tun_subnet, ifaces)?;
                }
                ironguard_config::Masquerade::Disabled => {}
            }
        }
    }

    // Run PostUp hooks
    for cmd in &iface_cfg.post_up {
        net_mgr.run_hook(cmd, &iface_name)?;
    }

    // 4. Create WireGuard device (raw UDP data plane)
    type Wg = ironguard_core::device::WireGuard<MacosTun, MacosUdp>;
    let wg: Wg = ironguard_core::device::WireGuard::new_with_handle(
        tun_writer,
        tokio::runtime::Handle::current(),
    );

    // 5. Build SessionManager from QUIC config
    if let Some(transport) = &iface_cfg.transport {
        if transport == "udp" {
            return Err(anyhow!(
                "UDP transport is not supported. IronGuard uses QUIC-based \
                 session management. Remove the transport field from your config."
            ));
        }
        tracing::warn!("transport field is deprecated and ignored -- QUIC is always used");
    }

    let quic_cfg = iface_cfg
        .quic
        .as_ref()
        .ok_or_else(|| anyhow!("missing [quic] config section -- required for IronGuard"))?;

    let quic_port = quic_cfg
        .port
        .or_else(|| iface_cfg.listen_port.filter(|&p| p < 65535).map(|p| p + 1))
        .ok_or_else(|| anyhow!("set quic.port or ensure listen_port < 65535"))?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{quic_port}").parse().unwrap();
    let session_config = QuicSessionConfig {
        bind_addr,
        alpn: quic_cfg
            .alpn
            .as_deref()
            .unwrap_or("ironguard/1")
            .as_bytes()
            .to_vec(),
        cert_path: quic_cfg.cert_path.as_ref().map(std::path::PathBuf::from),
        key_path: quic_cfg.key_path.as_ref().map(std::path::PathBuf::from),
        sni: quic_cfg.sni.clone(),
        our_certs: Vec::new(),
        our_key: None,
    };
    let session_mgr = Arc::new(SessionManager::new(session_config));

    eprintln!("session manager created (bind={})", bind_addr);

    // Build a peer lookup table for the accept loop.
    let known_peers = Arc::new(PeerLookup::new());

    // Build known_peer_pks set for mTLS identity verification.
    let known_peer_pks: std::collections::HashSet<[u8; 32]> = iface_cfg
        .peers
        .iter()
        .filter_map(|p| {
            let bytes = hex::decode(&p.public_key).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect();

    // 6. For each peer: connect via QUIC, get keys, add peer to device
    for (i, peer_cfg) in iface_cfg.peers.iter().enumerate() {
        let pk_bytes = ironguard_config::decode_key(&peer_cfg.public_key)
            .map_err(|e| anyhow!("failed to decode public key for peer {i}: {e}"))?;
        let pk = ironguard_core::PublicKey::from_bytes(pk_bytes);

        // Add peer to the WireGuard device first.
        wg.add_peer(pk.clone());

        let handle = wg
            .get_peer_handle(&pk)
            .ok_or_else(|| anyhow!("peer {i} not found after adding"))?;

        // Set allowed IPs.
        for allowed_ip_str in &peer_cfg.allowed_ips {
            let (ip, masklen) = parse_cidr(allowed_ip_str)?;
            handle.add_allowed_ip(ip, masklen);
        }

        // Wire ACL into peer configuration.
        if let Some(acl) = &peer_cfg.acl {
            let acl_table = ironguard_core::router::RoutingTable::new();
            for cidr in &acl.allow_destinations {
                let (ip, prefix_len) = parse_cidr(cidr)?;
                acl_table.insert(ip, prefix_len, ());
            }
            handle.set_acl_destinations(Some(acl_table));
        }

        // Set persistent keepalive.
        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
        }

        // Connect via QUIC session if an endpoint is configured.
        if let Some(ep_str) = &peer_cfg.endpoint {
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(MacosEndpoint::from_address(addr));

            // Register peer in lookup table for the accept loop.
            known_peers.add(addr, pk_bytes);

            let data_port = iface_cfg.listen_port.unwrap_or(0);
            let receiver_id: u32 = rand::random();

            let quic_port = peer_cfg.quic_port.unwrap_or(addr.port() + 1);
            let quic_addr: SocketAddr = (addr.ip(), quic_port).into();

            match session_mgr
                .connect(pk_bytes, quic_addr, None, data_port, receiver_id)
                .await
            {
                Ok(session) => {
                    eprintln!(
                        "  peer {i}: QUIC session established (epoch={}, receiver_id={})",
                        session.epoch, session.receiver_id
                    );

                    let keypair = ironguard_core::KeyPair {
                        birth: Instant::now(),
                        initiator: true,
                        send: ironguard_core::Key {
                            cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.send_key),
                            key: session.keys.send_key,
                            id: session.peer_receiver_id,
                        },
                        recv: ironguard_core::Key {
                            cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.recv_key),
                            key: session.keys.recv_key,
                            id: session.receiver_id,
                        },
                    };
                    handle.add_keypair(keypair);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = i,
                        error = %e,
                        "QUIC session failed; peer will not have keys until session succeeds"
                    );
                }
            }
        } else {
            // Server-side peer without endpoint -- accept from any address.
            known_peers.add_wildcard(pk_bytes);
        }

        eprintln!(
            "  peer {i}: configured (allowed_ips: {})",
            peer_cfg.allowed_ips.join(", ")
        );
    }

    // 7. Bind raw UDP for the data plane
    let port = iface_cfg.listen_port.unwrap_or(0);
    let (udp_readers, udp_writer, owner) =
        MacosUdp::bind(port).map_err(|e| anyhow!("failed to bind UDP socket: {e}"))?;

    wg.set_writer(udp_writer);
    for reader in udp_readers {
        wg.add_udp_reader(reader);
    }
    let actual_port = owner.port();
    eprintln!("data plane listening on port {actual_port}");

    // 8. Add TUN readers
    for reader in tun_readers {
        wg.add_tun_reader(reader);
    }

    // 9. Mesh forwarding setup
    let mesh_enabled = mesh_flag
        || iface_cfg
            .mesh
            .as_ref()
            .is_some_and(|m| m.enabled && m.forward);

    if mesh_enabled {
        // Set local addresses from interface config
        for addr_str in &iface_cfg.address {
            if let Ok((ip, _masklen)) = parse_cidr(addr_str) {
                wg.router.add_local_address(ip);
            }
        }

        // Build forwarding table from peer allowed_ips
        let peer_handles = wg.peer_handles.read();
        for (_pk_bytes, peer_handle) in peer_handles.iter() {
            let allowed = peer_handle.list_allowed_ips();
            for (ip, masklen) in allowed {
                wg.router.add_forwarding_route(ip, masklen, peer_handle);
            }
        }

        // Enable forwarding
        wg.router.set_forwarding_enabled(true);
        eprintln!("mesh forwarding enabled");
    }

    // 10. Bring up
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    // 11. Start timer task
    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    // 12. Spawn QUIC accept loop and rekey timer background tasks.
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let wg_installer = Arc::new(WgKeyInstaller { wg: wg.clone() });

    let server_config = make_test_server_config();
    let quic_endpoint = quinn::Endpoint::server(server_config.clone(), bind_addr)
        .or_else(|_| {
            let fallback: SocketAddr = (bind_addr.ip(), 0u16).into();
            quinn::Endpoint::server(server_config, fallback)
        })
        .map_err(|e| anyhow!("failed to create QUIC server endpoint: {e}"))?;

    let quic_listen_addr = quic_endpoint
        .local_addr()
        .map_err(|e| anyhow!("QUIC endpoint local_addr: {e}"))?;
    eprintln!("QUIC accept loop listening on {quic_listen_addr}");

    let _accept_handle = tokio::spawn(quic_accept_loop(
        quic_endpoint,
        session_mgr.clone(),
        wg_installer.clone(),
        known_peers,
        known_peer_pks,
        actual_port,
        stop.clone(),
        shutdown.clone(),
    ));

    let _rekey_handle = tokio::spawn(rekey_timer_task(
        session_mgr.clone(),
        wg_installer,
        stop.clone(),
        shutdown.clone(),
    ));

    write_pid_file(interface)?;
    let cleanup_iface = iface_name.clone();
    let cleanup_cfg = iface_cfg.clone();
    eprintln!(
        "interface {interface} is up (mtu={mtu}, transport=quic-session, mesh={mesh_enabled}, sessions={})",
        session_mgr.session_count()
    );

    // 13. Wait for Ctrl+C or SIGTERM
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = async {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            sigterm.recv().await;
        } => {},
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown.notify_waiters();

    // PostDown hooks
    for cmd in &cleanup_cfg.post_down {
        let _ = net_mgr.run_hook(cmd, &cleanup_iface);
    }
    // Remove masquerade
    let _ = net_mgr.remove_masquerade(&cleanup_iface);
    // Remove routes
    for peer_cfg in &cleanup_cfg.peers {
        for allowed_ip in &peer_cfg.allowed_ips {
            if let Ok((dest, prefix_len)) = parse_cidr_u8(allowed_ip) {
                let _ = net_mgr.remove_route(&cleanup_iface, dest, prefix_len);
            }
        }
    }
    // Remove addresses
    for addr_str in &cleanup_cfg.address {
        if let Ok((ip, prefix_len)) = parse_cidr_u8(addr_str) {
            let _ = net_mgr.remove_address(&cleanup_iface, ip, prefix_len);
        }
    }

    wg.down();
    remove_pid_file(&cleanup_iface);
    eprintln!("interface {interface} is down");

    Ok(())
}

/// Linux startup path -- uses SessionManager for QUIC-based key exchange.
#[cfg(target_os = "linux")]
async fn cmd_up(
    interface: &str,
    config_path: &str,
    foreground: bool,
    mesh_flag: bool,
) -> Result<()> {
    ensure_root("up")?;

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use ironguard_core::session::manager::SessionManager;
    use ironguard_core::session::quic::{QuicSessionConfig, make_test_server_config};
    use ironguard_core::session::tasks::{PeerLookup, quic_accept_loop, rekey_timer_task};
    use ironguard_platform::endpoint::Endpoint;
    use ironguard_platform::linux::endpoint::LinuxEndpoint;
    use ironguard_platform::linux::tun::LinuxTun;
    use ironguard_platform::linux::udp::LinuxUdp;
    use ironguard_platform::tun::PlatformTun;
    use ironguard_platform::udp::PlatformUdp;

    // 1. Load and validate config
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow!("failed to read config file {config_path}: {e}"))?;
    let cfg: ironguard_config::Config = serde_json::from_str(&content)
        .map_err(|e| anyhow!("failed to parse config file {config_path}: {e}"))?;

    let iface_cfg = cfg
        .interfaces
        .get(interface)
        .ok_or_else(|| anyhow!("interface {interface} not found in config"))?;

    let warnings = ironguard_config::validate(&cfg)?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    // 2. Load private key -- used for static identity.
    let _sk_bytes = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    // 3. Create TUN device
    let iface_name = interface.to_string();
    let (tun_readers, tun_writer, _tun_status) =
        LinuxTun::create(interface).map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

    // 3a. Create platform-specific network manager
    use ironguard_platform::net_manager::NetworkManager;
    let net_mgr = ironguard_platform::linux::net_manager::LinuxNetManager::new();

    // Crash recovery: clean stale state from previous run
    for addr_str in &iface_cfg.address {
        if let Ok((ip, prefix_len)) = parse_cidr_u8(addr_str) {
            let _ = net_mgr.remove_address(&iface_name, ip, prefix_len);
        }
    }
    let _ = net_mgr.remove_masquerade(&iface_name);

    // Assign addresses to TUN interface
    for addr_str in &iface_cfg.address {
        let (ip, prefix_len) = parse_cidr_u8(addr_str)?;
        net_mgr.add_address(&iface_name, ip, prefix_len)?;
        tracing::info!("assigned {addr_str} to {iface_name}");
    }

    // Add routes for each peer's allowed_ips
    for peer_cfg in &iface_cfg.peers {
        for allowed_ip in &peer_cfg.allowed_ips {
            let (dest, prefix_len) = parse_cidr_u8(allowed_ip)?;
            if prefix_len == 0 {
                tracing::warn!(
                    "skipping default route {allowed_ip} -- use post_up for catch-all routing"
                );
                continue;
            }
            net_mgr.add_route(&iface_name, dest, prefix_len)?;
            tracing::info!("route {allowed_ip} via {iface_name}");
        }
    }

    // Enable masquerade if configured
    if !iface_cfg.masquerade.is_disabled() {
        if let Some(tun_subnet) = iface_cfg.address.first() {
            match &iface_cfg.masquerade {
                ironguard_config::Masquerade::All => {
                    net_mgr.add_masquerade(&iface_name, tun_subnet, &[])?;
                }
                ironguard_config::Masquerade::Interfaces(ifaces) => {
                    net_mgr.add_masquerade(&iface_name, tun_subnet, ifaces)?;
                }
                ironguard_config::Masquerade::Disabled => {}
            }
        }
    }

    // Run PostUp hooks
    for cmd in &iface_cfg.post_up {
        net_mgr.run_hook(cmd, &iface_name)?;
    }

    // 4. Create WireGuard device (raw UDP data plane)
    type Wg = ironguard_core::device::WireGuard<LinuxTun, LinuxUdp>;
    let wg: Wg = ironguard_core::device::WireGuard::new_with_handle(
        tun_writer,
        tokio::runtime::Handle::current(),
    );

    // 5. Build SessionManager from QUIC config
    if let Some(transport) = &iface_cfg.transport {
        if transport == "udp" {
            return Err(anyhow!(
                "UDP transport is not supported. IronGuard uses QUIC-based \
                 session management. Remove the transport field from your config."
            ));
        }
        tracing::warn!("transport field is deprecated and ignored -- QUIC is always used");
    }

    let quic_cfg = iface_cfg
        .quic
        .as_ref()
        .ok_or_else(|| anyhow!("missing [quic] config section -- required for IronGuard"))?;

    let quic_port = quic_cfg
        .port
        .or_else(|| iface_cfg.listen_port.filter(|&p| p < 65535).map(|p| p + 1))
        .ok_or_else(|| anyhow!("set quic.port or ensure listen_port < 65535"))?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{quic_port}").parse().unwrap();
    let session_config = QuicSessionConfig {
        bind_addr,
        alpn: quic_cfg
            .alpn
            .as_deref()
            .unwrap_or("ironguard/1")
            .as_bytes()
            .to_vec(),
        cert_path: quic_cfg.cert_path.as_ref().map(std::path::PathBuf::from),
        key_path: quic_cfg.key_path.as_ref().map(std::path::PathBuf::from),
        sni: quic_cfg.sni.clone(),
        our_certs: Vec::new(),
        our_key: None,
    };
    let session_mgr = Arc::new(SessionManager::new(session_config));

    eprintln!("session manager created (bind={})", bind_addr);

    // Build a peer lookup table for the accept loop.
    let known_peers = Arc::new(PeerLookup::new());

    // Build known_peer_pks set for mTLS identity verification.
    let known_peer_pks: std::collections::HashSet<[u8; 32]> = iface_cfg
        .peers
        .iter()
        .filter_map(|p| {
            let bytes = hex::decode(&p.public_key).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect();

    // 6. For each peer: connect via QUIC, get keys, add peer to device
    for (i, peer_cfg) in iface_cfg.peers.iter().enumerate() {
        let pk_bytes = ironguard_config::decode_key(&peer_cfg.public_key)
            .map_err(|e| anyhow!("failed to decode public key for peer {i}: {e}"))?;
        let pk = ironguard_core::PublicKey::from_bytes(pk_bytes);

        wg.add_peer(pk.clone());

        let handle = wg
            .get_peer_handle(&pk)
            .ok_or_else(|| anyhow!("peer {i} not found after adding"))?;

        for allowed_ip_str in &peer_cfg.allowed_ips {
            let (ip, masklen) = parse_cidr(allowed_ip_str)?;
            handle.add_allowed_ip(ip, masklen);
        }

        // Wire ACL into peer configuration.
        if let Some(acl) = &peer_cfg.acl {
            let acl_table = ironguard_core::router::RoutingTable::new();
            for cidr in &acl.allow_destinations {
                let (ip, prefix_len) = parse_cidr(cidr)?;
                acl_table.insert(ip, prefix_len, ());
            }
            handle.set_acl_destinations(Some(acl_table));
        }

        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
        }

        if let Some(ep_str) = &peer_cfg.endpoint {
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(LinuxEndpoint::from_address(addr));

            known_peers.add(addr, pk_bytes);

            let data_port = iface_cfg.listen_port.unwrap_or(0);
            let receiver_id: u32 = rand::random();

            let quic_port = peer_cfg.quic_port.unwrap_or(addr.port() + 1);
            let quic_addr: SocketAddr = (addr.ip(), quic_port).into();

            match session_mgr
                .connect(pk_bytes, quic_addr, None, data_port, receiver_id)
                .await
            {
                Ok(session) => {
                    eprintln!(
                        "  peer {i}: QUIC session established (epoch={}, receiver_id={})",
                        session.epoch, session.receiver_id
                    );

                    let keypair = ironguard_core::KeyPair {
                        birth: Instant::now(),
                        initiator: true,
                        send: ironguard_core::Key {
                            cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.send_key),
                            key: session.keys.send_key,
                            id: session.peer_receiver_id,
                        },
                        recv: ironguard_core::Key {
                            cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.recv_key),
                            key: session.keys.recv_key,
                            id: session.receiver_id,
                        },
                    };
                    handle.add_keypair(keypair);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = i,
                        error = %e,
                        "QUIC session failed; peer will not have keys until session succeeds"
                    );
                }
            }
        } else {
            known_peers.add_wildcard(pk_bytes);
        }

        eprintln!(
            "  peer {i}: configured (allowed_ips: {})",
            peer_cfg.allowed_ips.join(", ")
        );
    }

    // 7. Bind raw UDP for the data plane
    let port = iface_cfg.listen_port.unwrap_or(0);
    let (udp_readers, udp_writer, owner) =
        LinuxUdp::bind(port).map_err(|e| anyhow!("failed to bind UDP socket: {e}"))?;

    wg.set_writer(udp_writer);
    for reader in udp_readers {
        wg.add_udp_reader(reader);
    }
    let actual_port = owner.port();
    eprintln!("data plane listening on port {actual_port}");

    // 8. Add TUN readers
    for reader in tun_readers {
        wg.add_tun_reader(reader);
    }

    // 9. Mesh forwarding setup
    let mesh_enabled = mesh_flag
        || iface_cfg
            .mesh
            .as_ref()
            .is_some_and(|m| m.enabled && m.forward);

    if mesh_enabled {
        // Set local addresses from interface config
        for addr_str in &iface_cfg.address {
            if let Ok((ip, _masklen)) = parse_cidr(addr_str) {
                wg.router.add_local_address(ip);
            }
        }

        // Build forwarding table from peer allowed_ips
        let peer_handles = wg.peer_handles.read();
        for (_pk_bytes, peer_handle) in peer_handles.iter() {
            let allowed = peer_handle.list_allowed_ips();
            for (ip, masklen) in allowed {
                wg.router.add_forwarding_route(ip, masklen, peer_handle);
            }
        }

        // Enable forwarding
        wg.router.set_forwarding_enabled(true);
        eprintln!("mesh forwarding enabled");
    }

    // 10. Bring up
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    // 11. Start timer task
    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    // 12. Spawn QUIC accept loop and rekey timer background tasks.
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let wg_installer = Arc::new(WgKeyInstaller { wg: wg.clone() });

    let server_config = make_test_server_config();
    let quic_endpoint = quinn::Endpoint::server(server_config.clone(), bind_addr)
        .or_else(|_| {
            let fallback: SocketAddr = (bind_addr.ip(), 0u16).into();
            quinn::Endpoint::server(server_config, fallback)
        })
        .map_err(|e| anyhow!("failed to create QUIC server endpoint: {e}"))?;

    let quic_listen_addr = quic_endpoint
        .local_addr()
        .map_err(|e| anyhow!("QUIC endpoint local_addr: {e}"))?;
    eprintln!("QUIC accept loop listening on {quic_listen_addr}");

    let _accept_handle = tokio::spawn(quic_accept_loop(
        quic_endpoint,
        session_mgr.clone(),
        wg_installer.clone(),
        known_peers,
        known_peer_pks,
        actual_port,
        stop.clone(),
        shutdown.clone(),
    ));

    let _rekey_handle = tokio::spawn(rekey_timer_task(
        session_mgr.clone(),
        wg_installer,
        stop.clone(),
        shutdown.clone(),
    ));

    write_pid_file(interface)?;
    let cleanup_iface = iface_name.clone();
    let cleanup_cfg = iface_cfg.clone();
    eprintln!(
        "interface {interface} is up (mtu={mtu}, transport=quic-session, mesh={mesh_enabled}, sessions={})",
        session_mgr.session_count()
    );

    // 13. Wait for Ctrl+C or SIGTERM
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = async {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            sigterm.recv().await;
        } => {},
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown.notify_waiters();

    // PostDown hooks
    for cmd in &cleanup_cfg.post_down {
        let _ = net_mgr.run_hook(cmd, &cleanup_iface);
    }
    // Remove masquerade
    let _ = net_mgr.remove_masquerade(&cleanup_iface);
    // Remove routes
    for peer_cfg in &cleanup_cfg.peers {
        for allowed_ip in &peer_cfg.allowed_ips {
            if let Ok((dest, prefix_len)) = parse_cidr_u8(allowed_ip) {
                let _ = net_mgr.remove_route(&cleanup_iface, dest, prefix_len);
            }
        }
    }
    // Remove addresses
    for addr_str in &cleanup_cfg.address {
        if let Ok((ip, prefix_len)) = parse_cidr_u8(addr_str) {
            let _ = net_mgr.remove_address(&cleanup_iface, ip, prefix_len);
        }
    }

    wg.down();
    remove_pid_file(&cleanup_iface);
    eprintln!("interface {interface} is down");

    Ok(())
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
async fn cmd_up(
    _interface: &str,
    _config_path: &str,
    _foreground: bool,
    _mesh_flag: bool,
) -> Result<()> {
    eprintln!("Platform not yet supported");
    Ok(())
}

fn cmd_gen_quic_cert(key_path: &str, out_cert: &str, out_key: &str) -> Result<()> {
    use anyhow::Context;

    let key_data = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read key file: {key_path}"))?;
    let key_hex = key_data.trim();
    let private_bytes =
        hex::decode(key_hex).with_context(|| "failed to decode private key as hex")?;

    let secret = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(private_bytes.as_slice())
            .map_err(|_| anyhow!("private key must be 32 bytes"))?,
    );
    let public = x25519_dalek::PublicKey::from(&secret);
    let wg_pk: [u8; 32] = public.to_bytes();

    let (cert_der, key_der) = ironguard_core::session::quic::generate_wg_cert(&wg_pk)
        .map_err(|e| anyhow!("cert generation failed: {e}"))?;

    // Write PEM-encoded certificate
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.as_ref()));
    std::fs::write(out_cert, &cert_pem)
        .with_context(|| format!("failed to write cert: {out_cert}"))?;

    // Write PEM-encoded private key
    let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key_der.secret_der()));
    std::fs::write(out_key, &key_pem)
        .with_context(|| format!("failed to write key: {out_key}"))?;

    eprintln!("Generated mTLS certificate:");
    eprintln!("  cert: {out_cert}");
    eprintln!("  key:  {out_key}");
    Ok(())
}

fn resolve_endpoint(endpoint: &str) -> Result<std::net::SocketAddr> {
    // Try direct parse first
    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }

    // DNS resolution
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = endpoint
        .to_socket_addrs()
        .map_err(|e| anyhow!("failed to resolve endpoint {endpoint}: {e}"))?
        .collect();

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("endpoint {endpoint} resolved to no addresses"))
}

fn parse_cidr(cidr: &str) -> Result<(std::net::IpAddr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!("invalid CIDR: {cidr}"));
    }

    let ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|e| anyhow!("invalid IP in CIDR {cidr}: {e}"))?;
    let masklen: u32 = parts[1]
        .parse()
        .map_err(|e| anyhow!("invalid mask length in CIDR {cidr}: {e}"))?;

    Ok((ip, masklen))
}

/// Parse CIDR with `u8` prefix length (for NetworkManager API).
fn parse_cidr_u8(cidr: &str) -> Result<(std::net::IpAddr, u8)> {
    let (ip, masklen) = parse_cidr(cidr)?;
    let prefix: u8 = masklen
        .try_into()
        .map_err(|_| anyhow!("prefix length {masklen} out of u8 range in {cidr}"))?;
    Ok((ip, prefix))
}

fn cmd_status(interface: Option<&str>, config_path: Option<&str>) -> Result<()> {
    let content = match config_path {
        Some(p) => std::fs::read_to_string(p).map_err(|e| anyhow!("failed to read config: {e}"))?,
        None => std::fs::read_to_string("wg.json")
            .or_else(|_| std::fs::read_to_string("/etc/ironguard/wg.json"))
            .map_err(|_| anyhow!("no config found at wg.json or /etc/ironguard/wg.json"))?,
    };

    let cfg: ironguard_config::Config = serde_json::from_str(&content)?;

    match interface {
        Some(iface) => {
            let ic = cfg
                .interfaces
                .get(iface)
                .ok_or_else(|| anyhow!("interface {iface} not found"))?;
            print_interface_status(iface, ic);
        }
        None => {
            for (name, ic) in &cfg.interfaces {
                print_interface_status(name, ic);
            }
        }
    }

    Ok(())
}

fn print_interface_status(name: &str, ic: &ironguard_config::types::InterfaceConfig) {
    eprintln!("interface: {name}");
    if let Some(port) = ic.listen_port {
        eprintln!("  listening port: {port}");
    }
    eprintln!("  transport: {}", ic.transport.as_deref().unwrap_or("udp"));
    eprintln!("  peers: {}", ic.peers.len());
    for (i, peer) in ic.peers.iter().enumerate() {
        eprintln!("  peer {i}:");
        eprintln!("    public key: {}", peer.public_key);
        if let Some(ep) = &peer.endpoint {
            eprintln!("    endpoint: {ep}");
        }
        eprintln!("    allowed ips: {}", peer.allowed_ips.join(", "));
    }
}

fn cmd_pubkey() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let hex_key = input.trim();

    let sk_bytes = hex::decode(hex_key).map_err(|e| anyhow!("invalid hex private key: {e}"))?;
    if sk_bytes.len() != 32 {
        return Err(anyhow!(
            "private key must be 32 bytes, got {}",
            sk_bytes.len()
        ));
    }

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);

    let sk = x25519_dalek::StaticSecret::from(sk_arr);
    let pk = x25519_dalek::PublicKey::from(&sk);
    println!("{}", hex::encode(pk.as_bytes()));

    Ok(())
}

fn cmd_validate(config_path: &str) -> Result<()> {
    let content =
        std::fs::read_to_string(config_path).map_err(|e| anyhow!("failed to read config: {e}"))?;
    let cfg: ironguard_config::Config =
        serde_json::from_str(&content).map_err(|e| anyhow!("failed to parse config: {e}"))?;

    let warnings = ironguard_config::validate(&cfg)?;
    if warnings.is_empty() {
        eprintln!("config valid: {config_path}");
    } else {
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        eprintln!(
            "config valid with {} warnings: {config_path}",
            warnings.len()
        );
    }

    Ok(())
}

fn cmd_import(conf_path: &str, output_path: &str) -> Result<()> {
    let config = ironguard_config::import_conf(conf_path)?;
    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write(output_path, &json)
        .map_err(|e| anyhow!("failed to write {output_path}: {e}"))?;
    eprintln!("imported {conf_path} -> {output_path}");
    Ok(())
}

fn cmd_export(json_path: &str, interface: &str, output: Option<&str>) -> Result<()> {
    let content = std::fs::read_to_string(json_path)
        .map_err(|e| anyhow!("failed to read {json_path}: {e}"))?;
    let config: ironguard_config::Config =
        serde_json::from_str(&content).map_err(|e| anyhow!("failed to parse {json_path}: {e}"))?;

    let conf_str = ironguard_config::export_conf(&config, interface)?;

    match output {
        Some(path) => {
            std::fs::write(path, &conf_str).map_err(|e| anyhow!("failed to write {path}: {e}"))?;
            eprintln!("exported {interface} -> {path}");
        }
        None => {
            print!("{conf_str}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PID file helpers — used by cmd_up* to support `ironguard down`
// ---------------------------------------------------------------------------

fn pid_file_path(interface: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/tmp/ironguard-{interface}.pid"))
}

fn write_pid_file(interface: &str) -> Result<()> {
    let path = pid_file_path(interface);
    std::fs::write(&path, std::process::id().to_string())
        .map_err(|e| anyhow!("failed to write PID file {}: {e}", path.display()))?;
    Ok(())
}

fn remove_pid_file(interface: &str) {
    let _ = std::fs::remove_file(pid_file_path(interface));
}

fn cmd_down(interface: &str) -> Result<()> {
    ensure_root("down")?;

    let path = pid_file_path(interface);
    let pid_str = std::fs::read_to_string(&path).map_err(|_| {
        anyhow!(
            "interface {interface} is not running (no PID file at {})",
            path.display()
        )
    })?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .map_err(|e| anyhow!("invalid PID in {}: {e}", path.display()))?;

    // Send SIGTERM to the running process.
    #[cfg(unix)]
    {
        use std::io;
        // SAFETY: sending a signal to a valid PID is safe.
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(anyhow!("permission denied sending SIGTERM to PID {pid}"));
            }
            // ESRCH = no such process — stale PID file
            remove_pid_file(interface);
            return Err(anyhow!(
                "process {pid} not found (stale PID file removed); interface may already be down"
            ));
        }
        eprintln!("sent SIGTERM to ironguard PID {pid} (interface {interface})");
    }

    #[cfg(not(unix))]
    {
        return Err(anyhow!(
            "ironguard down is only supported on Unix platforms"
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// WgKeyInstaller — bridges SessionManager keys to the WireGuard router
// ---------------------------------------------------------------------------

/// Installs session-derived keypairs into the WireGuard device's router.
///
/// Implements `KeyInstaller` from `ironguard_core::session::tasks` so that
/// the accept loop and rekey timer can push new keys without knowing the
/// concrete platform types.
#[cfg(target_os = "macos")]
struct WgKeyInstaller {
    wg: ironguard_core::device::WireGuard<
        ironguard_platform::macos::tun::MacosTun,
        ironguard_platform::macos::udp::MacosUdp,
    >,
}

#[cfg(target_os = "macos")]
impl ironguard_core::session::tasks::KeyInstaller for WgKeyInstaller {
    fn install_keypair(
        &self,
        peer_pk: &[u8; 32],
        session: &ironguard_core::session::manager::SessionResult,
        initiator: bool,
    ) {
        let pk = ironguard_core::PublicKey::from_bytes(*peer_pk);
        if let Some(handle) = self.wg.get_peer_handle(&pk) {
            // send.id = peer's receiver_id (what the peer expects in frame headers)
            // recv.id = our receiver_id (registered in our recv map for lookup)
            let keypair = ironguard_core::KeyPair {
                birth: std::time::Instant::now(),
                initiator,
                send: ironguard_core::Key {
                    cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.send_key),
                    key: session.keys.send_key,
                    id: session.peer_receiver_id,
                },
                recv: ironguard_core::Key {
                    cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.recv_key),
                    key: session.keys.recv_key,
                    id: session.receiver_id,
                },
            };
            handle.add_keypair(keypair);
            tracing::info!(
                peer = hex::encode(peer_pk),
                epoch = session.epoch,
                send_id = session.peer_receiver_id,
                recv_id = session.receiver_id,
                "installed keypair into router"
            );
        } else {
            tracing::warn!(
                peer = hex::encode(peer_pk),
                "cannot install keypair: peer not found in device"
            );
        }
    }
}

#[cfg(target_os = "linux")]
struct WgKeyInstaller {
    wg: ironguard_core::device::WireGuard<
        ironguard_platform::linux::tun::LinuxTun,
        ironguard_platform::linux::udp::LinuxUdp,
    >,
}

#[cfg(target_os = "linux")]
impl ironguard_core::session::tasks::KeyInstaller for WgKeyInstaller {
    fn install_keypair(
        &self,
        peer_pk: &[u8; 32],
        session: &ironguard_core::session::manager::SessionResult,
        initiator: bool,
    ) {
        let pk = ironguard_core::PublicKey::from_bytes(*peer_pk);
        if let Some(handle) = self.wg.get_peer_handle(&pk) {
            // send.id = peer's receiver_id (what the peer expects in frame headers)
            // recv.id = our receiver_id (registered in our recv map for lookup)
            let keypair = ironguard_core::KeyPair {
                birth: std::time::Instant::now(),
                initiator,
                send: ironguard_core::Key {
                    cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.send_key),
                    key: session.keys.send_key,
                    id: session.peer_receiver_id,
                },
                recv: ironguard_core::Key {
                    cached_aead: ironguard_core::CachedAeadKey::new(&session.keys.recv_key),
                    key: session.keys.recv_key,
                    id: session.receiver_id,
                },
            };
            handle.add_keypair(keypair);
            tracing::info!(
                peer = hex::encode(peer_pk),
                epoch = session.epoch,
                send_id = session.peer_receiver_id,
                recv_id = session.receiver_id,
                "installed keypair into router"
            );
        } else {
            tracing::warn!(
                peer = hex::encode(peer_pk),
                "cannot install keypair: peer not found in device"
            );
        }
    }
}
