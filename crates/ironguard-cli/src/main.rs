use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

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
    /// Generate an ML-KEM-768 post-quantum keypair (requires --features pq)
    #[cfg(feature = "pq")]
    PqGenkey,
    /// Derive ML-KEM-768 public key from private key on stdin (requires --features pq)
    #[cfg(feature = "pq")]
    PqPubkey,
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
    /// Start a WireGuard interface using the v2 QUIC session path (requires --features quic)
    #[cfg(feature = "quic")]
    UpV2 {
        /// Interface name
        interface: String,
        /// Path to wg.json config file
        #[arg(short, long, default_value = "wg.json")]
        config: String,
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
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
        } => {
            cmd_up(&interface, &config, foreground).await?;
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
        #[cfg(feature = "pq")]
        Commands::PqGenkey => {
            cmd_pq_genkey();
        }
        #[cfg(feature = "pq")]
        Commands::PqPubkey => {
            cmd_pq_pubkey()?;
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
        #[cfg(feature = "quic")]
        Commands::UpV2 {
            interface,
            config,
            foreground,
        } => {
            cmd_up_v2(&interface, &config, foreground).await?;
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
async fn cmd_up(interface: &str, config_path: &str, foreground: bool) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

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

    // 2. Load private key
    let sk_bytes = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    // 3. Create TUN device
    let (tun_readers, tun_writer, _tun_status) =
        MacosTun::create(interface).map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

    // Branch on transport mode
    #[cfg(feature = "quic")]
    if iface_cfg.transport == "quic" {
        return cmd_up_quic(iface_cfg, tun_readers, tun_writer, sk_bytes, interface).await;
    }

    // 4. Create WireGuard device (raw UDP path)
    type Wg = ironguard_core::device::WireGuard<MacosTun, MacosUdp>;
    let wg: Wg = ironguard_core::device::WireGuard::new(tun_writer);

    // 5. Set private key
    let sk = ironguard_core::StaticSecret::from_bytes(sk_bytes);
    wg.set_key(Some(sk));

    // 6. Configure peers
    for (i, peer_cfg) in iface_cfg.peers.iter().enumerate() {
        let pk_bytes = ironguard_config::decode_key(&peer_cfg.public_key)
            .map_err(|e| anyhow!("failed to decode public key for peer {i}: {e}"))?;
        let pk = ironguard_core::PublicKey::from_bytes(pk_bytes);

        wg.add_peer(pk.clone());

        let handle = wg
            .get_peer_handle(&pk)
            .ok_or_else(|| anyhow!("peer {i} not found after adding"))?;

        // Set endpoint if configured
        if let Some(ep_str) = &peer_cfg.endpoint {
            // Resolve endpoint (may be hostname:port)
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(MacosEndpoint::from_address(addr));
            eprintln!("  peer {i}: endpoint {addr}");
        }

        // Set allowed IPs
        for allowed_ip_str in &peer_cfg.allowed_ips {
            let (ip, masklen) = parse_cidr(allowed_ip_str)?;
            handle.add_allowed_ip(ip, masklen);
        }

        // Set preshared key if configured
        if let Some(psk) = ironguard_config::load_preshared_key(peer_cfg)
            .map_err(|e| anyhow!("failed to load preshared key for peer {i}: {e}"))?
        {
            wg.set_psk(&pk, psk);
            eprintln!("  peer {i}: preshared key loaded");
        }

        // Set persistent keepalive
        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
            eprintln!("  peer {i}: persistent keepalive {ka}s");
        }

        eprintln!(
            "  peer {i}: configured (allowed_ips: {})",
            peer_cfg.allowed_ips.join(", ")
        );
    }

    // 7. Bind UDP
    let port = iface_cfg.listen_port.unwrap_or(0);
    let (udp_readers, udp_writer, owner) =
        MacosUdp::bind(port).map_err(|e| anyhow!("failed to bind UDP socket: {e}"))?;

    wg.set_writer(udp_writer);
    for reader in udp_readers {
        wg.add_udp_reader(reader);
    }
    let actual_port = owner.port();
    eprintln!("listening on port {actual_port}");

    // 8. Add TUN readers
    for reader in tun_readers {
        wg.add_tun_reader(reader);
    }

    // 9. Bring up
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    // 10. Start timer task
    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    write_pid_file(interface)?;
    eprintln!("interface {interface} is up (mtu={mtu})");

    // 11. Wait for Ctrl+C or SIGTERM
    tokio::signal::ctrl_c().await?;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    wg.down();
    remove_pid_file(interface);
    eprintln!("interface {interface} is down");

    Ok(())
}

/// QUIC transport path for `cmd_up`.
///
/// Creates a WireGuard device parameterized over `QuicUdp` instead of `MacosUdp`,
/// connects to the QUIC relay specified in the interface config, and sets up
/// the tunnel the same way as the raw-UDP path.
#[cfg(all(target_os = "macos", feature = "quic"))]
async fn cmd_up_quic(
    iface_cfg: &ironguard_config::types::InterfaceConfig,
    tun_readers: Vec<
        <ironguard_platform::macos::tun::MacosTun as ironguard_platform::tun::Tun>::Reader,
    >,
    tun_writer: <ironguard_platform::macos::tun::MacosTun as ironguard_platform::tun::Tun>::Writer,
    sk_bytes: [u8; 32],
    interface: &str,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use ironguard_platform::endpoint::Endpoint;
    use ironguard_platform::macos::tun::MacosTun;
    use ironguard_platform::quic::{
        QuicConfig, QuicEndpoint, QuicReader, QuicTransport, QuicUdp, QuicWriter,
    };

    let quic_cfg = iface_cfg
        .quic
        .as_ref()
        .ok_or_else(|| anyhow!("transport=quic but no [quic] config section"))?;

    // Determine relay address from the first peer's endpoint.
    let relay_addr = iface_cfg
        .peers
        .first()
        .and_then(|p| p.endpoint.as_ref())
        .ok_or_else(|| anyhow!("transport=quic requires at least one peer with an endpoint"))?;
    let relay_addr = resolve_endpoint(relay_addr)?;

    eprintln!("connecting QUIC transport to {relay_addr}...");

    let transport_config = QuicConfig {
        relay_addr,
        port: quic_cfg.port,
        sni: quic_cfg.sni.clone(),
    };

    let transport = QuicTransport::connect(transport_config)
        .await
        .map_err(|e| anyhow!("failed to establish QUIC connection: {e}"))?;

    let actual_port = transport
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(quic_cfg.port);
    eprintln!("QUIC transport connected (local port {actual_port})");

    // Create WireGuard device parameterized over QUIC.
    type WgQuic = ironguard_core::device::WireGuard<MacosTun, QuicUdp>;
    let wg: WgQuic = ironguard_core::device::WireGuard::new(tun_writer);

    // Set private key.
    let sk = ironguard_core::StaticSecret::from_bytes(sk_bytes);
    wg.set_key(Some(sk));

    // Configure peers.
    for (i, peer_cfg) in iface_cfg.peers.iter().enumerate() {
        let pk_bytes = ironguard_config::decode_key(&peer_cfg.public_key)
            .map_err(|e| anyhow!("failed to decode public key for peer {i}: {e}"))?;
        let pk = ironguard_core::PublicKey::from_bytes(pk_bytes);

        wg.add_peer(pk.clone());

        let handle = wg
            .get_peer_handle(&pk)
            .ok_or_else(|| anyhow!("peer {i} not found after adding"))?;

        if let Some(ep_str) = &peer_cfg.endpoint {
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(QuicEndpoint::from_address(addr));
            eprintln!("  peer {i}: endpoint {addr} (via QUIC)");
        }

        for allowed_ip_str in &peer_cfg.allowed_ips {
            let (ip, masklen) = parse_cidr(allowed_ip_str)?;
            handle.add_allowed_ip(ip, masklen);
        }

        if let Some(psk) = ironguard_config::load_preshared_key(peer_cfg)
            .map_err(|e| anyhow!("failed to load preshared key for peer {i}: {e}"))?
        {
            wg.set_psk(&pk, psk);
            eprintln!("  peer {i}: preshared key loaded");
        }

        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
            eprintln!("  peer {i}: persistent keepalive {ka}s");
        }

        eprintln!(
            "  peer {i}: configured (allowed_ips: {})",
            peer_cfg.allowed_ips.join(", ")
        );
    }

    // Set QUIC writer and reader.
    let writer = QuicWriter::new(Arc::clone(&transport));
    let reader = QuicReader::new(Arc::clone(&transport));

    wg.set_writer(writer);
    wg.add_udp_reader(reader);

    // Add TUN readers.
    for reader in tun_readers {
        wg.add_tun_reader(reader);
    }

    // Bring up.
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    write_pid_file(interface)?;
    eprintln!("interface {interface} is up (mtu={mtu}, transport=quic)");

    tokio::signal::ctrl_c().await?;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    wg.down();
    remove_pid_file(interface);
    eprintln!("interface {interface} is down");

    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn cmd_up(interface: &str, config_path: &str, foreground: bool) -> Result<()> {
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

    let _sk = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    for (i, peer) in iface_cfg.peers.iter().enumerate() {
        if let Some(_psk) = ironguard_config::load_preshared_key(peer)
            .map_err(|e| anyhow!("failed to load preshared key for peer {i}: {e}"))?
        {
            eprintln!("  peer {i}: preshared key loaded");
        }
    }

    eprintln!("Interface {interface} configured:");
    eprintln!("  listen_port: {:?}", iface_cfg.listen_port);
    eprintln!("  peers: {}", iface_cfg.peers.len());
    eprintln!("  transport: {}", iface_cfg.transport);

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    eprintln!("Platform not yet supported -- only macOS is implemented");

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
    eprintln!("  transport: {}", ic.transport);
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

#[cfg(feature = "pq")]
fn cmd_pq_genkey() {
    use ironguard_core::handshake::pq::PqKeyPair;

    let kp = PqKeyPair::generate();
    println!("{}", hex::encode(kp.dk_bytes()));
}

#[cfg(feature = "pq")]
fn cmd_pq_pubkey() -> Result<()> {
    use ironguard_core::handshake::pq::PqKeyPair;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let hex_key = input.trim();

    let dk_bytes = hex::decode(hex_key).map_err(|e| anyhow!("invalid hex private key: {e}"))?;

    let kp = PqKeyPair::from_dk_bytes(&dk_bytes)
        .map_err(|e| anyhow!("invalid ML-KEM-768 decapsulation key: {e}"))?;

    println!("{}", hex::encode(kp.ek_bytes()));
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
// cmd_up_v2 — QUIC session-based startup path
// ---------------------------------------------------------------------------

/// V2 startup path that uses `SessionManager` for QUIC-based key exchange
/// instead of the legacy Noise handshake.
///
/// Skeleton implementation that demonstrates the integration between
/// `SessionManager`, the device, and the router. For each configured peer:
/// 1. Resolve endpoint address.
/// 2. Connect via QUIC and derive data-plane keys.
/// 3. Add the peer to the WireGuard device.
/// 4. Install the derived keypair into the router.
/// 5. Bind raw UDP for the data plane and start pipeline workers.
#[cfg(all(target_os = "macos", feature = "quic"))]
async fn cmd_up_v2(interface: &str, config_path: &str, foreground: bool) -> Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use ironguard_core::session::manager::SessionManager;
    use ironguard_core::session::quic::QuicSessionConfig;
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

    // 2. Load private key — used for static identity and legacy fallback.
    let sk_bytes = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    // 3. Create TUN device
    let (tun_readers, tun_writer, _tun_status) =
        MacosTun::create(interface).map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

    // 4. Create WireGuard device (raw UDP data plane)
    type Wg = ironguard_core::device::WireGuard<MacosTun, MacosUdp>;
    let wg: Wg = ironguard_core::device::WireGuard::new(tun_writer);

    // Set private key on the device so legacy handshake fallback works.
    let sk = ironguard_core::StaticSecret::from_bytes(sk_bytes);
    wg.set_key(Some(sk));

    // 5. Build SessionManager from QUIC config
    let quic_cfg = iface_cfg
        .quic
        .as_ref()
        .ok_or_else(|| anyhow!("up-v2 requires a [quic] config section"))?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", quic_cfg.port).parse().unwrap();
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
    };
    let mut session_mgr = SessionManager::new(session_config);

    eprintln!("session manager created (bind={})", bind_addr);

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

        // Set persistent keepalive.
        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
        }

        // Connect via QUIC session if an endpoint is configured.
        if let Some(ep_str) = &peer_cfg.endpoint {
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(MacosEndpoint::from_address(addr));

            let data_port = iface_cfg.listen_port.unwrap_or(0);
            let receiver_id: u32 = rand::random();

            match session_mgr
                .connect(pk_bytes, addr, data_port, receiver_id)
                .await
            {
                Ok(session) => {
                    eprintln!(
                        "  peer {i}: QUIC session established (epoch={}, receiver_id={})",
                        session.epoch, session.receiver_id
                    );

                    // Install the derived keys into the router as a KeyPair.
                    // This connects the session's data-plane keys to the
                    // router's encrypt/decrypt path.
                    let keypair = ironguard_core::KeyPair {
                        birth: Instant::now(),
                        initiator: true,
                        send: ironguard_core::Key {
                            key: session.keys.send_key,
                            id: session.receiver_id,
                        },
                        recv: ironguard_core::Key {
                            key: session.keys.recv_key,
                            id: receiver_id,
                        },
                    };
                    handle.add_keypair(keypair);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = i,
                        error = %e,
                        "QUIC session failed; peer will use legacy Noise handshake on first data"
                    );
                }
            }
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

    // 9. Bring up
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    // 10. Start timer task
    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    write_pid_file(interface)?;
    eprintln!(
        "interface {interface} is up (mtu={mtu}, transport=quic-session, sessions={})",
        session_mgr.session_count()
    );

    // 11. Wait for Ctrl+C or SIGTERM
    tokio::signal::ctrl_c().await?;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    wg.down();
    remove_pid_file(interface);
    eprintln!("interface {interface} is down");

    Ok(())
}

/// Linux v2 startup path — uses SessionManager for QUIC-based key exchange.
#[cfg(all(target_os = "linux", feature = "quic"))]
async fn cmd_up_v2(interface: &str, config_path: &str, foreground: bool) -> Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use ironguard_core::session::manager::SessionManager;
    use ironguard_core::session::quic::QuicSessionConfig;
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

    // 2. Load private key — used for static identity and legacy fallback.
    let sk_bytes = ironguard_config::load_private_key(iface_cfg)
        .map_err(|e| anyhow!("failed to load private key: {e}"))?;

    if !foreground {
        eprintln!("Note: daemonize not yet implemented, running in foreground");
    }

    // 3. Create TUN device
    let (tun_readers, tun_writer, _tun_status) =
        LinuxTun::create(interface).map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

    // 4. Create WireGuard device (raw UDP data plane)
    type Wg = ironguard_core::device::WireGuard<LinuxTun, LinuxUdp>;
    let wg: Wg = ironguard_core::device::WireGuard::new(tun_writer);

    // Set private key on the device so legacy handshake fallback works.
    let sk = ironguard_core::StaticSecret::from_bytes(sk_bytes);
    wg.set_key(Some(sk));

    // 5. Build SessionManager from QUIC config
    let quic_cfg = iface_cfg
        .quic
        .as_ref()
        .ok_or_else(|| anyhow!("up-v2 requires a [quic] config section"))?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", quic_cfg.port).parse().unwrap();
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
    };
    let mut session_mgr = SessionManager::new(session_config);

    eprintln!("session manager created (bind={})", bind_addr);

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

        if let Some(ka) = peer_cfg.persistent_keepalive {
            handle.opaque().set_persistent_keepalive_interval(ka);
        }

        if let Some(ep_str) = &peer_cfg.endpoint {
            let addr = resolve_endpoint(ep_str)?;
            handle.set_endpoint(LinuxEndpoint::from_address(addr));

            let data_port = iface_cfg.listen_port.unwrap_or(0);
            let receiver_id: u32 = rand::random();

            match session_mgr
                .connect(pk_bytes, addr, data_port, receiver_id)
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
                            key: session.keys.send_key,
                            id: session.receiver_id,
                        },
                        recv: ironguard_core::Key {
                            key: session.keys.recv_key,
                            id: receiver_id,
                        },
                    };
                    handle.add_keypair(keypair);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = i,
                        error = %e,
                        "QUIC session failed; peer will use legacy Noise handshake on first data"
                    );
                }
            }
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

    // 9. Bring up
    let mtu = iface_cfg.mtu.unwrap_or(1420) as usize;
    wg.up(mtu);

    // 10. Start timer task
    let stop = Arc::new(AtomicBool::new(false));
    let _timer = wg.start_timer_task(stop.clone());

    write_pid_file(interface)?;
    eprintln!(
        "interface {interface} is up (mtu={mtu}, transport=quic-session, sessions={})",
        session_mgr.session_count()
    );

    // 11. Wait for Ctrl+C or SIGTERM
    tokio::signal::ctrl_c().await?;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    wg.down();
    remove_pid_file(interface);
    eprintln!("interface {interface} is down");

    Ok(())
}

/// Fallback for unsupported platforms.
#[cfg(all(not(any(target_os = "macos", target_os = "linux")), feature = "quic"))]
async fn cmd_up_v2(_interface: &str, _config_path: &str, _foreground: bool) -> Result<()> {
    eprintln!("Platform not yet supported for up-v2");
    Ok(())
}
