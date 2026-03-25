use anyhow::Result;

use super::{config, keys, system};

/// Run the full non-interactive setup.
pub fn run_setup(sys: &system::System, iface: &str, port: u16, ip: &str) -> Result<()> {
    println!("=== IronGuard Setup ({:?}) ===", sys.os);
    println!("  interface: {iface}  port: {port}  ip: {ip}");
    println!();

    // 1. Check binary
    print!("[1/6] Checking ironguard binary... ");
    if system::ironguard_installed(sys) {
        println!("found: {}", sys.ironguard_bin());
    } else {
        println!("not found");
        system::install_binary(sys)?;
    }

    // 2. Directories
    print!("[2/6] Creating directories... ");
    system::ensure_dirs(sys)?;
    println!("done");

    // 3. Keys
    print!("[3/6] Generating server keys... ");
    let pk = keys::ensure_server_keys()?;
    println!("done");
    println!("  public key: {pk}");

    // 4. Config
    print!("[4/6] Creating config... ");
    config::ensure_server_config(iface, port)?;
    println!("{}", sys.config_file());

    // 5. Service
    print!("[5/6] Installing service... ");
    match system::install_service(sys, iface) {
        Ok(()) => println!("done"),
        Err(e) => println!("{e}"),
    }

    // 6. Firewall + forwarding
    print!("[6/6] Firewall + IP forwarding... ");
    match system::configure_firewall(sys, port) {
        Ok(msg) => println!("{msg}"),
        Err(e) => println!("{e}"),
    }
    system::enable_ip_forwarding(sys).ok();

    println!();
    println!("=== Done ===");
    println!();
    println!("Server public key: {pk}");
    println!();
    println!("Next:");
    println!("  ironguard-tui client create laptop --endpoint=vpn.example.com:{port}");
    println!("  ironguard-tui start");
    println!("  ironguard-tui status");

    Ok(())
}
