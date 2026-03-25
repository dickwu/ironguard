mod actions;
mod app;
mod event;
mod tui;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ironguard-tui", about = "IronGuard WireGuard manager")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initial server setup (install, keys, config, service)
    Setup {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value = "51820")]
        port: u16,
        #[arg(long, default_value = "10.0.0.1")]
        ip: String,
    },
    /// Start the server
    Start,
    /// Stop the server
    Stop,
    /// Restart the server
    Restart,
    /// Show server status
    Status,
    /// Tail server logs
    Logs,
    /// Print server public key
    ServerKey,
    /// List configured peers
    Peers,
    /// Client management
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    /// Create a new client
    Create {
        name: String,
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// List all clients
    List,
    /// Show client details
    Show { name: String },
    /// Remove a client
    Remove { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => tui::run(),
        Some(cmd) => run_command(cmd),
    }
}

fn run_command(cmd: Commands) -> Result<()> {
    let sys = actions::system::System::detect();

    match cmd {
        Commands::Setup {
            interface,
            port,
            ip,
        } => {
            let iface = interface.unwrap_or_else(|| sys.default_interface().to_owned());
            actions::setup::run_setup(&sys, &iface, port, &ip)?;
        }
        Commands::Start => {
            let cfg = actions::config::load_server_config()?;
            actions::server::start(&sys, &cfg.interface)?;
        }
        Commands::Stop => {
            let cfg = actions::config::load_server_config()?;
            actions::server::stop(&sys, &cfg.interface)?;
        }
        Commands::Restart => {
            let cfg = actions::config::load_server_config()?;
            actions::server::stop(&sys, &cfg.interface)?;
            std::thread::sleep(std::time::Duration::from_secs(1));
            actions::server::start(&sys, &cfg.interface)?;
        }
        Commands::Status => {
            let info = actions::server::status(&sys)?;
            println!("{info}");
        }
        Commands::Logs => {
            actions::server::tail_logs(&sys)?;
        }
        Commands::ServerKey => {
            let pk = actions::keys::server_public_key()?;
            println!("{pk}");
        }
        Commands::Peers => {
            let peers = actions::config::list_peers()?;
            if peers.is_empty() {
                println!("No peers configured.");
            } else {
                println!("{:<15} {:<18} {:<44}", "NAME", "ALLOWED IPS", "PUBLIC KEY");
                println!("{:<15} {:<18} {:<44}", "----", "-----------", "----------");
                for p in &peers {
                    println!(
                        "{:<15} {:<18} {:<44}",
                        p.comment, p.allowed_ips, p.public_key
                    );
                }
            }
        }
        Commands::Client { action } => match action {
            ClientAction::Create { name, endpoint } => {
                let info = actions::config::create_client(&name, endpoint.as_deref())?;
                println!("Client created: {}", info.name);
                println!("  IP:         {}", info.ip);
                println!("  Public key: {}", info.public_key);
                println!("  Config:     {}", info.config_dir);
            }
            ClientAction::List => {
                let clients = actions::config::list_clients()?;
                if clients.is_empty() {
                    println!("No clients.");
                } else {
                    println!("{:<15} {:<15} {:<44}", "NAME", "IP", "PUBLIC KEY");
                    println!("{:<15} {:<15} {:<44}", "----", "--", "----------");
                    for c in &clients {
                        println!("{:<15} {:<15} {:<44}", c.name, c.ip, c.public_key);
                    }
                }
            }
            ClientAction::Show { name } => {
                let info = actions::config::show_client(&name)?;
                println!("Client: {}", info.name);
                println!("  IP:         {}", info.ip);
                println!("  Public key: {}", info.public_key);
                println!("  Created:    {}", info.created);
                println!("  Config:     {}", info.config_dir);
            }
            ClientAction::Remove { name } => {
                actions::config::remove_client(&name)?;
                println!("Removed: {name}");
            }
        },
    }
    Ok(())
}
