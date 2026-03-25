use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use super::keys;
use super::system::System;

// ── Data types returned to callers ───────────────────────────────────────────

pub struct ServerConfig {
    pub interface: String,
    pub port: u16,
}

pub struct PeerInfo {
    pub public_key: String,
    pub allowed_ips: String,
    pub comment: String,
    pub keepalive: String,
}

pub struct ClientInfo {
    pub name: String,
    pub ip: String,
    pub public_key: String,
    pub config_dir: String,
    pub created: String,
}

// ── Config reading ───────────────────────────────────────────────────────────

fn sys() -> System {
    System::detect()
}

fn read_config() -> Result<Value> {
    let path = sys().config_file();
    let data = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("Cannot read {path}. Run setup first."))?;
    let v: Value = serde_json::from_str(&data)?;
    Ok(v)
}

fn write_config(v: &Value) -> Result<()> {
    let path = sys().config_file();
    let data = serde_json::to_string_pretty(v)?;
    std::fs::write(&path, data)?;
    Ok(())
}

fn first_interface(v: &Value) -> Result<(String, &Value)> {
    let ifaces = v
        .get("interfaces")
        .and_then(|i| i.as_object())
        .ok_or_else(|| anyhow!("No interfaces in config"))?;
    let (name, val) = ifaces
        .iter()
        .next()
        .ok_or_else(|| anyhow!("Empty interfaces"))?;
    Ok((name.clone(), val))
}

fn first_interface_mut(v: &mut Value) -> Result<(String, &mut Value)> {
    let ifaces = v
        .get_mut("interfaces")
        .and_then(|i| i.as_object_mut())
        .ok_or_else(|| anyhow!("No interfaces in config"))?;
    let name = ifaces
        .keys()
        .next()
        .ok_or_else(|| anyhow!("Empty interfaces"))?
        .clone();
    let val = ifaces.get_mut(&name).unwrap();
    Ok((name, val))
}

// ── Public API ───────────────────────────────────────────────────────────────

pub fn load_server_config() -> Result<ServerConfig> {
    let v = read_config()?;
    let (name, iface) = first_interface(&v)?;
    let port = iface
        .get("listen_port")
        .and_then(|p| p.as_u64())
        .unwrap_or(51820) as u16;
    Ok(ServerConfig {
        interface: name,
        port,
    })
}

pub fn list_peers() -> Result<Vec<PeerInfo>> {
    let v = read_config()?;
    let (_, iface) = first_interface(&v)?;
    let peers = iface
        .get("peers")
        .and_then(|p| p.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    let result = peers
        .iter()
        .filter(|p| {
            p.get("public_key")
                .and_then(|k| k.as_str())
                .is_some_and(|k| k != "REPLACE_WITH_CLIENT_PUBLIC_KEY")
        })
        .map(|p| PeerInfo {
            public_key: p
                .get("public_key")
                .and_then(|k| k.as_str())
                .unwrap_or("?")
                .to_owned(),
            allowed_ips: p
                .get("allowed_ips")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
            comment: p
                .get("_comment")
                .and_then(|c| c.as_str())
                .unwrap_or("-")
                .to_owned(),
            keepalive: p
                .get("persistent_keepalive")
                .and_then(|k| k.as_u64())
                .map(|k| format!("{k}s"))
                .unwrap_or_else(|| "-".into()),
        })
        .collect();

    Ok(result)
}

pub fn ensure_server_config(iface: &str, port: u16) -> Result<()> {
    let s = sys();
    let path = s.config_file();
    if std::path::Path::new(&path).exists() {
        return Ok(());
    }

    let key_path = format!("{}/server.key", s.key_dir());
    let config = json!({
        "$schema": "ironguard/v1",
        "interfaces": {
            iface: {
                "private_key_file": key_path,
                "listen_port": port,
                "mtu": 1420,
                "transport": "udp",
                "peers": []
            }
        }
    });

    let data = serde_json::to_string_pretty(&config)?;
    std::fs::write(&path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn create_client(name: &str, endpoint: Option<&str>) -> Result<ClientInfo> {
    let s = sys();
    let client_dir = format!("{}/{name}", s.client_dir());

    if std::path::Path::new(&client_dir).exists() {
        return Err(anyhow!("Client '{name}' already exists"));
    }

    std::fs::create_dir_all(&client_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // generate client keys
    let (private_hex, public_hex) = keys::generate_client_keys();
    std::fs::write(format!("{client_dir}/private.key"), &private_hex)?;
    std::fs::write(format!("{client_dir}/public.key"), &public_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            format!("{client_dir}/private.key"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }

    // determine client IP
    let client_ip = next_client_ip()?;

    // get server info
    let server_pk = keys::server_public_key().unwrap_or_else(|_| "SERVER_KEY".into());
    let server_port = load_server_config().map(|c| c.port).unwrap_or(51820);

    let default_ep = format!("YOUR_SERVER:{server_port}");
    let ep = endpoint.unwrap_or(&default_ep);
    let client_iface = if cfg!(target_os = "macos") {
        "utun10"
    } else {
        "wg-client"
    };

    // write client config
    let client_config = json!({
        "$schema": "ironguard/v1",
        "interfaces": {
            client_iface: {
                "private_key_file": "./private.key",
                "listen_port": 0,
                "mtu": 1420,
                "transport": "udp",
                "peers": [{
                    "public_key": server_pk,
                    "endpoint": ep,
                    "allowed_ips": ["10.0.0.0/24"],
                    "persistent_keepalive": 25,
                    "_comment": "IronGuard server"
                }]
            }
        }
    });
    std::fs::write(
        format!("{client_dir}/wg.json"),
        serde_json::to_string_pretty(&client_config)?,
    )?;

    // write info.json
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let info = json!({
        "name": name,
        "ip": client_ip,
        "public_key": public_hex,
        "created": now
    });
    std::fs::write(
        format!("{client_dir}/info.json"),
        serde_json::to_string_pretty(&info)?,
    )?;

    // add peer to server config
    add_peer_to_server(&public_hex, &client_ip, name)?;

    Ok(ClientInfo {
        name: name.to_owned(),
        ip: client_ip,
        public_key: public_hex,
        config_dir: client_dir,
        created: now,
    })
}

pub fn list_clients() -> Result<Vec<ClientInfo>> {
    let s = sys();
    let dir = s.client_dir();
    let mut clients = Vec::new();

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(clients),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let info_path = entry.path().join("info.json");
        if let Ok(data) = std::fs::read_to_string(&info_path) {
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                clients.push(ClientInfo {
                    name: v["name"].as_str().unwrap_or("?").to_owned(),
                    ip: v["ip"].as_str().unwrap_or("?").to_owned(),
                    public_key: v["public_key"].as_str().unwrap_or("?").to_owned(),
                    config_dir: entry.path().to_string_lossy().into_owned(),
                    created: v["created"].as_str().unwrap_or("?").to_owned(),
                });
            }
        }
    }

    Ok(clients)
}

pub fn show_client(name: &str) -> Result<ClientInfo> {
    let s = sys();
    let dir = format!("{}/{name}", s.client_dir());
    let info_path = format!("{dir}/info.json");
    let data =
        std::fs::read_to_string(&info_path).map_err(|_| anyhow!("Client '{name}' not found"))?;
    let v: Value = serde_json::from_str(&data)?;
    Ok(ClientInfo {
        name: v["name"].as_str().unwrap_or("?").to_owned(),
        ip: v["ip"].as_str().unwrap_or("?").to_owned(),
        public_key: v["public_key"].as_str().unwrap_or("?").to_owned(),
        config_dir: dir,
        created: v["created"].as_str().unwrap_or("?").to_owned(),
    })
}

pub fn remove_client(name: &str) -> Result<()> {
    let s = sys();
    let dir = format!("{}/{name}", s.client_dir());

    // read client public key
    let pk_path = format!("{dir}/public.key");
    let pk = std::fs::read_to_string(&pk_path).ok();

    // remove peer from server config
    if let Some(ref pk) = pk {
        remove_peer_from_server(pk.trim())?;
    }

    // remove client directory
    std::fs::remove_dir_all(&dir).map_err(|_| anyhow!("Client '{name}' not found"))?;
    Ok(())
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn next_client_ip() -> Result<String> {
    let peers = list_peers().unwrap_or_default();
    let n = peers.len() + 2; // server is .1, first client is .2
    Ok(format!("10.0.0.{n}"))
}

fn add_peer_to_server(public_key: &str, ip: &str, comment: &str) -> Result<()> {
    let mut v = read_config()?;
    let (_, iface) = first_interface_mut(&mut v)?;

    let peers = iface
        .get_mut("peers")
        .and_then(|p| p.as_array_mut())
        .ok_or_else(|| anyhow!("No peers array"))?;

    // remove placeholder
    peers.retain(|p| {
        p.get("public_key")
            .and_then(|k| k.as_str())
            .is_some_and(|k| k != "REPLACE_WITH_CLIENT_PUBLIC_KEY")
    });

    peers.push(json!({
        "public_key": public_key,
        "allowed_ips": [format!("{ip}/32")],
        "persistent_keepalive": 25,
        "_comment": comment
    }));

    write_config(&v)
}

fn remove_peer_from_server(public_key: &str) -> Result<()> {
    let mut v = read_config()?;
    let (_, iface) = first_interface_mut(&mut v)?;

    if let Some(peers) = iface.get_mut("peers").and_then(|p| p.as_array_mut()) {
        peers.retain(|p| {
            p.get("public_key")
                .and_then(|k| k.as_str())
                .is_some_and(|k| k != public_key)
        });
    }

    write_config(&v)
}
