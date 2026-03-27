pub mod conf;
pub mod keys;
pub mod types;
pub mod validate;

pub use conf::{export_conf, import_conf};
pub use keys::{decode_key, load_preshared_key, load_private_key};
pub use types::{Config, Masquerade};
pub use validate::validate;

#[cfg(test)]
mod tests {
    use super::types::*;

    #[test]
    fn test_config_roundtrip() {
        let json = r#"{
            "$schema": "ironguard/v1",
            "interfaces": {
                "wg0": {
                    "private_key_file": "/etc/ironguard/keys/wg0.key",
                    "listen_port": 51820,
                    "address": ["10.0.0.1/24"],
                    "transport": "udp",
                    "peers": [
                        {
                            "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                            "endpoint": "vpn.example.com:51820",
                            "allowed_ips": ["10.0.0.2/32"],
                            "persistent_keepalive": 25,
                            "_comment": "Office server"
                        }
                    ]
                }
            }
        }"#;

        let config: Config = serde_json::from_str(json).expect("parse failed");
        assert_eq!(config.interfaces.len(), 1);

        let wg0 = config.interfaces.get("wg0").expect("wg0 missing");
        assert_eq!(wg0.listen_port, Some(51820));
        assert_eq!(wg0.peers.len(), 1);
        assert_eq!(wg0.peers[0].comment.as_deref(), Some("Office server"));

        let serialized = serde_json::to_string_pretty(&config).expect("serialize failed");
        let reparsed: Config = serde_json::from_str(&serialized).expect("reparse failed");
        assert_eq!(reparsed.interfaces.len(), 1);
    }
}
