//! Integration test: config parsing -> core device setup
//!
//! Exercises the full pipeline from a wg.json config file to creating
//! and configuring a WireGuard device with dummy backends.

use std::collections::HashMap;
use std::net::IpAddr;

use ironguard_config::types::{Config, InterfaceConfig, PeerConfig, PostQuantumMode};
use ironguard_config::{load_preshared_key, load_private_key, validate};
use ironguard_core::PublicKey;
use ironguard_platform::dummy::tun as dummy_tun;
use ironguard_platform::dummy::tun::DummyTun;
use ironguard_platform::dummy::udp::DummyUdp;

type TestWireGuard = ironguard_core::device::WireGuard<DummyTun, DummyUdp>;

/// Build a Config with two peers, write keys to temp files, and verify
/// the full config -> device setup pipeline.
#[test]
fn test_config_to_device_setup() {
    let dir = tempfile::tempdir().unwrap();

    // Generate keys
    let sk_bytes: [u8; 32] = rand::random();
    let sk_path = dir.path().join("wg0.key");
    std::fs::write(&sk_path, hex::encode(sk_bytes)).unwrap();

    // Derive peer public keys using x25519
    let peer_sk_a: [u8; 32] = rand::random();
    let dalek_sk_a = x25519_dalek::StaticSecret::from(peer_sk_a);
    let dalek_pk_a = x25519_dalek::PublicKey::from(&dalek_sk_a);
    let pk_a_hex = hex::encode(dalek_pk_a.as_bytes());

    let peer_sk_b: [u8; 32] = rand::random();
    let dalek_sk_b = x25519_dalek::StaticSecret::from(peer_sk_b);
    let dalek_pk_b = x25519_dalek::PublicKey::from(&dalek_sk_b);
    let pk_b_hex = hex::encode(dalek_pk_b.as_bytes());

    // Write a preshared key for peer A
    let psk_bytes: [u8; 32] = rand::random();
    let psk_path = dir.path().join("peer_a.psk");
    std::fs::write(&psk_path, hex::encode(psk_bytes)).unwrap();

    // Build config
    let mut interfaces = HashMap::new();
    interfaces.insert(
        "wg0".to_string(),
        InterfaceConfig {
            private_key_file: Some(sk_path.to_str().unwrap().to_string()),
            private_key_env: None,
            listen_port: Some(51820),
            address: vec!["10.0.0.1/24".to_string()],
            dns: vec![],
            mtu: Some(1420),
            fwmark: None,
            transport: "udp".to_string(),
            quic: None,
            post_quantum: PostQuantumMode::default(),
            mesh: None,
            peers: vec![
                PeerConfig {
                    public_key: pk_a_hex.clone(),
                    preshared_key_file: Some(psk_path.to_str().unwrap().to_string()),
                    endpoint: Some("192.168.1.100:51820".to_string()),
                    allowed_ips: vec!["10.0.0.2/32".to_string()],
                    persistent_keepalive: Some(25),
                    comment: Some("Peer A".to_string()),
                    pq_public_key: None,
                    quic_port: None,
                    role: None,
                    relay_for: Vec::new(),
                },
                PeerConfig {
                    public_key: pk_b_hex.clone(),
                    preshared_key_file: None,
                    endpoint: Some("192.168.1.200:51820".to_string()),
                    allowed_ips: vec!["10.0.0.3/32".to_string(), "fd00::3/128".to_string()],
                    persistent_keepalive: None,
                    comment: None,
                    pq_public_key: None,
                    quic_port: None,
                    role: None,
                    relay_for: Vec::new(),
                },
            ],
        },
    );

    let config = Config {
        schema: Some("ironguard/v1".to_string()),
        interfaces,
    };

    // 1. Validate config
    let warnings = validate(&config).unwrap();
    assert!(
        warnings.is_empty(),
        "config should be valid, got warnings: {warnings:?}"
    );

    // 2. Serialize to JSON and re-parse (roundtrip)
    let json = serde_json::to_string_pretty(&config).unwrap();
    let reparsed: Config = serde_json::from_str(&json).unwrap();
    let iface = reparsed.interfaces.get("wg0").unwrap();

    // 3. Load private key
    let loaded_sk = load_private_key(iface).unwrap();
    assert_eq!(loaded_sk, sk_bytes);

    // 4. Load preshared key for peer A
    let loaded_psk = load_preshared_key(&iface.peers[0]).unwrap();
    assert_eq!(loaded_psk, Some(psk_bytes));

    // 5. No preshared key for peer B
    let no_psk = load_preshared_key(&iface.peers[1]).unwrap();
    assert_eq!(no_psk, None);

    // 6. Create a WireGuard device with dummy backends
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let wg: TestWireGuard = ironguard_core::device::WireGuard::new(tun_writer);

    // v2: no static key or PSK at device level -- key material is
    // exchanged via QUIC sessions and installed as keypairs directly.
    // We still verify that the loaded key bytes are correct (step 3 above).

    // 7. Add peers from config
    for peer_cfg in &iface.peers {
        let pk_bytes = hex::decode(&peer_cfg.public_key).unwrap();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let pk = PublicKey::from_bytes(pk_arr);

        assert!(wg.add_peer(pk.clone()), "should add peer successfully");

        // v2: PSK is exchanged during QUIC session setup, not set
        // directly on the device. Verify loading still works.
        let _psk = load_preshared_key(peer_cfg).unwrap();

        // Add allowed IPs
        let handle = wg.get_peer_handle(&pk).unwrap();
        for allowed_ip in &peer_cfg.allowed_ips {
            if let Some((addr, prefix)) = parse_cidr(allowed_ip) {
                handle.add_allowed_ip(addr, prefix);
            }
        }
    }

    // 9. Verify peers were added
    let pk_a_bytes = hex::decode(&pk_a_hex).unwrap();
    let mut pk_a_arr = [0u8; 32];
    pk_a_arr.copy_from_slice(&pk_a_bytes);
    let pk_a = PublicKey::from_bytes(pk_a_arr);
    assert!(
        wg.get_peer_handle(&pk_a).is_some(),
        "peer A should be registered"
    );

    let pk_b_bytes = hex::decode(&pk_b_hex).unwrap();
    let mut pk_b_arr = [0u8; 32];
    pk_b_arr.copy_from_slice(&pk_b_bytes);
    let pk_b = PublicKey::from_bytes(pk_b_arr);
    assert!(
        wg.get_peer_handle(&pk_b).is_some(),
        "peer B should be registered"
    );

    // 10. Bring device up and verify MTU
    let mtu = iface.mtu.unwrap_or(1500) as usize;
    wg.up(mtu);
    assert_eq!(
        wg.mtu.load(std::sync::atomic::Ordering::Relaxed),
        mtu,
        "MTU should match config"
    );

    // Cleanup
    wg.down();
}

/// Parse a CIDR string like "10.0.0.0/24" into (IpAddr, prefix_len).
fn parse_cidr(s: &str) -> Option<(IpAddr, u32)> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    let addr: IpAddr = addr_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    Some((addr, prefix))
}

/// Test that .conf import -> wg.json -> device setup works end-to-end.
#[test]
fn test_conf_import_to_device() {
    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("wg0.conf");

    let sk_bytes: [u8; 32] = rand::random();
    let sk_b64 = ironguard_config::keys::base64_encode(&sk_bytes);

    let peer_sk: [u8; 32] = rand::random();
    let dalek_sk = x25519_dalek::StaticSecret::from(peer_sk);
    let dalek_pk = x25519_dalek::PublicKey::from(&dalek_sk);
    let pk_b64 = ironguard_config::keys::base64_encode(dalek_pk.as_bytes());

    let conf_content = format!(
        "[Interface]\n\
         PrivateKey = {sk_b64}\n\
         ListenPort = 51821\n\
         Address = 10.0.0.1/24\n\
         \n\
         [Peer]\n\
         PublicKey = {pk_b64}\n\
         AllowedIPs = 10.0.0.2/32\n\
         Endpoint = 1.2.3.4:51821\n"
    );

    std::fs::write(&conf_path, &conf_content).unwrap();

    // Import .conf
    let config = ironguard_config::import_conf(conf_path.to_str().unwrap()).unwrap();
    let iface = config.interfaces.get("wg0").unwrap();

    assert_eq!(iface.listen_port, Some(51821));
    assert_eq!(iface.peers.len(), 1);

    // Load key and create device
    let loaded_sk = load_private_key(iface).unwrap();
    assert_eq!(loaded_sk, sk_bytes);

    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let wg: TestWireGuard = ironguard_core::device::WireGuard::new(tun_writer);

    // v2: no static key at device level -- key material is exchanged
    // via QUIC sessions. We verified loaded_sk matches above.

    // Add peer
    let pk_bytes = hex::decode(&iface.peers[0].public_key).unwrap();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let pk = PublicKey::from_bytes(pk_arr);
    assert!(wg.add_peer(pk.clone()));
    assert!(wg.get_peer_handle(&pk).is_some());

    wg.down();
}
