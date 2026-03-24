//! UPnP IGD port mapping for NAT traversal.
//!
//! Requests a port mapping on the gateway router via UPnP IGD,
//! enabling direct inbound connections without hole punching.
//! UPnP is available on most consumer routers but may be
//! disabled for security. Failure is expected and non-fatal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::Mutex;

/// Default lease duration requested from the gateway (seconds).
const DEFAULT_LEASE_SECS: u32 = 7200;

/// Refresh the mapping at 80% of lease to avoid expiration gaps.
const LEASE_REFRESH_RATIO: f64 = 0.8;

/// Protocol description advertised to the gateway.
const MAPPING_DESCRIPTION: &str = "IronGuard WireGuard";

/// Errors from UPnP port mapping operations.
#[derive(Debug, Error)]
pub enum PortmapError {
    /// No UPnP-capable gateway found on the network.
    #[error("no UPnP gateway found: {0}")]
    NoGateway(String),

    /// The gateway refused or failed the mapping request.
    #[error("port mapping failed: {0}")]
    MappingFailed(String),

    /// The gateway returned an unexpected response.
    #[error("unexpected gateway response: {0}")]
    UnexpectedResponse(String),
}

/// Tracks an active UPnP port mapping for periodic refresh and cleanup.
#[derive(Debug, Clone)]
struct ActiveMapping {
    /// The external address returned by the gateway.
    external_addr: SocketAddr,
    /// The internal port that was mapped.
    internal_port: u16,
    /// Lease duration granted by the gateway (seconds).
    lease_secs: u32,
}

/// Manages UPnP IGD port mappings for a single listen port.
///
/// Handles discovery, mapping, periodic refresh, and cleanup.
/// All methods are safe to call even when UPnP is unavailable --
/// errors are returned but are expected to be non-fatal in the
/// connectivity pipeline.
pub struct PortMapper {
    /// The currently active mapping, if any.
    active: Arc<Mutex<Option<ActiveMapping>>>,
    /// Handle to the background refresh task.
    refresh_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl PortMapper {
    /// Creates a new port mapper with no active mapping.
    pub fn new() -> Self {
        Self {
            active: Arc::new(Mutex::new(None)),
            refresh_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Attempts to create a UPnP IGD port mapping for the given port.
    ///
    /// Searches for a UPnP gateway on the local network and requests
    /// a UDP port mapping. Returns the external address if successful.
    ///
    /// This is expected to fail on networks without UPnP support.
    /// Callers should treat errors as informational, not critical.
    pub async fn try_upnp_mapping(&self, port: u16) -> Result<SocketAddr, PortmapError> {
        let internal_port = port;

        // Search for the gateway in a blocking task since igd-next
        // uses synchronous I/O for SSDP discovery.
        let gateway = tokio::task::spawn_blocking(|| {
            igd_next::search_gateway(igd_next::SearchOptions {
                timeout: Some(Duration::from_secs(3)),
                ..Default::default()
            })
        })
        .await
        .map_err(|e| PortmapError::NoGateway(format!("task failed: {e}")))?
        .map_err(|e| PortmapError::NoGateway(e.to_string()))?;

        tracing::debug!(
            "found UPnP gateway at {}",
            gateway.addr
        );

        // Request the port mapping
        let lease_secs = DEFAULT_LEASE_SECS;

        // igd-next wants the local LAN address. We ask the gateway to map
        // external_port -> internal_port on our LAN IP.
        let external_port = internal_port;
        let gateway_clone = gateway.clone();
        tokio::task::spawn_blocking(move || {
            // Get our local address that can reach the gateway
            let local_ip = get_local_ip_for_gateway(&gateway_clone);
            let local_addr = SocketAddr::new(local_ip, internal_port);

            gateway_clone.add_port(
                igd_next::PortMappingProtocol::UDP,
                external_port,
                local_addr,
                lease_secs,
                MAPPING_DESCRIPTION,
            )
        })
        .await
        .map_err(|e| PortmapError::MappingFailed(format!("task failed: {e}")))?
        .map_err(|e| PortmapError::MappingFailed(e.to_string()))?;

        // The external address is the gateway's external IP + the mapped port
        let external_ip = gateway
            .get_external_ip()
            .map_err(|e| {
                PortmapError::UnexpectedResponse(format!("cannot get external IP: {e}"))
            })?;
        let external_addr = SocketAddr::new(external_ip, external_port);

        tracing::info!(
            "UPnP port mapping created: external {} -> internal port {}",
            external_addr,
            internal_port
        );

        // Store the active mapping
        {
            let mut active = self.active.lock().await;
            *active = Some(ActiveMapping {
                external_addr,
                internal_port,
                lease_secs,
            });
        }

        Ok(external_addr)
    }

    /// Starts a background task that refreshes the mapping at 80% of its lease.
    ///
    /// Must be called after a successful `try_upnp_mapping()`. Does nothing
    /// if no mapping is active.
    pub async fn start_refresh_loop(&self) {
        let active = self.active.clone();

        let handle = tokio::spawn(async move {
            loop {
                let refresh_interval = {
                    let guard = active.lock().await;
                    match guard.as_ref() {
                        Some(mapping) => {
                            let secs =
                                (mapping.lease_secs as f64 * LEASE_REFRESH_RATIO) as u64;
                            Duration::from_secs(secs.max(60))
                        }
                        None => return,
                    }
                };

                tokio::time::sleep(refresh_interval).await;

                let mapping_info = {
                    let guard = active.lock().await;
                    guard.clone()
                };

                let Some(mapping) = mapping_info else {
                    return;
                };

                tracing::debug!(
                    "refreshing UPnP mapping for port {}",
                    mapping.internal_port
                );

                match refresh_mapping_once(mapping.internal_port, mapping.lease_secs).await {
                    Ok(()) => {
                        tracing::debug!("UPnP mapping refreshed successfully");
                    }
                    Err(e) => {
                        tracing::warn!("UPnP mapping refresh failed: {e}");
                        // Clear the mapping since it may have expired
                        let mut guard = active.lock().await;
                        *guard = None;
                        return;
                    }
                }
            }
        });

        let mut refresh = self.refresh_handle.lock().await;
        if let Some(old_handle) = refresh.take() {
            old_handle.abort();
        }
        *refresh = Some(handle);
    }

    /// Removes the active port mapping from the gateway.
    ///
    /// Should be called on shutdown to clean up. Errors are logged
    /// but not propagated since cleanup failure is non-critical.
    pub async fn remove_mapping(&self) {
        // Stop the refresh loop
        {
            let mut refresh = self.refresh_handle.lock().await;
            if let Some(handle) = refresh.take() {
                handle.abort();
            }
        }

        let mapping = {
            let mut active = self.active.lock().await;
            active.take()
        };

        let Some(mapping) = mapping else {
            return;
        };

        tracing::debug!(
            "removing UPnP mapping for port {}",
            mapping.internal_port
        );

        let port = mapping.internal_port;
        let result = tokio::task::spawn_blocking(move || {
            let gateway = igd_next::search_gateway(igd_next::SearchOptions {
                timeout: Some(Duration::from_secs(2)),
                ..Default::default()
            })?;

            gateway.remove_port(igd_next::PortMappingProtocol::UDP, port)?;
            Ok::<(), igd_next::Error>(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                tracing::info!("UPnP mapping removed for port {port}");
            }
            Ok(Err(e)) => {
                tracing::debug!("UPnP mapping removal failed (non-critical): {e}");
            }
            Err(e) => {
                tracing::debug!("UPnP removal task failed: {e}");
            }
        }
    }

    /// Returns the current external address if a mapping is active.
    pub async fn external_addr(&self) -> Option<SocketAddr> {
        let active = self.active.lock().await;
        active.as_ref().map(|m| m.external_addr)
    }
}

impl Default for PortMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Refreshes an existing UPnP mapping by re-adding it with a fresh lease.
async fn refresh_mapping_once(port: u16, lease_secs: u32) -> Result<(), PortmapError> {
    tokio::task::spawn_blocking(move || {
        let gateway = igd_next::search_gateway(igd_next::SearchOptions {
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        })
        .map_err(|e| PortmapError::NoGateway(e.to_string()))?;

        let local_ip = get_local_ip_for_gateway(&gateway);
        let local_addr = SocketAddr::new(local_ip, port);

        gateway
            .add_port(
                igd_next::PortMappingProtocol::UDP,
                port,
                local_addr,
                lease_secs,
                MAPPING_DESCRIPTION,
            )
            .map_err(|e| PortmapError::MappingFailed(e.to_string()))
    })
    .await
    .map_err(|e| PortmapError::MappingFailed(format!("task failed: {e}")))?
}

/// Determines the local IP address on the same network as the UPnP gateway.
///
/// Connects a UDP socket to the gateway address and reads back the
/// local address the OS chose. This gives us the correct LAN IP
/// without parsing interface tables.
fn get_local_ip_for_gateway(gateway: &igd_next::Gateway) -> std::net::IpAddr {
    let gateway_addr = gateway.addr.ip();
    let target = SocketAddr::new(gateway_addr, 1); // port doesn't matter for connect()

    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect(target).is_ok() {
            if let Ok(local) = sock.local_addr() {
                return local.ip();
            }
        }
    }

    // Fallback: use 0.0.0.0 and let the gateway figure it out
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portmapper_default() {
        let mapper = PortMapper::default();
        // No active mapping initially
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(mapper.external_addr());
        assert!(addr.is_none());
    }

    #[test]
    fn test_lease_refresh_ratio() {
        // 80% of 7200 = 5760 seconds
        let refresh_secs = (DEFAULT_LEASE_SECS as f64 * LEASE_REFRESH_RATIO) as u64;
        assert_eq!(refresh_secs, 5760);
    }

    #[test]
    fn test_lease_defaults() {
        assert_eq!(DEFAULT_LEASE_SECS, 7200);
        assert!(LEASE_REFRESH_RATIO > 0.5);
        assert!(LEASE_REFRESH_RATIO < 1.0);
    }

    #[tokio::test]
    async fn test_remove_mapping_no_active() {
        // Removing a mapping when none is active should be a no-op
        let mapper = PortMapper::new();
        mapper.remove_mapping().await;
        assert!(mapper.external_addr().await.is_none());
    }

    #[test]
    fn test_active_mapping_clone() {
        let mapping = ActiveMapping {
            external_addr: "1.2.3.4:51820".parse().unwrap(),
            internal_port: 51820,
            lease_secs: 7200,
        };
        let cloned = mapping.clone();
        assert_eq!(cloned.external_addr, mapping.external_addr);
        assert_eq!(cloned.internal_port, mapping.internal_port);
        assert_eq!(cloned.lease_secs, mapping.lease_secs);
    }

    // Network-dependent test: requires a UPnP gateway on the LAN.
    #[tokio::test]
    #[ignore]
    async fn test_upnp_mapping_real_gateway() {
        let mapper = PortMapper::new();
        match mapper.try_upnp_mapping(51820).await {
            Ok(addr) => {
                tracing::info!("UPnP mapping created: {addr}");
                assert!(!addr.ip().is_unspecified());
                mapper.remove_mapping().await;
            }
            Err(e) => {
                tracing::warn!("UPnP not available (expected): {e}");
            }
        }
    }
}
