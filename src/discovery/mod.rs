//! ONVIF WS-Discovery implementation for finding IP cameras on the network.
//!
//! This module provides functionality to discover ONVIF-compliant devices using the
//! WS-Discovery protocol. It supports both fast discovery (WS-Discovery multicast only)
//! and detailed device interrogation (full ONVIF device inspection).
//!
//! # Quick Start
//!
//! ```no_run
//! use retina::discovery;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Fast discovery - just find devices on current subnet
//!     let results = discovery::discover_devices().await?;
//!
//!     for device in &results.devices {
//!         println!("Found: {} {} at {}",
//!             device.manufacturer, device.model, device.ip_address);
//!     }
//!
//!     // Detailed interrogation of a specific device
//!     if let Some(device) = results.devices.first() {
//!         let credentials = discovery::Credentials {
//!             username: "admin".to_string(),
//!             password: "password".to_string(),
//!         };
//!
//!         let details = discovery::interrogate_device(device, Some(&credentials)).await?;
//!
//!         for stream in &details.streams {
//!             println!("Stream: {} - {}", stream.name, stream.rtsp_url);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Multi-Subnet Discovery
//!
//! Standard multicast discovery only works within the local subnet. If your cameras
//! are on different network segments (e.g., 192.168.1.x vs 192.168.3.x), use these options:
//!
//! ```no_run
//! use retina::discovery;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Option 1: Extended discovery (tries common subnets automatically)
//!     let results = discovery::discover_devices_extended().await?;
//!
//!     // Option 2: Specific subnet discovery
//!     let results = discovery::discover_devices_on_subnet("192.168.3.0/24").await?;
//!
//!     // Option 3: Multiple specific subnets
//!     let results = discovery::discover_devices_multi_subnet(vec![
//!         "192.168.1.0/24".to_string(),
//!         "192.168.3.0/24".to_string(),
//!         "10.0.1.0/24".to_string(),
//!     ]).await?;
//!
//!     println!("Found {} cameras across all subnets", results.devices.len());
//!     Ok(())
//! }
//! ```
//!
//! # Two-Phase Discovery
//!
//! This module implements a two-phase discovery approach:
//!
//! 1. **Fast Discovery**: Uses WS-Discovery UDP multicast to quickly find all ONVIF
//!    devices on the network. Returns basic device information.
//!
//! 2. **Device Interrogation**: Connects to specific devices using ONVIF SOAP calls
//!    to get detailed information including RTSP stream URLs.
//!
//! This approach provides a responsive user experience where devices are found quickly,
//! and detailed information is retrieved on-demand.
//!
//! # Network Configuration Notes
//!
//! - **Same subnet**: Use `discover_devices()` for fastest results
//! - **Multiple subnets**: Use `discover_devices_extended()` or specify subnets manually
//! - **Router limitations**: Some routers block multicast between VLANs
//! - **Firewall**: Ensure UDP port 3702 is not blocked
//! - **Performance**: Multi-subnet discovery takes longer due to additional probes

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use serde::Serialize;
use thiserror::Error;

mod device;
mod interrogate;
mod probe;
mod soap;

pub use device::*;
pub use interrogate::*;
pub use probe::*;

/// Default timeout for WS-Discovery probe
pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// WS-Discovery multicast address
pub const WS_DISCOVERY_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// WS-Discovery port
pub const WS_DISCOVERY_PORT: u16 = 3702;

/// Maximum number of devices to return from discovery
pub const MAX_DISCOVERY_RESULTS: usize = 100;

/// Results from a WS-Discovery scan
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryResults {
    /// Discovered devices
    pub devices: Vec<DiscoveredDevice>,

    /// Duration of the discovery scan
    pub scan_duration: Duration,

    /// Non-fatal errors encountered during discovery
    pub errors: Vec<String>,

    /// Number of probe responses received (including duplicates/invalid)
    pub responses_received: usize,
}

/// A device discovered via WS-Discovery
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredDevice {
    /// Unique device identifier
    pub uuid: String,

    /// Device name (often generic like "IPCamera")
    pub name: String,

    /// Manufacturer name extracted from device response
    pub manufacturer: String,

    /// Device model extracted from hardware info
    pub model: String,

    /// IP address of the device
    pub ip_address: IpAddr,

    /// MAC address if available
    pub mac_address: Option<String>,

    /// ONVIF device service URL
    pub device_service_url: String,

    /// Hardware information string
    pub hardware_info: String,

    /// Device location if specified
    pub location: Option<String>,

    /// Device types (e.g., "dn:NetworkVideoTransmitter")
    pub types: Vec<String>,

    /// ONVIF scopes
    pub scopes: Vec<String>,

    /// Metadata version
    pub metadata_version: u32,

    /// When this device was discovered (milliseconds since UNIX epoch)
    pub discovered_at: u64,

    /// Response time from probe to response (milliseconds)
    pub response_time: u64,
}

/// Credentials for device authentication
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Options for discovery behavior
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Timeout for discovery scan
    pub timeout: Duration,

    /// Specific network interfaces to scan (empty = all)
    pub interfaces: Vec<String>,

    /// Include IPv6 discovery
    pub include_ipv6: bool,

    /// Maximum number of results to return
    pub max_results: usize,

    /// Additional subnets to probe directly (for cross-subnet discovery)
    /// Example: vec!["192.168.3.0/24", "10.0.1.0/24"]
    pub additional_subnets: Vec<String>,

    /// Use directed broadcast in addition to multicast
    /// Helps with some network configurations
    pub use_broadcast: bool,

    /// Custom multicast TTL (default: 2 for local network)
    pub multicast_ttl: u32,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_DISCOVERY_TIMEOUT,
            interfaces: Vec::new(),
            include_ipv6: false,
            max_results: MAX_DISCOVERY_RESULTS,
            additional_subnets: Vec::new(),
            use_broadcast: false,
            multicast_ttl: 2,
        }
    }
}

/// Errors that can occur during discovery
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    XmlParsing(String),

    #[error("Invalid device response: {0}")]
    InvalidResponse(String),

    #[error("Discovery timeout")]
    Timeout,

    #[error("No network interfaces available")]
    NoInterfaces,
}

/// Discover ONVIF devices on the network using default options
///
/// This performs a fast WS-Discovery scan and returns basic device information.
/// Use `interrogate_device()` to get detailed information including RTSP URLs.
pub async fn discover_devices() -> Result<DiscoveryResults, DiscoveryError> {
    discover_with_options(DiscoveryOptions::default()).await
}

/// Discover ONVIF devices with custom timeout
pub async fn discover_devices_timeout(
    timeout: Duration,
) -> Result<DiscoveryResults, DiscoveryError> {
    discover_with_options(DiscoveryOptions {
        timeout,
        ..Default::default()
    })
    .await
}

/// Discover ONVIF devices across multiple subnets
///
/// This is useful when cameras are on different network segments.
/// Example: discover_devices_multi_subnet(vec!["192.168.1.0/24", "192.168.3.0/24"]).await
pub async fn discover_devices_multi_subnet(
    subnets: Vec<String>,
) -> Result<DiscoveryResults, DiscoveryError> {
    discover_with_options(DiscoveryOptions {
        additional_subnets: subnets,
        use_broadcast: true,
        multicast_ttl: 3,
        ..Default::default()
    })
    .await
}

/// Discover ONVIF devices using common subnet patterns
///
/// This helper automatically tries multiple common network configurations:
/// - Standard multicast discovery
/// - Broadcast discovery
/// - Common private subnets (192.168.x.x, 10.x.x.x)
pub async fn discover_devices_extended() -> Result<DiscoveryResults, DiscoveryError> {
    let common_subnets = vec![
        "192.168.1.0/24".to_string(),
        "192.168.2.0/24".to_string(),
        "192.168.3.0/24".to_string(),
        "192.168.0.0/24".to_string(),
        "10.0.0.0/24".to_string(),
        "10.0.1.0/24".to_string(),
    ];

    discover_with_options(DiscoveryOptions {
        timeout: Duration::from_secs(8), // Longer timeout for multiple subnets
        additional_subnets: common_subnets,
        use_broadcast: true,
        multicast_ttl: 3,
        ..Default::default()
    })
    .await
}

/// Discover ONVIF devices on a specific subnet
///
/// Convenience function for single subnet discovery.
/// Example: discover_devices_on_subnet("192.168.3.0/24").await
pub async fn discover_devices_on_subnet(subnet: &str) -> Result<DiscoveryResults, DiscoveryError> {
    discover_with_options(DiscoveryOptions {
        additional_subnets: vec![subnet.to_string()],
        use_broadcast: true,
        multicast_ttl: 3,
        timeout: Duration::from_secs(6),
        ..Default::default()
    })
    .await
}

/// Discover ONVIF devices with custom options
pub async fn discover_with_options(
    options: DiscoveryOptions,
) -> Result<DiscoveryResults, DiscoveryError> {
    let start_time = Instant::now();

    log::info!(
        "Starting ONVIF device discovery (timeout: {:?})",
        options.timeout
    );

    // Perform WS-Discovery probe
    let probe_results = probe::discover_devices_multicast(options).await?;

    let scan_duration = start_time.elapsed();

    log::info!(
        "Discovery completed in {:?}: found {} devices, received {} responses",
        scan_duration,
        probe_results.devices.len(),
        probe_results.responses_received
    );

    Ok(DiscoveryResults {
        devices: probe_results.devices,
        scan_duration,
        errors: probe_results.errors,
        responses_received: probe_results.responses_received,
    })
}

/// Test if credentials work for a device
///
/// This is a lightweight test that attempts to authenticate with the device
/// without performing a full interrogation.
pub async fn test_credentials(
    device: &DiscoveredDevice,
    credentials: &Credentials,
) -> Result<bool, InterrogationError> {
    interrogate::test_device_credentials(device, credentials).await
}

/// Get detailed information about a specific device
///
/// This connects to the device using ONVIF SOAP calls to retrieve:
/// - Detailed device information
/// - Available media profiles
/// - RTSP stream URLs
/// - Device capabilities
pub async fn interrogate_device(
    device: &DiscoveredDevice,
    credentials: Option<&Credentials>,
) -> Result<DeviceDetails, InterrogationError> {
    log::info!(
        "Interrogating device: {} {} at {}",
        device.manufacturer,
        device.model,
        device.ip_address
    );

    interrogate::interrogate_device_details(device, credentials).await
}

/// Interrogate multiple devices in parallel
///
/// Returns results in the same order as the input devices.
/// Failed interrogations are returned as errors.
pub async fn interrogate_multiple(
    devices: &[DiscoveredDevice],
    credentials: Option<&Credentials>,
) -> Vec<Result<DeviceDetails, InterrogationError>> {
    use futures::future::join_all;

    let futures = devices
        .iter()
        .map(|device| interrogate_device(device, credentials));

    join_all(futures).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_timeout() {
        let result = discover_devices_timeout(Duration::from_millis(100)).await;
        assert!(result.is_ok());

        let results = result.unwrap();
        assert!(results.scan_duration >= Duration::from_millis(100));
    }

    #[test]
    fn test_default_options() {
        let options = DiscoveryOptions::default();
        assert_eq!(options.timeout, DEFAULT_DISCOVERY_TIMEOUT);
        assert_eq!(options.max_results, MAX_DISCOVERY_RESULTS);
        assert!(!options.include_ipv6);
        assert!(options.interfaces.is_empty());
        assert!(options.additional_subnets.is_empty());
        assert!(!options.use_broadcast);
        assert_eq!(options.multicast_ttl, 2);
    }

    #[test]
    fn test_multi_subnet_options() {
        let subnets = vec!["192.168.1.0/24".to_string(), "192.168.3.0/24".to_string()];
        let options = DiscoveryOptions {
            additional_subnets: subnets.clone(),
            use_broadcast: true,
            multicast_ttl: 3,
            ..Default::default()
        };

        assert_eq!(options.additional_subnets, subnets);
        assert!(options.use_broadcast);
        assert_eq!(options.multicast_ttl, 3);
    }
}
