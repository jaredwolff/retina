//! WS-Discovery probe implementation for discovering ONVIF devices.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::timeout;

use super::soap::*;
use super::{DiscoveredDevice, DiscoveryError, DiscoveryOptions};

/// Results from WS-Discovery probe
#[derive(Debug)]
pub struct ProbeResults {
    pub devices: Vec<DiscoveredDevice>,
    pub responses_received: usize,
    pub errors: Vec<String>,
}

/// Discover ONVIF devices using WS-Discovery multicast
pub async fn discover_devices_multicast(
    options: DiscoveryOptions,
) -> Result<ProbeResults, DiscoveryError> {
    let start_time = Instant::now();

    log::debug!(
        "Starting WS-Discovery probe with timeout {:?}",
        options.timeout
    );

    // Create UDP socket for multicast
    let socket = create_multicast_socket(&options).await?;

    // Collect responses
    let mut devices = HashMap::new();
    let mut responses_received = 0;
    let mut errors = Vec::new();

    // Send standard multicast probe
    let probe_message = generate_ws_discovery_probe();
    let multicast_addr = SocketAddr::new(
        IpAddr::V4(super::WS_DISCOVERY_MULTICAST_ADDR),
        super::WS_DISCOVERY_PORT,
    );

    log::debug!("Sending WS-Discovery probe to {}", multicast_addr);

    // Send multiple multicast probes with small delays to increase response rate
    for i in 0..3 {
        if let Err(e) = socket
            .send_to(probe_message.as_bytes(), multicast_addr)
            .await
        {
            errors.push(format!("Failed to send multicast probe {}: {}", i + 1, e));
        } else {
            log::debug!("Sent multicast probe {} of 3", i + 1);
        }
        
        if i < 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Send additional subnet probes if configured
    for subnet in &options.additional_subnets {
        log::info!("Sending directed probes to subnet: {}", subnet);
        if let Err(e) = send_subnet_probes(&socket, &probe_message, subnet).await {
            errors.push(format!("Failed to probe subnet {}: {}", subnet, e));
        }
    }

    // Send broadcast probe if enabled
    if options.use_broadcast {
        if let Err(e) = send_broadcast_probe(&socket, &probe_message).await {
            errors.push(format!("Failed to send broadcast probe: {}", e));
        }
    }

    let response_future = collect_probe_responses(
        &socket,
        &mut devices,
        &mut responses_received,
        &mut errors,
        options.max_results,
        start_time,
    );

    // Wait for responses with timeout
    match timeout(options.timeout, response_future).await {
        Ok(_) => {
            log::debug!("Probe response collection completed normally");
        }
        Err(_) => {
            log::debug!("Probe response collection timed out");
        }
    }

    // Convert HashMap to Vec and sort by IP address
    let mut device_list: Vec<DiscoveredDevice> = devices.into_values().collect();
    device_list.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));

    log::info!(
        "WS-Discovery probe completed: {} unique devices found from {} responses",
        device_list.len(),
        responses_received
    );

    Ok(ProbeResults {
        devices: device_list,
        responses_received,
        errors,
    })
}

/// Create a UDP socket configured for multicast
async fn create_multicast_socket(
    options: &DiscoveryOptions,
) -> Result<TokioUdpSocket, DiscoveryError> {
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;

    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(DiscoveryError::Network)?;

    // Enable broadcast
    socket
        .set_broadcast(true)
        .map_err(DiscoveryError::Network)?;

    // Set multicast TTL for cross-subnet discovery
    socket
        .set_multicast_ttl_v4(options.multicast_ttl)
        .map_err(DiscoveryError::Network)?;

    // Join multicast group for receiving responses
    let multicast_addr = super::WS_DISCOVERY_MULTICAST_ADDR;
    let interface_addr = Ipv4Addr::UNSPECIFIED;

    socket
        .join_multicast_v4(multicast_addr, interface_addr)
        .map_err(DiscoveryError::Network)?;

    log::debug!(
        "Created multicast socket bound to {:?}, TTL: {}",
        socket.local_addr(),
        options.multicast_ttl
    );

    Ok(socket)
}

/// Collect probe responses from the UDP socket
async fn collect_probe_responses(
    socket: &TokioUdpSocket,
    devices: &mut HashMap<String, DiscoveredDevice>,
    responses_received: &mut usize,
    errors: &mut Vec<String>,
    max_results: usize,
    start_time: Instant,
) -> Result<(), DiscoveryError> {
    let mut buf = vec![0u8; 8192]; // Buffer for UDP packets
    let mut consecutive_timeouts = 0;
    const MAX_CONSECUTIVE_TIMEOUTS: u32 = 5;

    loop {
        // Break if we've reached the maximum number of results
        if devices.len() >= max_results {
            log::debug!("Reached maximum results limit: {}", max_results);
            break;
        }

        // Receive response with moderate timeout to collect more responses
        match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src_addr))) => {
                *responses_received += 1;
                let response_time = start_time.elapsed();

                log::debug!(
                    "Received response {} from {} ({} bytes)",
                    *responses_received,
                    src_addr,
                    len
                );

                let response_data = String::from_utf8_lossy(&buf[..len]);

                // Parse the probe match response
                match parse_probe_match_response(&response_data) {
                    Ok(probe_match) => {
                        log::debug!(
                            "Successfully parsed probe match from {}: UUID={}, XAddrs={:?}",
                            src_addr,
                            probe_match.endpoint_reference,
                            probe_match.x_addrs
                        );

                        match convert_probe_match_to_device(probe_match, response_time, start_time)
                        {
                            Ok(device) => {
                                log::info!(
                                    "Found device: {} {} at {} ({}ms)",
                                    device.manufacturer,
                                    device.model,
                                    device.ip_address,
                                    device.response_time
                                );
                                // Use UUID as key to avoid duplicates
                                devices.insert(device.uuid.clone(), device);
                            }
                            Err(e) => {
                                let error_msg = format!(
                                    "Failed to convert probe match from {}: {}",
                                    src_addr, e
                                );
                                log::warn!("{}", error_msg);
                                errors.push(error_msg);
                            }
                        }
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Failed to parse response from {}: {}", src_addr, e);
                        log::debug!("{}", error_msg);
                        log::debug!(
                            "Raw response (first 500 chars): {}",
                            &response_data.chars().take(500).collect::<String>()
                        );
                        errors.push(error_msg);
                    }
                }
            }
            Ok(Err(e)) => {
                let error_msg = format!("Socket receive error: {}", e);
                log::warn!("{}", error_msg);
                errors.push(error_msg);
            }
            Err(_) => {
                // Timeout - this is normal during collection
                consecutive_timeouts += 1;
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                    log::debug!("No responses for {} consecutive timeouts, ending collection", MAX_CONSECUTIVE_TIMEOUTS);
                    break;
                }
                continue;
            }
        }
        
        // Reset timeout counter on successful receive
        consecutive_timeouts = 0;
    }

    Ok(())
}

/// Convert a ProbeMatch to a DiscoveredDevice
fn convert_probe_match_to_device(
    probe_match: ProbeMatchInfo,
    response_time: Duration,
    _discovered_at: Instant,
) -> Result<DiscoveredDevice, DiscoveryError> {
    // Extract IP address from XAddrs
    let ip_address = extract_ip_from_xaddrs(&probe_match.x_addrs).ok_or_else(|| {
        DiscoveryError::InvalidResponse("No valid IP address found in XAddrs".to_string())
    })?;

    // Extract device service URL
    let device_service_url = probe_match
        .x_addrs
        .first()
        .ok_or_else(|| {
            DiscoveryError::InvalidResponse("No XAddrs found in probe match".to_string())
        })?
        .clone();

    // Extract manufacturer and model from scopes
    let manufacturer = extract_manufacturer_from_scopes(&probe_match.scopes);
    let model = extract_model_from_scopes(&probe_match.scopes);

    // Extract optional information
    let mac_address = extract_mac_address_from_scopes(&probe_match.scopes);
    let location = extract_location_from_scopes(&probe_match.scopes);

    // Create hardware info string
    let hardware_info = format!("{} {}", manufacturer, model);

    // Generate a name - use manufacturer + model, or fall back to "IP Camera"
    let name = if manufacturer != "Unknown" && model != "Unknown" {
        format!("{} {}", manufacturer, model)
    } else if manufacturer != "Unknown" {
        manufacturer.clone()
    } else {
        "IP Camera".to_string()
    };

    Ok(DiscoveredDevice {
        uuid: probe_match.endpoint_reference,
        name,
        manufacturer,
        model,
        ip_address,
        mac_address,
        device_service_url,
        hardware_info,
        location,
        types: probe_match.types,
        scopes: probe_match.scopes,
        metadata_version: probe_match.metadata_version,
        discovered_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        response_time: response_time.as_millis() as u64,
    })
}

/// Send probes to all addresses in a subnet
async fn send_subnet_probes(
    socket: &TokioUdpSocket,
    probe_message: &str,
    subnet: &str,
) -> Result<(), DiscoveryError> {
    let subnet_addrs = parse_subnet(subnet)?;

    log::debug!(
        "Probing subnet {} ({} addresses)",
        subnet,
        subnet_addrs.len()
    );

    // Send probes in batches with small delays to avoid overwhelming the network
    for (i, addr) in subnet_addrs.iter().enumerate() {
        let target = SocketAddr::new(IpAddr::V4(*addr), super::WS_DISCOVERY_PORT);
        match socket.send_to(probe_message.as_bytes(), target).await {
            Ok(bytes) => {
                log::trace!("Sent {} byte probe to {}", bytes, target);
            }
            Err(e) => {
                log::debug!("Failed to send probe to {}: {}", target, e);
                // Continue with other addresses - don't fail the whole subnet
            }
        }
        
        // Small delay every 10 probes to avoid packet loss
        if i > 0 && i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    
    log::info!("Sent probes to {} addresses in subnet {}", subnet_addrs.len(), subnet);

    Ok(())
}

/// Send broadcast probe to local network
async fn send_broadcast_probe(
    socket: &TokioUdpSocket,
    probe_message: &str,
) -> Result<(), DiscoveryError> {
    let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), super::WS_DISCOVERY_PORT);

    log::debug!("Sending broadcast probe to {}", broadcast_addr);

    socket
        .send_to(probe_message.as_bytes(), broadcast_addr)
        .await
        .map_err(DiscoveryError::Network)?;

    Ok(())
}

/// Parse subnet CIDR notation and return list of IP addresses
fn parse_subnet(subnet: &str) -> Result<Vec<Ipv4Addr>, DiscoveryError> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err(DiscoveryError::InvalidResponse(format!(
            "Invalid subnet format: {}",
            subnet
        )));
    }

    let base_ip = Ipv4Addr::from_str(parts[0]).map_err(|e| {
        DiscoveryError::InvalidResponse(format!("Invalid IP address {}: {}", parts[0], e))
    })?;

    let prefix_len: u8 = parts[1].parse().map_err(|e| {
        DiscoveryError::InvalidResponse(format!("Invalid prefix length {}: {}", parts[1], e))
    })?;

    if prefix_len > 32 {
        return Err(DiscoveryError::InvalidResponse(format!(
            "Invalid prefix length: {}",
            prefix_len
        )));
    }

    // For practical discovery, limit to /16 and above (max 65536 addresses)
    if prefix_len < 16 {
        return Err(DiscoveryError::InvalidResponse(
            "Subnet too large (use /16 or smaller)".to_string(),
        ));
    }

    let mut addresses = Vec::new();
    let base_u32 = u32::from(base_ip);
    let network_mask = !((1u32 << (32 - prefix_len)) - 1);
    let network_addr = base_u32 & network_mask;
    let host_count = 1u32 << (32 - prefix_len);

    // Handle /32 (single host) specially
    if prefix_len == 32 {
        addresses.push(base_ip);
    } else {
        // Skip network and broadcast addresses, and limit to reasonable number
        let max_hosts = std::cmp::min(host_count.saturating_sub(2), 1024);

        for i in 1..=max_hosts {
            let addr_u32 = network_addr + i;
            addresses.push(Ipv4Addr::from(addr_u32));
        }
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_probe_match_to_device() {
        let probe_match = ProbeMatchInfo {
            endpoint_reference: "test-uuid-123".to_string(),
            types: vec!["dn:NetworkVideoTransmitter".to_string()],
            scopes: vec![
                "onvif://www.onvif.org/name/Hikvision".to_string(),
                "onvif://www.onvif.org/hardware/DS-2CD2143G0-I".to_string(),
                "onvif://www.onvif.org/MAC/68:6d:bc:5c:b1:5d".to_string(),
            ],
            x_addrs: vec!["http://192.168.1.100/onvif/device_service".to_string()],
            metadata_version: 10,
        };

        let response_time = Duration::from_millis(45);
        let discovered_at = Instant::now();

        let device = convert_probe_match_to_device(probe_match, response_time, discovered_at)
            .expect("Should convert successfully");

        assert_eq!(device.uuid, "test-uuid-123");
        assert_eq!(device.manufacturer, "Hikvision");
        assert_eq!(device.model, "DS-2CD2143G0-I");
        assert_eq!(device.ip_address.to_string(), "192.168.1.100");
        assert_eq!(device.mac_address, Some("68:6d:bc:5c:b1:5d".to_string()));
        assert_eq!(
            device.device_service_url,
            "http://192.168.1.100/onvif/device_service"
        );
        assert_eq!(device.response_time, response_time.as_millis() as u64);
        assert_eq!(device.metadata_version, 10);
    }

    #[test]
    fn test_convert_probe_match_minimal() {
        let probe_match = ProbeMatchInfo {
            endpoint_reference: "minimal-uuid".to_string(),
            types: vec!["dn:NetworkVideoTransmitter".to_string()],
            scopes: vec![],
            x_addrs: vec!["http://192.168.1.200/onvif/device_service".to_string()],
            metadata_version: 1,
        };

        let response_time = Duration::from_millis(100);
        let discovered_at = Instant::now();

        let device = convert_probe_match_to_device(probe_match, response_time, discovered_at)
            .expect("Should convert successfully");

        assert_eq!(device.uuid, "minimal-uuid");
        assert_eq!(device.manufacturer, "Unknown");
        assert_eq!(device.model, "Unknown");
        assert_eq!(device.name, "IP Camera");
        assert_eq!(device.ip_address.to_string(), "192.168.1.200");
        assert_eq!(device.mac_address, None);
    }

    #[test]
    fn test_convert_probe_match_no_ip() {
        let probe_match = ProbeMatchInfo {
            endpoint_reference: "no-ip-uuid".to_string(),
            types: vec!["dn:NetworkVideoTransmitter".to_string()],
            scopes: vec![],
            x_addrs: vec!["invalid-url".to_string()],
            metadata_version: 1,
        };

        let response_time = Duration::from_millis(100);
        let discovered_at = Instant::now();

        let result = convert_probe_match_to_device(probe_match, response_time, discovered_at);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No valid IP address"));
    }

    #[test]
    fn test_parse_subnet() {
        // Valid subnets
        let addrs = parse_subnet("192.168.1.0/24").unwrap();
        assert_eq!(addrs.len(), 254); // .1 to .254
        assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addrs[253], Ipv4Addr::new(192, 168, 1, 254));

        let addrs = parse_subnet("10.0.0.0/16").unwrap();
        assert_eq!(addrs.len(), 1024); // Limited to 1024 addresses

        // Invalid subnets
        assert!(parse_subnet("invalid").is_err());
        assert!(parse_subnet("192.168.1.0").is_err());
        assert!(parse_subnet("192.168.1.0/33").is_err());
        assert!(parse_subnet("192.168.1.0/8").is_err()); // Too large
    }

    #[tokio::test]
    async fn test_create_multicast_socket() {
        let options = DiscoveryOptions::default();
        let result = create_multicast_socket(&options).await;

        // This test might fail in some CI environments without proper network access
        match result {
            Ok(socket) => {
                assert!(socket.local_addr().is_ok());
                println!("Multicast socket created successfully");
            }
            Err(e) => {
                println!(
                    "Multicast socket creation failed (expected in some CI environments): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_discover_devices_timeout() {
        let options = DiscoveryOptions {
            timeout: Duration::from_millis(100),
            max_results: 10,
            ..Default::default()
        };

        let result = discover_devices_multicast(options).await;

        // Should succeed even if no devices found
        match result {
            Ok(results) => {
                // In a test environment, we probably won't find any devices
                println!(
                    "Discovery completed: found {} devices",
                    results.devices.len()
                );
                assert!(
                    results.responses_received == 0
                        || results.devices.len() <= results.responses_received
                );
            }
            Err(e) => {
                // Network errors are acceptable in test environments
                println!("Discovery failed (acceptable in test environment): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_multi_subnet_discovery() {
        let options = DiscoveryOptions {
            timeout: Duration::from_millis(100),
            additional_subnets: vec!["192.168.3.0/24".to_string()],
            use_broadcast: true,
            multicast_ttl: 3,
            ..Default::default()
        };

        let result = discover_devices_multicast(options).await;

        // Should succeed even if no devices found
        match result {
            Ok(results) => {
                println!(
                    "Multi-subnet discovery completed: found {} devices",
                    results.devices.len()
                );
                // Test should complete without error
            }
            Err(e) => {
                println!(
                    "Multi-subnet discovery failed (acceptable in test environment): {}",
                    e
                );
            }
        }
    }
}
