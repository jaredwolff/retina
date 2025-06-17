//! Device interrogation module for detailed ONVIF device inspection.

use std::time::{Duration, Instant};

use tokio::time::timeout;

use super::device::*;
use super::soap::*;
use super::{Credentials, DiscoveredDevice};

/// Default timeout for ONVIF SOAP requests
const ONVIF_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Test device credentials without full interrogation
pub async fn test_device_credentials(
    device: &DiscoveredDevice,
    credentials: &Credentials,
) -> Result<bool, InterrogationError> {
    log::debug!(
        "Testing credentials for device {} at {}",
        device.name,
        device.ip_address
    );

    // Try a simple GetDeviceInformation request with credentials
    let request =
        generate_get_device_information(Some(&credentials.username), Some(&credentials.password));

    match send_onvif_request(
        &device.device_service_url,
        &request,
        "application/soap+xml",
        "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
    )
    .await
    {
        Ok(_) => {
            log::debug!("Credentials test successful for {}", device.ip_address);
            Ok(true)
        }
        Err(InterrogationError::AuthFailed) => {
            log::debug!("Credentials test failed for {}", device.ip_address);
            Ok(false)
        }
        Err(InterrogationError::Http(ref msg)) => {
            log::debug!("Bad request: {:?}", msg);
            Ok(false)
        }
        Err(e) => {
            log::warn!("Error testing credentials for {}: {}", device.ip_address, e);
            Err(e)
        }
    }
}

/// Perform detailed interrogation of an ONVIF device
pub async fn interrogate_device_details(
    device: &DiscoveredDevice,
    credentials: Option<&Credentials>,
) -> Result<DeviceDetails, InterrogationError> {
    let start_time = Instant::now();

    log::info!(
        "Starting detailed interrogation of {} at {}",
        device.name,
        device.ip_address
    );

    // Step 1: Get device information
    let device_info = get_device_information(device, credentials).await?;

    // Step 2: Get available services (including Media service)
    let services = get_device_services(device, credentials).await?;

    // Step 3: Find media service URL from services
    log::debug!(
        "Found {} services from GetServices response:",
        services.len()
    );
    for service in &services {
        log::debug!("  Service: {} -> {}", service.namespace, service.url);
    }

    let media_service_url = services
        .iter()
        .find(|s| s.namespace.contains("media"))
        .map(|s| s.url.clone())
        .ok_or_else(|| {
            log::error!("Media service not found in GetServices response. Available services:");
            for service in &services {
                log::error!("  - {}", service.namespace);
            }
            InterrogationError::ServiceUnavailable(
                "Media service not found in GetServices response".to_string(),
            )
        })?;

    log::debug!("Using media service URL: {}", media_service_url);

    // Step 4: Get media profiles and streams
    let streams = get_media_streams(&media_service_url, credentials).await?;

    // Step 5: Get device capabilities
    let capabilities = get_device_capabilities(device, credentials).await?;

    let interrogation_duration = start_time.elapsed();

    log::info!(
        "Completed interrogation of {} in {:?}: found {} streams",
        device.name,
        interrogation_duration,
        streams.len()
    );

    Ok(DeviceDetails {
        device_info,
        capabilities,
        streams,
        services,
        interrogation_duration,
    })
}

/// Get device information using GetDeviceInformation
async fn get_device_information(
    device: &DiscoveredDevice,
    credentials: Option<&Credentials>,
) -> Result<DeviceInfo, InterrogationError> {
    // Try SOAP 1.2 first (without credentials)
    let request = generate_get_device_information(None, None);

    match send_onvif_request(
        &device.device_service_url,
        &request,
        "application/soap+xml",
        "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
    )
    .await
    {
        Ok(response) => parse_device_information_response(&response),
        Err(InterrogationError::AuthRequired) if credentials.is_some() => {
            // Retry SOAP 1.2 with credentials
            let creds = credentials.unwrap();
            let auth_request =
                generate_get_device_information(Some(&creds.username), Some(&creds.password));
            let response = send_onvif_request(
                &device.device_service_url,
                &auth_request,
                "application/soap+xml",
                "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
            )
            .await?;
            parse_device_information_response(&response)
        }
        Err(e) => Err(e),
    }
}

/// Get device capabilities using GetCapabilities
async fn get_device_capabilities(
    device: &DiscoveredDevice,
    credentials: Option<&Credentials>,
) -> Result<DeviceCapabilities, InterrogationError> {
    // Try SOAP 1.2 first
    let request = if let Some(creds) = credentials {
        generate_get_capabilities(Some(&creds.username), Some(&creds.password))
    } else {
        generate_get_capabilities(None, None)
    };

    match send_onvif_request(
        &device.device_service_url,
        &request,
        "application/soap+xml",
        "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
    )
    .await
    {
        Ok(response) => parse_capabilities_response(&response),
        Err(e) => Err(e),
    }
}

/// Get media streams from the media service
async fn get_media_streams(
    media_service_url: &str,
    credentials: Option<&Credentials>,
) -> Result<Vec<MediaStream>, InterrogationError> {
    // First, get all profiles
    let request = if let Some(creds) = credentials {
        generate_get_profiles(Some(&creds.username), Some(&creds.password))
    } else {
        generate_get_profiles(None, None)
    };

    let response = send_onvif_request(
        media_service_url,
        &request,
        "application/soap+xml",
        "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
    )
    .await?;

    log::debug!("GetProfiles response received from {}", media_service_url);
    let profiles = parse_profiles_response(&response)?;

    log::debug!(
        "Found {} profiles from GetProfiles response:",
        profiles.len()
    );
    for profile in &profiles {
        log::debug!("  Profile: {} (token: {})", profile.name, profile.token);
    }

    // Then get stream URI for each profile
    let mut streams = Vec::new();
    for profile in profiles {
        log::debug!(
            "Getting stream URI for profile: {} (token: {})",
            profile.name,
            profile.token
        );
        let stream_request = if let Some(creds) = credentials {
            generate_get_stream_uri(&profile.token, Some(&creds.username), Some(&creds.password))
        } else {
            generate_get_stream_uri(&profile.token, None, None)
        };

        match send_onvif_request(
            media_service_url,
            &stream_request,
            "application/soap+xml",
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
        )
        .await
        {
            Ok(stream_response) => match parse_stream_uri_response(&stream_response, &profile) {
                Ok(stream) => streams.push(stream),
                Err(e) => {
                    log::warn!(
                        "Failed to parse stream URI for profile {}: {}",
                        profile.token,
                        e
                    );
                }
            },
            Err(e) => {
                log::warn!(
                    "Failed to get stream URI for profile {}: {}",
                    profile.token,
                    e
                );
            }
        }
    }

    Ok(streams)
}

/// Get available services from device
async fn get_device_services(
    device: &DiscoveredDevice,
    credentials: Option<&Credentials>,
) -> Result<Vec<ServiceInfo>, InterrogationError> {
    use crate::discovery::soap::generate_get_services;

    // Try SOAP 1.2 first (without credentials)
    let request = generate_get_services(None, None);

    log::debug!(
        "Sending GetServices request to {}",
        device.device_service_url
    );
    log::debug!("GetServices request body: {}", request);

    match send_onvif_request(
        &device.device_service_url,
        &request,
        "application/soap+xml",
        "http://www.onvif.org/ver10/device/wsdl/GetServices",
    )
    .await
    {
        Ok(response) => {
            log::debug!("GetServices response: {}", response);
            parse_services_response(&response)
        }
        Err(InterrogationError::AuthRequired) if credentials.is_some() => {
            log::debug!("GetServices requires authentication, retrying with credentials");
            // Retry SOAP 1.2 with credentials
            let creds = credentials.unwrap();
            let auth_request = generate_get_services(Some(&creds.username), Some(&creds.password));
            log::debug!("GetServices auth request body: {}", auth_request);
            let response = send_onvif_request(
                &device.device_service_url,
                &auth_request,
                "application/soap+xml",
                "http://www.onvif.org/ver10/device/wsdl/GetServices",
            )
            .await?;
            log::debug!("GetServices auth response: {}", response);
            parse_services_response(&response)
        }
        Err(e) => {
            log::error!("GetServices request failed: {}", e);
            Err(e)
        }
    }
}

/// Send an ONVIF SOAP request
async fn send_onvif_request(
    url: &str,
    request_body: &str,
    content_type: &str,
    soap_action: &str,
) -> Result<String, InterrogationError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;

    let parsed_url = Url::parse(url)
        .map_err(|e| InterrogationError::InvalidResponse(format!("Invalid URL {}: {}", url, e)))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| InterrogationError::InvalidResponse("No host in URL".to_string()))?;

    let port = parsed_url.port().unwrap_or(80);

    // Create HTTP POST request with proper ONVIF headers
    let content_length = request_body.len();
    let soap_action_header = if content_type.starts_with("text/xml") {
        // SOAP 1.1 requires SOAPAction header
        format!("SOAPAction: \"{}\"\r\n", soap_action)
    } else {
        // SOAP 1.2 embeds action in Content-Type
        String::new()
    };

    let content_type_header = if content_type.starts_with("application/soap+xml") {
        format!("{} charset=utf-8; action=\"{}\"", content_type, soap_action)
    } else {
        format!("{} charset=utf-8", content_type)
    };

    let http_request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         {}User-Agent: ONVIF-Client/1.0\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        parsed_url.path(),
        host,
        port,
        content_type_header,
        content_length,
        soap_action_header,
        request_body
    );

    log::info!("{:?}", http_request);

    // Connect and send request
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(ONVIF_REQUEST_TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| InterrogationError::Timeout)?
        .map_err(InterrogationError::Network)?;

    // Send HTTP request
    stream
        .write_all(http_request.as_bytes())
        .await
        .map_err(InterrogationError::Network)?;

    // Read response
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(InterrogationError::Network)?;

    let response_str = String::from_utf8_lossy(&response);

    // Check for HTTP errors with better diagnostics
    let first_line = response_str.lines().next().unwrap_or("Unknown");

    if response_str.contains("HTTP/1.1 401") || response_str.contains("HTTP/1.0 401") {
        return Err(InterrogationError::AuthRequired);
    }

    if response_str.contains("HTTP/1.1 403") || response_str.contains("HTTP/1.0 403") {
        return Err(InterrogationError::AuthFailed);
    }

    if response_str.contains("HTTP/1.1 400") || response_str.contains("HTTP/1.0 400") {
        log::debug!("HTTP 400 response from {}: {}", url, first_line);
        log::debug!("Request was: {}", request_body);
        return Err(InterrogationError::Http(format!(
            "Bad Request (400) - possibly unsupported SOAP format: {}",
            first_line
        )));
    }

    if !response_str.contains("HTTP/1.1 200") && !response_str.contains("HTTP/1.0 200") {
        log::debug!("Non-200 response from {}: {}", url, first_line);
        return Err(InterrogationError::Http(format!(
            "HTTP error response: {}",
            first_line
        )));
    }

    // Extract body (after \r\n\r\n)
    let body_start = response_str
        .find("\r\n\r\n")
        .ok_or_else(|| InterrogationError::InvalidResponse("No HTTP body found".to_string()))?
        + 4;

    Ok(response_str[body_start..].to_string())
}

/// Parse GetDeviceInformation response
fn parse_device_information_response(xml: &str) -> Result<DeviceInfo, InterrogationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut device_info = DeviceInfo {
        manufacturer: "Unknown".to_string(),
        model: "Unknown".to_string(),
        firmware_version: "Unknown".to_string(),
        serial_number: "Unknown".to_string(),
        hardware_id: "Unknown".to_string(),
    };
    let mut current_element = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|e| {
                    InterrogationError::XmlParsing(format!("Text decode error: {}", e))
                })?;

                if current_element == "Manufacturer" || current_element.ends_with(":Manufacturer") {
                    device_info.manufacturer = text.to_string();
                } else if current_element == "Model" || current_element.ends_with(":Model") {
                    device_info.model = text.to_string();
                } else if current_element == "FirmwareVersion"
                    || current_element.ends_with(":FirmwareVersion")
                {
                    device_info.firmware_version = text.to_string();
                } else if current_element == "SerialNumber"
                    || current_element.ends_with(":SerialNumber")
                {
                    device_info.serial_number = text.to_string();
                } else if current_element == "HardwareId"
                    || current_element.ends_with(":HardwareId")
                {
                    device_info.hardware_id = text.to_string();
                }
            }
            Ok(Event::End(_)) => {
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(InterrogationError::XmlParsing(format!(
                    "XML parsing error: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(device_info)
}

/// Parse GetCapabilities response
fn parse_capabilities_response(xml: &str) -> Result<DeviceCapabilities, InterrogationError> {
    // Simplified parsing - in a full implementation, this would parse the entire capabilities structure
    let capabilities = DeviceCapabilities {
        auth_methods: vec![AuthMethod::Digest, AuthMethod::Basic], // Default assumption
        onvif_version: "2.0".to_string(),
        ptz_supported: xml.contains("PTZ"),
        audio_input_supported: xml.contains("AudioSources"),
        audio_output_supported: xml.contains("AudioOutputs"),
        video_sources: 1, // Default assumption
        audio_sources: 0,
        profiles: vec!["Profile_1".to_string()],
        analytics_supported: xml.contains("Analytics"),
        events_supported: xml.contains("Events"),
    };

    // Try to extract media service URL
    if !xml.contains("Media") {
        return Err(InterrogationError::ServiceUnavailable(
            "Media service not available".to_string(),
        ));
    }

    Ok(capabilities)
}

/// Extract media service URL from capabilities
fn extract_media_service_url(
    _capabilities: &DeviceCapabilities,
) -> Result<String, InterrogationError> {
    // In a full implementation, this would extract the actual media service URL from capabilities
    // For now, we'll construct it based on common patterns
    Err(InterrogationError::ServiceUnavailable(
        "Media service URL extraction not implemented".to_string(),
    ))
}

/// Profile information from GetProfiles
#[derive(Debug, Clone)]
struct ProfileInfo {
    token: String,
    name: String,
    video_encoding: VideoEncoding,
    resolution: Resolution,
}

/// Parse GetProfiles response
fn parse_profiles_response(xml: &str) -> Result<Vec<ProfileInfo>, InterrogationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut profiles = Vec::new();
    let mut in_profile = false;
    let mut current_profile = ProfileInfo {
        token: String::new(),
        name: String::new(),
        video_encoding: VideoEncoding::H264,
        resolution: Resolution::new(1920, 1080),
    };

    log::debug!("Parsing GetProfiles response");

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if name_str == "Profiles" || name_str == "trt:Profiles" {
                    in_profile = true;
                    current_profile = ProfileInfo {
                        token: String::new(),
                        name: String::new(),
                        video_encoding: VideoEncoding::H264,
                        resolution: Resolution::new(1920, 1080),
                    };

                    // Extract token from attributes
                    for attr in e.attributes() {
                        if let Ok(attr) = attr {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            if key == "token" {
                                if let Ok(value) = attr.unescape_value() {
                                    current_profile.token = value.to_string();
                                    log::debug!("Found profile token: {}", current_profile.token);
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if in_profile {
                    if let Ok(text) = e.unescape() {
                        let text_str = text.as_ref().trim();
                        if !text_str.is_empty() && current_profile.name.is_empty() {
                            current_profile.name = text_str.to_string();
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if name_str == "Profiles" || name_str == "trt:Profiles" {
                    if in_profile && !current_profile.token.is_empty() {
                        if current_profile.name.is_empty() {
                            current_profile.name = format!("Profile_{}", current_profile.token);
                        }
                        log::debug!(
                            "Adding profile: {} (token: {})",
                            current_profile.name,
                            current_profile.token
                        );
                        profiles.push(current_profile.clone());
                    }
                    in_profile = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                log::warn!("XML parsing warning in parse_profiles_response: {}", e);
                // Continue parsing despite errors
            }
            _ => {}
        }
    }

    // If no profiles found, try a fallback approach
    if profiles.is_empty() {
        log::warn!("No profiles found in GetProfiles response, trying fallback parsing");
        log::debug!("GetProfiles response XML: {}", xml);

        // Look for common profile token patterns in the XML
        for line in xml.lines() {
            if line.contains("token=") {
                if let Some(start) = line.find("token=\"") {
                    let start = start + 7; // Skip 'token="'
                    if let Some(end) = line[start..].find('"') {
                        let token = &line[start..start + end];
                        if !token.is_empty() {
                            profiles.push(ProfileInfo {
                                token: token.to_string(),
                                name: format!("Profile_{}", token),
                                video_encoding: VideoEncoding::H264,
                                resolution: Resolution::new(1920, 1080),
                            });
                            log::debug!("Found profile token via fallback: {}", token);
                        }
                    }
                }
            }
        }
    }

    if profiles.is_empty() {
        log::error!("No profiles found in GetProfiles response");
        return Err(InterrogationError::InvalidResponse(
            "No profiles found in GetProfiles response".to_string(),
        ));
    }

    log::debug!("Successfully parsed {} profiles", profiles.len());
    Ok(profiles)
}

/// Parse GetStreamUri response
/// Parse GetServices response
fn parse_services_response(xml: &str) -> Result<Vec<ServiceInfo>, InterrogationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut services = Vec::new();
    let mut in_service = false;
    let mut in_namespace = false;
    let mut in_xaddr = false;
    let mut in_version = false;
    let mut current_service = ServiceInfo {
        namespace: String::new(),
        url: String::new(),
        version: String::new(),
    };

    // Also try to extract services from a simpler format if the standard format fails
    let mut found_any_service_elements = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if name_str == "Service" || name_str == "tds:Service" {
                    found_any_service_elements = true;
                    in_service = true;
                    current_service = ServiceInfo {
                        namespace: String::new(),
                        url: String::new(),
                        version: String::new(),
                    };
                } else if (name_str == "Namespace" || name_str == "tds:Namespace") && in_service {
                    in_namespace = true;
                } else if (name_str == "XAddr" || name_str == "tds:XAddr") && in_service {
                    in_xaddr = true;
                } else if (name_str == "Version" || name_str == "tds:Version") && in_service {
                    in_version = true;
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|e| {
                    InterrogationError::InvalidResponse(format!("XML decode error: {}", e))
                })?;

                if in_service {
                    let text_str = text.as_ref().trim();

                    if in_namespace {
                        current_service.namespace = text_str.to_string();
                    } else if in_xaddr {
                        current_service.url = text_str.to_string();
                    } else if in_version {
                        current_service.version = text_str.to_string();
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                if name_str == "Service" || name_str == "tds:Service" {
                    if in_service
                        && !current_service.namespace.is_empty()
                        && !current_service.url.is_empty()
                    {
                        if current_service.version.is_empty() {
                            current_service.version = "1.0".to_string();
                        }
                        services.push(current_service.clone());
                    }
                    in_service = false;
                } else if name_str == "Namespace" || name_str == "tds:Namespace" {
                    in_namespace = false;
                } else if name_str == "XAddr" || name_str == "tds:XAddr" {
                    in_xaddr = false;
                } else if name_str == "Version" || name_str == "tds:Version" {
                    in_version = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(InterrogationError::InvalidResponse(format!(
                    "XML parse error: {}",
                    e
                )))
            }
            _ => {}
        }
    }

    // If we didn't find any services in the XML, try to construct from common patterns
    if services.is_empty() {
        log::warn!("No services found in GetServices response, attempting fallback construction");
        log::debug!("GetServices response XML: {}", xml);

        // Try to find any URL-like patterns in the response that might be service endpoints
        let mut fallback_services = Vec::new();

        // Look for common ONVIF service patterns
        if xml.contains("onvif") {
            // Extract the base URL from the original device service URL
            if let Some(device_url) = extract_base_url_from_response(xml) {
                // Construct common service URLs
                fallback_services.push(ServiceInfo {
                    namespace: "http://www.onvif.org/ver10/device/wsdl".to_string(),
                    url: format!("{}/onvif/device_service", device_url),
                    version: "1.0".to_string(),
                });

                fallback_services.push(ServiceInfo {
                    namespace: "http://www.onvif.org/ver10/media/wsdl".to_string(),
                    url: format!("{}/onvif/media_service", device_url),
                    version: "1.0".to_string(),
                });
            }
        }

        if fallback_services.is_empty() {
            return Err(InterrogationError::ServiceUnavailable(
                "No services found in GetServices response and unable to construct fallback"
                    .to_string(),
            ));
        }

        services = fallback_services;
    }

    log::debug!(
        "Parsed {} services from GetServices response",
        services.len()
    );
    for service in &services {
        log::debug!("  Service: {} -> {}", service.namespace, service.url);
    }

    Ok(services)
}

/// Extract base URL from response XML (helper for fallback service construction)
fn extract_base_url_from_response(xml: &str) -> Option<String> {
    // Look for URL patterns in the XML
    for line in xml.lines() {
        if let Some(start) = line.find("http://") {
            if let Some(end) = line[start..].find("/onvif") {
                return Some(line[start..start + end].to_string());
            }
            // Also try to find just the base URL without /onvif
            if let Some(end) = line[start..]
                .find_char_boundary(|c: char| c.is_whitespace() || c == '<' || c == '"')
            {
                let url = &line[start..start + end];
                if url.contains("://") && !url.ends_with('/') {
                    return Some(url.to_string());
                }
            }
        }
    }
    None
}

trait FindCharBoundary {
    fn find_char_boundary<F>(&self, f: F) -> Option<usize>
    where
        F: Fn(char) -> bool;
}

impl FindCharBoundary for str {
    fn find_char_boundary<F>(&self, f: F) -> Option<usize>
    where
        F: Fn(char) -> bool,
    {
        for (i, c) in self.char_indices() {
            if f(c) {
                return Some(i);
            }
        }
        None
    }
}

fn parse_stream_uri_response(
    xml: &str,
    profile: &ProfileInfo,
) -> Result<MediaStream, InterrogationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    log::debug!("Stream uri response: {:?}", xml);

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut rtsp_url = String::new();
    let mut current_element = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|e| {
                    InterrogationError::XmlParsing(format!("Text decode error: {}", e))
                })?;

                if (current_element == "Uri" || current_element.ends_with(":Uri"))
                    && text.starts_with("rtsp://")
                {
                    rtsp_url = text.to_string();
                }
            }
            Ok(Event::End(_)) => {
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(InterrogationError::XmlParsing(format!(
                    "XML parsing error: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    if rtsp_url.is_empty() {
        return Err(InterrogationError::InvalidResponse(
            "No RTSP URL found in GetStreamUri response".to_string(),
        ));
    }

    // Determine stream type based on profile name
    let stream_type = if profile.name.to_lowercase().contains("main")
        || profile.name.to_lowercase().contains("primary")
    {
        StreamType::Primary
    } else if profile.name.to_lowercase().contains("sub")
        || profile.name.to_lowercase().contains("secondary")
    {
        StreamType::Secondary
    } else {
        StreamType::Unknown
    };

    Ok(MediaStream {
        profile_token: profile.token.clone(),
        name: profile.name.clone(),
        rtsp_url,
        video_encoding: profile.video_encoding.clone(),
        resolution: profile.resolution.clone(),
        framerate: Some(30.0), // Default assumption
        bitrate: None,
        stream_type,
        audio_encoding: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_device_information_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <GetDeviceInformationResponse>
            <Manufacturer>Hikvision</Manufacturer>
            <Model>DS-2CD2143G0-I</Model>
            <FirmwareVersion>V5.5.0</FirmwareVersion>
            <SerialNumber>DS-2CD2143G0-I20200101AACH123456789</SerialNumber>
            <HardwareId>1.0</HardwareId>
        </GetDeviceInformationResponse>
    </soap:Body>
</soap:Envelope>"#;

        let result = parse_device_information_response(xml);
        assert!(result.is_ok());

        let device_info = result.unwrap();
        assert_eq!(device_info.manufacturer, "Hikvision");
        assert_eq!(device_info.model, "DS-2CD2143G0-I");
        assert_eq!(device_info.firmware_version, "V5.5.0");
        assert_eq!(
            device_info.serial_number,
            "DS-2CD2143G0-I20200101AACH123456789"
        );
        assert_eq!(device_info.hardware_id, "1.0");
    }

    #[test]
    fn test_parse_device_information_response_with_namespace() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <SOAP-ENV:Header></SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <tds:GetDeviceInformationResponse>
            <tds:Manufacturer>GeoVision_2</tds:Manufacturer>
            <tds:Model>GV-BX2700-3V</tds:Model>
            <tds:FirmwareVersion>V1.2.3</tds:FirmwareVersion>
            <tds:SerialNumber>GV123456789</tds:SerialNumber>
            <tds:HardwareId>2.0</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

        let result = parse_device_information_response(xml);
        assert!(result.is_ok());

        let device_info = result.unwrap();
        assert_eq!(device_info.manufacturer, "GeoVision_2");
        assert_eq!(device_info.model, "GV-BX2700-3V");
        assert_eq!(device_info.firmware_version, "V1.2.3");
        assert_eq!(device_info.serial_number, "GV123456789");
        assert_eq!(device_info.hardware_id, "2.0");
    }

    #[test]
    fn test_parse_stream_uri_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <GetStreamUriResponse>
            <MediaUri>
                <Uri>rtsp://192.168.1.100:554/Streaming/Channels/101</Uri>
                <InvalidAfterConnect>false</InvalidAfterConnect>
                <InvalidAfterReboot>false</InvalidAfterReboot>
                <Timeout>PT60S</Timeout>
            </MediaUri>
        </GetStreamUriResponse>
    </soap:Body>
</soap:Envelope>"#;

        let profile = ProfileInfo {
            token: "Profile_1".to_string(),
            name: "MainStream".to_string(),
            video_encoding: VideoEncoding::H264,
            resolution: Resolution::new(1920, 1080),
        };

        let result = parse_stream_uri_response(xml, &profile);
        assert!(result.is_ok());

        let stream = result.unwrap();
        assert_eq!(
            stream.rtsp_url,
            "rtsp://192.168.1.100:554/Streaming/Channels/101"
        );
        assert_eq!(stream.profile_token, "Profile_1");
        assert_eq!(stream.name, "MainStream");
        assert_eq!(stream.stream_type, StreamType::Primary);
    }

    #[test]
    fn test_parse_stream_uri_response_with_namespace() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
    <SOAP-ENV:Header></SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <trt:GetStreamUriResponse>
            <trt:MediaUri>
                <tt:Uri>rtsp://192.168.3.104/media/video1</tt:Uri>
                <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
                <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
                <tt:Timeout>PT60S</tt:Timeout>
            </trt:MediaUri>
        </trt:GetStreamUriResponse>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

        let profile = ProfileInfo {
            token: "media_profile2".to_string(),
            name: "Profile2".to_string(),
            video_encoding: VideoEncoding::H264,
            resolution: Resolution::new(1920, 1080),
        };

        let result = parse_stream_uri_response(xml, &profile);
        assert!(result.is_ok());

        let stream = result.unwrap();
        assert_eq!(stream.rtsp_url, "rtsp://192.168.3.104/media/video1");
        assert_eq!(stream.profile_token, "media_profile2");
        assert_eq!(stream.name, "Profile2");
    }

    #[tokio::test]
    async fn test_send_onvif_request_invalid_url() {
        let result = send_onvif_request(
            "not-a-url",
            "<test/>",
            "application/soap+xml",
            "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid URL"));
    }
}
