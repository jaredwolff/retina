//! SOAP message handling for WS-Discovery and ONVIF communication.

use base64::prelude::*;
use chrono::Utc;
use rand::Rng;
use sha1::{Digest, Sha1};
use uuid::Uuid;

/// Generate a WS-Discovery Probe message
pub fn generate_ws_discovery_probe() -> String {
    let message_id = Uuid::new_v4();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>uuid:{}</wsa:MessageID>
        <wsa:ReplyTo>
            <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>"#,
        message_id
    )
}

/// Parse a WS-Discovery ProbeMatch response
pub fn parse_probe_match_response(
    xml: &str,
) -> Result<ProbeMatchInfo, crate::discovery::DiscoveryError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    log::debug!("{:?}", xml);

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut probe_match = ProbeMatchInfo::default();
    let mut current_element = String::new();
    let mut in_probe_match = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                // Handle different namespace prefixes (tns:ProbeMatch, d:ProbeMatch, etc.)
                if current_element.ends_with("ProbeMatch") {
                    in_probe_match = true;
                }
            }
            Ok(Event::Text(e)) => {
                if !in_probe_match {
                    continue;
                }

                let text = e.unescape().map_err(|e| {
                    crate::discovery::DiscoveryError::XmlParsing(format!(
                        "Text decode error: {}",
                        e
                    ))
                })?;

                // Handle different namespace prefixes by checking the local name
                let local_name = current_element
                    .split(':')
                    .last()
                    .unwrap_or(&current_element);
                match local_name {
                    "Address" => {
                        let addr_str = text.to_string();
                        if addr_str.starts_with("urn:uuid:") {
                            probe_match.endpoint_reference = addr_str
                                .strip_prefix("urn:uuid:")
                                .unwrap_or(&addr_str)
                                .to_string();
                        }
                    }
                    "Types" => {
                        probe_match.types =
                            text.split_whitespace().map(|s| s.to_string()).collect();
                    }
                    "Scopes" => {
                        probe_match.scopes =
                            text.split_whitespace().map(|s| s.to_string()).collect();
                    }
                    "XAddrs" => {
                        probe_match.x_addrs =
                            text.split_whitespace().map(|s| s.to_string()).collect();
                    }
                    "MetadataVersion" => {
                        probe_match.metadata_version = text.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let element_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                // Handle different namespace prefixes
                if element_name.ends_with("ProbeMatch") {
                    in_probe_match = false;
                }
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(crate::discovery::DiscoveryError::XmlParsing(format!(
                    "XML parsing error: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    if probe_match.endpoint_reference.is_empty() {
        return Err(crate::discovery::DiscoveryError::InvalidResponse(
            "No endpoint reference found in ProbeMatch".to_string(),
        ));
    }

    Ok(probe_match)
}

/// Information extracted from a ProbeMatch response
#[derive(Debug, Clone, Default)]
pub struct ProbeMatchInfo {
    pub endpoint_reference: String,
    pub types: Vec<String>,
    pub scopes: Vec<String>,
    pub x_addrs: Vec<String>,
    pub metadata_version: u32,
}

/// Extract manufacturer from ONVIF scopes
pub fn extract_manufacturer_from_scopes(scopes: &[String]) -> String {
    for scope in scopes {
        if let Some(name_scope) = scope.strip_prefix("onvif://www.onvif.org/name/") {
            return name_scope.to_string();
        }
        if let Some(manufacturer_scope) = scope.strip_prefix("onvif://www.onvif.org/manufacturer/")
        {
            return manufacturer_scope.to_string();
        }
        if let Some(company_scope) = scope.strip_prefix("onvif://www.onvif.org/company/") {
            return company_scope.to_string();
        }
        if let Some(hardware_scope) = scope.strip_prefix("onvif://www.onvif.org/hardware/") {
            // Sometimes manufacturer is in hardware scope
            if let Some(first_part) = hardware_scope.split('/').next() {
                return first_part.to_string();
            }
        }
    }

    // Fallback: try to extract from any scope that looks like manufacturer info
    for scope in scopes {
        if scope.contains("manufacturer") || scope.contains("vendor") || scope.contains("company") {
            if let Some(value) = scope.split('=').nth(1).or_else(|| scope.split('/').last()) {
                return value.to_string();
            }
        }
    }

    "Unknown".to_string()
}

/// Extract model from ONVIF scopes
pub fn extract_model_from_scopes(scopes: &[String]) -> String {
    for scope in scopes {
        if let Some(hardware_scope) = scope.strip_prefix("onvif://www.onvif.org/hardware/") {
            return hardware_scope.to_string();
        }
        if scope.contains("model") {
            if let Some(value) = scope.split('=').nth(1).or_else(|| scope.split('/').last()) {
                return value.to_string();
            }
        }
    }

    "Unknown".to_string()
}

/// Extract MAC address from ONVIF scopes
pub fn extract_mac_address_from_scopes(scopes: &[String]) -> Option<String> {
    for scope in scopes {
        if let Some(mac_scope) = scope.strip_prefix("onvif://www.onvif.org/MAC/") {
            return Some(mac_scope.to_string());
        }
    }
    None
}

/// Extract location from ONVIF scopes
pub fn extract_location_from_scopes(scopes: &[String]) -> Option<String> {
    for scope in scopes {
        if let Some(location_scope) = scope.strip_prefix("onvif://www.onvif.org/location/") {
            return Some(location_scope.to_string());
        }
    }
    None
}

/// Extract IP address from XAddrs
pub fn extract_ip_from_xaddrs(x_addrs: &[String]) -> Option<std::net::IpAddr> {
    for addr in x_addrs {
        if let Ok(url) = url::Url::parse(addr) {
            if let Some(host) = url.host_str() {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Generate ONVIF GetDeviceInformation request
pub fn generate_get_device_information(username: Option<&str>, password: Option<&str>) -> String {
    let auth_header = if let (Some(user), Some(pass)) = (username, password) {
        generate_wsse_auth_header(user, pass)
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <SOAP-ENV:Header>
        {}
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <tds:GetDeviceInformation/>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        auth_header
    )
}

/// Generate ONVIF GetCapabilities request
pub fn generate_get_capabilities(username: Option<&str>, password: Option<&str>) -> String {
    let auth_header = if let (Some(user), Some(pass)) = (username, password) {
        generate_wsse_auth_header(user, pass)
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
    xmlns:tt="http://www.onvif.org/ver10/schema">
    <SOAP-ENV:Header>
        {}
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <tds:GetCapabilities>
            <tds:Category>All</tds:Category>
        </tds:GetCapabilities>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        auth_header
    )
}

/// Generate ONVIF GetProfiles request for media service
pub fn generate_get_profiles(username: Option<&str>, password: Option<&str>) -> String {
    let auth_header = if let (Some(user), Some(pass)) = (username, password) {
        generate_wsse_auth_header(user, pass)
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
    <SOAP-ENV:Header>
        {}
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <trt:GetProfiles/>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        auth_header
    )
}

/// Generate ONVIF GetStreamUri request
pub fn generate_get_services(username: Option<&str>, password: Option<&str>) -> String {
    let auth_header = if let (Some(user), Some(pass)) = (username, password) {
        generate_wsse_auth_header(user, pass)
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <SOAP-ENV:Header>
        {}
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <tds:GetServices>
            <tds:IncludeCapability>false</tds:IncludeCapability>
        </tds:GetServices>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        auth_header
    )
}

pub fn generate_get_stream_uri(
    username: Option<&str>,
    password: Option<&str>,
    profile_token: &str,
) -> String {
    let auth_header = if let (Some(user), Some(pass)) = (username, password) {
        generate_wsse_auth_header(user, pass)
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
    xmlns:tt="http://www.onvif.org/ver10/schema">
    <SOAP-ENV:Header>
        {}
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <trt:GetStreamUri>
            <trt:StreamSetup>
                <tt:Stream>RTP-Unicast</tt:Stream>
                <tt:Transport>
                    <tt:Protocol>RTSP</tt:Protocol>
                </tt:Transport>
            </trt:StreamSetup>
            <trt:ProfileToken>{}</trt:ProfileToken>
        </trt:GetStreamUri>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        auth_header, profile_token
    )
}


/// Generate WS-Security authentication header
fn generate_wsse_auth_header(username: &str, password: &str) -> String {
    // Generate random nonce (16 bytes)
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill(&mut nonce);
    let nonce_b64 = BASE64_STANDARD.encode(&nonce);

    // Generate ISO 8601 timestamp
    let created = Utc::now();
    let created_iso8601 = created.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Create password digest: base64(sha1(nonce + created + password))
    let digest_input = [&nonce, created_iso8601.as_bytes(), password.as_bytes()].concat();
    let mut hasher = Sha1::new();
    hasher.update(&digest_input);
    let digest = hasher.finalize();
    let password_digest = BASE64_STANDARD.encode(&digest);

    format!(
        r#"<wsse:Security SOAP-ENV:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-1">
                <wsse:Username>{}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
                <wsu:Created>{}</wsu:Created>
            </wsse:UsernameToken>
        </wsse:Security>"#,
        username, password_digest, nonce_b64, created_iso8601
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ws_discovery_probe() {
        let probe = generate_ws_discovery_probe();

        assert!(probe.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"));
        assert!(probe.contains("dn:NetworkVideoTransmitter"));
        assert!(probe.contains("uuid:"));
    }

    #[test]
    fn test_extract_manufacturer_from_scopes() {
        let scopes = vec![
            "onvif://www.onvif.org/name/Hikvision".to_string(),
            "onvif://www.onvif.org/hardware/DS-2CD2143G0-I".to_string(),
        ];

        let manufacturer = extract_manufacturer_from_scopes(&scopes);
        assert_eq!(manufacturer, "Hikvision");
    }

    #[test]
    fn test_extract_model_from_scopes() {
        let scopes = vec!["onvif://www.onvif.org/hardware/DS-2CD2143G0-I".to_string()];

        let model = extract_model_from_scopes(&scopes);
        assert_eq!(model, "DS-2CD2143G0-I");
    }

    #[test]
    fn test_extract_mac_address_from_scopes() {
        let scopes = vec!["onvif://www.onvif.org/MAC/68:6d:bc:5c:b1:5d".to_string()];

        let mac = extract_mac_address_from_scopes(&scopes);
        assert_eq!(mac, Some("68:6d:bc:5c:b1:5d".to_string()));
    }

    #[test]
    fn test_extract_ip_from_xaddrs() {
        let x_addrs = vec!["http://192.168.1.100/onvif/device_service".to_string()];

        let ip = extract_ip_from_xaddrs(&x_addrs);
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_generate_get_device_information() {
        let request = generate_get_device_information(Some("admin"), Some("password"));

        assert!(request.contains("GetDeviceInformation"));
        assert!(request.contains("wsse:Security"));
        assert!(request.contains("SOAP-ENV:Envelope"));
    }

    #[test]
    fn test_parse_probe_match_minimal() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <ProbeMatches>
            <ProbeMatch>
                <EndpointReference>
                    <Address>urn:uuid:test-uuid</Address>
                </EndpointReference>
                <Types>dn:NetworkVideoTransmitter</Types>
                <XAddrs>http://192.168.1.100/onvif/device_service</XAddrs>
                <MetadataVersion>1</MetadataVersion>
            </ProbeMatch>
        </ProbeMatches>
    </soap:Body>
</soap:Envelope>"#;

        let result = parse_probe_match_response(xml);
        assert!(result.is_ok());

        let probe_match = result.unwrap();
        assert_eq!(probe_match.endpoint_reference, "test-uuid");
        assert_eq!(probe_match.types, vec!["dn:NetworkVideoTransmitter"]);
        assert_eq!(
            probe_match.x_addrs,
            vec!["http://192.168.1.100/onvif/device_service"]
        );
        assert_eq!(probe_match.metadata_version, 1);
    }

    #[test]
    fn test_parse_geovision_probe_match() {
        let xml = include_str!("testdata/geovision_probe_match.xml");

        let result = parse_probe_match_response(xml);
        assert!(result.is_ok());

        let probe_match = result.unwrap();
        assert_eq!(
            probe_match.endpoint_reference,
            "00010010-0001-1020-8000-0013e22b41d4"
        );
        assert_eq!(
            probe_match.types,
            vec!["dn:NetworkVideoTransmitter", "tds:Device"]
        );
        assert_eq!(
            probe_match.x_addrs,
            vec!["http://192.168.3.110:80/onvif/device_service"]
        );
        assert_eq!(probe_match.metadata_version, 1);

        // Test manufacturer extraction
        let manufacturer = extract_manufacturer_from_scopes(&probe_match.scopes);
        assert_eq!(manufacturer, "GeoVision_2");

        let model = extract_model_from_scopes(&probe_match.scopes);
        assert_eq!(model, "GV-TBL8804");
    }

    #[test]
    fn test_generate_get_services() {
        let request = generate_get_services(None, None);
        assert!(request.contains("GetServices"));
        assert!(request.contains("IncludeCapability"));
        assert!(request.contains("false"));
        assert!(request.contains("xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\""));
    }

    #[test]
    fn test_generate_get_services_with_auth() {
        let request = generate_get_services(Some("admin"), Some("password"));
        assert!(request.contains("GetServices"));
        assert!(request.contains("IncludeCapability"));
        assert!(request.contains("wsse:Security"));
        assert!(request.contains("wsse:UsernameToken"));
    }
}
