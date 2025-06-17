//! Device information types and structures for ONVIF discovery.

use std::fmt;
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

/// Detailed information about an ONVIF device
#[derive(Debug, Clone, Serialize)]
pub struct DeviceDetails {
    /// Enhanced device information from ONVIF calls
    pub device_info: DeviceInfo,

    /// Device capabilities and supported features
    pub capabilities: DeviceCapabilities,

    /// Available media streams
    pub streams: Vec<MediaStream>,

    /// Available ONVIF services
    pub services: Vec<ServiceInfo>,

    /// Time taken to interrogate the device
    pub interrogation_duration: Duration,
}

/// Detailed device information from ONVIF GetDeviceInformation
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    /// Device manufacturer
    pub manufacturer: String,

    /// Device model
    pub model: String,

    /// Firmware version
    pub firmware_version: String,

    /// Serial number
    pub serial_number: String,

    /// Hardware ID
    pub hardware_id: String,
}

/// Device capabilities and supported features
#[derive(Debug, Clone, Serialize)]
pub struct DeviceCapabilities {
    /// Supported authentication methods
    pub auth_methods: Vec<AuthMethod>,

    /// ONVIF version supported
    pub onvif_version: String,

    /// PTZ (Pan-Tilt-Zoom) support
    pub ptz_supported: bool,

    /// Audio input support
    pub audio_input_supported: bool,

    /// Audio output support
    pub audio_output_supported: bool,

    /// Number of video sources
    pub video_sources: u32,

    /// Number of audio sources
    pub audio_sources: u32,

    /// Supported ONVIF profiles
    pub profiles: Vec<String>,

    /// Analytics support
    pub analytics_supported: bool,

    /// Events support
    pub events_supported: bool,
}

/// Authentication method
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum AuthMethod {
    /// No authentication required
    None,
    /// HTTP Basic authentication
    Basic,
    /// HTTP Digest authentication
    Digest,
    /// WS-Security username token
    UsernameToken,
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::None => write!(f, "None"),
            AuthMethod::Basic => write!(f, "Basic"),
            AuthMethod::Digest => write!(f, "Digest"),
            AuthMethod::UsernameToken => write!(f, "UsernameToken"),
        }
    }
}

/// Information about a media stream
#[derive(Debug, Clone, Serialize)]
pub struct MediaStream {
    /// ONVIF profile token
    pub profile_token: String,

    /// Human-readable stream name
    pub name: String,

    /// RTSP stream URL
    pub rtsp_url: String,

    /// Video encoding format
    pub video_encoding: VideoEncoding,

    /// Video resolution
    pub resolution: Resolution,

    /// Video framerate (fps)
    pub framerate: Option<f32>,

    /// Video bitrate (bps)
    pub bitrate: Option<u32>,

    /// Stream classification
    pub stream_type: StreamType,

    /// Audio encoding if available
    pub audio_encoding: Option<AudioEncoding>,
}

/// Video encoding format
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum VideoEncoding {
    H264,
    H265,
    MJPEG,
    MPEG4,
    Unknown(String),
}

impl fmt::Display for VideoEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VideoEncoding::H264 => write!(f, "H.264"),
            VideoEncoding::H265 => write!(f, "H.265"),
            VideoEncoding::MJPEG => write!(f, "MJPEG"),
            VideoEncoding::MPEG4 => write!(f, "MPEG-4"),
            VideoEncoding::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for VideoEncoding {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "H264" | "H.264" => VideoEncoding::H264,
            "H265" | "H.265" | "HEVC" => VideoEncoding::H265,
            "MJPEG" | "JPEG" => VideoEncoding::MJPEG,
            "MPEG4" | "MPEG-4" => VideoEncoding::MPEG4,
            _ => VideoEncoding::Unknown(s.to_string()),
        }
    }
}

/// Audio encoding format
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum AudioEncoding {
    AAC,
    G711,
    G726,
    PCM,
    Unknown(String),
}

impl fmt::Display for AudioEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AudioEncoding::AAC => write!(f, "AAC"),
            AudioEncoding::G711 => write!(f, "G.711"),
            AudioEncoding::G726 => write!(f, "G.726"),
            AudioEncoding::PCM => write!(f, "PCM"),
            AudioEncoding::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for AudioEncoding {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "AAC" => AudioEncoding::AAC,
            "G711" | "G.711" => AudioEncoding::G711,
            "G726" | "G.726" => AudioEncoding::G726,
            "PCM" => AudioEncoding::PCM,
            _ => AudioEncoding::Unknown(s.to_string()),
        }
    }
}

/// Video resolution
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

impl Resolution {
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// Common resolution names
    pub fn name(&self) -> &'static str {
        match (self.width, self.height) {
            (1920, 1080) => "1080p",
            (1280, 720) => "720p",
            (640, 480) => "VGA",
            (320, 240) => "QVGA",
            (704, 576) => "4CIF",
            (352, 288) => "CIF",
            (176, 144) => "QCIF",
            _ => "Custom",
        }
    }

    /// Calculate total pixels
    pub fn pixels(&self) -> u32 {
        self.width * self.height
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}×{} ({})", self.width, self.height, self.name())
    }
}

/// Stream type classification
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum StreamType {
    /// Primary/main stream (highest quality)
    Primary,
    /// Secondary/sub stream (lower quality)
    Secondary,
    /// Third stream
    Third,
    /// Snapshot/JPEG stream
    Snapshot,
    /// Unknown/other stream type
    Unknown,
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamType::Primary => write!(f, "Primary"),
            StreamType::Secondary => write!(f, "Secondary"),
            StreamType::Third => write!(f, "Third"),
            StreamType::Snapshot => write!(f, "Snapshot"),
            StreamType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// ONVIF service information
#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    /// Service namespace
    pub namespace: String,

    /// Service URL
    pub url: String,

    /// Service version
    pub version: String,
}

/// Errors that can occur during device interrogation
#[derive(Debug, Error)]
pub enum InterrogationError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Device not responding")]
    DeviceUnreachable,

    #[error("ONVIF not supported")]
    OnvifUnsupported,

    #[error("XML parsing error: {0}")]
    XmlParsing(String),

    #[error("Invalid ONVIF response: {0}")]
    InvalidResponse(String),

    #[error("Service not available: {0}")]
    ServiceUnavailable(String),

    #[error("Timeout waiting for response")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_display() {
        let res_1080p = Resolution::new(1920, 1080);
        assert_eq!(res_1080p.to_string(), "1920×1080 (1080p)");
        assert_eq!(res_1080p.name(), "1080p");
        assert_eq!(res_1080p.pixels(), 2_073_600);

        let res_custom = Resolution::new(800, 600);
        assert_eq!(res_custom.to_string(), "800×600 (Custom)");
        assert_eq!(res_custom.name(), "Custom");
    }

    #[test]
    fn test_video_encoding_from_str() {
        assert_eq!(VideoEncoding::from("H264"), VideoEncoding::H264);
        assert_eq!(VideoEncoding::from("h264"), VideoEncoding::H264);
        assert_eq!(VideoEncoding::from("H.264"), VideoEncoding::H264);
        assert_eq!(VideoEncoding::from("HEVC"), VideoEncoding::H265);
        assert_eq!(VideoEncoding::from("MJPEG"), VideoEncoding::MJPEG);

        match VideoEncoding::from("unknown") {
            VideoEncoding::Unknown(s) => assert_eq!(s, "unknown"),
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_audio_encoding_from_str() {
        assert_eq!(AudioEncoding::from("AAC"), AudioEncoding::AAC);
        assert_eq!(AudioEncoding::from("G711"), AudioEncoding::G711);
        assert_eq!(AudioEncoding::from("G.711"), AudioEncoding::G711);

        match AudioEncoding::from("custom") {
            AudioEncoding::Unknown(s) => assert_eq!(s, "custom"),
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(AuthMethod::None.to_string(), "None");
        assert_eq!(AuthMethod::Basic.to_string(), "Basic");
        assert_eq!(AuthMethod::Digest.to_string(), "Digest");
        assert_eq!(AuthMethod::UsernameToken.to_string(), "UsernameToken");
    }

    #[test]
    fn test_stream_type_display() {
        assert_eq!(StreamType::Primary.to_string(), "Primary");
        assert_eq!(StreamType::Secondary.to_string(), "Secondary");
        assert_eq!(StreamType::Snapshot.to_string(), "Snapshot");
    }
}
