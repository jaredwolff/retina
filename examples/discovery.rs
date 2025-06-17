//! ONVIF WS-Discovery example
//!
//! This example demonstrates how to discover ONVIF cameras on the network
//! and optionally interrogate them for detailed information including RTSP URLs.

use std::time::Duration;

use retina::discovery::{self, Credentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🔍 Starting ONVIF camera discovery...\n");

    // Ask user about discovery method
    println!("Select discovery method:");
    println!("1. Standard discovery (current subnet only)");
    println!("2. Extended discovery (multiple common subnets)");
    println!("3. Custom subnet discovery");
    println!("Enter choice (1-3, default: 1): ");

    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    // Phase 1: Discovery based on user choice
    let discovery_results = match choice {
        "2" => {
            println!("🌐 Using extended discovery (multiple subnets)...");
            discovery::discover_devices_extended().await?
        }
        "3" => {
            println!("📡 Enter subnet (e.g., 192.168.3.0/24): ");
            let mut subnet = String::new();
            std::io::stdin().read_line(&mut subnet)?;
            let subnet = subnet.trim();

            println!("🌐 Discovering on subnet {}...", subnet);
            discovery::discover_devices_on_subnet(subnet).await?
        }
        _ => {
            println!("📡 Using standard discovery...");
            discovery::discover_devices_timeout(Duration::from_secs(5)).await?
        }
    };

    println!(
        "✅ Discovery completed in {:.2}s",
        discovery_results.scan_duration.as_secs_f64()
    );
    println!(
        "📡 Received {} responses",
        discovery_results.responses_received
    );
    println!(
        "📷 Found {} unique cameras\n",
        discovery_results.devices.len()
    );

    if discovery_results.devices.is_empty() {
        println!("❌ No ONVIF cameras found on the network.");
        println!("   Make sure cameras are powered on and connected to the same network.");
        return Ok(());
    }

    // Display discovered cameras
    println!("📋 Discovered cameras:");
    println!(
        "{:<3} {:<20} {:<20} {:<15} {:<8}",
        "No.", "Name", "Manufacturer", "IP Address", "Response"
    );
    println!("{}", "-".repeat(70));

    for (i, device) in discovery_results.devices.iter().enumerate() {
        println!(
            "{:<3} {:<20} {:<20} {:<15} {:<8}ms",
            i + 1,
            truncate(&device.name, 18),
            truncate(&device.manufacturer, 18),
            device.ip_address,
            device.response_time
        );
    }
    println!();

    // Ask user if they want detailed interrogation
    println!("🔬 Would you like to interrogate cameras for detailed information? (y/N)");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !input.trim().to_lowercase().starts_with('y') {
        println!("👋 Discovery complete. Use the device URLs above to connect with retina.");
        return Ok(());
    }

    // Get credentials from user
    println!("\n🔐 Enter camera credentials (leave empty if no auth required):");
    print!("Username: ");
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let username = username.trim();

    let credentials = if !username.is_empty() {
        print!("Password: ");
        let mut password = String::new();
        std::io::stdin().read_line(&mut password)?;
        let password = password.trim();

        Some(Credentials {
            username: username.to_string(),
            password: password.to_string(),
        })
    } else {
        None
    };

    // Phase 2: Detailed interrogation
    println!("\n🔬 Interrogating cameras for detailed information...\n");

    for (i, device) in discovery_results.devices.iter().enumerate() {
        println!(
            "📷 Camera {}: {} ({})",
            i + 1,
            device.name,
            device.ip_address
        );

        match discovery::interrogate_device(device, credentials.as_ref()).await {
            Ok(details) => {
                println!("  ✅ Interrogation successful!");
                println!("  📝 Device Info:");
                println!("     Manufacturer: {}", details.device_info.manufacturer);
                println!("     Model: {}", details.device_info.model);
                println!("     Firmware: {}", details.device_info.firmware_version);
                println!("     Serial: {}", details.device_info.serial_number);

                println!("  🎥 Available Streams:");
                if details.streams.is_empty() {
                    println!("     No streams found");
                } else {
                    for stream in &details.streams {
                        println!("     • {} ({})", stream.name, stream.stream_type);
                        println!("       Resolution: {}", stream.resolution);
                        println!("       Encoding: {}", stream.video_encoding);
                        println!("       RTSP URL: {}", stream.rtsp_url);
                        if let Some(fps) = stream.framerate {
                            println!("       Framerate: {:.1} fps", fps);
                        }
                    }
                }

                println!("  ⚙️  Capabilities:");
                println!("     ONVIF Version: {}", details.capabilities.onvif_version);
                println!("     PTZ Support: {}", details.capabilities.ptz_supported);
                println!(
                    "     Audio Input: {}",
                    details.capabilities.audio_input_supported
                );
                println!("     Auth Methods: {:?}", details.capabilities.auth_methods);
            }
            Err(e) => {
                println!("  ❌ Interrogation failed: {}", e);
                match e {
                    discovery::InterrogationError::AuthRequired => {
                        println!("     Hint: This camera requires authentication");
                    }
                    discovery::InterrogationError::AuthFailed => {
                        println!("     Hint: Check username/password");
                    }
                    discovery::InterrogationError::DeviceUnreachable => {
                        println!("     Hint: Camera may be offline or blocking requests");
                    }
                    _ => {}
                }
            }
        }
        println!();
    }

    println!("🎉 Discovery and interrogation complete!");

    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
