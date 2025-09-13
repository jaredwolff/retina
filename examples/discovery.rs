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
    println!("4. Specific IP addresses");
    println!("Enter choice (1-4, default: 1): ");

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
        "4" => {
            println!("📡 Enter IP addresses (comma-separated, e.g., 192.168.3.104,192.168.3.108): ");
            println!("    Note: For subnet discovery, use option 3 instead");
            let mut ips_input = String::new();
            std::io::stdin().read_line(&mut ips_input)?;
            let input = ips_input.trim();
            
            // Check if user entered a subnet notation (contains /)
            if input.contains('/') {
                println!("⚠️  Subnet notation detected! Use option 3 for subnet discovery.");
                println!("    Treating as single IP by removing /24 suffix...");
                let ip = input.split('/').next().unwrap_or(input);
                println!("🎯 Discovering at specific IP: {}...", ip);
                discovery::discover_devices_at_ips(vec![ip]).await?
            } else {
                // Parse as individual IPs
                let ips: Vec<&str> = input.split(',').map(|s| s.trim()).collect();
                println!("🎯 Discovering at specific IPs: {:?}...", ips);
                discovery::discover_devices_at_ips(ips).await?
            }
        }
        _ => {
            println!("📡 Using standard discovery with extended timeout...");
            discovery::discover_devices_timeout(Duration::from_secs(8)).await?
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
        println!("\n📝 Troubleshooting tips:");
        println!("   1. Make sure cameras are powered on and connected to the network");
        println!("   2. Check if cameras have ONVIF/WS-Discovery enabled in their settings");
        println!("   3. Verify no firewall is blocking UDP port 3702");
        println!("   4. Try option 3 with subnet 192.168.3.0/24 for directed discovery");
        println!("   5. Try option 4 with specific IPs: 192.168.3.104,192.168.3.108,192.168.3.109,192.168.3.110,192.168.3.111");
        println!("   6. Some cameras (like GV-TBL8804) may have multicast disabled - check camera settings");
        println!("\n💡 For GV-TBL8804 cameras, check the web interface for:");
        println!("   - ONVIF settings (should be enabled)");
        println!("   - Multicast settings (should be enabled)");
        println!("   - Network isolation or VLAN settings");
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
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let username = username.trim();

    let credentials = if !username.is_empty() {
        print!("Password: ");
        std::io::stdout().flush()?;
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
