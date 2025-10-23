/// SetTimerResolution - Windows Timer Resolution Control
///
/// A modern Rust implementation that sets and maintains Windows timer resolution.
/// This is a critical utility for low-latency applications, games, and benchmarking.
///
/// License: GPLv3
/// Original: https://github.com/valleyofdoom

use clap::Parser;
use std::io::{self, Write};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::System;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleWindow};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::GetCurrentProcess;


// ============================================================================
// Windows API Definitions
// ============================================================================

const PROCESS_POWER_THROTTLING_CURRENT_VERSION: u32 = 1;
const PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION: u32 = 0x4;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ProcessPowerThrottling {
    version: u32,
    control_mask: u32,
    state_mask: u32,
}

type NtSetTimerResolution = unsafe extern "system" fn(
    desired_resolution: u32,
    set_resolution: u8,
    current_resolution: *mut u32,
) -> i32;

type SetProcessInformation = unsafe extern "system" fn(
    process: HANDLE,
    process_information_class: u32,
    process_information: *const ProcessPowerThrottling,
    process_information_size: u32,
) -> i32;

const PROCESS_POWER_THROTTLING: u32 = 4;

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "SetTimerResolution",
    version = "0.1.0",
    about = "Windows Timer Resolution Control - GPLv3",
    long_about = "Set and maintain Windows timer resolution for low-latency applications.\nGitHub: https://github.com/valleyofdoom"
)]
struct Args {
    /// Desired timer resolution in 100-nanosecond units (e.g., 5000 = 0.5ms)
    #[arg(long, value_name = "UNITS")]
    resolution: u32,

    /// Hide the console window after initialization
    #[arg(long)]
    no_console: bool,

    /// Display verbose output
    #[arg(short, long)]
    verbose: bool,
}

// ============================================================================
// Instance Management
// ============================================================================

/// Check if another instance of this program is already running
fn check_single_instance() -> io::Result<bool> {
    let mut system = System::new_all();
    system.refresh_all();

    let current_exe = std::env::current_exe()?
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let instance_count = system
        .processes()
        .values()
        .filter(|p| {
            p.name()
                .to_string_lossy()
                .to_lowercase()
                .contains(&current_exe)
        })
        .count();

    Ok(instance_count <= 1)
}

// ============================================================================
// Windows Power Throttling Control
// ============================================================================

/// Disable power throttling for timer resolution on Windows 8+
///
/// This ensures the OS doesn't interfere with our timer resolution settings.
unsafe fn disable_power_throttling(verbose: bool) -> Result<(), String> {
    // Load kernel32.dll
    let kernel32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let kernel32 = LoadLibraryW(kernel32_name.as_ptr());

    if kernel32.is_null() {
        return Err("Failed to load kernel32.dll".to_string());
    }

    // Try to get SetProcessInformation (doesn't exist on Windows 7)
    let func_name = b"SetProcessInformation\0";
    let set_process_info = GetProcAddress(kernel32, func_name.as_ptr());

    if set_process_info.is_none() {
        if verbose {
            println!("⚠️  SetProcessInformation not available (Windows 7 or older)");
        }
        return Ok(()); // Not an error, just not supported
    }

    let set_process_info: SetProcessInformation = mem::transmute(set_process_info);

    // Configure power throttling to ignore timer resolution
    let mut power_throttling = ProcessPowerThrottling {
        version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        control_mask: PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
        state_mask: 0,
    };

    let result = set_process_info(
        GetCurrentProcess(),
        PROCESS_POWER_THROTTLING,
        &power_throttling as *const _,
        mem::size_of::<ProcessPowerThrottling>() as u32,
    );

    if result == 0 {
        return Err("SetProcessInformation failed".to_string());
    }

    if verbose {
        println!("✓ Power throttling disabled for timer resolution");
    }

    Ok(())
}

// ============================================================================
// Timer Resolution Control
// ============================================================================

/// Set Windows timer resolution using NtSetTimerResolution
///
/// # Arguments
/// * `desired_resolution` - Resolution in 100-nanosecond units
/// * `verbose` - Enable verbose output
///
/// # Returns
/// The actual resolution set by the system (may differ from requested)
unsafe fn set_timer_resolution(
    desired_resolution: u32,
    verbose: bool,
) -> Result<u32, String> {
    // Load ntdll.dll
    let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll = LoadLibraryW(ntdll_name.as_ptr());

    if ntdll.is_null() {
        return Err("Failed to load ntdll.dll".to_string());
    }

    // Get NtSetTimerResolution function
    let func_name = b"NtSetTimerResolution\0";
    let nt_set_timer = GetProcAddress(ntdll, func_name.as_ptr());

    if nt_set_timer.is_none() {
        return Err("Failed to get NtSetTimerResolution".to_string());
    }

    let nt_set_timer: NtSetTimerResolution = mem::transmute(nt_set_timer);

    // Set the timer resolution
    let mut current_resolution: u32 = 0;
    let status = nt_set_timer(desired_resolution, 1, &mut current_resolution);

    if status != 0 {
        return Err(format!("NtSetTimerResolution failed with status: 0x{:08X}", status));
    }

    if verbose {
        let requested_ms = desired_resolution as f64 / 10_000.0;
        let actual_ms = current_resolution as f64 / 10_000.0;
        println!("✓ Requested resolution: {:.4}ms", requested_ms);
        println!("✓ Actual resolution: {:.4}ms", actual_ms);
    }

    Ok(current_resolution)
}

// ============================================================================
// Signal Handling
// ============================================================================

/// Setup graceful shutdown on Ctrl+C
fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\n🛑 Shutdown signal received. Cleaning up...");
        r.store(false, Ordering::Relaxed);
    })
        .expect("Error setting Ctrl-C handler");

    running
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Display header
    if !args.no_console {
        println!("╔═══════════════════════════════════════════════════╗");
        println!("║   SetTimerResolution v0.1.0 - Rust Edition       ║");
        println!("║   Windows Timer Resolution Control               ║");
        println!("╚═══════════════════════════════════════════════════╝\n");
    }

    // Check for single instance
    if args.verbose {
        print!("🔍 Checking for existing instances... ");
        io::stdout().flush()?;
    }

    if !check_single_instance()? {
        eprintln!("\n❌ Error: Another instance of SetTimerResolution is already running.");
        eprintln!("   Please close all instances and try again.");
        return Err("Multiple instances detected".into());
    }

    if args.verbose {
        println!("✓ No conflicts detected");
    }

    // Validate resolution range (0.5ms to 15.6ms is typical)
    if args.resolution < 5000 || args.resolution > 156_000 {
        eprintln!("⚠️  Warning: Resolution {} is outside typical range (5000-156000 units)", args.resolution);
        eprintln!("   Typical values:");
        eprintln!("     5000  = 0.5ms (high precision)");
        eprintln!("     10000 = 1.0ms (balanced)");
        eprintln!("     15600 = 1.56ms (default Windows)");
    }

    // Disable power throttling
    unsafe {
        if let Err(e) = disable_power_throttling(args.verbose) {
            eprintln!("⚠️  Warning: {}", e);
        }
    }

    // Set timer resolution
    if args.verbose {
        print!("⏱️  Setting timer resolution... ");
        io::stdout().flush()?;
    }

    let current_resolution = unsafe {
        set_timer_resolution(args.resolution, args.verbose)?
    };

    let actual_ms = current_resolution as f64 / 10_000.0;
    println!("\n✅ Timer resolution active: {:.4}ms", actual_ms);

    // Hide console if requested
    if args.no_console {
        unsafe {
            let console_window = GetConsoleWindow();
            if !console_window.is_null() {
                FreeConsole();
                if args.verbose {
                    // This won't be visible, but good for logging
                    println!("🔇 Console hidden");
                }
            }
        }
    }

    // Setup signal handler for graceful shutdown
    let running = setup_signal_handler();

    println!("🔄 Maintaining timer resolution. Press Ctrl+C to exit...\n");

    // Keep the process alive to maintain timer resolution
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("✅ Timer resolution released. Exiting...");
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_range_validation() {
        // Test typical resolutions
        let valid_resolutions = vec![5000, 10000, 15600, 20000];

        for res in valid_resolutions {
            assert!(res >= 5000 && res <= 156_000);
        }
    }

    #[test]
    fn test_resolution_to_milliseconds() {
        // 10000 units = 1.0ms
        let units = 10000u32;
        let ms = units as f64 / 10_000.0;
        assert!((ms - 1.0).abs() < 0.0001);

        // 5000 units = 0.5ms
        let units = 5000u32;
        let ms = units as f64 / 10_000.0;
        assert!((ms - 0.5).abs() < 0.0001);
    }

    #[test]
    fn test_power_throttling_struct_size() {
        // Verify struct layout
        assert_eq!(
            mem::size_of::<ProcessPowerThrottling>(),
            12, // 3 x u32
            "ProcessPowerThrottling struct size mismatch"
        );
    }

    #[test]
    fn test_instance_check_runs() {
        // Should not panic
        let result = check_single_instance();
        assert!(result.is_ok());
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(all(test, windows))]
mod integration_tests {
    use super::*;

    #[test]
    #[ignore] // Run with: cargo test -- --ignored --test-threads=1
    fn test_set_timer_resolution_integration() {
        unsafe {
            // Try to set 1ms resolution
            let result = set_timer_resolution(10000, true);

            // Should succeed on Windows
            assert!(result.is_ok(), "Failed to set timer resolution");

            if let Ok(actual) = result {
                // Actual should be close to requested
                let actual_ms = actual as f64 / 10_000.0;
                assert!(actual_ms > 0.0 && actual_ms < 2.0);
            }
        }
    }
}