/// MeasureSleep - Windows Timer Resolution Measurement Tool
///
/// Measures the accuracy of Windows Sleep() function under different timer resolutions.
/// This tool is essential for benchmarking timer precision and system latency.
///
/// License: GPLv3
/// Original: https://github.com/valleyofdoom
use clap::Parser;
use std::io::{self, Write};
use std::mem;
use std::ptr;
use std::time::Instant;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, REALTIME_PRIORITY_CLASS, SetPriorityClass, Sleep,
};

// ============================================================================
// Windows API Definitions
// ============================================================================

type NtQueryTimerResolution = unsafe extern "system" fn(
    minimum_resolution: *mut u32,
    maximum_resolution: *mut u32,
    current_resolution: *mut u32,
) -> i32;

// ============================================================================
// Admin Privilege Check
// ============================================================================

/// Check if the current process has administrator privileges
fn is_admin() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        ) != 0
            && elevation.TokenIsElevated != 0;

        windows_sys::Win32::Foundation::CloseHandle(token);
        result
    }
}

// ============================================================================
// Timer Resolution Query
// ============================================================================

/// Query current Windows timer resolution
///
/// Returns (minimum, maximum, current) resolution in 100-nanosecond units
fn query_timer_resolution() -> io::Result<(u32, u32, u32)> {
    unsafe {
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = LoadLibraryW(ntdll_name.as_ptr());

        if ntdll.is_null() {
            return Err(io::Error::other("Failed to load ntdll.dll"));
        }

        let func_name = b"NtQueryTimerResolution\0";
        let nt_query = GetProcAddress(ntdll, func_name.as_ptr());

        if nt_query.is_none() {
            return Err(io::Error::other("Failed to get NtQueryTimerResolution"));
        }

        let nt_query: NtQueryTimerResolution = mem::transmute(nt_query);

        let (mut min_res, mut max_res, mut cur_res) = (0u32, 0u32, 0u32);
        let status = nt_query(&mut min_res, &mut max_res, &mut cur_res);

        if status != 0 {
            return Err(io::Error::other(format!(
                "NtQueryTimerResolution failed with status: 0x{:08X}",
                status
            )));
        }

        Ok((min_res, max_res, cur_res))
    }
}

// ============================================================================
// Sleep Measurement
// ============================================================================

/// Measurement result for a single sleep operation
#[derive(Debug, Clone, Copy)]
struct SleepMeasurement {
    resolution_ms: f64,
    actual_sleep_ms: f64,
    delta_ms: f64,
}

impl SleepMeasurement {
    fn measure(sleep_duration_ms: u32) -> io::Result<Self> {
        let (_, _, current_resolution) = query_timer_resolution()?;
        let resolution_ms = current_resolution as f64 / 10_000.0;

        let start = Instant::now();

        // CRITICAL: Use Windows Sleep() API directly (not std::thread::sleep)
        // This is affected by timer resolution, which is what we want to measure
        unsafe {
            Sleep(sleep_duration_ms);
        }

        let elapsed = start.elapsed();
        let actual_sleep_ms = elapsed.as_secs_f64() * 1000.0;
        let delta_ms = actual_sleep_ms - sleep_duration_ms as f64;

        Ok(Self {
            resolution_ms,
            actual_sleep_ms,
            delta_ms,
        })
    }

    fn display(&self, sleep_n: u32) {
        println!(
            "Resolution: {:.4}ms, Sleep(n={}) slept {:.4}ms (delta: {:.4})",
            self.resolution_ms, sleep_n, self.actual_sleep_ms, self.delta_ms
        );
    }
}

// ============================================================================
// Statistical Analysis
// ============================================================================

#[derive(Debug, Clone)]
struct Statistics {
    max: f64,
    avg: f64,
    min: f64,
    stdev: f64,
    sample_count: usize,
}

impl Statistics {
    /// Compute statistics from sleep delta measurements
    ///
    /// Note: Discards the first sample as it's often invalid due to cold start
    fn from_deltas(mut deltas: Vec<f64>) -> Option<Self> {
        if deltas.len() < 2 {
            return None;
        }

        // Discard first sample (cold start)
        deltas.remove(0);
        deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let sample_count = deltas.len();
        let sum: f64 = deltas.iter().sum();
        let avg = sum / sample_count as f64;

        // Calculate standard deviation
        let variance: f64 =
            deltas.iter().map(|&x| (x - avg).powi(2)).sum::<f64>() / (sample_count - 1) as f64;
        let stdev = variance.sqrt();

        Some(Self {
            max: *deltas.last()?,
            avg,
            min: *deltas.first()?,
            stdev,
            sample_count,
        })
    }

    fn display(&self) {
        println!("\nResults from {} samples", self.sample_count);
        println!("\nMax: {:.4}", self.max);
        println!("Avg: {:.4}", self.avg);
        println!("Min: {:.4}", self.min);
        println!("STDEV: {:.4}", self.stdev);
    }
}

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "MeasureSleep",
    version = "2.0.0",
    about = "Windows Sleep() Accuracy Measurement Tool - GPLv3",
    long_about = "Measures the accuracy of Windows Sleep() function under different timer resolutions.\nGitHub: https://github.com/valleyofdoom"
)]
struct Args {
    /// Duration in milliseconds for Sleep() function
    #[arg(long, default_value_t = 1, value_name = "MS")]
    sleep_n: u32,

    /// Number of samples to collect for statistical analysis
    #[arg(long, value_name = "COUNT")]
    samples: Option<usize>,

    /// Display verbose output
    #[arg(short, long)]
    verbose: bool,
}

impl Args {
    fn validate(&self) -> Result<(), String> {
        if let Some(samples) = self.samples {
            if samples < 2 {
                return Err("--samples must be at least 2".to_string());
            }
        }
        Ok(())
    }
}

// ============================================================================
// Main Execution
// ============================================================================

fn run_continuous_measurement(sleep_n: u32, verbose: bool) -> io::Result<()> {
    println!("Running continuous measurement (Press Ctrl+C to stop)...\n");

    loop {
        let measurement = SleepMeasurement::measure(sleep_n)?;
        measurement.display(sleep_n);

        if verbose {
            io::stdout().flush()?;
        }

        // Use Windows Sleep() API for consistency
        unsafe {
            Sleep(1000);
        }
    }
}

fn run_sampled_measurement(sleep_n: u32, samples: usize, verbose: bool) -> io::Result<()> {
    println!("Collecting {} samples...\n", samples);

    let mut deltas = Vec::with_capacity(samples);

    for i in 1..=samples {
        let measurement = SleepMeasurement::measure(sleep_n)?;

        if verbose {
            measurement.display(sleep_n);
        } else {
            print!("\rProgress: {}/{} samples", i, samples);
            io::stdout().flush()?;
        }

        deltas.push(measurement.delta_ms);

        if i < samples {
            // Use Windows Sleep() API for consistency
            unsafe {
                Sleep(100);
            }
        }
    }

    if !verbose {
        println!(); // New line after progress
    }

    // Compute and display statistics
    if let Some(stats) = Statistics::from_deltas(deltas) {
        stats.display();
    } else {
        eprintln!("❌ Insufficient data for statistical analysis");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate arguments
    args.validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Check admin privileges
    if !is_admin() {
        eprintln!("❌ Error: Administrator privileges required!");
        eprintln!("   Please run this program as Administrator.");
        return Err("Administrator privileges required".into());
    }

    // Display header
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║   MeasureSleep v0.1.2 - Rust Edition              ║");
    println!("║   Windows Timer Resolution Measurement            ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    // Set process priority to realtime for accurate measurements
    unsafe {
        if SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS) == 0 {
            eprintln!("⚠️  Warning: Failed to set REALTIME_PRIORITY_CLASS");
            eprintln!("   Measurements may be less accurate.");
        } else if args.verbose {
            println!("✓ Process priority set to REALTIME");
        }
    }

    // Display current timer resolution
    if args.verbose {
        match query_timer_resolution() {
            Ok((min, max, cur)) => {
                println!("\n📊 Timer Resolution Information:");
                println!("   Minimum: {:.4}ms", min as f64 / 10_000.0);
                println!("   Maximum: {:.4}ms", max as f64 / 10_000.0);
                println!("   Current: {:.4}ms\n", cur as f64 / 10_000.0);
            }
            Err(e) => {
                eprintln!("⚠️  Warning: Failed to query timer resolution: {}", e);
            }
        }
    }

    // Run measurement mode
    match args.samples {
        Some(samples) => run_sampled_measurement(args.sleep_n, samples, args.verbose)?,
        None => run_continuous_measurement(args.sleep_n, args.verbose)?,
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_calculation() {
        let deltas = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let stats = Statistics::from_deltas(deltas).unwrap();

        // First element (0.1) should be discarded
        assert_eq!(stats.sample_count, 4);
        assert_eq!(stats.min, 0.2);
        assert_eq!(stats.max, 0.5);
        assert!((stats.avg - 0.35).abs() < 0.001);
    }

    #[test]
    fn test_statistics_insufficient_data() {
        let deltas = vec![0.1];
        assert!(Statistics::from_deltas(deltas).is_none());
    }

    #[test]
    fn test_statistics_stdev() {
        let deltas = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = Statistics::from_deltas(deltas).unwrap();

        // After removing first element: [2, 3, 4, 5]
        // Mean = 3.5, Variance = 1.6667, StdDev ≈ 1.29
        assert!(stats.stdev > 1.2 && stats.stdev < 1.4);
    }

    #[test]
    fn test_args_validation() {
        let args = Args {
            sleep_n: 1,
            samples: Some(1),
            verbose: false,
        };
        assert!(args.validate().is_err());

        let args = Args {
            sleep_n: 1,
            samples: Some(2),
            verbose: false,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_resolution_conversion() {
        // 10000 units = 1.0ms
        let units = 10000u32;
        let ms = units as f64 / 10_000.0;
        assert!((ms - 1.0).abs() < 0.0001);
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(all(test, windows))]
mod integration_tests {
    use super::*;

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_query_timer_resolution() {
        let result = query_timer_resolution();
        assert!(result.is_ok(), "Failed to query timer resolution");

        if let Ok((min, max, cur)) = result {
            // Sanity checks
            assert!(min > 0, "Minimum resolution should be > 0");
            assert!(max > 0, "Maximum resolution should be > 0");
            assert!(cur > 0, "Current resolution should be > 0");
            assert!(min >= max, "Minimum should be >= Maximum (in 100ns units)");
            assert!(cur >= max, "Current should be >= Maximum");
            assert!(cur <= min, "Current should be <= Minimum");
        }
    }

    #[test]
    #[ignore]
    fn test_sleep_measurement_accuracy() {
        let measurement = SleepMeasurement::measure(1);
        assert!(measurement.is_ok(), "Sleep measurement failed");

        if let Ok(m) = measurement {
            // With default timer resolution, Sleep(1) should sleep ~15ms
            // With high resolution, it should be closer to 1-2ms
            assert!(m.actual_sleep_ms > 0.0);
            assert!(m.actual_sleep_ms < 20.0, "Sleep took too long");
        }
    }

    #[test]
    #[ignore]
    fn test_admin_check() {
        // This test needs to be run with admin privileges
        let admin = is_admin();
        println!("Running as admin: {}", admin);
        // Just verify it doesn't panic
    }
}
