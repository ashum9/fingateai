use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use hdrhistogram::Histogram;
use traffic_gateway::env::{Env, RealEnv};

// ─── Command Line Config ──────────────────────────────────────────────────────

struct Config {
    target: String,
    connections: usize,
    duration: Duration,
    payload_size: usize,
    rate_per_sec: u64,
    sweep_mode: bool,
    sweep_step: u64,
    max_rate: u64,
}

fn parse_config() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Err(usage());
    }

    let target = get_arg(&args, "--target").unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let connections: usize = get_arg(&args, "--connections")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let duration_secs: u64 = get_arg(&args, "--duration")
        .and_then(|s| s.trim_end_matches('s').parse().ok())
        .unwrap_or(5);
    let payload_size: usize = get_arg(&args, "--payload-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let rate_per_sec: u64 = get_arg(&args, "--rate")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let sweep_mode = args.iter().any(|a| a == "--sweep");
    let sweep_step: u64 = get_arg(&args, "--sweep-step")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let max_rate: u64 = get_arg(&args, "--max-rate")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    Ok(Config {
        target,
        connections,
        duration: Duration::from_secs(duration_secs),
        payload_size,
        rate_per_sec,
        sweep_mode,
        sweep_step,
        max_rate,
    })
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn usage() -> String {
    format!(
        "FinGate Open-Loop Benchmark Harness (Coordinated Omission Corrected)\n\
         Usage: openloop_loadtest [OPTIONS]\n\n\
         Options:\n\
         \x20 --target <addr>        Gateway address (default: 127.0.0.1:8080)\n\
         \x20 --connections <N>      Number of parallel connection worker tasks (default: 10)\n\
         \x20 --rate <R>             Target open-loop request rate per second (default: 10000)\n\
         \x20 --duration <secs>      Duration per test step in seconds (default: 5)\n\
         \x20 --payload-size <bytes> Request size in bytes (default: 64)\n\
         \x20 --sweep                Enable automatic latency knee curve sweep\n\
         \x20 --sweep-step <R>       Rate increment per step during sweep (default: 10000)\n\
         \x20 --max-rate <R>         Maximum rate ceiling for sweep (default: 100000)\n\
         \x20 --help                 Show this help menu"
    )
}

// ─── Metrics Result per Step ──────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Clone)]
struct StepMetrics {
    target_rate: u64,
    actual_rate: f64,
    successes: u64,
    io_errors: u64,
    raw_p50_us: u64,
    raw_p90_us: u64,
    raw_p99_us: u64,
    raw_p999_us: u64,
    raw_max_us: u64,
    co_p50_us: u64,
    co_p90_us: u64,
    co_p99_us: u64,
    co_p999_us: u64,
    co_max_us: u64,
    service_demand_us: f64,
}

fn build_payload(id: u64, size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let bytes = id.to_be_bytes();
    for &b in bytes.iter().take(size.min(8)) {
        buf.push(b);
    }
    while buf.len() < size {
        buf.push(0x42);
    }
    buf
}

// Worker measurement record
struct MeasureRecord {
    raw_lat_us: u64,
    co_lat_us: u64,
    scheduled_interval_us: u64,
}

async fn run_benchmark_step(
    env: &RealEnv,
    config: &Config,
    target_rate: u64,
) -> Result<StepMetrics, String> {
    let running = Arc::new(AtomicBool::new(true));
    let test_start = env.now_instant();
    let duration = config.duration;
    let payload_size = config.payload_size;
    let num_connections = config.connections;

    // Establish persistent connection pool
    let mut streams = Vec::with_capacity(num_connections);
    for _ in 0..num_connections {
        let stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&config.target),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("Connection error: {}", e)),
            Err(_) => return Err("Connection timeout".to_string()),
        };
        streams.push(stream);
    }

    let interval_nanos = (1_000_000_000.0 / target_rate as f64) as u64;
    let interval_us = (interval_nanos / 1000).max(1);

    let global_counter = Arc::new(AtomicU64::new(0));

    // Timer to signal stop
    let running_flag = running.clone();
    tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        running_flag.store(false, Ordering::Relaxed);
    });

    let mut worker_handles = Vec::with_capacity(num_connections);

    // Distribute target rate among workers
    let rate_per_worker = (target_rate as f64 / num_connections as f64) as u64;
    let worker_interval_nanos = (1_000_000_000.0 / rate_per_worker.max(1) as f64) as u64;

    for (worker_id, mut stream) in streams.into_iter().enumerate() {
        let running = running.clone();
        let global_counter = global_counter.clone();

        let handle = tokio::spawn(async move {
            let mut records: Vec<MeasureRecord> = Vec::with_capacity(100_000);
            let mut io_errors = 0u64;
            let mut recv_buf = vec![0u8; payload_size];

            let worker_start = Instant::now();
            let mut seq = 0u64;

            while running.load(Ordering::Relaxed) {
                // Calculate open-loop target schedule time T_sched
                let target_offset_nanos = seq * worker_interval_nanos;
                let target_sched = worker_start + Duration::from_nanos(target_offset_nanos);

                // Wait until scheduled dispatch time
                let now = Instant::now();
                if now < target_sched {
                    tokio::time::sleep(target_sched - now).await;
                }

                let t_sent = Instant::now();
                let req_id = ((worker_id as u64) << 32) | global_counter.fetch_add(1, Ordering::Relaxed);
                let payload = build_payload(req_id, payload_size);

                // Send request
                if stream.write_all(&payload).await.is_err() {
                    io_errors += 1;
                    break;
                }

                // Recv response
                if stream.read_exact(&mut recv_buf).await.is_err() {
                    io_errors += 1;
                    break;
                }

                let t_recv = Instant::now();

                // Calculate latencies
                let raw_lat_us = t_recv.duration_since(t_sent).as_micros() as u64;
                let co_lat_us = t_recv.duration_since(target_sched).as_micros() as u64;

                records.push(MeasureRecord {
                    raw_lat_us,
                    co_lat_us,
                    scheduled_interval_us: interval_us,
                });

                seq += 1;
            }

            (records, io_errors)
        });

        worker_handles.push(handle);
    }

    let mut all_records = Vec::new();
    let mut total_io_errors = 0u64;

    for handle in worker_handles {
        if let Ok((recs, errs)) = handle.await {
            all_records.extend(recs);
            total_io_errors += errs;
        }
    }

    let elapsed = test_start.elapsed().as_secs_f64();
    let total_successes = all_records.len() as u64;
    let actual_rate = if elapsed > 0.0 {
        total_successes as f64 / elapsed
    } else {
        0.0
    };

    // Calculate Service Demand: D = L / lambda = active connections / throughput
    // Little's Law inversion
    let service_demand_us = if actual_rate > 0.0 {
        (config.connections as f64 / actual_rate) * 1_000_000.0
    } else {
        0.0
    };

    // Build HdrHistograms
    let mut raw_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
        .map_err(|e| format!("Histogram init failed: {}", e))?;
    let mut co_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
        .map_err(|e| format!("Histogram init failed: {}", e))?;

    for rec in all_records {
        let _ = raw_hist.record(rec.raw_lat_us.max(1));
        
        // Record CO latency & backfill missing virtual samples for omitted requests during stalls
        let _ = co_hist.record(rec.co_lat_us.max(1));

        // Coordinated Omission Backfilling: if CO latency > interval, synthesize intermediate samples
        if rec.co_lat_us > rec.raw_lat_us + rec.scheduled_interval_us {
            let mut omitted_lat = rec.co_lat_us.saturating_sub(rec.scheduled_interval_us);
            while omitted_lat > rec.raw_lat_us {
                let _ = co_hist.record(omitted_lat.max(1));
                if omitted_lat > rec.scheduled_interval_us {
                    omitted_lat -= rec.scheduled_interval_us;
                } else {
                    break;
                }
            }
        }
    }

    Ok(StepMetrics {
        target_rate,
        actual_rate,
        successes: total_successes,
        io_errors: total_io_errors,
        raw_p50_us: raw_hist.value_at_quantile(0.50),
        raw_p90_us: raw_hist.value_at_quantile(0.90),
        raw_p99_us: raw_hist.value_at_quantile(0.99),
        raw_p999_us: raw_hist.value_at_quantile(0.999),
        raw_max_us: raw_hist.max(),
        co_p50_us: co_hist.value_at_quantile(0.50),
        co_p90_us: co_hist.value_at_quantile(0.90),
        co_p99_us: co_hist.value_at_quantile(0.99),
        co_p999_us: co_hist.value_at_quantile(0.999),
        co_max_us: co_hist.max(),
        service_demand_us,
    })
}

fn format_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{}µs", us)
    }
}

// ─── Main Runner ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let config = match parse_config() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    };

    let env = RealEnv::new();

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║     FinGate Open-Loop Benchmark Harness (HdrHistogram + CO)          ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║  Platform Tag: {:<53} ║", env.platform_tag());
    println!("║  Target:       {:<53} ║", config.target);
    println!("║  Connections:  {:<53} ║", config.connections);
    println!("║  Step Duration:<{:<53} ║", format!("{}s", config.duration.as_secs()));
    println!("║  Payload Size: {:<53} ║", format!("{} bytes", config.payload_size));
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();

    let rates_to_test: Vec<u64> = if config.sweep_mode {
        let mut rates = Vec::new();
        let mut r = config.sweep_step;
        while r <= config.max_rate {
            rates.push(r);
            r += config.sweep_step;
        }
        rates
    } else {
        vec![config.rate_per_sec]
    };

    let mut all_metrics = Vec::new();

    for &rate in &rates_to_test {
        print!("  Running test step at target rate {:>6} req/sec... ", rate);
        let _ = tokio::io::stdout();
        match run_benchmark_step(&env, &config, rate).await {
            Ok(metrics) => {
                println!("DONE (actual: {:.0} req/s, raw p99.9: {}, CO p99.9: {})",
                    metrics.actual_rate, format_us(metrics.raw_p999_us), format_us(metrics.co_p999_us));
                all_metrics.push(metrics.clone());

                // Check for saturation threshold (e.g. error rate > 5% or extreme CO p99.9 spike)
                if metrics.io_errors > (metrics.successes / 10).max(10) {
                    println!("\n⚠️ Saturation threshold reached due to IO errors. Halting sweep.");
                    break;
                }
            }
            Err(e) => {
                println!("FAILED ({})", e);
                break;
            }
        }
    }

    // Print Final Side-by-Side Table
    println!("\n");
    println!("### LATENCY KNEE CURVE & COORDINATED OMISSION BENCHMARK REPORT");
    println!("**Platform Identifier:** `{}`", env.platform_tag());
    println!("**Measurement Method:** Open-Loop Schedule Dispatcher + HdrHistogram\n");

    println!("| Target Rate | Actual Rate | Service Demand | Raw p50 | Raw p99 | Raw p99.9 | CO p50 | CO p99 | CO p99.9 | CO Max | Errors |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");

    for m in &all_metrics {
        println!(
            "| {} req/s | {:.0} req/s | {:.2} µs | {} | {} | {} | {} | {} | {} | {} | {} |",
            m.target_rate,
            m.actual_rate,
            m.service_demand_us,
            format_us(m.raw_p50_us),
            format_us(m.raw_p99_us),
            format_us(m.raw_p999_us),
            format_us(m.co_p50_us),
            format_us(m.co_p99_us),
            format_us(m.co_p999_us),
            format_us(m.co_max_us),
            m.io_errors
        );
    }

    println!("\n✅ Phase 0 Open-Loop Benchmark Execution Complete.");
}
