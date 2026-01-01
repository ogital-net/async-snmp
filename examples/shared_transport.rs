//! Shared Transport for High-Throughput Polling
//!
//! This example demonstrates using SharedUdpTransport for polling thousands
//! of targets efficiently. Instead of one socket per target (which hits OS
//! limits around 1000-10000 sockets), a single socket is shared across all
//! clients using request-ID correlation.
//!
//! Key concepts:
//! - SharedUdpTransport: A single UDP socket shared across many clients
//! - SharedUdpHandle: Per-target handle implementing Transport trait
//! - Request ID correlation: Responses are matched to requests by ID
//! - Engine cache: Share SNMPv3 engine discovery across clients
//!
//! Run with: cargo run --example shared_transport

use async_snmp::{
    Auth, AuthProtocol, Client, ClientConfig, EngineCache, MasterKeys, PrivProtocol,
    SharedUdpTransport, oid,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    // =========================================================================
    // Example 1: Basic shared transport setup
    // =========================================================================
    println!("--- Basic Shared Transport ---\n");

    // Create a shared transport bound to an ephemeral port
    let shared = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await?;

    println!("Shared transport bound to {}", shared.local_addr());

    // Create handles for different targets
    let target1: SocketAddr = "127.0.0.1:11161".parse()?;
    let target2: SocketAddr = "127.0.0.1:11162".parse()?;

    let handle1 = shared.handle(target1);
    let handle2 = shared.handle(target2);

    // Create clients using the handles
    let config = ClientConfig::default();

    let client1 = Client::new(handle1, config.clone());
    let client2 = Client::new(handle2, config);

    println!(
        "Created clients for {} and {}",
        client1.peer_addr(),
        client2.peer_addr()
    );

    // Both clients share the same socket
    println!("Both clients use local addr: {}\n", shared.local_addr());

    // =========================================================================
    // Example 2: High-throughput polling simulation
    // =========================================================================
    println!("--- High-Throughput Polling ---\n");

    // Simulate polling 100 targets (in production, these would be real devices)
    let mut targets: Vec<SocketAddr> = Vec::new();

    // Generate target addresses (10.0.0.1 through 10.0.0.100)
    for i in 1..=100 {
        targets.push(format!("10.0.0.{}:161", i).parse()?);
    }

    println!("Polling {} targets concurrently...", targets.len());

    // Create the shared transport
    let shared = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .warn_on_source_mismatch(false) // Disable for high-throughput
        .max_message_size(65535)
        .build()
        .await?;

    let config = ClientConfig {
        timeout: Duration::from_millis(500), // Short timeout for demo
        retries: 0,                          // No retries for speed
        ..Default::default()
    };

    // Poll all targets concurrently using FuturesUnordered
    let mut futures = FuturesUnordered::new();

    for target in &targets {
        let handle = shared.handle(*target);
        let client = Client::new(handle, config.clone());

        let fut = async move {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            (client.peer_addr(), result)
        };

        futures.push(fut);
    }

    // Collect results
    let mut success_count = 0;
    let mut timeout_count = 0;

    while let Some((addr, result)) = futures.next().await {
        match result {
            Ok(_) => success_count += 1,
            Err(async_snmp::Error::Timeout { .. }) => timeout_count += 1,
            Err(e) => {
                // Other errors (should be rare)
                println!("  {}: {}", addr, e);
            }
        }
    }

    println!(
        "Results: {} success, {} timeout",
        success_count, timeout_count
    );
    println!("(Timeouts expected - demo targets are not real devices)\n");

    // =========================================================================
    // Example 3: SNMPv3 with shared engine cache
    // =========================================================================
    println!("--- SNMPv3 with Shared Engine Cache ---\n");

    // For SNMPv3, engine discovery is cached to avoid repeated discovery requests.
    // The EngineCache can be shared across multiple clients.
    let engine_cache = Arc::new(EngineCache::new());

    // Pre-compute master keys once (expensive: ~850us for SHA-256)
    let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass123")
        .with_privacy(PrivProtocol::Aes128, b"privpass123");

    println!("Master keys derived (one-time cost)");
    println!("Engine cache created for sharing\n");

    // Create shared transport for v3 polling
    let shared_v3 = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await?;

    // Simulate polling multiple v3 targets
    let v3_targets: Vec<SocketAddr> = (1..=10)
        .map(|i| format!("192.168.1.{}:161", i).parse().unwrap())
        .collect();

    println!("Polling {} v3 targets...", v3_targets.len());

    for target in &v3_targets {
        let handle = shared_v3.handle(*target);

        // Create auth with master keys (cheap: just clones Arc)
        let auth: Auth = Auth::usm("snmpuser")
            .with_master_keys(master_keys.clone())
            .into();

        // Build client with engine cache
        let client = Client::builder(target.to_string(), auth)
            .timeout(Duration::from_millis(500))
            .retries(0)
            .engine_cache(engine_cache.clone())
            .build(handle)?;

        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
            Ok(vb) => println!("  {}: {:?}", target, vb.value),
            Err(async_snmp::Error::Timeout { .. }) => {
                println!("  {}: timeout (expected)", target);
            }
            Err(e) => println!("  {}: {}", target, e),
        }
    }

    // =========================================================================
    // Example 4: Production polling pattern
    // =========================================================================
    println!("\n--- Production Polling Pattern ---\n");

    // A typical production polling loop structure
    let shared_prod = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await?;

    // In production, targets would come from a database or config
    let poll_targets: Vec<PollTarget> = vec![
        PollTarget {
            addr: "127.0.0.1:11161".parse()?,
            community: "public".to_string(),
            oids: vec![
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
                oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
            ],
        },
        // Add more targets...
    ];

    // Poll interval
    let poll_interval = Duration::from_secs(60);

    println!(
        "Would poll {} targets every {:?}",
        poll_targets.len(),
        poll_interval
    );

    // Single poll iteration (in production, this would be in a loop)
    for target in &poll_targets {
        let handle = shared_prod.handle(target.addr);
        let client = Client::builder(target.addr.to_string(), Auth::v2c(&target.community))
            .timeout(Duration::from_secs(5))
            .retries(2)
            .build(handle)?;

        match client.get_many(&target.oids).await {
            Ok(results) => {
                println!("  {}: {} values", target.addr, results.len());
                for vb in results {
                    println!("    {}: {:?}", vb.oid, vb.value);
                }
            }
            Err(e) => {
                println!("  {}: {}", target.addr, e);
            }
        }
    }

    // =========================================================================
    // Example 5: Batched polling with rate limiting
    // =========================================================================
    println!("\n--- Batched Polling with Rate Limiting ---\n");

    // For very large target counts, batch requests to avoid overwhelming
    // the network or hitting rate limits

    let batch_size = 100;
    let batch_delay = Duration::from_millis(10);

    let all_targets: Vec<SocketAddr> = (1..=500)
        .map(|i| format!("10.1.{}.{}:161", i / 256, i % 256).parse().unwrap())
        .collect();

    println!(
        "Polling {} targets in batches of {}...",
        all_targets.len(),
        batch_size
    );

    let shared_batched = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await?;

    let config = ClientConfig {
        timeout: Duration::from_millis(200),
        retries: 0,
        ..Default::default()
    };

    let mut total_success = 0;
    let mut total_timeout = 0;

    for (batch_num, chunk) in all_targets.chunks(batch_size).enumerate() {
        let mut batch_futures = FuturesUnordered::new();

        for target in chunk {
            let handle = shared_batched.handle(*target);
            let client = Client::new(handle, config.clone());

            batch_futures.push(async move { client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await });
        }

        while let Some(result) = batch_futures.next().await {
            match result {
                Ok(_) => total_success += 1,
                Err(async_snmp::Error::Timeout { .. }) => total_timeout += 1,
                Err(_) => {}
            }
        }

        // Small delay between batches
        if batch_num < all_targets.len() / batch_size {
            tokio::time::sleep(batch_delay).await;
        }
    }

    println!("Batch polling complete:");
    println!("  Success: {}", total_success);
    println!("  Timeout: {} (expected - demo targets)", total_timeout);

    println!("\nExample complete!");
    Ok(())
}

/// Configuration for a poll target (production example)
struct PollTarget {
    addr: SocketAddr,
    community: String,
    oids: Vec<async_snmp::Oid>,
}
