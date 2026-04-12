use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use sentinel_rs::devices::oui;
use sentinel_rs::sniffer::{list_interfaces, Sniffer};
use sentinel_rs::{anomaly, blocking, db, devices, web, AppState};

fn setup_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .finish();

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Failed to set tracing subscriber: {}", e);
    }
}

fn get_oui_path() -> PathBuf {
    std::env::var("OUI_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/oui.txt"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logging();

    info!("Starting Sentinel-RS - Network Security Monitor with Blocking");

    let interfaces = list_interfaces();
    if interfaces.is_empty() {
        error!("No network interfaces found. Run as root or with net_raw capability.");
        return Ok(());
    }

    info!("Available interfaces: {:?}", interfaces);

    let interface = std::env::var("INTERFACE").unwrap_or_else(|_| String::new());

    info!("Using interface: {}", interface);

    // Initialize database path first
    let db_path = std::env::var("DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/sentinel.db"));

    if let Some(parent) = db_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!("Failed to create data directory {:?}: {}", parent, e);
        }
    }

    // Initialize OUI database in a separate thread (non-blocking)
    let oui_path = get_oui_path();
    let _oui_handle = std::thread::spawn(move || {
        if oui_path.exists() {
            match oui::load_oui_database(&oui_path) {
                Ok(()) => info!("OUI database loaded from {:?}", oui_path),
                Err(e) => info!("OUI database error: {}", e),
            }
        } else {
            info!(
                "OUI file not found at {:?} - skipping manufacturer lookup",
                oui_path
            );
        }
    });

    // Initialize database (can run in parallel with OUI loading)
    let database =
        Arc::new(db::Database::new(&db_path).map_err(|e| format!("Database error: {}", e))?);
    info!("Database initialized at {:?}", db_path);

    // Initialize managers
    let (alert_tx, _) = broadcast::channel(1000);
    let device_manager = Arc::new(devices::DeviceManager::new(alert_tx.clone()));
    let anomaly_detector = Arc::new(anomaly::AnomalyDetector::new(alert_tx));

    // Initialize blocking components
    let blocklist = Arc::new(blocking::Blocklist::new());
    
    // Load blocklists in parallel
    let blocklist_clone = blocklist.clone();
    let blocklist_handle = std::thread::spawn(move || {
        blocklist_clone.load_default_lists();
        let blocklists_dir = PathBuf::from("data/blocklists");
        if blocklists_dir.exists() {
            if let Ok(count) = blocklist_clone.load_from_file(
                &blocklists_dir.join("trackers.txt"),
                blocking::BlockType::Tracker,
            ) {
                info!("Loaded {} tracker domains", count);
            }
            if let Ok(count) = blocklist_clone.load_from_file(
                &blocklists_dir.join("malware.txt"),
                blocking::BlockType::Malware,
            ) {
                info!("Loaded {} malware domains", count);
            }
        }
    });

    let dns_sinkhole_enabled = std::env::var("DNS_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(false);

    let dns_sinkhole = Arc::new(blocking::DnsSinkhole::new(
        blocklist.clone(),
        !dns_sinkhole_enabled, // allow_fallback
    ));

    let firewall_enabled = std::env::var("FIREWALL_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(true);

    let firewall = Arc::new(blocking::FirewallManager::new(
        blocklist.clone(),
        "SENTINEL-RS",
    ));

    // Wait for blocklist loading to complete
    let _ = blocklist_handle.join();
    // OUI loading is running in background, don't wait for it

    if firewall_enabled {
        if let Err(e) = firewall.init() {
            error!("Failed to initialize firewall: {}", e);
        } else {
            info!("Firewall manager initialized");
        }
    }

    let app_state = Arc::new(AppState::new(
        device_manager.clone(),
        anomaly_detector.clone(),
        database.clone(),
        blocklist.clone(),
        dns_sinkhole.clone(),
        firewall.clone(),
    ));

    // Shared shutdown flag for sniffer thread
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Start sniffer (skip if no permissions)
    let sniffer_enabled = std::env::var("SNIFFER_ENABLED")
        .map(|v| v != "false")
        .unwrap_or(true);

    if sniffer_enabled {
        let sniffer = Sniffer::new(interface);
        sniffer.start(
            app_state.packet_tx.clone(),
            device_manager,
            anomaly_detector,
            database.clone(),
            shutdown_flag.clone(),
        );
        info!("Sniffer started");
    }

    // Start web server and async tasks on a single tokio runtime
    let router = web::create_router(app_state.clone());
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    info!("Starting web server on http://{}", addr);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Start DNS sinkhole as a tokio task (not a separate runtime)
        if dns_sinkhole_enabled {
            let dns_port: u16 = std::env::var("DNS_PORT")
                .map(|p| p.parse().unwrap_or(53))
                .unwrap_or(53);

            let dns = dns_sinkhole.clone();
            tokio::spawn(async move {
                if let Err(e) = dns.start(dns_port).await {
                    tracing::error!("DNS sinkhole error: {}", e);
                }
            });
            info!("DNS sinkhole started on port {}", dns_port);
        }

        // Start periodic session cleanup task
        let auth_for_cleanup = app_state.auth.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // every 5 min
            loop {
                interval.tick().await;
                auth_for_cleanup.cleanup_expired();
                tracing::debug!("Cleaned up expired sessions and login attempts");
            }
        });

        // Start periodic template cache cleanup
        let cache_for_cleanup = app_state.template_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600)); // every 10 min
            loop {
                interval.tick().await;
                cache_for_cleanup.cleanup();
                tracing::debug!("Cleaned up expired template cache entries");
            }
        });

        // Start periodic database cleanup task
        let db_for_cleanup = database.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // every hour
            interval.tick().await; // skip the first immediate tick
            loop {
                interval.tick().await;
                match db_for_cleanup.cleanup_old_logs(30) {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Periodic cleanup removed {} old records", count);
                        }
                    }
                    Err(e) => tracing::warn!("Periodic cleanup failed: {}", e),
                }
            }
        });

        // Bind listener
        let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
            error!("Failed to bind to {}: {}", addr, e);
            format!("Failed to bind to {}: {}", addr, e)
        })?;
        info!("Web server listening on http://{}", addr);

        // Graceful shutdown: wait for Ctrl+C
        let shutdown_flag_for_signal = shutdown_flag.clone();
        let firewall_for_cleanup = firewall.clone();
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install Ctrl+C handler");
                info!("Shutdown signal received — draining connections...");

                // Signal the sniffer thread to stop
                shutdown_flag_for_signal.store(true, Ordering::SeqCst);

                // Cleanup firewall rules
                firewall_for_cleanup.cleanup();
                info!("Firewall rules cleaned up");
            })
            .await
            .map_err(|e| {
                error!("Web server error: {}", e);
                format!("Web server error: {}", e)
            })?;

        info!("Sentinel-RS shut down gracefully");
        Ok::<(), String>(())
    })
    .map_err(|e: String| e)?;

    Ok(())
}
