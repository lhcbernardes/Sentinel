use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, Level};
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

    // Initialize OUI database
    let oui_path = get_oui_path();
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

    // Initialize database
    let db_path = std::env::var("DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/sentinel.db"));

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let database =
        Arc::new(db::Database::new(&db_path).map_err(|e| format!("Database error: {}", e))?);
    info!("Database initialized at {:?}", db_path);

    // Initialize managers
    let (alert_tx, _) = broadcast::channel(1000);
    let device_manager = Arc::new(devices::DeviceManager::new(alert_tx.clone()));
    let anomaly_detector = Arc::new(anomaly::AnomalyDetector::new(alert_tx));

    // Initialize blocking components
    let blocklist = Arc::new(blocking::Blocklist::new());
    blocklist.load_default_lists();

    // Load blocklists from files if they exist
    let blocklists_dir = PathBuf::from("data/blocklists");
    if blocklists_dir.exists() {
        if let Ok(count) = blocklist.load_from_file(
            &blocklists_dir.join("trackers.txt"),
            blocking::BlockType::Tracker,
        ) {
            info!("Loaded {} tracker domains", count);
        }
        if let Ok(count) = blocklist.load_from_file(
            &blocklists_dir.join("malware.txt"),
            blocking::BlockType::Malware,
        ) {
            info!("Loaded {} malware domains", count);
        }
    }

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

    // Start DNS sinkhole if enabled
    if dns_sinkhole_enabled {
        let dns_port: u16 = std::env::var("DNS_PORT")
            .map(|p| p.parse().unwrap_or(53))
            .unwrap_or(53);

        let dns = dns_sinkhole.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Err(e) = dns.start(dns_port).await {
                    tracing::error!("DNS sinkhole error: {}", e);
                }
            });
        });
        info!("DNS sinkhole started on port {}", dns_port);
    }

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
            database,
        );
        info!("Sniffer started");
    }

    // Start web server
    let router = web::create_router(app_state.clone());

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    info!("Starting web server on http://{}", addr);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, router).await.ok();
    });

    Ok(())
}
