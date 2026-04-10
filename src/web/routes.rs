use askama::Template;
use axum::http::{header, Method};
use axum::{
    extract::{Path, State},
    response::sse::{Event, Sse},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use std::convert::Infallible;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::anomaly::detector::Alert;
use crate::blocking::BlocklistUpdater;
use crate::devices::Device;
use crate::sniffer::packet::PacketInfo;
use crate::AppState;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate;

pub async fn index() -> impl IntoResponse {
    Html(IndexTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "devices.html")]
pub struct DevicesTemplate {
    pub devices: Vec<Device>,
}

pub async fn devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let devices = state.device_manager.get_all();
    Html(DevicesTemplate { devices }.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "alerts.html")]
pub struct AlertsTemplate {
    pub alerts: Vec<Alert>,
}

pub async fn alerts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let alerts = state.anomaly_detector.get_recent_alerts();
    Html(AlertsTemplate { alerts }.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "packets.html")]
pub struct PacketsTemplate {
    pub packets: Vec<PacketInfo>,
}

pub async fn packets(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packets: Vec<_> = state.packet_cache.read().iter().cloned().collect();
    Html(PacketsTemplate { packets }.render().unwrap_or_default())
}

pub async fn blocking(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let blocklist_stats = state.blocklist.stats();
    let blocked_ips = state.firewall.get_blocked_ips();
    let dns_stats = state.dns_sinkhole.stats();
    let firewall_stats = state.firewall.stats();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blocking - Sentinel-RS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div class="max-w-7xl mx-auto flex justify-between items-center">
            <h1 class="text-2xl font-bold text-cyan-400">Sentinel-RS</h1>
            <div class="flex items-center space-x-4">
                <a href="/" class="text-sm text-gray-300 hover:text-white">Dashboard</a>
                <a href="/blocking" class="text-sm text-red-400 hover:text-red-300">Blocking</a>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-6 py-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Trackers Blocked</div>
                <div class="text-2xl font-bold text-red-400">{}</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Malware Blocked</div>
                <div class="text-2xl font-bold text-orange-400">{}</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Attackers Blocked</div>
                <div class="text-2xl font-bold text-yellow-400">{}</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Custom Rules</div>
                <div class="text-2xl font-bold text-cyan-400">{}</div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-gray-800 rounded-lg border border-gray-700">
                <div class="px-4 py-3 border-b border-gray-700">
                    <h2 class="font-semibold text-lg">DNS Sinkhole</h2>
                </div>
                <div class="p-4">
                    <div class="flex justify-between items-center mb-4">
                        <span class="text-gray-400">Status</span>
                        <span class="px-2 py-1 rounded text-xs font-medium bg-green-900 text-green-300">Active</span>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <div class="text-gray-500 text-sm">Total Queries</div>
                            <div class="text-xl font-bold">{}</div>
                        </div>
                        <div>
                            <div class="text-gray-500 text-sm">Blocked</div>
                            <div class="text-xl font-bold text-red-400">{}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg border border-gray-700">
                <div class="px-4 py-3 border-b border-gray-700">
                    <h2 class="font-semibold text-lg">Firewall ({})</h2>
                </div>
                <div class="p-4">
                    <div class="flex justify-between items-center mb-4">
                        <span class="text-gray-400">Status</span>
                        <span class="px-2 py-1 rounded text-xs font-medium bg-green-900 text-green-300">Active</span>
                    </div>
                    <div class="mb-4">
                        <div class="text-gray-500 text-sm">Backend</div>
                        <div class="font-mono text-sm">{}</div>
                    </div>
                    <div>
                        <div class="text-gray-500 text-sm">Blocked IPs</div>
                        <div class="text-xl font-bold">{}</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="mt-6 bg-gray-800 rounded-lg border border-gray-700">
            <div class="px-4 py-3 border-b border-gray-700">
                <h2 class="font-semibold text-lg">Blocked IP Addresses</h2>
            </div>
            <div class="p-4">
                {}
            </div>
        </div>

        <div class="mt-6 bg-gray-800 rounded-lg border border-gray-700">
            <div class="px-4 py-3 border-b border-gray-700">
                <h2 class="font-semibold text-lg">Add Custom Block</h2>
            </div>
            <div class="p-4">
                <div class="flex gap-2">
                    <input type="text" id="customBlockInput" placeholder="Domain or IP address" class="flex-1 bg-gray-700 text-white px-3 py-2 rounded">
                    <button onclick="addCustomBlock()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded">Block</button>
                </div>
            </div>
        </div>

        <div class="mt-6 bg-gray-800 rounded-lg border border-gray-700">
            <div class="px-4 py-3 border-b border-gray-700 flex justify-between items-center">
                <h2 class="font-semibold text-lg">Update Blocklists</h2>
                <button onclick="updateBlocklists()" id="updateBtn" class="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded">Update Now</button>
            </div>
            <div class="p-4">
                <p class="text-gray-400 text-sm mb-4">Download latest blocklists from fabriziosalmi/blacklists repository</p>
                <div id="updateStatus" class="text-sm"></div>
            </div>
        </div>

        <div class="mt-6 bg-gray-800 rounded-lg border border-gray-700">
            <div class="px-4 py-3 border-b border-gray-700">
                <h2 class="font-semibold text-lg">Network Setup Guide</h2>
            </div>
            <div class="p-4 space-y-4">
                <div class="bg-gray-750 p-3 rounded">
                    <h3 class="font-medium text-cyan-400 mb-2">Option 1: Router DNS (Recommended)</h3>
                    <p class="text-gray-400 text-sm">Configure your router's DNS to point to this machine's IP address. All devices will use it automatically.</p>
                    <div class="mt-2 font-mono text-sm text-gray-300">Example: Set DNS to 192.168.1.x (this machine's IP)</div>
                </div>
                <div class="bg-gray-750 p-3 rounded">
                    <h3 class="font-medium text-cyan-400 mb-2">Option 2: Individual Device DNS</h3>
                    <p class="text-gray-400 text-sm">Manually set DNS on each device to this machine's IP.</p>
                    <div class="mt-2 text-sm text-gray-500">Windows: Network Settings → DNS | macOS: Network → DNS | Linux: /etc/resolv.conf</div>
                </div>
                <div class="bg-gray-750 p-3 rounded">
                    <h3 class="font-medium text-cyan-400 mb-2">Option 3: Enable DNS Sinkhole</h3>
                    <p class="text-gray-400 text-sm">Start the DNS server on this machine:</p>
                    <div class="mt-2 font-mono text-sm text-yellow-400">DNS_ENABLED=true DNS_PORT=53 cargo run</div>
                    <div class="mt-2 text-xs text-gray-500">Requires sudo/root for port 53</div>
                </div>
            </div>
        </div>
    </main>

    <script>
        function addCustomBlock() {{
            const input = document.getElementById('customBlockInput');
            const value = input.value.trim();
            if (!value) return;
            fetch('/api/add-block', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{entry: value}})
            }}).then(() => {{
                input.value = '';
                location.reload();
            }});
        }}

        function updateBlocklists() {{
            const btn = document.getElementById('updateBtn');
            const status = document.getElementById('updateStatus');
            btn.disabled = true;
            btn.textContent = 'Updating...';
            status.innerHTML = '<span class="text-yellow-400">Downloading blocklists...</span>';
            
            fetch('/api/update-blocklists', {{ method: 'POST' }})
                .then(res => res.json())
                .then(data => {{
                    btn.disabled = false;
                    btn.textContent = 'Update Now';
                    if (data.status === 'ok') {{
                        status.innerHTML = '<span class="text-green-400">Updated! Trackers: ' + data.trackers + ', Malware: ' + data.malware + ', Attackers: ' + data.attackers + '</span>';
                        setTimeout(() => location.reload(), 2000);
                    }} else {{
                        status.innerHTML = '<span class="text-red-400">Error: ' + data.message + '</span>';
                    }}
                }})
                .catch(err => {{
                    btn.disabled = false;
                    btn.textContent = 'Update Now';
                    status.innerHTML = '<span class="text-red-400">Error: ' + err + '</span>';
                }});
        }}
    </script>
</body>
</html>"#,
        blocklist_stats.trackers,
        blocklist_stats.malware,
        blocklist_stats.attackers,
        blocklist_stats.custom,
        dns_stats.queries,
        dns_stats.blocked,
        firewall_stats.backend,
        firewall_stats.backend,
        firewall_stats.blocked_count,
        if blocked_ips.is_empty() {
            "<div class=\"text-gray-500 text-center\">No IPs blocked</div>".to_string()
        } else {
            blocked_ips.iter().map(|ip| format!(
                "<div class=\"flex justify-between items-center p-2 bg-gray-750 rounded\"><span class=\"font-mono text-sm\">{}</span></div>", ip
            )).collect::<Vec<_>>().join("\n")
        }
    );

    Html(html)
}

#[derive(serde::Deserialize)]
pub struct BlockRequest {
    ip: String,
}

#[derive(serde::Deserialize)]
pub struct CustomBlockRequest {
    entry: String,
}

#[derive(serde::Deserialize)]
pub struct ConfigUpdateRequest {
    key: String,
    value: serde_json::Value,
}

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<BlockRequest>,
) -> impl IntoResponse {
    let _ = state.firewall.unblock_ip(&req.ip);
    "OK"
}

pub async fn add_custom_block(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CustomBlockRequest>,
) -> impl IntoResponse {
    state.blocklist.add_custom_block(req.entry);
    "OK"
}

pub async fn update_config(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    let mut config = state.blocklist.get_config();
    match req.key.as_str() {
        "block_trackers" => config.block_trackers = req.value.as_bool().unwrap_or(false),
        "block_malware" => config.block_malware = req.value.as_bool().unwrap_or(false),
        "block_attackers" => config.block_attackers = req.value.as_bool().unwrap_or(false),
        "auto_block_attackers" => {
            config.auto_block_attackers = req.value.as_bool().unwrap_or(false)
        }
        "port_scan_threshold" => {
            config.port_scan_threshold = req.value.as_u64().unwrap_or(10) as u32
        }
        _ => {}
    }
    state.blocklist.update_config(config);
    "OK"
}

pub async fn update_blocklists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let updater = BlocklistUpdater::new(state.blocklist.clone());

    match updater.update_all().await {
        Ok(_) => {
            let stats = state.blocklist.stats();
            serde_json::json!({
                "status": "ok",
                "trackers": stats.trackers,
                "malware": stats.malware,
                "attackers": stats.attackers
            })
            .to_string()
        }
        Err(e) => serde_json::json!({
            "status": "error",
            "message": e
        })
        .to_string(),
    }
}

pub async fn event_stream(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.packet_tx.subscribe();
    let mut alert_rx = state.alert_tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                packet = rx.recv() => {
                    if let Ok(p) = packet {
                        let json = serde_json::to_string(&p).unwrap_or_default();
                        yield Ok(Event::default().event("packet").data(json));
                    }
                }
                alert = alert_rx.recv() => {
                    if let Ok(a) = alert {
                        let json = serde_json::to_string(&a).unwrap_or_default();
                        yield Ok(Event::default().event("alert").data(json));
                    }
                }
            }
        }
    };

    Sse::new(stream)
}

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(vec![Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(false);

    Router::new()
        .route("/", get(index))
        .route("/devices", get(devices))
        .route("/alerts", get(alerts))
        .route("/packets", get(packets))
        .route("/blocking", get(blocking))
        .route("/events", get(event_stream))
        .route("/api/unblock-ip", post(unblock_ip))
        .route("/api/add-block", post(add_custom_block))
        .route("/api/update-config", post(update_config))
        .route("/api/update-blocklists", post(update_blocklists))
        // API v1 routes
        .route("/api/v1/status", get(api_v1_status))
        .route("/api/v1/health", get(api_v1_health))
        .route("/api/v1/login", post(api_v1_login))
        .route("/api/v1/devices", get(api_v1_devices))
        .route("/api/v1/devices/{id}", get(api_v1_device_detail))
        .route("/api/v1/packets", get(api_v1_packets))
        .route("/api/v1/alerts", get(api_v1_alerts))
        .route("/api/v1/blocklist/stats", get(api_v1_blocklist_stats))
        .route("/api/v1/blocklist/ips", get(api_v1_blocked_ips))
        .route("/api/v1/firewall/status", get(api_v1_firewall_status))
        .route("/metrics", get(api_v1_metrics))
        .layer(cors)
        .with_state(state)
}

// API v1 handlers
use axum::response::Json;
use serde_json::json;

async fn api_v1_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.stats.get_stats();
    Json(
        json!({ "success": true, "data": { "version": "1.0.0", "packets": stats.packets, "devices": state.device_manager.get_all().len() } }),
    )
}

async fn api_v1_health() -> Json<serde_json::Value> {
    Json(json!({ "success": true, "data": { "status": "healthy" } }))
}

async fn api_v1_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<crate::auth::LoginRequest>,
) -> Json<serde_json::Value> {
    match state.auth.login(payload) {
        Some(r) => Json(json!({ "success": true, "data": r })),
        None => Json(json!({ "success": false, "error": "Invalid credentials" })),
    }
}

async fn api_v1_devices(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "success": true, "data": state.device_manager.get_all() }))
}

async fn api_v1_device_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match state.device_manager.get_by_mac(&id) {
        Some(d) => Json(json!({ "success": true, "data": d })),
        None => Json(json!({ "success": false, "error": "Not found" })),
    }
}

async fn api_v1_packets(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let packets: Vec<_> = state.packet_cache.read().iter().take(50).cloned().collect();
    Json(json!({ "success": true, "data": packets }))
}

async fn api_v1_alerts(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "success": true, "data": state.anomaly_detector.get_recent_alerts() }))
}

async fn api_v1_blocklist_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.blocklist.stats();
    Json(
        json!({ "success": true, "data": { "trackers": stats.trackers, "malware": stats.malware, "custom": stats.custom } }),
    )
}

async fn api_v1_blocked_ips(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "success": true, "data": state.firewall.get_blocked_ips() }))
}

async fn api_v1_firewall_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.firewall.stats();
    Json(
        json!({ "success": true, "data": { "enabled": stats.enabled, "backend": stats.backend, "blocked_count": stats.blocked_count } }),
    )
}

async fn api_v1_metrics(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    state.metrics.record_request("metrics");
    (axum::http::StatusCode::OK, state.metrics.get_metrics())
}
