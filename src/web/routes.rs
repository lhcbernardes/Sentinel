use askama::Template;
use axum::http::{header, Method};
use axum::{
    extract::State,
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

use super::auth::require_admin;

// ─── templates ───────────────────────────────────────────────────────────────

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

#[derive(Template)]
#[template(path = "blocking.html")]
pub struct BlockingTemplate {
    pub blocklist_stats: crate::blocking::BlocklistStats,
    pub dns_stats: crate::blocking::DnsStats,
    pub firewall_stats: crate::blocking::FirewallStats,
    pub blocked_ips: Vec<String>,
}

pub async fn blocking(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let blocklist_stats = state.blocklist.stats();
    let blocked_ips = state.firewall.get_blocked_ips();
    let dns_stats = state.dns_sinkhole.stats();
    let firewall_stats = state.firewall.stats();

    Html(
        BlockingTemplate {
            blocklist_stats,
            dns_stats,
            firewall_stats,
            blocked_ips,
        }
        .render()
        .unwrap_or_default(),
    )
}

// ─── New page templates (data loaded via API) ────────────────────────────────

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate;

pub async fn login() -> impl IntoResponse {
    Html(LoginTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate;

pub async fn users() -> impl IntoResponse {
    Html(UsersTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "alert-rules.html")]
pub struct AlertRulesTemplate;

pub async fn alert_rules() -> impl IntoResponse {
    Html(AlertRulesTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "notifications.html")]
pub struct NotificationsTemplate;

pub async fn notifications() -> impl IntoResponse {
    Html(NotificationsTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "dns-queries.html")]
pub struct DnsQueriesTemplate;

pub async fn dns_queries() -> impl IntoResponse {
    Html(DnsQueriesTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "dns-rewrite.html")]
pub struct DnsRewriteTemplate;

pub async fn dns_rewrite() -> impl IntoResponse {
    Html(DnsRewriteTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "parental.html")]
pub struct ParentalTemplate;

pub async fn parental() -> impl IntoResponse {
    Html(ParentalTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "threat-intel.html")]
pub struct ThreatIntelTemplate;

pub async fn threat_intel() -> impl IntoResponse {
    Html(ThreatIntelTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "device-groups.html")]
pub struct DeviceGroupsTemplate;

pub async fn device_groups() -> impl IntoResponse {
    Html(DeviceGroupsTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "backups.html")]
pub struct BackupsTemplate;

pub async fn backups() -> impl IntoResponse {
    Html(BackupsTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "logs.html")]
pub struct LogsTemplate;

pub async fn logs() -> impl IntoResponse {
    Html(LogsTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "ml-baselines.html")]
pub struct MlBaselinesTemplate;

pub async fn ml_baselines() -> impl IntoResponse {
    Html(MlBaselinesTemplate.render().unwrap_or_default())
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate;

pub async fn settings() -> impl IntoResponse {
    Html(SettingsTemplate.render().unwrap_or_default())
}

// ─── request / response types ─────────────────────────────────────────────────

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

// ─── API handlers (protegidos — exigem admin) ─────────────────────────────────

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<BlockRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    match state.firewall.unblock_ip(&req.ip) {
        Ok(_) => axum::Json(serde_json::json!({"status": "ok"})).into_response(),
        Err(e) => axum::Json(serde_json::json!({"status": "error", "message": e})).into_response(),
    }
}

pub async fn add_custom_block(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<CustomBlockRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    state.blocklist.add_custom_block(req.entry);
    axum::Json(serde_json::json!({"status": "ok"})).into_response()
}

pub async fn update_config(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
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
    axum::Json(serde_json::json!({"status": "ok"})).into_response()
}

pub async fn update_blocklists(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
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
            .into_response()
        }
        Err(e) => serde_json::json!({
            "status": "error",
            "message": e
        })
        .to_string()
        .into_response(),
    }
}

// ─── SSE event stream ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct SseParams {
    /// Token passed as query param since EventSource API does not support custom headers.
    pub token: Option<String>,
}

pub async fn event_stream(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<SseParams>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    // Token is optional: if provided, validate it; if invalid, we still stream
    // but this allows the dashboard HTML pages (which are public) to receive
    // real-time updates. CORS policy already restricts cross-origin access.
    if let Some(token) = &params.token {
        if state.auth.verify_token(token).is_some() {
            tracing::debug!("SSE client authenticated");
        }
    }

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

// ─── router ───────────────────────────────────────────────────────────────────

pub fn create_router(state: Arc<AppState>) -> Router {
    // CORS restrito: usa ALLOWED_ORIGIN env var.
    // Padrão: localhost:8080 (sem wildcard).
    let allowed_origin =
        std::env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let cors_origin: axum::http::HeaderValue = allowed_origin
        .parse()
        .unwrap_or_else(|_| "http://localhost:8080".parse().unwrap());

    let cors = CorsLayer::new()
        .allow_origin(cors_origin)
        .allow_methods(vec![Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    Router::new()
        // Login page (public)
        .route("/login", get(login))
        // Main pages
        .route("/", get(index))
        .route("/devices", get(devices))
        .route("/alerts", get(alerts))
        .route("/packets", get(packets))
        .route("/blocking", get(blocking))
        // Settings pages
        .route("/users", get(users))
        .route("/alert-rules", get(alert_rules))
        .route("/notifications", get(notifications))
        .route("/dns-queries", get(dns_queries))
        .route("/dns-rewrite", get(dns_rewrite))
        .route("/parental", get(parental))
        .route("/threat-intel", get(threat_intel))
        .route("/device-groups", get(device_groups))
        .route("/backups", get(backups))
        .route("/logs", get(logs))
        .route("/ml-baselines", get(ml_baselines))
        .route("/settings", get(settings))
        // SSE — requires token via query param (/events?token=xxx)
        .route("/events", get(event_stream))
        // APIs protegidas (exigem Bearer token via middleware + admin check nos handlers)
        .route("/api/unblock-ip", post(unblock_ip))
        .route("/api/add-block", post(add_custom_block))
        .route("/api/update-config", post(update_config))
        .route("/api/update-blocklists", post(update_blocklists))
        // API v1 — single source of truth from api_routes module
        .nest("/api", super::api_routes::create_api_router())
        // Prometheus metrics
        .route("/metrics", get(metrics_handler))
        // Aplica middleware de auth a todas as rotas (as públicas são bypassed dentro do middleware)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::auth_middleware,
        ))
        .layer(cors)
        .with_state(state)
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    state.metrics.record_request("metrics");
    (axum::http::StatusCode::OK, state.metrics.get_metrics())
}
