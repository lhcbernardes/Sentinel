use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::UserRole;
use crate::AppState;

use crate::web::api::{
    ApiResponse, BlocklistResponse, DnsQueryResponse, StatusResponse, TrafficStatsResponse,
};
use crate::web::auth::{require_admin, require_auth};

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(50),
        }
    }
}

pub fn create_api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/status", get(api_status))
        .route("/v1/health", get(api_health))
        .route("/v1/login", post(api_login))
        .route("/v1/logout", post(api_logout))
        .route("/v1/refresh", post(api_refresh))
        .route("/v1/devices", get(api_devices_list))
        .route("/v1/devices/:id", get(api_device_detail))
        .route("/v1/packets", get(api_packets_list))
        .route("/v1/packets/stats", get(api_packets_stats))
        .route("/v1/alerts", get(api_alerts_list))
        .route("/v1/dns/queries", get(api_dns_queries))
        .route("/v1/dns/stats", get(api_dns_stats))
        .route("/v1/blocklist/stats", get(api_blocklist_stats))
        .route("/v1/blocklist/ips", get(api_blocked_ips))
        .route("/v1/blocklist/ips", post(api_block_ip))
        .route("/v1/blocklist/ips/:ip", delete(api_unblock_ip))
        .route("/v1/blocklist/domains", post(api_block_domain))
        .route("/v1/blocklist/update", post(api_update_blocklist))
        .route("/v1/firewall/status", get(api_firewall_status))
        .route("/v1/firewall/rules", get(api_firewall_rules))
        .route("/v1/traffic/stats", get(api_traffic_stats))
        .route("/v1/traffic/flows", get(api_traffic_flows))
        .route("/v1/config", get(api_config_get))
        .route("/v1/users", get(api_users_list))
        .route("/v1/users", post(api_user_create))
        .route("/v1/users/:username", get(api_user_detail))
        .route("/v1/users/:username/password", put(api_user_password))
        .route("/v1/netflow/collect", post(api_netflow_collect))
        .route("/v1/netflow/stats", get(api_netflow_stats))
        .route("/v1/dpi/inspect", post(api_dpi_inspect))
        .route("/v1/dpi/stats", get(api_dpi_stats))
        .route("/v1/export/siem", get(api_export_siem))
}

// ─── status / health ──────────────────────────────────────────────────────────

async fn api_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats.get_stats();
    let status = StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0,
        blocks_active: true,
        dns_enabled: false,
        packet_count: stats.packets,
        device_count: state.device_manager.get_all().len(),
        alert_count: state.anomaly_detector.get_recent_alerts().len() as u64,
    };
    Json(ApiResponse::ok(status))
}

async fn api_health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "healthy", "timestamp": chrono::Utc::now().to_rfc3339() }))
}

// ─── autenticação ─────────────────────────────────────────────────────────────

async fn api_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<crate::auth::LoginRequest>,
) -> impl IntoResponse {
    match state.auth.login(payload) {
        Ok(r) => (StatusCode::OK, Json(ApiResponse::ok(r))).into_response(),
        Err(e) => (StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}

async fn api_logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        state.auth.logout(token);
    }
    Json(ApiResponse::ok("Logged out"))
}

/// Renova um token válido sem exigir senha novamente.
/// O token antigo é revogado e um novo token é emitido.
async fn api_refresh(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = match headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("Token não fornecido".to_string())),
            )
                .into_response()
        }
    };

    match state.auth.renew_token(&token) {
        Some(r) => (StatusCode::OK, Json(ApiResponse::ok(r))).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::err(
                "Token inválido ou expirado".to_string(),
            )),
        )
            .into_response(),
    }
}

// ─── dispositivos ─────────────────────────────────────────────────────────────

async fn api_devices_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let devices = state.device_manager.get_all();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let devices: Vec<_> = devices
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .collect();
    Json(ApiResponse::ok(devices))
}

async fn api_device_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.device_manager.get_by_mac(&id) {
        Some(d) => Json(ApiResponse::ok(d)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::err("Device not found".to_string())),
        )
            .into_response(),
    }
}

// ─── pacotes ──────────────────────────────────────────────────────────────────

async fn api_packets_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let packets: Vec<_> = state.packet_cache.read().iter().cloned().collect();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let packets: Vec<_> = packets
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .collect();
    Json(ApiResponse::ok(packets))
}

async fn api_packets_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packets: Vec<_> = state.packet_cache.read().iter().cloned().collect();
    let total = packets.len();
    let total_bytes: u64 = packets.iter().map(|p| p.size as u64).sum();
    Json(ApiResponse::ok(
        serde_json::json!({ "total_packets": total, "total_bytes": total_bytes }),
    ))
}

// ─── alertas ─────────────────────────────────────────────────────────────────

async fn api_alerts_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let alerts = state.anomaly_detector.get_recent_alerts();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let alerts: Vec<_> = alerts
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .collect();
    Json(ApiResponse::ok(alerts))
}

// ─── DNS ──────────────────────────────────────────────────────────────────────

async fn api_dns_queries(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let queries = state.dns_sinkhole.get_recent_queries();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let queries: Vec<_> = queries
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .map(|q| crate::web::api::DnsQuery {
            timestamp: q.timestamp,
            client_ip: q.client_ip,
            domain: q.domain,
            blocked: q.blocked,
            block_type: q.block_type,
        })
        .collect();
    let blocked_count = queries.iter().filter(|q| q.blocked).count();
    Json(ApiResponse::ok(DnsQueryResponse {
        queries: queries.clone(),
        total: queries.len(),
        blocked_count,
    }))
}

async fn api_dns_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.dns_sinkhole.stats();
    Json(ApiResponse::ok(
        serde_json::json!({ "queries": stats.queries, "blocked": stats.blocked }),
    ))
}

// ─── blocklist (exige admin para mutação) ─────────────────────────────────────

async fn api_blocklist_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.blocklist.stats();
    Json(ApiResponse::ok(BlocklistResponse {
        trackers: stats.trackers,
        malware: stats.malware,
        attackers: stats.attackers,
        custom: stats.custom,
        total: stats.trackers + stats.malware + stats.attackers + stats.custom,
    }))
}

async fn api_blocked_ips(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ApiResponse::ok(state.firewall.get_blocked_ips()))
}

async fn api_block_ip(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<BlockIpRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    match state.firewall.block_ip(&payload.ip) {
        Ok(_) => Json(ApiResponse::ok(())).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}

async fn api_unblock_ip(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    match state.firewall.unblock_ip(&ip) {
        Ok(_) => Json(ApiResponse::ok(())).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}

async fn api_block_domain(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<BlockDomainRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    state.blocklist.add_custom_block(payload.domain);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_update_blocklist(
    State(_state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&_state, &headers) {
        return resp;
    }
    Json(ApiResponse::ok("Blocklist update initiated")).into_response()
}

// ─── firewall ─────────────────────────────────────────────────────────────────

async fn api_firewall_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.firewall.stats();
    Json(ApiResponse::ok(
        serde_json::json!({ "enabled": stats.enabled, "backend": stats.backend, "blocked_count": stats.blocked_count }),
    ))
}

async fn api_firewall_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ips = state.firewall.get_blocked_ips();
    let rules: Vec<_> = ips
        .iter()
        .map(|ip| serde_json::json!({ "ip": ip, "action": "block" }))
        .collect();
    Json(ApiResponse::ok(rules))
}

// ─── tráfego ─────────────────────────────────────────────────────────────────

async fn api_traffic_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packets: Vec<_> = state.packet_cache.read().iter().cloned().collect();
    let total_bytes: u64 = packets.iter().map(|p| p.size as u64).sum();
    let mut protocol_counts = std::collections::HashMap::new();
    for p in &packets {
        *protocol_counts.entry(p.protocol.to_string()).or_insert(0u64) += 1;
    }
    let mut top_protocols: Vec<_> = protocol_counts.into_iter().collect();
    top_protocols.sort_by(|a, b| b.1.cmp(&a.1));
    top_protocols.truncate(5);
    Json(ApiResponse::ok(TrafficStatsResponse {
        total_bytes,
        total_packets: packets.len() as u64,
        bytes_per_second: 0.0,
        packets_per_second: 0.0,
        top_protocols,
        top_talkers: vec![],
    }))
}

async fn api_traffic_flows(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let flows: Vec<_> = state.netflow_collector.read().iter().cloned().collect();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let flows: Vec<_> = flows
        .into_iter()
        .skip((page - 1) * limit)
        .take(limit)
        .map(|f| {
            serde_json::json!({ "src_addr": f.src_addr, "dst_addr": f.dst_addr, "bytes": f.bytes })
        })
        .collect();
    Json(ApiResponse::ok(flows))
}

// ─── config ───────────────────────────────────────────────────────────────────

async fn api_config_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    // TODO: retornar configuração real do blocklist
    Json(ApiResponse::ok(
        serde_json::json!({ "block_trackers": true, "block_malware": true }),
    ))
    .into_response()
}

// ─── gerenciamento de usuários (exige auth / admin) ───────────────────────────

/// Lista usuários — exige autenticação.
async fn api_users_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    Json(ApiResponse::ok(state.auth.list_users())).into_response()
}

/// Cria usuário — exige role admin.
async fn api_user_create(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    let role = if payload.admin {
        UserRole::Admin
    } else {
        UserRole::Viewer
    };
    if state.auth.add_user(payload.username, payload.password, role) {
        Json(ApiResponse::ok(())).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::err("Usuário já existe".to_string())),
        )
            .into_response()
    }
}

async fn api_user_detail(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    let users = state.auth.list_users();
    match users.into_iter().find(|u| u.username == username) {
        Some(u) => Json(ApiResponse::ok(u)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::err("Usuário não encontrado".to_string())),
        )
            .into_response(),
    }
}

/// Troca de senha com verificação de autorização:
/// - Admin pode trocar qualquer senha sem fornecer a senha atual.
/// - Usuário comum só pode trocar a própria senha e DEVE fornecer `old_password`.
async fn api_user_password(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let caller = match require_auth(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    if caller.role != "admin" {
        // Usuário comum: só pode alterar a própria senha
        if caller.sub != username {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<()>::err(
                    "Não é permitido alterar a senha de outro usuário".to_string(),
                )),
            )
                .into_response();
        }
        // E deve fornecer a senha atual
        match &payload.old_password {
            Some(old) => {
                if !state.auth.verify_current_password(&username, old) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ApiResponse::<()>::err("Senha atual incorreta".to_string())),
                    )
                        .into_response();
                }
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::<()>::err(
                        "old_password é obrigatório".to_string(),
                    )),
                )
                    .into_response();
            }
        }
    }

    if state.auth.change_password(&username, &payload.new_password) {
        Json(ApiResponse::ok(())).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::err("Usuário não encontrado".to_string())),
        )
            .into_response()
    }
}

// ─── netflow ─────────────────────────────────────────────────────────────────

async fn api_netflow_collect(
    State(state): State<Arc<AppState>>,
    Json(flow): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut c = state.netflow_collector.write();
    if let Ok(r) = serde_json::from_value::<crate::NetFlowRecord>(flow) {
        c.push(r);
        // Cap para evitar OOM sob alta carga
        if c.len() > 10_000 {
            c.drain(0..5_000);
        }
    }
    Json(ApiResponse::ok(())).into_response()
}

async fn api_netflow_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let flows = state.netflow_collector.read();
    Json(ApiResponse::ok(serde_json::json!({ "flows": flows.len() })))
}

// ─── DPI ─────────────────────────────────────────────────────────────────────

async fn api_dpi_inspect(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DpiInspectRequest>,
) -> impl IntoResponse {
    let r = state.dpi_engine.inspect(&payload.data, &payload.protocol);
    Json(ApiResponse::ok(
        serde_json::json!({ "application": r.application, "risk_level": r.risk_level }),
    ))
}

async fn api_dpi_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let s = state.dpi_engine.get_stats();
    Json(ApiResponse::ok(
        serde_json::json!({ "packets_inspected": s.packets_inspected }),
    ))
}

// ─── SIEM export ──────────────────────────────────────────────────────────────

async fn api_export_siem(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<SiemParams>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    let logs: Vec<_> = state.logs.get_recent(100);
    let format = params.format.as_deref().unwrap_or("syslog");
    let data = match format {
        "json" => serde_json::to_string(&logs).unwrap_or_default(),
        _ => logs
            .iter()
            .map(|l| l.message.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    };
    Json(ApiResponse::ok(data)).into_response()
}

// ─── request structs ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct BlockIpRequest {
    ip: String,
}

#[derive(serde::Deserialize)]
struct BlockDomainRequest {
    domain: String,
}

#[derive(serde::Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    admin: bool,
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    /// Senha atual (obrigatória para usuários comuns, ignorada para admins).
    old_password: Option<String>,
    new_password: String,
}

#[derive(serde::Deserialize)]
struct DpiInspectRequest {
    data: String,
    protocol: String,
}

#[derive(serde::Deserialize)]
struct SiemParams {
    format: Option<String>,
}
