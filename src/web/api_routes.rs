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
    GeoBlockRequest, GeoStatusResponse,
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
        .route("/v1/devices/{id}", get(api_device_detail))
        .route("/v1/packets", get(api_packets_list))
        .route("/v1/packets/stats", get(api_packets_stats))
        .route("/v1/alerts", get(api_alerts_list))
        .route("/v1/dns/queries", get(api_dns_queries))
        .route("/v1/dns/stats", get(api_dns_stats))
        .route("/v1/blocklist/stats", get(api_blocklist_stats))
        .route("/v1/blocklist/ips", get(api_blocked_ips))
        .route("/v1/blocklist/ips", post(api_block_ip))
        .route("/v1/blocklist/ips/{ip}", delete(api_unblock_ip))
        .route("/v1/blocklist/domains", post(api_block_domain))
        .route("/v1/blocklist/domains", delete(api_unblock_domain))
        .route("/v1/blocklist/update", post(api_update_blocklist))
        .route("/v1/firewall/status", get(api_firewall_status))
        .route("/v1/firewall/rules", get(api_firewall_rules))
        .route("/v1/traffic/stats", get(api_traffic_stats))
        .route("/v1/traffic/flows", get(api_traffic_flows))
        .route("/v1/config", get(api_config_get))
        .route("/v1/users", get(api_users_list))
        .route("/v1/users", post(api_user_create))
        .route("/v1/users/{username}", get(api_user_detail))
        .route("/v1/users/{username}", delete(api_user_delete))
        .route("/v1/users/{username}/password", put(api_user_password))
        .route("/v1/netflow/collect", post(api_netflow_collect))
        .route("/v1/netflow/stats", get(api_netflow_stats))
        .route("/v1/dpi/inspect", post(api_dpi_inspect))
        .route("/v1/dpi/stats", get(api_dpi_stats))
        .route("/v1/export/siem", get(api_export_siem))
        .route("/v1/parental/config", get(api_parental_config_get))
        .route("/v1/parental/config", put(api_parental_config_put))
        .route("/v1/backups", get(api_backups_list))
        .route("/v1/backups", post(api_backups_create))
        .route("/v1/backups/config", get(api_backup_config_get))
        .route("/v1/backups/config", put(api_backup_config_put))
        .route("/v1/backups/restore", post(api_backup_restore_upload))
        .route("/v1/backups/{id}", delete(api_backups_delete))
        .route("/v1/backups/{id}/restore", post(api_backup_restore_specific))
        .route("/v1/alerts/rules", get(api_alert_rules_list))
        .route("/v1/alerts/rules", post(api_alert_rules_create))
        .route("/v1/alerts/rules/{id}", put(api_alert_rules_update))
        .route("/v1/alerts/rules/{id}", delete(api_alert_rules_delete))
        .route("/v1/notifications/config", get(api_notifications_config_get))
        .route("/v1/notifications/config", put(api_notifications_config_put))
        .route("/v1/notifications/test/{channel}", post(api_notifications_test_channel))
        .route("/v1/threatintel/stats", get(api_threat_intel_stats_get))
        .route("/v1/threatintel/lookup", post(api_threat_intel_lookup))
        .route("/v1/threatintel/config", get(api_threat_intel_config_get))
        .route("/v1/threatintel/config", put(api_threat_intel_config_put))
        .route("/v1/threatintel/update", post(api_threat_intel_update_post))
        .route("/v1/logs", get(api_logs_list))
        .route("/v1/ml/baselines", get(api_ml_baselines_get))
        .route("/v1/ml/anomalies", get(api_ml_anomalies_get))
        .route("/v1/ml/baselines/{id}", delete(api_ml_baseline_delete))
        .route("/v1/device-groups", get(api_device_groups_get))
        .route("/v1/device-groups", put(api_device_groups_put))
        .route("/v1/device-groups/policies", put(api_device_groups_policies_put))
        // DNS Rewrite
        .route("/v1/dns/rewrite", get(api_dns_rewrite_list))
        .route("/v1/dns/rewrite", post(api_dns_rewrite_add))
        .route("/v1/dns/rewrite/{domain}", put(api_dns_rewrite_update))
        .route("/v1/dns/rewrite/{domain}", delete(api_dns_rewrite_delete))
        // Geo-Blocking
        .route("/v1/firewall/geo/status", get(api_geo_status))
        .route("/v1/firewall/geo/block", post(api_geo_block_country))
        .route("/v1/firewall/geo/unblock/{code}", delete(api_geo_unblock_country))
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
    // Validate domain
    let domain = payload.domain.trim().to_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(
                "Domain must be between 1 and 253 characters".to_string(),
            )),
        )
            .into_response();
    }
    if !domain.contains('.') || domain.contains(' ') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err("Invalid domain format".to_string())),
        )
            .into_response();
    }
    state.blocklist.add_custom_block(domain);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_unblock_domain(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<BlockDomainRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    state.blocklist.remove_custom_block(&payload.domain);
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
        *protocol_counts
            .entry(p.protocol.to_string())
            .or_insert(0u64) += 1;
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
    let role = match payload.role.as_str() {
        "admin" => UserRole::Admin,
        _ => UserRole::Viewer,
    };
    match state
        .auth
        .add_user(payload.username, payload.password, role)
    {
        Ok(true) => Json(ApiResponse::ok(())).into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::err("Usuário já existe".to_string())),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::err(format!(
                "Erro ao criar usuário: {}",
                e
            ))),
        )
            .into_response(),
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

    match state.auth.change_password(&username, &payload.new_password) {
        Ok(true) => Json(ApiResponse::ok(())).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::err("Usuário não encontrado".to_string())),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::err(format!(
                "Erro ao alterar senha: {}",
                e
            ))),
        )
            .into_response(),
    }
}

/// Remove usuário — exige role admin.
async fn api_user_delete(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let caller = match require_admin(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Impede que o usuário exclua a si mesmo
    if caller.sub == username {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(
                "Você não pode remover seu próprio usuário".to_string(),
            )),
        )
            .into_response();
    }

    match state.auth.delete_user(&username) {
        Ok(true) => Json(ApiResponse::ok(())).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::err("Usuário não encontrado".to_string())),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(e)),
        )
            .into_response(),
    }
}

// ─── netflow ─────────────────────────────────────────────────────────────────

async fn api_netflow_collect(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(flow): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    let mut c = state.netflow_collector.write();
    if let Ok(r) = serde_json::from_value::<crate::NetFlowRecord>(flow) {
        c.push_back(r);
        // Cap para evitar OOM sob alta carga — drop oldest entries
        while c.len() > 10_000 {
            c.pop_front();
        }
    }
    Json(ApiResponse::ok(())).into_response()
}

async fn api_netflow_stats(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    let flows = state.netflow_collector.read();
    Json(ApiResponse::ok(serde_json::json!({ "flows": flows.len() }))).into_response()
}

// ─── DPI ─────────────────────────────────────────────────────────────────────

async fn api_dpi_inspect(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<DpiInspectRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    // Limit payload size to prevent resource exhaustion (1MB max)
    if payload.data.len() > 1_048_576 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err(
                "Payload too large (max 1MB)".to_string(),
            )),
        )
            .into_response();
    }
    let r = state.dpi_engine.inspect(&payload.data, &payload.protocol);
    Json(ApiResponse::ok(
        serde_json::json!({ "application": r.application, "risk_level": r.risk_level }),
    ))
    .into_response()
}

async fn api_dpi_stats(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    let s = state.dpi_engine.get_stats();
    Json(ApiResponse::ok(
        serde_json::json!({ "packets_inspected": s.packets_inspected }),
    ))
    .into_response()
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

async fn api_parental_config_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    Json(ApiResponse::ok(state.parental_control.get_config())).into_response()
}

async fn api_parental_config_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<crate::blocking::parental::ParentalConfig>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    state.parental_control.update_config(payload);
    Json(ApiResponse::ok(())).into_response()
}

// ─── alert rules ──────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct AlertRuleWeb {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub rule_type: String,
    pub condition: String,
    pub severity: String,
    pub actions: Vec<String>,
    pub trigger_count: u32,
    pub cooldown_minutes: u32,
}

async fn api_alert_rules_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let rules = state.alert_rules.get_rules();
    let stats = state.alert_rules.get_stats();
    
    let web_rules: Vec<AlertRuleWeb> = rules.into_iter().map(|r| {
        let id = r.id.clone();
        let trigger_count = *stats.get(&id).unwrap_or(&0);
        
        AlertRuleWeb {
            id: r.id,
            name: r.name,
            description: r.description,
            enabled: r.enabled,
            rule_type: format!("{:?}", r.condition), // Simplified for now
            condition: format!("{:?}", r.condition),
            severity: format!("{:?}", r.severity),
            actions: vec![format!("{:?}", r.action)],
            trigger_count,
            cooldown_minutes: r.cooldown_seconds / 60,
        }
    }).collect();
    
    Json(ApiResponse::ok(web_rules)).into_response()
}

async fn api_alert_rules_create(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AlertRuleWeb>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    // Convert Web Rule to Internal Rule
    // Basic mapping for now to satisfy the UI
    let condition = match payload.rule_type.as_str() {
        "Threshold" => crate::alerts::AlertCondition::Threshold {
            metric: "packets".to_string(), // Default
            value: 100.0,
            operator: crate::alerts::ComparisonOp::GreaterThan,
        },
        _ => crate::alerts::AlertCondition::Anomaly {
            score: 0.8,
            device_id: None,
        },
    };
    
    let action = crate::alerts::AlertAction::Log;
    let severity = match payload.severity.as_str() {
        "Critical" => crate::alerts::rules::AlertSeverity::Critical,
        "High" => crate::alerts::rules::AlertSeverity::High,
        "Low" => crate::alerts::rules::AlertSeverity::Low,
        "Info" => crate::alerts::rules::AlertSeverity::Info,
        _ => crate::alerts::rules::AlertSeverity::Medium,
    };
    
    let mut rule = crate::alerts::AlertRule::new(
        payload.name,
        condition,
        action,
        severity,
    );
    rule.description = payload.description;
    rule.cooldown_seconds = payload.cooldown_minutes * 60;
    
    state.alert_rules.add_rule(rule);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_alert_rules_update(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<AlertRuleWeb>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    state.alert_rules.set_rule_enabled(&id, payload.enabled);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_alert_rules_delete(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    state.alert_rules.remove_rule(&id);
    Json(ApiResponse::ok(())).into_response()
}

// ─── notifications ────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct NotificationConfigWeb {
    pub telegram: TelegramWeb,
    pub slack: SlackWeb,
    pub email: EmailWeb,
    pub min_severity: String,
    pub notify_new_device: bool,
    pub notify_portscan: bool,
    pub notify_blocked_domain: bool,
    pub notify_blocked_ip: bool,
    pub notify_critical: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TelegramWeb {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SlackWeb {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EmailWeb {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub recipients: String,
}

async fn api_notifications_config_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let alert_config = state.alerts.get_config();
    let notif_config = state.notifications.get_config();
    
    let telegram = notif_config.telegram.unwrap_or(crate::notifications::TelegramConfig {
        enabled: false,
        bot_token: "".to_string(),
        chat_ids: vec![],
    });
    
    let slack = notif_config.slack.unwrap_or(crate::notifications::SlackConfig {
        enabled: false,
        webhook_url: "".to_string(),
        channel: None,
    });
    
    let email = notif_config.email.unwrap_or(crate::notifications::EmailConfig {
        enabled: false,
        smtp_server: "".to_string(),
        smtp_port: 587,
        username: "".to_string(),
        password: "".to_string(),
        from_email: "".to_string(),
        to_emails: vec![],
    });
    
    let config_web = NotificationConfigWeb {
        telegram: TelegramWeb {
            enabled: telegram.enabled,
            bot_token: telegram.bot_token,
            chat_id: telegram.chat_ids.get(0).cloned().unwrap_or_default(),
        },
        slack: SlackWeb {
            enabled: slack.enabled,
            webhook_url: slack.webhook_url,
        },
        email: EmailWeb {
            enabled: email.enabled,
            smtp_host: email.smtp_server,
            smtp_port: email.smtp_port,
            username: email.username,
            password: email.password,
            recipients: email.to_emails.join(", "),
        },
        min_severity: format!("{:?}", alert_config.min_severity),
        notify_new_device: alert_config.notify_new_device,
        notify_portscan: alert_config.notify_port_scan,
        notify_blocked_domain: alert_config.notify_blocked_domain,
        notify_blocked_ip: alert_config.notify_blocked_ip,
        notify_critical: alert_config.notify_critical,
    };
    
    Json(ApiResponse::ok(config_web)).into_response()
}

async fn api_notifications_config_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<NotificationConfigWeb>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    // Update NotificationManager
    let _ = state.notifications.configure_telegram(crate::notifications::TelegramConfig {
        enabled: payload.telegram.enabled,
        bot_token: payload.telegram.bot_token,
        chat_ids: vec![payload.telegram.chat_id],
    });
    
    let _ = state.notifications.configure_slack(crate::notifications::SlackConfig {
        enabled: payload.slack.enabled,
        webhook_url: payload.slack.webhook_url,
        channel: None,
    });
    
    let _ = state.notifications.configure_email(crate::notifications::EmailConfig {
        enabled: payload.email.enabled,
        smtp_server: payload.email.smtp_host,
        smtp_port: payload.email.smtp_port,
        from_email: payload.email.username.clone(), // Default to username
        username: payload.email.username,
        password: payload.email.password,
        to_emails: payload.email.recipients.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    });
    
    // Update AlertManager
    let min_severity = match payload.min_severity.as_str() {
        "Critical" => crate::alerts::AlertSeverity::Critical,
        "Error" | "High" => crate::alerts::AlertSeverity::Error,
        "Warning" | "Medium" => crate::alerts::AlertSeverity::Warning,
        _ => crate::alerts::AlertSeverity::Info,
    };
    
    state.alerts.update_config(crate::alerts::AlertConfig {
        notify_new_device: payload.notify_new_device,
        notify_port_scan: payload.notify_portscan,
        notify_blocked_domain: payload.notify_blocked_domain,
        notify_blocked_ip: payload.notify_blocked_ip,
        notify_critical: payload.notify_critical,
        min_severity,
    });
    
    Json(ApiResponse::ok(())).into_response()
}

async fn api_notifications_test_channel(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(channel): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    let message = crate::notifications::NotificationMessage {
        title: "Sentinel-RS Test".to_string(),
        message: format!("This is a test notification from Sentinel-RS for the {} channel.", channel),
        severity: crate::notifications::NotificationSeverity::Info,
        timestamp: chrono::Utc::now().timestamp(),
        source: "Sentinel-RS Dashboard".to_string(),
    };
    
    let _ = state.notifications.send(message).await;
    
    Json(ApiResponse::ok(())).into_response()
}

// ─── threat intel ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct ThreatStatsWeb {
    pub malicious_ips: usize,
    pub malicious_domains: usize,
    pub feeds_enabled: usize,
    pub last_update: i64,
}

#[derive(serde::Serialize)]
struct ThreatLookupResultWeb {
    pub malicious: bool,
    pub indicator: String,
    pub r#type: String,
    pub threat_type: Option<String>,
    pub confidence: u8,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ThreatConfigWeb {
    pub auto_block: bool,
    pub feeds: ThreatFeedsWeb,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ThreatFeedsWeb {
    pub urlhaus: bool,
    pub emerging_threats: bool,
    pub abuseipdb: bool,
}

async fn api_threat_intel_stats_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let stats = state.threat_intel.get_stats();
    let feeds_enabled = 2; // Fixed for now
    
    Json(ApiResponse::ok(ThreatStatsWeb {
        malicious_ips: stats.blocked_ips,
        malicious_domains: stats.blocked_domains,
        feeds_enabled,
        last_update: stats.last_update,
    })).into_response()
}

#[derive(serde::Deserialize)]
struct LookupRequest {
    indicator: String,
}

async fn api_threat_intel_lookup(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<LookupRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let indicator = payload.indicator.trim();
    
    let result = if indicator.contains('.') && !indicator.chars().all(|c| c.is_numeric() || c == '.') {
        state.threat_intel.check_domain(indicator)
    } else {
        state.threat_intel.check_ip(indicator)
    };
    
    match result {
        Some(entry) => {
            Json(ApiResponse::ok(ThreatLookupResultWeb {
                malicious: entry.is_malicious(),
                indicator: entry.indicator,
                r#type: format!("{:?}", entry.threat_type),
                threat_type: Some(format!("{:?}", entry.threat_type)),
                confidence: entry.confidence,
            })).into_response()
        }
        None => {
            Json(ApiResponse::ok(ThreatLookupResultWeb {
                malicious: false,
                indicator: indicator.to_string(),
                r#type: "Unknown".to_string(),
                threat_type: None,
                confidence: 0,
            })).into_response()
        }
    }
}

async fn api_threat_intel_config_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    Json(ApiResponse::ok(ThreatConfigWeb {
        auto_block: state.threat_intel.is_enabled(),
        feeds: ThreatFeedsWeb {
            urlhaus: true,
            emerging_threats: true,
            abuseipdb: false,
        },
    })).into_response()
}

async fn api_threat_intel_config_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<ThreatConfigWeb>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    state.threat_intel.set_enabled(payload.auto_block);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_threat_intel_update_post(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    let _ = state.threat_intel.update_all().await;
    Json(ApiResponse::ok(())).into_response()
}

// ─── logs ────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct LogWeb {
    pub timestamp: i64,
    pub level: String,
    pub message: String,
    pub source: String,
}

async fn api_logs_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let logs = state.logs.get_recent(1000);
    let web_logs: Vec<LogWeb> = logs.into_iter().map(|l| {
        let level = match l.level {
            crate::logs::LogLevel::Debug => "debug",
            crate::logs::LogLevel::Info => "info",
            crate::logs::LogLevel::Warning => "warn",
            crate::logs::LogLevel::Error => "error",
            crate::logs::LogLevel::Critical => "error",
        }.to_string();
        
        LogWeb {
            timestamp: l.timestamp,
            level,
            message: l.message,
            source: l.category,
        }
    }).collect();
    
    Json(ApiResponse::ok(web_logs)).into_response()
}

// ─── ml ──────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct DeviceBaselineWeb {
    pub device_id: String,
    pub learned_at: i64,
    pub avg_traffic: f64,
    pub peak_traffic: f64,
    pub avg_connections: usize,
    pub sensitivity: f64,
}

#[derive(serde::Serialize)]
struct AnomalyWeb {
    pub id: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub severity: String,
    pub description: String,
    pub detected_at: i64,
}

async fn api_ml_baselines_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let detector = state.ml_detector.read();
    let baselines = detector.get_all_baselines();
    let thresholds = detector.get_thresholds();
    
    let web_baselines: Vec<DeviceBaselineWeb> = baselines.into_iter().map(|b| {
        DeviceBaselineWeb {
            device_id: b.device_id,
            learned_at: b.learned_at,
            avg_traffic: b.avg_bytes_per_sec,
            peak_traffic: b.avg_bytes_per_sec * 1.5, // Estimated for UI
            avg_connections: b.common_ports.len(),
            sensitivity: (1.0 / thresholds.high_traffic_multiplier) * 100.0,
        }
    }).collect();
    
    Json(ApiResponse::ok(web_baselines)).into_response()
}

async fn api_ml_anomalies_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let detector = state.ml_detector.read();
    let anomalies = detector.get_recent_anomalies(50);
    
    let web_anomalies: Vec<AnomalyWeb> = anomalies.into_iter().map(|a| {
        let severity = if a.severity > 0.8 { "Critical" }
                      else if a.severity > 0.6 { "High" }
                      else if a.severity > 0.4 { "Medium" }
                      else { "Low" };
                      
        AnomalyWeb {
            id: format!("anom-{}", a.timestamp),
            type_name: format!("{:?}", a.anomaly_type),
            severity: severity.to_string(),
            description: a.description,
            detected_at: a.timestamp,
        }
    }).collect();
    
    Json(ApiResponse::ok(web_anomalies)).into_response()
}

async fn api_ml_baseline_delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    state.ml_detector.write().clear_baseline(&id);
    Json(ApiResponse::ok(())).into_response()
}

// ─── device groups ────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct DeviceGroupWeb {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub devices: Vec<crate::devices::Device>,
    pub policies: crate::blocking::client_manager::GroupPolicies,
}

async fn api_device_groups_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let manager = &state.client_manager;
    let mut web_groups = Vec::new();
    
    let all_ids = manager.get_all_group_ids();
    for id in all_ids {
        let group = crate::blocking::client_manager::DeviceGroup::from_id(id).unwrap();
        let name = match group {
            crate::blocking::client_manager::DeviceGroup::Trusted => "Trusted",
            crate::blocking::client_manager::DeviceGroup::Kids => "Kids",
            crate::blocking::client_manager::DeviceGroup::Guests => "Guests",
            crate::blocking::client_manager::DeviceGroup::IoT => "IoT",
            crate::blocking::client_manager::DeviceGroup::Default => "Default",
        };
        let icon = match group {
            crate::blocking::client_manager::DeviceGroup::Trusted => "🛡️",
            crate::blocking::client_manager::DeviceGroup::Kids => "👶",
            crate::blocking::client_manager::DeviceGroup::Guests => "👥",
            crate::blocking::client_manager::DeviceGroup::IoT => "📡",
            crate::blocking::client_manager::DeviceGroup::Default => "⚙️",
        };
        
        let macs = manager.get_members_for_group(group);
        let mut devices = Vec::new();
        for mac in macs {
            if let Some(device) = state.device_manager.get_by_mac(&mac) {
                devices.push(device);
            }
        }
        
        web_groups.push(DeviceGroupWeb {
            id: id.to_string(),
            name: name.to_string(),
            icon: icon.to_string(),
            devices,
            policies: manager.get_policies(group),
        });
    }
    
    Json(ApiResponse::ok(web_groups)).into_response()
}

#[derive(serde::Deserialize)]
struct GroupUpdate {
    id: String,
    devices: Vec<String>,
}

async fn api_device_groups_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Vec<GroupUpdate>>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    for update in payload {
        for mac in update.devices {
            state.client_manager.assign_device(mac, &update.id);
        }
    }
    
    Json(ApiResponse::ok(())).into_response()
}

#[derive(serde::Deserialize)]
struct PolicyUpdate {
    id: String,
    policies: crate::blocking::client_manager::GroupPolicies,
}

async fn api_device_groups_policies_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Vec<PolicyUpdate>>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    for update in payload {
        state.client_manager.update_policies(&update.id, update.policies);
    }
    
    Json(ApiResponse::ok(())).into_response()
}

// ─── backups ──────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct BackupInfo {
    id: String,
    name: String,
    size: u64,
    created_at: i64,
}

async fn api_backups_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    
    let backups = state.backup.list_backups();
    let info: Vec<BackupInfo> = backups
        .into_iter()
        .map(|m| BackupInfo {
            id: m.filename.clone(),
            name: m.filename,
            size: m.size_bytes,
            created_at: m.timestamp * 1000, // Convert to ms for JS
        })
        .collect();
        
    Json(ApiResponse::ok(info)).into_response()
}

async fn api_backups_create(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    // We pass None for now as direct DB/Blocklist data isn't needed for basic config backup
    match state.backup.create_backup(None, None) {
        Ok(_) => Json(ApiResponse::ok(())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}

async fn api_backup_config_get(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp.into_response();
    }
    Json(ApiResponse::ok(state.backup.get_config())).into_response()
}

async fn api_backup_config_put(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<crate::backup::BackupConfig>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    state.backup.configure(payload);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_backups_delete(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    match state.backup.delete_backup(&id) {
        Ok(_) => Json(ApiResponse::ok(())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}
// ─── DNS Rewrite ─────────────────────────────────────────────────────────────

async fn api_dns_rewrite_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    
    Json(ApiResponse::ok(state.dns_rewrite.get_all_records())).into_response()
}

async fn api_dns_rewrite_add(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<DnsRewriteRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    match payload.ip.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            state.dns_rewrite.add_record(
                payload.domain,
                ip,
                payload.ttl,
                payload.enabled.unwrap_or(true),
                None
            );
            Json(ApiResponse::ok("Record added")).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::err("Invalid IP address".to_string()))).into_response(),
    }
}

async fn api_dns_rewrite_update(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(domain): Path<String>,
    Json(payload): Json<DnsRewriteRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    match payload.ip.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            state.dns_rewrite.add_record(
                domain,
                ip,
                payload.ttl,
                payload.enabled.unwrap_or(true),
                None
            );
            Json(ApiResponse::ok("Record updated")).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::err("Invalid IP address".to_string()))).into_response(),
    }
}

async fn api_dns_rewrite_delete(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    if state.dns_rewrite.remove_record(&domain) {
        Json(ApiResponse::ok("Record removed")).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::err("Record not found".to_string()))).into_response()
    }
}

async fn api_backup_restore_specific(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    match state.backup.restore_backup(&id) {
        Ok(data) => {
            // Apply backup config
            state.backup.configure(data.config);
            // In a full implementation we would restore DB/Blocklist here
            Json(ApiResponse::ok("Backup restored")).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::err(e))).into_response(),
    }
}

async fn api_backup_restore_upload(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(data): Json<crate::backup::BackupData>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    
    state.backup.configure(data.config);
    // Restoration logic would go here
    Json(ApiResponse::ok("Backup uploaded and applied")).into_response()
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
    role: String,
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    /// Senha atual (obrigatória para usuários comuns, ignorada para admins).
    old_password: Option<String>,
    new_password: String,
}

#[derive(serde::Deserialize)]
struct DnsRewriteRequest {
    domain: String,
    ip: String,
    ttl: u32,
    enabled: Option<bool>,
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

// ─── geo-blocking ─────────────────────────────────────────────────────────────

async fn api_geo_status(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&state, &headers) {
        return resp;
    }
    
    let geoip = state.firewall.get_geoip();
    let blocked = state.firewall.get_blocked_countries();
    
    Json(ApiResponse::ok(GeoStatusResponse {
        is_loaded: geoip.is_loaded(),
        blocked_countries: blocked,
    })).into_response()
}

async fn api_geo_block_country(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GeoBlockRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    
    let code = payload.country_code.trim().to_uppercase();
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::err("Invalid ISO country code (must be 2 letters)".to_string())),
        ).into_response();
    }
    
    state.firewall.block_country(&code);
    Json(ApiResponse::ok(())).into_response()
}

async fn api_geo_unblock_country(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(code): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp;
    }
    
    let code = code.trim().to_uppercase();
    state.firewall.unblock_country(&code);
    Json(ApiResponse::ok(())).into_response()
}
