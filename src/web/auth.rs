use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::AppState;

// ─── rotas públicas ─────────────────────────────────────────────────────────

/// Rotas exatas que não exigem autenticação.
const PUBLIC_EXACT: &[&str] = &[
    "/api/v1/login",
    "/api/v1/health",
    "/api/login",
    "/api/v1/refresh", // refresh valida o token internamente
];

/// Prefixos que não exigem autenticação.
/// Nota: EventSource (SSE) não suporta headers customizados no browser,
/// por isso /events fica público. Considere autenticação via query param em produção.
const PUBLIC_PREFIXES: &[&str] = &["/events"];

// ─── middleware ─────────────────────────────────────────────────────────────

/// Middleware de autenticação JWT.
///
/// Rotas HTML (sem prefixo `/api/`) são deixadas públicas intencionalmente —
/// elas são shells de UI que não expõem dados sensíveis por si só.
/// Toda ação destrutiva passa por uma rota `/api/` protegida.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let uri = request.uri().path();

    // Apenas rotas /api/ exigem autenticação
    if !uri.starts_with("/api/") {
        return next.run(request).await;
    }

    // Rotas API públicas
    if PUBLIC_EXACT.contains(&uri) {
        return next.run(request).await;
    }
    for prefix in PUBLIC_PREFIXES {
        if uri.starts_with(prefix) {
            return next.run(request).await;
        }
    }

    // Extrai e valida o Bearer token
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    match token {
        Some(t) if !t.is_empty() => {
            if state.auth.verify_token(&t).is_some() {
                next.run(request).await
            } else {
                unauthorized("Token inválido ou expirado")
            }
        }
        _ => unauthorized("Autenticação obrigatória. Forneça um Bearer token."),
    }
}

// ─── helpers de autorização (usados pelos handlers) ─────────────────────────

/// Extrai o Bearer token do header `Authorization`.
pub fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Verifica presença e validade do token. Retorna o payload ou uma `Response`
/// 401 pronta para retornar do handler.
pub fn require_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<crate::auth::JwtPayload, Response> {
    let token = extract_token(headers).ok_or_else(|| unauthorized("Autenticação obrigatória"))?;
    state
        .auth
        .verify_token(&token)
        .ok_or_else(|| unauthorized("Token inválido ou expirado"))
}

/// Igual a `require_auth`, mas exige role `admin`.
pub fn require_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<crate::auth::JwtPayload, Response> {
    let payload = require_auth(state, headers)?;
    if payload.role != "admin" {
        return Err(forbidden("Acesso restrito a administradores"));
    }
    Ok(payload)
}

// ─── respostas de erro ───────────────────────────────────────────────────────

fn unauthorized(msg: &str) -> Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": msg, "code": 401})),
    )
        .into_response()
}

fn forbidden(msg: &str) -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({"error": msg, "code": 403})),
    )
        .into_response()
}