use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub async fn auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let uri = request.uri().path();
    
    // Rotas públicas que não precisam de auth
    let public_routes = [
        "/",
        "/login",
        "/api/login",
        "/events",
    ];
    
    if public_routes.iter().any(|r| uri.starts_with(r)) {
        return next.run(request).await;
    }
    
    // APIs que precisam de autenticação
    let protected_apis = [
        "/api/",
    ];
    
    if protected_apis.iter().any(|r| uri.starts_with(r)) {
        // Verificar token no header Authorization
        let auth_header = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        
        match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                let token = &header[7..];
                if token.is_empty() {
                    return Response::builder()
                        .status(401)
                        .body(Body::from(r#"{"error":"Invalid token"}"#))
                        .unwrap();
                }
                // Token existe - deixar passar por agora
                // A verificação real deve ser feita no handler
            }
            _ => {
                // Token não fornecido - permitir por enquanto (debug)
                // Em produção, retornar 401:
                // return Response::builder()
                //     .status(401)
                //     .body(Body::from(r#"{"error":"Unauthorized"}"#))
                //     .unwrap();
            }
        }
    }
    
    next.run(request).await
}