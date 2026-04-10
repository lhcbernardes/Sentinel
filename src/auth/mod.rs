use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 24 horas de validade por token
const JWT_EXPIRY_SECS: u64 = 86400;
/// Máximo de tentativas de login antes do lockout
const MAX_LOGIN_ATTEMPTS: u32 = 10;
/// Janela de lockout em segundos (5 minutos)
const LOCKOUT_WINDOW_SECS: u64 = 300;

// ─── utilidades ────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Carrega o segredo JWT da variável de ambiente `SENTINEL_JWT_SECRET`.
/// Se não definida ou muito curta, gera um segredo aleatório e emite um warning —
/// nesse caso todos os tokens são invalidados ao reiniciar o serviço.
fn get_jwt_secret() -> Vec<u8> {
    match std::env::var("SENTINEL_JWT_SECRET") {
        Ok(secret) if secret.len() >= 32 => {
            tracing::info!("JWT secret carregado de SENTINEL_JWT_SECRET.");
            secret.into_bytes()
        }
        Ok(_) => {
            tracing::warn!(
                "SENTINEL_JWT_SECRET é muito curto (mínimo 32 caracteres). \
                 Gerando segredo aleatório — configure esta variável para persistir sessões."
            );
            generate_random_secret()
        }
        Err(_) => {
            tracing::warn!(
                "SENTINEL_JWT_SECRET não definida. Usando segredo aleatório — \
                 tokens serão invalidados ao reiniciar. Defina SENTINEL_JWT_SECRET em produção."
            );
            generate_random_secret()
        }
    }
}

fn generate_random_secret() -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(64)
        .collect()
}

/// Validates password complexity:
/// - Minimum 8 characters
/// - At least one uppercase letter
/// - At least one digit
/// - At least one special character
fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Senha deve ter pelo menos 8 caracteres".to_string());
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("Senha deve conter pelo menos uma letra maiúscula".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Senha deve conter pelo menos um número".to_string());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Senha deve conter pelo menos um caractere especial".to_string());
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ─── tipos públicos ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: u64,
    pub user: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
}

/// Claims armazenadas dentro do JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

// ─── rate limiting ──────────────────────────────────────────────────────────

struct LoginAttemptRecord {
    count: u32,
    window_start: u64,
}

// ─── AuthManager ────────────────────────────────────────────────────────────

pub struct AuthManager {
    users: RwLock<HashMap<String, User>>,
    /// Mapa de tokens ativos: token → claims.
    /// Usado para implementar logout real (revogação de token).
    sessions: RwLock<HashMap<String, JwtPayload>>,
    /// Controle de rate limiting por username.
    login_attempts: RwLock<HashMap<String, LoginAttemptRecord>>,
    jwt_secret: Vec<u8>,
}

impl AuthManager {
    pub fn new() -> Self {
        let jwt_secret = get_jwt_secret();

        // Senha padrão configurável via env; warning se usar o padrão.
        let default_password = std::env::var("SENTINEL_ADMIN_PASSWORD").unwrap_or_else(|_| {
            tracing::warn!(
                "SENTINEL_ADMIN_PASSWORD não definida. Usando senha padrão 'Sentinel@2024'. \
                 ALTERE ESTA SENHA IMEDIATAMENTE em produção!"
            );
            "Sentinel@2024".to_string()
        });

        let default_password_hash = hash_password(&default_password)
            .expect("Failed to hash default admin password — cannot start safely");

        let mut users = HashMap::new();
        users.insert(
            "admin".to_string(),
            User {
                username: "admin".to_string(),
                password_hash: default_password_hash,
                role: UserRole::Admin,
                created_at: now_secs() as i64,
            },
        );

        Self {
            users: RwLock::new(users),
            sessions: RwLock::new(HashMap::new()),
            login_attempts: RwLock::new(HashMap::new()),
            jwt_secret,
        }
    }

    // ── rate limiting ──────────────────────────────────────────────────────

    fn check_rate_limit(&self, username: &str) -> Result<(), String> {
        let now = now_secs();
        let mut attempts = self.login_attempts.write();
        let entry = attempts
            .entry(username.to_string())
            .or_insert(LoginAttemptRecord {
                count: 0,
                window_start: now,
            });

        // Reinicia janela se expirou
        if now.saturating_sub(entry.window_start) > LOCKOUT_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= MAX_LOGIN_ATTEMPTS {
            let remaining =
                LOCKOUT_WINDOW_SECS.saturating_sub(now.saturating_sub(entry.window_start));
            return Err(format!(
                "Muitas tentativas de login. Tente novamente em {} segundos.",
                remaining
            ));
        }

        Ok(())
    }

    fn record_failed_attempt(&self, username: &str) {
        let now = now_secs();
        let mut attempts = self.login_attempts.write();
        let entry = attempts
            .entry(username.to_string())
            .or_insert(LoginAttemptRecord {
                count: 0,
                window_start: now,
            });
        entry.count += 1;
    }

    fn clear_attempts(&self, username: &str) {
        self.login_attempts.write().remove(username);
    }

    // ── login / logout ─────────────────────────────────────────────────────

    /// Autentica um usuário. Retorna `Err` com mensagem legível em caso de
    /// credenciais inválidas ou rate limit atingido.
    pub fn login(&self, request: LoginRequest) -> Result<LoginResponse, String> {
        self.check_rate_limit(&request.username)?;

        let users = self.users.read();
        let user = users.get(&request.username);

        // Realiza a verificação sempre (mesmo se usuário não existe) para
        // evitar timing attacks que permitiriam enumerar usuários válidos.
        let is_valid = match user {
            Some(u) => verify_password(&request.password, &u.password_hash),
            None => {
                // Executa trabalho fictício para equalizar o tempo de resposta
                let _ = verify_password(
                    &request.password,
                    "$argon2id$v=19$m=19456,t=2,p=1$dummysaltdummysalt$dummyhash000000000000000000000000000000000",
                );
                false
            }
        };

        if !is_valid {
            drop(users);
            self.record_failed_attempt(&request.username);
            // Mensagem genérica para não revelar qual campo está errado
            return Err("Credenciais inválidas".to_string());
        }

        let user = user.unwrap();
        let role_str = user.role.as_str().to_string();
        let username = user.username.clone();
        drop(users);

        self.clear_attempts(&request.username);
        self.issue_token(username, role_str)
    }

    /// Cria um novo par (token, LoginResponse) para o usuário/role informados.
    /// Chamado internamente por `login` e `renew_token`.
    fn issue_token(&self, username: String, role: String) -> Result<LoginResponse, String> {
        let now = now_secs() as usize;
        let expiry = now + JWT_EXPIRY_SECS as usize;

        let payload = JwtPayload {
            sub: username.clone(),
            role: role.clone(),
            exp: expiry,
            iat: now,
        };

        let token = encode(
            &Header::default(), // HS256
            &payload,
            &EncodingKey::from_secret(&self.jwt_secret),
        )
        .map_err(|e| format!("Falha ao gerar token: {}", e))?;

        self.sessions.write().insert(token.clone(), payload);

        Ok(LoginResponse {
            token,
            expires_at: expiry as u64,
            user: UserInfo { username, role },
        })
    }

    /// Verifica um token: checa se está na lista de sessões ativas E valida
    /// assinatura + expiração via `jsonwebtoken`.
    pub fn verify_token(&self, token: &str) -> Option<JwtPayload> {
        // Verificação rápida: token precisa estar na lista de sessões ativas.
        // Isso garante que tokens revogados via logout não passem.
        if !self.sessions.read().contains_key(token) {
            return None;
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<JwtPayload>(
            token,
            &DecodingKey::from_secret(&self.jwt_secret),
            &validation,
        )
        .ok()
        .map(|data| data.claims)
    }

    /// Invalida o token (logout real — o token não poderá mais ser usado).
    pub fn logout(&self, token: &str) {
        self.sessions.write().remove(token);
    }

    /// Renova um token válido sem exigir senha novamente.
    /// Revoga o token antigo e emite um novo com expiração renovada.
    pub fn renew_token(&self, token: &str) -> Option<LoginResponse> {
        let payload = self.verify_token(token)?;

        // Revoga o token atual antes de emitir o novo
        self.sessions.write().remove(token);

        self.issue_token(payload.sub, payload.role).ok()
    }

    pub fn is_admin(&self, token: &str) -> bool {
        self.verify_token(token)
            .map(|p| p.role == "admin")
            .unwrap_or(false)
    }

    /// Remove expired sessions and stale login attempt records to prevent
    /// unbounded memory growth. Should be called periodically.
    pub fn cleanup_expired(&self) {
        let now = now_secs();

        // Remove expired session tokens
        let expired_sessions = {
            let mut sessions = self.sessions.write();
            let before = sessions.len();
            sessions.retain(|_, payload| payload.exp as u64 > now);
            before - sessions.len()
        };

        // Remove stale login attempt records outside their window
        let expired_attempts = {
            let mut attempts = self.login_attempts.write();
            let before = attempts.len();
            attempts
                .retain(|_, record| now.saturating_sub(record.window_start) <= LOCKOUT_WINDOW_SECS);
            before - attempts.len()
        };

        if expired_sessions > 0 || expired_attempts > 0 {
            tracing::debug!(
                "Auth cleanup: removed {} expired sessions, {} stale login records",
                expired_sessions,
                expired_attempts
            );
        }
    }

    // ── gerenciamento de usuários ──────────────────────────────────────────

    pub fn add_user(
        &self,
        username: String,
        password: String,
        role: UserRole,
    ) -> Result<bool, String> {
        // Validate username
        if username.len() < 3 || username.len() > 32 {
            return Err("Nome de usuário deve ter entre 3 e 32 caracteres".to_string());
        }
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err("Nome de usuário deve conter apenas letras, números, _ ou -".to_string());
        }
        // Validate password complexity
        validate_password(&password)?;

        let mut users = self.users.write();
        if users.contains_key(&username) {
            return Ok(false);
        }
        let password_hash = hash_password(&password)?;
        let user = User {
            username: username.clone(),
            password_hash,
            role,
            created_at: now_secs() as i64,
        };
        users.insert(username, user);
        Ok(true)
    }

    pub fn list_users(&self) -> Vec<UserInfo> {
        self.users
            .read()
            .values()
            .map(|u| UserInfo {
                username: u.username.clone(),
                role: u.role.as_str().to_string(),
            })
            .collect()
    }

    /// Verifica se `password` corresponde à senha atual do usuário (para
    /// exigir confirmação antes de troca de senha).
    pub fn verify_current_password(&self, username: &str, password: &str) -> bool {
        self.users
            .read()
            .get(username)
            .map(|u| verify_password(password, &u.password_hash))
            .unwrap_or(false)
    }

    pub fn change_password(&self, username: &str, new_password: &str) -> Result<bool, String> {
        // Validate password complexity
        validate_password(new_password)?;

        let mut users = self.users.write();
        if let Some(user) = users.get_mut(username) {
            user.password_hash = hash_password(new_password)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}
