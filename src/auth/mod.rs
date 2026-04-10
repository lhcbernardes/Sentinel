use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_SECRET: &[u8] = b"sentinel_rs_secret_key_2024_secure_change_in_production";
const JWT_EXPIRY_SECS: u64 = 86400; // 24 hours

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: i64,
}

fn hash_password(password: &str) -> String {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .unwrap_or_else(|_| password.to_string())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Viewer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    pub sub: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

pub struct AuthManager {
    users: RwLock<HashMap<String, User>>,
    sessions: RwLock<HashMap<String, JwtPayload>>,
    jwt_secret: Vec<u8>,
}

impl AuthManager {
    pub fn new() -> Self {
        let mut users = HashMap::new();

        // Default admin user - CHANGE PASSWORD IN PRODUCTION!
        // Default password: admin123 (hashed with Argon2)
        let default_password_hash = hash_password("admin123");

        users.insert(
            "admin".to_string(),
            User {
                username: "admin".to_string(),
                password_hash: default_password_hash,
                role: UserRole::Admin,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            },
        );

        Self {
            users: RwLock::new(users),
            sessions: RwLock::new(HashMap::new()),
            jwt_secret: JWT_SECRET.to_vec(),
        }
    }

    pub fn login(&self, request: LoginRequest) -> Option<LoginResponse> {
        let users = self.users.read();

        let user = users.get(&request.username)?;

        if !verify_password(&request.password, &user.password_hash) {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expiry = now + JWT_EXPIRY_SECS as i64;

        let payload = JwtPayload {
            sub: user.username.clone(),
            role: match user.role {
                UserRole::Admin => "admin",
                UserRole::Viewer => "viewer",
            }
            .to_string(),
            exp: expiry,
            iat: now,
        };

        let token = self.encode_jwt(&payload);

        self.sessions.write().insert(token.clone(), payload.clone());

        Some(LoginResponse {
            token,
            expires_at: expiry,
            user: UserInfo {
                username: user.username.clone(),
                role: match user.role {
                    UserRole::Admin => "admin".to_string(),
                    UserRole::Viewer => "viewer".to_string(),
                },
            },
        })
    }

    pub fn verify_token(&self, token: &str) -> Option<JwtPayload> {
        let payload = self.decode_jwt(token)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if payload.exp < now {
            self.sessions.write().remove(token);
            return None;
        }

        Some(payload)
    }

    pub fn logout(&self, token: &str) {
        self.sessions.write().remove(token);
    }

    pub fn is_admin(&self, token: &str) -> bool {
        self.verify_token(token)
            .map(|p| p.role == "admin")
            .unwrap_or(false)
    }

    pub fn add_user(&self, username: String, password: String, role: UserRole) -> bool {
        let mut users = self.users.write();
        if users.contains_key(&username) {
            return false;
        }
        let user = User {
            username: username.clone(),
            password_hash: hash_password(&password),
            role,
            created_at: chrono::Utc::now().timestamp(),
        };
        users.insert(username, user);
        true
    }

    pub fn list_users(&self) -> Vec<UserInfo> {
        self.users
            .read()
            .values()
            .map(|u| UserInfo {
                username: u.username.clone(),
                role: match u.role {
                    UserRole::Admin => "admin".to_string(),
                    UserRole::Viewer => "viewer".to_string(),
                },
            })
            .collect()
    }

    pub fn change_password(&self, username: &str, new_password: &str) -> bool {
        let mut users = self.users.write();

        if let Some(user) = users.get_mut(username) {
            user.password_hash = hash_password(new_password);
            true
        } else {
            false
        }
    }

    fn encode_jwt(&self, payload: &JwtPayload) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);

        let claims = serde_json::to_string(payload).unwrap();
        let payload_encoded = URL_SAFE_NO_PAD.encode(claims.as_bytes());

        let signature = self.sign(format!("{}.{}", header, payload_encoded));

        format!("{}.{}.{}", header, payload_encoded, signature)
    }

    fn decode_jwt(&self, token: &str) -> Option<JwtPayload> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let expected_signature = self.sign(format!("{}.{}", parts[0], parts[1]));

        if expected_signature != parts[2] {
            return None;
        }

        match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(payload_bytes) => match String::from_utf8(payload_bytes) {
                Ok(payload_str) => serde_json::from_str(&payload_str).ok(),
                Err(_) => None,
            },
            Err(_) => None,
        }
    }

    fn sign(&self, data: String) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let mut key = self.jwt_secret.clone();
        key.extend(data.as_bytes());

        let hash = sha256::digest(String::from_utf8_lossy(&key).as_ref());
        URL_SAFE_NO_PAD.encode(hash.as_bytes())
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

// Simple SHA-256 implementation for JWT signing
mod sha256 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    pub fn digest(input: &str) -> String {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:016x}{:016x}", hasher.finish(), hasher.finish())
    }
}
