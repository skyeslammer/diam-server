use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

// ============ OPAQUE SERVER STATE ============

#[derive(Clone)]
pub struct OpaqueServerState {
    // Хранилище состояния регистрации: registration_id -> ServerRegistration
    pub registration_states: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    // Хранилище состояния логина: session_id -> ServerLogin
    pub login_states: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl OpaqueServerState {
    pub fn new() -> Self {
        Self {
            registration_states: Arc::new(RwLock::new(HashMap::new())),
            login_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn save_registration_state(&self, id: &str, state: Vec<u8>) {
        let mut states = self.registration_states.write().await;
        states.insert(id.to_string(), state);
    }

    pub async fn get_registration_state(&self, id: &str) -> Option<Vec<u8>> {
        let states = self.registration_states.read().await;
        states.get(id).cloned()
    }

    pub async fn remove_registration_state(&self, id: &str) {
        let mut states = self.registration_states.write().await;
        states.remove(id);
    }

    pub async fn save_login_state(&self, id: &str, state: Vec<u8>) {
        let mut states = self.login_states.write().await;
        states.insert(id.to_string(), state);
    }

    pub async fn get_login_state(&self, id: &str) -> Option<Vec<u8>> {
        let states = self.login_states.read().await;
        states.get(id).cloned()
    }

    pub async fn remove_login_state(&self, id: &str) {
        let mut states = self.login_states.write().await;
        states.remove(id);
    }
}

impl Default for OpaqueServerState {
    fn default() -> Self {
        Self::new()
    }
}

// ============ ТИПЫ ИДЕНТИФИКАТОРОВ ============

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierType {
    Username,
    Email,
    Phone,
}

pub fn get_identifier_type(identifier: &str) -> IdentifierType {
    if identifier.contains('@') {
        IdentifierType::Email
    } else if identifier.starts_with('+') || identifier.len() == 11 && identifier.chars().all(|c| c.is_numeric()) {
        IdentifierType::Phone
    } else {
        IdentifierType::Username
    }
}

// ============ ТИПЫ ПОЛЬЗОВАТЕЛЕЙ ============
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_type", rename_all = "lowercase")]
pub enum UserType {
    Regular,
    Bot,
    Guest,
}

impl std::fmt::Display for UserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserType::Regular => write!(f, "regular"),
            UserType::Bot => write!(f, "bot"),
            UserType::Guest => write!(f, "guest"),
        }
    }
}

impl From<String> for UserType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "regular" => UserType::Regular,
            "bot" => UserType::Bot,
            "guest" => UserType::Guest,
            _ => UserType::Regular,
        }
    }
}

// ============ ЗАПРОСЫ/ОТВЕТЫ ДЛЯ OPAQUE ============

#[derive(Debug, Deserialize, Serialize)]
pub struct OpaqueRegisterStartRequest {
    pub identifier: String, // email, phone или username
    pub registration_request: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpaqueRegisterStartResponse {
    pub registration_request: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpaqueRegisterFinishRequest {
    pub identifier: String,
    pub registration_upload: Vec<u8>,
    pub user_type: Option<UserType>, // По умолчанию Regular
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpaqueRegisterFinishResponse {
    pub user_id: Uuid,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpaqueAuthStartRequest {
    pub identifier: String,
    pub credential_request: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpaqueAuthStartResponse {
    pub credential_request: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpaqueAuthFinishRequest {
    pub identifier: String,
    pub session_id: String,
    pub credential_finalization: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpaqueAuthFinishResponse {
    pub session_id: Uuid,
    pub session_key: Vec<u8>,
}

// ============ ХРАНИМЫЕ ДАННЫЕ ============

#[derive(Debug, Clone)]
pub struct User {
    pub uuid: Uuid,
    pub username_hash: Option<Vec<u8>>,
    pub email_hash: Option<Vec<u8>>,
    pub phone_hash: Option<Vec<u8>>,
    pub seed_phrase_hash: Option<Vec<u8>>,
    pub opaque_record: Vec<u8>,
    pub server_public_key: Vec<u8>,
    pub user_type: UserType,
    pub is_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl User {
    pub fn new(uuid: Uuid, identifier: &str, pepper: &str, user_type: UserType) -> Self {
        let identifier_type = get_identifier_type(identifier);
        let identifier_hash = hash_with_pepper(identifier, pepper);

        let (username_hash, email_hash, phone_hash) = match identifier_type {
            IdentifierType::Username => (Some(identifier_hash), None, None),
            IdentifierType::Email => (None, Some(identifier_hash), None),
            IdentifierType::Phone => (None, None, Some(identifier_hash)),
        };

        let now = chrono::Utc::now();

        User {
            uuid,
            username_hash,
            email_hash,
            phone_hash,
            seed_phrase_hash: None,
            opaque_record: Vec::new(),
            server_public_key: Vec::new(),
            user_type,
            is_verified: false,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub uuid: Uuid,
    pub user_uuid: Uuid,
    pub session_key_hash: Vec<u8>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ============ ОШИБКИ ============
// (остаётся как у вас, но добавим новые варианты)

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("User already exists")]
    UserExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Session expired")]
    SessionExpired,

    #[error("OPAQUE protocol error: {0}")]
    OpaqueError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Bot authentication failed")]
    BotAuthFailed,

    #[error("User not verified")]
    UserNotVerified,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid user type")]
    InvalidUserType,

    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl ApiError {
    pub fn opaque_error<E: std::error::Error>(err: E) -> Self {
        ApiError::OpaqueError(err.to_string())
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::UserExists => (StatusCode::CONFLICT, "User already exists".to_string()),
            ApiError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            ApiError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
            }
            ApiError::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired".to_string()),
            ApiError::OpaqueError(msg) => {
                (StatusCode::BAD_REQUEST, format!("OPAQUE error: {}", msg))
            }
            ApiError::DatabaseError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ApiError::BotAuthFailed => (
                StatusCode::UNAUTHORIZED,
                "Bot authentication failed".to_string(),
            ),
            ApiError::UserNotVerified => (StatusCode::FORBIDDEN, "User not verified".to_string()),
            ApiError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
            ),
            ApiError::InvalidUserType => (StatusCode::BAD_REQUEST, "Invalid user type".to_string()),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = axum::Json(serde_json::json!({
            "error": self.to_string(),
            "message": message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

pub fn hash_with_pepper(data: &str, pepper: &str) -> Vec<u8> {
    let combined = format!("{}{}", data, pepper);
    blake3::hash(combined.as_bytes()).as_bytes().to_vec()
}

pub fn verify_hash_with_pepper(input: &str, pepper: &str, stored_hash: &[u8]) -> bool {
    let computed_hash = hash_with_pepper(input, pepper);
    computed_hash == stored_hash
}
