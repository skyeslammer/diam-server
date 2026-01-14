use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Deserialize)]
pub struct OpaqueRegisterStartRequest {
    pub identifier: String, // email, phone или username
}

#[derive(Debug, Serialize)]
pub struct OpaqueRegisterStartResponse {
    pub registration_request: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct OpaqueRegisterFinishRequest {
    pub identifier: String,
    pub registration_upload: Vec<u8>,
    pub user_type: Option<UserType>, // По умолчанию Regular
}

#[derive(Debug, Serialize)]
pub struct OpaqueRegisterFinishResponse {
    pub user_id: Uuid,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct OpaqueAuthStartRequest {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct OpaqueAuthStartResponse {
    pub credential_request: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct OpaqueAuthFinishRequest {
    pub identifier: String,
    pub credential_finalization: Vec<u8>,
}

#[derive(Debug, Serialize)]
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
