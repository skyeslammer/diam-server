use axum::{Json, extract::State};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerRegistration,
};
use rand_core::OsRng;
use uuid::Uuid;

use crate::{
    AppState,
    ciphersuite::DefaultCipherSuite,
    models::{
        ApiError, OpaqueAuthFinishRequest, OpaqueAuthFinishResponse, OpaqueAuthStartRequest,
        OpaqueAuthStartResponse, OpaqueRegisterFinishRequest, OpaqueRegisterFinishResponse,
        OpaqueRegisterStartRequest, OpaqueRegisterStartResponse, Session, User, UserType,
        hash_with_pepper,
    },
};

// FIXME: тут надо сделать регистрацию, авторизацию и так далее

// ============ OPAQUE РЕГИСТРАЦИЯ ============

pub async fn register_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueRegisterStartRequest>,
) -> Result<Json<OpaqueRegisterStartResponse>, ApiError> {
    let identifier = payload.identifier.trim();

    // Хэшируем идентификатор для проверки
    let identifier_hash = hash_with_pepper(identifier, &state.server_pepper);

    // Проверяем существование пользователя
    let exists = match crate::models::get_identifier_type(identifier) {
        crate::models::IdentifierType::Email => {
            state
                .db
                .user_exists(None, Some(&identifier_hash), None)
                .await?
        }
        crate::models::IdentifierType::Phone => {
            state
                .db
                .user_exists(None, None, Some(&identifier_hash))
                .await?
        }
        crate::models::IdentifierType::Username => {
            state
                .db
                .user_exists(Some(&identifier_hash), None, None)
                .await?
        }
    };

    if exists {
        return Err(ApiError::UserExists);
    }

    let mut rng = OsRng;

    // Начинаем регистрацию
    let (registration_request, server_registration) =
        ServerRegistration::<DefaultCipherSuite>::start(
            &mut rng,
            &state.opaque_server_setup,
            identifier.as_bytes(), // OPAQUE 4.x принимает bytes
        )
        .map_err(|e| {
            tracing::error!("OPAQUE registration start failed: {:?}", e);
            ApiError::OpaqueError(format!("Registration failed: {}", e))
        })?;

    // Сохраняем состояние регистрации
    let registration_id = Uuid::new_v4().to_string();
    state
        .save_registration_state(&registration_id, server_registration)
        .await?;

    // Готовим ответ
    let server_public_key = state
        .opaque_server_setup
        .get_public_key()
        .serialize()
        .to_vec();

    Ok(Json(OpaqueRegisterStartResponse {
        registration_id,
        registration_request: registration_request.serialize().to_vec(),
        server_public_key,
    }))
}

pub async fn register_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueRegisterFinishRequest>,
) -> Result<Json<OpaqueRegisterFinishResponse>, ApiError> {
    // Получаем состояние регистрации
    let server_registration = state
        .get_registration_state(&payload.registration_id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest("Registration session expired or not found".to_string())
        })?;

    // Десериализуем registration upload
    let registration_upload =
        RegistrationUpload::<DefaultCipherSuite>::deserialize(&payload.registration_upload)
            .map_err(|e| {
                tracing::error!("Failed to deserialize registration upload: {:?}", e);
                ApiError::BadRequest(format!("Invalid registration upload: {}", e))
            })?;

    // Завершаем регистрацию
    let (server_record, server_public_key) = server_registration
        .finish(registration_upload)
        .map_err(|e| {
            tracing::error!("OPAQUE registration finish failed: {:?}", e);
            ApiError::OpaqueError(format!("Registration finish failed: {}", e))
        })?;

    // Удаляем состояние регистрации
    state
        .remove_registration_state(&payload.registration_id)
        .await?;

    // Создаём пользователя
    let user_uuid = Uuid::new_v4();
    let identifier = payload.identifier.trim();
    let identifier_hash = hash_with_pepper(identifier, &state.server_pepper);

    let mut user = User::new(
        user_uuid,
        identifier,
        &state.server_pepper,
        UserType::Regular,
    );

    // Устанавливаем OPAQUE запись
    user.opaque_record = server_record.serialize().to_vec();
    user.server_public_key = server_public_key.serialize().to_vec();

    // Сохраняем пользователя
    state.db.save_user(&user).await.map_err(|e| {
        tracing::error!("Failed to save user: {:?}", e);
        ApiError::DatabaseError(e)
    })?;

    Ok(Json(OpaqueRegisterFinishResponse {
        user_id: user_uuid,
        message: "Registration successful".to_string(),
    }))
}

// ============ OPAQUE АУТЕНТИФИКАЦИЯ ============

pub async fn login_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueAuthStartRequest>,
) -> Result<Json<OpaqueAuthStartResponse>, ApiError> {
    let identifier = payload.identifier.trim();

    // Ищем пользователя
    let identifier_hash = hash_with_pepper(identifier, &state.server_pepper);
    let user = state
        .db
        .find_user_by_identifier(&identifier_hash)
        .await?
        .ok_or_else(|| ApiError::UserNotFound)?;

    if user.user_type != UserType::Regular {
        return Err(ApiError::InvalidUserType);
    }

    // Десериализуем OPAQUE запись
    let server_record = opaque_ke::ServerRecord::<DefaultCipherSuite>::deserialize(
        &user.opaque_record,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize server record: {:?}", e);
        ApiError::OpaqueError(format!("Invalid server record: {}", e))
    })?;

    let mut rng = OsRng;

    // Создаём credential request
    let credential_request =
        CredentialRequest::<DefaultCipherSuite>::new(&mut rng).map_err(|e| {
            tracing::error!("Failed to create credential request: {:?}", e);
            ApiError::OpaqueError(format!("Failed to create request: {}", e))
        })?;

    // Начинаем процесс логина
    let server_login = ServerLogin::<DefaultCipherSuite>::start(
        &mut rng,
        &state.opaque_server_setup,
        credential_request.clone(),
        identifier.as_bytes(),
        server_record,
    )
    .map_err(|e| {
        tracing::error!("OPAQUE login start failed: {:?}", e);
        ApiError::OpaqueError(format!("Login start failed: {}", e))
    })?;

    // Сохраняем состояние логина
    let session_id = Uuid::new_v4().to_string();
    state.save_login_state(&session_id, server_login).await?;

    let server_public_key = state
        .opaque_server_setup
        .get_public_key()
        .serialize()
        .to_vec();

    Ok(Json(OpaqueAuthStartResponse {
        session_id,
        credential_request: credential_request.serialize().to_vec(),
        server_public_key,
    }))
}

pub async fn login_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueAuthFinishRequest>,
) -> Result<Json<OpaqueAuthFinishResponse>, ApiError> {
    // Получаем состояние логина
    let server_login = state
        .get_login_state(&payload.session_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("Login session expired or not found".to_string()))?;

    // Десериализуем credential finalization
    let credential_finalization =
        CredentialFinalization::<DefaultCipherSuite>::deserialize(&payload.credential_finalization)
            .map_err(|e| {
                tracing::error!("Failed to deserialize credential finalization: {:?}", e);
                ApiError::BadRequest(format!("Invalid credential finalization: {}", e))
            })?;

    // Завершаем процесс логина
    let session_key = server_login.finish(credential_finalization).map_err(|e| {
        tracing::error!("OPAQUE login finish failed: {:?}", e);
        ApiError::InvalidCredentials
    })?;

    // Удаляем состояние логина
    state.remove_login_state(&payload.session_id).await?;

    // Получаем пользователя для создания сессии
    let identifier_hash = hash_with_pepper(&payload.identifier, &state.server_pepper);
    let user = state
        .db
        .find_user_by_identifier(&identifier_hash)
        .await?
        .ok_or_else(|| {
            tracing::error!("User not found after OPAQUE auth: {}", payload.identifier);
            ApiError::UserNotFound
        })?;

    // Создаём сессию
    let session_uuid = Uuid::new_v4();
    let session_key_hash = blake3::hash(session_key.as_ref()).as_bytes().to_vec();

    let session = Session {
        uuid: session_uuid,
        user_uuid: user.uuid,
        session_key_hash,
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        created_at: chrono::Utc::now(),
    };

    state.db.save_session(&session).await.map_err(|e| {
        tracing::error!("Failed to save session: {:?}", e);
        ApiError::DatabaseError(e)
    })?;

    Ok(Json(OpaqueAuthFinishResponse {
        session_id: session_uuid,
        session_key: session_key.as_ref().to_vec(),
    }))
}
