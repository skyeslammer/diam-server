use axum::{Json, extract::State};
use opaque_ke::{
    ServerRegistration, ServerLogin, ServerLoginParameters,
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
        hash_with_pepper, get_identifier_type, IdentifierType,
    },
};

// ============ OPAQUE РЕГИСТРАЦИЯ ============

/// Начало процесса регистрации
pub async fn register_start(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueRegisterStartRequest>,
) -> Result<Json<OpaqueRegisterStartResponse>, ApiError> {
    let identifier = payload.identifier.trim();

    // Хэшируем идентификатор для проверки
    let identifier_hash = hash_with_pepper(identifier, &state.server_pepper);

    // Проверяем существование пользователя
    let exists = match get_identifier_type(identifier) {
        IdentifierType::Email => {
            state
                .db
                .user_exists(None, Some(&identifier_hash), None)
                .await?
        }
        IdentifierType::Phone => {
            state
                .db
                .user_exists(None, None, Some(&identifier_hash))
                .await?
        }
        IdentifierType::Username => {
            state
                .db
                .user_exists(Some(&identifier_hash), None, None)
                .await?
        }
    };

    if exists {
        return Err(ApiError::UserExists);
    }

    // Десериализуем RegistrationRequest из payload
    let client_reg_start = opaque_ke::RegistrationRequest::<DefaultCipherSuite>::deserialize(
        &payload.registration_request,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize registration request: {:?}", e);
        ApiError::BadRequest(format!("Invalid registration request: {}", e))
    })?;

    // Начинаем регистрацию на сервере
    let reg_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &state.opaque_server_setup,
        client_reg_start,
        identifier.as_bytes(),
    )
    .map_err(|e| {
        tracing::error!("OPAQUE registration start failed: {:?}", e);
        ApiError::OpaqueError(format!("Registration failed: {}", e))
    })?;

    Ok(Json(OpaqueRegisterStartResponse {
        registration_request: reg_start_result.message.serialize().to_vec(),
        server_public_key: vec![],
    }))
}

/// Завершение процесса регистрации
pub async fn register_finish(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueRegisterFinishRequest>,
) -> Result<Json<OpaqueRegisterFinishResponse>, ApiError> {
    // Десериализуем RegistrationUpload от клиента
    let client_reg_upload = opaque_ke::RegistrationUpload::<DefaultCipherSuite>::deserialize(
        &payload.registration_upload,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize registration upload: {:?}", e);
        ApiError::BadRequest(format!("Invalid registration upload: {}", e))
    })?;

    // Завершаем регистрацию и получаем password file (ServerRegistration)
    let password_file = ServerRegistration::<DefaultCipherSuite>::finish(client_reg_upload);

    // Создаём пользователя
    let user_uuid = Uuid::new_v4();
    let identifier = payload.identifier.trim();
    let user_type = payload.user_type.clone().unwrap_or(UserType::Regular);

    let mut user = User::new(user_uuid, identifier, &state.server_pepper, user_type);

    // Устанавливаем OPAQUE запись (password file)
    user.opaque_record = password_file.serialize().to_vec();
    user.server_public_key = vec![];

    // Сохраняем пользователя в БД
    state.db.save_user(&user).await
        .map_err(|e| {
            tracing::error!("Failed to save user: {:?}", e);
            e
        })?;

    tracing::info!("User registered successfully: {}", user_uuid);

    Ok(Json(OpaqueRegisterFinishResponse {
        user_id: user_uuid,
        message: "Registration successful".to_string(),
    }))
}

// ============ OPAQUE АУТЕНТИФИКАЦИЯ ============

/// Начало процесса аутентификации
pub async fn login_start(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueAuthStartRequest>,
) -> Result<Json<OpaqueAuthStartResponse>, ApiError> {
    let identifier = payload.identifier.trim();

    // Ищем пользователя по идентификатору
    let user = state
        .db
        .find_user_by_identifier(identifier, &state.server_pepper)
        .await?
        .ok_or_else(|| {
            tracing::warn!("User not found during login: {}", identifier);
            ApiError::UserNotFound
        })?;

    // Проверяем тип пользователя
    if user.user_type != UserType::Regular {
        return Err(ApiError::InvalidUserType);
    }

    // Десериализуем password file пользователя
    let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(
        &user.opaque_record,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize password file: {:?}", e);
        ApiError::OpaqueError(format!("Invalid password file: {}", e))
    })?;

    // Десериализуем CredentialRequest от клиента
    let client_login_start = opaque_ke::CredentialRequest::<DefaultCipherSuite>::deserialize(
        &payload.credential_request,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize credential request: {:?}", e);
        ApiError::BadRequest(format!("Invalid credential request: {}", e))
    })?;

    let mut rng = OsRng;

    // Начинаем процесс логина на сервере
    let login_start_result = ServerLogin::<DefaultCipherSuite>::start(
        &mut rng,
        &state.opaque_server_setup,
        Some(password_file),
        client_login_start,
        identifier.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| {
        tracing::error!("OPAQUE login start failed: {:?}", e);
        ApiError::OpaqueError(format!("Login start failed: {}", e))
    })?;

    // Сохраняем состояние логина
    let session_id = Uuid::new_v4().to_string();
    let state_bytes = bincode::serialize(&login_start_result.state)
        .map_err(|e| ApiError::InternalError(format!("Serialization failed: {}", e)))?;
    state
        .opaque_state
        .save_login_state(&session_id, state_bytes)
        .await;

    Ok(Json(OpaqueAuthStartResponse {
        credential_request: login_start_result.message.serialize().to_vec(),
        server_public_key: vec![],
    }))
}

/// Завершение процесса аутентификации
pub async fn login_finish(
    State(state): State<AppState>,
    Json(payload): Json<OpaqueAuthFinishRequest>,
) -> Result<Json<OpaqueAuthFinishResponse>, ApiError> {
    // Получаем состояние логина
    let state_bytes = state
        .opaque_state
        .get_login_state(&payload.session_id)
        .await
        .ok_or_else(|| ApiError::BadRequest("Login session expired or not found".to_string()))?;

    // Десериализуем ServerLogin state
    let server_login_state: ServerLogin<DefaultCipherSuite> = bincode::deserialize(&state_bytes)
        .map_err(|e| ApiError::InternalError(format!("Deserialization failed: {}", e)))?;

    // Десериализуем CredentialFinalization от клиента
    let client_login_finish = opaque_ke::CredentialFinalization::<DefaultCipherSuite>::deserialize(
        &payload.credential_finalization,
    )
    .map_err(|e| {
        tracing::error!("Failed to deserialize credential finalization: {:?}", e);
        ApiError::BadRequest(format!("Invalid credential finalization: {}", e))
    })?;

    // Завершаем процесс логина и получаем session key
    let finish_result = server_login_state.finish(
        client_login_finish,
        ServerLoginParameters::default(),
    ).map_err(|e| {
        tracing::error!("OPAQUE login finish failed: {:?}", e);
        ApiError::InvalidCredentials
    })?;

    // Удаляем состояние логина
    state.opaque_state.remove_login_state(&payload.session_id).await;

    // Получаем пользователя для создания сессии
    let user = state
        .db
        .find_user_by_identifier(&payload.identifier, &state.server_pepper)
        .await?
        .ok_or_else(|| {
            tracing::error!("User not found after OPAQUE auth: {}", payload.identifier);
            ApiError::UserNotFound
        })?;

    // Создаём сессию
    let session_uuid = Uuid::new_v4();
    let session_key_hash = blake3::hash(&finish_result.session_key).as_bytes().to_vec();

    let session = Session {
        uuid: session_uuid,
        user_uuid: user.uuid,
        session_key_hash,
        expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        created_at: chrono::Utc::now(),
    };

    // Сохраняем сессию в БД
    state.db.save_session(&session).await
        .map_err(|e| {
            tracing::error!("Failed to save session: {:?}", e);
            e
        })?;

    tracing::info!("User authenticated successfully: {}", user.uuid);

    Ok(Json(OpaqueAuthFinishResponse {
        session_id: session_uuid,
        session_key: finish_result.session_key.to_vec(),
    }))
}

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

/// Проверка и получение пользователя по сессии
pub async fn verify_session(
    state: &AppState,
    session_id: &Uuid,
) -> Result<(Session, User), ApiError> {
    let session = state
        .db
        .get_session(session_id)
        .await?
        .ok_or(ApiError::SessionExpired)?;

    let user = state
        .db
        .get_user_by_uuid(&session.user_uuid)
        .await?
        .ok_or(ApiError::UserNotFound)?;

    Ok((session, user))
}
