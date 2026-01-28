use axum::{
    extract::{ws::{WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState,
    models::{
        ApiError, OpaqueAuthFinishRequest, OpaqueAuthFinishResponse, 
        OpaqueAuthStartRequest, OpaqueAuthStartResponse, OpaqueRegisterFinishRequest, 
        OpaqueRegisterFinishResponse, OpaqueRegisterStartRequest, OpaqueRegisterStartResponse,
    },
    handlers,
};

// ============ WEBSOCKET MESSAGE TYPES ============

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    // Регистрация
    #[serde(rename = "register_start")]
    RegisterStart(OpaqueRegisterStartRequest),
    
    #[serde(rename = "register_finish")]
    RegisterFinish(OpaqueRegisterFinishRequest),
    
    // Аутентификация
    #[serde(rename = "login_start")]
    LoginStart(OpaqueAuthStartRequest),
    
    #[serde(rename = "login_finish")]
    LoginFinish(OpaqueAuthFinishRequest),
    
    // Ping для проверки соединения
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsResponse {
    // Регистрация
    #[serde(rename = "register_start")]
    RegisterStart(OpaqueRegisterStartResponse),
    
    #[serde(rename = "register_finish")]
    RegisterFinish(OpaqueRegisterFinishResponse),
    
    // Аутентификация
    #[serde(rename = "login_start")]
    LoginStart(OpaqueAuthStartResponse),
    
    #[serde(rename = "login_finish")]
    LoginFinish(OpaqueAuthFinishResponse),
    
    // Pong в ответ на ping
    #[serde(rename = "pong")]
    Pong,
    
    // Ошибка
    #[serde(rename = "error")]
    Error {
        message: String,
        code: u16,
    },
}

// ============ WEBSOCKET HANDLER ============

pub async fn websocket_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let session_id = Uuid::new_v4().to_string();

    tracing::info!("WebSocket connected: {}", session_id);

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(axum::extract::ws::Message::Text(text)) => {
                match serde_json::from_str::<WsMessage>(&text) {
                    Ok(ws_msg) => {
                        let response = handle_ws_message(ws_msg, &state).await;
                        let response_json = match serde_json::to_string(&response) {
                            Ok(json) => json,
                            Err(e) => {
                                tracing::error!("Failed to serialize response: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = sender.send(axum::extract::ws::Message::Text(response_json)).await {
                            tracing::error!("Failed to send WebSocket message: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse WebSocket message: {}", e);
                        let error_response = WsResponse::Error {
                            message: format!("Invalid message format: {}", e),
                            code: 400,
                        };
                        let error_json = serde_json::to_string(&error_response).unwrap();
                        if sender.send(axum::extract::ws::Message::Text(error_json)).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(axum::extract::ws::Message::Close(_)) => {
                tracing::info!("WebSocket closed: {}", session_id);
                break;
            }
            Err(e) => {
                tracing::error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    tracing::info!("WebSocket disconnected: {}", session_id);
}

// ============ MESSAGE HANDLERS ============

async fn handle_ws_message(msg: WsMessage, state: &AppState) -> WsResponse {
    match msg {
        WsMessage::RegisterStart(req) => {
            match handlers::register_start(axum::extract::State((*state).clone()), axum::Json(req)).await {
                Ok(axum::Json(response)) => WsResponse::RegisterStart(response),
                Err(e) => error_response(&e),
            }
        }
        WsMessage::RegisterFinish(req) => {
            match handlers::register_finish(axum::extract::State((*state).clone()), axum::Json(req)).await {
                Ok(axum::Json(response)) => WsResponse::RegisterFinish(response),
                Err(e) => error_response(&e),
            }
        }
        WsMessage::LoginStart(req) => {
            match handlers::login_start(axum::extract::State((*state).clone()), axum::Json(req)).await {
                Ok(axum::Json(response)) => WsResponse::LoginStart(response),
                Err(e) => error_response(&e),
            }
        }
        WsMessage::LoginFinish(req) => {
            match handlers::login_finish(axum::extract::State((*state).clone()), axum::Json(req)).await {
                Ok(axum::Json(response)) => WsResponse::LoginFinish(response),
                Err(e) => error_response(&e),
            }
        }
        WsMessage::Ping => WsResponse::Pong,
    }
}

fn error_response(error: &ApiError) -> WsResponse {
    WsResponse::Error {
        message: error.to_string(),
        code: match error {
            ApiError::BadRequest(_) => 400,
            ApiError::UserExists => 409,
            ApiError::UserNotFound => 404,
            ApiError::InvalidCredentials => 401,
            ApiError::SessionExpired => 401,
            ApiError::OpaqueError(_) => 400,
            ApiError::DatabaseError(_) => 500,
            ApiError::BotAuthFailed => 401,
            ApiError::UserNotVerified => 403,
            ApiError::RateLimitExceeded => 429,
            ApiError::InvalidUserType => 400,
            ApiError::InternalError(_) => 500,
        },
    }
}
