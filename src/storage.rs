use crate::models::{ApiError, Session, User, UserType};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::env;
use uuid::Uuid;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await?;

        // Создаём пользовательский тип если его нет
        sqlx::query(
            r#"DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_type') THEN
                    CREATE TYPE user_type AS ENUM ('regular', 'bot', 'guest');
                END IF;
            END $$;"#,
        )
        .execute(&pool)
        .await?;

        // Таблица пользователей с поддержкой верификации
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username_hash BYTEA UNIQUE,
                email_hash BYTEA,
                phone_hash BYTEA,
                seed_phrase_hash BYTEA,
                opaque_record BYTEA NOT NULL,
                server_public_key BYTEA NOT NULL,
                user_type user_type NOT NULL DEFAULT 'regular',
                is_verified BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Таблица сессий
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
                session_key_hash BYTEA NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_uuid, session_key_hash)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Индексы
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username_hash ON users(username_hash)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users(phone_hash)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_seed_hash ON users(seed_phrase_hash)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_uuid ON sessions(user_uuid)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    // Сохранение пользователя
    pub async fn save_user(&self, user: &User) -> Result<Uuid, ApiError> {
        let row = sqlx::query(
            r#"
            INSERT INTO users
            (uuid, username_hash, email_hash, phone_hash, seed_phrase_hash,
             opaque_record, server_public_key, user_type, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (uuid) DO UPDATE SET
                username_hash = EXCLUDED.username_hash,
                email_hash = EXCLUDED.email_hash,
                phone_hash = EXCLUDED.phone_hash,
                seed_phrase_hash = EXCLUDED.seed_phrase_hash,
                opaque_record = EXCLUDED.opaque_record,
                server_public_key = EXCLUDED.server_public_key,
                user_type = EXCLUDED.user_type,
                is_verified = EXCLUDED.is_verified,
                updated_at = CURRENT_TIMESTAMP
            RETURNING uuid
            "#,
        )
        .bind(user.uuid)
        .bind(&user.username_hash)
        .bind(&user.email_hash)
        .bind(&user.phone_hash)
        .bind(&user.seed_phrase_hash)
        .bind(&user.opaque_record)
        .bind(&user.server_public_key)
        .bind(&user.user_type)
        .bind(user.is_verified)
        .fetch_one(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.get::<Uuid, _>("uuid"))
    }

    // Поиск пользователя по хэшу
    pub async fn find_user_by_hash(
        &self,
        username_hash: Option<&[u8]>,
        email_hash: Option<&[u8]>,
        phone_hash: Option<&[u8]>,
        seed_hash: Option<&[u8]>,
    ) -> Result<Option<User>, ApiError> {
        // Строим динамический запрос
        let mut query = "SELECT * FROM users WHERE ".to_string();
        let mut conditions = vec![];
        let mut params: Vec<&[u8]> = vec![];
        let mut param_count = 1;

        if let Some(hash) = username_hash {
            conditions.push(format!("username_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }
        if let Some(hash) = email_hash {
            conditions.push(format!("email_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }
        if let Some(hash) = phone_hash {
            conditions.push(format!("phone_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }
        if let Some(hash) = seed_hash {
            conditions.push(format!("seed_phrase_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }

        if conditions.is_empty() {
            return Ok(None);
        }

        query += &conditions.join(" OR ");

        // Выполняем запрос
        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let row = query_builder
            .fetch_optional(&self.pool)
            .await
            .map_err(ApiError::DatabaseError)?;

        Ok(row.map(|r| User {
            uuid: r.get("uuid"),
            username_hash: r.get("username_hash"),
            email_hash: r.get("email_hash"),
            phone_hash: r.get("phone_hash"),
            seed_phrase_hash: r.get("seed_phrase_hash"),
            opaque_record: r.get("opaque_record"),
            server_public_key: r.get("server_public_key"),
            user_type: r.get("user_type"),
            is_verified: r.get("is_verified"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    // Получение OPAQUE записи по UUID
    pub async fn get_opaque_record(&self, user_uuid: &Uuid) -> Result<Option<Vec<u8>>, ApiError> {
        let row = sqlx::query(
            r#"
            SELECT opaque_record FROM users
            WHERE uuid = $1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.map(|r| r.get("opaque_record")))
    }

    // Получение пользователя по UUID
    pub async fn get_user_by_uuid(&self, user_uuid: &Uuid) -> Result<Option<User>, ApiError> {
        let row = sqlx::query(
            r#"
            SELECT * FROM users
            WHERE uuid = $1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.map(|r| User {
            uuid: r.get("uuid"),
            username_hash: r.get("username_hash"),
            email_hash: r.get("email_hash"),
            phone_hash: r.get("phone_hash"),
            seed_phrase_hash: r.get("seed_phrase_hash"),
            opaque_record: r.get("opaque_record"),
            server_public_key: r.get("server_public_key"),
            user_type: r.get("user_type"),
            is_verified: r.get("is_verified"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    // Проверка существования пользователя
    pub async fn user_exists(
        &self,
        username_hash: Option<&[u8]>,
        email_hash: Option<&[u8]>,
        phone_hash: Option<&[u8]>,
    ) -> Result<bool, ApiError> {
        let mut conditions = vec![];
        let mut params: Vec<&[u8]> = vec![];
        let mut param_count = 1;

        if let Some(hash) = username_hash {
            conditions.push(format!("username_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }
        if let Some(hash) = email_hash {
            conditions.push(format!("email_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }
        if let Some(hash) = phone_hash {
            conditions.push(format!("phone_hash = ${}", param_count));
            params.push(hash);
            param_count += 1;
        }

        if conditions.is_empty() {
            return Ok(false);
        }

        let query = format!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE {})",
            conditions.join(" OR ")
        );

        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let row = query_builder
            .fetch_one(&self.pool)
            .await
            .map_err(ApiError::DatabaseError)?;

        Ok(row.get::<bool, _>("exists"))
    }

    // Обновление статуса верификации
    pub async fn set_verified(&self, user_uuid: &Uuid, verified: bool) -> Result<(), ApiError> {
        sqlx::query(
            r#"
            UPDATE users
            SET is_verified = $1, updated_at = CURRENT_TIMESTAMP
            WHERE uuid = $2
            "#,
        )
        .bind(verified)
        .bind(user_uuid)
        .execute(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(())
    }

    // Сохранение сессии
    pub async fn save_session(&self, session: &Session) -> Result<Uuid, ApiError> {
        let row = sqlx::query(
            r#"
            INSERT INTO sessions (uuid, user_uuid, session_key_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING uuid
            "#,
        )
        .bind(session.uuid)
        .bind(session.user_uuid)
        .bind(&session.session_key_hash)
        .bind(session.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.get::<Uuid, _>("uuid"))
    }

    // Получение сессии
    pub async fn get_session(&self, session_uuid: &Uuid) -> Result<Option<Session>, ApiError> {
        let row = sqlx::query(
            r#"
            SELECT * FROM sessions
            WHERE uuid = $1 AND expires_at > CURRENT_TIMESTAMP
            "#,
        )
        .bind(session_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.map(|r| Session {
            uuid: r.get("uuid"),
            user_uuid: r.get("user_uuid"),
            session_key_hash: r.get("session_key_hash"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }))
    }

    // Получение сессии по user_uuid
    pub async fn get_session_by_user(&self, user_uuid: &Uuid) -> Result<Option<Session>, ApiError> {
        let row = sqlx::query(
            r#"
            SELECT * FROM sessions
            WHERE user_uuid = $1 AND expires_at > CURRENT_TIMESTAMP
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(row.map(|r| Session {
            uuid: r.get("uuid"),
            user_uuid: r.get("user_uuid"),
            session_key_hash: r.get("session_key_hash"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }))
    }

    // Удаление сессии
    pub async fn delete_session(&self, session_uuid: &Uuid) -> Result<(), ApiError> {
        sqlx::query(
            r#"
            DELETE FROM sessions
            WHERE uuid = $1
            "#,
        )
        .bind(session_uuid)
        .execute(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(())
    }

    // Удаление всех сессий пользователя
    pub async fn delete_user_sessions(&self, user_uuid: &Uuid) -> Result<u64, ApiError> {
        let result = sqlx::query(
            r#"
            DELETE FROM sessions
            WHERE user_uuid = $1
            "#,
        )
        .bind(user_uuid)
        .execute(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(result.rows_affected())
    }

    // Удаление просроченных сессий
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, ApiError> {
        let result = sqlx::query(
            r#"
            DELETE FROM sessions
            WHERE expires_at <= CURRENT_TIMESTAMP
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;

        Ok(result.rows_affected())
    }

    // Поиск пользователя по любому идентификатору
    pub async fn find_user_by_identifier(
        &self,
        identifier: &str,
        pepper: &str,
    ) -> Result<Option<User>, ApiError> {
        // Определяем тип идентификатора по формату
        if identifier.contains('@') {
            // Email
            let email_hash = crate::models::hash_with_pepper(identifier, pepper);
            self.find_user_by_hash(None, Some(&email_hash), None, None)
                .await
        } else if identifier.chars().all(|c| c.is_ascii_digit() || c == '+') {
            // Phone (только цифры и +)
            let phone_hash = crate::models::hash_with_pepper(identifier, pepper);
            self.find_user_by_hash(None, None, Some(&phone_hash), None)
                .await
        } else {
            // Username или seed phrase
            let username_hash = crate::models::hash_with_pepper(identifier, pepper);
            let seed_hash = crate::models::hash_with_pepper(identifier, pepper);

            // Сначала ищем по username, потом по seed phrase
            if let Some(user) = self
                .find_user_by_hash(Some(&username_hash), None, None, None)
                .await?
            {
                return Ok(Some(user));
            }

            self.find_user_by_hash(None, None, None, Some(&seed_hash))
                .await
        }
    }
}
