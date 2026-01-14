use axum::{
    Router,
    routing::{get, post},
    extract::FromRef,
};
use std::process;
use std::{fs, io::Write, net::SocketAddr};
use tokio::net::TcpListener;
use tracing_subscriber;

mod ciphersuite;
mod handlers;
mod models;
mod storage;

use crate::storage::Database;
use crate::handlers::OpaqueServerState;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub opaque_state: OpaqueServerState,
    pub server_pepper: String,
}

// Для axum extractor
impl FromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for OpaqueServerState {
    fn from_ref(state: &AppState) -> Self {
        state.opaque_state.clone()
    }
}

#[tokio::main]
async fn main() {
    // Инициализация логгера
    tracing_subscriber::fmt::init();
    println!("Hello from Skyeslammer Foundation!");

    // Проверяем настройку БД и секретов
    if !storage::is_configured() {
        println!("It seems that server is not configured.");
        if let Err(e) = setup().await {
            eprintln!("| DSE | Could not set up the server. Reason: {}", e);
            process::exit(1);
        }
        println!("Setup is now done. Please, restart the server.");
        process::exit(0);
    }

    // Подключаемся к БД
    let db = match Database::connect().await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("| DSE | Could not connect to database. Reason: {}", e);
            process::exit(1);
        }
    };

    // Инициализируем OPAQUE Server Setup
    let server_setup_str = match std::env::var("OPAQUE_SERVER_SETUP") {
        Ok(setup) => setup,
        Err(e) => {
            eprintln!("| DSE | Failed to load OPAQUE server setup. Reason: {}", e);
            process::exit(1);
        }
    };

    // Десериализуем ServerSetup
    let server_setup = match ciphersuite::deserialize_server_setup(&server_setup_str) {
        Ok(setup) => setup,
        Err(e) => {
            eprintln!("| DSE | Failed to deserialize server setup. Reason: {}", e);
            process::exit(1);
        }
    };

    // Читаем серверный перец для хэширования
    let server_pepper = match std::env::var("SERVER_PEPPER") {
        Ok(pepper) => pepper,
        Err(e) => {
            eprintln!("| DSE | Failed to load server pepper. Reason: {}", e);
            process::exit(1);
        }
    };

    // Создаём роутер
    let app = Router::new()
        .route("/api/register/start", post(handlers::register_start))
        .route("/api/register/finish", post(handlers::register_finish))
        .route("/api/login/start", post(handlers::login_start))
        .route("/api/login/finish", post(handlers::login_finish))
        .route("/health", get(|| async { "OK" }))
        .with_state(AppState {
            db,
            server_setup,
            server_pepper,
        });

    // Запускаем сервер
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("| DSE | Failed to run server. Reason: {}", e);
            process::exit(1);
        }
    };

    println!("🚀 Server is successfully running on {}!", addr);

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap_or_else(|e| {
            eprintln!("| DSE | Server Error: {}", e);
            process::exit(1);
        });
}

/// Настройка сервера при первом запуске
async fn setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Diam Server Setup ===");

    // 1. Настройка БД
    println!("\nLet's connect your server to the database.");

    let db_user = ask_input("Type here your Postgres username: ")?;
    let db_password = ask_password("Great! Now type your Postgres password: ")?;
    let db_url = format!("postgres://{}:{}@localhost/diam", db_user, db_password);

    // 2. Генерация OPAQUE Server Setup
    println!("\nGenerating OPAQUE server setup...");
    let cs = ciphersuite::DefaultCipherSuite::new();
    let server_setup = opaque_ke::ServerSetup::<ciphersuite::DefaultCipherSuite>::new(&rand::thread_rng());
    let server_setup_hex = hex::encode(bincode::serialize(&server_setup)?);

    // 3. Генерация серверного перца
    let server_pepper = generate_pepper();

    // 4. Запись в .env
    let mut dotenv_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(".env")?;

    writeln!(&mut dotenv_file, "DATABASE_URL={}", db_url)?;
    writeln!(&mut dotenv_file, "OPAQUE_SERVER_SETUP={}", server_setup_hex)?;
    writeln!(&mut dotenv_file, "SERVER_PEPPER={}", server_pepper)?;

    println!("| DSI | Successfully generated OPAQUE server setup and server pepper.");

    // 5. Создание таблиц в БД
    println!("\nCreating database tables...");
    if let Err(e) = create_database_tables(&db_url).await {
        eprintln!("| DSE | Failed to create tables: {}", e);
    } else {
        println!("| DSI | Database tables created successfully.");
    }

    println!("\n✅ Your server is now set up!");
    println!("Restart your server to proceed.");

    Ok(())
}

/// Запрос ввода у пользователя
fn ask_input(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Запрос пароля (без эха в терминале)
fn ask_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    Ok(rpassword::read_password()?.trim().to_string())
}

/// Генерация серверного перца
fn generate_pepper() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let pepper: [u8; 32] = rng.gen();
    hex::encode(pepper)
}

pub fn is_configured() -> bool {
    env::var("DATABASE_URL").is_ok()
        && env::var("OPAQUE_SERVER_SETUP").is_ok()
        && env::var("SERVER_PEPPER").is_ok()
}
