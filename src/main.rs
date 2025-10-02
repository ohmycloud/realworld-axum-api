use axum::{
    Router,
    routing::{get, post},
};
use std::env;

use realworld_axum_api::{
    handlers::{
        auth::{current_user, login, register},
        health_check, verify_email,
    },
    state::AppState,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file or environment");
    let app_state = AppState::new(&database_url)
        .await
        .expect("Failed to connect to database");
    println!("Connected to database successfully.");

    let app = Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        // Authentication endpoints
        .route("/api/users", post(register))
        .route("/api/users/login", post(login))
        .route("/api/user", get(current_user))
        .route("/api/auth/verify-email", get(verify_email))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server is running on http://127.0.0.1:3000");
    println!("  POST /api/users         - Register new user");
    println!("  POST /api/users/login   - Login existing user");
    println!("  GET  /api/user          - Get current user (requires auth)");
    println!("  GET  /health            - Health check");

    axum::serve(listener, app).await.unwrap();
}
