use std::env;

use axum::{Router, routing::get};

use crate::{handlers::health_check, state::AppState};

mod handlers;
mod models;
mod repositories;
mod state;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file or environment");
    let app_state = AppState::new(&database_url)
        .await
        .expect("Failed to connect to database");
    println!("Connected to database successfully.");

    let app = Router::new()
        .route("/health", get(health_check))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server is running on http://127.0.0.1:3000");

    axum::serve(listener, app).await.unwrap();
}
