use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::state::AppState;

pub async fn health_check(State(state): State<AppState>) -> Json<Value> {
    // Json(...) is a wrapper that tells Axum to set the Content-Type: application/json header,
    // serialize the data to JSON string and set appropriate HTTP status.
    // json!({...}) is a macro that creates a JSON object.
    match sqlx::query("SELECT 1").execute(&state.db_pool).await {
        Ok(_) => Json(json!({
            "status": "OK",
            "message": "Server is running"
        })),
        Err(err) => {
            eprintln!("Database error: {}", err);
            Json(json!({
                "status": "ERROR",
                "database": "disconnected",
                "error": err.to_string()
            }))
        }
    }
}
