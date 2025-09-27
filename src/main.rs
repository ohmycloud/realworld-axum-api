use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health_check));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server is running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> Json<Value> {
    // Json(...) is a wrapper that tells Axum to set the Content-Type: application/json header,
    // serialize the data to JSON string and set appropriate HTTP status.
    // json!({...}) is a macro that creates a JSON object.
    Json(json!({
        "status": "OK",
        "message": "Server is running"
    }))
}
