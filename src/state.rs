use sqlx::PgPool;

// SQLx pools use Arc (atomic reference counting) internally,
// so cloning just copies a reference, not the entire pool
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db_pool = PgPool::connect(database_url).await?;
        Ok(Self { db_pool })
    }
}
