use axum::extract::FromRef;
use sqlx::PgPool;

use crate::repositories::UserRepository;

// SQLx pools use Arc (atomic reference counting) internally,
// so cloning just copies a reference, not the entire pool
#[derive(Clone, FromRef)]
pub struct AppState {
    pub db_pool: PgPool,
    pub user_repository: UserRepository,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db_pool = PgPool::connect(database_url).await?;

        // Run migrations automatically
        sqlx::migrate!("./migrations").run(&db_pool).await?;

        // Create the user repository
        let user_repository = UserRepository::new(db_pool.clone());

        Ok(Self {
            db_pool,
            user_repository,
        })
    }
}
