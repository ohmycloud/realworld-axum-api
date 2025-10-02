use axum::extract::FromRef;
use sqlx::PgPool;
use std::sync::Arc;

use crate::repositories::{
    EmailVerificationRepository, EmailVerificationRepositoryTrait, UserRepository,
    UserRespositoryTrait,
};

// SQLx pools use Arc (atomic reference counting) internally,
// so cloning just copies a reference, not the entire pool
#[derive(Clone, FromRef)]
pub struct AppState {
    pub db_pool: PgPool,
    pub user_repository: Arc<dyn UserRespositoryTrait>,
    pub email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait>,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db_pool = PgPool::connect(database_url).await?;

        // Run migrations automatically
        sqlx::migrate!("./migrations").run(&db_pool).await?;

        // Create the user repository
        let user_repository: Arc<dyn UserRespositoryTrait> =
            Arc::new(UserRepository::new(db_pool.clone()));

        // Create the email verification repository
        let email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait> =
            Arc::new(EmailVerificationRepository::new(db_pool.clone()));

        Ok(Self {
            db_pool,
            user_repository,
            email_verification_repository,
        })
    }
}
