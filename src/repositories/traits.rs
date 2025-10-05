use crate::models::{EmailVerificationToken, PasswordResetToken, User};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Error as SqlxError;
use uuid::Uuid;

#[async_trait]
pub trait UserRespositoryTrait: Send + Sync {
    async fn create(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<User, SqlxError>;

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, SqlxError>;

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, SqlxError>;

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, SqlxError>;

    async fn update(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        bio: Option<&str>,
        image: Option<&str>,
    ) -> Result<Option<User>, SqlxError>;
}

#[async_trait]
pub trait EmailVerificationRepositoryTrait: Send + Sync {
    /// Inserts a new verification token into the database
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, SqlxError>;

    /// Looks up a token (when user clicks the verification link)
    async fn find_by_token(&self, token: &str)
    -> Result<Option<EmailVerificationToken>, SqlxError>;

    /// Removes a token after it’s used (single-use tokens)
    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    /// Marks a user as verified in the users table
    async fn verify_user_email(&self, user_id: Uuid) -> Result<(), SqlxError>;
}

#[async_trait]
pub trait PasswordResetRepositoryTrait: Send + Sync {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, SqlxError>;

    async fn find_by_token(&self, token: &str) -> Result<Option<PasswordResetToken>, SqlxError>;

    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    async fn delete_all_user_tokens(&self, user_id: Uuid) -> Result<(), SqlxError>;
}
