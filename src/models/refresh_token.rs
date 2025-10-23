use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;

// The `FromRow` derive macro lets SQLx automatically convert database rows into this `RefreshToken`,
// and Serialize/Deserialize handle JSON conversion.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub is_used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    // Check if token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used
    }
}
