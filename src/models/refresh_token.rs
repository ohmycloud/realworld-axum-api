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
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}
