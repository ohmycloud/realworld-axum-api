use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl PasswordResetToken {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
