-- Add migration script here
-- `id`: Primary key, auto-generated UUID
-- `user_id`: Links the token to a specific user, with foreign key constraint
-- `token`: The actual refresh token string (UUID)
-- `created_at`: When the token was created
-- `last_used_at`: Tracks when the token was last used,
-- useful for monitoring and detecting suspicious activity
-- `ON DELETE CASCADE`: If we delete a user, all their refresh tokens get deleted automatically
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
