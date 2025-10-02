-- Add migration script here
-- user_id UUID NOT NULL REFERENCES users(id) - This creates a foreign key relationship.
-- Each token belongs to exactly one user.
-- ON DELETE CASCADE - This is crucial. If we delete a user,
-- PostgreSQL automatically deletes all their tokens.
-- No orphaned data floating around in our database.
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_expires ON email_verification_tokens(expires_at);
