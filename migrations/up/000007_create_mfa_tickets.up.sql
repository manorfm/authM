CREATE TABLE IF NOT EXISTS mfa_tickets (
    id VARCHAR(32) PRIMARY KEY,
    user_id VARCHAR(26) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_tickets_user_id ON mfa_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_tickets_expires_at ON mfa_tickets(expires_at); 