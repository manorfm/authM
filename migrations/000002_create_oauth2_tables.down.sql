-- Drop indexes
DROP INDEX IF EXISTS idx_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;

-- Drop tables
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS oauth2_clients; 