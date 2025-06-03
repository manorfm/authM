-- Drop indexes
DROP INDEX IF EXISTS idx_verification_codes_user_id;
DROP INDEX IF EXISTS idx_verification_codes_code;
DROP INDEX IF EXISTS idx_verification_codes_expires_at;

-- Drop table
DROP TABLE IF EXISTS verification_codes; 