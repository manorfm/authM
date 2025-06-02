-- Add email_verified column to users table
ALTER TABLE users
ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Update existing users to have email_verified as false
UPDATE users SET email_verified = FALSE WHERE email_verified IS NULL; 