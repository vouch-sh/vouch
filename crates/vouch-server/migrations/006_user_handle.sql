-- Add user_handle column to authenticators table
-- user_handle is the user ID stored in discoverable credentials (resident keys)
-- It allows the authenticator to identify the user without requiring email lookup
ALTER TABLE authenticators ADD COLUMN user_handle BLOB;
