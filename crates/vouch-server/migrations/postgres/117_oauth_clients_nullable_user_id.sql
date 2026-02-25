-- Make oauth_clients.user_id nullable to support RFC 7591 open registration.
-- Open registration creates clients without user association; the client_id
-- alone grants zero access (FIDO2 authentication still required for tokens).
ALTER TABLE oauth_clients ALTER COLUMN user_id DROP NOT NULL;
