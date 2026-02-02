-- Index for OAuth client secret hash lookups
CREATE INDEX ASYNC idx_oauth_client_secrets_hash ON oauth_client_secrets(secret_hash);
