-- Index for OAuth client secret lookups by client
CREATE INDEX ASYNC idx_oauth_client_secrets_client ON oauth_client_secrets(oauth_client_id);
