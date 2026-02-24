-- RFC 7523: Set default for new rows.
ALTER TABLE oauth_clients ALTER COLUMN token_endpoint_auth_method SET DEFAULT 'client_secret_basic';
