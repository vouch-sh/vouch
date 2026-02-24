-- RFC 7523: Token endpoint auth method (DSQL-safe: name and type only).
ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT;
